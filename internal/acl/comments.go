package acl

// FNV-1a, written out so that a text is hashed a byte at a time without a call for each.
const (
	fnvOffset uint64 = 14695981039346656037
	fnvPrime  uint64 = 1099511628211
)

func fnvBytes(b []byte) uint64 {
	h := fnvOffset
	for _, c := range b {
		h ^= uint64(c)
		h *= fnvPrime
	}
	return h
}

// textScan is what one pass over a policy's text finds that its normal form does not keep.
type textScan struct {
	// comments counts the comments of the text by the hash of each one's bytes (a line
	// comment without its line end).
	comments map[uint64]int
	// layout hashes the text with its comments left out, so two texts with the same layout
	// differ at most in their comments: any other difference (whitespace, punctuation, key
	// order, the spelling of a string) changes it.
	layout uint64
}

// scanText reads the text the way the HuJSON parser does, so a comment inside a string is
// not one. A pass over the bytes costs one unit for every eight of them.
func scanText(m *meter, src []byte) (textScan, error) {
	if err := m.tick(len(src)/8 + 1); err != nil {
		return textScan{}, err
	}
	out := textScan{comments: map[uint64]int{}, layout: fnvOffset}
	h := fnvOffset
	n := len(src)
	for i := 0; i < n; i++ {
		c := src[i]
		switch {
		case c == '"':
			h = (h ^ uint64(c)) * fnvPrime
			for i++; i < n && src[i] != '"'; i++ {
				h = (h ^ uint64(src[i])) * fnvPrime
				if src[i] == '\\' && i+1 < n {
					i++
					h = (h ^ uint64(src[i])) * fnvPrime
				}
			}
			if i < n {
				h = (h ^ '"') * fnvPrime
			}
		case c == '/' && i+1 < n && src[i+1] == '/':
			start := i
			for i < n && src[i] != '\n' {
				i++
			}
			end := i
			if end > start && src[end-1] == '\r' {
				end--
			}
			out.comments[fnvBytes(src[start:end])]++
			i-- // the line end is text
		case c == '/' && i+1 < n && src[i+1] == '*':
			start := i
			i += 2
			for i+1 < n && (src[i] != '*' || src[i+1] != '/') {
				i++
			}
			i++
			out.comments[fnvBytes(src[start:min(i+1, n)])]++
		default:
			h = (h ^ uint64(c)) * fnvPrime
		}
	}
	out.layout = h
	return out, nil
}

// commentDifference is how many comments one text has that the other lacks, both ways.
func commentDifference(a, b map[uint64]int) int {
	d := 0
	for h, x := range a {
		if y := b[h]; x > y {
			d += x - y
		}
	}
	for h, y := range b {
		if x := a[h]; y > x {
			d += y - x
		}
	}
	return d
}
