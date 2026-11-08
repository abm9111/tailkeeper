package sanitize

import (
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

// readable is the text that masking reads: s with each "[p:" it holds rewritten (unforged),
// and the unusual spellings of an IPv4 address and of an at sign taken to what they
// denote (normalizeForms). Text, Remask and TextRefs mask this and nothing else.
func (m Masker) readable(s string) string { return normalizeForms(m.unforged(s)) }

// normalizeForms makes the spellings of an address that the masker's scans do not read
// into ones they do (VIGIL-EGRESS-002). It rewrites two things and leaves all other text
// as it is:
//
//   - An IPv4 address written as inet_aton and a URL parser read it (see addressForm): a
//     part in hexadecimal in a number of two to four parts (0x8.0x8.0x8.0x8, 203.0x7107), a
//     part with a leading zero after the first (octal, or decimal: 203.000.113.007,
//     010.010.010.010), digits or full stops written full-width (８.８.８.８, 8。8。8。8),
//     and, where a URL host is meant, a number alone, in any spelling, or in two or three
//     parts (http://134744072/, http://0x08080808/, http://8.8.2056/). One that
//     denotes a public address is written as that address in dotted decimal (8.8.8.8) and
//     masked by the scan for the usual form, to its network like any other: a "/" and a
//     prefix length after it are read as they are after a plain address, a narrower one cut
//     to the network and a wider one losing its host bits, and nothing of the spelling or of
//     the host part is left. One that denotes no public address, or that is not read (see
//     below), stays as written.
//   - An at sign written as &#64;, &#x40; (in any case, with any leading zeros), &commat;,
//     the full-width at sign (U+FF20) or the small commercial at (U+FE6B) is written as @
//     where it stands between the end of a local part and the start of a domain, so that
//     the email scan reads the address it joins.
//
// What is not read, because nothing tells it from the ordinary text it is spelled like: a
// number alone (134744072, and 0x08080808, which is as often a Windows error code such as
// 0x80070005 as an address) or in two or three decimal parts (8.8.2056, and so 1.27.3 and
// 31.10.2026) outside a URL host, which are epoch times, sizes, versions, dates and codes;
// and a number that is glued to a letter, a digit, an underscore or a full stop before it
// (ip0x08080808, host.0x08080808), which the scans for the usual forms read when they can.
// A number of two or three parts with a hexadecimal part (203.0x7107) is read wherever it
// stands: a dotted number with such a part is no code, version or date.
//
// The result masks to itself: a rewritten address is written in plain dotted decimal, which
// this scan leaves to the usual one, and the at sign as @.
func normalizeForms(s string) string {
	var b strings.Builder
	copied := 0
	for i := 0; i < len(s); {
		c := s[i]
		from, end, repl := i, 0, ""
		switch {
		case c == '&':
			if end = i + atEntityLen(s[i:]); end > i && atBetween(s, i, end) {
				repl = "@"
			} else {
				i++
				continue
			}
		case c >= 0x80 && atRuneLen(s[i:]) > 0:
			if end = i + atRuneLen(s[i:]); atBetween(s, i, end) {
				repl = "@"
			} else {
				i = end
				continue
			}
		case isDigit(c) || c >= 0x80:
			var ok bool
			if from, end, repl, ok = addressForm(s, i); !ok {
				i = max(end, i+1)
				continue
			}
		default:
			i++
			continue
		}
		b.WriteString(s[copied:from])
		b.WriteString(repl)
		copied, i = end, end
	}
	if copied == 0 {
		return s
	}
	b.WriteString(s[copied:])
	return b.String()
}

// atEntityLen is the length of the character reference for "@" that s starts with, or 0:
// &#64; and &#x40; (x in either case, any number of leading zeros) and &commat;.
func atEntityLen(s string) int {
	if strings.HasPrefix(s, "&commat;") {
		return len("&commat;")
	}
	if len(s) < 5 || s[0] != '&' || s[1] != '#' {
		return 0
	}
	base, p := 10, 2
	if s[p] == 'x' || s[p] == 'X' {
		base, p = 16, 3
	}
	zeros := p
	for p < len(s) && s[p] == '0' && p-zeros <= 16 {
		p++
	}
	if p-zeros > 16 {
		return 0 // not a number anyone writes; the scan stays short
	}
	digits := "64;"
	if base == 16 {
		digits = "40;"
	}
	if !strings.HasPrefix(s[p:], digits) {
		return 0
	}
	return p + len(digits)
}

// atRuneLen is the length of the full-width at sign (U+FF20) or the small commercial at
// (U+FE6B) that s starts with, or 0.
func atRuneLen(s string) int {
	r, n := utf8.DecodeRuneInString(s)
	if r == '＠' || r == '﹫' {
		return n
	}
	return 0
}

// atBetween reports whether the at sign spelled at s[i:end] stands between a local part
// and a domain: a byte of a local part (or a closing quote) right before it, and a byte of
// a domain right after it. A spelling with a space or a line end beside it is text, not an
// address, and stays as written.
func atBetween(s string, i, end int) bool {
	return i > 0 && (localByte(s[i-1]) || s[i-1] == '"') && end < len(s) && domainByte(s[end])
}

// A part is one number of a written IPv4 address.
type formPart struct {
	start, end int
	hex        bool   // 0x followed by hexadecimal digits
	lead0      bool   // decimal digits with more than one, the first a zero
	octOK      bool   // lead0 and every digit is below 8
	dec, oct   uint64 // the value read as decimal (as hexadecimal for a hex part) and, for lead0, as octal
}

// A formNumber is the numbers that full stops join (an ASCII one or a full-width one), as
// far as it can be an IPv4 address: at most four parts of at most twelve digits.
type formNumber struct {
	parts    [4]formPart
	n        int
	end      int
	bad      bool // more than four parts, a number too long, or too large for a hex part
	nonASCII bool // a full-width digit or full stop
}

// digitAt is the value and the length in bytes of the digit that s starts at i: an ASCII
// digit or a full-width one (U+FF10 to U+FF19). The length is 0 for any other byte.
func digitAt(s string, i int) (value uint64, size int) {
	if i >= len(s) {
		return 0, 0
	}
	if isDigit(s[i]) {
		return uint64(s[i] - '0'), 1
	}
	if s[i] == 0xEF && i+2 < len(s) && s[i+1] == 0xBC && s[i+2] >= 0x90 && s[i+2] <= 0x99 {
		return uint64(s[i+2] - 0x90), 3
	}
	return 0, 0
}

// dotAt is the length in bytes of the full stop that s starts at i, which is the ASCII one
// or one that a URL parser reads as one (U+FF0E, U+3002, U+FF61), or 0.
func dotAt(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	if s[i] == '.' {
		return 1
	}
	if r, n := utf8.DecodeRuneInString(s[i:]); r == '．' || r == '。' || r == '｡' {
		return n
	}
	return 0
}

// readFormNumber reads the number that starts at s[i], a digit, as far as it goes.
func readFormNumber(s string, i int) formNumber {
	var f formNumber
	p := i
	for {
		part, q, ok := readFormPart(s, p)
		if !ok || f.n >= len(f.parts) {
			f.bad = true
		} else {
			f.parts[f.n] = part
		}
		f.n++
		if part.start != part.end && !isASCIIDigits(s[part.start:part.end]) && !part.hex {
			f.nonASCII = true
		}
		p = q
		dot := dotAt(s, p)
		if dot == 0 {
			break
		}
		if _, size := digitAt(s, p+dot); size == 0 {
			break
		}
		f.nonASCII = f.nonASCII || dot > 1
		p += dot
	}
	f.end = p
	return f
}

func isASCIIDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// hexDigit is the value of the hexadecimal digit c, and whether c is one.
func hexDigit(c byte) (uint64, bool) {
	switch {
	case c >= '0' && c <= '9':
		return uint64(c - '0'), true
	case c >= 'a' && c <= 'f':
		return uint64(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return uint64(c-'A') + 10, true
	}
	return 0, false
}

// maxFormDigits is the most digits of a decimal or octal part: 4294967295 is ten decimal
// digits and 037777777777 twelve octal ones.
const maxFormDigits = 12

// readFormPart reads one part at s[p], a digit: 0x and hexadecimal digits, or decimal
// digits (ASCII or full-width). ok is false for a part that cannot be an IPv4 number: one
// of more than twelve digits, or a hexadecimal one of more than eight. The part is read to
// its end either way, so that the caller skips it whole.
func readFormPart(s string, p int) (part formPart, q int, ok bool) {
	if s[p] == '0' && p+2 < len(s) && (s[p+1] == 'x' || s[p+1] == 'X') && hexVal(s[p+2]) >= 0 {
		return readHexPart(s, p)
	}
	return readDecimalPart(s, p)
}

// readHexPart reads the part that starts with 0x at s[p].
func readHexPart(s string, p int) (part formPart, q int, ok bool) {
	part.start = p
	part.hex = true
	q = p + 2
	for q < len(s) {
		d, isHex := hexDigit(s[q])
		if !isHex {
			break
		}
		if q-p-2 < 8 {
			part.dec = part.dec<<4 | d
		}
		q++
	}
	part.end = q
	return part, q, q-p-2 <= 8
}

// readDecimalPart reads the decimal digits (ASCII or full-width) that start at s[p].
func readDecimalPart(s string, p int) (part formPart, q int, ok bool) {
	part.start = p
	part.octOK = true
	q, digits, zeroFirst := p, 0, false
	for {
		d, size := digitAt(s, q)
		if size == 0 {
			break
		}
		if digits == 0 {
			zeroFirst = d == 0
		}
		if digits < maxFormDigits {
			part.dec = part.dec*10 + d
			part.oct = part.oct*8 + d
		}
		part.octOK = part.octOK && d < 8
		digits++
		q += size
	}
	part.end = q
	part.lead0 = digits > 1 && zeroFirst
	part.octOK = part.octOK && part.lead0
	return part, q, digits <= maxFormDigits
}

// address reads the number as inet_aton reads it: four parts are the four bytes, three
// parts end in a 16-bit number, two in a 24-bit one and one is the whole address. A part
// with a leading zero is octal when octal is set and every digit of it is below 8, and
// decimal otherwise: parsers differ on "010", so both readings are tried.
func (f formNumber) address(octal bool) (netip.Addr, bool) {
	v, ok := f.values(octal)
	if !ok {
		return netip.Addr{}, false
	}
	w, ok := joinParts(f.n, v)
	if !ok || w > 0xFFFFFFFF {
		return netip.Addr{}, false
	}
	a := netip.AddrFrom4([4]byte{byte(w >> 24 & 0xFF), byte(w >> 16 & 0xFF), byte(w >> 8 & 0xFF), byte(w & 0xFF)}) // w is at most 0xFFFFFFFF: the masks drop nothing
	return a, true
}

// values are the values of the parts: a part with a leading zero is read as octal when octal
// is set, and ok is false if one of them has a digit that octal has not.
func (f formNumber) values(octal bool) (v [4]uint64, ok bool) {
	for k := 0; k < f.n; k++ {
		p := f.parts[k]
		v[k] = p.dec
		if p.lead0 && octal {
			if !p.octOK {
				return v, false
			}
			v[k] = p.oct
		}
	}
	return v, true
}

// joinParts is the 32-bit number that n parts with the values v make: the last part fills what
// the others leave. ok is false for a part that is too large, or for a count of parts that
// makes no address.
func joinParts(n int, v [4]uint64) (w uint64, ok bool) {
	switch n {
	case 1:
		return v[0], true
	case 2:
		if v[0] > 0xFF || v[1] > 0xFFFFFF {
			return 0, false
		}
		return v[0]<<24 | v[1], true
	case 3:
		if v[0] > 0xFF || v[1] > 0xFF || v[2] > 0xFFFF {
			return 0, false
		}
		return v[0]<<24 | v[1]<<16 | v[2], true
	case 4:
		if v[0] > 0xFF || v[1] > 0xFF || v[2] > 0xFF || v[3] > 0xFF {
			return 0, false
		}
		return v[0]<<24 | v[1]<<16 | v[2]<<8 | v[3], true
	}
	return 0, false
}

// publicAddress is the public address the number denotes in one of its readings (octal
// first), if there is one. 0.0.0.0/8 locates no one, as it does in the dotted scan.
func (f formNumber) publicAddress() (netip.Addr, bool) {
	for _, octal := range [2]bool{true, false} {
		if a, ok := f.address(octal); ok && public(a) && a.As4()[0] != 0 {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// wordRune reports whether the rune that ends the text before a number, or starts the text
// after it, would make the number part of a longer word: a letter, a digit or an underscore.
func wordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// addressForm reads the number at s[i], which starts with a digit, as an IPv4 address in an
// unusual spelling, and returns where its replacement starts and ends in s and the text of
// it. ok is false when the number is not rewritten; end is then where it ends, for the caller
// to skip it whole, so that the time stays linear in the text.
//
// A number is read only where nothing makes it part of a longer word: no letter, digit,
// underscore or full stop before it, and no letter, digit or underscore after it. Then
//
//   - four parts are read when one is hexadecimal, one after the first has a leading zero, or
//     a digit or full stop is full-width. (A first part with a leading zero, "007.8.8.8", is
//     read as glue by the scan for the usual form, which already masks it. Four parts of
//     plain decimal numbers are that scan's too.)
//   - two or three parts are read when one is hexadecimal. Every other number of fewer than
//     four parts, one number alone (hexadecimal or not) included, is read only as the host
//     of a URL, right after "//" and followed by the end of the text or a character that
//     ends a host (a slash, a colon, a question mark, a number sign, a backslash, white
//     space, a quote, a bracket, a comma or a semicolon). A URL parser reads such a host as
//     an IPv4 address whatever its spelling, as a number that ends it; the same text
//     elsewhere is a time, a size, a version, a date or an error code.
//
// The address is the number as inet_aton reads it (formNumber.address), in either reading of
// a leading zero, the octal one first. It is rewritten when it is public, as that address in
// dotted decimal, and so masked by the scan for the usual form, with whatever prefix length
// follows it. There is no number to leave alone for being masked already: what masking writes
// is a plain dotted network, which this function does not read.
func addressForm(s string, i int) (from, end int, repl string, ok bool) {
	_, first := digitAt(s, i)
	if first == 0 {
		return i, i, "", false
	}
	if i > 0 && joinsWordBefore(s, i) {
		return i, i + first, "", false
	}
	f := readFormNumber(s, i)
	if !f.isRead(s, i) {
		return i, f.end, "", false
	}
	a, ok := f.publicAddress()
	if !ok {
		return i, f.end, "", false
	}
	return i, f.end, a.String(), true
}

// joinsWordBefore reports whether the text before s[i] makes a number there part of a longer
// word or number: it ends in a full stop, a letter, a digit or an underscore.
func joinsWordBefore(s string, i int) bool {
	before, _ := utf8.DecodeLastRuneInString(s[:i])
	return before == '.' || wordRune(before)
}

// isRead reports whether the number f that starts at s[i] is read as an address by how it is
// spelled and where it stands: four parts when one is hexadecimal, one after the first has a
// leading zero, or a digit or full stop is full-width; fewer than four only when one is
// hexadecimal, or as the host of a URL; and in every case with nothing after it that makes it
// part of a longer word, or, for a host, that does not end one.
func (f formNumber) isRead(s string, i int) bool {
	if f.bad {
		return false
	}
	hasHex, tail0 := f.spellings()
	host := i >= 2 && s[i-2] == '/' && s[i-1] == '/'
	hostOnly := f.n < 4 && (f.n == 1 || !hasHex) // a number that is an address only as the host of a URL
	switch {
	case f.n == 4 && !hasHex && !tail0 && !f.nonASCII:
		return false
	case hostOnly && !host:
		return false
	}
	return f.endsAsNumber(s, hostOnly)
}

// spellings reports whether a part of the number is hexadecimal, and whether a part after the
// first has a leading zero.
func (f formNumber) spellings() (hasHex, tail0 bool) {
	for k := 0; k < f.n; k++ {
		hasHex = hasHex || f.parts[k].hex
		tail0 = tail0 || k > 0 && f.parts[k].lead0
	}
	return hasHex, tail0
}

// endsAsNumber reports whether what follows the number f in s does not make it part of a longer
// word, and, for a number that is read only as a URL host, ends a host.
func (f formNumber) endsAsNumber(s string, hostOnly bool) bool {
	if f.end >= len(s) {
		return true
	}
	after, _ := utf8.DecodeRuneInString(s[f.end:])
	return !(wordRune(after) || hostOnly && !strings.ContainsRune(hostEnds, after))
}

// hostEnds are the characters after a URL host: the end of the authority and the
// characters of the text around a URL.
const hostEnds = "/:?#\\ \t\r\n\"'<>()[],;"
