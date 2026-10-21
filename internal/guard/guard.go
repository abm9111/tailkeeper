// Package guard is the check that runs on HuJSON text before any call into
// github.com/tailscale/hujson that recurses (Parse, Standardize, Pack, Format, Patch).
//
// The HuJSON parser recurses once for each level of nesting and has no bound. A Go stack
// overflow is a fatal error, not a panic, so recover cannot catch it: a proposal of a
// million "[" would end the process and every call in flight. So the depth is measured on
// the bytes first, by a pass that needs no stack of its own, and text nested deeper than
// any policy file is refused before the parser sees it.
//
// The same pass counts the structural characters that open or separate a value, which
// bounds the number of values the parser would build, so a caller can refuse a document
// of millions of tiny values before the parser allocates for them.
package guard

// MaxPolicyBytes is the largest policy tailkeeper reads or checks: 4 MiB, decoded.
// Tailscale publishes no cap of its own; this one is tailkeeper's. A policy over it is
// refused with its size, never cut.
const MaxPolicyBytes = 4 << 20

// MaxDepth is how many levels of braces and brackets HuJSON text may nest before it is
// refused unread. A policy file is a few levels deep.
const MaxDepth = 1000

// Result is what one pass over a text found.
type Result struct {
	// TooDeep reports that the braces and brackets nest more than the limit.
	TooDeep bool
	// Offset is the byte offset of the bracket that passed the limit, and Line its line
	// (counted by "\n", from 1). Both are zero unless TooDeep.
	Offset, Line int
	// NodeBound is an upper bound on the number of values the HuJSON parser builds for the
	// text: every opening brace or bracket, comma and colon outside strings and comments
	// starts at most one value, and so does the root. A member's name is a value too, and
	// its colon counts for it. The pass stops at the first level past the limit, so on
	// TooDeep it is a count of what was read.
	NodeBound int
}

// Scan reads t in one pass, as the HuJSON parser does: a string ends at its first quote
// that no backslash escapes, a line comment at the next line feed, and a block comment at
// the first "*/" after its "/*". A comment that does not end ends the text for it, as an
// error does for the parser. Closing a level that was never opened counts for nothing, so
// the depth reached is never less than the parser's.
func Scan[T ~string | ~[]byte](t T, limit int) Result {
	r := Result{NodeBound: 1}
	depth := 0
	n := len(t)
	for i := 0; i < n; i++ {
		switch t[i] {
		case '"':
			for i++; i < n && t[i] != '"'; i++ {
				if t[i] == '\\' {
					i++
				}
			}
		case '/':
			if i+1 == n {
				break
			}
			switch t[i+1] {
			case '/':
				j := i
				for j < n && t[j] != '\n' {
					j++
				}
				if j == n {
					return r
				}
				i = j
			case '*':
				j := i + 2
				for j+1 < n && (t[j] != '*' || t[j+1] != '/') {
					j++
				}
				if j+1 >= n {
					return r
				}
				i = j + 1
			}
		case '{', '[':
			r.NodeBound++
			if depth++; depth > limit {
				r.TooDeep, r.Offset, r.Line = true, i, 1
				for j := 0; j < i; j++ {
					if t[j] == '\n' {
						r.Line++
					}
				}
				return r
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		case ',', ':':
			r.NodeBound++
		}
	}
	return r
}

// NestsDeeperThan reports whether the braces and brackets in t, outside its strings and
// comments, nest more than limit levels deep.
func NestsDeeperThan[T ~string | ~[]byte](t T, limit int) bool {
	return Scan(t, limit).TooDeep
}
