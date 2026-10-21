package tools

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// loginPattern matches a login as a reply may write it: in any case, and with each at sign
// as @, as a JSON escape (backslash, u, 0040), as a brace escape (backslash, u, an opening
// brace, the code point 40 with any leading zeros, a closing brace) or as %40.
func loginPattern(login string) *regexp.Regexp {
	bs := string(rune(92))
	at := "(?:@|" + regexp.QuoteMeta(bs+"u0040") + "|" + regexp.QuoteMeta(bs+"u{") + "0*40" + regexp.QuoteMeta("}") + "|%40)"
	parts := strings.Split(login, "@")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return regexp.MustCompile("(?i)" + strings.Join(parts, at))
}

// hideLogin masks each match of p in text. A match is masked together with the local-part
// bytes that stand right before it, as one address: where amy@example.com was resolved,
// bigamy@example.com is another user's address, and masking the match alone would show
// "big".
func hideLogin(text string, p *regexp.Regexp) string {
	var b strings.Builder
	last := 0
	for _, m := range p.FindAllStringIndex(text, -1) {
		start := m[0]
		for start > last && sanitize.LocalByte(text[start-1]) {
			start--
		}
		b.WriteString(text[last:start])
		b.WriteString(sanitize.MaskIdentifier(text[start:m[1]]))
		last = m[1]
	}
	b.WriteString(text[last:])
	return b.String()
}

// hideLimit is the most of a text Hide reads. Every display is cut at 1 KiB after Hide, so
// what the limit drops is never shown, and the work of a call does not grow with the text.
const hideLimit = 4096

// maxLoginBytes is the longest address Hide looks for at the cut: 64 bytes of local part, an
// at sign and 255 of domain, each of them as long as a six-byte JSON escape can make it.
// The walk back stays under what the display shows: hideLimit less this is 2176 bytes,
// and every display is cut at 1 KiB.
const maxLoginBytes = 6 * 320

// addressByte reports whether c may belong to an address in any spelling the masker reads:
// a byte of a local part or a domain, an at sign, the backslash that starts a JSON or brace
// escape (the bytes after it are local bytes already) and the quote of a quoted word.
func addressByte(c byte) bool {
	return sanitize.LocalByte(c) || c == '@' || c == '\\' || c == '"'
}

// cutForHide cuts text to hideLimit bytes at a rune boundary. Where it cut, it also takes
// back whatever a login that began before the cut leaves in the text, in two steps:
//
//   - a start of a handed-out login: the end of the text, from a byte of the last
//     maxLoginBytes on, is the start of a login in any letter case with each at sign spelled
//     as the pattern reads it (see startsLogin). A login may hold bytes the address scan does
//     not read (a slash, a space, a quote around a word), so no walk over address bytes finds
//     where it began; the login itself says what it began with.
//   - the address bytes that end what is left, up to the longest address there is: a word
//     glued to the front of the login, the front of an address that is not a handed-out
//     login, and a local part spelled in escapes.
//
// Nothing of a login that straddles the cut remains, whichever way its at sign and its
// characters are spelled. The one exception is bounded by the work: a brace escape written
// with more than maxLoginBytes leading zeros.
func cutForHide(text string, logins []resolvedLogin) string {
	if len(text) <= hideLimit {
		return text
	}
	n := hideLimit
	for n > 0 && !utf8.RuneStart(text[n]) {
		n--
	}
	text = text[:n]
	return text[:dropAddressBytes(text[:dropLoginStart(text, logins)])]
}

// dropLoginStart returns the length text keeps once the start of a login, if it ends with
// one, is dropped: the leftmost byte, within maxLoginBytes of the end, from which the rest of
// the text is the start of a handed-out login.
func dropLoginStart(text string, logins []resolvedLogin) int {
	for s := max(0, len(text)-maxLoginBytes); s < len(text); s++ {
		if !utf8.RuneStart(text[s]) {
			continue
		}
		for _, l := range logins {
			if startsLogin(text[s:], l.parts) {
				return s
			}
		}
	}
	return len(text)
}

// dropAddressBytes returns the length text keeps once the address bytes that end it are
// dropped, up to the longest address there is, and any partial character that is left.
func dropAddressBytes(text string) int {
	n := len(text)
	for back := 0; n > 0 && back < maxLoginBytes && addressByte(text[n-1]); back++ {
		n--
	}
	for n > 0 && n < len(text) && !utf8.RuneStart(text[n]) {
		n--
	}
	return n
}

// prefixState is how far a piece of a login got along a text.
type prefixState int

const (
	prefixMismatch prefixState = iota // the text holds something the piece does not
	prefixEnded                       // the text ended before the piece did
	prefixDone                        // the piece was read whole and the text goes on, or ends with it
)

// startsLogin reports whether t is the start of a login, or the whole of one: the parts
// are the login split at its at signs, and t spells each at sign in any way loginPattern
// reads and every letter in any case. A start is every prefix of such a spelling.
func startsLogin(t string, parts []string) bool {
	for i, part := range parts {
		var st prefixState
		if i > 0 {
			if t, st = consumeAt(t); st != prefixDone {
				return st == prefixEnded
			}
		}
		if t, st = consumeFold(t, part); st != prefixDone {
			return st == prefixEnded
		}
	}
	return t == ""
}

// consumeAt reads one spelling of an at sign from the front of t: @, a JSON escape, a brace
// escape with any number of leading zeros, or %40, as loginPattern reads them.
func consumeAt(t string) (string, prefixState) {
	bs := string(rune(92))
	for _, lit := range []string{"@", "%40", bs + "u0040"} {
		if rest, st := consumeFold(t, lit); st != prefixMismatch {
			return rest, st
		}
	}
	rest, st := consumeFold(t, bs+"u{")
	if st != prefixDone {
		return rest, st
	}
	return consumeFold(strings.TrimLeft(rest, "0"), "40}")
}

// consumeFold reads lit from the front of t, in any letter case as the pattern does.
func consumeFold(t, lit string) (string, prefixState) {
	for lit != "" {
		if t == "" {
			return t, prefixEnded
		}
		lr, ln := utf8.DecodeRuneInString(lit)
		tr, tn := utf8.DecodeRuneInString(t)
		if !foldEqual(lr, tr) {
			return t, prefixMismatch
		}
		lit, t = lit[ln:], t[tn:]
	}
	return t, prefixDone
}

// foldEqual reports whether a and b are the same letter in some case, as (?i) reads them.
func foldEqual(a, b rune) bool {
	for r := unicode.SimpleFold(a); r != a; r = unicode.SimpleFold(r) {
		if r == b {
			return true
		}
	}
	return a == b
}

// Hide is the reverse map: it masks, in text that Tailscale wrote or echoed, every
// login this resolver has handed out, then every other address, all without pseudonyms. A
// reply repeats what was sent, and a pseudonym beside it would confirm a guess. The logins
// are replaced whole and longest first, so a login with a byte the address scan does not
// read (a slash) is not left half showing. A word glued to the front of a login (bigamy@ for
// amy@) is another user's address and is masked with it, from its first byte. The text is
// cut to hideLimit bytes first (see cutForHide), and a marker it holds is rewritten (the
// masker's Unforge): Hide appends no pseudonym, so a marker in the result would be one the
// text forged, and the registry's masking pass does not rewrite it. While personalData is
// show the text is returned as it came.
func (r *SubjectResolver) Hide(text string) string {
	if r.env.ShowPersonalData() {
		return text
	}
	resolved := r.state().users().resolved
	text = r.env.Masker().Unforge(cutForHide(text, resolved))
	for _, l := range resolved {
		text = hideLogin(text, l.pattern)
	}
	return sanitize.MaskEmails(text)
}

// HideError returns a copy of err, as a *tkerr.Error, with its message and hint passed
// through Hide. The code and the HTTP status are kept; the cause is dropped, since it may
// quote what Hide has just masked.
func (r *SubjectResolver) HideError(err error) error {
	if err == nil {
		return nil
	}
	fe := tkerr.From(err)
	if fe == nil {
		// A typed-nil *tkerr.Error is a non-nil error with nothing in it.
		fe = tkerr.New(tkerr.Internal, "unexpected internal error", "report this with `tailkeeper version` output")
	}
	e := *fe
	e.Message, e.Hint = r.Hide(e.Message), r.Hide(e.Hint)
	e.Err = nil
	return &e
}
