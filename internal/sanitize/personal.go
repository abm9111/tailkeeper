package sanitize

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// Personal data (spec Appendix C) in tool results is masked unless the owner opts
// in with "personalData": "show":
//
//   - A field tagged `tk:"personal"` holds an identifier people are known by: a
//     login name, display name or email address, or the tailnet ID. The whole value
//     is masked to its first character, plus the domain when the value is an
//     address: "amy@example.com" becomes "a…@example.com", "Amy Lee" becomes "A…".
//   - Every other field tagged `tk:"untrusted"` is free text from the tailnet or the
//     node. Email addresses in it are masked the same way, and each public IP address
//     is cut to its network (/24 for IPv4, /48 for IPv6, /40 for a 6to4 address,
//     whose next bits hold an IPv4 address), keeping a port; a prefix no narrower
//     than that network is kept. Tailnet, private, loopback and link-local addresses
//     are kept. This is a best effort over text: a name written in it, or an address
//     in an unusual form, is not found.
//   - `tk:"untrusted,plain"` exempts untrusted text whose addresses are configuration
//     a diagnosis needs, such as DNS resolvers and routes.
//   - `tk:"untrusted,emails"` masks only the email addresses in untrusted text whose
//     addresses are configuration, such as the policy file and the reasons a policy
//     test failed for.
//   - `tk:"untrusted,premasked"` is untrusted text the tool masked itself with
//     Masker.Text, because it cuts the text and must mask before it cuts. The
//     registry masks it again (Remask) but does not rewrite the pseudonym markers
//     the tool's own pass appended.
//
// Masking keeps what a question about the tailnet needs (whether a value is set,
// which provider or network, which rows share an initial) and drops what
// identifies a person. Values the system generates (IDs, enums, timestamps) carry
// no tag and are never masked.

// taggedDevices is the owner Tailscale reports for tagged devices, as login and
// display name. It names no person.
var taggedDevices = map[string]bool{"tagged-devices": true, "Tagged Devices": true}

// IsTaggedDevices reports whether s is the owner Tailscale reports for tagged
// devices, which names no person and is never masked.
func IsTaggedDevices(s string) bool { return taggedDevices[s] }

// Masker masks personal data. With a privacy key it also follows each masked
// identifier and email address with its pseudonym (spec Appendix C), so a
// model can tell values apart, and filter on them, without seeing them. The
// zero Masker masks without pseudonyms.
type Masker struct{ key *privacy.Key }

// NewMasker returns a Masker that names masked values under k; a nil k names
// nothing.
func NewMasker(k *privacy.Key) Masker { return Masker{key: k} }

// Identifier masks a login name, display name or email address, and appends its
// pseudonym when the value was masked. It is not idempotent on masked input:
// masking "a…@example.com [p:…]" again would name that text, so a personal field
// is masked once.
func (m Masker) Identifier(s string) string {
	out, ref := m.identifier(s)
	if ref == "" {
		return out
	}
	return out + privacy.Suffix(ref)
}

// IdentifierRefs returns the pseudonym a personal field holding s shows once it
// has been through Mask and then Fields with the byte cap max (0 means none):
// none when masking leaves s unchanged (an empty value, or the owner of tagged
// devices) or when the cap cuts the pseudonym off. As for TextRefs, a filter on a
// pseudonym the display does not show would confirm a guess at the value.
func (m Masker) IdentifierRefs(s string, max int) []string {
	out, ref := m.identifier(s)
	if ref == "" {
		return nil
	}
	if shown := String(tripwire.Redact(out+privacy.Suffix(ref)), max); !strings.Contains(shown, privacy.Suffix(ref)) {
		return nil
	}
	return []string{ref}
}

// identifier masks s and returns, besides the masked value, the pseudonym that
// follows it: empty when there is no key or masking changed nothing.
func (m Masker) identifier(s string) (out, ref string) { return m.quotedIdentifier(s, false) }

// quotedIdentifier is identifier for an address whose local part may have been quoted
// (see maskIdentifier); s holds it without its quotes.
func (m Masker) quotedIdentifier(s string, quoted bool) (out, ref string) {
	out = maskIdentifier(s, quoted)
	if m.key == nil || out == s {
		return out, ""
	}
	return out, m.key.Pseudonym(s)
}

// Text masks the email addresses and public IP addresses in free text. With a
// key it first rewrites every "[p:" the text holds (see unforged), so a pseudonym
// marker in the result is one Text appended and nothing else.
func (m Masker) Text(s string) string { return m.Emails(MaskAddrs(m.unforged(s))) }

// Remask is Text for text a tool already masked with Text: the same scan, so
// whatever escaping or cutting exposed since is masked too. It does not rewrite
// "[p:": every marker in text already through Text was appended by it, and the
// rewrite would destroy them. Only a field tagged premasked is masked this way.
func (m Masker) Remask(s string) string { return m.Emails(MaskAddrs(s)) }

// forgedOpen is what "[p:" becomes in free text, with the bracket spelled the way
// String spells a character it cannot show. Without it, a tailnet member could
// write " [p:xxxxxxxxxx]" into a name, and the display would show a pseudonym the
// masker never appended, beside an address the length cap hides: a filter reading
// the display could not tell a hidden address of the member's guess from any
// other. The bracket is the character spelled, not the colon, so the rewrite is
// not a character of the address after it: "[p:amy@example.com" keeps amy's
// own pseudonym.
var forgedOpen = fmt.Sprintf(`\u{%04X}p:`, '[')

// unforged rewrites every "[p:" in s, so that no marker in the text masked from
// it was written by whoever wrote s. Without a key nothing is appended, so
// nothing is rewritten.
func (m Masker) unforged(s string) string {
	if m.key == nil {
		return s
	}
	return strings.ReplaceAll(s, "[p:", forgedOpen)
}

// MaskIdentifier keeps the first character of a login name, display name or email
// address, and the domain when the whole value is an address.
func MaskIdentifier(s string) string { return maskIdentifier(s, false) }

// maskIdentifier is MaskIdentifier; quoted says that the local part, if s is an address,
// is the content of a quoted string, which may hold any byte: its quotes are gone.
func maskIdentifier(s string, quoted bool) string {
	if s == "" || taggedDevices[s] {
		return s
	}
	r, _ := utf8.DecodeRuneInString(s)
	masked := string(r) + marker
	if at := strings.IndexByte(s, '@'); at > 0 && address(s[:at], s[at+1:], quoted) {
		masked += s[at:]
	}
	return masked
}

// address reports whether local@domain is shaped like an email address: no
// spaces, brackets or second "@", so a display name such as "Amy Lee (@amylee)"
// keeps nothing after its first character. A quoted local part is not held to the
// bytes of an unquoted one.
func address(local, domain string, quoted bool) bool {
	if local == "" || domain == "" {
		return false
	}
	for i := 0; i < len(local) && !quoted; i++ {
		if n := braceEscapeLen(local[i:]); n > 0 {
			i += n - 1
		} else if !localByte(local[i]) {
			return false
		}
	}
	domain = domain[skipControls(domain):]
	if domain == "" {
		return false
	}
	for i := 0; i < len(domain); i++ {
		if !domainByte(domain[i]) {
			return false
		}
	}
	return true
}

// localByte and domainByte are the bytes of an email address's local part and
// domain. Bytes of non-ASCII characters count, so international addresses are
// found whole.
func localByte(c byte) bool {
	// RFC 5322 atext, less "/": it is rare in an address and common in a URL,
	// where it would carry the mask over the path. A control character other than
	// a tab or a line end is read as part of the address too: whoever put one
	// inside an address meant the mask to stop there, and it must not.
	return domainByte(c) || strings.IndexByte("!#$%&'*+=?^_`{|}~", c) >= 0 || controlByte(c)
}

// controlByte reports whether c is a control character that does not end text: not
// a tab, a line feed or a carriage return, which separate fields and lines.
func controlByte(c byte) bool {
	return c < 0x20 && c != '\t' && c != '\n' && c != '\r' || c == 0x7F
}

// braceEscapeLen is the length of the brace escape that s starts with, or 0: a backslash,
// u, a left brace, one to eight hex digits and a right brace. It is how sanitize.String
// shows a character it cannot show (\u{001B}), so text that has been through String, or
// that was written that way, spells a control character in an address with it.
func braceEscapeLen(s string) int {
	if len(s) < 5 || s[0] != '\\' || s[1] != 'u' || s[2] != '{' {
		return 0
	}
	for n := 3; n < len(s) && n <= 3+8; n++ {
		switch {
		case hexVal(s[n]) >= 0:
		case s[n] == '}' && n > 3:
			return n + 1
		default:
			return 0
		}
	}
	return 0
}

// braceEscapeBefore is the length of the brace escape that ends at s[end-1], not reaching
// back before last, or 0.
func braceEscapeBefore(s string, last, end int) int {
	if end-last < 5 || s[end-1] != '}' {
		return 0
	}
	i := end - 2
	for i >= last && end-2-i < 8 && hexVal(s[i]) >= 0 {
		i--
	}
	if i < last+2 || s[i] != '{' || i == end-2 || s[i-1] != 'u' || s[i-2] != '\\' {
		return 0
	}
	return end - (i - 2)
}

// controlLen is the length of the control character that s starts with, in one byte,
// as the three bytes of its percent-encoding ("%00") or as a brace escape, or 0.
func controlLen(s string) int {
	switch {
	case s == "":
		return 0
	case controlByte(s[0]):
		return 1
	case s[0] == '\\':
		return braceEscapeLen(s)
	case len(s) >= 3 && s[0] == '%':
		// Two hex digits make at most 0xFF: the mask drops nothing.
		if hi, lo := hexVal(s[1]), hexVal(s[2]); hi >= 0 && lo >= 0 && controlByte(byte((hi<<4|lo)&0xFF)) {
			return 3
		}
	}
	return 0
}

// skipControls is the length of the control characters s starts with. They are read
// through directly after an at sign as they are before one: a domain that begins
// with one is a domain, and the mask must not stop at the at sign.
func skipControls(s string) int {
	n := 0
	for m := controlLen(s); m > 0; m = controlLen(s[n:]) {
		n += m
	}
	return n
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func domainByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c >= 0x80
}

// MaskText masks the email addresses and public IP addresses in free text.
func MaskText(s string) string { return Masker{}.Text(s) }

// MaskEmails masks every email address in s: each "@" with a local part before it
// and a domain after it. "ask amy@example.com." becomes "ask a…@example.com.".
// A JSON escape such as \u0061 counts as one character of an address, and \u0040
// as an "@": a policy file can spell a login that way, and Tailscale reads it as
// one. A chain such as a@b@c.d is masked whole, to its first character: masking
// a@b alone would leave b@c.d.
func MaskEmails(s string) string { return Masker{}.Emails(s) }

// Emails masks every email address in s, as MaskEmails does, and names each one
// when m has a key.
func (m Masker) Emails(s string) string {
	out, _ := m.emails(s)
	return out
}

// EmailRefs returns, in order, the pseudonyms Emails appends to s: one for each
// address it masks, found by the same scan. A filter on a pseudonym matches
// exactly the text that shows it only if it asks this scan and not its own.
func (m Masker) EmailRefs(s string) []string {
	_, refs := m.emails(s)
	return refs
}

// TextRefs returns the distinct pseudonyms, in order of first appearance, that
// an untrusted string shows once it has been through Mask and then Fields with
// the byte cap max (0 means none): those Text appends, less any the credential
// redaction or the cap cut off. A pseudonym that is not displayed must not match
// a filter, or a guess at a hidden value could be confirmed by asking for it.
//
// Whether one survived is read off the displayed text. That is sound because
// Text rewrites every "[p:" the string holds before it names an address: a
// marker in the display is one Text appended, so what the display shows is
// exactly what it appended, less what the cap cut.
func (m Masker) TextRefs(s string, max int) []string {
	masked, refs := m.emails(MaskAddrs(m.unforged(s)))
	if len(refs) == 0 {
		return nil
	}
	shown := String(tripwire.Redact(masked), max)
	var kept []string
	for _, r := range refs {
		if !slices.Contains(kept, r) && strings.Contains(shown, privacy.Suffix(r)) {
			kept = append(kept, r)
		}
	}
	return kept
}

// emails masks the addresses in s and returns the pseudonyms it appended.
func (m Masker) emails(s string) (string, []string) {
	if !strings.Contains(s, "@") && !strings.Contains(s, jsonAt) && !strings.Contains(s, pctAt) {
		return s, nil
	}
	var refs []string
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); i++ {
		at := 1
		if s[i] != '@' {
			if at = atLen(s[i:]); at == 0 {
				continue
			}
		}
		// Neither scan crosses the mask marker, so a masked identifier never joins
		// another address, and masking what MaskEmails returned changes nothing.
		// The local part stops at an earlier at sign, escaped or not, and an at
		// sign with no local part is passed over before the domain is scanned:
		// either way a run of at signs would be rescanned once for each of them.
		//
		// A quoted word ("amy"@example.com, or "amy".smith@example.com) is read back to its
		// opening quote, and its quotes are no part of the name. A quote that follows other
		// local bytes and no full stop ends the address, as it does when nothing is quoted.
		//
		// A quoted word is read only for an at sign with a domain. A chain crosses the
		// at signs it holds, each of which has a quote right after it and so no domain:
		// reading back from every one of those would cross all the ones before it.
		start := i
		domain, end := -1, 0 // where the domain starts and ends, found when first needed
		var quotes [][2]int  // the quotes of the quoted words, as byte ranges of s
		quoted := false      // the last thing read was a quoted word
		for start > last && !strings.HasSuffix(s[last:start], marker) {
			chain := 0 // the length of an at sign, in any spelling, right before a quoted word
			if quoted {
				switch {
				case s[start-1] == '@':
					chain = 1
				case strings.HasSuffix(s[last:start], jsonAt):
					chain = len(jsonAt)
				case strings.HasSuffix(s[last:start], pctAt):
					chain = len(pctAt)
				}
			}
			quoted = false
			if chain > 0 {
				start -= chain // a chain, as a@b@c.d is one: the address before the quoted word is masked with it
			} else if e := s[max(start-len(jsonAt), last):start]; uEscape(e) && e != jsonAt {
				start -= len(jsonAt)
			} else if strings.HasSuffix(s[last:start], pctAt) {
				break // an earlier at sign, percent-encoded: its characters are local bytes
			} else if n := braceEscapeBefore(s, last, start); n > 0 {
				start -= n // a control character spelled \u{0001}, as String shows one
			} else if localByte(s[start-1]) {
				start--
			} else if s[start-1] != '"' {
				break // no closing quote
			} else {
				if domain < 0 {
					domain, end = domainEnd(s, i+at)
				}
				if end == domain {
					break // no domain, so no address to read a quoted word for
				}
				open, from, to := quotedWord(s, last, start)
				if open < 0 || (start != i && s[start] != '.') {
					break
				}
				quotes = append(quotes, [2]int{open, from}, [2]int{to, start})
				start, quoted = open, true
			}
		}
		if start == i {
			continue
		}
		if domain < 0 {
			domain, end = domainEnd(s, i+at)
		}
		if end == domain {
			continue
		}
		text := s[start:end]
		if len(quotes) > 0 {
			// Quotes that split an at sign ("%4" "0") are kept: taking them out would make
			// an at sign, so the address is masked as it stands, from its first byte.
			if stripped := withoutRanges(s, start, end, quotes); atSigns(stripped) == atSigns(text) {
				text = stripped
			}
		}
		b.WriteString(s[last:start])
		out, ref := m.quotedIdentifier(strings.ReplaceAll(strings.ReplaceAll(text, jsonAt, "@"), pctAt, "@"), len(quotes) > 0)
		b.WriteString(out)
		if ref != "" {
			b.WriteString(privacy.Suffix(ref))
			refs = append(refs, ref)
		}
		last, i = end, end-1
	}
	b.WriteString(s[last:])
	return b.String(), refs
}

// domainEnd reads the domain after an at sign, from the byte after it: where it starts,
// once the control characters at its start are passed, and where it ends. A full stop
// that ends the sentence is no part of it. It is empty when the two are the same.
func domainEnd(s string, from int) (domain, end int) {
	end = from + skipControls(s[from:])
	domain = end
	for end < len(s) && !strings.HasPrefix(s[end:], marker) {
		if domainByte(s[end]) || s[end] == '@' {
			end++
		} else if uEscape(s[end:min(end+len(jsonAt), len(s))]) {
			end += len(jsonAt)
		} else if strings.HasPrefix(s[end:], pctAt) {
			end += len(pctAt)
		} else {
			break
		}
	}
	for end > domain && s[end-1] == '.' {
		end-- // a full stop ends the sentence, not the domain
	}
	return domain, end
}

// quotedWord reads the quoted word that ends at s[end-1], a double quote, back to the
// nearest opening quote of its kind that is not before last and has no line end between:
// its first byte, where its opening quote ends and where its closing quote starts. In
// JSON text both quotes are spelled \" . Where no quote of its kind opens it, the nearest
// quote of the other kind does (a closing quote and an opening \" , from text that mixes
// the two). A word with nothing in it, or none that opens, is no quoted word (open is -1).
func quotedWord(s string, last, end int) (open, from, to int) {
	if s[end-1] != '"' {
		return -1, 0, 0
	}
	to = end - 1
	escaped := to-1 >= last && s[to-1] == '\\'
	if escaped {
		to--
	}
	other := -1 // the nearest quote of the other kind
scan:
	for p := to - 1; p >= last; p-- {
		switch s[p] {
		case '\n', '\r':
			break scan
		case '"':
			if (p-1 >= last && s[p-1] == '\\') != escaped {
				if other < 0 {
					other = p
				}
				continue
			}
			open, from = p, p+1
			if escaped {
				open--
			}
			if from >= to {
				return -1, 0, 0
			}
			return open, from, to
		case marker[len(marker)-1]:
			if p >= len(marker)-1 && s[p-len(marker)+1:p+1] == marker {
				break scan // masked text before this point
			}
		}
	}
	if other >= 0 && other+1 < to {
		if !escaped {
			return other - 1, other + 1, to // the backslash before the opening quote is part of it
		}
		return other, other + 1, to
	}
	return -1, 0, 0
}

// atSigns is how many at signs s holds, in the three spellings.
func atSigns(s string) int {
	return strings.Count(s, "@") + strings.Count(s, jsonAt) + strings.Count(s, pctAt)
}

// withoutRanges is s[start:end] without the quotes of the quoted words read back from the
// at sign: an opening and a closing range for each word, the last word first.
func withoutRanges(s string, start, end int, quotes [][2]int) string {
	var b strings.Builder
	pos := start
	for w := len(quotes) - 2; w >= 0; w -= 2 {
		b.WriteString(s[pos:quotes[w][0]])
		b.WriteString(s[quotes[w][1]:quotes[w+1][0]])
		pos = quotes[w+1][1]
	}
	b.WriteString(s[pos:end])
	return b.String()
}

// marker is what masking puts in place of the characters it removes.
const marker = "…"

// jsonAt is "@" as a JSON escape, and pctAt as a URL escape: a policy file may
// spell a login the first way, a URL that carries an address the second.
const (
	jsonAt = `\u0040`
	pctAt  = "%40"
)

// atLen is the length of the escaped at sign that starts s, or 0.
func atLen(s string) int {
	switch {
	case strings.HasPrefix(s, jsonAt):
		return len(jsonAt)
	case strings.HasPrefix(s, pctAt):
		return len(pctAt)
	}
	return 0
}

// uEscape reports whether e is a JSON escape of one UTF-16 code unit, \uXXXX.
func uEscape(e string) bool {
	if len(e) != len(jsonAt) || e[0] != '\\' || e[1] != 'u' {
		return false
	}
	for i := 2; i < len(e); i++ {
		if c := e[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// tailnetRange is Tailscale's IPv4 range (the shared address space). Its IPv6
// range is a unique local prefix, which netip already counts as private.
var tailnetRange = netip.MustParsePrefix("100.64.0.0/10")

// reservedV6 is the IETF-reserved block at the start of IPv6, which also holds the
// deprecated IPv4-compatible form. Text that parses as an address there is far
// more often something else: "std::bad_alloc" holds "::bad", and an EUI-64 MAC
// such as 00:1a:2b:ff:fe:3c:4d:5e has eight groups.
var reservedV6 = netip.MustParsePrefix("::/8")

// sixToFour holds 6to4 addresses, whose bits 16-47 are an IPv4 address.
var sixToFour = netip.MustParsePrefix("2002::/16")

// MaskAddrs cuts every public IP address in s to its network. Masked text masks
// to itself.
//
// An address is found at the end of a run of address characters, however the run
// begins: a label that ends in a hex digit or a letter ("ipv6:2001:db8::1",
// "eth0:2001:db8::/48"), a name and a full stop ("ipv6.203.0.113.7"), or an escape
// that ends in a digit ("%22203.0.113.7") all run into the address, and read as part
// of it they hide it. The run is read again from each place an address can start
// in it (see starts), so what the label is glued to does not matter.
//
// A dotted number is read first for the addresses it holds anywhere (see maskWindows),
// since an address need not end it ("203.0.113.7.443"). Masking can make a new run of
// text: "123." and the "8.8.8.0/24" that "::ffff:8.8.8.8" is cut to read as the number
// 123.8.8.8.0/24, which holds an address again, and a network that masking wrote can be
// followed by the digits of the next address. So the text is masked again until nothing
// changes, at most maxRounds times.
func MaskAddrs(s string) string {
	for range maxRounds {
		next := maskAddrs(maskWindows(s), true)
		if next == s {
			break
		}
		s = next
	}
	return s
}

// maxRounds bounds how often MaskAddrs masks its own output. Text of any real shape
// needs one round or two for the seams between masked and unmasked text; a prefix that
// is wider than its address's first number cuts one digit of a glued number in each
// round, which is no reason to read an input as many times as it has digits, so the time
// stays linear.
const maxRounds = 4

// maskAddrs masks the runs of s. With settle, an address read from behind a label is
// masked once more together with the label (see maskAt).
func maskAddrs(s string, settle bool) string {
	if !strings.ContainsAny(s, ".:") {
		return s // every address literal has a dot or a colon
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if !addrByte(s[i]) {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && addrByte(s[j]) {
			j++
		}
		out, end := maskEscapedRun(s, i, j, settle)
		b.WriteString(out)
		i = end
	}
	return b.String()
}

// A part is one number of a dotted number: s[start:end], digits only.
type part struct{ start, end int }

// maskWindows masks the public IPv4 addresses that a dotted number holds wherever they
// sit in it. maskAddrs reads a run for the address that ends it, which leaves undone an
// address that more digits follow ("203.0.113.7.443", as tcpdump and netstat print an
// address and a port; "8.8.8.8.1"). A window is four consecutive parts of a dotted number
// of five parts or more, or of four whose first part is no octet. It is an address when
// each part is an octet (at most 255, no leading zero) and the four make a public
// address; see firstIsPublic for the first part, which a name's, an escape's or another
// number's digits run into. The first window that is an address is masked by replacing
// its fourth part with "0/24", every window that shares that part is masked with it, and
// the count resumes after it. So the digit a name ends in and the first three parts of
// the address after it are an address that is cut at its third part ("ens5.203.0.113.7"
// holds 5.203.0.113 as well as 203.0.113.7), where a name that ends in 0 makes none
// (0.203.0.113 is no one's). The prefix length after a masked network is no part of a
// window ("/24" of "203.0.113.0/24.9.9.9.9.9"), so that masked text masks to itself.
// Where the part is the last of a number that "/bits" follow, the bits are the ones to
// keep and "0" replaces the part (so the network "203.0.113.0/24" stays as it is):
// maskRun cuts the prefix to its network afterwards. Each window is read in a constant
// number of steps, so the time is linear in the text.
func maskWindows(s string) string {
	if !strings.Contains(s, ".") {
		return s
	}
	var b strings.Builder
	var parts []part
	var hits []int
	copied := 0
	for i := 0; i < len(s); {
		if !isDigit(s[i]) {
			i++
			continue
		}
		parts = parts[:0]
		for p := i; ; {
			q := p
			for q < len(s) && isDigit(s[q]) {
				q++
			}
			parts = append(parts, part{p, q})
			if q+1 < len(s) && s[q] == '.' && isDigit(s[q+1]) {
				p = q + 1
				continue
			}
			i = q
			break
		}
		first := 0 // the first part that can start a window
		glued := false
		if followsNetwork(s, parts[0].start, parts[0].end) {
			first = 1 // the prefix length of a masked network
			if p := parts[0]; p.end-p.start >= 2 && s[p.start-3:p.start-1] == ".0" {
				// ... but a prefix length is one or two digits up to 32 ("/24"). Two digits
				// above that are the start of an address ("/88.9.9.9"), and a longer number
				// holds the first digits of the next one ("/24198.51.100.231").
				switch v := (s[p.start]-'0')*10 + (s[p.start+1] - '0'); {
				case v > 32 && p.end-p.start == 2:
					first, glued = 0, true
				case v > 32:
					parts[0].start++
					first, glued = 0, true
				case p.end-p.start > 2:
					parts[0].start += 2
					first, glued = 0, true
				}
			}
		}
		n := len(parts)
		if n-first < 4 || n-first == 4 && first == 0 && !glued && octet(s[parts[first].start:parts[first].end]) >= 0 {
			continue // a lone address is read as a run
		}
		// "/bits" follow the number: not when a dotted number of four parts or more does, which
		// is an address (see bitsEnd), unless the slash follows a network that masking wrote.
		bits := i+1 < len(s) && s[i] == '/' && isDigit(s[i+1]) &&
			(followsNetwork(s, i+1, digitsEnd(s, i+1)) || partsFrom(s, i+1, 4) < 4)
		hits = hits[:0]
		escape := escapeDigits(s, parts[0].start)
		for k := first; k+3 < n; {
			if windowIsPublic(s, parts, k, escapeOf(k, escape)) {
				hits = append(hits, k+3)
				k += 4
			} else {
				k++
			}
		}
		for _, h := range hits {
			b.WriteString(s[copied:parts[h].start])
			if h == n-1 && bits {
				b.WriteString("0")
			} else {
				b.WriteString("0/24")
			}
			copied = parts[h].end
		}
	}
	if copied == 0 {
		return s
	}
	b.WriteString(s[copied:])
	return b.String()
}

// windowIsPublic reports whether the four parts from k make a public IPv4 address. The
// first of them is read by its last one to three digits if it is no octet: a name's or
// an escape's digits ran into it, or the number is two glued together ("10.0.0.53" and
// "198.51.100.231" make 10.0.0.53198.51.100.231). escape is the number of its leading
// digits that may be an escape's (0 if none).
func windowIsPublic(s string, parts []part, k, escape int) bool {
	var rest [3]int
	for x := range rest {
		if rest[x] = octet(s[parts[k+1+x].start:parts[k+1+x].end]); rest[x] < 0 {
			return false
		}
	}
	return firstIsPublic(s[parts[k].start:parts[k].end], escape, rest, false)
}

// escapeDigits is the number of digits after s[start-1] that an escape before them
// takes: two after "%" or a backslash and x, four after a backslash and u.
func escapeDigits(s string, start int) int {
	switch {
	case start >= 1 && s[start-1] == '%':
		return 2
	case start >= 2 && s[start-2] == '\\' && s[start-1] == 'x':
		return 2
	case start >= 2 && s[start-2] == '\\' && s[start-1] == 'u':
		return 4
	}
	return 0
}

// firstIsPublic reports whether head and the three octets after it make a public
// address. A head that is an octet is that octet: 0 makes no address, unless zero says
// that 0.0.0.0/8 counts as public, as public does. One that is no octet is read by its
// last one to three digits, none of which makes an address from 0. But if its first
// escape digits are an escape's ("%22" before 192.168.1.1), only two readings count, as
// they are read when the escape is the first thing in a run: the digits after the
// escape's, and the head itself, or the longest octet it ends in if it is none. A
// shorter reading would make a private address public.
func firstIsPublic(head string, escape int, rest [3]int, zero bool) bool {
	ok := func(o int) bool { // o and rest are octets, 0 to 255: the masks drop nothing
		return public(netip.AddrFrom4([4]byte{byte(o & 0xFF), byte(rest[0] & 0xFF), byte(rest[1] & 0xFF), byte(rest[2] & 0xFF)}))
	}
	o := octet(head)
	if o >= 0 && (o != 0 || zero) && ok(o) {
		return true
	}
	if escape > 0 && len(head) > escape {
		if a := octet(head[escape:]); a > 0 && ok(a) {
			return true
		}
		if o >= 0 {
			return false
		}
		for n := 3; n >= 1; n-- {
			if n <= len(head) {
				if b := octet(head[len(head)-n:]); b >= 0 {
					return b > 0 && ok(b)
				}
			}
		}
		return false
	}
	if o >= 0 {
		return false
	}
	for n := 1; n <= 3 && n <= len(head); n++ {
		if b := octet(head[len(head)-n:]); b > 0 && ok(b) {
			return true
		}
	}
	return false
}

// octet reads a decimal octet: one to three digits, no leading zero, at most 255. It
// returns -1 for anything else.
func octet(t string) int {
	if len(t) == 0 || len(t) > 3 || len(t) > 1 && t[0] == '0' {
		return -1
	}
	n := 0
	for i := 0; i < len(t); i++ {
		n = n*10 + int(t[i]-'0')
	}
	if n > 255 {
		return -1
	}
	return n
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// escapeOf is the number of leading digits of the part that starts the window at k that
// an escape may have taken: only the number's first part follows an escape.
func escapeOf(k, escape int) int {
	if k == 0 {
		return escape
	}
	return 0
}

// maskEscapedRun masks the run s[i:j] and returns the text that replaces s up to the
// returned end. When the run follows what could be an escape, "%22" or a backslash
// and x or u with their digits, the digits may be the escape's or the address's, and
// the text is read both ways: the escape's digits are not the start of what follows
// them ("%22" before 10.0.0.53 is not "2210.0.0.53"), but a reader who takes the
// backslash and x for two ordinary characters sees 52.94.236.248 in "\x52.94.236.248",
// and sees 8.8.8.8 in "%228.8.8.8" whatever 228.8.8.8 is. A public address in either
// reading is masked. The reading with the escape's digits left out is used when it
// masks an address from the start of what follows them; otherwise the run is read
// from its start, and if that masks something, or is one address that is not public,
// it is used.
func maskEscapedRun(s string, i, j int, settle bool) (string, int) {
	skip := escapeLen(s, i, j)
	if skip == 0 {
		out, end, _ := maskRun(s, i, j, settle)
		return out, end
	}
	outA, endA, fA := maskRun(s, i+skip, j, settle)
	if fA.reading == masked && fA.start == i+skip {
		return s[i:i+skip] + outA, endA
	}
	outB, endB, fB := maskRun(s, i, j, settle)
	if fB.reading == kept && fB.start == i && s[i-1] != '%' && outA != s[i+skip:endA] {
		// A backslash and x or u is an escape, whatever follows: "\xfd7a:115c:a1e0::1" is
		// the byte 0xfd and "7a:115c:a1e0::1", not a tailnet address behind a stray "\x".
		// (After a percent sign that may be a sign and no escape, the tailnet address wins.)
		return s[i:i+skip] + outA, endA
	}
	if outB != s[i:endB] || fB.reading == kept && fB.start == i {
		// Read from its start the run is a public address, or is all one address that
		// locates nobody ("ipv6%fd7a:115c:a1e0::1", a tailnet address after a percent
		// sign), which the escape's reading with a later start does not outweigh.
		return outB, endB
	}
	return s[i:i+skip] + outA, endA
}

// escapeLen is the number of hex digits at the start of the run s[i:j] that may belong
// to the escape before it: two after a "%" or a backslash and x, four after a
// backslash and u.
func escapeLen(s string, i, j int) int {
	n := 0
	switch {
	case i >= 1 && s[i-1] == '%':
		n = 2
	case i >= 2 && s[i-2] == '\\' && s[i-1] == 'x':
		n = 2
	case i >= 2 && s[i-2] == '\\' && s[i-1] == 'u':
		n = 4
	}
	if i+n > j {
		return 0
	}
	for _, c := range []byte(s[i : i+n]) {
		if hexVal(c) < 0 {
			return 0
		}
	}
	return n
}

// addrByte reports whether c can be part of an IP address or address:port
// literal. Brackets and zones end a run, so "[v6]:port" splits into the address
// and the port.
func addrByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == '.' || c == ':'
}

// A reading is what a stretch of a run makes when it is read as an address.
type reading int

const (
	unread   reading = iota // no address
	reserved                // an address in ::/8: a label's digits and the address after it read together, or no address at all
	kept                    // an address that locates nobody: private, tailnet, loopback, link-local, multicast
	masked                  // a public address
)

// classify reads what a valid address is.
func classify(a netip.Addr) reading {
	switch {
	case public(a):
		return masked
	case reservedV6.Contains(a.Unmap()):
		return reserved
	}
	return kept
}

// A found is a stretch of a run read as an address, and what to do with it.
type found struct {
	reading
	text   string // for a public address, its network, and the port or "/bits" it carried
	start  int    // where the address starts in the text
	embeds bool   // an IPv6 address with an IPv4 address written in it
	dotted bool   // an IPv4 address
}

// readAddr reads all of sub as an address, or as an IPv4 address and port (brackets
// end a run, so an IPv6 address arrives without its port).
func readAddr(sub string) found {
	a, err := netip.ParseAddr(sub)
	port := ""
	if err != nil {
		// A port is five digits at most: only a colon among the last six bytes can
		// start one, so a long run is not searched for it.
		lo := max(0, len(sub)-6)
		c := strings.LastIndexByte(sub[lo:], ':')
		if c < 0 {
			return found{}
		}
		ap, err := netip.ParseAddrPort(sub)
		if err != nil {
			return found{}
		}
		a, port = ap.Addr(), sub[lo+c:]
	}
	f := found{reading: classify(a), dotted: a.Is4(), embeds: embedsIPv4(a, sub)}
	if f.reading == masked {
		f.text = network(a) + port
	}
	return f
}

// embedsIPv4 reports whether sub, which reads as a, is an IPv6 address with an IPv4
// address written inside it ("64:ff9b::203.0.113.7"), which is not "::ffff:" and the
// IPv4 address after it.
func embedsIPv4(a netip.Addr, sub string) bool {
	return a.Is6() && !a.Is4In6() && strings.IndexByte(sub, '.') >= 0
}

// readPrefix reads all of sub as an address and a "/bits": a narrower prefix than
// the network is cut to it, and a wider one loses only its host bits, so a network
// written by MaskAddrs is kept. "::ffff:203.0.113.0/24" is the IPv4 prefix at its
// tail, which a later start reads.
func readPrefix(sub string) found {
	p, err := netip.ParsePrefix(sub)
	if err != nil || p.Addr().Is4In6() {
		return found{}
	}
	f := found{reading: classify(p.Addr()), dotted: p.Addr().Is4(), embeds: embedsIPv4(p.Addr(), sub)}
	if f.reading == masked {
		f.text = p.Masked().String() // "203.0.113.9/24" names an address too
		if p.Bits() > networkBits(p.Addr()) {
			f.text = network(p.Addr())
		}
	}
	return f
}

// maskRun masks the run s[i:j] and returns the text that replaces s up to the
// returned end: j, or the end of a "/bits" that follows the run, when the run ends
// in a prefix. It also returns what the run was read as.
func maskRun(s string, i, j int, settle bool) (string, int, found) {
	k := bitsEnd(s, i, j)
	var res struct {
		out string
		end int
		f   found
	}
	if k > j {
		out, _, f := maskAt(s, i, j, k, "", settle, 1)
		if f.reading == masked || f.reading == kept {
			return out, k, f
		}
		if f.reading == reserved {
			// Read as a prefix the run is text that is no address, such as the IPv4-in-IPv6
			// form "20::ffff:8.8.8.8/64"; read without the bits, "::ffff:8.8.8.8" is one.
			res.out, res.end, res.f = out, k, f
		}
	}
	out, end, f := maskAt(s, i, j, j, s[j:k], settle, 1)
	if f.reading == masked || f.reading == kept || f.reading == reserved && res.f.reading == unread {
		return out, end, f
	}
	if res.f.reading == reserved {
		return res.out, res.end, res.f
	}
	mout, usedBits := maskIPv4WithinBits(s[i:j], s[j:k])
	if usedBits {
		return mout, k, found{start: -1}
	}
	return mout, j, found{start: -1}
}

// bitsEnd is the end of the "/bits" that follows the run ending at j, or j.
//
// What follows a slash is not bits when it is an address: "1.1.1.1/8.8.8.8" holds two
// addresses, not the prefix 1.1.1.1/8 and the text .8.8.8. That is the case when the
// number after the slash has four parts or more, unless the slash follows a network that
// masking wrote (see followsNetwork: "203.0.113.0/24.5.6.7"), where the prefix length
// comes first in what follows. Three digits above 128 are no prefix length;
// after a network as masking writes it (/24, /48, /40) they are the prefix length and
// the first digit of the next number ("/24198" is /24 and 198).
func bitsEnd(s string, i, j int) int {
	k := j
	if k < len(s) && s[k] == '/' {
		k++
		for k < len(s) && k-j <= 3 && isDigit(s[k]) {
			k++
		}
		if k-j == 4 && int(s[j+1]-'0')*100+int(s[j+2]-'0')*10+int(s[j+3]-'0') > 128 {
			// Three digits above 128 are no prefix length. After a network as masking writes
			// it ("203.0.113.0/24", "2001:db8::/48", "2002:cb00:7100::/40") they are the
			// prefix length and the first digit of the next number ("/24198").
			net := s[j+1 : j+3]
			switch {
			case j >= 2 && s[j-2:j] == ".0" && strings.IndexByte(s[i:j], ':') < 0 && net == "24",
				j >= 2 && s[j-2:j] == "::" && (net == "48" || net == "40"):
				k = j + 3
			}
		}
	}
	if k <= j+1 {
		return j
	}
	if !followsNetwork(s, j+1, digitsEnd(s, j+1)) && partsFrom(s, j+1, 4) >= 4 {
		return j
	}
	return k
}

// followsNetwork reports whether the number s[start:end] begins with the prefix length of
// a network that masking wrote: the slash before it follows ".0" (the network
// "203.0.113.0/24"), or "::" and the length is 48 or 40 ("2001:db8::/48").
func followsNetwork(s string, start, end int) bool {
	if start < 3 || s[start-1] != '/' {
		return false
	}
	switch s[start-3 : start-1] {
	case ".0":
		return true
	case "::":
		return s[start:end] == "48" || s[start:end] == "40"
	}
	return false
}

// digitsEnd is the end of the digits that start at s[i].
func digitsEnd(s string, i int) int {
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return i
}

// partsFrom counts the numbers that full stops join from s[p], up to max.
func partsFrom(s string, p, max int) int {
	n := 0
	for n < max {
		q := p
		for q < len(s) && isDigit(s[q]) {
			q++
		}
		if q == p {
			break
		}
		n++
		if q+1 >= len(s) || s[q] != '.' {
			break
		}
		p = q + 1
	}
	return n
}

// maskAt reads the run s[i:j] as glue and an address that ends it, or, when k > j,
// as glue and a prefix that ends at k, and returns s[i:k] masked, with the end of what it
// masked and what the address was. The address starts at the first candidate (see starts)
// that reads as a public address, so the whole of what the label might hide is masked: a
// text in the reserved block is read again from a later start, and one that is another
// kind of address stays as it is and ends the search (in a run that holds two "::", a
// reading after the first is kept only when no later one is public). The address may end
// where the run does, before the colons and full stops that end it, or before the last
// "::" of a run that holds two. What comes before it is masked as glue (maskGlue) and
// what comes after it as text: an IPv4 address in it, with bits, the "/bits" that
// follow a run that is not read as a prefix, if it ends the run. Nothing is returned when
// no start reads as an address. depth is 1 for a run, and 0 for glue read as a run: glue
// is never the whole of its run, and is not read for a glue of its own.
func maskAt(s string, i, j, k int, bits string, settle bool, depth int) (string, int, found) {
	ends := []int{j}
	// Glue that ends in a colon (depth 0) is the front of a longer run: its eight groups after
	// a "::" are not an address of their own, as they are where the run ends.
	open := depth == 0 && j > i && s[j-1] == ':'
	portFrom := -1     // the ends from here on are those before a colon and a port
	var stopEnds []int // the ends before a full stop and more, tried when nothing else reads
	if k == j {
		// A full stop or a colon after an address ends the sentence, not the address; but
		// an address may end in "::" ("2001:db8::.").
		if e := trimEnd(s, i, j); e > i && e < j {
			if j-e > 2 && s[e] == ':' && s[e+1] == ':' {
				ends = append(ends, e+2)
			}
			ends = append(ends, e)
		}
		// So may an IPv6 address that a port follows after a full stop, as tcpdump writes
		// it ("2001:db8::1.443").
		for _, e := range slices.Clone(ends) {
			if d := strings.LastIndexByte(s[i:e], '.') + i; d > i && e-d <= 6 && e-d > 1 && digitsEnd(s, d+1) >= e && strings.IndexByte(s[i:d], ':') >= 0 {
				ends = append(ends, d)
			}
		}
		// A second "::" begins text that is no part of an address: "2001:db8::1::5".
		if e := strings.LastIndex(s[i:j], "::") + i; e > i && strings.Contains(s[i:e], "::") {
			ends = append(ends, e)
		}
		// Or one that a port follows after a colon ("2001:db8::1:41641", "2001:db8:::443"), or
		// after a full stop whatever its length ("2001:db8::1.100022"). These ends come last,
		// since the run is read whole first: a colon and digits are one more group of the
		// address where the two make an address ("2001:db8::1:4164"), and the port after it
		// where they do not.
		portFrom = len(ends)
		for _, e := range slices.Clone(ends) {
			if c := strings.LastIndexByte(s[i:e], ':') + i; c > i && e-c > 1 && digitsEnd(s, c+1) >= e {
				ends = append(ends, c)
				if c-1 > i && s[c-1] == ':' {
					ends = append(ends, c-1) // a port after "::": the address ends before both colons
				}
			}
			if d := strings.LastIndexByte(s[i:e], '.') + i; d > i && e-d > 6 && digitsEnd(s, d+1) >= e && strings.IndexByte(s[i:d], ':') >= 0 {
				ends = append(ends, d)
			}
		}
		// Or one that a full stop and more follow: a word that starts with a letter a to f is
		// part of the run ("2001:db8::1.Error"), and so are numbers ("2001:db8::1.5.6"), and a
		// colon may follow them ("2001:db8::1.dead:443"). A full stop belongs to the literal
		// only in an IPv4 address at its end, which the whole run is read for first, so the
		// address ends before the first full stop after its last colon, or after its first.
		// A colon and a port may stand before the full stop, as they may at the end of the
		// run ("2001:db8::1:41641.example.com", "2001:db8::1:41641:.Error"): the address
		// ends before the colons that end it, after the end before the full stop, and then
		// before the port.
		// These ends are tried only when no reading above is made, not even a reserved one,
		// and the run holds no IPv4 address to mask: that one is masked first, and the run
		// read again ("dead::198.51.100.247a" is not "dead::198" and a tail).
		addStop := func(e int) {
			if !slices.Contains(stopEnds, e) {
				stopEnds = append(stopEnds, e)
			}
		}
		for _, e := range ends[:portFrom] {
			for _, c := range []int{strings.LastIndexByte(s[i:e], ':'), strings.IndexByte(s[i:e], ':')} {
				if c >= 0 {
					if d := strings.IndexByte(s[i+c:e], '.'); d > 0 && !slices.Contains(stopEnds, i+c+d) {
						stop := i + c + d
						addStop(stop)
						if t := trimEnd(s, i, stop); t > i && t < stop {
							addStop(t)
							stop = t
						}
						if q := strings.LastIndexByte(s[i:stop], ':') + i; q > i && stop-q > 1 && digitsEnd(s, q+1) >= stop {
							addStop(q)
							if q-1 > i && s[q-1] == ':' {
								addStop(q - 1)
							}
						}
					}
				}
			}
		}
	}
	// The text after the address is masked as text: an IPv4 address in it, with the bits
	// that follow the run if it ends the run, is cut to its network (see
	// maskIPv4WithinBits). Then the bits are used, and the end is theirs.
	tail := func(e int) (string, int) {
		out, usedBits := maskIPv4WithinBits(s[e:j], bits)
		if usedBits {
			return out, j + len(bits)
		}
		return out, j
	}
	// atMasked is the text for the public reading f of s[t:e].
	atMasked := func(t, e int, f found) (string, int, found) {
		rest, end := tail(e)
		out := maskGlue(s, i, t, depth, f.dotted) + f.text + rest
		if settle && !f.dotted && t > i && (s[t-1] == ':' || hexVal(s[t-1]) >= 0) {
			// "dead:" and eight groups is no address, so the eight were masked on
			// their own; but "dead:2001:db8:abcd::/48" is one, and the next scan
			// would cut it to "dead:2001:db8::/48". The same holds where the label
			// runs into the first group ("0" and "226:fe80::/48" make the group 0226,
			// which a scan writes as 226). Settle on that now. It is for IPv6 only:
			// a second scan of a masked IPv4 prefix has nothing to add, and reads it
			// without the name that it was read behind.
			out = maskAddrs(out, false)
		}
		return out, max(end, k), f
	}
	sawReserved, reservedAt, reservedEnd := false, k, k
	lateKept, lateKeptEnd, lateKeptFound := -1, 0, found{}
	// stopRead reads the run as ending before a full stop, one of stopEnds:
	// the reading that is made when nothing else reads, not even a reserved one, and the run
	// holds no IPv4 address to mask first, which is masked, and the run read again
	// ("dead::198.51.100.247a" is not "dead::198" and a tail). It reads as the run was read
	// before eight groups after a "::" were an address, or, with afterColons, only at such a
	// start.
	stopRead := func(afterColons bool) (int, int, found, bool) {
		if len(stopEnds) > 0 && maskIPv4Within(s[i:j]) != s[i:j] {
			return 0, 0, found{}, false
		}
		for _, e := range stopEnds {
			for _, t := range starts(s, i, e, j, open || !afterColons) {
				if afterColons && (t <= i+1 || s[t-1] != ':' || s[t-2] != ':' || strings.Count(s[i:e], "::") >= 2) {
					continue
				}
				f := readAddr(s[t:e])
				f.start = t
				if f.reading == masked {
					return t, e, f, true
				}
				if f.reading == kept {
					break // an address that is kept is not read from behind its first groups
				}
			}
		}
		return 0, 0, found{}, false
	}
	// lateRead is a public reading that starts after a "::" only because the eight groups
	// there end the run (see starts).
	type lateRead struct {
		t, e int
		f    found
	}
	var late lateRead
	for x, e := range ends {
		multi := strings.Count(s[i:e], "::") >= 2
		for _, t := range starts(s, i, e, j, open) {
			var f found
			if k > j {
				f = readPrefix(s[t:k])
			} else {
				f = readAddr(s[t:e])
			}
			f.start = t
			if portFrom >= 0 && x >= portFrom && f.reading != masked {
				// A port is the last reading to try: it changes nothing but what it masks, and
				// an address that is kept ("fd7a:115c:a1e0::1:41641") is not read from behind
				// its first groups.
				if f.reading == kept {
					break
				}
				continue
			}
			if f.embeds && f.reading != masked && (t > i || e < j || afterEscape(s, i) || depth == 0) {
				// An IPv4 address inside an IPv6 literal is kept only when the literal
				// is all there is to the run ("64:ff9b::203.0.113.7"). Behind a label, after
				// an escape's digits, or before a full stop, the literal is not the whole
				// run, and the IPv4 address in it is masked as it is anywhere else in the run.
				continue
			}
			switch f.reading {
			case masked:
				if !multi && t > i+1 && s[t-1] == ':' && s[t-2] == ':' {
					// A start after a "::" is listed only for eight groups that end the run, and
					// the run is read as it was before that first: its front may be an address
					// that this reading would leave whole ("<eight groups>.5.6::<eight groups>").
					// The late reading is made when nothing else reads; the next round of
					// MaskAddrs masks what the front left.
					if late.e == 0 {
						late = lateRead{t, e, f}
					}
					continue
				}
				return atMasked(t, e, f)
			case kept:
				if multi && t > i+1 && s[t-1] == ':' && s[t-2] == ':' {
					// In a run that holds two "::" a reading after the first is one guess among
					// several: look on for a public one before settling for it.
					if lateKept < 0 {
						lateKept, lateKeptEnd, lateKeptFound = t, e, f
					}
					continue
				}
				rest, end := tail(e)
				return maskGlue(s, i, t, depth, false) + s[t:e] + rest + s[j:k], max(end, k), f
			case reserved:
				if t < reservedAt {
					reservedAt, reservedEnd = t, e
				}
				sawReserved = true
			}
		}
	}
	if lateKept >= 0 {
		rest, end := tail(lateKeptEnd)
		return maskGlue(s, i, lateKept, depth, false) + s[lateKept:lateKeptEnd] + rest + s[j:k], max(end, k), lateKeptFound
	}
	if sawReserved {
		// What the label's digits and the address read as is left as it is, but not what
		// comes before the first such reading: "8.8.8.8::1" holds the IPv4 address 8.8.8.8
		// and the text ::1.
		rest, end := tail(reservedEnd)
		return maskGlue(s, i, reservedAt, depth, false) + s[reservedAt:reservedEnd] + rest + s[j:k], max(end, k), found{reading: reserved, start: i}
	}
	if t, e, f, ok := stopRead(false); ok {
		return atMasked(t, e, f)
	}
	if late.e > 0 {
		return atMasked(late.t, late.e, late.f)
	}
	if t, e, f, ok := stopRead(true); ok {
		return atMasked(t, e, f)
	}
	return "", j, found{start: -1}
}

// maskGlue masks what comes before the address that starts at t in the run s[i:j]: the
// IPv4 addresses in it, and, once, the IPv6 address it may hold if it is written with
// "::", since two addresses can be written with nothing between them. So may glue of
// eight groups or more: before an IPv4 address (v4: "2001:db8:abcd:b3a7:c9d1:e2f4:a5b6:9e8f"
// and 5.6.7.8, with a full stop between them or not), and, ending in a full stop, before
// any address ("...:9e8f." and dead::1): the full stop ends an address; or when the start
// is inside a group, because an address was glued on in front of another with nothing
// between them (the glue ends in a hex digit: "...:9e8f" and 2606:4700:...), and a port's
// digits make such a group too. (Other glue of groups alone may be a fingerprint or a MAC
// address: a run of 16 groups has no address in its first eight.)
func maskGlue(s string, i, t, depth int, v4 bool) string {
	if g := s[i:t]; depth > 0 && (strings.Contains(g, "::") || strings.Count(g, ":") >= 7 && (v4 || fullStopAfterEightGroups(g) || hexByte(g[len(g)-1]))) {
		if out, _, f := maskAt(s, i, t, t, "", false, depth-1); f.reading != unread {
			return out
		}
	}
	return maskIPv4Within(s[i:t])
}

// hexByte reports whether c is a hex digit. Glue that ends in one has a start inside a group:
// a group too long to be one, because an address was glued on in front of another.
func hexByte(c byte) bool { return hexVal(c) >= 0 }

// fullStopAfterEightGroups reports whether glue has a last full stop after the seventh of
// its colons and at most one colon after it ("2001:db8:abcd:b3a7:c9d1:e2f4:a5b6:9e8f.A", or
// that and a number and a full stop, or a full stop and a colon): an address of eight groups
// and the full stop that ends it, then a word. A full stop before the colons
// ("x.2001:db8:abcd:b3a7:c9d1:e2f4:a5b6:9e8f:2001:...") is a label's, and one with more
// groups after it ends nothing.
func fullStopAfterEightGroups(g string) bool {
	d := strings.LastIndexByte(g, '.')
	return d >= 0 && strings.Count(g[:d], ":") >= 7 && strings.Count(g[d:], ":") <= 1
}

// afterEscape reports whether the run that starts at i follows hex digits: they are
// an escape's, which maskAddrs left out of the run.
func afterEscape(s string, i int) bool { return i > 0 && hexVal(s[i-1]) >= 0 }

// trimEnd is the end of s[i:j] without the colons and full stops that end it.
func trimEnd(s string, i, j int) int {
	for j > i && (s[j-1] == ':' || s[j-1] == '.') {
		j--
	}
	return j
}

// eightGroups is how many groups an address has with no "::" to stand for some: with that
// many after a "::", what comes before cannot be part of the address, and they are one of their own.
const eightGroups = 8

// maxSeps is the most colons and full stops one address holds: "1:2:3:4:5:6:1.2.3.4"
// has nine.
const maxSeps = 9

// starts lists, in order, where an address that ends the run s[i:e] can start, so
// that the first to read as one is the longest: a group of the run (the groups
// being what the colons and full stops divide it into) that is short enough to be
// an address's first, within the last maxSeps separators; the last characters of a
// group that is too long to be one, because a label or an escape ran into it ("20"
// before an address that begins 198, "6" before 2001), as many as the first group
// of an address holds (four hex digits, or three decimal ones before a full stop),
// and, for a short group of digits before a full stop, each shorter number it ends in;
// and each "::", which may start an address behind a label. A start inside a "::"
// is never listed (nor the group after it, unless the run has eight groups from there on,
// which no address before the "::" can use), so the IPv4 address in
// "64:ff9b::203.0.113.7" is part of the address that holds it, except in a run that holds
// two "::", which is no address as a whole. Nor is the last number of a public IPv4 address that a colon follows
// (endsPublicQuad): "8" of "8.8.8.8::1" is not the first group of "8::1". No start is
// listed in a group that is the last of the run: a lone group is no address. A bounded
// number of starts, each read in a bounded number of bytes, keeps the scan linear
// however long the run is; a scan that tried every start of a long group would read the
// rest of the group from each.
func starts(s string, i, e, j int, open bool) []int {
	var ring [maxSeps + 1]int
	n := 0
	for p := i; p < e; p++ {
		if c := s[p]; c == ':' || c == '.' {
			ring[n%len(ring)] = p
			n++
		}
	}
	cnt := min(n, len(ring))
	var seps [maxSeps + 1]int
	for x := range cnt {
		seps[x] = ring[(n-cnt+x)%len(ring)]
	}
	prev, first := i, 0
	if n >= len(ring) {
		// The group before the oldest separator held would need more than maxSeps of
		// them to be the first group of an address.
		prev, first = seps[0]+1, 1
	}
	multi := strings.Count(s[i:e], "::") >= 2 // two "::" make the run no address, and an address in it may follow the first
	// colons[x] is how many colons the run has from separator x on, up to e: an address from the
	// group before it to e has one more group than that. A start after a "::" is listed for eight
	// groups and a port only (at most eightGroups colons from there to the end of the run): in a
	// longer run, what follows the eight is more text of the run and not a port, and the run is
	// read as it was. So it is in glue that ends in a colon (open): the front of a longer run.
	var colons [maxSeps + 2]int
	beyond := strings.Count(s[e:max(e, trimEnd(s, e, j))], ":") // the colons of the run past e, whose groups are no part of a reading to e (not those that end it)
	for x := cnt - 1; x >= 0; x-- {
		colons[x] = colons[x+1]
		if s[seps[x]] == ':' {
			colons[x]++
		}
	}
	out := make([]int, 0, 4*len(ring))
	for x := first; x < cnt; x++ {
		b := seps[x]
		if a := prev; a < b {
			maxLen := 4
			if s[b] == '.' {
				maxLen = 3
			}
			switch {
			case b-a > maxLen:
				lo := b - maxLen
				if s[b] == '.' {
					for lo < b && (s[lo] < '0' || s[lo] > '9') {
						lo++
					}
				}
				for t := lo; t < b; t++ {
					out = append(out, t)
				}
			case a == i || multi && s[b] == ':' || !open && colons[x] >= eightGroups-1 && colons[x]+beyond <= eightGroups || !(a-2 >= i && s[a-1] == ':' && s[a-2] == ':'):
				if s[b] == ':' && endsPublicQuad(s, i, a, b) {
					break // the last number of an IPv4 address, not the first group of an IPv6 one
				}
				out = append(out, a)
				if s[b] == '.' {
					// A number the group does not make ("652", or "052": no octet has a
					// leading zero) may be glue and a shorter one: "eth0" and "52.94.236.248".
					lo := b
					for lo > a && s[lo-1] >= '0' && s[lo-1] <= '9' {
						lo--
					}
					for t := max(lo, a+1); t < b; t++ {
						out = append(out, t)
					}
				}
			}
		}
		if s[b] == ':' && b+1 < e && s[b+1] == ':' {
			out = append(out, b)
		}
		prev = b + 1
	}
	return out
}

// endsPublicQuad reports whether the group s[a:b], which a colon follows, begins with the
// last of four numbers that full stops join and that make a public IPv4 address: the "8"
// of "8.8.8.8::1" or of "8.8.8.8a1::". Read as the first group of an IPv6 address
// ("8::1", "8a1::") it would cut the IPv4 address in two, and neither half is masked.
// (A private or tailnet address before colons is not cut by it: "100.101.102.103::" has
// always read as the address and a network, and still does.) The first number of the
// four may carry a name's digits.
func endsPublicQuad(s string, i, a, b int) bool {
	n := 0
	for a+n < b && n < 4 && isDigit(s[a+n]) {
		n++
	}
	var oct [3]int
	if oct[2] = octet(s[a : a+n]); oct[2] < 0 {
		return false
	}
	p := a
	for x := 1; x >= 0; x-- {
		if p-1 < i || s[p-1] != '.' {
			return false
		}
		q := p - 1
		for q > i && isDigit(s[q-1]) && p-1-q < 4 {
			q--
		}
		if oct[x] = octet(s[q : p-1]); oct[x] < 0 {
			return false
		}
		p = q
	}
	if p-1 < i || s[p-1] != '.' {
		return false
	}
	q := p - 1
	for q > i && isDigit(s[q-1]) && p-1-q < 9 {
		q--
	}
	escape := 0 // the first number of the run, and so of the number, may follow an escape
	if q == i || !isDigit(s[q-1]) && s[q-1] != '.' {
		escape = escapeDigits(s, q)
	}
	return q < p-1 && firstIsPublic(s[q:p-1], escape, oct, true)
}

// maskIPv4Within masks the IPv4 addresses inside a run that is not one literal.
func maskIPv4Within(run string) string {
	out, _ := maskIPv4WithinBits(run, "")
	return out
}

// maskIPv4WithinBits is maskIPv4Within for a run that bits ("/24") follows. An IPv4
// address that ends the run is the address of a prefix, and is masked with it as
// readPrefix masks one, so that "203.0.113.0/24" does not become "203.0.113.0/24/24".
// It reports whether it took the bits.
func maskIPv4WithinBits(run, bits string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(run); {
		if !isDigit(run[i]) {
			b.WriteByte(run[i])
			i++
			continue
		}
		e := numberEnd(run, i)
		core := run[i:e]
		if a, err := netip.ParseAddr(core); err == nil && a.Is4() && public(a) {
			if bits != "" && e == len(run) {
				if f := readPrefix(core + bits); f.reading == masked {
					b.WriteString(f.text)
					return b.String(), true
				}
			}
			core = network(a)
		}
		b.WriteString(core)
		i = e
	}
	return b.String(), false
}

// numberEnd is the end of the dotted number that starts at the digit s[i]: numbers that
// single full stops join, each followed by a digit.
func numberEnd(s string, i int) int {
	for {
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		if i+1 < len(s) && s[i] == '.' && isDigit(s[i+1]) {
			i++
			continue
		}
		return i
	}
}

// public reports whether a can locate someone: a global unicast address outside
// private ranges and the tailnet.
func public(a netip.Addr) bool {
	u := a.Unmap()
	return u.IsGlobalUnicast() && !u.IsPrivate() && !tailnetRange.Contains(u) && !reservedV6.Contains(u)
}

// networkBits is the length of the network a public address is cut to.
func networkBits(a netip.Addr) int {
	u := a.Unmap()
	switch {
	case u.Is4():
		return 24
	case sixToFour.Contains(u):
		return 40 // 16 bits of 2002::, then the IPv4 address's /24
	}
	return 48
}

// network is the network a public address is cut to, as a prefix.
func network(a netip.Addr) string {
	u := a.Unmap().WithZone("")
	p, _ := u.Prefix(networkBits(u))
	return p.String()
}

// Mask rewrites, in place, the personal data reachable from ptr, without
// pseudonyms. See Masker.Mask.
func Mask(ptr any) { Masker{}.Mask(ptr) }

// Mask rewrites, in place, the personal data reachable from ptr (a pointer), as
// described above. PersonalPaths, run at registration, guarantees that every
// field tagged personal is a string, a pointer to one or a slice of them.
func (m Masker) Mask(ptr any) {
	v := reflect.ValueOf(ptr)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		panic(fmt.Sprintf("sanitize.Mask: want a non-nil pointer, got %T", ptr))
	}
	m.mask(v.Elem(), keep)
}

type maskMode int

const (
	keep       maskMode = iota // system data, or untrusted text tagged plain
	maskText                   // untrusted free text
	maskWhole                  // an identifier tagged personal
	maskEmails                 // untrusted text tagged emails
	maskAgain                  // untrusted text tagged premasked
)

func (m Masker) mask(v reflect.Value, mode maskMode) {
	switch v.Kind() {
	case reflect.String:
		if !v.CanSet() {
			return
		}
		switch mode {
		case maskText:
			v.SetString(m.Text(v.String()))
		case maskWhole:
			v.SetString(m.Identifier(v.String()))
		case maskEmails:
			v.SetString(m.Emails(v.String()))
		case maskAgain:
			v.SetString(m.Remask(v.String()))
		}
	case reflect.Pointer:
		if !v.IsNil() {
			m.mask(v.Elem(), mode)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			fieldMode := mode
			switch {
			case HasTag(f.Tag, "personal"):
				fieldMode = maskWhole
			case HasTag(f.Tag, "plain"):
				fieldMode = keep
			case HasTag(f.Tag, "emails"):
				fieldMode = maskEmails
			case HasTag(f.Tag, "premasked"):
				fieldMode = maskAgain
			case HasTag(f.Tag, "untrusted"):
				fieldMode = maskText
			}
			m.mask(v.Field(i), fieldMode)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			m.mask(v.Index(i), mode)
		}
	case reflect.Map:
		// Output maps hold scalars (UntrustedPaths refuses others). Values are
		// masked; keys are not, since two keys masked alike would collide.
		if mode == keep || v.IsNil() || !v.CanSet() {
			return
		}
		fresh := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			val := reflect.New(v.Type().Elem()).Elem()
			val.Set(iter.Value())
			m.mask(val, mode)
			fresh.SetMapIndex(iter.Key(), val)
		}
		v.Set(fresh)
	}
}

// PersonalPaths lists, in sorted order, the JSON paths of fields tagged
// `tk:"personal"` in type t, and PlainPaths those tagged `tk:"plain"`. Both panic
// on a tag Mask cannot honour: personal on anything but a string, a pointer to one
// or a slice of them; plain on a field that is not untrusted; or both on one
// field. A tool with such a field fails at registration instead of returning the
// value unmasked.
func PersonalPaths(t reflect.Type) []string { return tagged(t, "personal") }

// PlainPaths: see PersonalPaths.
func PlainPaths(t reflect.Type) []string { return tagged(t, "plain") }

// EmailPaths lists the fields tagged `tk:"emails"`: see PersonalPaths.
func EmailPaths(t reflect.Type) []string { return tagged(t, "emails") }

func tagged(t reflect.Type, option string) []string {
	var out []string
	taggedPaths(t, option, "", map[reflect.Type]bool{}, &out)
	sort.Strings(out)
	return out
}

func taggedPaths(t reflect.Type, option, prefix string, seen map[reflect.Type]bool, out *[]string) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		taggedPaths(t.Elem(), option, prefix+"[]", seen, out)
		return
	case reflect.Struct:
	default:
		return
	}
	if seen[t] {
		return
	}
	seen[t] = true
	defer delete(seen, t)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := jsonName(f)
		if !f.IsExported() || name == "-" {
			continue
		}
		path := join(prefix, name)
		personal, plain, emails, premasked := HasTag(f.Tag, "personal"), HasTag(f.Tag, "plain"), HasTag(f.Tag, "emails"), HasTag(f.Tag, "premasked")
		switch {
		case personal && plain, personal && emails, plain && emails, premasked && (personal || plain || emails):
			panic(fmt.Sprintf("sanitize: output field %q takes one of personal, plain, emails and premasked", path))
		case premasked && !HasTag(f.Tag, "untrusted"):
			panic(fmt.Sprintf("sanitize: output field %q is tagged premasked but not untrusted", path))
		case emails && !HasTag(f.Tag, "untrusted"):
			panic(fmt.Sprintf("sanitize: output field %q is tagged emails but not untrusted", path))
		case personal && !maskable(f.Type):
			panic(fmt.Sprintf("sanitize: output field %q is tagged personal but is %s; it must be a string, a pointer to one or a slice of them", path, f.Type))
		case plain && !HasTag(f.Tag, "untrusted"):
			panic(fmt.Sprintf("sanitize: output field %q is tagged plain but not untrusted; plain exempts untrusted text from masking", path))
		}
		if HasTag(f.Tag, option) {
			*out = append(*out, path)
			continue
		}
		taggedPaths(f.Type, option, path, seen, out)
	}
}

func maskable(t reflect.Type) bool {
	if t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	return t.Kind() == reflect.String
}
