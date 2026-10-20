package tools

import (
	"regexp"
	"sort"
	"strings"

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

// Hide is the reverse map: it masks, in text that Tailscale wrote or echoed, every
// login this resolver has handed out, then every other address, all without pseudonyms. A
// reply repeats what was sent, and a pseudonym beside it would confirm a guess. The logins
// are replaced whole and longest first, so a login with a byte the address scan does not
// read (a slash) is not left half showing. A word glued to the front of a login (bigamy@ for
// amy@) is another user's address and is masked with it, from its first byte. While
// personalData is show the text is returned as it came.
func (r *SubjectResolver) Hide(text string) string {
	if r.env.ShowPersonalData() {
		return text
	}
	resolved := r.state().users.resolved
	seen := make(map[string]bool, len(resolved))
	var logins []string
	for _, l := range resolved {
		if !seen[l] {
			seen[l] = true
			logins = append(logins, l)
		}
	}
	sort.SliceStable(logins, func(i, j int) bool { return len(logins[i]) > len(logins[j]) })
	for _, l := range logins {
		text = hideLogin(text, loginPattern(l))
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
