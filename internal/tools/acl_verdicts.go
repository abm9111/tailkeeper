package tools

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/acl"
)

// FailureKind says what a line of a validate reply is about a test.
type FailureKind string

const (
	// AssertionFailed: a line in the want/got grammar, the server's answer that a
	// destination was accepted or dropped against the test's expectation.
	AssertionFailed FailureKind = "assertion_failed"
	// TestUnevaluable: anything else the server says about a test (a name it cannot resolve,
	// a destination kind tests do not take, a malformed test). It says nothing about access,
	// and is never read as a verdict.
	TestUnevaluable FailureKind = "test_unevaluable"
)

// FailureLine is one error line of a validate reply, read by the grammar of probe A-9
// (20 Oct 2026). The zero fields of a TestUnevaluable line mean nothing.
type FailureLine struct {
	Kind     FailureKind
	SSH      bool
	Dst      string // the address as the server quoted it (tests form), or the dst (SSH form)
	Protocol string // "" when the line has none
	Want     string // "Accept" or "Drop" (tests), "accept" or "deny" (SSH)
	Got      string
}

// Failure is the acl.Failure that locates this line, for a test whose source is src.
func (f FailureLine) Failure(src string) acl.Failure {
	return acl.Failure{Src: src, Dst: f.Dst, SSH: f.SSH}
}

// The headings the server puts before a line; either may be missing.
const (
	testHeading = "[acl test error]: "
	sshHeading  = "[ssh test error]: "
)

// ParseFailureLine reads one error line. The grammar is positional and anchored, never a
// search: a tag or a host name can embed a destination and the words want and got, so every
// quoted field is read as one Go-quoted string from its opening quote, and the text after it
// must be exactly what the grammar says, to the end of the line.
//
//	[acl test error]: address "<dst>"( (protocol "<p>"))?: want: (Accept|Drop), got: (Accept|Drop)
//	[ssh test error]: src "<s>" at "<ip>", dst "<d>" at "<ip>", ssh user "<u>": want: "accept" got: "deny"
//
// A line that is not in the grammar, or whose quoted field does not unquote, or whose two
// verdicts are the same, is TestUnevaluable: that can only turn a verdict into "unresolved",
// never into a pass.
func ParseFailureLine(line string) FailureLine {
	s := line
	if rest, ok := strings.CutPrefix(s, testHeading); ok {
		s = rest
	} else if rest, ok := strings.CutPrefix(s, sshHeading); ok {
		s = rest
	}
	if rest, ok := strings.CutPrefix(s, "address "); ok {
		if f, ok := parseAddressLine(rest); ok {
			return f
		}
	} else if rest, ok := strings.CutPrefix(s, "src "); ok {
		if f, ok := parseSSHLine(rest); ok {
			return f
		}
	}
	return FailureLine{Kind: TestUnevaluable}
}

// quoted reads a Go-quoted string at the start of s and returns it with the rest.
func quoted(s string) (value, rest string, ok bool) {
	q, err := strconv.QuotedPrefix(s)
	if err != nil {
		return "", "", false
	}
	v, err := strconv.Unquote(q)
	if err != nil {
		return "", "", false
	}
	return v, s[len(q):], true
}

var verdictWords = map[string]bool{"Accept": true, "Drop": true}

// parseAddressLine reads what follows "address " in the tests form.
func parseAddressLine(s string) (FailureLine, bool) {
	dst, rest, ok := quoted(s)
	if !ok {
		return FailureLine{}, false
	}
	f := FailureLine{Kind: AssertionFailed, Dst: dst}
	if after, ok := strings.CutPrefix(rest, " (protocol "); ok {
		p, rest2, ok := quoted(after)
		if !ok {
			return FailureLine{}, false
		}
		after, ok = strings.CutPrefix(rest2, ")")
		if !ok {
			return FailureLine{}, false
		}
		f.Protocol, rest = p, after
	}
	rest, ok = strings.CutPrefix(rest, ": want: ")
	if !ok {
		return FailureLine{}, false
	}
	want, rest, ok := strings.Cut(rest, ", got: ")
	if !ok || !verdictWords[want] || !verdictWords[rest] || want == rest {
		return FailureLine{}, false
	}
	f.Want, f.Got = want, rest
	return f, true
}

var sshVerdictWords = map[string]bool{"accept": true, "deny": true}

// quotedFields reads len(seps)+1 Go-quoted strings, each but the last followed by the
// separator of its index, and returns them with the text left over.
func quotedFields(s string, seps ...string) (values []string, rest string, ok bool) {
	for i := 0; i <= len(seps); i++ {
		v, r, ok := quoted(s)
		if !ok {
			return nil, "", false
		}
		values, s = append(values, v), r
		if i < len(seps) {
			if s, ok = strings.CutPrefix(s, seps[i]); !ok {
				return nil, "", false
			}
		}
	}
	return values, s, true
}

// parseSSHLine reads what follows "src " in the SSH form.
func parseSSHLine(s string) (FailureLine, bool) {
	v, rest, ok := quotedFields(s, " at ", ", dst ", " at ", ", ssh user ", ": want: ", " got: ")
	if !ok || rest != "" {
		return FailureLine{}, false
	}
	want, got := v[5], v[6]
	if !sshVerdictWords[want] || !sshVerdictWords[got] || want == got {
		return FailureLine{}, false
	}
	return FailureLine{Kind: AssertionFailed, SSH: true, Dst: v[2], Want: want, Got: got}, true
}

// maxQuotedToken is the longest token quotedToken returns.
const maxQuotedToken = 1 << 10

// positionIn reads a leading "line N, column M: " from a server message. ok is false when it
// is absent or when a number is not a positive count of at most nine digits.
func positionIn(msg string) (line, col int, ok bool) {
	rest, ok := strings.CutPrefix(msg, "line ")
	if !ok {
		return 0, 0, false
	}
	l, rest, ok := leadingCount(rest)
	if !ok {
		return 0, 0, false
	}
	rest, ok = strings.CutPrefix(rest, ", column ")
	if !ok {
		return 0, 0, false
	}
	c, rest, ok := leadingCount(rest)
	if !ok || !strings.HasPrefix(rest, ": ") {
		return 0, 0, false
	}
	return l, c, true
}

// leadingCount reads one to nine digits at the start of s, as a number from 1.
func leadingCount(s string) (n int, rest string, ok bool) {
	i := 0
	for i < len(s) && i < 10 && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 || i > 9 {
		return 0, "", false
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil || n < 1 {
		return 0, "", false
	}
	return n, s[i:], true
}

// quotedToken returns the first double-quoted token of a message, unquoted and cut at 1 KiB
// (at a rune boundary). A server message that names a tag or a group quotes it; the token is
// where to look in the caller's text. ok is false when the message holds no quoted token, or
// when the token is empty (or is cut down to nothing: 1 KiB of bytes that are not UTF-8 has
// no rune start to cut at): looked up, the empty string would be found at every empty entry
// of the policy.
func quotedToken(msg string) (string, bool) {
	i := strings.IndexByte(msg, '"')
	if i < 0 {
		return "", false
	}
	tok, _, ok := quoted(msg[i:])
	if !ok {
		return "", false
	}
	if len(tok) > maxQuotedToken {
		n := maxQuotedToken
		for n > 0 && !utf8.RuneStart(tok[n]) {
			n--
		}
		tok = tok[:n]
	}
	return tok, tok != ""
}
