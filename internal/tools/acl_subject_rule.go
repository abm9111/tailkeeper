package tools

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// notALoginRE matches, as a whole string, the three forms that hold an at sign and name no
// user: the domain selectors user:*@domain and localpart:*@domain, which may carry
// ports, and the Tailscale-written logstream@tailscale.
var notALoginRE = regexp.MustCompile(`^(?:(?:user|localpart):\*@[A-Za-z0-9.-]+(?::[0-9*,-]+)?|logstream@tailscale)$`)

// maxSubjectPointers is how many offending strings a refusal names.
const maxSubjectPointers = 8

// IsLiteralLogin reports whether s holds a user login as the masker reads one: the
// masker would change it, unless it is one of the three forms that are not logins. A masked
// value carrying a pseudonym is not a literal login, and neither is a synced group's name.
func IsLiteralLogin(s string) bool {
	if notALoginRE.MatchString(s) {
		return false
	}
	return sanitize.MaskEmails(s) != s
}

// pointerEscape and pointerUnescape are the RFC 6901 escapes of a pointer segment.
var (
	pointerEscape   = strings.NewReplacer("~", "~0", "/", "~1")
	pointerUnescape = strings.NewReplacer("~1", "/", "~0", "~")
)

// maxPointerSegment is how many bytes of a key a pointer shows.
const maxPointerSegment = 64

// loginSegment stands in a pointer for a key that is a literal login.
const loginSegment = "(a login)"

// subjectScan walks a parsed HuJSON value and collects the JSON pointers of its strings,
// keys and values, that are literal logins. Comments are not strings and are never read.
// A pointer never repeats a login: a key that is one shows as (a login) on the path, and any
// other key shows capped at maxPointerSegment bytes, with control characters escaped.
type subjectScan struct {
	path  []string
	found []string // the first maxSubjectPointers, masked
	total int
}

// pointer is the JSON pointer of the value being read, as text a reader can follow. Its
// segments are the capped, escaped ones that walk put on the path.
func (s *subjectScan) pointer() string {
	if len(s.path) == 0 {
		return "the top level"
	}
	var b strings.Builder
	for _, seg := range s.path {
		b.WriteByte('/')
		b.WriteString(pointerEscape.Replace(seg))
	}
	return b.String()
}

// literalLoginOrPointer reports whether str is a literal login, or begins with a slash and is
// one once read as a JSON pointer with ~1 and ~0 undone.
func literalLoginOrPointer(str string) bool {
	return IsLiteralLogin(str) || (strings.HasPrefix(str, "/") && IsLiteralLogin(pointerUnescape.Replace(str)))
}

// segment is what a key shows on the path: (a login) for a literal login, so its text never
// enters a pointer, and otherwise the key capped and with control characters escaped.
func segment(name string) string {
	if literalLoginOrPointer(name) {
		return loginSegment
	}
	return sanitize.String(name, maxPointerSegment)
}

func (s *subjectScan) walk(v *hujson.Value) {
	switch x := v.Value.(type) {
	case hujson.Literal:
		if x.Kind() == '"' {
			s.check(x.String(), false)
		}
	case *hujson.Object:
		for i := range x.Members {
			m := &x.Members[i]
			name := ""
			if lit, ok := m.Name.Value.(hujson.Literal); ok {
				name = lit.String()
			}
			s.check(name, true)
			s.path = append(s.path, segment(name))
			s.walk(&m.Value)
			s.path = s.path[:len(s.path)-1]
		}
	case *hujson.Array:
		for i := range x.Elements {
			s.path = append(s.path, strconv.Itoa(i))
			s.walk(&x.Elements[i])
			s.path = s.path[:len(s.path)-1]
		}
	}
}

// check records the current position if str is a literal login. A string that begins with a
// slash is also read as a JSON pointer, with ~1 and ~0 undone: the path and from of a patch
// operation name keys, and a key may be a login. For a key the pointer is its parent's, so
// the refusal never repeats the key; the path to a deeper value shows a login key as (a login).
func (s *subjectScan) check(str string, key bool) {
	if !literalLoginOrPointer(str) {
		return
	}
	s.total++
	if len(s.found) < maxSubjectPointers {
		p := s.pointer()
		if key {
			p += " (a key)"
		}
		s.found = append(s.found, sanitize.MaskEmails(p))
	}
}

// refusal is the filter_refused error for what the scan found, or nil. Pseudonyms exist only
// with a privacy key, so without one the hint says that, as filterRefused does, and sends no one
// to a pseudonym.
func (s *subjectScan) refusal(env *registry.Env, what string) error {
	if s.total == 0 {
		return nil
	}
	noun := "1 string is a login"
	if s.total > 1 {
		noun = strconv.Itoa(s.total) + " strings are logins"
	}
	at := ", at "
	if s.total > maxSubjectPointers {
		at = ", at the first " + strconv.Itoa(maxSubjectPointers) + ": "
	}
	hint := "name the user by the pseudonym a result shows (p:…), or by a masked value that ends in it, or by a group the owner defined; the owner can set personalData to show"
	if keyless(env) {
		hint = keylessHint
	}
	return tkerr.New(tkerr.FilterRefused,
		"while personal data is masked, "+what+" may not hold a user's login: "+noun+at+strings.Join(s.found, ", ")+
			": a match would confirm a guess", hint)
}

// checkSubjects applies the rule to text, which is HuJSON: the depth pre-scan comes before
// any hujson call, since hujson recurses once per level and a stack overflow ends the process.
func checkSubjects(env *registry.Env, text, what string) error {
	if env.ShowPersonalData() {
		return nil
	}
	if nestsDeeperThan(text, maxHuJSONDepth) {
		return tkerr.New(tkerr.ValidationFailed, what+" nests deeper than 1,000 levels, which no policy does", "")
	}
	// A line comment ends at a line feed, and one that ends the text has none: give it one, as
	// redactNested does, so a comment on the last line is a comment and not a syntax error.
	v, err := hujson.Parse([]byte(text + "\n"))
	if err != nil {
		return tkerr.New(tkerr.ValidationFailed, what+" is not valid HuJSON, so it cannot be checked for user logins", "fix the syntax first")
	}
	var s subjectScan
	s.walk(&v)
	return s.refusal(env, what)
}

// CheckProposalSubjects applies the subject rule to a policy text given over MCP:
// while masking is on, no string of it, outside comments, key or value, may be a user login.
// It is nil when the rule holds or personalData is show, filter_refused naming the JSON
// pointers when it does not, and validation_failed when the text nests deeper than 1,000
// levels or is not valid HuJSON (it is never a pass for text it could not read).
//
// Check the exact bytes you will send, and check them before you replace a pseudonym by the
// login it names: the text after the replacement holds a literal login by design.
func CheckProposalSubjects(env *registry.Env, text string) error {
	return checkSubjects(env, text, "a proposal")
}

// CheckPatchSubjects applies the subject rule to RFC 6902 patch operations given over MCP:
// the whole patch is read as one HuJSON document, and no string in it, outside comments, key
// or value, in a path, a from or a value, in any operation, may be a user login. The errors
// are those of CheckProposalSubjects, and the pointers are those of the patch (/2/value/src/0
// is the third operation's value). Whether the text is a well-formed patch is for
// hujson.Patch to say when the patch is applied.
//
// Check the exact bytes you will send, and check them before you replace a pseudonym by the
// login it names: the text after the replacement holds a literal login by design.
func CheckPatchSubjects(env *registry.Env, patch []byte) error {
	return checkSubjects(env, string(patch), "a patch")
}
