package tools_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// maxSubjects is the most distinct pseudonyms one text may carry (the unexported maxSubjects
// of the package).
const maxSubjects = 64

// substEnv is a keyed environment over a fake API that lists the given logins, and the
// pseudonym of each.
func substEnv(t *testing.T, logins ...string) (*apitest.Fake, *registry.Env, *privacy.Key, []string) {
	t.Helper()
	f, _, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, logins...))
	kenv, k := keyed(t, env)
	refs := make([]string, len(logins))
	for i, l := range logins {
		refs[i] = k.APIPseudonym(l)
	}
	return f, kenv, k, refs
}

func substitute(env *registry.Env, text string) (string, int, error) {
	out, n, err := tools.SubstituteSubjects(context.Background(), tools.NewSubjectResolver(env), []byte(text))
	return string(out), n, err
}

func TestSubstituteReplacesCarriersInKeysAndValuesAndKeepsComments(t *testing.T) {
	f, env, _, refs := substEnv(t, "amy@example.com", "bob@example.org", "carol@example.com")
	amy, bob, carol := refs[0], refs[1], refs[2]
	// The comments hold quoted carriers on purpose: a pass that read comments as strings would
	// replace them.
	text := func(amyV, bobV, carolV, amyKey string) string {
		return "// header: \"" + amy + "\" is quoted, but it is a comment\n" +
			"{\n" +
			"\t\"groups\": {\n" +
			"\t\t\"group:eng\": [" + amyV + ", " + bobV + "], // trailing \"[" + bob + "]\"\n" +
			"\t\t/* block \"" + carol + "\" */\n" +
			"\t\t\"group:ops\": [" + carolV + "],\n" +
			"\t},\n" +
			"\t\"hosts\": {" + amyKey + ": \"100.64.0.1\", \"group:" + strings.TrimPrefix(amy, "p:") + "\": \"100.64.0.2\"},\n" +
			"}\n"
	}
	in := text(`"`+amy+`"`, `"[`+bob+`]"`, `"c…@example.com [`+carol+`]"`, `"`+amy+`"`)
	want := text(`"amy@example.com"`, `"bob@example.org"`, `"carol@example.com"`, `"amy@example.com"`)
	for name, c := range map[string]struct{ in, want string }{
		"LF":   {in, want},
		"CRLF": {strings.ReplaceAll(in, "\n", "\r\n"), strings.ReplaceAll(want, "\n", "\r\n")},
	} {
		before := usersRequests(f)
		out, n, err := substitute(env, c.in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if out != c.want {
			t.Errorf("%s: the output differs from the input at more than the carriers:\n got  %q\n want %q", name, out, c.want)
		}
		if n != 4 {
			t.Errorf("%s: replaced %d strings, want 4 (amy as a value and as a key, bob and carol once each)", name, n)
		}
		if got := usersRequests(f) - before; got != 1 {
			t.Errorf("%s: %d requests for the users, want 1", name, got)
		}
		if _, err := hujson.Parse([]byte(out)); err != nil {
			t.Errorf("%s: the output is not HuJSON: %v", name, err)
		}
	}
}

func TestSubstituteEscapesTheLoginAsJSON(t *testing.T) {
	const login = `a"b\c/d@example.com`
	_, env, _, refs := substEnv(t, login, "bob@example.org")
	out, n, err := substitute(env, `{"groups": {"group:x": ["`+refs[0]+`"]}}`)
	if err != nil || n != 1 {
		t.Fatalf("substitute: %d, %v", n, err)
	}
	v, err := hujson.Parse([]byte(out))
	if err != nil {
		t.Fatalf("the output %q is not HuJSON: %v", out, err)
	}
	v.Standardize()
	var got struct {
		Groups map[string][]string `json:"groups"`
	}
	if err := json.Unmarshal(v.Pack(), &got); err != nil || len(got.Groups["group:x"]) != 1 || got.Groups["group:x"][0] != login {
		t.Errorf("the login decodes to %v (%v), want %q", got.Groups, err, login)
	}
	if !strings.Contains(out, `a\"b\\c/d@example.com`) {
		t.Errorf("the output %q does not escape the quote and the backslash", out)
	}
}

// What is not a carrier is left as it is, and what holds a marker without being one is
// refused before any request: Resolve ignores the prefix of a masked value, so accepting
// "tag:x [p:...]" would turn a tag into a login without a word.
func TestSubstituteRefusesWhatIsNotACarrier(t *testing.T) {
	f, env, _, refs := substEnv(t, "amy@example.com", "bob@example.org")
	amy := refs[0]
	cases := map[string]string{
		"a tag then a marker":                `{"x": ["tag:x [` + amy + `]"]}`,
		"a name then a marker":               `{"x": ["amy [` + amy + `]"]}`,
		"a marker inside a longer string":    `{"x": ["see [` + amy + `] here"]}`,
		"a marker glued to a word":           `{"x": ["word[` + amy + `]"]}`,
		"a marker as a key inside a string":  `{"x": {"k [` + amy + `]": 1}}`,
		"a bracketed marker in a path":       `[{"op": "remove", "path": "/groups/[` + amy + `]"}]`,
		"a bare pseudonym as a path segment": `[{"op": "remove", "path": "/ssh/0/users/` + amy + `"}]`,
		"a masked carrier in a path":         `[{"op": "remove", "path": "/groups/a…@example.com [` + amy + `]"}]`,
		"a carrier in a from":                `[{"op": "move", "from": "/groups/[` + amy + `]", "path": "/groups/x"}]`,
		"an escaped marker":                  `{"x": ["see ` + string(rune(92)) + `u005b` + amy + `] here"]}`,
	}
	before := usersRequests(f)
	checked := 0
	for name, text := range cases {
		checked++
		out, n, err := substitute(env, text)
		if code(err) != tkerr.ValidationFailed || out != "" || n != 0 {
			t.Errorf("%s: %q, %d, %v; want validation_failed, no output", name, out, n, err)
			continue
		}
		if strings.Contains(err.Error(), amy) || strings.Contains(err.Error(), "amy@") {
			t.Errorf("%s: the error repeats what it refused: %v", name, err)
		}
	}
	if checked != len(cases) || checked != 10 {
		t.Fatalf("checked %d cases, want all 10", checked)
	}
	if got := usersRequests(f) - before; got != 0 {
		t.Errorf("%d requests for the users, want none: a text that is refused is refused before any lookup", got)
	}
}

func TestSubstituteLeavesWhatIsNotAMarkerAlone(t *testing.T) {
	f, env, _, refs := substEnv(t, "amy@example.com", "bob@example.org")
	amy := refs[0]
	text := "// [" + amy + "] in a line comment\n" +
		"/* " + amy + " in a block comment */\n" +
		`{"groups": {"group:abcdefghij": ["tag:` + strings.TrimPrefix(amy, "p:") + `", "group:` + strings.TrimPrefix(amy, "p:") + `"]}, "x": ["p:abc", "` + strings.Repeat("a", 1<<20) + `"]}`
	before := usersRequests(f)
	out, n, err := substitute(env, text)
	if err != nil || n != 0 || out != text {
		t.Errorf("a text with no carrier: %d replaced, %v, same bytes %v; want none replaced and the text as it came", n, err, out == text)
	}
	if got := usersRequests(f) - before; got != 0 {
		t.Errorf("%d requests for the users, want none", got)
	}
}

func TestSubstituteRefusesTextItCannotRead(t *testing.T) {
	_, env, _, refs := substEnv(t, "amy@example.com", "bob@example.org")
	for name, text := range map[string]string{
		"an unterminated string":        `{"x": ["` + refs[0] + `]}`,
		"an unterminated block comment": `{"x": ["` + refs[0] + `"]} /* never closed`,
		"a bad escape":                  `{"x": ["bad \q escape"]}`,
	} {
		if out, n, err := substitute(env, text); code(err) != tkerr.ValidationFailed || out != "" || n != 0 {
			t.Errorf("%s: %q, %d, %v; want validation_failed", name, out, n, err)
		}
	}
}

func TestZeroOrSeveralUsersForAPseudonymFail(t *testing.T) {
	// Several: two users forced to one pseudonym.
	_, env, k, refs := substEnv(t, "amy@example.com", "bob@example.org", "carol@example.com")
	r := tools.NewSubjectResolver(env)
	r.SetPseudonymFunc(func(login string) string {
		if login == "amy@example.com" || login == "bob@example.org" {
			return refs[0]
		}
		return k.APIPseudonym(login)
	})
	out, n, err := tools.SubstituteSubjects(context.Background(), r, []byte(`{"x": ["`+refs[0]+`"]}`))
	if code(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), "more than one user") || out != nil || n != 0 {
		t.Errorf("a collision: %q, %d, %v; want validation_failed: more than one user", out, n, err)
	}
	// None: a pseudonym minted under another key.
	other, err2 := privacy.Parse(strings.Repeat("c3", 32))
	if err2 != nil {
		t.Fatal(err2)
	}
	out, n, err = tools.SubstituteSubjects(context.Background(), tools.NewSubjectResolver(env), []byte(`{"x": ["`+other.APIPseudonym("amy@example.com")+`"]}`))
	if code(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), "no user has that pseudonym") || out != nil || n != 0 {
		t.Errorf("a replaced key: %q, %d, %v; want validation_failed: no user has that pseudonym", out, n, err)
	}
}

func TestMoreThanMaxSubjectsIsRefusedBeforeAnyRequest(t *testing.T) {
	logins := make([]string, maxSubjects+1)
	for i := range logins {
		logins[i] = fmt.Sprintf("user%02d@example.com", i)
	}
	build := func(env *registry.Env, k *privacy.Key, n int) string {
		var items []string
		for _, l := range logins[:n] {
			items = append(items, `"`+k.APIPseudonym(l)+`"`)
		}
		// One more mention of the first: repeats are not distinct pseudonyms.
		items = append(items, `"`+k.APIPseudonym(logins[0])+`"`)
		return `{"groups": {"group:x": [` + strings.Join(items, ",") + `]}}`
	}
	f, env, k, _ := substEnv(t, logins...)
	before := usersRequests(f)
	if out, n, err := substitute(env, build(env, k, maxSubjects+1)); code(err) != tkerr.ValidationFailed || out != "" || n != 0 || usersRequests(f) != before {
		t.Errorf("%d distinct pseudonyms: %d replaced, %v, %d requests; want validation_failed before any request", maxSubjects+1, n, err, usersRequests(f)-before)
	}
	out, n, err := substitute(env, build(env, k, maxSubjects))
	if err != nil || n != maxSubjects+1 || strings.Contains(out, `"p:`) {
		t.Errorf("%d distinct pseudonyms: %d replaced, %v; want all %d replaced", maxSubjects, n, err, maxSubjects+1)
	}
}

// The subject rule runs on the exact bytes the caller gave, and substitution comes after: the
// output holds a literal login by design, so the rule would refuse it.
func TestSubstitutionRunsAfterTheSubjectCheck(t *testing.T) {
	_, env, _, refs := substEnv(t, "amy@example.com", "bob@example.org")
	text := `{"groups": {"group:eng": ["` + refs[0] + `"]}}`
	if err := tools.CheckProposalSubjects(env, text); err != nil {
		t.Fatalf("the rule refuses the text with its carrier: %v", err)
	}
	out, n, err := substitute(env, text)
	if err != nil || n != 1 || !strings.Contains(out, "amy@example.com") {
		t.Fatalf("substitute: %q, %d, %v", out, n, err)
	}
	if err := tools.CheckProposalSubjects(env, out); code(err) != tkerr.FilterRefused {
		t.Errorf("the rule on the output: %v, want filter_refused: it holds a literal login", err)
	}
	if bytes.Contains([]byte(text), []byte("amy@")) {
		t.Error("the input was changed")
	}
}

// The three branches the carrier walk takes besides a plain replacement: a cancelled
// call, a text that would pass the byte cap once logins are written at their longest,
// and a line comment that ends the text with no newline.
func TestSubstituteSubjectsBranches(t *testing.T) {
	f, env, _, refs := substEnv(t, "amy@example.com", "bob@example.org")
	carrier := refs[0]
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled, n, err := tools.SubstituteSubjects(ctx, tools.NewSubjectResolver(env), []byte(`{"x":["`+carrier+`"]}`))
	if code(err) != tkerr.APIError || !strings.Contains(err.Error(), "request cancelled") || cancelled != nil || n != 0 {
		t.Errorf("cancelled: %q, %d, %v", cancelled, n, err)
	}
	// A cancelled call is cancelled whether or not the text holds a pseudonym: with none,
	// nothing else would notice, and the caller would go on to send a request nobody waits for.
	for _, plain := range []string{`{"x":["tag:web"]}`, `{}`, ``} {
		out, n, err := tools.SubstituteSubjects(ctx, tools.NewSubjectResolver(env), []byte(plain))
		if code(err) != tkerr.APIError || !strings.Contains(err.Error(), "request cancelled") || out != nil || n != 0 {
			t.Errorf("cancelled, no pseudonym in %q: %q, %d, %v", plain, out, n, err)
		}
	}
	if usersRequests(f) != 0 {
		t.Errorf("a cancelled call read the users %d time(s)", usersRequests(f))
	}

	pad := acl.MaxBytes - len(carrier) - len(`{"x":"","pad":""}`) - 10
	wide := `{"x":"` + carrier + `","pad":"` + strings.Repeat("a", pad) + `"}`
	if len(wide) <= acl.MaxBytes-320 || len(wide) > acl.MaxBytes {
		t.Fatalf("fixture length %d does not sit in the window below the cap", len(wide))
	}
	before := usersRequests(f)
	out, n, err := substitute(env, wide)
	if code(err) != tkerr.TooComplex || out != "" || n != 0 || usersRequests(f) != before {
		t.Errorf("over the cap: %d replaced, %d requests, %v", n, usersRequests(f)-before, err)
	}

	raw := "{\"x\":\"" + carrier + "\"} // \"" + carrier + "\""
	if strings.HasSuffix(raw, "\n") {
		t.Fatal("the comment fixture ends in a newline")
	}
	got, n, err := substitute(env, raw)
	if err != nil || n != 1 || !strings.Contains(got, "amy@example.com") || !strings.HasSuffix(got, "// \""+carrier+"\"") {
		t.Errorf("comment at end of text: %q, %d, %v", got, n, err)
	}
}
