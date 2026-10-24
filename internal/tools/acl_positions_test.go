package tools_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// A number in a result is computed on the text the caller wrote or on the text as the caller
// sees it, never on a text that holds a login the caller never saw. Each test below runs the
// same call for two users whose logins differ in length and read alike once masked, and holds
// the results to be the same bytes.

var twoLogins = []string{"chris@example.com", "christopher.longname.of.some.length@example.com"}

// pseudonym is a stand-in as long as the pseudonym a result shows (p: and ten characters).
const pseudonym = "p:xxxxxxxxxx"

// withLogin runs tool for the user u1, whose login is the given one, of a tailnet that also has
// bob, with a privacy key and the live policy given. args builds the arguments from the
// pseudonym the user is shown as; serve sets up the fake further. The pseudonym is replaced by
// <ref> in what comes back, since it differs from one login to the next.
func withLogin(t *testing.T, login, live, tool string, args func(ref string) string, serve func(*apitest.Fake)) string {
	t.Helper()
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, login, "bob@example.org"))
	kenv, _ := keyed(t, env)
	serveLive(f, live, nil, nil)
	if serve != nil {
		serve(f)
	}
	ref := shownRef(t, reg, kenv, "u1")
	s, err := call(t, reg, kenv, tool, args(ref))
	if err != nil {
		t.Fatalf("%s for %q: %v", tool, login, err)
	}
	return strings.ReplaceAll(s, ref, "<ref>")
}

// sameForBoth fails unless the two results are the same bytes.
func sameForBoth(t *testing.T, what string, got []string) {
	t.Helper()
	if got[0] != got[1] {
		t.Errorf("%s tells the length of a login:\n%.700s\n%.700s", what, got[0], got[1])
	}
}

func problemsOf(t *testing.T, s string, field string) []tools.ACLProblem {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		t.Fatal(err)
	}
	var ps []tools.ACLProblem
	if r, ok := raw[field]; ok {
		if err := json.Unmarshal(r, &ps); err != nil {
			t.Fatal(err)
		}
	}
	return ps
}

// An operation the engine refuses is placed in the patch the caller wrote: the column is that
// of the caller's own text, whatever the pseudonym before it stands for, in acl_validate and in
// acl_diff, which sends no request and so is unmetered.
func TestAPatchProblemIsPlacedInTheCallersOwnPatch(t *testing.T) {
	const live = "{\n\"groups\": {\"group:eng\": []},\n\"hosts\": {}}\n"
	patch := func(ref string) string {
		return `[{"op":"add","path":"/groups/group:eng/-","value":"` + ref + `"},{"op":"copy","from":"/groups","path":"/hosts"}]`
	}
	for _, tool := range []string{"acl_validate", "acl_diff"} {
		t.Run(tool, func(t *testing.T) {
			var got []string
			for _, login := range twoLogins {
				got = append(got, withLogin(t, login, live, tool, func(ref string) string { return patchCall(patch(ref)) }, nil))
			}
			sameForBoth(t, tool+" with a patch that is refused", got)
			var ps []tools.ACLProblem
			if tool == "acl_validate" {
				ps = problemsOf(t, got[0], "errors")
			} else {
				var out tools.ACLDiffOutput
				if err := json.Unmarshal([]byte(got[0]), &out); err != nil {
					t.Fatal(err)
				}
				ps = out.New.Findings
			}
			if len(ps) != 1 {
				t.Fatalf("problems = %+v in %s", ps, got[0])
			}
			want := strings.Index(patch(pseudonym), `"copy"`) + 1
			if p := ps[0]; p.Source != "patch" || p.Line != 1 || p.Column != want {
				t.Errorf("the problem is at %s %d:%d, in the caller's patch the copy is at 1:%d", p.Source, p.Line, p.Column, want)
			}
		})
	}
}

// Tailscale counts the lines and columns of the policy the patch makes, a text that holds
// logins and that the caller never wrote: a position it gives for a patch is left out, in the
// fields and in the words of the message.
func TestAServerPositionForAPatchIsLeftOut(t *testing.T) {
	const live = "{\n\"groups\": {\"group:eng\": []}\n}\n"
	var got []string
	for _, login := range twoLogins {
		got = append(got, withLogin(t, login, live, "acl_validate", func(ref string) string {
			return patchCall(`[{"op":"add","path":"/groups/group:eng/-","value":"` + ref + `"}]`)
		}, func(f *apitest.Fake) { f.ServeValidate(apitest.PolicySyntaxError(7, 45, "unexpected")) }))
	}
	// The digest of the patched policy is keyed by the logins in it, as it is meant to be: what
	// the test holds equal is the problem.
	sameForBoth(t, "acl_validate with a patch that Tailscale positions", []string{mustJSON(t, problemsOf(t, got[0], "errors")), mustJSON(t, problemsOf(t, got[1], "errors"))})
	ps := problemsOf(t, got[0], "errors")
	if len(ps) != 1 || ps[0].Source != "patch" || ps[0].Line != 0 || ps[0].Column != 0 {
		t.Fatalf("errors = %+v", ps)
	}
	if m := ps[0].Message; strings.Contains(m, "line 7") || strings.Contains(m, "column 45") || !strings.Contains(m, "unexpected") {
		t.Errorf("the message keeps the position of the policy the patch makes: %q", m)
	}
}

// The live policy holds logins the caller never saw, so a column in it is left out and its line
// is kept (a line is a count of line feeds, the same for any login). The caller reads the line
// in acl_get.
func TestAColumnInTheLivePolicyIsLeftOutAndItsLineIsKept(t *testing.T) {
	var live []string
	for _, login := range []string{"a@example.com", "averyveryverylonglocalpart@example.com"} {
		live = append(live, "{\n\"groups\": {\"group:a\": [\""+login+"\"], \"group:a\": []}}\n")
	}
	run := func(tool, args string, serve func(*apitest.Fake)) []string {
		var got []string
		for _, l := range live {
			f, reg, env := apiEnv(t)
			serveLive(f, l, nil, nil)
			if serve != nil {
				serve(f)
			}
			s, err := call(t, reg, env, tool, args)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, s)
		}
		return got
	}
	validate := run("acl_validate", `{}`, func(f *apitest.Fake) { f.ServeValidate(apitest.TestsPassEmptyObject()) })
	sameForBoth(t, "acl_validate of the live policy", validate)
	ps := problemsOf(t, validate[0], "notices")
	if len(ps) == 0 || ps[0].Kind != "duplicate_key" || ps[0].Source != "live" || ps[0].Line != 2 || ps[0].Column != 0 {
		t.Errorf("notices = %+v, want the repeated key of the live policy at line 2 with no column", ps)
	}
	diff := run("acl_diff", `{"against":"{}"}`, nil)
	sameForBoth(t, "acl_diff with the live policy on a side", diff)
	var out tools.ACLDiffOutput
	if err := json.Unmarshal([]byte(diff[0]), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.New.Findings) == 0 || out.New.Findings[0].Source != "live" || out.New.Findings[0].Column != 0 || out.New.Findings[0].Line != 2 {
		t.Errorf("findings = %+v, want the repeated key of the live policy at line 2 with no column", out.New.Findings)
	}
}

// A key written twice only once pseudonyms are logins is found in the text with logins in it
// and placed in the text the caller wrote, by acl_diff as by acl_validate.
func TestARepeatedKeyThatPseudonymsMakeIsPlacedInTheCallersText(t *testing.T) {
	const live = "{\n\"groups\": {\"group:eng\": []}\n}\n"
	text := func(ref string) string {
		return `{"hosts": {"` + ref + `": "192.0.2.1", "[` + ref + `]": "192.0.2.2"}}`
	}
	for name, args := range map[string]func(ref string) string{
		"policy":  func(ref string) string { return `{"policy":` + jsonString(text(ref)) + `}` },
		"against": func(ref string) string { return `{"against":` + jsonString(text(ref)) + `,"policy":"{}"}` },
	} {
		var got []string
		for _, login := range twoLogins {
			got = append(got, withLogin(t, login, live, "acl_diff", args, nil))
		}
		sameForBoth(t, "acl_diff with "+name, got)
		var out tools.ACLDiffOutput
		if err := json.Unmarshal([]byte(got[0]), &out); err != nil {
			t.Fatal(err)
		}
		side := out.New
		if name == "against" {
			side = out.Old
		}
		want := strings.Index(text(pseudonym), `"[`+pseudonym+`]"`) + 1
		if len(side.Findings) != 1 || side.Findings[0].Line != 1 || side.Findings[0].Column != want {
			t.Errorf("%s: findings = %+v, want one at 1:%d", name, side.Findings, want)
		}
	}
}

// A pointer is cut after it is masked: where the path to a key written twice runs past 1 KiB, the
// cut falls at the same place for two users whose logins differ in length and read alike. The
// key is repeated only once pseudonyms are logins.
func TestAPointerIsCutAfterItIsMasked(t *testing.T) {
	const live = "{\n\"groups\": {\"group:eng\": []}\n}\n"
	args := func(ref string) string {
		text := `{"` + ref + `": {"` + strings.Repeat("x", 1100) + `": {"` + ref + `": 1, "[` + ref + `]": 2}}}`
		return `{"policy":` + jsonString(text) + `}`
	}
	var findings []string
	for _, login := range twoLogins {
		s := withLogin(t, login, live, "acl_diff", args, nil)
		var out tools.ACLDiffOutput
		if err := json.Unmarshal([]byte(s), &out); err != nil {
			t.Fatal(err)
		}
		var repeated []tools.ACLProblem
		for _, p := range out.New.Findings {
			if p.Kind == "duplicate_key" {
				repeated = append(repeated, p)
			}
		}
		if len(repeated) != 1 {
			t.Fatalf("findings = %+v, want a repeated key", out.New.Findings)
		}
		findings = append(findings, mustJSON(t, repeated))
	}
	sameForBoth(t, "the pointer to a repeated key", findings)
}

// A section named by a login whose local part is longer than the cut a sentence makes of a name
// shows nothing of it: the name is masked before it is cut, so the cut cannot leave the local
// part without the at sign that makes the masker read it.
func TestASectionNamedByALongLoginShowsNothingOfIt(t *testing.T) {
	// Two logins whose local parts are longer than the 128-byte cut of a pointer, of different
	// lengths: the results are one and the same, and hold no run of the local part.
	for _, tool := range []string{"acl_diff", "acl_validate"} {
		results := map[int]string{}
		for _, local := range []int{150, 200} {
			login := "a" + strings.Repeat("bcdefghij", local/9) + "@example.com"
			f, reg, env := apiEnv(t)
			serveLive(f, "{\n\""+login+"\": {}\n}\n", nil, nil)
			f.ServeValidate(apitest.TestsPassEmptyObject())
			args := `{"against":"{}"}`
			if tool == "acl_validate" {
				args = `{}`
			}
			s, err := call(t, reg, env, tool, args)
			if err != nil {
				t.Fatalf("%s: %v", tool, err)
			}
			absent(t, s, "bcdefghij")
			if !strings.Contains(s, "unknown_section") || !strings.Contains(s, "a…@example.com") {
				t.Errorf("%s: no finding names the unknown section by its masked login, so the test checked nothing: %.600s", tool, s)
			}
			results[local] = s
		}
		if results[150] != results[200] {
			t.Errorf("%s: the result tells the length of the login:\n%.700s\n%.700s", tool, results[150], results[200])
		}
	}
}

// Where a text crosses the size the engine reads is the same for two users whose logins differ
// in length: a text that names a user thousands of times is refused by the longest a login can
// be, and the refusal says nothing of the login.
func TestTheSizeLimitTellsNothingOfTheLengthOfALogin(t *testing.T) {
	const live = "{\n\"groups\": {\"group:eng\": []}\n}\n"
	args := func(n int) func(ref string) string {
		return func(ref string) string {
			text := `{"groups": {"group:eng": [` + strings.Repeat(`"`+ref+`",`, n) + `"tag:x"]}}`
			return `{"policy":` + jsonString(text) + `}`
		}
	}
	long := []string{"chris@example.com", "c" + strings.Repeat("h", 38) + "@example.com"}
	for name, n := range map[string]int{"a text of thousands": 84000, "a text of hundreds": 800} {
		var got, errs []string
		for _, login := range long {
			f, reg, env := apiEnv(t)
			f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, login, "bob@example.org"))
			kenv, _ := keyed(t, env)
			serveLive(f, live, nil, nil)
			ref := shownRef(t, reg, kenv, "u1")
			_, err := call(t, reg, kenv, "acl_diff", args(n)(ref))
			if err != nil {
				errs = append(errs, strings.ReplaceAll(err.Error(), ref, "<ref>"))
				continue
			}
			got = append(got, "result")
		}
		if len(errs) == 2 {
			if errs[0] != errs[1] {
				t.Errorf("%s: the refusal tells the length of a login:\n%s\n%s", name, errs[0], errs[1])
			}
			if !strings.Contains(errs[0], "could come to more than") {
				t.Errorf("%s: refused for another reason: %s", name, errs[0])
			}
		} else if len(errs) != 0 || len(got) != 2 {
			t.Errorf("%s: one login was refused and the other was not: errors %q, results %d", name, errs, len(got))
		}
	}
}

// A message of the server that begins with no position is kept whole, whatever it holds: only a
// position at the front is left out.
func TestAServerMessageForAPatchWithNoPositionIsKept(t *testing.T) {
	const live = "{\n\"groups\": {\"group:eng\": []}\n}\n"
	f, _, env := apiEnv(t)
	serveLive(f, live, nil, nil)
	f.ServeValidate(apitest.BareMessage200("bad host: edge, line 7, column 45 is not a place"))
	out := validateOnline(t, env, patchCall(`[{"op":"add","path":"/groups/group:eng/-","value":"tag:x"}]`))
	if len(out.Errors) != 1 || out.Errors[0].Message != "bad host: edge, line 7, column 45 is not a place" {
		t.Errorf("errors = %+v", out.Errors)
	}
}

// A live policy this version cannot read is placed by its line: the column of the error counts
// the bytes of logins the caller never saw.
func TestAColumnInAnUnreadableLivePolicyIsLeftOut(t *testing.T) {
	var live []string
	for _, login := range []string{"a@example.com", "averyveryverylonglocalpart@example.com"} {
		live = append(live, "{\n\"groups\": {\"group:a\": [\""+login+"\" \"tag:b\"]}\n}\n")
	}
	for _, tool := range []string{"acl_validate", "acl_diff"} {
		var got []string
		var ps []tools.ACLProblem
		for _, l := range live {
			f, reg, env := apiEnv(t)
			serveLive(f, l, nil, nil)
			f.ServeValidate(apitest.TestsPassEmptyObject())
			args := `{}`
			if tool == "acl_diff" {
				args = `{"against":"{}"}`
			}
			s, err := call(t, reg, env, tool, args)
			if err != nil {
				t.Fatalf("%s: %v", tool, err)
			}
			got = append(got, s)
			if tool == "acl_validate" {
				ps = problemsOf(t, s, "errors")
			} else {
				var out tools.ACLDiffOutput
				if err := json.Unmarshal([]byte(s), &out); err != nil {
					t.Fatal(err)
				}
				ps = out.New.Findings
			}
		}
		sameForBoth(t, tool+" with a live policy that is not readable", got)
		if len(ps) != 1 || ps[0].Source != "live" || ps[0].Line != 2 || ps[0].Column != 0 {
			t.Errorf("%s: problems = %+v, want one at line 2 of the live policy with no column", tool, ps)
		}
	}
}
