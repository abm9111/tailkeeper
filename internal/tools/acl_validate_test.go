package tools_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// goodPolicy is a proposal that is valid HuJSON, with a comment, a trailing comma and a
// test, and names no login.
const goodPolicy = "// a proposal\n{\n\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"]},\n" +
	"\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"tag:ci:22\"]}],\n" +
	"\t\"tests\": [{\"src\": \"tag:ci\", \"accept\": [\"tag:ci:22\"]}],\n}\n"

// runValidate runs acl_validate on an input the test fills in. The switches that exist on
// the command line only (offline, the operator mark) cannot be sent as MCP arguments, so
// the test sets them on the prepared input, as the command line's binder does.
func runValidate(t *testing.T, env *registry.Env, set func(*tools.ACLValidateInput)) (tools.ACLValidateOutput, error) {
	t.Helper()
	tool, ok := newRegistry(t).Get("acl_validate")
	if !ok {
		t.Fatal("acl_validate is not registered")
	}
	p, err := tool.Validate(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	set(p.Input().(*tools.ACLValidateInput))
	out, err := p.Run(context.Background(), env)
	if err != nil {
		return tools.ACLValidateOutput{}, err
	}
	return out.(tools.ACLValidateOutput), nil
}

// offlineValidate checks a text here only, as an operator would with --offline --from.
func offlineValidate(t *testing.T, policy string) tools.ACLValidateOutput {
	t.Helper()
	out, err := runValidate(t, &registry.Env{Now: func() time.Time { return now }}, func(in *tools.ACLValidateInput) {
		in.Policy, in.Offline, in.Operator = policy, true, true
	})
	if err != nil {
		t.Fatalf("offline validate: %v", err)
	}
	return out
}

func TestACLValidateLocalFindings(t *testing.T) {
	for _, c := range []struct {
		name         string
		policy       string
		status, kind string
		line, col    int
		exit         int
		message      string
	}{
		{"a UTF-8 byte order mark", "\xef\xbb\xbf{}", "invalid", "encoding", 1, 1, 2, "byte order mark"},
		{"a UTF-16 byte order mark", "\xff\xfe{\x00}\x00", "invalid", "encoding", 1, 1, 2, "UTF-16"},
		{"a NUL", "{\"a\": \"\x00\"}", "invalid", "encoding", 1, 8, 2, "NUL"},
		{"invalid UTF-8", "{\n\"a\": \"\xff\"}", "invalid", "encoding", 2, 7, 2, "not valid UTF-8"},
		{"a top-level array", "[]", "invalid", "structure", 1, 1, 2, "top level must be a JSON object"},
		{"a syntax error", "{\n  \"acls\": [\n    {,}\n  ]\n}", "invalid", "syntax", 3, 6, 2, ""},
		{"a key written twice", "{\n\"groups\": {},\n\"groups\": {}\n}", "invalid", "duplicate_key", 3, 1, 2, "Tailscale refuses a key written twice here (also at line 2)"},
		{"a top-level case collision", "{\"tests\": [],\n\"Tests\": []}", "invalid", "case_collision", 2, 1, 2, "Tailscale refuses two keys that differ only in case here (also at line 1)"},
		{"nesting past the guard", strings.Repeat("[", 1001), "invalid", "structure", 1, 1001, 2, "nests deeper"},
		{"a CRLF text counts lines by line feed", "{\r\n\"acls\": [\r\n{,}\r\n]\r\n}", "invalid", "syntax", 3, 2, 2, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := offlineValidate(t, c.policy)
			if out.Status != c.status || out.ExitCode() != c.exit || out.ServerChecked || len(out.Errors) != 1 {
				t.Fatalf("status %q exit %d serverChecked %v errors %+v; want %q exit %d, not checked by the server and one error", out.Status, out.ExitCode(), out.ServerChecked, out.Errors, c.status, c.exit)
			}
			p := out.Errors[0]
			if p.Kind != c.kind || p.Source != "from" || p.Severity != "error" || p.FromTailscale {
				t.Errorf("problem = %+v, want an error of kind %s in the proposal, in tailkeeper's words", p, c.kind)
			}
			if c.line != 0 && (p.Line != c.line || p.Column != c.col) {
				t.Errorf("position %d:%d, want %d:%d", p.Line, p.Column, c.line, c.col)
			}
			if !strings.Contains(p.Message, c.message) {
				t.Errorf("message %q lacks %q", p.Message, c.message)
			}
		})
	}
}

// An unknown section is a notice: Tailscale will probably refuse the proposal, but only it
// can say, and the offline check passes what it can read.
func TestAnUnknownSectionIsANoticeAndStillAPass(t *testing.T) {
	out := offlineValidate(t, "{\"nodeAttr\": []}")
	if out.Status != "pass" || len(out.Errors) != 0 || len(out.Notices) != 1 {
		t.Fatalf("status %q, errors %+v, notices %+v", out.Status, out.Errors, out.Notices)
	}
	n := out.Notices[0]
	if n.Kind != "unknown_section" || n.Severity != "notice" || n.Pointer != "/nodeAttr" || !strings.Contains(n.Message, "probably reject") {
		t.Errorf("notice = %+v", n)
	}
}

// An offline result is a local pass, and it says so in every field a script could read.
func TestAnOfflineResultIsNeverAServerPass(t *testing.T) {
	f, _, env := apiEnv(t)
	out, err := runValidate(t, env, func(in *tools.ACLValidateInput) { in.Policy, in.Offline, in.Operator = goodPolicy, true, true })
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "pass" || out.ServerChecked || out.DependsOnLiveState || out.TestsAfter != 1 || out.TestsBefore != 0 {
		t.Errorf("offline result = %+v", out)
	}
	if !contains(out.NotChecked, "server_validation") || !contains(out.NotChecked, "tests") {
		t.Errorf("notChecked = %v, want server_validation and tests among them", out.NotChecked)
	}
	rep := out.Report()
	if !strings.Contains(rep.Verdict, "NOT SENT TO TAILSCALE") || !strings.Contains(rep.Verdict, "1 test in the proposal, not run") {
		t.Errorf("verdict = %q", rep.Verdict)
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("an offline check sent %d requests", n)
	}
}

// An offline check reads no configured invariants file, and says that it did not: the verdict
// must not read as if the owner had configured none. --no-invariants takes them out of the
// call, so there is nothing to say then.
func TestAnOfflineResultNamesAConfiguredInvariantsFileAsNotRun(t *testing.T) {
	env := &registry.Env{Config: &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: "/etc/example/invariants.hujson"}}}}
	for _, c := range []struct {
		name string
		set  func(*tools.ACLValidateInput)
		want bool
	}{
		{"configured", func(in *tools.ACLValidateInput) {}, true},
		{"configured, switched off", func(in *tools.ACLValidateInput) { in.NoInvariants = true }, false},
	} {
		out, err := runValidate(t, env, func(in *tools.ACLValidateInput) {
			in.Policy, in.Offline, in.Operator = goodPolicy, true, true
			c.set(in)
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := contains(out.NotChecked, "invariants"); got != c.want {
			t.Errorf("%s: notChecked = %v, want invariants listed: %v", c.name, out.NotChecked, c.want)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestOfflineNeedsAText(t *testing.T) {
	_, err := runValidate(t, &registry.Env{}, func(in *tools.ACLValidateInput) { in.Offline, in.Operator = true, true })
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidationFailed || !strings.Contains(e.Message, "needs a text to check") {
		t.Errorf("err = %v, want validation_failed saying an offline check needs a text", err)
	}
}

// Without --offline a missing credential is credential_unavailable, never a local pass: a CI
// step that forgot its secret must not turn green.
func TestACLValidateWithoutACredentialIsCredentialUnavailable(t *testing.T) {
	env := &registry.Env{Now: func() time.Time { return now }}
	_, err := runValidate(t, env, func(in *tools.ACLValidateInput) { in.Policy, in.Operator = goodPolicy, true })
	if code(err) != tkerr.CredentialUnavailable || tkerr.ExitCode(err) != 5 {
		t.Errorf("CLI-style call: err = %v, want credential_unavailable and exit 5", err)
	}
	_, err = call(t, newRegistry(t), env, "acl_validate", `{"policy":`+jsonString(goodPolicy)+`}`)
	if code(err) != tkerr.CredentialUnavailable {
		t.Errorf("MCP call: err = %v, want credential_unavailable", err)
	}
}

// The exit code comes from the status alone, and a status this version does not know is
// unknown, never a pass.
func TestTheStatusExitTable(t *testing.T) {
	for status, want := range map[string]int{"pass": 0, "unknown": 1, "invalid": 2, "rejected": 2, "unresolved": 2, "fail": 9, "": 1, "passed": 1, "PASS": 1} {
		if got := (tools.ACLValidateOutput{Status: status}).ExitCode(); got != want {
			t.Errorf("status %q exits %d, want %d", status, got, want)
		}
	}
}

func TestACLValidateFailOnKindsAreAllFive(t *testing.T) {
	kinds := (tools.ACLValidateOutput{}).FailOnKinds()
	if strings.Join(kinds, ",") != "warnings,tests-reduced,defaults,widening,change" {
		t.Errorf("kinds = %v", kinds)
	}
	f := (tools.ACLValidateOutput{
		NewWarnings: make([]tools.ACLProblem, 2),
		Changes:     &tools.ACLChangeCounts{Defaults: 1, TestsReduced: 2, Widening: 3, TailscaleWritten: 4, Semantic: 5, CommentOnly: 6, FormatOnly: 7},
	}).Findings()
	if f.NewWarnings != 2 || f.Defaults != 1 || f.TestsReduced != 2 || f.Widenings != 3 || f.Changes != 12 {
		t.Errorf("findings = %+v, want change to count the entries that changed (the widenings belong to the semantic changes) and not the two classes that are only counted", f)
	}
}

// The fields only the command line can set are no part of the MCP schema, and an MCP call
// that names them is refused.
func TestTheOfflineSwitchAndTheOperatorMarkAreNeverMCPInput(t *testing.T) {
	tool, _ := newRegistry(t).Get("acl_validate")
	for _, name := range []string{"offline", "operator", "invariants", "noInvariants", "Offline", "Operator"} {
		if _, ok := tool.InputSchema.Properties[name]; ok {
			t.Errorf("the MCP schema has a %s property", name)
		}
		if _, err := tool.Validate(json.RawMessage(`{"` + name + `":true}`)); err == nil {
			t.Errorf("an MCP call naming %s was accepted", name)
		}
	}
}

func TestACLValidateDescriptionCarriesItsKeywords(t *testing.T) {
	tool, _ := newRegistry(t).Get("acl_validate")
	first, _, _ := strings.Cut(strings.ToLower(tool.Meta.Summary), ". ")
	for _, word := range []string{"validate", "policy", "proposal", "invariants", "sent to tailscale"} {
		if !strings.Contains(strings.ToLower(tool.Meta.Summary), word) {
			t.Errorf("the summary lacks %q: %s", word, tool.Meta.Summary)
		}
	}
	if !strings.Contains(first, "validate") || !strings.Contains(first, "proposal") || !strings.Contains(first, "invariants") || !strings.Contains(first, "policy") {
		t.Errorf("the first sentence lacks a keyword: %q", first)
	}
	if !tool.Meta.OpenWorld || tool.Meta.Title == "" || tool.Meta.Credential != registry.CredOptional {
		t.Errorf("meta = %+v, want an open-world tool with a title and an optional credential", tool.Meta)
	}
	if strings.Join(tool.Meta.Operations, ",") != "GET /tailnet/{tailnet}/acl,POST /tailnet/{tailnet}/acl/validate,GET /tailnet/{tailnet}/users,GET /tailnet/{tailnet}/settings" {
		t.Errorf("operations = %v", tool.Meta.Operations)
	}
	if len(tool.Meta.OptionalScopes) != 1 || tool.Meta.OptionalScopes[0].Scope != "users:read" {
		t.Errorf("optional scopes = %+v, want users:read to resolve a pseudonym", tool.Meta.OptionalScopes)
	}
}

// The lines of a report are counted by line feed, as Tailscale counts them: the report says
// so beside any finding that has a place.
func TestTheReportSaysHowLinesAreCounted(t *testing.T) {
	located := offlineValidate(t, "{\n\"groups\": {},\n\"groups\": {}\n}").Report()
	last := located.Findings[len(located.Findings)-1]
	if last.Severity != "notice" || !strings.Contains(last.Message, "Lines are counted by line feed and columns in bytes, as Tailscale counts them") {
		t.Errorf("last finding = %+v", last)
	}
	if located.Verdict != "INVALID · 1 problem found before anything was sent to Tailscale" || located.Level != registry.LevelFail {
		t.Errorf("verdict %q level %q", located.Verdict, located.Level)
	}
	plain := offlineValidate(t, goodPolicy).Report()
	for _, f := range plain.Findings {
		if strings.Contains(f.Message, "Lines are counted") {
			t.Errorf("a report with nothing located carries the notice: %+v", f)
		}
	}
	if plain.Level != registry.LevelWarn {
		t.Errorf("an offline pass is shown at level %q, want warn: it was not sent to Tailscale", plain.Level)
	}
}

// The invariants file's syntax is checked offline: only tests and sshTests, no pseudonym,
// the policy's own syntax.
func TestOfflineChecksAnInvariantsFile(t *testing.T) {
	env := &registry.Env{Now: func() time.Time { return now }}
	check := func(text string) tools.ACLValidateOutput {
		t.Helper()
		out, err := runValidate(t, env, func(in *tools.ACLValidateInput) { in.Invariants, in.Offline, in.Operator = text, true, true })
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	ok := check("// the owner's\n{\"tests\": [{\"src\": \"amy@example.com\", \"accept\": [\"tag:ci:22\"]}], \"SSHTests\": [{\"src\": \"tag:ci\", \"dst\": [\"tag:ci\"], \"accept\": [\"root\"]}]}")
	if ok.Status != "pass" || len(ok.Notices) != 1 || !strings.Contains(ok.Notices[0].Message, "2 tests") || !contains(ok.NotChecked, "invariants") {
		t.Errorf("a good file: %+v", ok)
	}
	for name, c := range map[string]struct{ text, kind, pointer string }{
		"another key":                    {`{"acls": []}`, "structure", "/acls"},
		"a pseudonym":                    {`{"tests": [{"src": "[p:abcdefghij]", "accept": ["tag:ci:22"]}]}`, "structure", ""},
		"a section that is not an array": {`{"tests": {}}`, "structure", "/tests"},
		"a test that is not an object":   {`{"tests": ["tag:ci"]}`, "structure", "/tests/0"},
		"a syntax error":                 {"{\"tests\": [\n,]}", "syntax", ""},
		"a key written twice":            {"{\"tests\": [],\n\"tests\": []}", "duplicate_key", ""},
		"a byte order mark":              {"\xef\xbb\xbf{}", "encoding", ""},
	} {
		out := check(c.text)
		if out.Status != "invalid" || len(out.Errors) == 0 || out.Errors[0].Source != "invariants" || out.Errors[0].Kind != c.kind || out.Errors[0].Pointer != c.pointer {
			t.Errorf("%s: status %q, errors %+v; want invalid, a %s problem in the invariants file at %q", name, out.Status, out.Errors, c.kind, c.pointer)
		}
	}
}

// A text past the engine's budget is an error, not a verdict: too_complex, exit 2, refused
// by the guard before the parser allocates for it, with a hint a program can act on.
func TestTooComplexIsAnErrorWithExit2(t *testing.T) {
	huge := `{"x": [` + strings.Repeat("1,", 600_000) + `1]}`
	_, err := runValidate(t, &registry.Env{Now: func() time.Time { return now }}, func(in *tools.ACLValidateInput) {
		in.Policy, in.Offline, in.Operator = huge, true, true
	})
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.TooComplex || tkerr.ExitCode(err) != 2 || !strings.Contains(e.Message, "more than") {
		t.Fatalf("err = %v, want too_complex (exit 2) naming the budget", err)
	}
	if hint := tkerr.ProgramHint(tkerr.TooComplex); !strings.Contains(hint, "over a size or work budget") {
		t.Errorf("hint = %q", hint)
	}
	// The same text as an invariants file is the same error.
	_, err = runValidate(t, &registry.Env{Now: func() time.Time { return now }}, func(in *tools.ACLValidateInput) {
		in.Invariants, in.Offline, in.Operator = huge, true, true
	})
	if code(err) != tkerr.TooComplex {
		t.Errorf("invariants file: err = %v, want too_complex", err)
	}
}
