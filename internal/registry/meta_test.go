package registry

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Summary and Notes are written verbatim into docs/tools.md as a heading's text
// and a list item, so a line break in either would break the generated file.
func TestAddRefusesLineBreaksInSummaryNotesAndTitle(t *testing.T) {
	for _, field := range []string{"summary", "notes", "title"} {
		for _, brk := range []string{"\n", "\r", "\r\n"} {
			m := readMeta("echo_lf", "echo", "lf")
			switch field {
			case "summary":
				m.Summary = "first" + brk + "second"
			case "notes":
				m.Notes = "first" + brk + "second"
			case "title":
				m.Title = "first" + brk + "second"
			}
			if err := New().Add(echoTool(m)); err == nil || !strings.Contains(err.Error(), field+" must be one line") {
				t.Errorf("%s with %q: err = %v, want %q", field, brk, err, field+" must be one line")
			}
		}
	}
	ok := readMeta("echo_ok", "echo", "ok")
	ok.Notes, ok.Title = "one line, with a: colon and | pipe.", "Echo a name"
	if err := New().Add(echoTool(ok)); err != nil {
		t.Errorf("a one-line summary, note and title were refused: %v", err)
	}
}

func TestAddChecksTheTitleAndOpenWorld(t *testing.T) {
	open := readMeta("echo_open", "echo", "open")
	open.OpenWorld = true
	if err := New().Add(echoTool(open)); err == nil || !strings.Contains(err.Error(), "open-world tool needs a title") {
		t.Errorf("an open-world tool without a title: %v", err)
	}
	open.Title = "Send a name to Tailscale"
	if err := New().Add(echoTool(open)); err != nil {
		t.Errorf("an open-world tool with a title: %v", err)
	}
	long := readMeta("echo_long", "echo", "long")
	long.Title = strings.Repeat("t", 81)
	if err := New().Add(echoTool(long)); err == nil || !strings.Contains(err.Error(), "title is longer than 80") {
		t.Errorf("a title of 81 characters: %v", err)
	}
	local := Meta{Name: "echo_local", Area: "echo", Verb: "local", Summary: "s", Tier: TierLocal, Stage: StageGA, Credential: CredNone, OpenWorld: true, Title: "t"}
	if err := New().Add(echoTool(local)); err == nil || !strings.Contains(err.Error(), "only API tools") {
		t.Errorf("an open-world local tool: %v", err)
	}
}

func TestAddChecksOptionalScopes(t *testing.T) {
	base := readMeta("echo_opt", "echo", "opt")
	for name, c := range map[string]struct {
		opt  []OptionalScope
		want string
	}{
		"empty scope":       {[]OptionalScope{{Scope: "", Reason: "r"}}, "needs a scope"},
		"empty reason":      {[]OptionalScope{{Scope: "users:read", Reason: ""}}, "needs a reason"},
		"line break":        {[]OptionalScope{{Scope: "users:read", Reason: "a\nb"}}, "reason must be one line"},
		"also required":     {[]OptionalScope{{Scope: "devices:core:read", Reason: "r"}}, "also required"},
		"listed twice":      {[]OptionalScope{{Scope: "users:read", Reason: "r"}, {Scope: "users:read", Reason: "s"}}, "listed twice"},
		"reason too long":   {[]OptionalScope{{Scope: "users:read", Reason: strings.Repeat("r", 201)}}, "reason is longer than 200"},
		"scope with spaces": {[]OptionalScope{{Scope: "users read", Reason: "r"}}, "needs a scope"},
	} {
		m := base
		m.OptionalScopes = c.opt
		if err := New().Add(echoTool(m)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, c.want)
		}
	}
	good := base
	good.OptionalScopes = []OptionalScope{{Scope: "users:read", Reason: "resolve a pseudonym to a login"}}
	if err := New().Add(echoTool(good)); err != nil {
		t.Errorf("a valid optional scope was refused: %v", err)
	}
	local := Meta{Name: "echo_local", Area: "echo", Verb: "local", Summary: "s", Tier: TierLocal, Stage: StageGA, Credential: CredNone,
		OptionalScopes: []OptionalScope{{Scope: "users:read", Reason: "r"}}}
	if err := New().Add(echoTool(local)); err == nil || !strings.Contains(err.Error(), "only read tools") {
		t.Errorf("optional scopes on a local tool: %v", err)
	}
}

// A missing scope fails the tool only when the tool needs it. The hint tells the
// two kinds apart, so a caller does not grant a scope that only enables a feature
// believing the tool cannot run without it.
func TestScopeMissingHintTellsRequiredFromOptional(t *testing.T) {
	fail := func(m Meta) string {
		tool := Define(m, func(context.Context, *Env, echoIn) (echoOut, error) {
			return echoOut{}, tkerr.New(tkerr.ScopeMissing, "forbidden", "a generic hint")
		})
		_, err := tool.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"x"}`))
		return tkerr.From(err).Hint
	}
	plain := readMeta("echo_get", "echo", "get")
	if got, want := fail(plain), "this tool reads with devices:core:read; grant the read credential the one it lacks, unless the feature is not on this plan"; got != want {
		t.Errorf("required only: hint = %q, want %q", got, want)
	}
	withOpt := plain
	withOpt.OptionalScopes = []OptionalScope{{Scope: "users:read", Reason: "resolve a pseudonym"}, {Scope: "policy_file:read", Reason: "read the policy"}}
	want := "this tool reads with devices:core:read; optional scopes, each enabling one feature: users:read (resolve a pseudonym), " +
		"policy_file:read (read the policy); grant the read credential the one it lacks, unless the feature is not on this plan"
	if got := fail(withOpt); got != want {
		t.Errorf("with optional scopes: hint = %q, want %q", got, want)
	}
}
