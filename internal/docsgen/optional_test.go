package docsgen

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

func addTool(reg *registry.Registry, m registry.Meta) {
	m.Area, m.Verb, m.Summary = m.Name, "get", "s"
	if m.Tier == "" {
		m.Tier = registry.TierRead
	}
	if m.Credential == "" {
		m.Credential = registry.CredRead
	}
	if m.Stage == "" {
		m.Stage = registry.StageGA
	}
	reg.MustAdd(registry.Define(m, func(context.Context, *registry.Env, noIn) (struct{}, error) { return struct{}{}, nil }))
}

func TestHeaderCountsToolsInTheSingular(t *testing.T) {
	one := registry.New()
	addTool(one, registry.Meta{Name: "zz_one", Scopes: []string{"zz:read"}})
	if md := Markdown(one); !strings.Contains(md, "\n1 tool. Each is an MCP tool") || strings.Contains(md, "1 tools.") {
		t.Errorf("one tool:\n%s", md[:400])
	}
	if md := Markdown(registry.New()); !strings.Contains(md, "\n0 tools. Each is an MCP tool") {
		t.Errorf("no tools:\n%s", md[:400])
	}
	addTool(one, registry.Meta{Name: "zy_two", Scopes: []string{"zz:read"}})
	if md := Markdown(one); !strings.Contains(md, "\n2 tools. Each is an MCP tool") {
		t.Errorf("two tools:\n%s", md[:400])
	}
}

// A tool lists the operations it can send, and a call sends some of them.
func TestMarkdownSaysAToolMaySendOnlySomeOfItsOperations(t *testing.T) {
	md := Markdown(registry.New())
	if !strings.Contains(md, "A tool may send only some of the API operations listed for it, depending on its arguments and on what it finds.") {
		t.Errorf("the conditional-operations sentence is missing:\n%s", md[:900])
	}
}

func TestMarkdownShowsOpenWorldCredentialAndOptionalScopes(t *testing.T) {
	reg := registry.New()
	addTool(reg, registry.Meta{Name: "zz_open", Scopes: []string{"zz:read"}, OpenWorld: true, Title: "Send it",
		OptionalScopes: []registry.OptionalScope{{Scope: "zz_users:read", Reason: "resolve a pseudonym | a login"}}})
	addTool(reg, registry.Meta{Name: "zz_opt", Scopes: []string{"zz:read"}, Credential: registry.CredOptional})
	addTool(reg, registry.Meta{Name: "zz_plain", Scopes: []string{"zz:read"}})
	md := Markdown(reg)
	section := func(name string) string {
		i := strings.Index(md, "### `"+name+"`")
		j := strings.Index(md[i+1:], "\n### ")
		if j < 0 {
			j = len(md) - i - 1
		}
		return md[i : i+1+j]
	}
	open, optional, plain := section("zz_open"), section("zz_opt"), section("zz_plain")
	for _, want := range []string{
		"- Title: Send it\n",
		"- Sends your input to Tailscale: yes\n",
		"- Optional OAuth scopes: `zz_users:read` (resolve a pseudonym | a login)\n",
	} {
		if !strings.Contains(open, want) {
			t.Errorf("zz_open lacks %q:\n%s", want, open)
		}
	}
	if !strings.Contains(optional, "- Credential: optional; the tool also runs without one, for the inputs it can answer locally\n") {
		t.Errorf("zz_opt lacks the credential line:\n%s", optional)
	}
	for _, not := range []string{"Title:", "Sends your input", "Optional OAuth scopes", "Credential:"} {
		if strings.Contains(plain, not) {
			t.Errorf("zz_plain shows %q:\n%s", not, plain)
		}
	}
}

// Optional uses are a new column and a new JSON key; the rows and keys that exist
// stay as they are for a scope nothing uses optionally.
func TestScopesCarryOptionalUses(t *testing.T) {
	reg := registry.New()
	addTool(reg, registry.Meta{Name: "zz_full", Scopes: []string{"zz:read"}})
	addTool(reg, registry.Meta{Name: "zz_asks", Scopes: []string{"zz:read"}, OptionalScopes: []registry.OptionalScope{
		{Scope: "zz_users:read", Reason: "resolve a pseudonym"}, {Scope: "zz:read2", Reason: "second | feature"}}})
	addTool(reg, registry.Meta{Name: "zz_alpha", Scopes: []string{"zz_alpha:read"}, Stage: registry.StageAlpha,
		OptionalScopes: []registry.OptionalScope{{Scope: "zz_users:read", Reason: "alpha reason"}}})
	want := []ScopeUse{
		{Scope: "zz:read", Tools: []string{"zz_asks", "zz_full"}},
		{Scope: "zz:read2", Tools: []string{}, OptionalTools: []OptionalUse{{Tool: "zz_asks", Reason: "second | feature"}}},
		{Scope: "zz_alpha:read", Tools: []string{"zz_alpha"}, AlphaOnly: true},
		{Scope: "zz_users:read", Tools: []string{}, OptionalTools: []OptionalUse{
			{Tool: "zz_alpha", Reason: "alpha reason"}, {Tool: "zz_asks", Reason: "resolve a pseudonym"}}},
	}
	if got := Scopes(reg); !reflect.DeepEqual(got, want) {
		t.Errorf("Scopes = %+v\nwant     %+v", got, want)
	}
	md := ScopesMarkdown(reg)
	for _, row := range []string{
		"| Scope | Tools that need it | Tools that read part of their result with it | Tools that use it optionally | Notes |\n",
		"| `zz:read` | `zz_asks`, `zz_full` |  |  |  |\n",
		"| `zz:read2` |  |  | `zz_asks` (second \\| feature) |  |\n",
		"| `zz_alpha:read` | `zz_alpha` |  |  | alpha tools only (MCP lists them with `--enable-alpha`) |\n",
		"| `zz_users:read` |  |  | `zz_alpha` (alpha reason), `zz_asks` (resolve a pseudonym) |  |\n",
	} {
		if !strings.Contains(md, row) {
			t.Errorf("markdown lacks %q:\n%s", row, md)
		}
	}
	// The JSON of a scope with no optional use is what 0.5.0 printed.
	plain, _ := json.Marshal(want[0])
	if strings.Contains(string(plain), "optionalTools") {
		t.Errorf("a scope without optional uses prints optionalTools: %s", plain)
	}
	opt, _ := json.Marshal(want[1])
	if !strings.Contains(string(opt), `"optionalTools":[{"tool":"zz_asks","reason":"second | feature"}]`) {
		t.Errorf("optional uses JSON = %s", opt)
	}
}
