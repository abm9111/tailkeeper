package docsgen

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

func TestScopesListEveryDeclaredScope(t *testing.T) {
	reg := registry.New()
	tools.Register(reg)
	uses := Scopes(reg)
	by := map[string]ScopeUse{}
	for i, u := range uses {
		if i > 0 && uses[i-1].Scope >= u.Scope {
			t.Errorf("not sorted: %s after %s", u.Scope, uses[i-1].Scope)
		}
		by[u.Scope] = u
	}
	for _, tool := range reg.All() {
		for _, s := range tool.Meta.Scopes {
			u, ok := by[s]
			if !ok {
				t.Errorf("%s: scope %s is missing", tool.Meta.Name, s)
				continue
			}
			if !slices.Contains(u.Tools, tool.Meta.Name) && !slices.Contains(u.PartialTools, tool.Meta.Name) {
				t.Errorf("%s does not list %s", s, tool.Meta.Name)
			}
		}
	}
	if u := by["oauth_apps:read"]; !u.AlphaOnly {
		t.Errorf("oauth_apps:read is used only by alpha tools: %+v", u)
	}
	if u := by["devices:core:read"]; u.AlphaOnly || !slices.Contains(u.Tools, "devices_list") || !slices.Contains(u.PartialTools, "settings_get") {
		t.Errorf("devices:core:read = %+v", u)
	}
	if u := by["logs:network:read"]; !slices.Contains(u.Plans, "network_flow_logs: Premium, Enterprise") {
		t.Errorf("logs:network:read plans = %v", u.Plans)
	}
	// Update this count, and docs/scopes.md (make docs), when a tool's scopes change.
	if len(uses) != 20 {
		t.Errorf("%d scopes, want 20", len(uses))
	}
	md := ScopesMarkdown(reg)
	if ScopesMarkdown(reg) != md {
		t.Error("ScopesMarkdown is not deterministic")
	}
	for _, u := range uses {
		if !strings.Contains(md, "| `"+u.Scope+"` |") {
			t.Errorf("markdown lacks %s", u.Scope)
		}
	}
}

type noIn struct{}

// The scope table is read from the registry: a tool added later, with a scope
// nothing else declares, appears in it without any list being edited.
func TestScopesComeFromTheRegistry(t *testing.T) {
	add := func(reg *registry.Registry, m registry.Meta) {
		m.Area, m.Verb, m.Summary = m.Name, "get", "s"
		m.Tier, m.Credential = registry.TierRead, registry.CredRead
		if m.Stage == "" {
			m.Stage = registry.StageGA
		}
		reg.MustAdd(registry.Define(m, func(context.Context, *registry.Env, noIn) (struct{}, error) { return struct{}{}, nil }))
	}
	reg := registry.New()
	add(reg, registry.Meta{Name: "zz_full", Scopes: []string{"zz:read"}})
	add(reg, registry.Meta{Name: "zz_part", Scopes: []string{"zz:read", "zz_only_part:read"}, PartialScopes: true})
	add(reg, registry.Meta{Name: "zz_plan", Scopes: []string{"zz:read"}, PlanGate: "Premium"})
	add(reg, registry.Meta{Name: "zz_alpha", Scopes: []string{"zz_alpha:read"}, Stage: registry.StageAlpha})

	want := []ScopeUse{
		{Scope: "zz:read", Tools: []string{"zz_full", "zz_plan"}, PartialTools: []string{"zz_part"}, Plans: []string{"zz_plan: Premium"}},
		{Scope: "zz_alpha:read", Tools: []string{"zz_alpha"}, AlphaOnly: true},
		{Scope: "zz_only_part:read", Tools: []string{}, PartialTools: []string{"zz_part"}},
	}
	if got := Scopes(reg); !reflect.DeepEqual(got, want) {
		t.Errorf("Scopes = %+v\nwant     %+v", got, want)
	}
	md := ScopesMarkdown(reg)
	for _, row := range []string{
		"| `zz:read` | `zz_full`, `zz_plan` | `zz_part` |  | Tailscale plans: zz_plan: Premium |\n",
		"| `zz_alpha:read` | `zz_alpha` |  |  | alpha tools only (MCP lists them with `--enable-alpha`) |\n",
		"| `zz_only_part:read` |  | `zz_part` |  |  |\n",
	} {
		if !strings.Contains(md, row) {
			t.Errorf("markdown lacks %q:\n%s", row, md)
		}
	}
	if got := Scopes(registry.New()); len(got) != 0 {
		t.Errorf("an empty registry declares scopes: %+v", got)
	}
}

// Only read tools count, as in `tailkeeper doctor`. The registry will not hold a
// tool of another tier with scopes, so the list is built by hand.
func TestScopesIgnoreToolsThatAreNotReadTools(t *testing.T) {
	tool := func(name string, tier registry.Tier, scopes ...string) registry.Tool {
		return registry.Tool{Meta: registry.Meta{Name: name, Tier: tier, Stage: registry.StageGA, Scopes: scopes}}
	}
	got := scopeUses([]registry.Tool{
		tool("a_read", registry.TierRead, "a:read"),
		tool("b_local", registry.TierLocal, "b:read"),
		tool("c_escalation", registry.TierEscalation, "c:write", "a:read"),
		tool("d_reversible", registry.TierReversible, "d:write"),
	})
	want := []ScopeUse{{Scope: "a:read", Tools: []string{"a_read"}, AlphaOnly: false}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("scopeUses = %+v, want %+v (the other tiers' scopes are not listed, and they are not counted as users of a:read)", got, want)
	}
}

// A tool that reads part of its result still needs one of its scopes: the document
// says so, and no longer says such a tool runs without any.
func TestScopesDocStatesWhenAPartialToolFails(t *testing.T) {
	md := ScopesMarkdown(registry.New())
	if !strings.Contains(md, "fails with `scope_missing` if you grant none of them") || strings.Contains(md, "still runs without it") {
		t.Errorf("the partial-scope sentence is wrong:\n%s", md)
	}
}
