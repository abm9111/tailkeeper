package docsgen

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// addAreaTool registers a tool whose area does not sort like its name, so the
// order the registry lists tools in is not the order of their names.
func addAreaTool(reg *registry.Registry, name, area string, stage registry.Stage, opt ...registry.OptionalScope) {
	reg.MustAdd(registry.Define(registry.Meta{Name: name, Area: area, Verb: "get", Summary: "s", Tier: registry.TierRead,
		Stage: stage, Credential: registry.CredRead, Scopes: []string{"zz:read"}, OptionalScopes: opt},
		func(context.Context, *registry.Env, noIn) (struct{}, error) { return struct{}{}, nil }))
}

// The tools that use a scope optionally are listed by tool name, whatever order
// the registry lists tools in, and a scope that only alpha tools use is alpha
// only even when they use it optionally.
func TestOptionalUsesAreSortedByToolNameAndCountForAlphaOnly(t *testing.T) {
	reg := registry.New()
	addAreaTool(reg, "zz_b", "aa", registry.StageAlpha, registry.OptionalScope{Scope: "zz_users:read", Reason: "b"})
	addAreaTool(reg, "zz_a", "bb", registry.StageAlpha, registry.OptionalScope{Scope: "zz_users:read", Reason: "a"})
	got := Scopes(reg)
	want := []ScopeUse{
		{Scope: "zz:read", Tools: []string{"zz_a", "zz_b"}, AlphaOnly: true},
		{Scope: "zz_users:read", Tools: []string{}, AlphaOnly: true,
			OptionalTools: []OptionalUse{{Tool: "zz_a", Reason: "a"}, {Tool: "zz_b", Reason: "b"}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Scopes = %+v\nwant     %+v", got, want)
	}
	// The same scope used optionally by a tool that is not alpha is not alpha only.
	addAreaTool(reg, "zz_c", "cc", registry.StageGA, registry.OptionalScope{Scope: "zz_users:read", Reason: "c"})
	if got := Scopes(reg); got[1].AlphaOnly {
		t.Errorf("a scope a GA tool uses optionally is alpha only: %+v", got[1])
	}
}

// The table is a Markdown table: its header is followed by the delimiter row.
func TestScopesMarkdownHasADelimiterRowUnderTheHeader(t *testing.T) {
	md := ScopesMarkdown(registry.New())
	header := "| Scope | Tools that need it | Tools that read part of their result with it | Tools that use it optionally | Notes |\n"
	if !strings.Contains(md, header+"|---|---|---|---|---|\n") {
		t.Errorf("no delimiter row under the header:\n%s", md)
	}
}
