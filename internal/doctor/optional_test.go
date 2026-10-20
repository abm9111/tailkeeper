package doctor

import (
	"context"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

type probeIn struct {
	Name string `json:"name"`
}

func addOptionalTool(a interface{ MustAdd(...registry.Tool) }, name string, stage registry.Stage, opt ...registry.OptionalScope) {
	a.MustAdd(registry.Define(registry.Meta{Name: name, Area: name, Verb: "get", Summary: "s", Tier: registry.TierRead, Stage: stage,
		Credential: registry.CredRead, Scopes: []string{"devices:core:read"}, OptionalScopes: opt},
		func(context.Context, *registry.Env, probeIn) (struct{}, error) { return struct{}{}, nil }))
}

// A missing optional scope turns a feature off and nothing else: doctor says so
// as information, and "every read tool can run" stays true.
func TestOptionalScopesAreInfoNotFailures(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	addOptionalTool(a.Registry, "zz_ask", registry.StageGA,
		registry.OptionalScope{Scope: "zz_users:read", Reason: "resolve a pseudonym"})
	addOptionalTool(a.Registry, "zz_ask2", registry.StageGA,
		registry.OptionalScope{Scope: "zz_users:read", Reason: "resolve a pseudonym in a patch"},
		registry.OptionalScope{Scope: "devices:core:read2", Reason: "read more"})
	addOptionalTool(a.Registry, "zz_alpha", registry.StageAlpha,
		registry.OptionalScope{Scope: "zz_alpha_only:read", Reason: "alpha feature"})
	r := Run(context.Background(), Input{App: a, Now: now})
	if got := status(r, "scopes"); len(got) != 1 || got[0] != OK {
		t.Errorf("scopes = %v: %+v", got, r.Checks)
	}
	if r.Failed != 0 {
		t.Errorf("failed %d, want none: %+v", r.Failed, r.Checks)
	}
	for _, c := range r.Checks {
		if c.Name != "optional scopes" {
			continue
		}
		want := "missing devices:core:read2, zz_users:read; these features are off: zz_ask (resolve a pseudonym), " +
			"zz_ask2 (read more), zz_ask2 (resolve a pseudonym in a patch)"
		if c.Status != Info || c.Detail != want {
			t.Errorf("optional scopes = %+v, want Info and %q", c, want)
		}
		return
	}
	t.Fatalf("no optional scopes check: %+v", r.Checks)
}

func TestAGrantedOptionalScopeIsNotReported(t *testing.T) {
	f, a := newApp(t, allReadScopes(t)+" zz_users:read")
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	addOptionalTool(a.Registry, "zz_ask", registry.StageGA,
		registry.OptionalScope{Scope: "zz_users:read", Reason: "resolve a pseudonym"})
	r := Run(context.Background(), Input{App: a, Now: now})
	if got := status(r, "optional scopes"); len(got) != 0 {
		t.Errorf("optional scopes = %v, want no check when every optional scope is granted", got)
	}
}
