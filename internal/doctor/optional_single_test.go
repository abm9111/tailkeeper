package doctor

import (
	"context"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// One missing optional scope is reported like several: as information naming it
// and the feature that is off, and never as a failure.
func TestOneMissingOptionalScopeIsReported(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	addOptionalTool(a.Registry, "zz_ask", registry.StageGA,
		registry.OptionalScope{Scope: "zz_users:read", Reason: "resolve a pseudonym"})
	r := Run(context.Background(), Input{App: a, Now: now})
	var found bool
	for _, c := range r.Checks {
		if c.Name != "optional scopes" {
			continue
		}
		found = true
		want := "missing zz_users:read; these features are off: zz_ask (resolve a pseudonym)"
		if c.Status != Info || c.Detail != want {
			t.Errorf("optional scopes = %+v, want Info and %q", c, want)
		}
	}
	if !found || r.Failed != 0 {
		t.Errorf("found = %v, failed = %d: %+v", found, r.Failed, r.Checks)
	}
}
