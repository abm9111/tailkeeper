package doctor

import (
	"context"
	"strings"
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

func TestAMissingOptionalPolicyScopeIsInformationInDoctorNamingDNSGet(t *testing.T) {
	scopes := strings.Join(strings.Fields(strings.ReplaceAll(allReadScopes(t), "policy_file:read", "")), " ")
	f, a := newApp(t, scopes)
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","expires":"2027-01-01T00:00:00Z"}`)
	r := Run(context.Background(), Input{App: a, Now: now})
	var optional, failed string
	for _, c := range r.Checks {
		switch {
		case c.Name == "optional scopes":
			optional = c.Detail
			if c.Status != Info {
				t.Errorf("optional scopes status = %s, want Info", c.Status)
			}
		case c.Name == "scopes" && c.Status == Warn:
			failed = c.Detail
		case c.Status == Fail && strings.Contains(c.Detail, "dns_get"):
			t.Errorf("a failure is attributed to dns_get: %+v", c)
		}
	}
	if !strings.Contains(optional, "policy_file:read") || !strings.Contains(optional, "dns_get (analyse extraDNSRecords and DNS node attributes in the policy)") {
		t.Errorf("optional scopes = %q", optional)
	}
	if strings.Contains(optional, "acl_get") || strings.Contains(optional, "acl_test") || strings.Contains(optional, "acl_validate") || strings.Contains(optional, "acl_diff") {
		t.Errorf("another tool's feature is attributed to the policy scope of dns_get: %q", optional)
	}
	if !strings.Contains(failed, "acl_get") || strings.Contains(failed, "dns_get") {
		t.Errorf("the tools that will fail = %q, and dns_get must not be among them", failed)
	}
}

func TestAGrantedOptionalScopeIsNotReported(t *testing.T) {
	f, a := newApp(t, allReadScopes(t)+" users:read zz_users:read")
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	addOptionalTool(a.Registry, "zz_ask", registry.StageGA,
		registry.OptionalScope{Scope: "zz_users:read", Reason: "resolve a pseudonym"})
	r := Run(context.Background(), Input{App: a, Now: now})
	if got := status(r, "optional scopes"); len(got) != 0 {
		t.Errorf("optional scopes = %v, want no check when every optional scope is granted", got)
	}
}
