package doctor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/audit"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/local"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

var now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

const keyPath = "/api/v2/tailnet/T1234CNTRL/keys/" + apitest.ClientID

// newApp returns a configured App talking to a fake API that grants scope.
func newApp(t *testing.T, scope string) (*apitest.Fake, *app.App) {
	t.Helper()
	f := apitest.New(t)
	f.Scope = scope
	reg := registry.New()
	tools.Register(reg)
	log, err := audit.Open(filepath.Join(t.TempDir(), audit.FileName), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	a := &app.App{Registry: reg, Loaded: &config.Loaded{Source: config.SourceUser, Path: "/home/u/config.hujson"},
		Context: "test", Tailnet: apitest.Tailnet,
		// Built as app.Build builds it, so the masking under test is the real one.
		Credential: creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, Provider: "env"}.String(),
		CredKind:   creds.KindOAuth, KeyID: apitest.ClientID, Audit: log, AuditReads: "metadata",
		Env: &registry.Env{API: f.Client(t), LocalErr: tkerr.New(tkerr.LocalBinaryMissing, "no tailscale CLI found", "")}}
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/contacts", 200, `{"security":{"email":"sec@example.com","needsVerification":false}}`)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/settings", 200, `{"aclsExternallyManagedOn":false}`)
	return f, a
}

func status(r Report, name string) []Status {
	var out []Status
	for _, c := range r.Checks {
		if c.Name == name {
			out = append(out, c.Status)
		}
	}
	return out
}

func allReadScopes(t *testing.T) string {
	reg := registry.New()
	tools.Register(reg)
	return strings.Join(reg.ReadScopes(), " ")
}

func TestHealthyDeployment(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","expires":"2027-01-01T00:00:00Z"}`)
	r := Run(context.Background(), Input{App: a, Now: now})
	if r.Failed != 0 || r.Err() != nil {
		t.Fatalf("failures: %+v", r.Checks)
	}
	for name, want := range map[string]Status{"read credential": OK, "key record": OK, "scopes": OK,
		"security contact": OK, "local tailscale": Warn, "audit log": OK} {
		if got := status(r, name); len(got) != 1 || got[0] != want {
			t.Errorf("%s = %v, want %s", name, got, want)
		}
	}
}

func TestWriteScopeOnReadCredentialFails(t *testing.T) {
	f, a := newApp(t, allReadScopes(t)+" devices:core")
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	r := Run(context.Background(), Input{App: a, Now: now})
	if got := status(r, "scopes"); len(got) != 1 || got[0] != Fail {
		t.Fatalf("scopes = %v: %+v", got, r.Checks)
	}
	if tkerr.ExitCode(r.Err()) != 8 {
		t.Errorf("exit code = %d, want 8", tkerr.ExitCode(r.Err()))
	}
}

func TestMissingScopesNameTheAffectedTools(t *testing.T) {
	f, a := newApp(t, "devices:core:read auth_keys:read")
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	r := Run(context.Background(), Input{App: a, Now: now})
	for _, c := range r.Checks {
		if c.Name == "scopes" {
			if c.Status != Warn || !strings.Contains(c.Detail, "dns_get") || strings.Contains(c.Detail, "devices_list") {
				t.Errorf("scopes check = %+v", c)
			}
			return
		}
	}
	t.Fatal("no scopes check")
}

func TestWrongTailnetFailsTheKeyRecord(t *testing.T) {
	_, a := newApp(t, allReadScopes(t))
	r := Run(context.Background(), Input{App: a, Now: now}) // no fake route: 404
	for _, c := range r.Checks {
		if c.Name == "key record" {
			if c.Status != Fail || !strings.Contains(c.Hint, "tailnetId T123…") {
				t.Errorf("key record = %+v", c)
			}
			return
		}
	}
	t.Fatal("no key record check")
}

func TestReportShowsOnlyTheStartOfTheTailnetID(t *testing.T) {
	for name, route := range map[string]bool{"healthy": true, "wrong tailnet": false} {
		f, a := newApp(t, allReadScopes(t))
		if route {
			f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","expires":"2027-01-01T00:00:00Z"}`)
		}
		r := Run(context.Background(), Input{App: a, Now: now})
		// The two lines doctor writes itself. (An API error's own text, in Detail,
		// is quoted as the API wrote it; the fake's names the request path.)
		for _, c := range r.Checks {
			switch {
			case c.Name == "read credential" && (strings.Contains(c.Detail, apitest.Tailnet) || !strings.Contains(c.Detail, "tailnet T123…")):
				t.Errorf("%s: read credential = %q, want only the start of the tailnet ID", name, c.Detail)
			case c.Name == "read credential" && (strings.Contains(c.Detail, apitest.ClientID) || !strings.Contains(c.Detail, "oauth client test…")):
				t.Errorf("%s: read credential = %q, want only the start of the client ID", name, c.Detail)
			case c.Name == "key record" && strings.Contains(c.Hint, apitest.Tailnet):
				t.Errorf("%s: key record hint = %q prints the whole tailnet ID", name, c.Hint)
			}
		}
	}
}

func TestLargeAuditLogSuggestsRotation(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","expires":"2027-01-01T00:00:00Z"}`)
	if got := status(Run(context.Background(), Input{App: a, Now: now}), "audit log size"); len(got) != 0 {
		t.Errorf("a small log: audit log size = %v, want no check", got)
	}
	defer func(old int64) { rotateAt = old }(rotateAt)
	rotateAt = 1
	r := Run(context.Background(), Input{App: a, Now: now})
	if got := status(r, "audit log size"); len(got) != 1 || got[0] != Warn {
		t.Errorf("audit log size = %v, want one warning", got)
	}
	// Windows has no rotation (audit rotate is refused there), so its hint is the manual
	// procedure; every other platform is pointed at the command.
	wantHint, notHint := "tailkeeper audit rotate", "move the log aside"
	if runtime.GOOS == "windows" {
		wantHint, notHint = "stop every tailkeeper process, then move the log aside", "audit rotate"
	}
	for _, c := range r.Checks {
		if c.Name == "audit log size" && (!strings.Contains(c.Hint, wantHint) || strings.Contains(c.Hint, notHint)) {
			t.Errorf("hint = %q, want it to contain %q and not %q", c.Hint, wantHint, notHint)
		}
	}
}

func TestExpiringKeyWarns(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","expires":"2026-10-12T00:00:00Z"}`)
	r := Run(context.Background(), Input{App: a, Now: now})
	if got := status(r, "key record"); len(got) != 1 || got[0] != Warn {
		t.Errorf("key record = %v", got)
	}
}

func TestBuildErrorIsReported(t *testing.T) {
	r := Run(context.Background(), Input{BuildErr: tkerr.New(tkerr.ConfigUnsafe, "config is group-writable", "chmod 600")})
	if len(r.Checks) != 1 || r.Checks[0].Status != Fail || r.Checks[0].Hint != "chmod 600" {
		t.Errorf("checks = %+v", r.Checks)
	}
}

func TestProbesReportAssumedScopes(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/dns/configuration", 200, `{}`)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/user-invites", 403, `{"message":"forbidden"}`)
	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	if got := status(r, "probe dns_get"); len(got) != 1 || got[0] != OK {
		t.Errorf("dns probe = %v", got)
	}
	if got := status(r, "probe user_invites_list"); len(got) != 1 || got[0] != Warn {
		t.Errorf("user invites probe = %v", got)
	}
}

func TestStrictModeNotEnforcedIsNotClaimed(t *testing.T) {
	strictModeEnforced = false
	t.Cleanup(func() { strictModeEnforced = config.StrictModeEnforced })
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	r := Run(context.Background(), Input{App: a, Now: now})
	for _, c := range r.Checks {
		if c.Name == "configuration" {
			if c.Status != Warn || strings.Contains(c.Detail, "verified") {
				t.Errorf("configuration = %+v", c)
			}
			return
		}
	}
	t.Fatal("no configuration check")
}

func TestAlphaScopesAreInfoNotWarn(t *testing.T) {
	var scopes []string
	for _, s := range strings.Fields(allReadScopes(t)) {
		if s != "oauth_apps:read" {
			scopes = append(scopes, s)
		}
	}
	f, a := newApp(t, strings.Join(scopes, " "))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	r := Run(context.Background(), Input{App: a, Now: now})
	if got := status(r, "scopes"); len(got) != 1 || got[0] != OK {
		t.Errorf("scopes = %v: %+v", got, r.Checks)
	}
	if got := status(r, "alpha scopes"); len(got) != 1 || got[0] != Info {
		t.Errorf("alpha scopes = %v", got)
	}
}

func TestCredentialShapesInChecksAreWithheld(t *testing.T) {
	// Assembled at run time so that no credential shape sits in the source.
	key := "tskey" + "-api-" + "kTEST1CNTRL-" + "notarealsecretvalue"
	r := Run(context.Background(), Input{BuildErr: tkerr.New(tkerr.ConfigInvalid, "config.hujson line 3: "+key, "remove "+key), Now: now})
	if len(r.Checks) != 1 || r.Failed != 1 || strings.Contains(r.Checks[0].Detail+r.Checks[0].Hint, "tskey") ||
		!strings.Contains(r.Checks[0].Detail, "withheld") {
		t.Errorf("checks = %+v", r.Checks)
	}
}

func TestPartialScopeToolsAreInfoNotFailures(t *testing.T) {
	var scopes []string
	for _, s := range strings.Fields(allReadScopes(t)) {
		if s != "auth_keys:read" {
			scopes = append(scopes, s)
		}
	}
	f, a := newApp(t, strings.Join(scopes, " "))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	r := Run(context.Background(), Input{App: a, Now: now})
	if got := status(r, "scopes"); len(got) != 1 || got[0] != OK {
		t.Errorf("scopes = %v: %+v", got, r.Checks)
	}
	for _, c := range r.Checks {
		if c.Name == "partial scopes" {
			if c.Status != Info || c.Detail != "missing auth_keys:read; these tools return only what the granted scopes cover: key_get, keys_list" {
				t.Errorf("partial scopes = %+v", c)
			}
			return
		}
	}
	t.Error("no partial scopes check")
}

func TestPartialScopeToolWithNoneGrantedFails(t *testing.T) {
	f, a := newApp(t, "devices:core:read")
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	r := Run(context.Background(), Input{App: a, Now: now})
	seen := 0
	for _, c := range r.Checks {
		switch c.Name {
		case "scopes":
			seen++
			if c.Status != Warn || !strings.Contains(c.Detail, "keys_list") || strings.Contains(c.Detail, "settings_get") {
				t.Errorf("scopes = %+v", c)
			}
		case "partial scopes":
			seen++
			if c.Status != Info || !strings.Contains(c.Detail, "settings_get") || strings.Contains(c.Detail, "keys_list") {
				t.Errorf("partial scopes = %+v", c)
			}
		}
	}
	if seen != 2 {
		t.Errorf("checks = %+v", r.Checks)
	}
}

func TestPersonalModeIsStated(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	r := Run(context.Background(), Input{App: a, Now: now})
	if got := status(r, "personal mode"); len(got) != 1 || got[0] != Info {
		t.Errorf("personal mode = %v", got)
	}
	a.Loaded.Source = config.SourceSystem
	r = Run(context.Background(), Input{App: a, Now: now})
	if got := status(r, "personal mode"); len(got) != 0 {
		t.Errorf("system configuration: personal mode = %v", got)
	}
}

func TestUnknownDaemonVersionWarns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in tailscale CLI is a shell script")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "tailscale")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho '{\"majorMinorPatch\":\"1.102.5\",\"long\":\"1.102.5-tTEST\"}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	a.Env.LocalErr = nil
	a.Env.Local = &local.Runner{Bin: local.Binary{Path: bin, Variant: local.VariantConfigured}, Home: dir, PerMinute: 1000}
	r := Run(context.Background(), Input{App: a, Now: now})
	for _, c := range r.Checks {
		if c.Name == "local tailscale" {
			if c.Status != Warn || !strings.Contains(c.Detail, "daemon unknown") {
				t.Errorf("local tailscale = %+v", c)
			}
			return
		}
	}
	t.Error("no local tailscale check")
}

func TestDoctorReadsAreTimed(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	Run(context.Background(), Input{App: a, Now: now})
	b, err := os.ReadFile(a.Audit.Path())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for _, line := range lines {
		if !strings.Contains(line, `"ms":`) {
			t.Errorf("record without ms: %s", line)
		}
	}
	if len(lines) < 3 {
		t.Errorf("only %d records", len(lines))
	}
}

func TestKeyRecordScopesCountWhenTheTokenNamesNone(t *testing.T) {
	f, a := newApp(t, "")
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","scopes":["devices:core:read","policy_file"]}`)
	r := Run(context.Background(), Input{App: a, Now: now})
	if got := status(r, "scopes"); len(got) == 0 || got[0] != Fail {
		t.Fatalf("scopes = %v: %+v", got, r.Checks)
	}
}

func TestChecksThatCannotRunAreListed(t *testing.T) {
	_, a := newApp(t, allReadScopes(t))
	a.Env.APIErr = tkerr.New(tkerr.CredentialUnavailable, "no read credential is configured", "")
	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	for _, name := range []string{"key record", "scopes", "security contact", "gitops lock", "probe dns_get"} {
		if got := status(r, name); len(got) != 1 || got[0] != NA {
			t.Errorf("%s = %v", name, got)
		}
	}
}

func TestFailedReadsAreWarningsNotNA(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/contacts", 500, `{"message":"boom"}`)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/settings", 403, `{"message":"forbidden"}`)
	r := Run(context.Background(), Input{App: a, Now: now})
	for _, c := range r.Checks {
		if (c.Name == "security contact" || c.Name == "gitops lock") && (c.Status != Warn || strings.Contains(c.Hint, "tailkeeper doctor")) {
			t.Errorf("%s = %+v", c.Name, c)
		}
	}
	if got := status(r, "gitops lock"); len(got) != 1 {
		t.Errorf("gitops lock = %v", got)
	}
}

func TestProbesDoNotPassUnexercisedEndpoints(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/settings", 200, `{"networkFlowLoggingOn":false}`)
	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	for _, name := range []string{"probe network_flow_logs", "probe log_streaming_get"} {
		if got := status(r, name); len(got) != 1 || got[0] != NA {
			t.Errorf("%s = %v", name, got)
		}
	}
}

func TestExpiredKeyFails(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","expires":"2026-10-01T00:00:00Z"}`)
	r := Run(context.Background(), Input{App: a, Now: now})
	if got := status(r, "key record"); len(got) != 1 || got[0] != Fail {
		t.Errorf("key record = %v", got)
	}
}

// canaryPolicy is a live policy that defines a tag, which is the source and the destination
// of the acl_test canary.
const canaryPolicy = "{\"tagOwners\": {\"tag:ci\": []}, \"acls\": []}\n"

// The acl_test canary cannot pass under any policy: an answer with no failure for it means the
// validate response is misread, which doctor --probe must report as a failure. It is sent
// from a tag the live policy defines, so that Tailscale evaluates it.
func TestACLTestCanary(t *testing.T) {
	canaryFailure := apitest.Entry{User: "tag:ci", Errors: []string{`[acl test error]: address "tag:ci:1" (protocol "tcp"): want: Accept, got: Drop`}}
	for _, c := range []struct {
		name  string
		shape apitest.Shape
		want  Status
	}{
		{"read as failed", apitest.TestsFailed(canaryFailure), OK},
		{"failures in a 400", apitest.TestsFailedIn400(canaryFailure), OK},
		{"a pass body, which a test that cannot pass never gets", apitest.TestsPass(), Fail},
		{"an empty object, which the live API answers a pass with", apitest.TestsPassEmptyObject(), Fail},
		{"warnings only", apitest.TestsWarned(apitest.Entry{User: "tag:ci", Warnings: []string{"tag:ci is not defined"}}), Warn},
		{"a line nobody can pair", apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{`[acl test error]: address "tag:other:9" (protocol "tcp"): want: Accept, got: Drop`}}), Warn},
		{"refused as invalid", apitest.Rejected400("tag not found"), Warn},
		{"an unrecognised pass", apitest.ErrorsListAt200("tag not found"), Warn},
		{"refused with a bare message at 200, as the live API refuses a document", apitest.PolicyTagNotFound("tag:ci"), Warn},
		{"a source the policy does not resolve", apitest.TestUnevaluable("tag:ci"), Warn},
		{"scope missing", apitest.Forbidden403(), Warn},
	} {
		f, a := newApp(t, allReadScopes(t))
		f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
		f.ServeDetails(apitest.DetailsOK(canaryPolicy, `"e1"`, nil, nil))
		f.ServeValidate(c.shape)
		r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
		if got := status(r, "probe acl_test"); len(got) != 1 || got[0] != c.want {
			t.Errorf("%s: probe acl_test = %v, want %s", c.name, got, c.want)
		}
		if got := status(r, "probe acl_get"); len(got) != 1 || got[0] != OK {
			t.Errorf("%s: probe acl_get = %v", c.name, got)
		}
		var sent string
		for _, req := range f.Requests() {
			if req.Method == "POST" {
				sent = string(req.Body)
			}
		}
		if !strings.Contains(sent, `"src":"tag:ci"`) || !strings.Contains(sent, `"accept":["tag:ci:1"],"deny":["tag:ci:1"]`) {
			t.Errorf("%s: canary sent %s", c.name, sent)
		}
	}
}

// On a tailnet whose policy defines no tag there is no source the canary can use, and the
// check is not applicable: it is no warning, and nothing is sent. Tailscale answers a test from
// a tag nobody defined with unresolved on every tailnet, which would warn every run.
func TestTheCanaryNeedsATagTheLivePolicyDefines(t *testing.T) {
	for name, policy := range map[string]string{
		"no tag":             "{\"acls\": []}\n",
		"tagOwners is empty": "{\"tagOwners\": {}, \"groups\": {\"group:eng\": []}}\n",
		"only odd names":     "{\"tagOwners\": {\"tag:a b\": [], \"tag:\": []}}\n",
	} {
		f, a := newApp(t, allReadScopes(t))
		f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
		f.ServeDetails(apitest.DetailsOK(policy, `"e1"`, nil, nil))
		f.ServeValidate(apitest.TestUnevaluable("tag:ci"))
		r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
		if got := status(r, "probe acl_test"); len(got) != 1 || got[0] != NA {
			t.Errorf("%s: probe acl_test = %v, want %s", name, got, NA)
		}
		for _, req := range f.Requests() {
			if req.Method == "POST" {
				t.Errorf("%s: a canary was sent: %s", name, req.Body)
			}
		}
	}
	// The first tag, in the order the summary lists them, is the one used.
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	f.ServeDetails(apitest.DetailsOK("{\"tagOwners\": {\"tag:web\": [], \"tag:db\": []}}\n", `"e1"`, nil, nil))
	f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: "tag:db", Errors: []string{`[acl test error]: address "tag:db:1" (protocol "tcp"): want: Accept, got: Drop`}}))
	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	if got := status(r, "probe acl_test"); len(got) != 1 || got[0] != OK {
		t.Errorf("two tags: probe acl_test = %v", got)
	}
}

// A canary that tailkeeper refuses itself never reaches the endpoint, so it can
// prove nothing: that is a failure, not the endpoint's refusal.
func TestCanaryVerdictReadsTheStatus(t *testing.T) {
	fail := tools.ACLTestOutput{Status: "fail", Verdicts: []tools.ACLTestVerdict{{Verdict: "denied"}}}
	if st, _, _, ok := canaryVerdict(fail, nil); !ok || st != OK {
		t.Errorf("fail with a denied verdict = %s %v, want OK", st, ok)
	}
	pass := tools.ACLTestOutput{Status: "pass"}
	if st, _, _, ok := canaryVerdict(pass, nil); !ok || st != Fail {
		t.Errorf("pass = %s %v, want Fail", st, ok)
	}
	// An unknown with nothing in it is the answer of a validator that read a test no policy can
	// pass as a pass; an unknown that holds a line or a warning is a line nobody could pair.
	if st, detail, _, ok := canaryVerdict(tools.ACLTestOutput{Status: "unknown"}, nil); !ok || st != Fail || !strings.Contains(detail, "misreads") {
		t.Errorf("unknown with nothing = %s %q %v, want Fail", st, detail, ok)
	}
	for name, out := range map[string]tools.ACLTestOutput{
		"an unpaired line": {Status: "unknown", Unmatched: []string{"x"}},
		"a failure":        {Status: "unknown", Failures: []tools.ACLTestResult{{Src: "tag:ci", Errors: []string{"x"}}}},
		"a warning":        {Status: "unknown", Warnings: []string{"w"}},
		"another test":     {Status: "unknown", OtherTests: []tools.ACLTestResult{{Src: "tag:o", Errors: []string{"x"}}}},
	} {
		if st, detail, _, ok := canaryVerdict(out, nil); !ok || st != Warn || !strings.Contains(detail, "was not exercised") {
			t.Errorf("unknown with %s = %s %q %v, want Warn", name, st, detail, ok)
		}
	}
	for _, status := range []string{"unresolved", "something else"} {
		st, detail, _, ok := canaryVerdict(tools.ACLTestOutput{Status: status}, nil)
		if !ok || st != Warn || !strings.Contains(detail, "was not exercised") {
			t.Errorf("%s = %s %q %v, want Warn", status, st, detail, ok)
		}
	}
}

func TestCanaryRefusedLocallyFails(t *testing.T) {
	local := tkerr.New(tkerr.ValidationFailed, "give at least one destination", "")
	if st, detail, _, ok := canaryVerdict(tools.ACLTestOutput{}, local); !ok || st != Fail || !strings.Contains(detail, "refused its own canary") {
		t.Errorf("local refusal = %s %q %v", st, detail, ok)
	}
	remote := &tkerr.Error{Code: tkerr.ValidationFailed, Message: "tag not found", Status: 400}
	if st, _, _, ok := canaryVerdict(tools.ACLTestOutput{}, remote); !ok || st != Warn {
		t.Errorf("API refusal = %s %v", st, ok)
	}
	if _, _, _, ok := canaryVerdict(tools.ACLTestOutput{}, tkerr.New(tkerr.ScopeMissing, "forbidden", "")); ok {
		t.Error("a missing scope must be reported as a failed read")
	}
}

// A policy written on one line, as GitOps tools may generate it, is readable:
// the probe asks for the largest page, so its first line fits.
func TestProbeReadsAOneLinePolicy(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	f.ServeDetails(apitest.DetailsOK(`{"acls":[`+strings.Repeat(`{"action":"accept","src":["tag:ci"],"dst":["tag:prod:22"]},`, 60)+`]}`, `"e1"`, nil, nil))
	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	if got := status(r, "probe acl_get"); len(got) != 1 || got[0] != OK {
		t.Errorf("probe acl_get = %v", got)
	}
}

func TestPrivacyKeyIsReported(t *testing.T) {
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		set  func(*app.App)
		want Status
	}{
		"none":      {func(*app.App) {}, Warn},
		"loaded":    {func(a *app.App) { a.Env.Privacy = k }, OK},
		"malformed": {func(a *app.App) { a.Env.PrivacyErr = tkerr.New(tkerr.PrivacyKeyUnavailable, "bad", "") }, Fail},
		"oidc":      {func(a *app.App) { a.Provider = config.Provider{Provider: "oidc"} }, Info},
		"shown": {func(a *app.App) {
			a.Loaded.Config.PersonalData = config.PersonalDataShow
			a.Env.Config = a.Loaded
		}, Info},
	} {
		f, a := newApp(t, allReadScopes(t))
		f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","expires":"2027-01-01T00:00:00Z"}`)
		c.set(a)
		r := Run(context.Background(), Input{App: a, Now: now})
		if got := status(r, "privacy key"); len(got) != 1 || got[0] != c.want {
			t.Errorf("%s: privacy key = %v, want %s", name, got, c.want)
		}
		if name == "oidc" {
			for _, ch := range r.Checks {
				if ch.Name == "privacy key" && (!strings.Contains(ch.Detail, "oidc stores no secret") || ch.Hint != "") {
					t.Errorf("oidc: the check must say why there is no key and give no hint to follow: %+v", ch)
				}
			}
		}
	}
}

func TestPrivacyKeyIsSkippedWithoutConfiguration(t *testing.T) {
	_, a := newApp(t, allReadScopes(t))
	a.Loaded = nil
	a.Env.APIErr = tkerr.New(tkerr.ConfigMissing, "no configuration", "")
	r := Run(context.Background(), Input{App: a, Now: now})
	if got := status(r, "privacy key"); len(got) != 1 || got[0] != NA {
		t.Errorf("privacy key = %v, want n/a", got)
	}
}

func TestPrivacyKeyReportCarriesNoKeyMaterial(t *testing.T) {
	hex := strings.Repeat("5a", 32)
	k, err := privacy.Parse(hex)
	if err != nil {
		t.Fatal(err)
	}
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","expires":"2027-01-01T00:00:00Z"}`)
	a.Env.Privacy = k
	_, bad := privacy.Parse(hex + "zz")
	a.Env.PrivacyErr = bad
	r := Run(context.Background(), Input{App: a, Now: now})
	for _, c := range r.Checks {
		if c.Name == "privacy key" && (strings.Contains(c.Detail, hex) || strings.Contains(c.Hint, hex) || strings.Contains(c.Detail, "zz")) {
			t.Errorf("privacy key check carries key material: %+v", c)
		}
	}
	if got := status(r, "privacy key"); len(got) != 1 || got[0] != Fail {
		t.Errorf("privacy key = %v, want fail", got)
	}
}

func TestChecksAreEscaped(t *testing.T) {
	const rlo, zwsp, lri = "\xe2\x80\xae", "\xe2\x80\x8b", "\xe2\x81\xa6"
	const bs = "\x5c"
	r := Run(context.Background(), Input{BuildErr: tkerr.New(tkerr.ConfigInvalid, "config.hujson line 3: "+rlo+"evil"+zwsp, "fix "+lri+" it"), Now: time.Now()})
	seen := false
	for _, c := range r.Checks {
		text := c.Detail + "\n" + c.Hint
		if strings.ContainsAny(text, rlo+zwsp+lri) {
			t.Errorf("check %s prints an invisible rune raw: %q", c.Name, text)
		}
		if strings.Contains(text, bs+"u{202E}evil"+bs+"u{200B}") {
			seen = true
		}
	}
	if !seen {
		t.Error("no check shows the escaped text")
	}
}
