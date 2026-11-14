package doctor

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

type gapOut struct {
	Ready bool `json:"ready"`
}

// gapAlphaTool is a throwaway alpha tool of a test, with scopes. It is added to the registry of
// the test's own app and nowhere else.
func gapAlphaTool(name, verb string, scopes ...string) registry.Tool {
	return registry.Define(registry.Meta{Name: name, Area: "gap", Verb: verb, Summary: "A throwaway tool of a test.",
		Tier: registry.TierRead, Stage: registry.StageAlpha, Credential: registry.CredRead, Scopes: scopes},
		func(context.Context, *registry.Env, struct{}) (gapOut, error) { return gapOut{Ready: true}, nil })
}

func checkOf(t *testing.T, r Report, name string) Check {
	t.Helper()
	var found []Check
	for _, c := range r.Checks {
		if c.Name == name {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d checks named %q: %+v", len(found), name, r.Checks)
	}
	return found[0]
}

// A scope an alpha tool shares with a tool that is advertised by default is needed by default,
// and is not listed again as one that only the alpha tools need: "needed only with --enable-alpha"
// would be false for it.
func TestAScopeSharedByAnAlphaAndANonAlphaToolIsNotCalledAlphaOnly(t *testing.T) {
	const shared = "devices:core:read"
	var granted []string
	for _, s := range strings.Fields(allReadScopes(t)) {
		if s != shared {
			granted = append(granted, s)
		}
	}
	f, a := newApp(t, strings.Join(granted, " "))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	a.Registry.MustAdd(gapAlphaTool("gap_shared", "shared", shared), gapAlphaTool("gap_own", "own", "zz_alpha:read"))
	r := Run(context.Background(), Input{App: a, Now: now})

	// The scope is missing, and a tool that is advertised by default needs it.
	if c := checkOf(t, r, "scopes"); c.Status != Warn || !strings.Contains(c.Detail, shared) || !strings.Contains(c.Detail, "devices_list") ||
		strings.Contains(c.Detail, "gap_shared") {
		t.Errorf("scopes = %+v: want %s named with the tools advertised by default, and no alpha tool", c, shared)
	}
	// The alpha check names the scope only the alpha tool needs, and not the shared one.
	c := checkOf(t, r, "alpha scopes")
	if c.Status != Info || !strings.Contains(c.Detail, "zz_alpha:read") || !strings.Contains(c.Detail, "gap_own") ||
		strings.Contains(c.Detail, shared) || strings.Contains(c.Detail, "gap_shared") {
		t.Errorf("alpha scopes = %+v: want only zz_alpha:read and gap_own", c)
	}
}

// The probe of the flow log asks for one record, so a tailnet with a busy log is not read whole.
// What the probe returned shows in the audit line of its read: the bytes of one record, and not
// of the three the log holds.
func TestTheFlowLogProbeAsksForOneRecord(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/settings", 200, `{"networkFlowLoggingOn":true}`)
	record := func(node string) string {
		return `{"nodeId":"` + node + `","logged":"2026-10-10T11:59:00Z","virtualTraffic":[{"proto":6,"src":"100.64.0.1:5000","dst":"100.64.0.2:443","txBytes":10}]}`
	}
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/logging/network", 200, `{"logs":[`+record("nAAA1CNTRL")+`,`+record("nBBB2CNTRL")+`,`+record("nCCC3CNTRL")+`]}`)

	// What the tool returns for one record and for three, called as the probe calls it.
	tool, ok := a.Registry.Get("network_flow_logs")
	if !ok {
		t.Fatal("network_flow_logs is not registered")
	}
	size := func(args string) int {
		out, err := tool.Call(context.Background(), a.Env, json.RawMessage(args))
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	}
	one, three := size(`{"maxRecords":1}`), size(`{"maxRecords":3}`)
	if one >= three {
		t.Fatalf("one record is %d bytes and three are %d: the fixture cannot tell the two apart", one, three)
	}

	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	if c := checkOf(t, r, "probe network_flow_logs"); c.Status != OK {
		t.Fatalf("probe network_flow_logs = %+v", c)
	}
	data, err := os.ReadFile(a.Audit.Path())
	if err != nil {
		t.Fatal(err)
	}
	var probed []int
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var l struct {
			Tool      string         `json:"tool"`
			Bytes     int            `json:"bytes"`
			Requester map[string]any `json:"requester"`
		}
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			t.Fatal(err)
		}
		if l.Tool == "network_flow_logs" && l.Requester["kind"] == "doctor" {
			probed = append(probed, l.Bytes)
		}
	}
	if len(probed) != 1 || probed[0] != one {
		t.Errorf("the probe's read returned %v bytes, want %d (one record); three would be %d", probed, one, three)
	}
}

// The privacy-key check reads the failure before the setting, and the setting before the key:
// with personalData show the key is not used, which is information, unless it is malformed,
// which is a failure.
func TestThePrivacyCheckPrecedence(t *testing.T) {
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	_, malformed := privacy.Parse(strings.Repeat("5a", 32) + "zz")
	show := func(a *app.App) {
		a.Loaded.Config.PersonalData = config.PersonalDataShow
		a.Env.Config = a.Loaded
	}
	for name, c := range map[string]struct {
		set    func(*app.App)
		want   Status
		detail string
	}{
		"show, key loaded":         {func(a *app.App) { show(a); a.Env.Privacy = k }, Info, "the privacy key is not used"},
		"show, key malformed":      {func(a *app.App) { show(a); a.Env.PrivacyErr = malformed }, Fail, string(tkerr.PrivacyKeyUnavailable)},
		"show, key loaded and bad": {func(a *app.App) { show(a); a.Env.Privacy = k; a.Env.PrivacyErr = malformed }, Fail, string(tkerr.PrivacyKeyUnavailable)},
		"masked, key loaded":       {func(a *app.App) { a.Env.Privacy = k }, OK, "loaded"},
		"masked, key malformed":    {func(a *app.App) { a.Env.PrivacyErr = malformed }, Fail, string(tkerr.PrivacyKeyUnavailable)},
		"masked, no key":           {func(*app.App) {}, Warn, "none"},
	} {
		f, a := newApp(t, allReadScopes(t))
		f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","expires":"2027-01-01T00:00:00Z"}`)
		c.set(a)
		r := Run(context.Background(), Input{App: a, Now: now})
		got := checkOf(t, r, "privacy key")
		if got.Status != c.want || !strings.Contains(got.Detail, c.detail) {
			t.Errorf("%s: privacy key = %s %q, want %s with %q", name, got.Status, got.Detail, c.want, c.detail)
		}
		wantFail := 0
		if c.want == Fail {
			wantFail = 1
		}
		if r.Failed != wantFail {
			t.Errorf("%s: %d checks failed, want %d: %+v", name, r.Failed, wantFail, r.Checks)
		}
	}
}

// The privacy-key check carries no key material in any state, in its detail or its hint and in the
// report as a program reads it: not the key's hexadecimal, not its bytes in base64, and not the
// malformed suffix of a key that failed to parse, even when the error that came with it holds the
// text it could not parse.
func TestThePrivacyCheckCarriesNoKeyMaterialInAnyState(t *testing.T) {
	const suffix = "zz"
	key := strings.Repeat("5a", 32)
	k, err := privacy.Parse(key)
	if err != nil {
		t.Fatal(err)
	}
	_, parseErr := privacy.Parse(key + suffix)
	raw, _ := hex.DecodeString(key)
	secrets := []string{key, strings.ToUpper(key), key + suffix, base64.StdEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw)[:16]}
	// An error whose cause holds the text it could not parse: what a different reader of the key
	// might return. Nothing but its code, message and hint may reach the report.
	carrying := tkerr.Wrap(tkerr.PrivacyKeyUnavailable, errors.New("cannot parse "+key+suffix), "the privacy key is malformed", "generate a new one")
	show := func(a *app.App) {
		a.Loaded.Config.PersonalData = config.PersonalDataShow
		a.Env.Config = a.Loaded
	}
	for name, set := range map[string]func(*app.App){
		"none":                     func(*app.App) {},
		"loaded":                   func(a *app.App) { a.Env.Privacy = k },
		"malformed":                func(a *app.App) { a.Env.PrivacyErr = parseErr },
		"malformed, with its text": func(a *app.App) { a.Env.PrivacyErr = carrying },
		"loaded and malformed":     func(a *app.App) { a.Env.Privacy = k; a.Env.PrivacyErr = carrying },
		"shown, loaded":            func(a *app.App) { show(a); a.Env.Privacy = k },
		"shown, malformed":         func(a *app.App) { show(a); a.Env.PrivacyErr = carrying },
	} {
		f, a := newApp(t, allReadScopes(t))
		f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","expires":"2027-01-01T00:00:00Z"}`)
		set(a)
		r := Run(context.Background(), Input{App: a, Now: now})
		c := checkOf(t, r, "privacy key")
		if c.Detail == "" {
			t.Errorf("%s: the check says nothing", name)
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			for field, text := range map[string]string{"detail": c.Detail, "hint": c.Hint, "report": string(b)} {
				if strings.Contains(text, s) {
					t.Errorf("%s: the privacy-key check %s carries %q: %s", name, field, s, text)
				}
			}
		}
		// The suffix is two letters, so it is looked for only where the check writes its own words.
		for field, text := range map[string]string{"detail": c.Detail, "hint": c.Hint} {
			if strings.Contains(text, suffix) {
				t.Errorf("%s: the privacy-key check %s carries the malformed suffix %q: %q", name, field, suffix, text)
			}
		}
	}
}
