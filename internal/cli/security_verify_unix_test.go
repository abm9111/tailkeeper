//go:build !windows

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func verifyFleetFixture(t *testing.T) (*harness, *apitest.Fake, string, time.Time) {
	t.Helper()
	at := scanAt(t)
	f := apitest.New(t)
	setVerifyFleet(t, f, at, "1.28.2-t0123456ab", true)
	h := newHarness(t, f)
	h.app.Env.Now = func() time.Time { return at }
	h.app.Env.RecordObservation = h.app.RecordObservation
	h.app.Env.RecordPack = h.app.RecordPack
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h.app.Env.Config = &config.Loaded{Dirs: config.Dirs{State: dir}}
	before := filepath.Join(dir, "before.json")
	if code := h.run("security", "export", "--scope", "fleet", "--out", before); code != 0 {
		t.Fatalf("export exit %d: %s %s", code, h.out, h.err)
	}
	h.out.Reset()
	h.err.Reset()
	return h, f, before, at
}

func setVerifyFleet(t *testing.T, f *apitest.Fake, at time.Time, version string, connected bool) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"devices": []map[string]any{scanDevice(at, "nOLD01CNTRL", version, map[string]any{"connectedToControl": connected})}})
	if err != nil {
		t.Fatal(err)
	}
	f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/devices", 200, string(body))
}

func verifyCorrectionFile(t *testing.T, dir string, text string) string {
	t.Helper()
	path := filepath.Join(dir, "correction.json")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func versionCorrection(at time.Time, device string) string {
	return fmt.Sprintf(`{"schema_version":1,"action_at":%q,"expect":{"versions":[{"device":%q,"name":"client","at_least":"1.32.3"}]}}`, at.UTC().Format(time.RFC3339), device)
}

func TestSecurityVerifyRefusalsDoNotCollect(t *testing.T) {
	tests := []struct {
		name       string
		correction func(time.Time) string
		before     func(string) string
		want       string
	}{
		{name: "invalid correction precedes unreadable pack", correction: func(time.Time) string { return `{}` }, before: func(p string) string { return p + ".missing" }, want: "correction_invalid"},
		{name: "unknown device", correction: func(at time.Time) string { return versionCorrection(at.Add(time.Minute), "nMISSINGCNTRL") }, want: "device_not_in_pack"},
		{name: "action before baseline", correction: func(at time.Time) string { return versionCorrection(at, "nOLD01CNTRL") }, want: "action_not_after_observation"},
		{name: "action in future", correction: func(at time.Time) string { return versionCorrection(at.Add(10*time.Minute), "nOLD01CNTRL") }, want: "action_in_future"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, f, before, at := verifyFleetFixture(t)
			if tc.before != nil {
				before = tc.before(before)
			}
			correction := verifyCorrectionFile(t, t.TempDir(), tc.correction(at))
			prior := len(f.Requests())
			records := 0
			h.app.Env.RecordObservation = func(context.Context, security.CollectionEvent) error { records++; return nil }
			code := h.run("security", "verify", "--before", before, "--correction", correction, "--json")
			if code != 2 || !strings.Contains(h.out.String()+h.err.String(), tc.want) {
				t.Fatalf("exit %d, want 2 and %s: %s %s", code, tc.want, h.out, h.err)
			}
			if got := len(f.Requests()) - prior; got != 0 || records != 0 {
				t.Fatalf("preflight refusal made %d API requests and %d source records", got, records)
			}
		})
	}
}

func TestSecurityVerifyReportsContradictionAndRequiresFinalAudit(t *testing.T) {
	h, f, before, at := verifyFleetFixture(t)
	action := at.Add(time.Minute)
	now := at.Add(3 * time.Minute)
	h.app.Env.Now = func() time.Time { return now }
	setVerifyFleet(t, f, now, "1.28.2-t0123456ab", true)
	correction := verifyCorrectionFile(t, t.TempDir(), versionCorrection(action, "nOLD01CNTRL"))
	prior := len(f.Requests())
	if code := h.run("security", "verify", "--before", before, "--correction", correction, "--json"); code != 8 || !strings.Contains(h.out.String(), "not_fixed") {
		t.Fatalf("exit %d, want not_fixed/8: %s %s", code, h.out, h.err)
	}
	if len(f.Requests()) <= prior {
		t.Fatal("verification did not collect fresh evidence")
	}
	h.out.Reset()
	h.err.Reset()
	h.app.Env.RecordPack = func(context.Context, registry.PackRecord) error {
		return tkerr.New(tkerr.AuditUnavailable, "audit unavailable", "")
	}
	if code := h.run("security", "verify", "--before", before, "--correction", correction, "--json"); code != 7 {
		t.Fatalf("exit %d, want audit failure 7: %s %s", code, h.out, h.err)
	}
	if strings.Contains(h.out.String(), "not_fixed") {
		t.Fatalf("verdict printed despite audit failure: %s", h.out)
	}
}

// This exercises real CLI dispatch and the real collector against apitest.Fake;
// it is in-process so the fake API can be injected without a production URL override.
func TestSecurityVerifyCorrectionDemo(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		connected bool
		wantExit  int
		want      string
	}{
		{name: "fresh running version", version: "1.102.5-t0123456ab", connected: true, wantExit: 0, want: "fixed"},
		{name: "old running version", version: "1.28.2-t0123456ab", connected: true, wantExit: 8, want: "not_fixed"},
		{name: "new version but disconnected", version: "1.102.5-t0123456ab", connected: false, wantExit: 1, want: "incomplete"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, f, before, at := verifyFleetFixture(t)
			now := at.Add(3 * time.Minute)
			h.app.Env.Now = func() time.Time { return now }
			setVerifyFleet(t, f, now, tc.version, tc.connected)
			records := 0
			h.app.Env.RecordPack = func(ctx context.Context, record registry.PackRecord) error {
				records++
				if call := registry.CallOf(ctx); call.Tool != "security_verify" || call.Caller.Kind != "cli" {
					t.Fatalf("wrong audit call identity: %+v", call)
				}
				if record.Pack != "verify" || record.Outcome != tc.want {
					t.Fatalf("wrong audit record: %+v", record)
				}
				return h.app.RecordPack(ctx, record)
			}
			correction := verifyCorrectionFile(t, t.TempDir(), versionCorrection(at.Add(time.Minute), "nOLD01CNTRL"))
			code := h.run("security", "verify", "--before", before, "--correction", correction, "--json")
			if code != tc.wantExit || !strings.Contains(h.out.String(), `"`+tc.want+`"`) {
				t.Fatalf("exit %d, want %s/%d: %s %s", code, tc.want, tc.wantExit, h.out, h.err)
			}
			if records != 1 {
				t.Fatalf("pack records %d, want one", records)
			}
			if strings.Contains(h.out.String(), "nOLD01CNTRL") {
				t.Fatal("full device ID appeared in output")
			}
		})
	}
}

func TestSecurityVerifyRefusesDifferentContextWithoutCollection(t *testing.T) {
	h, f, before, at := verifyFleetFixture(t)
	client, err := api.New(context.Background(), "T5678CNTRL", creds.Read{
		Kind: creds.KindOAuth, ClientID: apitest.ClientID,
		ClientSecret: creds.NewSecret(apitest.ClientSecret), Provider: "env",
	}, api.Options{BaseURL: f.URL()})
	if err != nil {
		t.Fatal(err)
	}
	h.app.Env.API = client
	h.app.Env.Now = func() time.Time { return at.Add(3 * time.Minute) }
	correction := verifyCorrectionFile(t, t.TempDir(), versionCorrection(at.Add(time.Minute), "nOLD01CNTRL"))
	prior := len(f.Requests())
	records := 0
	h.app.Env.RecordObservation = func(context.Context, security.CollectionEvent) error { records++; return nil }
	code := h.run("security", "verify", "--before", before, "--correction", correction, "--json")
	if code != 2 || !strings.Contains(h.out.String()+h.err.String(), "context_mismatch") {
		t.Fatalf("exit %d, want context_mismatch/2: %s %s", code, h.out, h.err)
	}
	if got := len(f.Requests()) - prior; got != 0 || records != 0 {
		t.Fatalf("context refusal made %d API requests and %d source records", got, records)
	}
}

func TestSecurityVerifyRerunsOnlyUnchangedCurrentIntent(t *testing.T) {
	at := scanAt(t)
	f := apitest.New(t)
	setVerifyFleet(t, f, at, "1.28.2-t0123456ab", true)
	model := &cliModel{allow: map[string]bool{
		"group:example-admins|tag:example-db:22": true,
		"tag:example-web|tag:example-db:22":      true,
	}}
	h := explainHarnessOn(t, f, cliExplainPolicy, model)
	h.app.Env.Now = func() time.Time { return at }
	h.app.Env.RecordObservation = h.app.RecordObservation
	h.app.Env.RecordPack = h.app.RecordPack
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h.app.Env.Config = &config.Loaded{Dirs: config.Dirs{State: dir}}
	before := filepath.Join(dir, "before.json")
	intent := writeIntent(t, cliExplainIntent)
	if code := h.run("security", "export", "--scope", "fleet", "--access", "--invariants", intent, "--out", before); code != 0 {
		t.Fatalf("export %d: %s %s", code, h.out, h.err)
	}
	h.out.Reset()
	h.err.Reset()
	changed := strings.Replace(cliExplainIntent, `"group:example-admins"`, `"group:changed-admins"`, 1)
	current := writeIntent(t, changed)
	correction := verifyCorrectionFile(t, t.TempDir(), fmt.Sprintf(`{"schema_version":1,"action_at":%q,"expectations":["network-2"]}`, at.Add(time.Minute).UTC().Format(time.RFC3339)))
	now := at.Add(3 * time.Minute)
	h.app.Env.Now = func() time.Time { return now }
	setVerifyFleet(t, f, now, "1.28.2-t0123456ab", true)
	prior := len(f.Requests())
	code := h.run("security", "verify", "--before", before, "--correction", correction, "--invariants", current, "--json")
	if code != 8 || !strings.Contains(h.out.String(), "intent_changed") || !strings.Contains(h.out.String(), "not_fixed") {
		t.Fatalf("exit %d, want not_fixed/8 and changed guard: %s %s", code, h.out, h.err)
	}
	var validations int
	for _, request := range f.Requests()[prior:] {
		if request.Path != apitest.ValidatePath {
			continue
		}
		validations++
		body, err := hujson.Standardize(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		var sent struct {
			Tests []struct {
				Source string `json:"src"`
			} `json:"tests"`
		}
		if err := json.Unmarshal(body, &sent); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, row := range sent.Tests {
			if row.Source == "group:example-admins" || row.Source == "group:changed-admins" {
				t.Fatal("verification sent a changed expectation to the validator")
			}
			found = found || row.Source == "tag:example-web"
		}
		if !found {
			t.Fatal("verification omitted the unchanged selected expectation")
		}
	}
	if validations != 1 {
		t.Fatalf("validation requests %d, want one", validations)
	}
}

func TestSecurityVerifyUsesCredentialedBuilder(t *testing.T) {
	h := newHarness(t, nil)
	h.app.Env.RecordPack = h.app.RecordPack
	correction := verifyCorrectionFile(t, t.TempDir(), `{}`)
	var normal, noCredential int
	h.r.Build = func(context.Context, string) (*app.App, error) { normal++; return h.app, nil }
	h.r.BuildNoCredential = func(context.Context, string) (*app.App, error) { noCredential++; return h.app, nil }
	code := h.run("security", "verify", "--before", "missing", "--correction", correction)
	if code != 2 || normal != 1 || noCredential != 0 || !strings.Contains(h.err.String(), "correction_invalid") {
		t.Fatalf("exit=%d credentialed=%d without=%d output=%s %s", code, normal, noCredential, h.out, h.err)
	}
}

func TestSecurityVerifyMasksCorrectionTextAfterPackReload(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			h, f, before, at := verifyFleetFixture(t)
			now := at.Add(3 * time.Minute)
			h.app.Env.Now = func() time.Time { return now }
			setVerifyFleet(t, f, now, "1.28.2-t0123456ab", true)
			correction := verifyCorrectionFile(t, t.TempDir(), fmt.Sprintf(`{"schema_version":1,"action_at":%q,"expect":{"features":[{"device":"nOLD01CNTRL","name":"zqprivate@example.com","value":true}]}}`, at.Add(time.Minute).UTC().Format(time.RFC3339)))
			args := []string{"security", "verify", "--before", before, "--correction", correction}
			if format == "json" {
				args = append(args, "--json")
			}
			h.app.Env.Config.Config.PersonalData = config.PersonalDataMask
			if code := h.run(args...); code != 1 {
				t.Fatalf("masked verify exit %d: %s %s", code, h.out, h.err)
			}
			if strings.Contains(h.out.String()+h.err.String(), "zqprivate@example.com") || strings.Contains(h.out.String()+h.err.String(), "nOLD01CNTRL") {
				t.Fatal("masked output disclosed correction text or the complete device ID")
			}
			h.out.Reset()
			h.err.Reset()
			h.app.Env.Config.Config.PersonalData = config.PersonalDataShow
			if code := h.run(args...); code != 1 || !strings.Contains(h.out.String(), "zqprivate@example.com") {
				t.Fatalf("show verify exit %d: %s %s", code, h.out, h.err)
			}
			if strings.Contains(h.out.String(), "nOLD01CNTRL") {
				t.Fatal("complete device ID appeared with personalData show")
			}
		})
	}
}

func TestSecurityVerifyClassifiesMissingCredentialBeforeContext(t *testing.T) {
	h, f, before, at := verifyFleetFixture(t)
	h.app.Env.API = nil
	h.app.Env.APIErr = tkerr.New(tkerr.CredentialUnavailable, "credential unavailable", "")
	h.app.Env.Now = func() time.Time { return at.Add(3 * time.Minute) }
	correction := verifyCorrectionFile(t, t.TempDir(), versionCorrection(at.Add(time.Minute), "nOLD01CNTRL"))
	prior := len(f.Requests())
	records := 0
	h.app.Env.RecordObservation = func(context.Context, security.CollectionEvent) error { records++; return nil }
	code := h.run("security", "verify", "--before", before, "--correction", correction, "--json")
	if code != 5 || strings.Contains(h.out.String()+h.err.String(), "context_mismatch") {
		t.Fatalf("exit %d, want credential failure 5: %s %s", code, h.out, h.err)
	}
	if got := len(f.Requests()) - prior; got != 0 || records != 0 {
		t.Fatalf("credential refusal made %d API requests and %d source records", got, records)
	}
}

func TestSecurityVerifyTextNamesExpectedFactAndRole(t *testing.T) {
	h, f, before, at := verifyFleetFixture(t)
	now := at.Add(3 * time.Minute)
	h.app.Env.Now = func() time.Time { return now }
	setVerifyFleet(t, f, now, "1.102.5-t0123456ab", true)
	correction := verifyCorrectionFile(t, t.TempDir(), versionCorrection(at.Add(time.Minute), "nOLD01CNTRL"))
	if code := h.run("security", "verify", "--before", before, "--correction", correction); code != 0 {
		t.Fatalf("verify exit %d: %s %s", code, h.out, h.err)
	}
	for _, text := range []string{"client", "running_daemon", "1.32.3", "before", "after", "evidence:", "age"} {
		if !strings.Contains(h.out.String(), text) {
			t.Errorf("text output lacks %q: %s", text, h.out)
		}
	}
}

func TestSecurityVerifyReadAuditWarningDoesNotChangeRecordedVerdict(t *testing.T) {
	h, f, before, at := verifyFleetFixture(t)
	now := at.Add(3 * time.Minute)
	h.app.Env.Now = func() time.Time { return now }
	setVerifyFleet(t, f, now, "1.102.5-t0123456ab", true)
	correction := verifyCorrectionFile(t, t.TempDir(), versionCorrection(at.Add(time.Minute), "nOLD01CNTRL"))
	var required int
	h.app.Env.RecordObservation = func(context.Context, security.CollectionEvent) error { return nil }
	h.app.Env.RecordPack = func(context.Context, registry.PackRecord) error { required++; return nil }
	h.app.Audit = nil
	h.app.AuditErr = tkerr.New(tkerr.AuditUnavailable, "audit unavailable", "")
	code := h.run("security", "verify", "--before", before, "--correction", correction, "--json")
	if code != 0 || required != 1 || !strings.Contains(h.out.String(), `"fixed"`) || !strings.Contains(h.err.String(), "audit") {
		t.Fatalf("exit=%d required=%d stdout=%s stderr=%s", code, required, h.out, h.err)
	}
}

func TestSecurityVerifyCancelledPreflightIsIncomplete(t *testing.T) {
	h, f, before, at := verifyFleetFixture(t)
	correction := verifyCorrectionFile(t, t.TempDir(), versionCorrection(at.Add(time.Minute), "nOLD01CNTRL"))
	prior := len(f.Requests())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code := h.r.Run(ctx, []string{"security", "verify", "--before", before, "--correction", correction, "--json"})
	if code != 1 {
		t.Fatalf("cancelled preflight exit %d, want 1: %s %s", code, h.out, h.err)
	}
	if len(f.Requests()) != prior {
		t.Fatal("cancelled preflight contacted the API")
	}
}

func TestSecurityVerifyInvalidCorrectionPrecedesMissingAudit(t *testing.T) {
	h := newHarness(t, nil)
	correction := verifyCorrectionFile(t, t.TempDir(), `{}`)
	code := h.run("security", "verify", "--before", "missing", "--correction", correction, "--json")
	if code != 2 || !strings.Contains(h.out.String()+h.err.String(), "correction_invalid") {
		t.Fatalf("exit %d, want correction_invalid/2: %s %s", code, h.out, h.err)
	}
}

func TestSecurityVerifyMissingAuditStopsBeforeCollection(t *testing.T) {
	h, f, before, at := verifyFleetFixture(t)
	h.app.Env.RecordPack = nil
	h.app.Env.Now = func() time.Time { return at.Add(3 * time.Minute) }
	correction := verifyCorrectionFile(t, t.TempDir(), versionCorrection(at.Add(time.Minute), "nOLD01CNTRL"))
	prior := len(f.Requests())
	var records int
	h.app.Env.RecordObservation = func(context.Context, security.CollectionEvent) error { records++; return nil }
	code := h.run("security", "verify", "--before", before, "--correction", correction, "--json")
	if code != 7 || len(f.Requests()) != prior || records != 0 {
		t.Fatalf("exit=%d requests=%d records=%d: %s %s", code, len(f.Requests())-prior, records, h.out, h.err)
	}
}
