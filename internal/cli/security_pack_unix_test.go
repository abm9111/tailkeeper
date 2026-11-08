//go:build !windows

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

func TestPackCommandsThroughCLI(t *testing.T) {
	h := newHarness(t, nil)
	catalog, err := advisory.Shipped()
	if err != nil {
		t.Fatal(err)
	}
	at := catalog.IssuedAt.Add(time.Hour)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h.app.Env.Now = func() time.Time { return at }
	h.app.Env.Config = &config.Loaded{Dirs: config.Dirs{State: dir}}
	h.app.Env.RecordObservation = h.app.RecordObservation
	h.app.Env.RecordPack = h.app.RecordPack
	path := filepath.Join(dir, "pack.json")
	if code := h.run("security", "export", "--scope", "local", "--out", path, "--json"); code != 0 {
		t.Fatalf("export %d: %s %s", code, h.out, h.err)
	}
	h.out.Reset()
	h.err.Reset()
	normal, none := 0, 0
	old := h.r.Build
	h.r.Build = func(ctx context.Context, name string) (*app.App, error) { normal++; return old(ctx, name) }
	h.r.BuildNoCredential = func(ctx context.Context, name string) (*app.App, error) { none++; return old(ctx, name) }
	if code := h.run("security", "replay", path, "--json"); code != 0 {
		t.Fatalf("replay %d: %s %s", code, h.out, h.err)
	}
	if !strings.Contains(h.out.String(), `"reproduced": true`) {
		t.Fatalf("replay output %s", h.out)
	}
	h.out.Reset()
	h.err.Reset()
	projection := filepath.Join(dir, "projection.json")
	if code := h.run("security", "redact", path, "--out", projection, "--json"); code != 0 {
		t.Fatalf("redact %d: %s %s", code, h.out, h.err)
	}
	if normal != 0 || none != 2 {
		t.Fatalf("builders normal=%d no-credential=%d", normal, none)
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("security", "replay", projection); code != 1 || !strings.Contains(h.out.String(), "redacted projection") {
		t.Fatalf("projection replay %d: %s %s", code, h.out, h.err)
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("security", "replay", path, "--format", "markdown"); code != 2 {
		t.Fatalf("unsupported format exit %d", code)
	}
}

func TestPackExportAccessAndAudit(t *testing.T) {
	h := explainHarness(t, cliExplainPolicy, adminCLIModel())
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h.app.Env.Config = &config.Loaded{Dirs: config.Dirs{State: dir}}
	h.app.Env.RecordObservation = h.app.RecordObservation
	h.app.Env.RecordPack = h.app.RecordPack
	intent := writeIntent(t, cliExplainIntent)
	path := filepath.Join(dir, "pack.json")
	if code := h.run("security", "export", "--scope", "local", "--access", "--only", "network-1", "--invariants", intent, "--out", path, "--json"); code != 0 {
		t.Fatalf("export %d: %s %s", code, h.out, h.err)
	}
	if strings.Contains(h.out.String(), "zq-policy") || strings.Contains(h.out.String(), "example-admins") {
		t.Fatal("private input appeared in export summary")
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("security", "replay", path, "--json"); code != 0 {
		t.Fatalf("replay %d: %s %s", code, h.out, h.err)
	}
	if !strings.Contains(h.out.String(), `"total": 1`) || !strings.Contains(h.out.String(), `"access"`) {
		t.Fatalf("selected access missing: %s", h.out)
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("security", "replay", path); code != 0 {
		t.Fatalf("text replay %d: %s %s", code, h.out, h.err)
	}
	for _, wanted := range []string{"coverage versions:", "recorded access explanation:", "network-1", "candidate rule", "Replay reproduces a decision"} {
		if !strings.Contains(h.out.String(), wanted) {
			t.Fatalf("text replay missing %q: %s", wanted, h.out)
		}
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("audit", "verify"); code != 0 {
		t.Fatalf("audit verify %d: %s %s", code, h.out, h.err)
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("audit", "tail", "-n", "20"); code != 0 || !strings.Contains(h.out.String(), "pack") {
		t.Fatalf("audit tail %d: %s %s", code, h.out, h.err)
	}
}

func TestPackExportAndReplayAreNotAssessmentGates(t *testing.T) {
	at := scanAt(t)
	h := scanHarness(t, at, fleet(at)...)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h.app.Env.Config = &config.Loaded{Dirs: config.Dirs{State: dir}}
	h.app.Env.RecordPack = h.app.RecordPack
	if code := h.run("security", "scan", "fleet", "--json"); code != 8 {
		t.Fatalf("positive control scan exit %d: %s %s", code, h.out, h.err)
	}
	h.out.Reset()
	h.err.Reset()
	path := filepath.Join(dir, "fleet.json")
	if code := h.run("security", "export", "--scope", "fleet", "--out", path, "--json"); code != 0 {
		t.Fatalf("export exit %d: %s %s", code, h.out, h.err)
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("security", "replay", path, "--json"); code != 0 {
		t.Fatalf("replay exit %d: %s %s", code, h.out, h.err)
	}
	if !strings.Contains(h.out.String(), `"affected": 1`) {
		t.Fatalf("affected finding missing: %s", h.out)
	}
}

func TestPackRedactPublishesWhenReadAuditFails(t *testing.T) {
	h := newHarness(t, nil)
	catalog, err := advisory.Shipped()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h.app.Env.Now = func() time.Time { return catalog.IssuedAt.Add(time.Hour) }
	h.app.Env.Config = &config.Loaded{Dirs: config.Dirs{State: dir}}
	h.app.Env.RecordObservation = h.app.RecordObservation
	h.app.Env.RecordPack = h.app.RecordPack
	path := filepath.Join(dir, "pack.json")
	if code := h.run("security", "export", "--scope", "local", "--out", path); code != 0 {
		t.Fatalf("export %d: %s", code, h.err)
	}
	h.app.Audit = nil
	h.app.AuditErr = tkerr.New(tkerr.AuditUnavailable, "audit unavailable", "")
	h.app.Env.RecordPack = func(context.Context, registry.PackRecord) error { t.Fatal("redact called required audit"); return nil }
	h.out.Reset()
	h.err.Reset()
	projection := filepath.Join(dir, "projection.json")
	if code := h.run("security", "redact", path, "--out", projection); code != 0 {
		t.Fatalf("redact %d: %s %s", code, h.out, h.err)
	}
	if _, err := os.Stat(projection); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.err.String(), "audit") {
		t.Fatalf("missing audit warning: %s", h.err)
	}
}

func TestPackOfflineCommandsNeverOpenCredentialFile(t *testing.T) {
	h := newHarness(t, nil)
	catalog, err := advisory.Shipped()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	h.app.Env.Now = func() time.Time { return catalog.IssuedAt.Add(time.Hour) }
	h.app.Env.Config = &config.Loaded{Dirs: config.Dirs{State: root}}
	h.app.Env.RecordObservation = h.app.RecordObservation
	h.app.Env.RecordPack = h.app.RecordPack
	pack := filepath.Join(root, "pack.json")
	if code := h.run("security", "export", "--scope", "local", "--out", pack); code != 0 {
		t.Fatalf("setup export %d: %s", code, h.err)
	}
	user := filepath.Join(root, "config")
	if err := os.Mkdir(user, 0700); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(root, "missing-provider")
	cfg := fmt.Sprintf(`{"contexts":{"test":{"tailnetId":"T1234CNTRL","credentials":{"read":{"provider":"file","path":%q}}}}}`, credential)
	if err := os.WriteFile(filepath.Join(user, config.FileName), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	t.Chdir(cwd)
	dirs := config.Dirs{System: filepath.Join(root, "system"), User: user, State: root, Logs: filepath.Join(root, "logs")}
	reads := 0
	build := func(ctx context.Context, name string, noCredential bool) (*app.App, error) {
		return app.Build(ctx, app.Options{Context: name, Dirs: &dirs, NoCredential: noCredential, Getenv: func(string) string { return "" }, Stat: func(string) (fs.FileInfo, error) { return nil, os.ErrNotExist }, ReadSecretFile: func(string) ([]byte, error) { reads++; return nil, os.ErrPermission }})
	}
	h.r.Build = func(ctx context.Context, name string) (*app.App, error) { return build(ctx, name, false) }
	h.r.BuildNoCredential = func(ctx context.Context, name string) (*app.App, error) { return build(ctx, name, true) }
	h.out.Reset()
	h.err.Reset()
	if code := h.run("security", "replay", pack); code != 0 {
		t.Fatalf("replay %d: %s", code, h.err)
	}
	h.out.Reset()
	h.err.Reset()
	projection := filepath.Join(root, "projection.json")
	if code := h.run("security", "redact", pack, "--out", projection); code != 0 {
		t.Fatalf("redact %d: %s", code, h.err)
	}
	if _, err := os.Stat(filepath.Join(cwd, "audit.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("offline commands wrote audit in working directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "logs", "audit.jsonl")); err != nil {
		t.Fatalf("offline commands did not write audit under configured log directory: %v", err)
	}
	if reads != 0 {
		t.Fatalf("offline commands opened provider %d times", reads)
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("security", "export", "--scope", "fleet", "--out", filepath.Join(root, "fleet.json")); code == 0 || reads != 1 {
		t.Fatalf("fleet positive control: exit=%d reads=%d stderr=%s", code, reads, h.err)
	}
}

func TestPackPrivacyMatrixAcrossReplay(t *testing.T) {
	key, err := privacy.Parse(strings.Repeat("01", 32))
	if err != nil {
		t.Fatal(err)
	}
	modes := []struct {
		name string
		show bool
		key  bool
	}{{"show", true, false}, {"masked-key", false, true}, {"masked-no-key", false, false}}
	for _, exportMode := range modes {
		t.Run(exportMode.name, func(t *testing.T) {
			h := explainHarness(t, cliExplainPolicy, adminCLIModel())
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			h.app.Env.Config = &config.Loaded{Dirs: config.Dirs{State: dir}}
			setPackPrivacy(h, exportMode.show, exportMode.key, key)
			h.app.Env.RecordObservation = h.app.RecordObservation
			h.app.Env.RecordPack = h.app.RecordPack
			intent := writeIntent(t, cliExplainIntent)
			path := filepath.Join(dir, "pack.json")
			if code := h.run("security", "export", "--scope", "local", "--access", "--invariants", intent, "--out", path); code != 0 {
				t.Fatalf("export %d: %s %s", code, h.out, h.err)
			}
			for _, replayMode := range modes {
				t.Run(replayMode.name, func(t *testing.T) {
					setPackPrivacy(h, replayMode.show, replayMode.key, key)
					h.out.Reset()
					h.err.Reset()
					if code := h.run("security", "replay", path, "--json"); code != 0 {
						t.Fatalf("replay %d: %s %s", code, h.out, h.err)
					}
					var result tools.SecurityReplayOutput
					if err := json.Unmarshal(h.out.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					if result.Access == nil {
						t.Fatal("access missing")
					}
					hasRecorded := exportMode.show || exportMode.key
					visible := exportMode.show && replayMode.show || exportMode.key && !replayMode.show && replayMode.key
					if (result.Report.IntentDigest != "") != visible || (result.Access.PolicyVersion != "") != visible {
						t.Fatalf("wrong token visibility: digest=%q policy=%q", result.Report.IntentDigest, result.Access.PolicyVersion)
					}
					if hasRecorded && !visible && (result.Report.WithheldNote == "" || result.Access.WithheldNote == "") {
						t.Fatal("missing withheld note")
					}
					if len(result.Report.IntentDigest) > len("hmac-sha256:")+12 || len(result.Access.PolicyVersion) > len("hmac-sha256:")+12 {
						t.Fatal("whole recorded digest escaped")
					}
				})
			}
		})
	}
}
func setPackPrivacy(h *harness, show, withKey bool, key *privacy.Key) {
	h.app.Env.Config.Config.PersonalData = config.PersonalDataMask
	if show {
		h.app.Env.Config.Config.PersonalData = config.PersonalDataShow
	}
	h.app.Env.Privacy = nil
	if withKey {
		h.app.Env.Privacy = key
	}
}

func TestPackCLIRefusesTamperingAndReportsNonreproduction(t *testing.T) {
	h := newHarness(t, nil)
	catalog, err := advisory.Shipped()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h.app.Env.Now = func() time.Time { return catalog.IssuedAt.Add(time.Hour) }
	h.app.Env.Config = &config.Loaded{Dirs: config.Dirs{State: dir}}
	h.app.Env.RecordObservation = h.app.RecordObservation
	h.app.Env.RecordPack = h.app.RecordPack
	original := filepath.Join(dir, "original.json")
	if code := h.run("security", "export", "--scope", "local", "--out", original); code != 0 {
		t.Fatalf("export %d: %s", code, h.err)
	}
	b, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Body      json.RawMessage `json:"body"`
		Integrity string          `json:"integrity"`
	}
	if err := json.Unmarshal(b, &envelope); err != nil {
		t.Fatal(err)
	}
	var assertion struct {
		Expected struct {
			Report struct {
				SHA256 string `json:"sha256"`
			} `json:"report"`
		} `json:"expected"`
	}
	if err := json.Unmarshal(envelope.Body, &assertion); err != nil {
		t.Fatal(err)
	}
	old := assertion.Expected.Report.SHA256
	replacement := strings.Repeat("0", 64)
	if old == replacement {
		replacement = strings.Repeat("1", 64)
	}
	body := bytes.Replace(envelope.Body, []byte(old), []byte(replacement), 1)
	sum := sha256.Sum256(append([]byte("tailkeeper-evidence-pack/1\n"), body...))
	altered := []byte(fmt.Sprintf("{\"body\":%s,\"integrity\":\"sha256:%x\"}\n", body, sum))
	if !bytes.Contains(b, []byte(old)) || !bytes.Contains(altered, []byte(replacement)) || !bytes.Contains(altered, []byte(fmt.Sprintf("%x", sum))) {
		t.Fatal("hash positive controls are absent from packs")
	}

	validChanged := filepath.Join(dir, "changed.json")
	if err := os.WriteFile(validChanged, altered, 0600); err != nil {
		t.Fatal(err)
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("security", "replay", validChanged, "--json"); code != 1 {
		t.Fatalf("nonreproduction exit %d: %s", code, h.err)
	}
	printed := h.out.String() + h.err.String()
	if strings.Contains(printed, old) || strings.Contains(printed, replacement) || strings.Contains(printed, strings.TrimPrefix(envelope.Integrity, "sha256:")) || strings.Contains(printed, fmt.Sprintf("%x", sum)) {
		t.Fatal("a private report or body hash appeared in output")
	}
	h.out.Reset()
	h.err.Reset()
	projection := filepath.Join(dir, "projection.json")
	if code := h.run("security", "redact", validChanged, "--out", projection); code != 1 {
		t.Fatalf("redact nonreproduction exit %d: %s", code, h.err)
	}
	if _, err := os.Stat(projection); !os.IsNotExist(err) {
		t.Fatal("nonreproduced projection was published")
	}
	corrupt := filepath.Join(dir, "corrupt.json")
	tampered := bytes.Replace(b, []byte(old), []byte(replacement), 1)
	if err := os.WriteFile(corrupt, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("security", "replay", corrupt); code != 2 {
		t.Fatalf("tamper exit %d: %s", code, h.err)
	}
	if strings.Contains(h.out.String()+h.err.String(), old) || strings.Contains(h.out.String()+h.err.String(), replacement) {
		t.Fatal("report hash appeared in refusal")
	}
}
func TestPackStoppedEarlyMapsToCLIExitOne(t *testing.T) {
	h := newHarness(t, nil)
	meta := tools.SecurityExportTool().Meta
	h.r.Registry = func() *registry.Registry {
		reg := registry.New()
		reg.MustAdd(registry.Define(meta, func(context.Context, *registry.Env, tools.SecurityExportInput) (tools.SecurityPackSummary, error) {
			return tools.SecurityPackSummary{}, tkerr.New(tkerr.APIError, "the evidence did not reproduce; no file was written", "")
		}))
		return reg
	}
	if code := h.run("security", "export", "--scope", "local"); code != 1 {
		t.Fatalf("stopped export exit %d: %s", code, h.err)
	}
}
