//go:build !windows

package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/securitypack"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func packTestEnv(t *testing.T) *registry.Env {
	t.Helper()
	c, err := advisory.Shipped()
	if err != nil {
		t.Fatal(err)
	}
	at := c.IssuedAt.Add(time.Hour)
	return &registry.Env{Config: &config.Loaded{Dirs: config.Dirs{State: t.TempDir()}}, Now: func() time.Time { return at }, RecordObservation: func(context.Context, security.CollectionEvent) error { return nil }, RecordPack: func(context.Context, registry.PackRecord) error { return nil }}
}
func exportArgs(t *testing.T, path string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(SecurityExportInput{Scope: "local", Out: path})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func replayArgs(t *testing.T, path string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(SecurityPackInput{Pack: path})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func redactArgs(t *testing.T, path, out string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(SecurityRedactInput{Pack: path, Out: out})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPackExportAuditBeforePublicationAndReplay(t *testing.T) {
	env := packTestEnv(t)
	path := filepath.Join(privatePackDir(t), "evidence.json")
	var records int
	env.RecordPack = func(_ context.Context, r registry.PackRecord) error {
		records++
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("published before audit: %v", err)
		}
		if r.Pack != "export" || r.Outcome != "reproduced" {
			t.Fatalf("record: %+v", r)
		}
		return nil
	}
	out, err := SecurityExportTool().Call(context.Background(), env, exportArgs(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if records != 1 || out.(SecurityPackSummary).ExitCode() != 0 {
		t.Fatalf("records %d output %+v", records, out)
	}
	if packSealer(env) != nil {
		t.Fatal("nil privacy key became a non-nil sealer")
	}
	replay, err := SecurityReplayTool().Call(context.Background(), env, replayArgs(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if !replay.(SecurityReplayOutput).Replay.Reproduced {
		t.Fatalf("replay: %+v", replay)
	}
	projected := filepath.Join(privatePackDir(t), "projection.json")
	env.RecordPack = func(context.Context, registry.PackRecord) error { t.Fatal("redact called required audit"); return nil }
	if _, err := SecurityRedactTool().Call(context.Background(), env, redactArgs(t, path, projected)); err != nil {
		t.Fatal(err)
	}
	_, _, err = securitypack.Decode(mustPackRead(t, projected), nil)
	if !errors.Is(err, securitypack.ErrProjectionNotReplayable) {
		t.Fatalf("projection decode: %v", err)
	}
}
func mustPackRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestPackExportRefusesPublicationOnAuditFailure(t *testing.T) {
	env := packTestEnv(t)
	dir := privatePackDir(t)
	path := filepath.Join(dir, "pack.json")
	env.RecordPack = func(context.Context, registry.PackRecord) error {
		return tkerr.New(tkerr.AuditUnavailable, "audit unavailable", "")
	}
	_, err := SecurityExportTool().Call(context.Background(), env, exportArgs(t, path))
	if tkerr.ExitCode(err) != 7 {
		t.Fatalf("error: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("files: %v, %v", entries, err)
	}
}
func TestPackToolsAreOwnerOnly(t *testing.T) {
	shared := registry.New()
	Register(shared)
	owner := registry.New()
	RegisterOwnerOnly(owner)
	for _, name := range []string{"security_export", "security_replay", "security_redact"} {
		if _, ok := shared.Get(name); ok {
			t.Fatalf("%s exposed", name)
		}
		if _, ok := owner.Get(name); !ok {
			t.Fatalf("%s missing", name)
		}
	}
}

func privatePackDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPackExportPrivacyFailurePrecedesCollection(t *testing.T) {
	env := packTestEnv(t)
	dir := privatePackDir(t)
	env.PrivacyErr = tkerr.New(tkerr.PrivacyKeyUnavailable, "privacy key unavailable", "")
	var collected, recorded int
	env.RecordObservation = func(context.Context, security.CollectionEvent) error { collected++; return nil }
	env.RecordPack = func(context.Context, registry.PackRecord) error { recorded++; return nil }
	_, err := SecurityExportTool().Call(context.Background(), env, exportArgs(t, filepath.Join(dir, "pack.json")))
	if tkerr.ExitCode(err) != 5 || collected != 0 || recorded != 0 {
		t.Fatalf("exit=%d collected=%d recorded=%d", tkerr.ExitCode(err), collected, recorded)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("files: %v, %v", entries, err)
	}
}

func TestPackExportRequiresAPIBeforeCollection(t *testing.T) {
	env := packTestEnv(t)
	env.APIErr = tkerr.New(tkerr.CredentialUnavailable, "credential unavailable", "")
	var collected int
	env.RecordObservation = func(context.Context, security.CollectionEvent) error { collected++; return nil }
	for _, in := range []SecurityExportInput{{Scope: "fleet"}, {Scope: "local", Access: true}} {
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		_, err = SecurityExportTool().Call(context.Background(), env, raw)
		if tkerr.ExitCode(err) != 5 || collected != 0 {
			t.Fatalf("input %+v exit=%d collected=%d", in, tkerr.ExitCode(err), collected)
		}
	}
}

func TestPackConcurrentExportsPreserveIdentityAndBytes(t *testing.T) {
	env := packTestEnv(t)
	dir := privatePackDir(t)
	var mu sync.Mutex
	seen := make(map[string]registry.Call)
	env.RecordPack = func(ctx context.Context, _ registry.PackRecord) error {
		call := registry.CallOf(ctx)
		mu.Lock()
		defer mu.Unlock()
		seen[call.ID] = call
		return nil
	}
	type result struct {
		id  string
		err error
	}
	results := make(chan result, 2)
	tool := SecurityExportTool()
	for _, name := range []string{"a.json", "b.json"} {
		raw := exportArgs(t, filepath.Join(dir, name))
		go func() {
			_, id, err := tool.CallWithID(registry.WithCaller(context.Background(), registry.Caller{Kind: "cli"}), env, raw)
			results <- result{id, err}
		}()
	}
	ids := make(map[string]bool)
	for range 2 {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		ids[r.id] = true
	}
	if len(ids) != 2 || len(seen) != 2 {
		t.Fatalf("call IDs %d audit IDs %d", len(ids), len(seen))
	}
	for id := range ids {
		call := seen[id]
		if call.Tool != "security_export" || call.Caller.Kind != "cli" {
			t.Fatalf("identity %+v", call)
		}
	}
	first := mustPackRead(t, filepath.Join(dir, "a.json"))
	second := mustPackRead(t, filepath.Join(dir, "b.json"))
	if !bytes.Equal(first, second) {
		t.Fatal("fixed inputs produced different pack bytes")
	}
}

func TestPackExportRefusesUnsafeDestinations(t *testing.T) {
	env := packTestEnv(t)
	dir := privatePackDir(t)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(dir, "repo")
	if err := os.Mkdir(repo, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	called := 0
	env.RecordPack = func(context.Context, registry.PackRecord) error { called++; return nil }
	for _, path := range []string{"-", link, filepath.Join(repo, "pack.json"), filepath.Join(dir, "missing", "pack.json")} {
		_, err := SecurityExportTool().Call(context.Background(), env, exportArgs(t, path))
		if tkerr.ExitCode(err) != 2 {
			t.Fatalf("unsafe path exit %d: %v", tkerr.ExitCode(err), err)
		}
	}
	if called != 0 {
		t.Fatalf("audit callback called %d times for refused paths", called)
	}
	if got := string(mustPackRead(t, target)); got != "unchanged" {
		t.Fatal("existing target changed")
	}
}

func TestPackInterruptedCommandsDoNotPublish(t *testing.T) {
	env := packTestEnv(t)
	dir := privatePackDir(t)
	pack := filepath.Join(dir, "pack.json")
	if _, err := SecurityExportTool().Call(context.Background(), env, exportArgs(t, pack)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name   string
		call   func() error
		output string
	}{
		{"replay", func() error { _, err := SecurityReplayTool().Call(ctx, env, replayArgs(t, pack)); return err }, ""},
		{"redact", func() error {
			_, err := SecurityRedactTool().Call(ctx, env, redactArgs(t, pack, filepath.Join(dir, "projection.json")))
			return err
		}, filepath.Join(dir, "projection.json")},
		{"export", func() error {
			_, err := SecurityExportTool().Call(ctx, env, exportArgs(t, filepath.Join(dir, "export.json")))
			return err
		}, filepath.Join(dir, "export.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if classified, ok := tkerr.As(err); !ok || classified.Code != tkerr.APIError || tkerr.ExitCode(err) != 1 || !errors.Is(err, context.Canceled) {
				t.Fatalf("interruption: %v (exit %d)", err, tkerr.ExitCode(err))
			}
			if tc.output != "" {
				if _, statErr := os.Stat(tc.output); !os.IsNotExist(statErr) {
					t.Fatalf("output published: %v", statErr)
				}
			}
		})
	}
}
