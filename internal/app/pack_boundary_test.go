package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/audit"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func TestNoCredentialNeverReadsTheProviderOrAKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider.env")
	cfg := fmt.Sprintf(`{"contexts":{"test":{"tailnetId":"T1234CNTRL","credentials":{"read":{"provider":"file","path":%q}}}}}`, path)
	key := strings.Repeat("5a", 32)
	for _, value := range []string{key, "file:" + path, ""} {
		reads := 0
		a, err := Build(context.Background(), Options{Dirs: dirs(t, cfg), Stat: noCLI, NoCredential: true,
			Getenv: func(k string) string {
				if k == privacy.EnvKey {
					return value
				}
				return ""
			},
			ReadSecretFile: func(string) ([]byte, error) { reads++; return nil, errors.New("unexpected read") }})
		if err != nil {
			t.Fatal(err)
		}
		if reads != 0 || a.Env.API != nil || code(a.Env.APIErr) != tkerr.CredentialUnavailable || tkerr.From(a.Env.APIErr).Message != "this command loads no credential" {
			t.Errorf("credential-free build: reads=%d api=%v err=%v", reads, a.Env.API != nil, a.Env.APIErr)
		}
		if (a.Env.Privacy != nil) != (value == key) {
			t.Error("privacy key did not come only from the process environment")
		}
		a.Env.Display(&struct {
			Value string `tk:"personal"`
		}{Value: "example"})
	}
	reads := 0
	a, err := Build(context.Background(), Options{Dirs: dirs(t, cfg), Stat: noCLI, Getenv: func(string) string { return "" },
		ReadSecretFile: func(string) ([]byte, error) {
			reads++
			return []byte(creds.EnvClientID + "=" + apitest.ClientID + "\n" + creds.EnvClientSecret + "=" + apitest.ClientSecret + "\n"), nil
		}})
	if err != nil || a.Env.APIErr != nil || reads != 1 {
		t.Fatalf("normal build: reads=%d, error=%v", reads, err)
	}
	other := providerSnapshot(path, func(name string) ([]byte, error) { reads++; return []byte(name), nil })
	first, err := other(path)
	if err != nil {
		t.Fatal(err)
	}
	first[0] = 'X'
	second, err := other(path)
	if err != nil || string(second) != path {
		t.Fatal("snapshot was modified")
	}
	_, err = other(path + "-other")
	if err != nil || reads != 3 {
		t.Fatalf("separate paths: reads=%d, err=%v", reads, err)
	}
	fresh := providerSnapshot(path, func(string) ([]byte, error) { reads++; return nil, nil })
	_, err = fresh(path)
	if err != nil || reads != 4 {
		t.Fatalf("fresh snapshot: reads=%d, err=%v", reads, err)
	}
}

func TestPackRecordsUseCallerIdentityAndVerifyConcurrently(t *testing.T) {
	a, path := buildApp(t, envConfig)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			client := fmt.Sprintf("client-%d", i)
			tool := registry.Define(registry.Meta{Name: "pack_probe", Area: "pack", Verb: "probe", Summary: "probe"},
				func(ctx context.Context, env *registry.Env, _ struct{}) (struct{}, error) {
					n, size := int64(i), int64(20)
					return struct{}{}, env.RecordPack(ctx, registry.PackRecord{Pack: "export", Seal: "keyed", Outcome: "fixed", Digest: "0123456789ab", Bytes: &size, Findings: &n})
				})
			_, err := tool.Call(registry.WithCaller(context.Background(), registry.Caller{Kind: "mcp", Client: client}), a.Env, json.RawMessage(`{}`))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := audit.Tail(path, 20)
	if err != nil || len(got) != 20 {
		t.Fatalf("tail: %d, %v", len(got), err)
	}
	seen := map[string]bool{}
	for _, l := range got {
		who, _ := l["requester"].(map[string]any)
		client, _ := who["client"].(string)
		parent, _ := l["parent"].(string)
		if l["event"] != "pack" || l["tool"] != "pack_probe" || who["kind"] != "mcp" || client != fmt.Sprintf("client-%d", int(l["findings"].(float64))) || !callIDShape.MatchString(parent) || seen[parent] {
			t.Errorf("invalid pack identity: %v", l)
		}
		seen[parent] = true
	}
	if n, err := audit.Verify(path); err != nil || n != 20 {
		t.Errorf("verify: %d %v", n, err)
	}
}

func TestPackMetadataIsClosedAndAuditFailureIsRequired(t *testing.T) {
	a, path := buildApp(t, envConfig)
	negative := int64(-1)
	for _, record := range []registry.PackRecord{{}, {Pack: "hostile"}, {Pack: "export", Seal: "hostile"}, {Pack: "export", Outcome: "hostile"}, {Pack: "export", Digest: "bad"}, {Pack: "export", Findings: &negative}} {
		if code(a.RecordPack(context.Background(), record)) != tkerr.Internal {
			t.Errorf("invalid record accepted: %+v", record)
		}
	}
	if got, err := audit.Tail(path, 10); err != nil || len(got) != 0 {
		t.Fatalf("rejected fields wrote %v: %v", got, err)
	}
	if err := a.Record(map[string]any{"pack": "export", "seal": "keyed", "outcome": "fixed", "findings": 3, "devices": 4, "fixed": 1, "not_fixed": 2, "incomplete": 0, "regressed": 0, "bytes": 5, "digest": "0123456789ab", "path": "bad"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Record(map[string]any{"pack": "bad", "seal": "bad", "outcome": "bad", "findings": "bad", "bytes": "bad"}); err != nil {
		t.Fatal(err)
	}
	got, err := audit.Tail(path, 10)
	if err != nil || len(got) != 2 {
		t.Fatal(err)
	}
	for _, key := range []string{"pack", "seal", "outcome", "findings", "devices", "fixed", "not_fixed", "incomplete", "regressed", "bytes", "digest"} {
		if _, ok := got[0][key]; !ok {
			t.Errorf("missing %s", key)
		}
	}
	for _, key := range []string{"pack", "seal", "outcome", "findings", "bytes", "path"} {
		if _, ok := got[1][key]; ok {
			t.Errorf("kept invalid %s", key)
		}
	}
	a.AuditReads = "none"
	if code(a.RecordPack(context.Background(), registry.PackRecord{Pack: "export"})) != tkerr.ConfigInvalid {
		t.Error("disabled audit accepted")
	}
	a.AuditReads, a.Audit = "metadata", nil
	a.AuditErr = tkerr.New(tkerr.AuditUnavailable, "test audit unavailable", "")
	if err := a.RecordPack(context.Background(), registry.PackRecord{Pack: "verify"}); !errors.Is(err, a.AuditErr) || code(err) != tkerr.AuditUnavailable {
		t.Errorf("lost audit failure: %v", err)
	}
}

func TestProviderSnapshotIsScopedToOneBuildAndContext(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.env")
	second := filepath.Join(t.TempDir(), "second.env")
	cfg := fmt.Sprintf(`{"contexts":{"first":{"tailnetId":"T1234CNTRL","credentials":{"read":{"provider":"file","path":%q}}},"second":{"tailnetId":"T1234CNTRL","credentials":{"read":{"provider":"file","path":%q}}}}}`, first, second)
	counts := map[string]int{}
	reader := func(path string) ([]byte, error) {
		counts[path]++
		return []byte(creds.EnvClientID + "=" + apitest.ClientID + "\n" + creds.EnvClientSecret + "=" + apitest.ClientSecret + "\n"), nil
	}
	d := dirs(t, cfg)
	for _, name := range []string{"first", "second", "first"} {
		a, err := Build(context.Background(), Options{Context: name, Dirs: d, Stat: noCLI, Getenv: func(string) string { return "" }, ReadSecretFile: reader})
		if err != nil || a.Env.APIErr != nil {
			t.Fatalf("build %s: %v", name, err)
		}
	}
	if counts[first] != 2 || counts[second] != 1 {
		t.Errorf("provider reads by context: %v", counts)
	}
}
