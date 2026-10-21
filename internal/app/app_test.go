package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func code(err error) tkerr.Code {
	if e, ok := tkerr.As(err); ok {
		return e.Code
	}
	return ""
}

// dirs returns temporary configuration directories; body, if set, is written as
// the user configuration.
func dirs(t *testing.T, body string) *config.Dirs {
	t.Helper()
	root := t.TempDir()
	d := &config.Dirs{System: filepath.Join(root, "etc"), User: filepath.Join(root, "user"),
		State: filepath.Join(root, "state"), Logs: filepath.Join(root, "logs")}
	if body != "" {
		if err := os.MkdirAll(d.User, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d.User, config.FileName), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func noCLI(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist }

const envConfig = `{
  // hujson: comments and trailing commas are allowed
  "contexts": {"test": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "env"}}}},
}`

func TestNoConfigurationKeepsLocalToolsAvailable(t *testing.T) {
	a, err := Build(context.Background(), Options{Dirs: dirs(t, ""), Stat: noCLI})
	if err != nil {
		t.Fatal(err)
	}
	if code(a.Env.APIErr) != tkerr.ConfigMissing || code(a.Env.LocalErr) != tkerr.LocalBinaryMissing {
		t.Fatalf("APIErr = %v, LocalErr = %v", a.Env.APIErr, a.Env.LocalErr)
	}
	if len(a.Registry.All()) != 43 {
		t.Errorf("registry has %d tools", len(a.Registry.All()))
	}
}

func TestUnsafeConfigurationRefusesEverything(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SKIPPED: Windows has no strict mode until Windows hardened mode (spec §4)")
	}
	d := dirs(t, envConfig)
	if err := os.Chmod(filepath.Join(d.User, config.FileName), 0o666); err != nil {
		t.Fatal(err)
	}
	_, err := Build(context.Background(), Options{Dirs: d, Stat: noCLI})
	if code(err) != tkerr.ConfigUnsafe {
		t.Fatalf("err = %v, want config_unsafe", err)
	}
}

func TestEnvProviderConnectsAndRecordsReads(t *testing.T) {
	f := apitest.New(t)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", 200, `{"devices":[{"nodeId":"nAAA1CNTRL","name":"secret-box"}]}`)
	env := map[string]string{creds.EnvClientID: apitest.ClientID, creds.EnvClientSecret: apitest.ClientSecret}
	d := dirs(t, envConfig)
	a, err := Build(context.Background(), Options{Dirs: d, Stat: noCLI, Getenv: func(k string) string { return env[k] },
		API: api.Options{BaseURL: f.URL(), Sleep: func(context.Context, time.Duration) error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Env.APIErr != nil || a.Context != "test" || a.Tailnet != "T1234CNTRL" {
		t.Fatalf("APIErr = %v, context %q, tailnet %q", a.Env.APIErr, a.Context, a.Tailnet)
	}
	if a.Credential != "oauth client test… via env" {
		t.Errorf("Credential = %q, want the client ID masked", a.Credential)
	}
	tool, _ := a.Registry.Get("devices_list")
	if _, err := tool.Call(context.Background(), a.Env, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.Record(map[string]any{"tool": "devices_list", "bytes": 42}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(d.Logs, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"event":"read"`) || !strings.Contains(string(data), `"tailnet":"T1234CNTRL"`) {
		t.Errorf("audit = %s", data)
	}
	if strings.Contains(string(data), "secret-box") {
		t.Error("a device name reached the audit log")
	}
}

// The configured acl.validatePerMinute reaches the client's validation bucket; without the
// key the rate is the default of 30.
func TestConnectPassesTheConfiguredValidateRate(t *testing.T) {
	f := apitest.New(t)
	f.ServeValidate(apitest.TestsPass())
	env := map[string]string{creds.EnvClientID: apitest.ClientID, creds.EnvClientSecret: apitest.ClientSecret}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	aclConfig := `{
  "contexts": {"test": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "env"}}}},
  "acl": {"validatePerMinute": 3},
}`
	a, err := Build(context.Background(), Options{Dirs: dirs(t, aclConfig), Stat: noCLI, Getenv: func(k string) string { return env[k] },
		API: api.Options{BaseURL: f.URL(), Now: func() time.Time { return now }}})
	if err != nil || a.Env.APIErr != nil {
		t.Fatalf("Build: %v, %v", err, a.Env.APIErr)
	}
	tests := []api.PolicyTest{{Src: "tag:p", Accept: []string{"tag:p:22"}}}
	for i := 0; i < 3; i++ {
		if _, err := a.Env.API.ValidateTests(context.Background(), tests); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
	}
	_, err = a.Env.API.ValidateTests(context.Background(), tests)
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidateRateLimited || !strings.Contains(e.Message, "limit of 3 validation requests a minute (") {
		t.Errorf("the fourth call: %v, want validate_rate_limited at 3 a minute", err)
	}

	// Without the key: 30.
	b, err := Build(context.Background(), Options{Dirs: dirs(t, envConfig), Stat: noCLI, Getenv: func(k string) string { return env[k] },
		API: api.Options{BaseURL: f.URL(), Now: func() time.Time { return now }}})
	if err != nil || b.Env.APIErr != nil {
		t.Fatalf("Build: %v, %v", err, b.Env.APIErr)
	}
	for i := 0; i < 30; i++ {
		if _, err := b.Env.API.ValidateTests(context.Background(), tests); err != nil {
			t.Fatalf("call %d of the default 30: %v", i+1, err)
		}
	}
	if _, err := b.Env.API.ValidateTests(context.Background(), tests); code(err) != tkerr.ValidateRateLimited {
		t.Errorf("the 31st call: %v", err)
	}
}

func TestRecordKeepsOnlyReadMetadata(t *testing.T) {
	f := apitest.New(t)
	env := map[string]string{creds.EnvClientID: apitest.ClientID, creds.EnvClientSecret: apitest.ClientSecret}
	d := dirs(t, envConfig)
	a, err := Build(context.Background(), Options{Dirs: d, Stat: noCLI, Getenv: func(k string) string { return env[k] },
		API: api.Options{BaseURL: f.URL(), Sleep: func(context.Context, time.Duration) error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Record(map[string]any{"tool": "devices_list", "tailnet": "EVIL", "context": "evil",
		"args": map[string]any{"q": "ARG-CANARY"}, "bytes": 1, "note": "EXTRA-CANARY",
		"requester": map[string]any{"kind": "mcp", "client": "c", "args": map[string]any{"x": "NEST-CANARY"}, "NESTKEY": 1}}); err != nil {
		t.Fatal(err)
	}
	// Assembled at run time so that no credential shape sits in the source.
	key := "tskey" + "-api-" + "kTEST1CNTRL-" + "notarealsecretvalue"
	if err := a.Record(map[string]any{"tool": "devices_list", "requester": map[string]any{"kind": "mcp", "client": key}}); err != nil {
		t.Fatalf("a withheld line must still be recorded: %v", err)
	}
	if err := a.Record(map[string]any{"tool": key}); err != nil {
		t.Fatalf("a withheld tool name must still be recorded: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(d.Logs, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"tailnet":"T1234CNTRL"`) || !strings.Contains(lines[1], `"status":"line_withheld"`) ||
		!strings.Contains(lines[1], `"tool":"devices_list"`) || !strings.Contains(lines[2], `"status":"line_withheld"`) {
		t.Fatalf("audit = %s", data)
	}
	for _, bad := range []string{"EVIL", "ARG-CANARY", "EXTRA-CANARY", "NEST-CANARY", "NESTKEY", "tskey"} {
		if strings.Contains(string(data), bad) {
			t.Errorf("audit contains %q: %s", bad, data)
		}
	}
}

// net/http honours ErrUseLastResponse only when CheckRedirect returns it itself, not
// wrapped, so the test sends a POST through the client and watches where it goes.
func TestTokenClientNeverFollowsRedirects(t *testing.T) {
	var reached atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	defer other.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()
	resp, err := tokenHTTPClient().Post(redirecting.URL, "text/plain", strings.NewReader("token request"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect || reached.Load() != 0 {
		t.Fatalf("the OIDC token client followed a redirect: status %d, %d request(s) reached the other host", resp.StatusCode, reached.Load())
	}
}

func TestExecProviderAsksForReexec(t *testing.T) {
	// An absolute path on this OS: "/usr/local/bin/wrapper" is relative on Windows, where
	// the configuration refuses it. The path is encoded, since a Windows path holds backslashes.
	wrapper := filepath.Join(t.TempDir(), "wrapper")
	command, err := json.Marshal([]string{wrapper, "--env-file=" + filepath.Join(filepath.Dir(wrapper), "read.env"), "--"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := `{"contexts": {"test": {"tailnetId": "T1234CNTRL", "credentials": {"read":
	  {"provider": "exec", "command": ` + string(command) + `}}}}}`
	a, err := Build(context.Background(), Options{Dirs: dirs(t, cfg), Stat: noCLI, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(a.Env.APIErr, creds.ErrReexecRequired) || a.Provider.Command[0] != wrapper {
		t.Fatalf("APIErr = %v, provider = %+v", a.Env.APIErr, a.Provider)
	}
}

func TestAuditReadsNone(t *testing.T) {
	cfg := `{"contexts": {"test": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "env"}}}},
	  "audit": {"reads": "none"}}`
	d := dirs(t, cfg)
	a, err := Build(context.Background(), Options{Dirs: d, Stat: noCLI, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Record(map[string]any{"tool": "devices_list"}); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(d.Logs, "audit.jsonl")); len(data) != 0 {
		t.Errorf("audit.reads none still wrote: %s", data)
	}
}

func TestKeyIDNeverKeepsTheSecret(t *testing.T) {
	secret := strings.Repeat("s", 20)
	key := "tskey" + "-api-" + "kID123CNTRL-" + secret // assembled so no literal matches a scanner rule
	if got := keyID(creds.Read{Kind: creds.KindAPIKey, APIKey: creds.NewSecret(key)}); got != "kID123CNTRL" {
		t.Errorf("keyID = %q", got)
	}
	if got := keyID(creds.Read{Kind: creds.KindAPIKey, APIKey: creds.NewSecret("unexpected")}); got != "" {
		t.Errorf("keyID of an unparsable key = %q", got)
	}
	if got := keyID(creds.Read{Kind: creds.KindOAuth, ClientID: "kCLIENT", ClientSecret: creds.NewSecret(secret)}); got != "kCLIENT" {
		t.Errorf("keyID = %q", got)
	}
}

func TestBuildLoadsThePrivacyKeyEvenWithoutACredential(t *testing.T) {
	env := map[string]string{privacy.EnvKey: strings.Repeat("5a", 32)}
	a, err := Build(context.Background(), Options{Dirs: dirs(t, envConfig), Stat: noCLI, Getenv: func(k string) string { return env[k] }})
	if err != nil {
		t.Fatal(err)
	}
	if a.Env.Privacy == nil || a.Env.PrivacyErr != nil {
		t.Fatalf("Privacy = %v, PrivacyErr = %v", a.Env.Privacy, a.Env.PrivacyErr)
	}
	if code(a.Env.APIErr) != tkerr.CredentialUnavailable {
		t.Fatalf("APIErr = %v: the credential is missing", a.Env.APIErr)
	}
	env[privacy.EnvKey] = "short"
	a, err = Build(context.Background(), Options{Dirs: dirs(t, envConfig), Stat: noCLI, Getenv: func(k string) string { return env[k] }})
	if err != nil || a.Env.Privacy != nil || code(a.Env.PrivacyErr) != tkerr.PrivacyKeyUnavailable {
		t.Fatalf("malformed key: Privacy = %v, PrivacyErr = %v, err = %v", a.Env.Privacy, a.Env.PrivacyErr, err)
	}
}

// The file provider's credential file is read through config.ReadSecretFile, which
// checks and reads one file; Options.ReadFile, the by-path reader that follows a
// separate check, is not used for it. A test with fakes cannot tell the two apart,
// so this one reads a real file.
func TestFileProviderReadsItsCredentialThroughReadSecretFile(t *testing.T) {
	f := apitest.New(t)
	credPath := filepath.Join(t.TempDir(), "read.env")
	body := creds.EnvClientID + "=" + apitest.ClientID + "\n" + creds.EnvClientSecret + "=" + apitest.ClientSecret + "\n"
	if err := os.WriteFile(credPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`{"contexts": {"test": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "file", "path": %q}}}}}`, credPath)
	var byPath []string
	a, err := Build(context.Background(), Options{Dirs: dirs(t, cfg), Stat: noCLI,
		Getenv:   func(string) string { return "" },
		ReadFile: func(p string) ([]byte, error) { byPath = append(byPath, p); return os.ReadFile(p) },
		API:      api.Options{BaseURL: f.URL(), Sleep: func(context.Context, time.Duration) error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	if a.Env.APIErr != nil || a.CredKind != creds.KindOAuth || a.Provider.Provider != "file" {
		t.Fatalf("APIErr = %v, kind %q, provider %q", a.Env.APIErr, a.CredKind, a.Provider.Provider)
	}
	if len(byPath) != 0 {
		t.Errorf("the credential file was read by path through Options.ReadFile: %v", byPath)
	}
}
