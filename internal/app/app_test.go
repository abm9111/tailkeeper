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
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
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
	if len(a.Registry.All()) != 48 {
		t.Errorf("registry has %d tools", len(a.Registry.All()))
	}
}

// The registry the app builds is the one the MCP server is made from. The tools of the owner's
// command line alone are not in it, whatever the configuration.
func TestTheAppRegistryHoldsNoOwnerTool(t *testing.T) {
	for _, body := range []string{"", envConfig} {
		a, err := Build(context.Background(), Options{Dirs: dirs(t, body), Stat: noCLI})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := a.Registry.Get("security_explain"); ok {
			t.Error("security_explain is in the app's registry, from which the MCP server is built")
		}
		if len(a.Registry.All()) != 48 {
			t.Errorf("registry has %d tools, want the 48 it had", len(a.Registry.All()))
		}
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

// The read line of the owner's security explanation carries where the intent came from, the start
// of its digest and the counts; a field of any other name is dropped.
func TestRecordKeepsTheFieldsOfTheExplanationAndNothingElse(t *testing.T) {
	f := apitest.New(t)
	env := map[string]string{creds.EnvClientID: apitest.ClientID, creds.EnvClientSecret: apitest.ClientSecret}
	d := dirs(t, envConfig)
	a, err := Build(context.Background(), Options{Dirs: d, Stat: noCLI, Getenv: func(k string) string { return env[k] },
		API: api.Options{BaseURL: f.URL(), Sleep: func(context.Context, time.Duration) error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	out := tools.SecurityExplainOutput{Intent: tools.SecurityExplainIntent{Source: "cli", Revision: "0123456789ab"},
		Counts: tools.SecurityExplainCounts{Total: 5, Met: 1, Unmet: 1, Unknown: 1, MetWithLimits: 1, NotEvaluated: 1}}
	fields := out.AuditFields()
	fields["tool"] = "security_explain"
	fields["source"], fields["path"], fields["policy"], fields["login"] = "SRC-CANARY", "PATH-CANARY", "POLICY-CANARY", "LOGIN-CANARY"
	if err := a.Record(fields); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(d.Logs, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &line); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{"intent": "cli", "digest": "0123456789ab", "expectations": float64(5), "met": float64(1), "unmet": float64(1),
		"unknown": float64(1), "limited": float64(1), "not_evaluated": float64(1), "tool": "security_explain"} {
		if line[k] != want {
			t.Errorf("%s = %v, want %v", k, line[k], want)
		}
	}
	for _, bad := range []string{"SRC-CANARY", "PATH-CANARY", "POLICY-CANARY", "LOGIN-CANARY"} {
		if strings.Contains(string(data), bad) {
			t.Errorf("the audit line holds %q: %s", bad, data)
		}
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
// checks and reads one file; Options defaults to that checked reader.
// A test with fakes cannot show that the check runs, so this one reads a real file: it is
// served while its mode is private and refused once it is not.
func TestFileProviderReadsItsCredentialThroughReadSecretFile(t *testing.T) {
	f := apitest.New(t)
	credPath := filepath.Join(t.TempDir(), "read.env")
	body := creds.EnvClientID + "=" + apitest.ClientID + "\n" + creds.EnvClientSecret + "=" + apitest.ClientSecret + "\n"
	if err := os.WriteFile(credPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`{"contexts": {"test": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "file", "path": %q}}}}}`, credPath)
	build := func() *App {
		t.Helper()
		a, err := Build(context.Background(), Options{Dirs: dirs(t, cfg), Stat: noCLI,
			Getenv: func(string) string { return "" },
			API:    api.Options{BaseURL: f.URL(), Sleep: func(context.Context, time.Duration) error { return nil }}})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a := build()
	if a.Env.APIErr != nil || a.CredKind != creds.KindOAuth || a.Provider.Provider != "file" {
		t.Fatalf("APIErr = %v, kind %q, provider %q", a.Env.APIErr, a.CredKind, a.Provider.Provider)
	}
	if runtime.GOOS == "windows" {
		return // Windows has no strict mode until Windows hardened mode (spec section 4)
	}
	if err := os.Chmod(credPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if a = build(); code(a.Env.APIErr) != tkerr.ConfigUnsafe {
		t.Errorf("a credential file with mode 0644: APIErr = %v, want config_unsafe from the checked read", a.Env.APIErr)
	}
}

// PrivacyState is the one condition for the privacy key: `doctor` reports it and the
// start-up warnings use it, so that they cannot disagree about what the key amounts to.
func TestPrivacyStateIsTheOneConditionForTheKey(t *testing.T) {
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	bad := tkerr.New(tkerr.PrivacyKeyUnavailable, "bad", "")
	show := &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
	for name, c := range map[string]struct {
		set  func(*App)
		want PrivacyState
	}{
		"nothing loaded":         {func(*App) {}, PrivacyNone},
		"a key":                  {func(a *App) { a.Env.Privacy = k }, PrivacyLoaded},
		"a key that failed":      {func(a *App) { a.Env.PrivacyErr = bad }, PrivacyFailed},
		"a failure beside a key": {func(a *App) { a.Env.Privacy, a.Env.PrivacyErr = k, bad }, PrivacyFailed},
		"oidc":                   {func(a *App) { a.Provider = config.Provider{Provider: "oidc"} }, PrivacyNotStored},
		"personal data shown":    {func(a *App) { a.Env.Config = show }, PrivacyUnused},
		"a failure while shown":  {func(a *App) { a.Env.Config, a.Env.PrivacyErr = show, bad }, PrivacyFailed},
	} {
		a := &App{Env: &registry.Env{}, Provider: config.Provider{Provider: "env"}}
		c.set(a)
		if got := a.PrivacyState(); got != c.want {
			t.Errorf("%s: state %d, want %d", name, got, c.want)
		}
	}
}

// Build keeps why a privacy key that looks set did not load, and the notice that says it is
// there while the key is none with a reason, or when it failed (the notice then says that);
// not when it loaded, not when personal data is shown and nothing failed (no key is used),
// not for oidc. The notice holds no value.
func TestBuildNotesAPrivacyKeyThatLooksSetAndDidNotLoad(t *testing.T) {
	key := strings.Repeat("5a", 32)
	shown := `{"contexts": {"test": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "env"}}}}, "personalData": "show"}`
	oidc := `{"contexts": {"test": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "oidc", "clientId": "c"}}}}}`
	for name, c := range map[string]struct {
		cfg    string
		env    map[string]string
		note   bool
		notice bool
	}{
		"absent":            {envConfig, nil, false, false},
		"a valid key":       {envConfig, map[string]string{privacy.EnvKey: key}, false, false},
		"set but empty":     {envConfig, map[string]string{privacy.EnvKey: ""}, true, true},
		"blank":             {envConfig, map[string]string{privacy.EnvKey: "  "}, true, true},
		"malformed":         {envConfig, map[string]string{privacy.EnvKey: "short"}, false, true},
		"empty, data shown": {shown, map[string]string{privacy.EnvKey: ""}, true, false},
		"empty, oidc":       {oidc, map[string]string{privacy.EnvKey: ""}, false, false},
	} {
		a, err := Build(context.Background(), Options{Dirs: dirs(t, c.cfg), Stat: noCLI,
			Getenv:    func(k string) string { return c.env[k] },
			LookupEnv: func(k string) (string, bool) { v, ok := c.env[k]; return v, ok }})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if (a.PrivacyNote != "") != c.note {
			t.Errorf("%s: note %q", name, a.PrivacyNote)
		}
		n := a.PrivacyNotice()
		if (n != "") != c.notice {
			t.Errorf("%s: notice %q", name, n)
		}
		want := "tailkeeper: warning: no privacy key was loaded (TAILKEEPER_PRIVACY_KEY is set but empty)"
		if name == "malformed" {
			want = "tailkeeper: the privacy key is malformed or unreadable (privacy_key_unavailable)" // said by the failure branch
		}
		if c.notice && (!strings.HasPrefix(n, want) || strings.Contains(n, key)) {
			t.Errorf("%s: notice %q", name, n)
		}
	}
}

// The real environment is read through os.LookupEnv, so that a variable set to nothing (an
// unset secret in a workflow, an empty line of an environment file) is told from one that
// is not there at all.
func TestBuildSeesAnEmptyPrivacyKeyVariableInTheRealEnvironment(t *testing.T) {
	for _, name := range []string{creds.EnvClientID, creds.EnvClientSecret, creds.EnvAPIKey, "TAILKEEPER_CONTEXT"} {
		t.Setenv(name, "")
	}
	t.Setenv(privacy.EnvKey, "")
	a, err := Build(context.Background(), Options{Dirs: dirs(t, envConfig), Stat: noCLI})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.PrivacyNote, "TAILKEEPER_PRIVACY_KEY is set but empty") {
		t.Errorf("a variable set to nothing: note %q", a.PrivacyNote)
	}
	if err := os.Unsetenv(privacy.EnvKey); err != nil {
		t.Fatal(err)
	}
	a, err = Build(context.Background(), Options{Dirs: dirs(t, envConfig), Stat: noCLI})
	if err != nil || a.PrivacyNote != "" {
		t.Errorf("a variable that is not set: note %q, err %v", a.PrivacyNote, err)
	}
}

// A key that is set and failed (malformed, unreadable) is said by the same notice, in the
// words the MCP server has always used, escaped, with no value; one that failed is not said
// twice when a note exists; an absent key says nothing.
func TestPrivacyNoticeSaysAMalformedKeyToo(t *testing.T) {
	const typed = "zz-not-the-key-zz"
	_, bad := privacy.Parse(typed)
	a := &App{Env: &registry.Env{PrivacyErr: bad}, Provider: config.Provider{Provider: "env"}, PrivacyNote: "TAILKEEPER_PRIVACY_KEY is set but empty"}
	n := a.PrivacyNotice()
	if !strings.HasPrefix(n, "tailkeeper: the privacy key is malformed or unreadable (privacy_key_unavailable): results are masked without pseudonyms and audit_log leaves out digests: ") ||
		strings.Contains(n, typed) || strings.Contains(n, "no privacy key was loaded") {
		t.Errorf("notice = %q", n)
	}
	a.Env.PrivacyErr = tkerr.New(tkerr.PrivacyKeyUnavailable, "key file \u202ebad\x1b[2J", "")
	if n := a.PrivacyNotice(); strings.ContainsAny(n, "\u202e\x1b") || !strings.Contains(n, `\u{202E}bad\u{001B}[2J`) {
		t.Errorf("the notice prints an invisible character raw, or not escaped: %q", n)
	}
	absent := &App{Env: &registry.Env{}, Provider: config.Provider{Provider: "env"}}
	if n := absent.PrivacyNotice(); n != "" {
		t.Errorf("an absent key said %q", n)
	}
}

// What a malformed key costs depends on the masking mode, and the notice says the cost of the
// mode in force. With masking on (the default, whether "mask" or nothing is configured),
// results are masked without pseudonyms and audit_log leaves out its digests. With personalData
// "show", nothing is masked and no key is used, and audit_log digests are plain SHA-256
// values, so the notice may not say that results are masked or that digests are left out.
func TestPrivacyNoticeSaysWhatAMalformedKeyCostsInEachMode(t *testing.T) {
	const typed = "zz-not-the-key-zz"
	_, bad := privacy.Parse(typed)
	withMode := func(mode string) *App {
		env := &registry.Env{PrivacyErr: bad}
		if mode != "no configuration" {
			env.Config = &config.Loaded{Config: config.Config{PersonalData: mode}}
		}
		return &App{Env: env, Provider: config.Provider{Provider: "env"}}
	}
	const prefix = "tailkeeper: the privacy key is malformed or unreadable (privacy_key_unavailable): "
	const masked = "results are masked without pseudonyms and audit_log leaves out digests: "
	for _, mode := range []string{"no configuration", "", config.PersonalDataMask} {
		n := withMode(mode).PrivacyNotice()
		if !strings.HasPrefix(n, prefix+masked) || strings.Contains(n, "not masked") || strings.Contains(n, typed) {
			t.Errorf("masking on (personalData %q): notice %q", mode, n)
		}
	}
	n := withMode(config.PersonalDataShow).PrivacyNotice()
	if !strings.HasPrefix(n, prefix) || !strings.Contains(n, `personalData is "show"`) || !strings.Contains(n, "results are not masked") ||
		!strings.Contains(n, "the key is not used") || !strings.Contains(n, "plain SHA-256") {
		t.Errorf(`personalData "show": notice %q does not say that nothing is masked, that the key is unused and that digests are plain`, n)
	}
	if strings.Contains(n, "are masked without") || strings.Contains(n, "leaves out digests") || strings.Contains(n, typed) {
		t.Errorf(`personalData "show": notice %q says what masking costs, or holds the typed key`, n)
	}
}
