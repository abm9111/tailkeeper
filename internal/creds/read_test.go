package creds

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func sys(vars map[string]string, files map[string]string) System {
	read := func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("no such file")
	}
	return System{
		Getenv:   func(k string) string { return vars[k] },
		ReadFile: read,
		// The fake file system has no permissions to check: a test that wants an
		// unsafe file replaces this, as production reads through config.ReadSecretFile.
		ReadSecretFile: read,
	}
}

func code(err error) tkerr.Code {
	if e, ok := tkerr.As(err); ok {
		return e.Code
	}
	return ""
}

func TestEnvOAuth(t *testing.T) {
	r, err := Resolve(context.Background(), config.Provider{Provider: "env"},
		sys(map[string]string{EnvClientID: "test-client", EnvClientSecret: "test-secret"}, nil))
	if err != nil || r.Kind != KindOAuth || r.ClientSecret.Reveal() != "test-secret" {
		t.Fatalf("Resolve = %+v, %v", r, err)
	}
	if strings.Contains(r.String(), "test-secret") {
		t.Fatal("String() leaked the secret")
	}
}

func TestStringMasksTheClientID(t *testing.T) {
	for _, c := range []struct {
		r    Read
		want string
	}{
		{Read{Kind: KindOAuth, ClientID: "kAbCdEf12CNTRL", Provider: "exec"}, "oauth client kAbC… via exec"},
		{Read{Kind: KindFederated, ClientID: "kZyXwVu98CNTRL", Provider: "oidc"}, "federated identity kZyX… via oidc"},
	} {
		if got := c.r.String(); got != c.want {
			t.Errorf("String() = %q, want %q", got, c.want)
		}
	}
}

func TestEnvFilePrefix(t *testing.T) {
	r, err := Resolve(context.Background(), config.Provider{Provider: "env"},
		sys(map[string]string{EnvAPIKey: "file:/run/secrets/key"}, map[string]string{"/run/secrets/key": "test-api-key\n"}))
	if err != nil || r.Kind != KindAPIKey || r.APIKey.Reveal() != "test-api-key" {
		t.Fatalf("Resolve = %+v, %v", r, err)
	}
}

func TestEnvIgnoresTailscaleVariables(t *testing.T) {
	_, err := Resolve(context.Background(), config.Provider{Provider: "env"},
		sys(map[string]string{"TAILSCALE_API_KEY": "user-token", "TS_API_KEY": "user-token",
			"TS_CLIENT_SECRET": "x", "TAILSCALE_OAUTH_CLIENT_SECRET": "x"}, nil))
	if code(err) != tkerr.CredentialUnavailable {
		t.Fatalf("err = %v, want credential_unavailable (TS_*/TAILSCALE_* must be ignored)", err)
	}
}

func TestEnvRejectsAmbiguousAndPartial(t *testing.T) {
	_, err := Resolve(context.Background(), config.Provider{Provider: "env"},
		sys(map[string]string{EnvAPIKey: "k", EnvClientID: "c"}, nil))
	if code(err) != tkerr.ConfigInvalid {
		t.Fatalf("both kinds: err = %v", err)
	}
	_, err = Resolve(context.Background(), config.Provider{Provider: "env"},
		sys(map[string]string{EnvClientID: "c"}, nil))
	if code(err) != tkerr.CredentialUnavailable {
		t.Fatalf("partial OAuth: err = %v", err)
	}
}

func TestExecAsksForReexecOnce(t *testing.T) {
	_, err := Resolve(context.Background(), config.Provider{Provider: "exec", Command: []string{"/usr/bin/true"}}, sys(nil, nil))
	if !errors.Is(err, ErrReexecRequired) {
		t.Fatalf("first run: err = %v, want ErrReexecRequired", err)
	}
	_, err = Resolve(context.Background(), config.Provider{Provider: "exec", Command: []string{"/usr/bin/true"}},
		sys(map[string]string{EnvReexec: "1"}, nil))
	if errors.Is(err, ErrReexecRequired) || code(err) != tkerr.CredentialUnavailable {
		t.Fatalf("after re-exec: err = %v, want credential_unavailable without looping", err)
	}
}

func TestFileProvider(t *testing.T) {
	s := sys(nil, map[string]string{"/etc/tk/read.env": "# comment\n" + EnvClientID + "=test-client\n" + EnvClientSecret + "=\"test-secret\"\n"})
	r, err := Resolve(context.Background(), config.Provider{Provider: "file", Path: "/etc/tk/read.env"}, s)
	if err != nil || r.ClientID != "test-client" || r.ClientSecret.Reveal() != "test-secret" {
		t.Fatalf("Resolve = %+v, %v", r, err)
	}
	s.ReadSecretFile = func(string) ([]byte, error) { return nil, tkerr.New(tkerr.ConfigUnsafe, "mode 0644", "") }
	if _, err := Resolve(context.Background(), config.Provider{Provider: "file", Path: "/etc/tk/read.env"}, s); code(err) != tkerr.ConfigUnsafe {
		t.Fatalf("unsafe file accepted: %v", err)
	}
}

func TestOIDCGitHub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gh-request-token" || r.URL.Query().Get("audience") != "api.tailscale.com/fed-client" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"value":"test-id-token"}`))
	}))
	defer srv.Close()
	s := sys(map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   srv.URL + "/token?api-version=2.0",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "gh-request-token",
	}, nil)
	s.HTTPClient = srv.Client()
	r, err := Resolve(context.Background(), config.Provider{Provider: "oidc", ClientID: "fed-client"}, s)
	if err != nil || r.Kind != KindFederated || r.Audience != "api.tailscale.com/fed-client" {
		t.Fatalf("Resolve = %+v, %v", r, err)
	}
	tok, err := r.IDToken(context.Background())
	if err != nil || tok != "test-id-token" {
		t.Fatalf("IDToken = %q, %v", tok, err)
	}
}

func TestOIDCNoTokenSource(t *testing.T) {
	r, err := Resolve(context.Background(), config.Provider{Provider: "oidc", ClientID: "fed-client"}, sys(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.IDToken(context.Background()); code(err) != tkerr.CredentialUnavailable {
		t.Fatalf("err = %v, want credential_unavailable", err)
	}
}

func TestExecResolutionKeepsTheRealCause(t *testing.T) {
	p := config.Provider{Provider: "exec", Command: []string{"/usr/bin/true"}}
	id, secret, key := EnvClientID, EnvClientSecret, EnvAPIKey
	cases := []struct {
		name string
		vars map[string]string
		want tkerr.Code
		re   bool // want ErrReexecRequired
	}{
		{"nothing before re-exec", map[string]string{}, "", true},
		{"client ID only before re-exec", map[string]string{id: "test-id"}, "", true},
		{"key and pair conflict", map[string]string{key: "test-key", id: "test-id", secret: "test-value"}, tkerr.ConfigInvalid, false},
		{"unreadable file: secret", map[string]string{id: "test-id", secret: "file:/nonexistent/secret"}, tkerr.CredentialUnavailable, false},
		{"nothing after re-exec", map[string]string{EnvReexec: "1"}, tkerr.CredentialUnavailable, false},
		{"client ID only after re-exec", map[string]string{EnvReexec: "1", id: "test-id"}, tkerr.CredentialUnavailable, false},
	}
	for _, c := range cases {
		_, err := Resolve(context.Background(), p, sys(c.vars, nil))
		if c.re {
			if !errors.Is(err, ErrReexecRequired) {
				t.Errorf("%s: err = %v, want a re-exec", c.name, err)
			}
			continue
		}
		e, ok := tkerr.As(err)
		if !ok || e.Code != c.want || errors.Is(err, ErrReexecRequired) {
			t.Errorf("%s: err = %v, want %s without a re-exec", c.name, err, c.want)
		}
	}
	_, err := Resolve(context.Background(), p, sys(map[string]string{EnvReexec: "1", id: "test-id"}, nil))
	if !strings.Contains(err.Error(), "only one of") {
		t.Errorf("after re-exec, a partial credential must say so: %v", err)
	}
}

func TestReexecEnvReplacesAnInheritedMarker(t *testing.T) {
	got := reexecEnv([]string{"HOME=/h", EnvReexec + "=0", "PATH=/bin", EnvReexec + "="})
	n := 0
	for _, kv := range got {
		if strings.HasPrefix(kv, EnvReexec+"=") {
			n++
			if kv != EnvReexec+"=1" {
				t.Errorf("marker = %q", kv)
			}
		}
	}
	if n != 1 || len(got) != 3 {
		t.Errorf("env = %v, want HOME, PATH and one %s=1", got, EnvReexec)
	}
}

// The OIDC token comes from tokenFile first, then GitHub Actions, then
// TAILKEEPER_OIDC_TOKEN; each failure says which source failed.
func TestOIDCTokenSources(t *testing.T) {
	p := config.Provider{Provider: "oidc", ClientID: "fed-client", TokenFile: "/run/tk/token"}
	r, err := Resolve(context.Background(), p, sys(nil, map[string]string{"/run/tk/token": "file-token\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := r.IDToken(context.Background()); err != nil || tok != "file-token" {
		t.Errorf("tokenFile: %q, %v", tok, err)
	}
	r, _ = Resolve(context.Background(), p, sys(nil, nil))
	if _, err := r.IDToken(context.Background()); code(err) != tkerr.CredentialUnavailable || !strings.Contains(err.Error(), "/run/tk/token") {
		t.Errorf("unreadable tokenFile: %v", err)
	}
	p.TokenFile = ""
	r, _ = Resolve(context.Background(), p, sys(map[string]string{EnvOIDCToken: "env-token"}, nil))
	if tok, err := r.IDToken(context.Background()); err != nil || tok != "env-token" {
		t.Errorf("%s: %q, %v", EnvOIDCToken, tok, err)
	}
}

func TestOIDCGitHubFailures(t *testing.T) {
	for body, want := range map[string]string{"403": "HTTP 403", `{"value":""}`: "had no value", `not json`: "had no value"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if body == "403" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(body))
		}))
		s := sys(map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": srv.URL + "/token", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "gh-request-token"}, nil)
		s.HTTPClient = srv.Client()
		r, _ := Resolve(context.Background(), config.Provider{Provider: "oidc", ClientID: "fed-client"}, s)
		if _, err := r.IDToken(context.Background()); code(err) != tkerr.CredentialUnavailable || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", body, err, want)
		}
		srv.Close()
	}
	s := sys(map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": "http://[::1", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "gh-request-token"}, nil)
	r, _ := Resolve(context.Background(), config.Provider{Provider: "oidc", ClientID: "fed-client"}, s)
	if _, err := r.IDToken(context.Background()); err == nil || !strings.Contains(err.Error(), "not a URL") {
		t.Errorf("bad request URL: err = %v", err)
	}
}

func TestFileProviderReadAndParseErrors(t *testing.T) {
	p := config.Provider{Provider: "file", Path: "/etc/tk/read.env"}
	if _, err := Resolve(context.Background(), p, sys(nil, nil)); code(err) != tkerr.CredentialUnavailable || !strings.Contains(err.Error(), "cannot read /etc/tk/read.env") {
		t.Errorf("unreadable: %v", err)
	}
	if _, err := Resolve(context.Background(), p, sys(nil, map[string]string{"/etc/tk/read.env": "not a NAME=value line\n"})); err == nil {
		t.Error("a malformed file was accepted")
	}
}

func TestPrivacyKeyComesFromWhereTheReadCredentialIs(t *testing.T) {
	key := strings.Repeat("5a", 32)
	for name, c := range map[string]struct {
		p     config.Provider
		vars  map[string]string
		files map[string]string
	}{
		"env":         {config.Provider{Provider: "env"}, map[string]string{privacy.EnvKey: key}, nil},
		"exec":        {config.Provider{Provider: "exec"}, map[string]string{privacy.EnvKey: key}, nil},
		"file prefix": {config.Provider{Provider: "env"}, map[string]string{privacy.EnvKey: "file:/k"}, map[string]string{"/k": key + "\n"}},
		"file":        {config.Provider{Provider: "file", Path: "/c.env"}, nil, map[string]string{"/c.env": privacy.EnvKey + "=" + key + "\n"}},
	} {
		k, err := PrivacyKey(c.p, sys(c.vars, c.files))
		if err != nil || k == nil {
			t.Errorf("%s: PrivacyKey = %v, %v", name, k, err)
		}
	}
}

func TestPrivacyKeyAbsentIsNotAnError(t *testing.T) {
	for _, p := range []config.Provider{{Provider: "env"}, {Provider: "exec"}, {Provider: "oidc", ClientID: "x"},
		{Provider: "file", Path: "/c.env"}} {
		vars := map[string]string{}
		if p.Provider == "oidc" {
			vars[privacy.EnvKey] = strings.Repeat("5a", 32) // oidc stores no secret, so it never reads one
		}
		k, err := PrivacyKey(p, sys(vars, map[string]string{"/c.env": "OTHER=1\n"}))
		if k != nil || err != nil {
			t.Errorf("%s: PrivacyKey = %v, %v; want nil, nil", p.Provider, k, err)
		}
	}
}

func TestPrivacyKeyMalformedFailsWithoutQuotingIt(t *testing.T) {
	bad := strings.Repeat("5a", 30)
	_, err := PrivacyKey(config.Provider{Provider: "env"}, sys(map[string]string{privacy.EnvKey: bad}, nil))
	if code(err) != tkerr.PrivacyKeyUnavailable || strings.Contains(fmt.Sprint(err), bad) {
		t.Fatalf("err = %v", err)
	}
	_, err = PrivacyKey(config.Provider{Provider: "env"}, sys(map[string]string{privacy.EnvKey: "file:/missing"}, nil))
	if code(err) != tkerr.PrivacyKeyUnavailable {
		t.Fatalf("unreadable key file: %v", err)
	}
}

// The file provider and the privacy key read the credential file through
// System.ReadSecretFile when it is set, so the check and the read cover one file;
// ReadFile, which reads by path, is not used then.
func TestSecretFilesAreReadThroughReadSecretFile(t *testing.T) {
	key := strings.Repeat("5a", 32)
	s := sys(nil, nil)
	s.ReadFile = func(string) ([]byte, error) { t.Error("ReadFile was used"); return nil, errors.New("unused") }
	var read []string
	s.ReadSecretFile = func(p string) ([]byte, error) {
		read = append(read, p)
		return []byte(EnvClientID + "=test-client\n" + EnvClientSecret + "=test-secret\n" + privacy.EnvKey + "=" + key + "\n"), nil
	}
	p := config.Provider{Provider: "file", Path: "/etc/tk/read.env"}
	r, err := Resolve(context.Background(), p, s)
	if err != nil || r.ClientID != "test-client" {
		t.Fatalf("Resolve = %+v, %v", r, err)
	}
	if k, err := PrivacyKey(p, s); err != nil || k == nil {
		t.Fatalf("PrivacyKey = %v, %v", k, err)
	}
	if len(read) != 2 {
		t.Errorf("ReadSecretFile calls = %v, want one for the credential and one for the key", read)
	}
	s.ReadSecretFile = func(string) ([]byte, error) { return nil, tkerr.New(tkerr.ConfigUnsafe, "mode 0644", "") }
	if _, err := Resolve(context.Background(), p, s); code(err) != tkerr.ConfigUnsafe {
		t.Errorf("an unsafe file: err = %v, want config_unsafe", err)
	}
}

// A System built without ReadSecretFile reads a credential file the way production
// does, through config.ReadSecretFile: one step that checks a file and reads that
// file. It does not fall back to checking a path and then reading the path again,
// which leaves a gap between the two, so a caller that forgets the field gets the
// safe read and no signal is needed. A real file system shows it: the fake ReadFile
// would serve the unsafe file below, and the check refuses it.
func TestASystemWithoutReadSecretFileStillReadsThroughTheCheckedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SKIPPED: Windows has no strict mode until Windows hardened mode (spec §4)")
	}
	key := strings.Repeat("5a", 32)
	path := filepath.Join(t.TempDir(), "read.env")
	body := EnvClientID + "=test-client\n" + EnvClientSecret + "=test-secret\n" + privacy.EnvKey + "=" + key + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	bypass := System{
		Getenv:   func(string) string { return "" },
		ReadFile: func(p string) ([]byte, error) { t.Errorf("ReadFile read %s by path", p); return []byte(body), nil },
	}
	p := config.Provider{Provider: "file", Path: path}
	r, err := Resolve(context.Background(), p, bypass)
	if err != nil || r.ClientID != "test-client" || r.ClientSecret.Reveal() != "test-secret" {
		t.Fatalf("Resolve = %+v, %v", r, err)
	}
	if k, err := PrivacyKey(p, bypass); err != nil || k == nil {
		t.Fatalf("PrivacyKey = %v, %v", k, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(context.Background(), p, bypass); code(err) != tkerr.ConfigUnsafe {
		t.Errorf("an unsafe file: Resolve err = %v, want config_unsafe", err)
	}
	if _, err := PrivacyKey(p, bypass); code(err) != tkerr.ConfigUnsafe {
		t.Errorf("an unsafe file: PrivacyKey err = %v, want config_unsafe", err)
	}
}

// A resolved credential never prints its secret: no fmt verb, on a Read, a pointer
// to one, a struct field, a slice element or a map value, and no JSON encoder or
// logger, shows the client secret or the API access token. (privacy.Key is held to
// the same rule in internal/privacy.)
func TestReadNeverPrintsItsSecrets(t *testing.T) {
	const secret, token = "PROBE-CLIENT-SECRET-VALUE", "PROBE-API-TOKEN-VALUE"
	oauth, err := Resolve(context.Background(), config.Provider{Provider: "env"},
		sys(map[string]string{EnvClientID: "probe-client", EnvClientSecret: secret}, nil))
	if err != nil {
		t.Fatal(err)
	}
	apiKey, err := Resolve(context.Background(), config.Provider{Provider: "env"},
		sys(map[string]string{EnvAPIKey: token}, nil))
	if err != nil {
		t.Fatal(err)
	}
	// What a leak looks like: the text, and its hex in both cases (%x and %X).
	var leaks []string
	for _, v := range []string{secret, token} {
		h := hex.EncodeToString([]byte(v))
		leaks = append(leaks, v, h, strings.ToUpper(h))
	}
	type unexported struct{ r Read } // fmt prints an unexported field of another struct field by field
	type exported struct{ R Read }
	// Read has its own String, which fmt uses for the verbs a string takes (%v %s %q %x
	// %X), so Read alone does not exercise Secret's Format: print the secrets directly
	// and inside structs that have no String.
	type secrets struct{ ClientSecret, APIKey Secret }
	type hiddenSecrets struct{ s secrets }
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%b", "%c", "%U", "%e", "%t", "%p", "%w"}
	for name, r := range map[string]Read{"oauth": oauth, "api key": apiKey} {
		views := map[string]any{
			"value": r, "pointer": &r, "unexported field": unexported{r}, "exported field": exported{r},
			"slice element": []Read{r}, "map value": map[string]Read{"k": r},
			"client secret": r.ClientSecret, "api key": r.APIKey, "pointer to a secret": &r.ClientSecret,
			"secrets in a struct": secrets{r.ClientSecret, r.APIKey}, "secrets in an unexported field": hiddenSecrets{secrets{r.ClientSecret, r.APIKey}},
			"secret slice": []Secret{r.ClientSecret, r.APIKey}, "secret map": map[string]Secret{"c": r.ClientSecret, "a": r.APIKey},
		}
		for view, v := range views {
			for _, verb := range verbs {
				got := fmt.Sprintf(verb, v)
				for _, s := range leaks {
					if strings.Contains(got, s) {
						t.Errorf("%s: a %s printed with %s shows a secret: %q", name, view, verb, got)
					}
				}
			}
			if b, err := json.Marshal(v); err == nil && (strings.Contains(string(b), secret) || strings.Contains(string(b), token)) {
				t.Errorf("%s: a %s encoded as JSON shows a secret: %s", name, view, b)
			}
			var buf bytes.Buffer
			slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "v", v)
			slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "v", v)
			if strings.Contains(buf.String(), secret) || strings.Contains(buf.String(), token) {
				t.Errorf("%s: a %s logged shows a secret: %s", name, view, buf.String())
			}
		}
	}
}

// Read cannot be encoded as JSON (IDToken is a func), so the JSON check in
// TestReadNeverPrintsItsSecrets never meets an encoded secret. This one encodes the
// secret fields themselves and requires the marker, so it cannot pass by failing to
// encode.
func TestSecretsEncodeAsAMarker(t *testing.T) {
	const secret, token = "PLANTED-CLIENT-SECRET", "PLANTED-API-TOKEN"
	type pair struct{ ClientSecret, APIKey Secret }
	v := pair{NewSecret(secret), NewSecret(token)}
	if got := v.ClientSecret.String() + v.APIKey.String(); got != "(secret)(secret)" {
		t.Errorf("String = %q", got)
	}
	b, err := json.Marshal(v)
	if err != nil || string(b) != `{"ClientSecret":"(secret)","APIKey":"(secret)"}` {
		t.Errorf("json.Marshal = %s, %v", b, err)
	}
	for name, h := range map[string]func(*bytes.Buffer) *slog.Logger{
		"text": func(b *bytes.Buffer) *slog.Logger { return slog.New(slog.NewTextHandler(b, nil)) },
		"json": func(b *bytes.Buffer) *slog.Logger { return slog.New(slog.NewJSONHandler(b, nil)) },
	} {
		var buf bytes.Buffer
		h(&buf).Info("x", "v", v)
		if got := buf.String(); strings.Contains(got, secret) || strings.Contains(got, token) || !strings.Contains(got, "(secret)") {
			t.Errorf("slog %s handler wrote %q, want the marker and no secret", name, got)
		}
	}
}

// githubToken falls back to a client of its own when it is given none. That client must not
// follow a redirect either, as no client tailkeeper builds does: the token request carries
// a bearer token, and a redirect would send it where the endpoint chose. (It once did follow:
// the fallback was a bare http.Client, unreachable in the shipped build, which always passes
// a client, and so unnoticed.) The normal request through the fallback still works.
func TestGithubTokenFallbackClientNeverFollowsARedirect(t *testing.T) {
	var reached atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		_, _ = w.Write([]byte(`{"value":"stolen"}`))
	}))
	defer other.Close()
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer redirecting.Close()
	tok, err := githubToken(context.Background(), redirecting.URL, "request-token", "aud", nil)
	if err == nil || tok != "" {
		t.Errorf("githubToken through a redirect = %q, %v, want an error and no token", tok, err)
	}
	if reached.Load() != 0 {
		t.Errorf("the fallback client followed a redirect: %d request(s) reached the other host", reached.Load())
	}

	var auth string
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"value":"the-oidc-token"}`))
	}))
	defer plain.Close()
	tok, err = githubToken(context.Background(), plain.URL, "request-token", "aud", nil)
	if err != nil || tok != "the-oidc-token" || auth != "Bearer request-token" {
		t.Errorf("the normal request through the fallback = %q, %v (authorization %q)", tok, err, auth)
	}
}
