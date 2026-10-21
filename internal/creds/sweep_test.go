package creds

import (
	"context"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// tkerr's view of an error, for the assertions below.
func asErr(t *testing.T, err error) *tkerr.Error {
	t.Helper()
	e, ok := tkerr.As(err)
	if !ok {
		t.Fatalf("err = %v, want a tailkeeper error", err)
	}
	return e
}

// TS_* and TAILSCALE_* are ignored on purpose, and the file provider takes them no more
// than the environment does: a credential file that holds the names of a developer's
// full-permission token is a file with no credential in it.
func TestTSVariablesAreIgnoredByTheFileProviderToo(t *testing.T) {
	file := "TS_API_KEY=user-token\nTAILSCALE_API_KEY=user-token\nTS_CLIENT_SECRET=x\nTAILSCALE_OAUTH_CLIENT_SECRET=x\n"
	s := sys(map[string]string{"TS_API_KEY": "user-token", "TAILSCALE_API_KEY": "user-token"},
		map[string]string{"/etc/tk/read.env": file})
	_, err := Resolve(context.Background(), config.Provider{Provider: "file", Path: "/etc/tk/read.env"}, s)
	if e := asErr(t, err); e.Code != tkerr.CredentialUnavailable || !strings.Contains(e.Message, "no read credential") {
		t.Errorf("err = %v, want credential_unavailable: no read credential", err)
	}
}

// A value of the form file:PATH inside a credential file is read by path, without the
// ownership and mode check the credential file itself gets. That is by design: a
// container secret mount (a directory of one file per secret, mode 0444 or root-owned)
// is the use, and the credential file the configuration names is the one that is checked.
// The test pins both halves, so a change to either is a decision.
func TestAFileValueInsideACredentialFileIsReadWithoutACheck(t *testing.T) {
	var checked, byPath []string
	s := System{
		Getenv: func(string) string { return "" },
		ReadSecretFile: func(p string) ([]byte, error) {
			checked = append(checked, p)
			return []byte(EnvAPIKey + "=file:/run/secrets/key\n"), nil
		},
		ReadFile: func(p string) ([]byte, error) {
			byPath = append(byPath, p)
			return []byte("test-api-key\n"), nil
		},
	}
	r, err := Resolve(context.Background(), config.Provider{Provider: "file", Path: "/etc/tk/read.env"}, s)
	if err != nil || r.Kind != KindAPIKey || r.APIKey.Reveal() != "test-api-key" {
		t.Fatalf("Resolve = %+v, %v", r, err)
	}
	if want := []string{"/etc/tk/read.env"}; !reflect.DeepEqual(checked, want) {
		t.Errorf("checked reads = %v, want %v", checked, want)
	}
	if want := []string{"/run/secrets/key"}; !reflect.DeepEqual(byPath, want) {
		t.Errorf("reads by path = %v, want %v: the file: value is not checked", byPath, want)
	}
}

// A credential file that is not there is not a mystery: the message names the file and
// the hint says what to create, whichever of the two codes the caller gave the read.
func TestAMissingCredentialFileNamesWhatToCreate(t *testing.T) {
	gone := func(p string) ([]byte, error) {
		return nil, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
	}
	s := sys(nil, nil)
	s.ReadSecretFile = gone
	p := config.Provider{Provider: "file", Path: "/etc/tk/read.env"}
	_, err := Resolve(context.Background(), p, s)
	e := asErr(t, err)
	if e.Code != tkerr.CredentialUnavailable || !strings.Contains(e.Message, "the credential file /etc/tk/read.env does not exist") ||
		!strings.Contains(e.Hint, "create the file the provider's path names, mode 600") {
		t.Errorf("Resolve: %v", err)
	}
	_, err = PrivacyKey(p, s)
	e = asErr(t, err)
	if e.Code != tkerr.PrivacyKeyUnavailable || !strings.Contains(e.Message, "does not exist") ||
		!strings.Contains(e.Hint, "create the file the provider's path names, mode 600") {
		t.Errorf("PrivacyKey: %v", err)
	}
	// Through the real read, on a real path that is not there.
	real := System{Getenv: func(string) string { return "" }}
	missing := config.Provider{Provider: "file", Path: t.TempDir() + "/none.env"}
	_, err = Resolve(context.Background(), missing, real)
	if e := asErr(t, err); e.Code != tkerr.CredentialUnavailable || !strings.Contains(e.Hint, "mode 600") {
		t.Errorf("Resolve of a path that is not there: %v", err)
	}
}

// A line the scanner cannot hold is a configuration error that says so, for the
// credential and for the key alike; it was a bare "token too long".
func TestAnOverlongCredentialFileLineIsConfigInvalid(t *testing.T) {
	body := EnvClientID + "=test-client\n" + EnvClientSecret + "=" + strings.Repeat("x", 70000) + "\n"
	p := config.Provider{Provider: "file", Path: "/etc/tk/read.env"}
	_, err := Resolve(context.Background(), p, sys(nil, map[string]string{p.Path: body}))
	if e := asErr(t, err); e.Code != tkerr.ConfigInvalid || e.Message != "credential file line 2 is longer than 64 KiB" {
		t.Errorf("Resolve: %v", err)
	}
	if _, err := parseEnvFile([]byte(strings.Repeat("y", 70000))); asErr(t, err).Message != "credential file line 1 is longer than 64 KiB" {
		t.Errorf("parseEnvFile: %v", err)
	}
}

// The privacy key is optional, but a key file that cannot be read is not "no key": every
// failure to read or parse the credential file that holds it is privacy_key_unavailable,
// with the reason and the fix a reader needs and the cause (which may hold a path or an
// operating-system message) hidden.
func TestPrivacyKeyFromAnUnsafeOrMalformedFileIsPrivacyKeyUnavailable(t *testing.T) {
	p := config.Provider{Provider: "file", Path: "/etc/tk/read.env"}
	unsafeFile := sys(nil, nil)
	unsafeFile.ReadSecretFile = func(string) ([]byte, error) {
		return nil, tkerr.New(tkerr.ConfigUnsafe, "/etc/tk/read.env has mode 0644", "run: chmod 600 '/etc/tk/read.env'")
	}
	for name, c := range map[string]struct {
		s    System
		want string
		hint string
	}{
		"unsafe":     {unsafeFile, "/etc/tk/read.env has mode 0644", "chmod 600"},
		"malformed":  {sys(nil, map[string]string{p.Path: "NOT-A-NAME-VALUE-LINE\n"}), "credential file line 1 is not NAME=value", ""},
		"overlong":   {sys(nil, map[string]string{p.Path: strings.Repeat("z", 70000)}), "line 1 is longer than 64 KiB", ""},
		"unreadable": {sys(nil, nil), "cannot read /etc/tk/read.env", ""},
	} {
		k, err := PrivacyKey(p, c.s)
		if k != nil {
			t.Errorf("%s: a key came back", name)
		}
		e := asErr(t, err)
		if e.Code != tkerr.PrivacyKeyUnavailable || !strings.Contains(e.Message, c.want) || !strings.Contains(e.Hint, c.hint) || e.Err != nil {
			t.Errorf("%s: %#v, want privacy_key_unavailable with %q, hint %q and no cause", name, e, c.want, c.hint)
		}
		if strings.Contains(e.Message, "NOT-A-NAME") || strings.Contains(e.Message, "zzzz") {
			t.Errorf("%s: the message quotes the file: %q", name, e.Message)
		}
	}
	// The key itself, present and well formed, still comes through.
	good := sys(nil, map[string]string{p.Path: privacy.EnvKey + "=" + strings.Repeat("5a", 32) + "\n"})
	if k, err := PrivacyKey(p, good); err != nil || k == nil {
		t.Errorf("PrivacyKey = %v, %v", k, err)
	}
}

// One pair of matching quotes round a value is taken off, not a run of them and not a
// quote that has no partner.
func TestOneMatchingPairOfQuotesIsStripped(t *testing.T) {
	for _, c := range []struct{ line, want string }{
		{`K="abc"`, `abc`},
		{`K='abc'`, `abc`},
		{`K=abc`, `abc`},
		{`K='abc"`, `'abc"`},
		{`K="abc'`, `"abc'`},
		{`K=abc"`, `abc"`},
		{`K="abc`, `"abc`},
		{`K=""abc""`, `"abc"`},
		{`K="'abc'"`, `'abc'`},
		{`K=""`, ``},
		{`K="`, `"`},
		{`K='`, `'`},
		{`K = "abc" `, `abc`},
	} {
		vars, err := parseEnvFile([]byte(c.line + "\n"))
		if err != nil || vars["K"] != c.want {
			t.Errorf("%s: K = %q, %v; want %q", c.line, vars["K"], err, c.want)
		}
	}
}

// A token file with nothing in it is said to be empty; it used to be an empty token that
// failed later, at the exchange, with an error about the token.
func TestAnEmptyOIDCTokenFileSaysSo(t *testing.T) {
	p := config.Provider{Provider: "oidc", ClientID: "fed-client", TokenFile: "/run/tk/token"}
	for name, body := range map[string]string{"empty": "", "blank": " \r\n\t\n"} {
		r, err := Resolve(context.Background(), p, sys(nil, map[string]string{p.TokenFile: body}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = r.IDToken(context.Background())
		if e := asErr(t, err); e.Code != tkerr.CredentialUnavailable || !strings.Contains(e.Message, "/run/tk/token is empty") {
			t.Errorf("%s: err = %v, want credential_unavailable: the token file is empty", name, err)
		}
	}
}
