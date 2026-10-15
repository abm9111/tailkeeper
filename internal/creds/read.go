// Package creds resolves credentials (spec §7). M1 implements the read class.
//
// tailkeeper never reads variables it did not define: TS_* and TAILSCALE_* are
// ignored even when present, because developer shells often hold full-permission
// user tokens in them.
package creds

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Kind is the authentication scheme of a credential.
type Kind string

const (
	KindOAuth     Kind = "oauth"
	KindAPIKey    Kind = "api_key"
	KindFederated Kind = "federated"
)

// Variable names of the read class (spec §7.3).
const (
	EnvClientID     = "TAILKEEPER_READ_CLIENT_ID"
	EnvClientSecret = "TAILKEEPER_READ_CLIENT_SECRET"
	EnvAPIKey       = "TAILKEEPER_READ_API_KEY"
	EnvOIDCToken    = "TAILKEEPER_OIDC_TOKEN"
	EnvReexec       = "TAILKEEPER_REEXEC"
)

// Read is a resolved read credential. Its String method never prints a secret,
// and shows only the start of the client ID.
type Read struct {
	Kind         Kind
	ClientID     string // OAuth client or federated identity ID: not a secret
	ClientSecret Secret // OAuth only
	APIKey       Secret // API access token only
	Audience     string // federated only
	IDToken      func(ctx context.Context) (string, error)
	Provider     string // env, file, exec or oidc
}

func (r Read) String() string {
	switch r.Kind {
	case KindOAuth:
		return fmt.Sprintf("oauth client %s via %s", sanitize.MaskID(r.ClientID), r.Provider)
	case KindAPIKey:
		return "api access token via " + r.Provider
	case KindFederated:
		return fmt.Sprintf("federated identity %s via %s", sanitize.MaskID(r.ClientID), r.Provider)
	}
	return "no credential"
}

// System is the environment and filesystem a provider reads. Tests replace it.
type System struct {
	Getenv   func(string) string
	ReadFile func(string) ([]byte, error) // files a variable names ("file:" values) and the OIDC token file
	// ReadSecretFile checks a credential file and reads it through the file it
	// checked, so nothing can be put in the path's place between the check and the
	// read. It is config.ReadSecretFile when nil: a System built without it takes the
	// safe read, and there is no path that checks a file by name and reads it by name
	// afterwards. A test that has no real file replaces it with a fake that does both.
	ReadSecretFile func(string) ([]byte, error)
	HTTPClient     *http.Client // used only to fetch platform OIDC tokens
}

// readSecret reads the credential file path, refusing an unsafe one. code classifies
// a read failure that carries no code of its own.
func (s System) readSecret(path string, code tkerr.Code) ([]byte, error) {
	read := s.ReadSecretFile
	if read == nil {
		read = config.ReadSecretFile
	}
	data, err := read(path)
	if err != nil {
		if _, ok := tkerr.As(err); !ok {
			return nil, tkerr.Wrap(code, err, "cannot read "+path, "")
		}
		return nil, err
	}
	return data, nil
}

// ErrReexecRequired means the exec provider must re-run tailkeeper under its wrapper.
var ErrReexecRequired = tkerr.New(tkerr.CredentialUnavailable,
	"the exec provider must re-run tailkeeper under its wrapper", "")

// Resolve turns a configured provider into a Read credential.
func Resolve(ctx context.Context, p config.Provider, sys System) (Read, error) {
	switch p.Provider {
	case "env":
		return fromVars(sys.Getenv, sys.ReadFile, "env")
	case "exec":
		r, err := fromVars(sys.Getenv, sys.ReadFile, "exec")
		if err == nil {
			return r, nil
		}
		// Only an absent or partial credential is the wrapper's to supply. A
		// conflicting or unreadable one is a mistake re-running cannot fix.
		missing := errors.Is(err, errNoCredential) || errors.Is(err, errPartialCredential)
		switch {
		case !missing:
			return Read{}, err
		case sys.Getenv(EnvReexec) != "1":
			return Read{}, ErrReexecRequired
		case errors.Is(err, errNoCredential):
			return Read{}, tkerr.New(tkerr.CredentialUnavailable,
				"the exec wrapper ran but did not provide "+EnvClientID+"/"+EnvClientSecret+" or "+EnvAPIKey,
				"check the wrapper's env file and that the secret manager is unlocked")
		}
		return Read{}, err
	case "file":
		data, err := sys.readSecret(p.Path, tkerr.CredentialUnavailable)
		if err != nil {
			return Read{}, err
		}
		vars, err := parseEnvFile(data)
		if err != nil {
			return Read{}, err
		}
		return fromVars(func(k string) string { return vars[k] }, sys.ReadFile, "file")
	case "oidc":
		return oidc(p, sys), nil
	}
	return Read{}, tkerr.New(tkerr.ConfigInvalid, fmt.Sprintf("unknown provider %q", p.Provider), "")
}

func fromVars(get func(string) string, readFile func(string) ([]byte, error), provider string) (Read, error) {
	id, err := value(get(EnvClientID), readFile)
	if err != nil {
		return Read{}, err
	}
	secret, err := value(get(EnvClientSecret), readFile)
	if err != nil {
		return Read{}, err
	}
	key, err := value(get(EnvAPIKey), readFile)
	if err != nil {
		return Read{}, err
	}
	switch {
	case key != "" && (id != "" || secret != ""):
		return Read{}, tkerr.New(tkerr.ConfigInvalid,
			"set either "+EnvAPIKey+" or "+EnvClientID+"/"+EnvClientSecret+", not both", "")
	case key != "":
		return Read{Kind: KindAPIKey, APIKey: NewSecret(key), Provider: provider}, nil
	case id != "" && secret != "":
		return Read{Kind: KindOAuth, ClientID: id, ClientSecret: NewSecret(secret), Provider: provider}, nil
	case id != "" || secret != "":
		return Read{}, errPartialCredential
	}
	return Read{}, errNoCredential
}

// fromVars' two "not there (yet)" outcomes; Resolve tells them apart.
var (
	errNoCredential = tkerr.New(tkerr.CredentialUnavailable,
		"no read credential: set "+EnvClientID+" and "+EnvClientSecret+" (or "+EnvAPIKey+")",
		"tailkeeper ignores TS_* and TAILSCALE_* variables on purpose")
	errPartialCredential = tkerr.New(tkerr.CredentialUnavailable,
		"only one of "+EnvClientID+" and "+EnvClientSecret+" is set", "set both")
)

// reexecEnv returns environ with every TAILKEEPER_REEXEC entry replaced by one
// TAILKEEPER_REEXEC=1. Appending alone is not enough: with duplicate keys a Go
// child reads the first entry, so an inherited value would re-trigger the wrapper
// forever.
func reexecEnv(environ []string) []string {
	out := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		if !strings.HasPrefix(kv, EnvReexec+"=") {
			out = append(out, kv)
		}
	}
	return append(out, EnvReexec+"=1")
}

// value resolves the `file:` prefix convention shared with Tailscale's TS_* variables.
func value(v string, readFile func(string) ([]byte, error)) (string, error) {
	if !strings.HasPrefix(v, "file:") {
		return strings.TrimSpace(v), nil
	}
	path := strings.TrimPrefix(v, "file:")
	data, err := readFile(path)
	if err != nil {
		return "", tkerr.Wrap(tkerr.CredentialUnavailable, err, "cannot read secret file "+path, "")
	}
	return strings.TrimSpace(string(data)), nil
}

func parseEnvFile(data []byte) (map[string]string, error) {
	vars := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		k, v, ok := strings.Cut(text, "=")
		if !ok {
			return nil, tkerr.New(tkerr.ConfigInvalid, fmt.Sprintf("credential file line %d is not NAME=value", line), "")
		}
		vars[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return vars, sc.Err()
}

func oidc(p config.Provider, sys System) Read {
	aud := p.Audience
	if aud == "" {
		aud = "api.tailscale.com/" + p.ClientID
	}
	return Read{
		Kind:     KindFederated,
		ClientID: p.ClientID,
		Audience: aud,
		Provider: "oidc",
		IDToken: func(ctx context.Context) (string, error) {
			return platformToken(ctx, p, aud, sys)
		},
	}
}

// platformToken returns an identity token: from tokenFile, then GitHub Actions'
// documented request endpoint, then TAILKEEPER_OIDC_TOKEN.
func platformToken(ctx context.Context, p config.Provider, aud string, sys System) (string, error) {
	if p.TokenFile != "" {
		data, err := sys.ReadFile(p.TokenFile)
		if err != nil {
			return "", tkerr.Wrap(tkerr.CredentialUnavailable, err, "cannot read OIDC token file "+p.TokenFile, "")
		}
		return strings.TrimSpace(string(data)), nil
	}
	if reqURL, reqTok := sys.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), sys.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"); reqURL != "" && reqTok != "" {
		return githubToken(ctx, reqURL, reqTok, aud, sys.HTTPClient)
	}
	if v := sys.Getenv(EnvOIDCToken); v != "" {
		return value(v, sys.ReadFile)
	}
	return "", tkerr.New(tkerr.CredentialUnavailable, "no OIDC identity token available",
		"set tokenFile, run in GitHub Actions with `permissions: id-token: write`, or set "+EnvOIDCToken)
}

func githubToken(ctx context.Context, reqURL, reqTok, aud string, hc *http.Client) (string, error) {
	u, err := url.Parse(reqURL)
	if err != nil {
		return "", tkerr.Wrap(tkerr.CredentialUnavailable, err, "ACTIONS_ID_TOKEN_REQUEST_URL is not a URL", "")
	}
	q := u.Query()
	q.Set("audience", aud)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", tkerr.Wrap(tkerr.CredentialUnavailable, err, "cannot build the GitHub OIDC request", "")
	}
	req.Header.Set("Authorization", "Bearer "+reqTok)
	if hc == nil {
		// Like every client tailkeeper builds, never follow a redirect (spec §20): the
		// request carries a bearer token.
		hc = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", tkerr.Wrap(tkerr.CredentialUnavailable, err, "GitHub OIDC token request failed", "")
	}
	defer func() { _ = resp.Body.Close() }() // read only
	if resp.StatusCode != http.StatusOK {
		return "", tkerr.New(tkerr.CredentialUnavailable,
			fmt.Sprintf("GitHub OIDC token request returned HTTP %d", resp.StatusCode),
			"the workflow needs `permissions: id-token: write`")
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil || body.Value == "" {
		return "", tkerr.New(tkerr.CredentialUnavailable, "GitHub OIDC token response had no value", "")
	}
	return body.Value, nil
}

// PrivacyKey reads TAILKEEPER_PRIVACY_KEY from where provider p keeps the read
// credential (spec §7.6): the environment for env and exec (exec's wrapper puts
// it there), the credential file for file. oidc stores no secret, so it has no
// key. No key set is not an error: masking then names nothing.
func PrivacyKey(p config.Provider, sys System) (*privacy.Key, error) {
	var raw string
	switch p.Provider {
	case "env", "exec":
		raw = sys.Getenv(privacy.EnvKey)
	case "file":
		data, err := sys.readSecret(p.Path, tkerr.PrivacyKeyUnavailable)
		if err != nil {
			return nil, err
		}
		vars, err := parseEnvFile(data)
		if err != nil {
			return nil, err
		}
		raw = vars[privacy.EnvKey]
	default:
		return nil, nil
	}
	v, err := value(raw, sys.ReadFile)
	if err != nil {
		return nil, tkerr.Wrap(tkerr.PrivacyKeyUnavailable, err, "cannot read the file "+privacy.EnvKey+" names", "")
	}
	if v == "" {
		return nil, nil
	}
	return privacy.Parse(v)
}
