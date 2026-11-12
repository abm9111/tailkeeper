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
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
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
	Getenv func(string) string
	// ReadSecretFile checks a credential file and reads it through the file it
	// checked, so nothing can be put in the path's place between the check and the
	// read. It is config.ReadSecretFile when nil: a System built without it takes the
	// safe read, and there is no path that checks a file by name and reads it by name
	// afterwards. A test that has no real file replaces it with a fake that does both.
	ReadSecretFile func(string) ([]byte, error)
	HTTPClient     *http.Client // used only to fetch platform OIDC tokens
	// LookupEnv says whether a variable is set at all, so that one set to nothing differs
	// from one that is not there. When nil it is derived from Getenv, and an empty
	// variable reads as not set.
	LookupEnv func(string) (string, bool)
}

// lookupEnv returns the variable name and whether it is set.
func (s System) lookupEnv(name string) (string, bool) {
	if s.LookupEnv != nil {
		return s.LookupEnv(name)
	}
	v := s.Getenv(name)
	return v, v != ""
}

// readSecret reads the credential file path, refusing an unsafe one. code classifies
// a read failure that carries no code of its own: a file that is not there says what
// to create, any other says it cannot be read.
func (s System) readSecret(path string, code tkerr.Code) ([]byte, error) {
	read := s.ReadSecretFile
	if read == nil {
		read = config.ReadSecretFile
	}
	data, err := read(path)
	if err != nil {
		if _, ok := tkerr.As(err); ok {
			return nil, err
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil, tkerr.Wrap(code, err, "the credential file "+path+" does not exist",
				"create the file the provider's path names, mode 600, with one NAME=value per line")
		}
		return nil, tkerr.Wrap(code, err, "cannot read "+path, "")
	}
	return data, nil
}

// readCredentialFile applies the same checked boundary to every indirection.
func (s System) readCredentialFile(path string) ([]byte, error) {
	return s.readSecret(path, tkerr.CredentialUnavailable)
}

// ErrReexecRequired means the exec provider must re-run tailkeeper under its wrapper.
var ErrReexecRequired = tkerr.New(tkerr.CredentialUnavailable,
	"the exec provider must re-run tailkeeper under its wrapper", "")

// Resolve turns a configured provider into a Read credential.
func Resolve(ctx context.Context, p config.Provider, sys System) (Read, error) {
	switch p.Provider {
	case "env":
		return fromVars(sys.Getenv, sys.readCredentialFile, "env")
	case "exec":
		r, err := fromVars(sys.Getenv, sys.readCredentialFile, "exec")
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
			// The variable may be inherited from a parent process: no wrapper ran, and
			// the message says what tailkeeper took from it.
			return Read{}, tkerr.New(tkerr.CredentialUnavailable,
				EnvReexec+"=1 is set, so tailkeeper took the exec wrapper to have run, but no credential came with it ("+
					EnvClientID+"/"+EnvClientSecret+" or "+EnvAPIKey+" are not set)",
				"check the wrapper's env file and that the secret manager is unlocked; if no wrapper ran, "+
					EnvReexec+" was inherited from a parent process: unset it")
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
		return fromVars(func(k string) string { return vars[k] }, sys.readCredentialFile, "file")
	case "oidc":
		return oidc(p, sys), nil
	}
	return Read{}, tkerr.New(tkerr.ConfigInvalid, fmt.Sprintf("unknown provider %q", p.Provider), "")
}

func fromVars(get func(string) string, readFile func(string) ([]byte, error), provider string) (Read, error) {
	id, err := value(EnvClientID, get(EnvClientID), readFile)
	if err != nil {
		return Read{}, err
	}
	secret, err := value(EnvClientSecret, get(EnvClientSecret), readFile)
	if err != nil {
		return Read{}, err
	}
	key, err := value(EnvAPIKey, get(EnvAPIKey), readFile)
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
		"set "+EnvClientID+" and "+EnvClientSecret+" (or "+EnvAPIKey+") where the provider reads them (README, Configure); "+
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

// errRelativePath is why a file: reference or a tokenFile is refused: it names a relative path.
var errRelativePath = errors.New("a credential file is named by a relative path")

// relativePath is the refusal of a relative path, named by what holds it (a variable, or the
// oidc tokenFile). It is config_invalid: the owner wrote something the documentation does
// not allow. It names the holder and never the path, which may be text that is not a path.
func relativePath(holder string) error {
	return tkerr.Wrap(tkerr.ConfigInvalid, errRelativePath,
		holder+": a file: reference must name an absolute path, not a relative one",
		"write file:"+absoluteExample(runtime.GOOS)+", so that the file does not depend on the directory tailkeeper runs in")
}

// errPaddedReference is why a file: reference is refused: spaces, tabs or line ends sit
// around it.
var errPaddedReference = errors.New("a file: reference has spaces around it")

// paddedReference is the refusal of a value that is a file: reference once its spaces are
// trimmed but has some before or after it. It is config_invalid, like a relative path: the
// owner wrote something the documentation does not allow. Read as it stands, such a value was
// a plain token that spelled "file:" and a path, or (with the space after it) a path that
// does not exist. The message names the variable and never the value.
func paddedReference(name string) error {
	return tkerr.Wrap(tkerr.ConfigInvalid, errPaddedReference,
		name+": a file: reference must not have spaces, tabs or line ends before or after it",
		"remove the spaces around the value, so that it is read as a reference to a file and not as the secret itself")
}

// absoluteExample is a path to show in a hint, spelled as an absolute path is on goos: a
// path with a root and no drive is relative on Windows, so "/absolute/path" would send a
// Windows reader to the same refusal.
func absoluteExample(goos string) string {
	if goos == "windows" {
		return `C:\absolute\path`
	}
	return "/absolute/path"
}

// value resolves the `file:` prefix convention shared with Tailscale's TS_* variables. The
// path after the prefix must be absolute: a relative one would be read from whatever
// directory tailkeeper happens to run in, which the owner did not choose. A reference with
// spaces around it is refused, not trimmed: the one place where the surrounding spaces
// change what the value means. A plain value is trimmed. name is the variable that holds v,
// and is all a refusal says of it.
func value(name, v string, readFile func(string) ([]byte, error)) (string, error) {
	trimmed := strings.TrimSpace(v)
	path, isFile := strings.CutPrefix(trimmed, "file:")
	if !isFile {
		return trimmed, nil
	}
	if trimmed != v {
		return "", paddedReference(name)
	}
	if !filepath.IsAbs(path) {
		return "", relativePath(name)
	}
	data, err := readFile(path)
	if err != nil {
		if _, ok := tkerr.As(err); ok {
			return "", err
		}
		return "", tkerr.Wrap(tkerr.CredentialUnavailable, err, "cannot read secret file "+path, "")
	}
	return strings.TrimSpace(string(data)), nil
}

// parseEnvFile reads the NAME=value lines of a credential file. A value keeps its
// quotes unless one matching pair surrounds it (unquote). A line the scanner cannot
// hold, longer than 64 KiB, is a configuration error that says which line.
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
		vars[strings.TrimSpace(k)] = unquote(strings.TrimSpace(v))
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, tkerr.New(tkerr.ConfigInvalid, fmt.Sprintf("credential file line %d is longer than 64 KiB", line+1), "")
		}
		return nil, tkerr.Wrap(tkerr.ConfigInvalid, err, "cannot read the credential file", "")
	}
	return vars, nil
}

// unquote takes off one pair of matching quotes, single or double, and nothing else:
// `'abc"` and a lone quote stay as they are.
func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
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
		if !filepath.IsAbs(p.TokenFile) {
			return "", tkerr.Wrap(tkerr.ConfigInvalid, errRelativePath, `oidc "tokenFile" must be an absolute path`,
				"write the absolute path of the token file, so that it does not depend on the directory tailkeeper runs in")
		}
		data, err := sys.readCredentialFile(p.TokenFile)
		if err != nil {
			return "", err
		}
		tok := strings.TrimSpace(string(data))
		if tok == "" {
			return "", tkerr.New(tkerr.CredentialUnavailable, "the OIDC token file "+p.TokenFile+" is empty",
				"write the identity token into it, or remove tokenFile to take the token from the platform")
		}
		return tok, nil
	}
	if reqURL, reqTok := sys.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), sys.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"); reqURL != "" && reqTok != "" {
		return githubToken(ctx, reqURL, reqTok, aud, sys.HTTPClient)
	}
	if v := sys.Getenv(EnvOIDCToken); v != "" {
		return value(EnvOIDCToken, v, sys.readCredentialFile)
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
	k, _, err := LoadPrivacyKey(p, sys)
	return k, err
}

// LoadPrivacyKey is PrivacyKey with one more answer. When no key loaded and nothing failed,
// but the owner appears to have set one, note says what is wrong with it, so that the
// surfaces can warn: masking goes on without pseudonyms and nothing in a result says so.
// That is the case when
//   - the variable (env, exec) or the line (file) is there and holds nothing, or names a
//     file: that holds nothing; or
//   - (file) a line names TAILKEEPER_PRIVACY_KEY and is not a NAME=value line for it: an
//     `export ` prefix, a UTF-8 byte order mark before the name, quotes around the name, or
//     another spelling of the name.
//
// A key that is simply absent is a choice and has no note. The note names a variable or a
// line number and holds no value, no path and no text of a line: a line may hold the key.
func LoadPrivacyKey(p config.Provider, sys System) (key *privacy.Key, note string, err error) {
	var raw string
	var set bool
	var lines privacyLines
	switch p.Provider {
	case "env", "exec":
		raw, set = sys.lookupEnv(privacy.EnvKey)
	case "file":
		data, err := sys.readSecret(p.Path, tkerr.PrivacyKeyUnavailable)
		if err != nil {
			return nil, "", privacyKeyFileError(err)
		}
		vars, err := parseEnvFile(data)
		if err != nil {
			return nil, "", privacyKeyFileError(err)
		}
		raw, set = vars[privacy.EnvKey]
		lines = scanPrivacyLines(data)
	default:
		return nil, "", nil
	}
	v, err := value(privacy.EnvKey, raw, sys.readCredentialFile)
	if err != nil {
		if errors.Is(err, errRelativePath) || errors.Is(err, errPaddedReference) {
			// The refusals whose reason the owner needs, and that carry no value.
			e := tkerr.From(err)
			return nil, "", tkerr.New(tkerr.PrivacyKeyUnavailable, e.Message, e.Hint)
		}
		return nil, "", tkerr.Wrap(tkerr.PrivacyKeyUnavailable, err, "cannot read the file "+privacy.EnvKey+" names", "")
	}
	if v == "" {
		return nil, emptyPrivacyNote(p.Provider, raw, set, lines), nil
	}
	k, err := privacy.Parse(v)
	return k, "", err
}

// emptyPrivacyNote says why a key that resolved to nothing looks as if it was meant to be
// there, or "" when it looks like a choice.
func emptyPrivacyNote(provider, raw string, set bool, lines privacyLines) string {
	named := strings.HasPrefix(raw, "file:")
	switch {
	case set && provider == "file" && named:
		return fmt.Sprintf("line %d of the credential file names a file for %s that holds nothing", lines.assigned, privacy.EnvKey)
	case set && provider == "file":
		return fmt.Sprintf("line %d of the credential file gives %s no value", lines.assigned, privacy.EnvKey)
	case set && named:
		return privacy.EnvKey + " names a file that holds nothing"
	case set:
		return privacy.EnvKey + " is set but empty"
	case lines.misnamed > 0:
		return fmt.Sprintf("line %d of the credential file names %s but is not a NAME=value line for it, and an `export ` prefix, a byte order mark and quotes around the name are not read", lines.misnamed, privacy.EnvKey)
	}
	return ""
}

// privacyLines are line numbers in a credential file, 0 for none: the last line that
// assigns TAILKEEPER_PRIVACY_KEY (the one parseEnvFile keeps) and the first that names it
// without being such a line.
type privacyLines struct{ assigned, misnamed int }

// scanPrivacyLines reads a credential file as parseEnvFile does and returns line numbers
// only: the text of a line may be the key.
func scanPrivacyLines(data []byte) privacyLines {
	var out privacyLines
	sc := bufio.NewScanner(bytes.NewReader(data))
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		// parseEnvFile has refused a line with no =, so every line here has one.
		name, _, _ := strings.Cut(text, "=")
		name = strings.TrimSpace(name)
		switch {
		case name == privacy.EnvKey:
			out.assigned = line
		case out.misnamed == 0 && namesPrivacyKey(name):
			out.misnamed = line
		}
	}
	return out
}

// namesPrivacyKey reports whether name, the text before the = of a line, holds the name of
// the key as a word of its own, in any case, as a person writes it by mistake:
// `export TAILKEEPER_PRIVACY_KEY`, a name behind the UTF-8 byte order mark that some editors
// put at the start of a file, or a name in quotes. parseEnvFile reads none of these as the
// key, so the key does not load and the owner must be told; what loads is not changed.
func namesPrivacyKey(name string) bool {
	for _, word := range strings.Fields(name) {
		word = strings.TrimPrefix(word, "\ufeff")
		word = strings.Trim(word, `"'`)
		if strings.EqualFold(word, privacy.EnvKey) {
			return true
		}
	}
	return false
}

// privacyKeyFileError is how a failure to read or parse the credential file that holds
// the privacy key is reported: privacy_key_unavailable, with the reason and the fix of
// the failure it replaces and none of its cause, which may hold an operating-system
// message.
func privacyKeyFileError(err error) error {
	e, ok := tkerr.As(err)
	if !ok {
		return tkerr.New(tkerr.PrivacyKeyUnavailable, "cannot read the privacy key from the credential file", "")
	}
	if e.Code == tkerr.PrivacyKeyUnavailable {
		return tkerr.New(e.Code, e.Message, e.Hint)
	}
	return tkerr.New(tkerr.PrivacyKeyUnavailable, "cannot read the privacy key from the credential file: "+e.Message, e.Hint)
}
