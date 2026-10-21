// Package app wires configuration, the read credential, the API client, the local
// runner and the audit log into one registry.Env for the CLI and the MCP server.
package app

import (
	"context"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/audit"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/local"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// Options configures Build. Zero values use the real system.
type Options struct {
	Context  string                            // --context flag value
	Getenv   func(string) string               // default os.Getenv
	Dirs     *config.Dirs                      // default config.DefaultDirs()
	Check    config.Checker                    // default config.CheckOwnership
	Stat     func(string) (fs.FileInfo, error) // default os.Stat, for finding the CLI
	ReadFile func(string) ([]byte, error)      // default os.ReadFile
	API      api.Options                       // BaseURL and retry settings (tests)
	Now      func() time.Time                  // default time.Now
}

// App is everything a surface needs.
type App struct {
	Registry   *registry.Registry
	Env        *registry.Env
	Loaded     *config.Loaded  // nil when no configuration exists
	Context    string          // selected context name
	Tailnet    string          // its tailnet ID
	Provider   config.Provider // its read provider
	Credential string          // a description of the read credential that never includes a secret
	CredKind   creds.Kind
	KeyID      string // the credential's key ID (OAuth client ID, federated identity ID or API key ID)
	AuditPath  string
	Audit      *audit.Log // nil when the log could not be opened; AuditErr says why
	AuditErr   error
	AuditReads string // "metadata" or "none"
}

// Build loads the configuration and wires the registry.
//
// It returns an error only when no tool may run: the configuration is unsafe or
// invalid, and the exec provider runs commands the configuration names. Problems
// that affect only API tools (no configuration, no context, no credential, or the
// exec provider still needing its wrapper) are kept in Env.APIErr so local tools
// keep working; creds.ErrReexecRequired there tells the caller to re-exec.
//
// ctx must outlive the App: the API client requests tokens under it, so API reads
// fail once it ends (api.New).
func Build(ctx context.Context, o Options) (*App, error) {
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Check == nil {
		o.Check = config.CheckOwnership
	}
	if o.Stat == nil {
		o.Stat = os.Stat
	}
	if o.ReadFile == nil {
		o.ReadFile = os.ReadFile
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	dirs := o.Dirs
	if dirs == nil {
		d, err := config.DefaultDirs()
		if err != nil {
			return nil, err
		}
		dirs = &d
	}
	a := &App{Registry: registry.New(), AuditReads: "metadata"}
	tools.Register(a.Registry)
	a.Env = &registry.Env{Now: o.Now}

	loaded, err := config.Load(*dirs, o.Check)
	switch {
	case err == nil:
		a.Loaded, a.Env.Config = loaded, loaded
		if r := loaded.Config.Audit.Reads; r != "" {
			a.AuditReads = r
		}
		a.Env.API, a.Env.APIErr = a.connect(ctx, o)
	case tkerr.From(err).Code == tkerr.ConfigMissing:
		a.Env.APIErr = err
	default:
		return nil, err
	}

	var localCfg config.Local
	if a.Loaded != nil {
		localCfg = a.Loaded.Config.Local
	}
	if bin, err := local.Discover(localCfg.TailscaleBinary, o.Stat); err != nil {
		a.Env.LocalErr = err
	} else {
		a.Env.Local = &local.Runner{Bin: bin, Socket: localCfg.Socket, Home: local.UserHome()}
	}

	a.AuditPath = filepath.Join(dirs.Logs, audit.FileName)
	a.Audit, a.AuditErr = audit.Open(a.AuditPath, o.Now)
	return a, nil
}

// connect selects the context, loads its privacy key, resolves its read
// credential and builds the client. The key is loaded once the context is
// selected and before the credential is resolved, so local tools mask with it
// when the credential is unavailable. When no context can be selected nothing
// is loaded, and there is no key.
func (a *App) connect(ctx context.Context, o Options) (*api.Client, error) {
	name, cctx, err := a.Loaded.Select(o.Context, o.Getenv)
	if err != nil {
		return nil, err
	}
	a.Context, a.Tailnet, a.Provider = name, cctx.TailnetID, cctx.Credentials.Read
	sys := creds.System{
		Getenv: o.Getenv, ReadFile: o.ReadFile,
		ReadSecretFile: config.ReadSecretFile, HTTPClient: tokenHTTPClient(),
	}
	a.Env.Privacy, a.Env.PrivacyErr = creds.PrivacyKey(a.Provider, sys)
	cred, err := creds.Resolve(ctx, a.Provider, sys)
	if err != nil {
		return nil, err
	}
	a.Credential, a.CredKind, a.KeyID = cred.String(), cred.Kind, keyID(cred)
	o.API.ValidatePerMinute = a.Loaded.Config.ACL.ValidateRate()
	return api.New(ctx, cctx.TailnetID, cred, o.API)
}

// tokenHTTPClient is the client for OIDC token requests. Like every client
// tailkeeper builds, it never follows a redirect (spec §20).
func tokenHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// keyID returns the key record ID of a credential. An API access token has the
// form tskey-api-<id>-<secret>; only the ID segment is kept.
func keyID(c creds.Read) string {
	if c.Kind != creds.KindAPIKey {
		return c.ClientID
	}
	parts := strings.SplitN(c.APIKey.Reveal(), "-", 4)
	if len(parts) == 4 && parts[0] == "tskey" && parts[1] == "api" {
		return parts[2]
	}
	return ""
}

// readFields are the keys a read event may carry: tool, requester, size and
// outcome, never values (spec §14). Any other field a caller passes is dropped.
var readFields = map[string]bool{"tool": true, "tier": true, "requester": true, "ms": true, "status": true,
	"code": true, "bytes": true}

// Record appends a metadata-only read event unless audit.reads is "none". A read
// is never refused for want of an audit line (spec §14); the error is returned so
// the surface can warn once. Context and tailnet always come from the App, and a
// line the audit log refuses (it held a credential shape) is replaced by one that
// says so, so the read is still recorded.
func (a *App) Record(fields map[string]any) error {
	if a.AuditReads == "none" {
		return nil
	}
	if a.Audit == nil {
		return a.AuditErr
	}
	f := map[string]any{}
	for k, v := range fields {
		if !readFields[k] {
			continue
		}
		if k == "requester" {
			v = requesterValue(v)
		} else {
			v = auditValue(v)
		}
		if v != nil {
			f[k] = v
		}
	}
	f["context"], f["tailnet"] = a.Context, a.Tailnet
	if err := a.Audit.Append("read", f); err != nil {
		// The fallback answers a refused line (the tripwire, an oversize entry), not
		// an unavailable log: retrying that doubles the wait and, if the log comes
		// back, writes a stripped line instead of reporting the failure.
		if tkerr.From(err).Code == tkerr.AuditUnavailable {
			return err
		}
		fallback := map[string]any{"context": a.Context, "tailnet": a.Tailnet, "status": "line_withheld"}
		// The refused value may be the tool field itself, so it is kept only in the
		// shape of a registry name.
		if s, ok := f["tool"].(string); ok && toolName.MatchString(s) {
			fallback["tool"] = s
		}
		return a.Audit.Append("read", fallback)
	}
	return nil
}

var toolName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// auditValue keeps a string (escaped and capped), a number or a boolean for an
// audit line; anything else is dropped.
func auditValue(v any) any {
	switch x := v.(type) {
	case string:
		return sanitize.String(x, 256)
	case bool, int, int64, float64:
		return x
	}
	return nil
}

// requesterValue keeps the string kind and client of a requester; anything else is
// dropped.
func requesterValue(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]any{}
	for _, k := range []string{"kind", "client"} {
		if s, ok := m[k].(string); ok {
			out[k] = sanitize.String(s, 64)
		}
	}
	return out
}
