// Package app wires configuration, the read credential, the API client, the local
// runner and the audit log into one registry.Env for the CLI and the MCP server.
package app

import (
	"bytes"
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
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// Options configures Build. Zero values use the real system.
type Options struct {
	Context        string                            // --context flag value
	NoCredential   bool                              // load no read credential or credential file
	ReadSecretFile func(string) ([]byte, error)      // default config.ReadSecretFile
	Getenv         func(string) string               // default os.Getenv
	Dirs           *config.Dirs                      // default config.DefaultDirs()
	Check          config.Checker                    // default config.CheckOwnership
	Stat           func(string) (fs.FileInfo, error) // default os.Stat, for finding the CLI
	API            api.Options                       // BaseURL and retry settings (tests)
	Now            func() time.Time                  // default time.Now
	// LookupEnv says whether a variable is set at all. It is os.LookupEnv when Getenv is the
	// default; with a Getenv of its own and no LookupEnv, a variable set to nothing reads as
	// not set.
	LookupEnv func(string) (string, bool)
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
	// PrivacyNote says, in words that hold no value, why a privacy key that looks set did
	// not load though nothing failed (creds.LoadPrivacyKey); empty when the key loaded,
	// failed or was never set. PrivacyNotice turns it into the warning.
	PrivacyNote string
}

// NoPrivacyKey is what a missing privacy key costs, in the words `doctor` and the start-up
// warnings share.
const NoPrivacyKey = "masked values carry no pseudonym, filters cannot name a masked value, and audit_log leaves out its digests"

// PrivacyState is what the privacy key amounts to for an App (spec §7.6).
type PrivacyState int

const (
	// PrivacyFailed: a key is set and malformed or unreadable (Env.PrivacyErr says why).
	PrivacyFailed PrivacyState = iota
	// PrivacyUnused: personalData is "show", so no value is masked and no key is used.
	PrivacyUnused
	// PrivacyNotStored: the oidc provider stores no secret, so it has no key.
	PrivacyNotStored
	// PrivacyLoaded: masked values carry pseudonyms and audit_log digests are keyed.
	PrivacyLoaded
	// PrivacyNone: no key loaded and nothing failed. Masking goes on without pseudonyms.
	PrivacyNone
)

// PrivacyState is the one condition `doctor` reports for the privacy key and the start-up
// warnings use.
func (a *App) PrivacyState() PrivacyState {
	switch {
	case a.Env.PrivacyErr != nil:
		return PrivacyFailed
	case a.Env.ShowPersonalData():
		return PrivacyUnused
	case a.Env.Privacy != nil:
		return PrivacyLoaded
	case a.Provider.Provider == "oidc":
		return PrivacyNotStored
	}
	return PrivacyNone
}

// PrivacyNotice is the warning for a privacy key that is set and failed (malformed or
// unreadable) or that looks set and did not load, or "" (a key that is simply absent is a
// choice). Nothing in a result would say it, so the surfaces do: standard error, once at MCP
// start and before each CLI tool call. It names an error code, a variable or a line number,
// never a value; the error's own message is escaped.
func (a *App) PrivacyNotice() string {
	if a == nil || a.Env == nil {
		return ""
	}
	switch a.PrivacyState() {
	case PrivacyFailed:
		fe := tkerr.From(a.Env.PrivacyErr)
		if fe == nil {
			fe = tkerr.New(tkerr.PrivacyKeyUnavailable, "the privacy key could not be read", "")
		}
		return "tailkeeper: the privacy key is malformed or unreadable (" + string(fe.Code) + "): " + a.failedKeyCost() + ": " + sanitize.String(fe.Message, sanitize.DefaultMax)
	case PrivacyNone:
		if a.PrivacyNote != "" {
			return "tailkeeper: warning: no privacy key was loaded (" + a.PrivacyNote + "): " + NoPrivacyKey + "; `tailkeeper doctor` checks it"
		}
	}
	return ""
}

// failedKeyCost says what a privacy key that failed costs in the masking mode in force. With
// masking on, results are masked without pseudonyms and audit_log has no keyed digest to give,
// so it leaves them out. With personalData "show" nothing is masked and no key is used, and
// audit_log digests are plain SHA-256 values: saying that results are masked, or that digests
// are left out, would be untrue.
func (a *App) failedKeyCost() string {
	if a.Env.ShowPersonalData() {
		return `personalData is "show", so results are not masked, the key is not used and audit_log digests are plain SHA-256 values`
	}
	return "results are masked without pseudonyms and audit_log leaves out digests"
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
		if o.LookupEnv == nil {
			o.LookupEnv = os.LookupEnv
		}
	}
	if o.Check == nil {
		o.Check = config.CheckOwnership
	}
	if o.Stat == nil {
		o.Stat = os.Stat
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
	a.Env = &registry.Env{Now: o.Now, RecordObservation: a.RecordObservation, RecordPack: a.RecordPack}

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
	if o.NoCredential {
		if raw := o.Getenv(privacy.EnvKey); raw != "" {
			a.Env.Privacy, a.Env.PrivacyErr = privacy.Parse(raw)
		}
		return nil, tkerr.New(tkerr.CredentialUnavailable, "this command loads no credential", "")
	}
	reader := o.ReadSecretFile
	if reader == nil {
		reader = config.ReadSecretFile
	}
	if a.Provider.Provider == "file" {
		reader = providerSnapshot(a.Provider.Path, reader)
	}
	sys := creds.System{
		Getenv: o.Getenv, LookupEnv: o.LookupEnv,
		ReadSecretFile: reader, HTTPClient: tokenHTTPClient(),
	}
	a.Env.Privacy, a.PrivacyNote, a.Env.PrivacyErr = creds.LoadPrivacyKey(a.Provider, sys)
	cred, err := creds.Resolve(ctx, a.Provider, sys)
	if err != nil {
		return nil, err
	}
	a.Credential, a.CredKind, a.KeyID = cred.String(), cred.Kind, keyID(cred)
	o.API.ValidatePerMinute = a.Loaded.Config.ACL.ValidateRate()
	return api.New(ctx, cctx.TailnetID, cred, o.API)
}

// providerSnapshot keeps the provider file's single checked read for this build.
// Both parsers see the same bytes; other paths and later builds read afresh.
func providerSnapshot(path string, read func(string) ([]byte, error)) func(string) ([]byte, error) {
	var data []byte
	var err error
	readOnce := false
	return func(name string) ([]byte, error) {
		if name != path {
			return read(name)
		}
		if !readOnce {
			data, err = read(name)
			readOnce = true
		}
		return bytes.Clone(data), err
	}
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

// readFields are the keys a read event may carry: tool, requester, call identifier, size and
// outcome, never values (spec §14). Any other field a caller passes is dropped. The last line is
// what the owner's security explanation adds (registry.Audited): where its intent came from, the
// start of the intent's digest, and counts, nothing of the intent or the policy.
var readFields = map[string]bool{"tool": true, "tier": true, "requester": true, "ms": true, "status": true,
	"code": true, "bytes": true, "call": true,
	"intent": true, "digest": true, "expectations": true, "met": true, "unmet": true, "unknown": true, "limited": true, "not_evaluated": true,
	"pack": true, "seal": true, "outcome": true, "findings": true, "devices": true, "fixed": true, "not_fixed": true, "incomplete": true, "regressed": true}

// The keys of an explanation's audit fields are shape-gated like "call": a value that is not of
// its key's shape is dropped, so that none of them can carry text from the tailnet or the policy.
// The intent comes from one of three closed words, its digest is the twelve hexadecimal digits the
// digest rule shows (the key is absent when there is none), and the six counts are whole numbers
// that are not negative.
var (
	intentWords      = map[string]bool{"configured": true, "cli": true, "none": true}
	digestPrefix     = regexp.MustCompile(`^[0-9a-f]{12}$`)
	explanationCount = map[string]bool{"expectations": true, "met": true, "unmet": true, "unknown": true, "limited": true, "not_evaluated": true,
		"bytes": true, "findings": true, "devices": true, "fixed": true, "not_fixed": true, "incomplete": true, "regressed": true}
	packWords    = map[string]bool{"export": true, "replay": true, "redact": true, "verify": true}
	sealWords    = map[string]bool{"keyed": true, "absent": true, "not_checked": true, "absent_key_loaded": true}
	outcomeWords = map[string]bool{"reproduced": true, "not_reproduced": true, "refused": true, "fixed": true, "not_fixed": true, "incomplete": true}
)

// maxExplanationCount bounds a count of an explanation: more than that is not a count of its
// expectations.
const maxExplanationCount = 1 << 31

// countValue is v as a count, or nil: a whole number from 0 to maxExplanationCount, as an
// integer or as the number a JSON decoder gives. A bool or a string is none.
func countValue(v any) any {
	var n float64
	switch x := v.(type) {
	case int:
		n = float64(x)
	case int64:
		n = float64(x)
	case float64:
		n = x
	default:
		return nil
	}
	if n < 0 || n > maxExplanationCount || n != float64(int64(n)) {
		return nil
	}
	return v
}

// readFieldValue is the value a read line keeps for a key, or nil when it keeps none.
func readFieldValue(k string, v any) any {
	switch s, isString := v.(string); {
	case k == "requester":
		return requesterValue(v)
	case k == "call":
		if isString && callIDShape.MatchString(s) {
			return s
		}
		return nil
	case k == "intent":
		if isString && intentWords[s] {
			return s
		}
		return nil
	case k == "pack" || k == "seal" || k == "outcome":
		return packWordValue(k, v)
	case k == "digest":
		if isString && digestPrefix.MatchString(s) {
			return s
		}
		return nil
	case explanationCount[k]:
		return countValue(v)
	}
	return auditValue(v)
}

func packWordValue(k string, v any) any {
	words := map[string]map[string]bool{"pack": packWords, "seal": sealWords, "outcome": outcomeWords}
	if s, ok := v.(string); ok && words[k][s] {
		return s
	}
	return nil
}

// callIDShape is the identifier the framework gives a call (registry.Call.ID): 16 lowercase
// hexadecimal digits. A read line keeps a "call" of that shape and drops anything else, so the
// field can only ever be joined to the collect lines of that call, never carry text.
var callIDShape = regexp.MustCompile(`^[0-9a-f]{16}$`)

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
		if v = readFieldValue(k, v); v != nil {
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

// RecordObservation is the required audit record of one source a security collection reads
// (registry.Env.RecordObservation). Unlike Record, it does not drop an event it cannot
// write: it returns an error for audit.reads "none", for a log that is not open, and for a
// line the log refuses, because a collection whose records are missing must not be taken for
// a complete one. The event is closed (security.CollectionEvent.Validate) and holds no text
// of a source. The tool, the call and the requester come from the context the framework set
// (registry.CallOf), never from the event or the tool's input.
func (a *App) RecordObservation(ctx context.Context, ev security.CollectionEvent) error {
	if err := ev.Validate(); err != nil {
		return tkerr.Wrap(tkerr.Internal, err, "a security collection made an event the audit log does not take", "this is a tailkeeper bug; report it")
	}
	if a.AuditReads == "none" {
		return tkerr.New(tkerr.ConfigInvalid, `the security assessment records every source it reads in the audit log, and audit.reads is "none"`,
			`set audit.reads to "metadata" (the default) in the configuration, or remove the setting`)
	}
	if a.Audit == nil {
		if a.AuditErr != nil {
			return a.AuditErr
		}
		return tkerr.New(tkerr.AuditUnavailable, "the audit log is not open, so the security assessment cannot record its sources", "run `tailkeeper doctor`")
	}
	f := map[string]any{
		"context": a.Context, "tailnet": a.Tailnet, "scope": string(ev.Scope), "source": string(ev.Source), "phase": string(ev.Phase),
	}
	if ev.Phase == security.PhaseOutcome {
		f["outcome"], f["observed"], f["dropped"], f["ms"] = string(ev.Outcome), ev.Observed, ev.Dropped, ev.Millis
		if ev.Code != "" {
			f["code"] = ev.Code
		}
	}
	if c := registry.CallOf(ctx); c.Tool != "" {
		f["tool"], f["parent"] = c.Tool, c.ID
		f["requester"] = requesterValue(map[string]any{"kind": c.Caller.Kind, "client": c.Caller.Client})
	}
	return a.Audit.Append("collect", f)
}

// RecordPack appends required, closed metadata about a pack operation. Identity is
// supplied by the registry call context, never by the fields.
func (a *App) RecordPack(ctx context.Context, record registry.PackRecord) error {
	f, err := packRecordFields(record)
	if err != nil {
		return err
	}
	if a.AuditReads == "none" {
		return tkerr.New(tkerr.ConfigInvalid, `the pack operation requires audit.reads "metadata"`, `set audit.reads to "metadata" in the configuration`)
	}
	if a.Audit == nil {
		if a.AuditErr != nil {
			return a.AuditErr
		}
		return tkerr.New(tkerr.AuditUnavailable, "the audit log is not open, so the pack operation cannot be recorded", "run `tailkeeper doctor`")
	}
	f["context"], f["tailnet"] = a.Context, a.Tailnet
	if c := registry.CallOf(ctx); c.Tool != "" {
		f["tool"], f["parent"] = c.Tool, c.ID
		f["requester"] = requesterValue(map[string]any{"kind": c.Caller.Kind, "client": c.Caller.Client})
	}
	return a.Audit.Append("pack", f)
}

// packRecordFields is the bridge to the existing generic audit log. Every field
// is checked before anything reaches it.
func packRecordFields(record registry.PackRecord) (map[string]any, error) {
	f := map[string]any{"pack": record.Pack}
	words := map[string]string{"seal": record.Seal, "outcome": record.Outcome, "digest": record.Digest}
	for k, v := range words {
		if v != "" {
			f[k] = v
		}
	}
	counts := map[string]*int64{"bytes": record.Bytes, "findings": record.Findings, "devices": record.Devices,
		"fixed": record.Fixed, "not_fixed": record.NotFixed, "incomplete": record.Incomplete, "regressed": record.Regressed}
	for k, v := range counts {
		if v != nil {
			f[k] = *v
		}
	}
	for k, v := range f {
		if readFieldValue(k, v) == nil {
			return nil, tkerr.New(tkerr.Internal, "a pack event has invalid metadata", "this is a tailkeeper bug; report it")
		}
	}
	return f, nil
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
