// Package doctor verifies a deployment (spec §7.5). It never writes to the tailnet;
// its own reads are appended to the local audit log like any other.
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/audit"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// Status is a check outcome.
type Status string

const (
	OK   Status = "ok"
	Warn Status = "warn"
	Fail Status = "fail"
	NA   Status = "n/a"
	Info Status = "info"
)

// Check is one verified fact.
type Check struct {
	Name   string `json:"name" tk:"col"`
	Status Status `json:"status" tk:"col"`
	Detail string `json:"detail" tk:"col"`
	Hint   string `json:"hint,omitempty"`
}

// Report is the outcome of a doctor run.
type Report struct {
	Checks []Check `json:"checks" tk:"rows"`
	Failed int     `json:"failed"`
	Warned int     `json:"warned"`
}

func (r *Report) add(name string, s Status, detail, hint string) {
	r.Checks = append(r.Checks, Check{Name: name, Status: s, Detail: detail, Hint: hint})
	switch s {
	case Fail:
		r.Failed++
	case Warn:
		r.Warned++
	}
}

func (r *Report) addErr(name string, s Status, err error) {
	e := tkerr.From(err)
	r.add(name, s, string(e.Code)+": "+e.Message, e.Hint)
}

// addReadErr reports a check whose read failed: n/a only where the plan or the
// feature is missing, a failure when the credential was rejected, a warning
// otherwise. A scope_missing hint already names the tool's scopes.
func (r *Report) addReadErr(name string, err error) {
	e := tkerr.From(err)
	s := Warn
	switch e.Code {
	case tkerr.PaymentRequired, tkerr.FeatureUnavailable:
		s = NA
	case tkerr.TokenRejected:
		s = Fail
	}
	r.add(name, s, string(e.Code)+": "+e.Message, e.Hint)
}

// skipped lists checks that could not run, so a missing check never reads as a
// passing one.
func (r *Report) skipped(reason string, names ...string) {
	for _, n := range names {
		r.add(n, NA, "skipped: "+reason, "")
	}
}

// Err is non-nil when any check failed; its exit code is 8 (findings).
func (r Report) Err() error {
	if r.Failed == 0 {
		return nil
	}
	return tkerr.New(tkerr.FindingsPresent, fmt.Sprintf("doctor found %d failing check(s)", r.Failed), "")
}

// Input is what doctor inspects. App is nil when app.Build failed with BuildErr.
type Input struct {
	App      *app.App
	BuildErr error
	Probe    bool
	Now      time.Time
}

// Run performs every check. It never writes to the tailnet.
func Run(ctx context.Context, in Input) Report {
	r := run(ctx, in)
	// Escape each check, then apply the tripwire (spec §7.6): a configuration error
	// can quote the file, so a check holding a credential shape loses its text, not
	// the report, and --json prints what the table prints. Escaping is idempotent
	// and uncapped here (max 0); the table and fix lines escape again and cap at
	// 1 KiB.
	for i := range r.Checks {
		c := &r.Checks[i]
		c.Detail, c.Hint = sanitize.String(c.Detail, 0), sanitize.String(c.Hint, 0)
		if hit := tripwire.Check([]byte(c.Detail + "\n" + c.Hint)); hit != nil {
			c.Detail, c.Hint = tkerr.From(hit).Message, ""
		}
	}
	return r
}

func run(ctx context.Context, in Input) Report {
	var r Report
	if in.BuildErr != nil {
		r.addErr("configuration", Fail, in.BuildErr)
		return r
	}
	a := in.App
	rl := &readLog{}
	ctx = context.WithValue(ctx, readLogKey{}, rl)
	if a.Loaded == nil {
		r.addErr("configuration", Fail, a.Env.APIErr)
		r.skipped("no configuration", credentialCheckNames(in)...)
		r.skipped("no configuration", "privacy key")
	} else {
		if strictModeEnforced {
			r.add("configuration", OK, fmt.Sprintf("%s configuration %s; strict-mode ownership and permissions verified", a.Loaded.Source, a.Loaded.Path), "")
		} else {
			r.add("configuration", Warn, fmt.Sprintf("%s configuration %s; strict mode is not enforced on this platform: ownership and permissions were not checked", a.Loaded.Source, a.Loaded.Path),
				"keep the configuration and credential files writable only by you")
		}
		if a.Loaded.IgnoredUserConfig {
			r.add("user configuration", Warn, "a user configuration exists but the system configuration is the only one used", "remove it to avoid confusion")
		}
		if a.Loaded.Source == config.SourceUser {
			// Spec §15: in personal mode doctor says so.
			r.add("personal mode", Info, "every process you run can write the user configuration directory, so this configuration is only as protected as your agent's sandbox makes it",
				"deny your agent's shell write access to "+filepath.Dir(a.Loaded.Path))
		}
		credentialChecks(ctx, &r, a, in)
		privacyCheck(&r, a)
	}
	localChecks(ctx, &r, a)
	auditChecks(&r, a, rl.err)
	return r
}

// privacyCheck reports the privacy key (spec §7.6). It never shows key material.
func privacyCheck(r *Report, a *app.App) {
	const name = "privacy key"
	switch {
	case a.Env.PrivacyErr != nil:
		r.addErr(name, Fail, a.Env.PrivacyErr)
	case a.Env.ShowPersonalData():
		r.add(name, Info, "personal data is shown whole (personalData: show); the privacy key is not used", "")
	case a.Provider.Provider == "oidc":
		r.add(name, Info, "oidc stores no secret, so there is no privacy key; masked values carry no pseudonym, filters cannot name a masked value, and audit_log leaves out its digests", "")
	case a.Env.Privacy != nil:
		r.add(name, OK, "loaded: masked values carry pseudonyms, and audit_log digests are keyed", "")
	default:
		r.add(name, Warn, "none: masked values carry no pseudonym, filters cannot name a masked value, and audit_log leaves out its digests",
			"add "+privacy.EnvKey+" (generate it with openssl rand -hex 32) where the read credential is kept")
	}
}

// strictModeEnforced is config.StrictModeEnforced; tests flip it to cover the
// platforms where strict mode is not enforced.
var strictModeEnforced = config.StrictModeEnforced

// credentialCheckNames are the checks credentialChecks reports.
func credentialCheckNames(in Input) []string {
	names := []string{"read credential", "key record", "scopes", "security contact", "gitops lock"}
	if in.Probe {
		for _, p := range probeList {
			names = append(names, "probe "+p.tool)
		}
		names = append(names, "probe acl_test")
	}
	return names
}

// readLog keeps the first failure to record one of doctor's own reads, for the
// audit-log check. After it doctor stops recording: each attempt could wait out a
// held lock again. It travels in the context because Report, which the CLI
// renders field by field, must not carry it.
type readLog struct{ err error }

type readLogKey struct{}

func call(ctx context.Context, a *app.App, name, args string, out any) error {
	t, ok := a.Registry.Get(name)
	if !ok {
		return tkerr.New(tkerr.Internal, "tool "+name+" is not registered", "")
	}
	start := time.Now()
	res, err := t.Call(ctx, a.Env, json.RawMessage(args))
	var b []byte
	if err == nil {
		b, err = json.Marshal(res)
	}
	f := map[string]any{"tool": name, "tier": string(t.Meta.Tier), "requester": map[string]any{"kind": "doctor"},
		"ms": time.Since(start).Milliseconds(), "status": "ok", "bytes": len(b)}
	if err != nil {
		f["status"], f["code"] = "error", string(tkerr.From(err).Code)
	}
	if rl, _ := ctx.Value(readLogKey{}).(*readLog); rl == nil {
		_ = a.Record(f)
	} else if rl.err == nil {
		rl.err = a.Record(f)
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func credentialChecks(ctx context.Context, r *Report, a *app.App, in Input) {
	if a.Env.APIErr != nil {
		r.addErr("read credential", Fail, a.Env.APIErr)
		r.skipped("no read credential", credentialCheckNames(in)[1:]...)
		return
	}
	// Only the start of the tailnet ID: agents that run doctor copy its output
	// into their transcripts.
	r.add("read credential", OK, fmt.Sprintf("%s; context %s, tailnet %s", a.Credential, a.Context, sanitize.MaskID(a.Tailnet)), "")
	if a.CredKind == creds.KindAPIKey {
		r.add("credential type", Warn, "an API access token carries its owner's full permissions",
			"use an OAuth client (or federated identity) holding read scopes only")
	}

	// The key record also proves the credential belongs to the configured tailnet:
	// it is fetched under that tailnet's path.
	var key tools.Key
	keyArgs, _ := json.Marshal(map[string]string{"id": a.KeyID})
	if a.KeyID == "" {
		r.add("key record", NA, "the credential's key ID is unknown", "")
	} else if err := call(ctx, a, "key_get", string(keyArgs), &key); err != nil {
		e := tkerr.From(err)
		hint := e.Hint
		if e.Code == tkerr.NotFound || e.Code == tkerr.ScopeMissing {
			hint = "check that tailnetId " + sanitize.MaskID(a.Tailnet) + " is the tailnet this credential belongs to"
		}
		r.add("key record", Fail, string(e.Code)+": "+e.Message, hint)
	} else {
		keyRecord(r, key, in.Now)
	}

	var contacts tools.ContactsOutput
	if err := call(ctx, a, "contacts_get", `{}`, &contacts); err != nil {
		r.addReadErr("security contact", err)
	} else if !contacts.SecurityContactOK {
		r.add("security contact", Warn, "no verified security contact",
			"set one in the admin console: Tailscale emails it when secret scanning revokes a leaked key")
	} else {
		r.add("security contact", OK, "set and verified", "")
	}

	var settings tools.SettingsOutput
	if err := call(ctx, a, "settings_get", `{}`, &settings); err != nil {
		r.addReadErr("gitops lock", err)
	} else if settings.ExternallyManaged == "true" {
		r.add("gitops lock", Info, "the policy file is managed externally; tailkeeper ACL writes will refuse", "")
	} else {
		r.add("gitops lock", Info, "aclsExternallyManagedOn is "+settings.ExternallyManaged, "")
	}
	// After the reads above, the token response (and so its scope list) is known.
	scopeChecks(r, a, key.Scopes)

	if in.Probe {
		probes(ctx, r, a)
	}
}

func keyRecord(r *Report, k tools.Key, now time.Time) {
	switch {
	case k.Invalid:
		r.add("key record", Fail, "the key is marked invalid", "create a new credential")
	case k.Revoked != "":
		r.add("key record", Fail, "the key was revoked at "+sanitize.String(k.Revoked, 64), "create a new credential")
	default:
		detail := "type " + sanitize.String(k.KeyType, 64)
		if k.Expires != "" {
			detail += ", expires " + sanitize.String(k.Expires, 64)
			t, err := time.Parse(time.RFC3339, k.Expires)
			switch {
			case err != nil:
				r.add("key record", Warn, detail, "the expiry date cannot be read; check the key in the admin console")
				return
			case !t.After(now):
				r.add("key record", Fail, detail, "the key has expired: create a new credential")
				return
			case t.Sub(now) < 7*24*time.Hour:
				r.add("key record", Warn, detail, "rotate the credential before it expires")
				return
			}
		}
		r.add("key record", OK, detail, "")
	}
}

// covers reports whether a granted scope satisfies a needed read scope.
func covers(granted []string, need string) bool {
	base := strings.TrimSuffix(need, ":read")
	for _, g := range granted {
		if g == need || g == base || g == "all" || g == "all:read" {
			return true
		}
	}
	return false
}

func scopeChecks(r *Report, a *app.App, keyScopes []string) {
	granted, _ := a.Env.API.GrantedScopes()
	// The key record lists the scopes too, which covers credentials whose token
	// response names none (federated identities).
	for _, k := range keyScopes {
		if !slices.Contains(granted, k) {
			granted = append(granted, k)
		}
	}
	if len(granted) == 0 {
		r.add("scopes", NA, "neither the token response nor the key record lists scopes", "")
		return
	}
	var writes []string
	for _, g := range granted {
		if g != "all:read" && !strings.HasSuffix(g, ":read") {
			writes = append(writes, g)
		}
	}
	if len(writes) > 0 {
		r.add("scopes", Fail, "the read credential holds write scopes: "+strings.Join(writes, ", "),
			"create an OAuth client with read scopes only (README.md, Configure)")
	}
	if slices.Contains(granted, "all:read") {
		r.add("scope breadth", Warn, "all:read also covers endpoints Tailscale adds later", "prefer the individual read scopes")
	}
	// Alpha tools are advertised only on request, so their scopes are not needed by
	// default. A tool with PartialScopes reads what its granted scopes cover and
	// fails only when none is granted.
	need, partial, alphaNeed := map[string][]string{}, map[string][]string{}, map[string][]string{}
	for _, t := range a.Registry.All() {
		if t.Meta.Tier != registry.TierRead {
			continue
		}
		into := need
		switch {
		case t.Meta.Stage == registry.StageAlpha:
			into = alphaNeed
		case t.Meta.PartialScopes && slices.ContainsFunc(t.Meta.Scopes, func(sc string) bool { return covers(granted, sc) }):
			into = partial
		}
		for _, sc := range t.Meta.Scopes {
			into[sc] = append(into[sc], t.Meta.Name)
		}
	}
	for sc := range need {
		delete(alphaNeed, sc)
	}
	if missing, affected := uncovered(granted, need); len(missing) > 0 {
		r.add("scopes", Warn, "missing "+strings.Join(missing, ", ")+"; these tools will fail with scope_missing: "+strings.Join(affected, ", "), "")
	} else if len(writes) == 0 {
		r.add("scopes", OK, fmt.Sprintf("%d granted; every read tool can run", len(granted)), "")
	}
	if missing, affected := uncovered(granted, partial); len(missing) > 0 {
		r.add("partial scopes", Info, "missing "+strings.Join(missing, ", ")+"; these tools return only what the granted scopes cover: "+strings.Join(affected, ", "),
			"grant a scope only if you need what it shows")
	}
	if missing, affected := uncovered(granted, alphaNeed); len(missing) > 0 {
		r.add("alpha scopes", Info, "missing "+strings.Join(missing, ", ")+" for the alpha tools "+strings.Join(affected, ", "),
			"needed only with --enable-alpha")
	}
}

// uncovered returns, sorted, the scopes in need that granted does not cover and
// the tools that need them.
func uncovered(granted []string, need map[string][]string) (missing, tools []string) {
	for sc, names := range need {
		if covers(granted, sc) {
			continue
		}
		missing = append(missing, sc)
		for _, n := range names {
			if !slices.Contains(tools, n) {
				tools = append(tools, n)
			}
		}
	}
	slices.Sort(missing)
	slices.Sort(tools)
	return missing, tools
}

// probeList are the tools whose scope or availability is unverified (spec §26).
var probeList = []struct{ tool, args string }{
	{"dns_get", `{}`},
	{"user_invites_list", `{}`},
	{"log_streaming_get", `{"logType":"configuration"}`},
	{"network_flow_logs", `{"maxRecords":1}`},
	{"acl_get", `{"maxBytes":4194304}`}, // the largest page: a minified policy is one long line
}

// aclCanary is a test no policy can pass: the same destination both accepted and
// denied. acl_test reads a pass from the absence of errors, so this proves that a
// failure is read as one, and that the read credential may run tests.
const aclCanary = `{"src":"tag:tailkeeper-canary","accept":["tag:tailkeeper-canary:1"],"deny":["tag:tailkeeper-canary:1"]}`

// probes call each tool of probeList. A tool that answered without reaching its
// endpoint (not enabled, not configured) proves nothing about the scope it needs.
func probes(ctx context.Context, r *Report, a *app.App) {
	for _, p := range probeList {
		var out map[string]any
		name := "probe " + p.tool
		if err := call(ctx, a, p.tool, p.args, &out); err != nil {
			r.addReadErr(name, err)
			continue
		}
		switch st, _ := out["status"].(string); st {
		case "not_enabled", "not_configured", "not_available":
			r.add(name, NA, st+": the endpoint was not exercised", "")
		default:
			r.add(name, OK, "readable", "")
		}
	}
	var t tools.ACLTestOutput
	err := call(ctx, a, "acl_test", aclCanary, &t)
	if st, detail, fix, ok := canaryVerdict(t, err); ok {
		r.add("probe acl_test", st, detail, fix)
	} else {
		r.addReadErr("probe acl_test", err)
	}
}

// canaryVerdict reads acl_test's answer to aclCanary. Only a failure carrying
// errors proves that a failure is read as one; ok is false for an error doctor
// reports like any other failed read.
func canaryVerdict(t tools.ACLTestOutput, err error) (st Status, detail, fix string, ok bool) {
	const known = "run `tailkeeper acl test` on a source and destination you know"
	if err == nil {
		switch {
		case t.Status != "pass":
			return OK, "a test that cannot pass is read as failed", "", true
		case len(t.Warnings) > 0:
			return Warn, "the canary test was not evaluated; the endpoint answered with warnings only", known, true
		}
		return Fail, "a test that no policy can pass came back as passed: tailkeeper misreads the validate response, so no acl_test result can be trusted",
			"report this with `tailkeeper version`", true
	}
	switch e := tkerr.From(err); {
	case e.Code == tkerr.ValidationFailed && e.Status == 0:
		return Fail, "tailkeeper refused its own canary test before sending it: " + e.Message, "report this with `tailkeeper version`", true
	case e.Code == tkerr.ValidationFailed:
		return Warn, "the validate endpoint refused the canary test, so how a failure is read was not exercised", known, true
	}
	return "", "", "", false
}

func localChecks(ctx context.Context, r *Report, a *app.App) {
	if a.Env.LocalErr != nil {
		r.addErr("local tailscale", Warn, a.Env.LocalErr)
		return
	}
	var v tools.VersionOutput
	if err := call(ctx, a, "local_version", `{}`, &v); err != nil {
		r.addErr("local tailscale", Warn, err)
		return
	}
	daemon := v.Daemon
	if daemon == "" {
		daemon = "unknown"
	}
	detail := fmt.Sprintf("%s (%s): CLI %s, daemon %s", a.Env.Local.Bin.Path, a.Env.Local.Bin.Variant, v.CLI, daemon)
	if v.Daemon == "" {
		r.add("local tailscale", Warn, detail, "the daemon did not report its version, so CLI and daemon skew was not checked")
		return
	}
	if v.Skew {
		r.add("local tailscale", Warn, detail, "CLI and daemon versions differ; update one of them")
		return
	}
	r.add("local tailscale", OK, detail, "")
}

// rotateAt is the audit log size at which doctor suggests a rotation. A read
// writes a line of a few hundred bytes, so 64 MiB is some 200,000 reads.
var rotateAt int64 = 64 << 20

// auditChecks reports the log's state; recordErr is the first failure to record
// one of doctor's own reads.
func auditChecks(r *Report, a *app.App, recordErr error) {
	if a.AuditErr != nil {
		r.addErr("audit log", Fail, a.AuditErr)
		return
	}
	n, err := audit.Verify(a.Audit.Path())
	if err != nil {
		r.addErr("audit log", Fail, err)
		return
	}
	if recordErr != nil {
		e := tkerr.From(recordErr)
		r.add("audit log", Warn, fmt.Sprintf("%s: %d lines, chain intact, but doctor's own reads were not recorded: %s", a.Audit.Path(), n, e.Message), e.Hint)
	} else {
		r.add("audit log", OK, fmt.Sprintf("%s: %d lines, chain intact; reads recorded as %s", a.Audit.Path(), n, a.AuditReads), "")
	}
	if fi, err := os.Stat(a.Audit.Path()); err == nil && fi.Size() >= rotateAt {
		hint := "`tailkeeper audit rotate` starts a new log and keeps this one beside it as an archive"
		if !audit.RotateSupported() {
			hint = "stop every tailkeeper process, then move the log aside; the next run starts a new one"
		}
		r.add("audit log size", Warn, fmt.Sprintf("%s is %d MiB; nothing is ever deleted from it", a.Audit.Path(), fi.Size()>>20), hint)
	}
	r.add("audit protection", Info, "plain SHA-256 chain: it detects damage and naive edits, not a writer who recomputes it",
		"HMAC keys and exports arrive with hardened mode")
}
