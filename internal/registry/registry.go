// Package registry is the single source of truth for tools (spec §5): metadata,
// input and output types, JSON Schemas, and the function that runs each tool. The
// CLI, the MCP server and the generated documentation are all built from it.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/local"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// Tier is a tool's base tier (spec §5).
type Tier string

const (
	TierRead           Tier = "read"
	TierLocal          Tier = "local"
	TierOffline        Tier = "offline"
	TierPrivilegedRead Tier = "privileged_read"
	TierReversible     Tier = "reversible"
	TierEscalation     Tier = "escalation"
	TierIrreversible   Tier = "irreversible"
)

// Stage is the documented release stage of the underlying Tailscale feature.
type Stage string

const (
	StageGA    Stage = "ga"
	StageBeta  Stage = "beta"
	StageAlpha Stage = "alpha"
)

// Credential is the credential class a tool uses (spec §7.1).
type Credential string

const (
	CredRead Credential = "read"
	CredNone Credential = "none"
	// CredOptional is for a read tool that can also run without a credential, for
	// example on two local files. The input type says when, through OfflineInput.
	CredOptional Credential = "optional"
)

// OptionalScope is an OAuth scope that enables one feature of a tool without being
// needed for the tool to run.
type OptionalScope struct {
	Scope  string `json:"scope"`
	Reason string `json:"reason"` // what the scope enables, in one line
}

// Meta is a tool's declared metadata.
type Meta struct {
	Name       string
	Area       string // CLI group, e.g. "devices"
	Verb       string // CLI command, e.g. "list"
	Summary    string
	Tier       Tier
	Stage      Stage
	PlanGate   string // documented plan gating; "" means all plans
	Credential Credential
	Scopes     []string // minimal OAuth scopes, companions included
	// PartialScopes means each scope reads part of the result (settings fields,
	// key types): a missing one narrows the result instead of failing the tool.
	PartialScopes bool
	// OptionalScopes each enable one feature of the tool and are not needed for it to
	// run: the tool tries the feature and, on scope_missing, leaves it out and says
	// so. They are never read from the granted list (stale for federated identities).
	OptionalScopes []OptionalScope
	// Title is the name a host shows for the tool. Optional, except for OpenWorld tools.
	Title string
	// OpenWorld marks a tool that sends text the caller supplied (a proposed policy,
	// a test) to Tailscale: MCP advertises openWorldHint true for it, and its
	// description says the input leaves the machine.
	OpenWorld bool
	Notes     string // extra facts for the docs, e.g. an unverified scope
	// Operations are the API operations the tool calls, as "METHOD /path" with the
	// path spelled as Tailscale's OpenAPI document spells it (spec §20).
	Operations []string
	// MaxResultChars raises the result size an MCP host keeps for this tool
	// (Claude Code's anthropic/maxResultSizeChars); 0 leaves the default, which
	// list tools raise to 200,000 characters.
	MaxResultChars int
}

// Env is everything a tool may use at run time.
type Env struct {
	API      *api.Client // nil when no credential is configured; APIErr says why
	APIErr   error
	Local    *local.Runner // nil when no tailscale CLI was found; LocalErr says why
	LocalErr error
	Config   *config.Loaded
	// Privacy names masked values and keys audit-log digests (spec §7.6); nil
	// when no key was provided, and PrivacyErr then says why if one was malformed.
	Privacy    *privacy.Key
	PrivacyErr error
	Now        func() time.Time
}

// ResultStringMax is the byte cap on one untrusted string in a result. Pseudonym
// filters read what a result still shows after the cap (UntrustedRefs), so the
// cap is applied and read here and nowhere else.
const ResultStringMax = sanitize.DefaultMax

// UntrustedRefs returns the pseudonyms a result shows for the untrusted string s,
// as the registry masks and caps it.
func (e *Env) UntrustedRefs(s string) []string {
	return e.Masker().TextRefs(s, ResultStringMax)
}

// Display rewrites ptr, which a tool owns, into what a result shows: masked
// unless the owner opted in, then escaped and capped. Mask comes before the cap:
// an address cut short by it would no longer parse and would keep its first
// octets. A tool that needs the bytes a caller will see (a sort key, say) runs it
// on a deep copy.
func (e *Env) Display(ptr any) {
	if !e.ShowPersonalData() {
		e.Masker().Mask(ptr)
	}
	sanitize.Fields(ptr, ResultStringMax)
}

// PersonalRefs returns the pseudonym a result shows for the personal field
// holding s (a login or a display name), as the registry masks and caps it.
func (e *Env) PersonalRefs(s string) []string {
	return e.Masker().IdentifierRefs(s, ResultStringMax)
}

// RequireAPI returns the API client or the reason it is unavailable.
func (e *Env) RequireAPI() (*api.Client, error) {
	if e.API != nil {
		return e.API, nil
	}
	if e.APIErr != nil {
		return nil, e.APIErr
	}
	return nil, tkerr.New(tkerr.CredentialUnavailable, "no read credential is configured", "run `tailkeeper doctor`")
}

// RequireLocal returns the local runner or the reason it is unavailable.
func (e *Env) RequireLocal() (*local.Runner, error) {
	if e.Local != nil {
		return e.Local, nil
	}
	if e.LocalErr != nil {
		return nil, e.LocalErr
	}
	return nil, tkerr.New(tkerr.LocalBinaryMissing, "no tailscale CLI found", "set local.tailscaleBinary")
}

// ShowPersonalData reports whether the owner opted in to unmasked personal data
// ("personalData": "show"). By default results are masked (spec Appendix C).
func (e *Env) ShowPersonalData() bool {
	return e != nil && e.Config != nil && e.Config.Config.PersonalData == config.PersonalDataShow
}

// Masker masks personal data, naming masked values when a privacy key is loaded.
func (e *Env) Masker() sanitize.Masker {
	if e == nil {
		return sanitize.Masker{}
	}
	return sanitize.NewMasker(e.Privacy)
}

// RequirePrivacy returns the privacy key, or why there is none.
func (e *Env) RequirePrivacy() (*privacy.Key, error) {
	switch {
	case e != nil && e.Privacy != nil:
		return e.Privacy, nil
	case e != nil && e.PrivacyErr != nil:
		return nil, e.PrivacyErr
	}
	return nil, tkerr.New(tkerr.PrivacyKeyUnavailable, "pseudonyms need the privacy key, and none was provided",
		"add "+privacy.EnvKey+" (64 hexadecimal characters) where the read credential is kept; `tailkeeper doctor` checks it")
}

// Clock returns the current time from Env.Now or time.Now.
func (e *Env) Clock() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Tool is a registered tool.
type Tool struct {
	Meta            Meta
	InputType       reflect.Type
	OutputType      reflect.Type
	InputSchema     *jsonschema.Schema
	OutputSchema    *jsonschema.Schema
	UntrustedFields []string // JSON paths of untrusted output fields
	PersonalFields  []string // JSON paths of identifiers masked whole unless personalData is "show"
	PlainFields     []string // JSON paths of untrusted fields kept unmasked (configuration such as routes)
	EmailFields     []string // JSON paths of untrusted fields whose email addresses alone are masked

	resolved *jsonschema.Resolved
	run      func(ctx context.Context, env *Env, in any) (any, error)
}

// Define builds a Tool from its metadata and a typed run function. Personal data
// is masked (unless the owner opted in) and untrusted output fields are sanitized
// in place after every run, so run must return values it owns, never shared or
// cached ones.
func Define[In, Out any](m Meta, run func(ctx context.Context, env *Env, in In) (Out, error)) Tool {
	in, err := jsonschema.For[In](nil)
	if err != nil {
		panic(fmt.Sprintf("tool %s: input schema: %v", m.Name, err))
	}
	out, err := jsonschema.For[Out](nil)
	if err != nil {
		panic(fmt.Sprintf("tool %s: output schema: %v", m.Name, err))
	}
	resolved, err := in.Resolve(nil)
	if err != nil {
		panic(fmt.Sprintf("tool %s: resolve input schema: %v", m.Name, err))
	}
	return Tool{
		Meta:            m,
		InputType:       reflect.TypeFor[In](),
		OutputType:      reflect.TypeFor[Out](),
		InputSchema:     in,
		OutputSchema:    out,
		UntrustedFields: sanitize.UntrustedPaths(reflect.TypeFor[Out]()),
		PersonalFields:  sanitize.PersonalPaths(reflect.TypeFor[Out]()),
		PlainFields:     sanitize.PlainPaths(reflect.TypeFor[Out]()),
		EmailFields:     sanitize.EmailPaths(reflect.TypeFor[Out]()),
		resolved:        resolved,
		run: func(ctx context.Context, env *Env, v any) (any, error) {
			res, err := run(ctx, env, v.(In))
			if err != nil {
				return nil, err
			}
			env.Display(&res)
			b, err := json.Marshal(res)
			if err != nil {
				return nil, tkerr.Wrap(tkerr.Internal, err, "cannot encode "+m.Name+" output", "")
			}
			if err := tripwire.Check(b); err != nil {
				return nil, err
			}
			return res, nil
		},
	}
}

// scrub gives an error what a result gets: an unclassified cause stays hidden
// (tkerr.From), the message and hint are sanitized like untrusted fields, and a
// credential shape in either withholds the whole error.
func scrub(err error, m Meta, env *Env) (clean error) {
	defer func() {
		// An error whose own methods panic (Unwrap, As) must not escape either.
		if recover() != nil {
			clean = tkerr.New(tkerr.Internal, "unexpected internal error in "+m.Name, "report this with `tailkeeper version` output")
		}
	}()
	fe := tkerr.From(err)
	if fe == nil {
		// A typed-nil *tkerr.Error is a non-nil error with nothing in it.
		fe = tkerr.New(tkerr.Internal, "unexpected internal error", "report this with `tailkeeper version` output")
	}
	e := *fe
	if e.Code == tkerr.ScopeMissing && len(m.Scopes) > 0 {
		// docs/design.md §19: name the scope, with companions. A scope that only enables a
		// feature is named apart, so it is not taken for one the tool cannot run without.
		e.Hint = "this tool reads with " + strings.Join(m.Scopes, ", ") + optionalHint(m.OptionalScopes) +
			"; grant the read credential the one it lacks, unless the feature is not on this plan"
	}
	if e.Hint == "" {
		// Every error tells a program what to do about it, whoever raised it.
		e.Hint = tkerr.ProgramHint(e.Code)
	}
	if !env.ShowPersonalData() {
		// Errors quote the API and the local CLI, which can name people and
		// addresses: they are free text like any untrusted field. They are masked
		// without pseudonyms, whatever key is loaded: an error echoes what the
		// caller typed, and a pseudonym beside an echoed guess would confirm it.
		e.Message, e.Hint = sanitize.MaskText(e.Message), sanitize.MaskText(e.Hint)
	}
	e.Message = sanitize.String(e.Message, sanitize.DefaultMax)
	e.Hint = sanitize.String(e.Hint, sanitize.DefaultMax)
	if hit := tripwire.Check([]byte(e.Message + "\n" + e.Hint)); hit != nil {
		return hit
	}
	return &e
}

// optionalHint lists optional scopes with their reasons, for the scope_missing hint.
func optionalHint(opt []OptionalScope) string {
	if len(opt) == 0 {
		return ""
	}
	parts := make([]string, len(opt))
	for i, o := range opt {
		parts[i] = o.Scope + " (" + o.Reason + ")"
	}
	return "; optional scopes, each enabling one feature: " + strings.Join(parts, ", ")
}

// secretNames and secretWords describe output field names that must never appear:
// they carry secrets or bearer capabilities in the Tailscale API (spec Appendix C).
// Tools omit them; this check catches an accidental inclusion. A name matches when,
// lowercased with '_' and '-' removed, it is in secretNames or contains a secretWords
// entry.
var secretNames = map[string]bool{"key": true, "authkey": true, "apikey": true, "inviteurl": true, "authurl": true}

var secretWords = []string{"secret", "token", "password", "credential", "privatekey"}

func secretName(name string) bool {
	n := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(name))
	if secretNames[n] {
		return true
	}
	for _, w := range secretWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)+$`)

var operationRE = regexp.MustCompile(`^(GET|POST) /[A-Za-z0-9/{}._-]+$`)

// Registry holds tools by name.
type Registry struct {
	tools map[string]Tool
	verbs map[string]string // "area verb" -> name
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{tools: map[string]Tool{}, verbs: map[string]string{}}
}

// Add validates a tool's metadata and registers it.
func (r *Registry) Add(t Tool) error {
	m := t.Meta
	switch {
	case t.run == nil:
		return fmt.Errorf("tool %q was not built with registry.Define", m.Name)
	case !nameRE.MatchString(m.Name):
		return fmt.Errorf("tool name %q must be area_verb in lower snake case", m.Name)
	case m.Area == "" || m.Verb == "" || m.Summary == "":
		return fmt.Errorf("tool %s: area, verb and summary are required", m.Name)
	case r.tools[m.Name].Meta.Name != "":
		return fmt.Errorf("tool %s registered twice", m.Name)
	case r.verbs[m.Area+" "+m.Verb] != "":
		return fmt.Errorf("tool %s: CLI command %q %q already used by %s", m.Name, m.Area, m.Verb, r.verbs[m.Area+" "+m.Verb])
	}
	if err := checkText(m); err != nil {
		return err
	}
	switch m.Stage {
	case StageGA, StageBeta, StageAlpha:
	default:
		return fmt.Errorf("tool %s: stage %q is not ga, beta or alpha", m.Name, m.Stage)
	}
	switch m.Tier {
	case TierRead:
		if (m.Credential != CredRead && m.Credential != CredOptional) || len(m.Scopes) == 0 {
			return fmt.Errorf("tool %s: read tools use the read credential (or an optional one) and declare scopes", m.Name)
		}
	case TierLocal, TierOffline:
		if m.Credential != CredNone || len(m.Scopes) != 0 {
			return fmt.Errorf("tool %s: local and offline tools use no credential", m.Name)
		}
	case TierPrivilegedRead, TierReversible, TierEscalation, TierIrreversible:
		// The approval gate arrives in milestone M2. Until then, nothing that writes
		// (or needs a write-level credential) can be registered.
		return fmt.Errorf("tool %s: tier %q needs the approval gate (milestone M2)", m.Name, m.Tier)
	default:
		return fmt.Errorf("tool %s: unknown tier %q", m.Name, m.Tier)
	}
	if (m.OpenWorld || len(m.OptionalScopes) > 0) && m.Tier != TierRead {
		return fmt.Errorf("tool %s: only API tools can be open-world or have optional scopes (only read tools use scopes)", m.Name)
	}
	if err := checkOptionalScopes(m); err != nil {
		return err
	}
	for _, op := range m.Operations {
		if !operationRE.MatchString(op) {
			return fmt.Errorf("tool %s: operation %q must be GET or POST and a path", m.Name, op)
		}
		if m.Tier != TierRead {
			return fmt.Errorf("tool %s: only API tools call operations", m.Name)
		}
	}
	if t.OutputType.Kind() != reflect.Struct {
		return fmt.Errorf("tool %s: output must be a struct", m.Name)
	}
	if bad := secretField(t.OutputType, map[reflect.Type]bool{}); bad != "" {
		return fmt.Errorf("tool %s: output field %q looks like a secret; tools must omit it", m.Name, bad)
	}
	r.tools[m.Name] = t
	r.verbs[m.Area+" "+m.Verb] = m.Name
	return nil
}

// maxTitle and maxReason bound the text a host shows and a hint repeats.
const (
	maxTitle  = 80
	maxReason = 200
)

var scopeRE = regexp.MustCompile(`^[A-Za-z0-9_:.-]+$`)

// checkText refuses a line break in the text that docs/tools.md writes verbatim
// as a heading and a list item, and an open-world tool without a title.
func checkText(m Meta) error {
	for _, f := range []struct{ name, v string }{{"summary", m.Summary}, {"notes", m.Notes}, {"title", m.Title}} {
		if strings.ContainsAny(f.v, "\r\n") {
			return fmt.Errorf("tool %s: %s must be one line", m.Name, f.name)
		}
	}
	if utf8.RuneCountInString(m.Title) > maxTitle {
		return fmt.Errorf("tool %s: title is longer than %d characters", m.Name, maxTitle)
	}
	if m.OpenWorld && m.Title == "" {
		return fmt.Errorf("tool %s: an open-world tool needs a title", m.Name)
	}
	return nil
}

// checkOptionalScopes refuses an optional scope that is empty, repeated, also
// required, or without a one-line reason.
func checkOptionalScopes(m Meta) error {
	seen := map[string]bool{}
	for _, o := range m.OptionalScopes {
		switch {
		case !scopeRE.MatchString(o.Scope):
			return fmt.Errorf("tool %s: an optional scope needs a scope name of letters, digits, '_', ':', '.' or '-'", m.Name)
		case o.Reason == "":
			return fmt.Errorf("tool %s: optional scope %s needs a reason", m.Name, o.Scope)
		case strings.ContainsAny(o.Reason, "\r\n"):
			return fmt.Errorf("tool %s: optional scope %s: the reason must be one line", m.Name, o.Scope)
		case utf8.RuneCountInString(o.Reason) > maxReason:
			return fmt.Errorf("tool %s: optional scope %s: the reason is longer than %d characters", m.Name, o.Scope, maxReason)
		case slices.Contains(m.Scopes, o.Scope):
			return fmt.Errorf("tool %s: optional scope %s is also required", m.Name, o.Scope)
		case seen[o.Scope]:
			return fmt.Errorf("tool %s: optional scope %s is listed twice", m.Name, o.Scope)
		}
		seen[o.Scope] = true
	}
	return nil
}

func secretField(t reflect.Type, seen map[reflect.Type]bool) string {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return ""
	}
	seen[t] = true
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" {
			name = f.Name
		}
		if secretName(name) {
			return name
		}
		if bad := secretField(f.Type, seen); bad != "" {
			return name + "." + bad
		}
	}
	return ""
}

// MustAdd is Add that panics, for static registration at startup.
func (r *Registry) MustAdd(tools ...Tool) {
	for _, t := range tools {
		if err := r.Add(t); err != nil {
			panic(err)
		}
	}
}

// Get returns a tool by name.
func (r *Registry) Get(name string) (Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// ByCommand returns the tool for a CLI area and verb.
func (r *Registry) ByCommand(area, verb string) (Tool, bool) {
	name, ok := r.verbs[area+" "+verb]
	if !ok {
		return Tool{}, false
	}
	return r.tools[name], true
}

// All returns every tool sorted by area then verb.
func (r *Registry) All() []Tool {
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Meta.Area != out[j].Meta.Area {
			return out[i].Meta.Area < out[j].Meta.Area
		}
		return out[i].Meta.Verb < out[j].Meta.Verb
	})
	return out
}

// Profile returns the tools an MCP profile advertises (spec §5.4). Profiles are a
// context-budget control on stdio, not a security boundary.
func (r *Registry) Profile(profile string, enableAlpha bool) ([]Tool, error) {
	switch profile {
	case "", "reads", "core", "full":
	default:
		return nil, tkerr.New(tkerr.Usage, "profile must be reads, core or full", "")
	}
	var out []Tool
	for _, t := range r.All() {
		if t.Meta.Stage == StageAlpha && !enableAlpha {
			continue
		}
		if profile == "" || profile == "reads" {
			if t.Meta.Tier != TierRead && t.Meta.Tier != TierLocal && t.Meta.Tier != TierOffline {
				continue
			}
		}
		out = append(out, t)
	}
	return out, nil
}

// ReadScopes returns the union of scopes of all read tools, sorted.
func (r *Registry) ReadScopes() []string {
	set := map[string]bool{}
	for _, t := range r.tools {
		if t.Meta.Tier == TierRead {
			for _, s := range t.Meta.Scopes {
				set[s] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
