package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// acl_validate asks Tailscale whether a policy is valid: the proposal the caller gives, or,
// with none, the live policy. The text is sent to POST .../acl/validate, which Tailscale
// documents as never changing the policy. This file is the tool's input and output, the
// checks that need no request, and the human report; acl_validate_online.go is the part
// that talks to Tailscale.

// The statuses of an ACLValidateOutput, and the exit code of each (ExitCode).
const (
	statusPass       = "pass"       // 0
	statusFail       = "fail"       // 9: a test of the policy or of the invariants failed
	statusInvalid    = "invalid"    // 2: the text is not a policy, found before anything was sent
	statusRejected   = "rejected"   // 2: Tailscale refused the text, or the live policy has stored errors
	statusUnresolved = "unresolved" // 2: a test names something Tailscale cannot resolve
	statusUnknown    = "unknown"    // 1: the answer is not one tailkeeper recognises; never ignorable
)

// ACLValidateInput is a proposal to validate.
type ACLValidateInput struct {
	Policy       string `json:"policy,omitempty" cli:"file:from,stdin,group=proposal" jsonschema:"the proposed policy as HuJSON text, a top-level object; leave it and patch out to validate the live policy"`
	Patch        string `json:"patch,omitempty" cli:"file:patch,stdin,group=proposal" jsonschema:"RFC 6902 operations, as JSON text, applied to the live policy; over MCP a user is named by pseudonym, in a file by login"`
	Invariants   string `json:"-" cli:"file:invariants" jsonschema:"a file of tests (a HuJSON object with tests and sshTests) that the policy must also pass, instead of the configured acl.invariantsFile"`
	NoInvariants bool   `json:"-" cli:"bool:no-invariants" jsonschema:"do not check the configured invariants"`
	Offline      bool   `json:"-" cli:"bool:offline" jsonschema:"check the text here only, send nothing to Tailscale and need no credential; no --fail-on kind can be computed without the live policy, so the flag is refused with it"`
	Operator     bool   `json:"-" cli:"operator"`
}

// RunsOffline says that --offline needs no credential.
func (in ACLValidateInput) RunsOffline(g registry.Given) bool { return g["offline"] }

// Check refuses a policy and a patch together, before anything is sent: the policy is the
// whole proposal, and the patch is a change to the live policy. On the command line the two
// flags are one group, and the binder refuses both before this runs.
func (in ACLValidateInput) Check() error {
	if in.Policy != "" && in.Patch != "" {
		return validationf("give a policy or a patch, not both: the policy is the whole proposal, the patch is applied to the live policy")
	}
	return nil
}

// ACLValidateOutput is the verdict on a proposal. Every verdict is a typed result, the
// invalid and rejected ones too, so that the registry redacts a hostile name instead of
// withholding the whole result; the exit code comes from Status alone.
type ACLValidateOutput struct {
	Status        string       `json:"status" jsonschema:"pass, fail (a test failed), invalid (not a policy), rejected (by Tailscale), unresolved (a test names what Tailscale cannot resolve) or unknown (an answer not recognised, or the live policy changed): unknown is not a pass"`
	ServerChecked bool         `json:"serverChecked" jsonschema:"false: the text was not sent to Tailscale, so a pass is a local one"`
	Errors        []ACLProblem `json:"errors,omitempty" jsonschema:"what made the status what it is, placed in the text where possible"`
	Notices       []ACLProblem `json:"notices,omitempty" jsonschema:"remarks that change no status"`
	// NewWarnings are the warnings the text adds to the live policy's own; ExistingWarnings
	// are the ones the live policy already has. A warning is existing only when it matches one
	// stored with the live policy word for word (see warnings in acl_validate_online.go), so
	// the doubt falls on the side of a gate: a warning worded differently reads as new.
	NewWarnings      []ACLProblem `json:"newWarnings,omitempty" jsonschema:"warnings the live policy does not already have: one is existing only if it matches a warning stored with the live policy word for word, so a reworded one reads as new"`
	ExistingWarnings []ACLProblem `json:"existingWarnings,omitempty" jsonschema:"warnings the live policy already has"`
	// NewWarningsOmitted counts the new warnings that NewWarnings does not list, past the caps
	// on what a reply and a result carry; they are part of Omitted, and --fail-on warnings
	// counts them.
	NewWarningsOmitted int      `json:"newWarningsOmitted,omitempty" jsonschema:"new warnings not listed in newWarnings, past the caps; still new warnings, and part of omitted"`
	ServerErrors       []string `json:"serverErrors,omitempty" tk:"untrusted,emails" jsonschema:"errors stored with the live policy"`
	Omitted            int      `json:"omitted,omitempty" jsonschema:"problems left out past the caps"`

	// What the verdict counts, as the tool files what Tailscale said: the assertions that
	// failed, the tests that could not be evaluated and the messages of a rejection, each
	// once, however many places in the text a message is filed at and whatever the cap on the
	// problems cuts. A result decoded from JSON has none of them, and its verdict counts the
	// problems it lists.
	failedAssertions, unevaluableTests, rejections int

	TestsBefore    int `json:"testsBefore" jsonschema:"in the live policy; 0 when not read"`
	TestsAfter     int `json:"testsAfter" jsonschema:"in the validated text"`
	SSHTestsBefore int `json:"sshTestsBefore"`
	SSHTestsAfter  int `json:"sshTestsAfter"`
	// Changes counts the differences from the live policy by class.
	Changes *ACLChangeCounts `json:"changes,omitempty" jsonschema:"differences from the live policy, by class"`

	InvariantsApplied   int      `json:"invariantsApplied" jsonschema:"invariant tests that ran; 0 means none"`
	InvariantsSignature string   `json:"invariantsSignature" jsonschema:"always none: unsigned"`
	NotChecked          []string `json:"notChecked" jsonschema:"what this does not establish"`
	DependsOnLiveState  bool     `json:"dependsOnLiveState" jsonschema:"the answer depends on the live policy"`

	PolicyVersion         string `json:"policyVersion,omitempty" jsonschema:"live policy version: a keyed digest of its ETag, or the ETag with personalData show; absent otherwise"`
	PolicySHA256          string `json:"policySha256,omitempty" jsonschema:"SHA-256 of the live policy as acl_get shows it"`
	LiveChanged           bool   `json:"liveChanged" jsonschema:"the live policy changed during the check; never a pass"`
	ValidatedLive         bool   `json:"validatedLive,omitempty" jsonschema:"true: no policy and no patch was given, so what was validated is the live policy itself (an empty policy is no policy)"`
	IdenticalToLive       bool   `json:"identicalToLive" jsonschema:"the text is byte for byte the live policy"`
	CheckedAt             string `json:"checkedAt"`
	ExternallyManaged     string `json:"externallyManaged" jsonschema:"true, false or unknown: managed outside the admin console"`
	ExternalLink          string `json:"externalLink,omitempty" tk:"untrusted,plain"`
	ExternallyManagedNote string `json:"externallyManagedNote,omitempty" jsonschema:"why it is unknown"`
	PatchedBytes          int    `json:"patchedBytes,omitempty" jsonschema:"for a patch: its size once applied, as acl_get shows a policy (while personal data is masked, the masked text)"`
	PatchedDigest         string `json:"patchedDigest,omitempty" jsonschema:"for a patch, with a privacy key: acl_get's summary semanticDigest equals it once the live policy means this"`
}

// ACLChangeCounts are the differences between the validated text and the live policy, by
// class.
type ACLChangeCounts struct {
	Defaults         int `json:"defaults"`
	TestsReduced     int `json:"testsReduced"`
	Widening         int `json:"widening"`
	TailscaleWritten int `json:"tailscaleWritten"`
	Semantic         int `json:"semantic"`
	CommentOnly      int `json:"commentOnly"`
	FormatOnly       int `json:"formatOnly"`
}

// ExitCode comes from the verdict alone, never from message text: pass 0, unknown 1,
// invalid, rejected and unresolved 2, fail 9. A status this version does not know is
// unknown.
func (o ACLValidateOutput) ExitCode() int {
	switch o.Status {
	case statusPass:
		return 0
	case statusFail:
		return 9
	case statusInvalid, statusRejected, statusUnresolved:
		return 2
	}
	return 1
}

// Findings counts what --fail-on can gate. Every kind is computed over all the changes, not
// over a page of them. The kind change fires for any of the five classes, the
// Tailscale-written ones included, because a gate named change that stays silent for a
// widening is the unsafe direction.
func (o ACLValidateOutput) Findings() registry.Findings {
	f := registry.Findings{NewWarnings: o.newWarningCount()}
	if c := o.Changes; c != nil {
		f.TestsReduced, f.Defaults, f.Widenings = c.TestsReduced, c.Defaults, c.Widening
		f.Changes = changedEntries(*c, true)
	}
	return f
}

// newWarningCount is every new warning, the ones the lists do not show included.
func (o ACLValidateOutput) newWarningCount() int { return len(o.NewWarnings) + o.NewWarningsOmitted }

// FailOnKinds: acl_validate computes all five kinds.
func (ACLValidateOutput) FailOnKinds() []string {
	return []string{"warnings", "tests-reduced", "defaults", "widening", "change"}
}

// OfflineFailOnKinds: an offline check compares nothing with the live policy and sends
// nothing, so it computes none of the five kinds, and --fail-on is refused with --offline.
func (ACLValidateOutput) OfflineFailOnKinds() []string { return nil }

// newValidateOutput is the result before anything is found.
func newValidateOutput(env *registry.Env) ACLValidateOutput {
	return ACLValidateOutput{
		Status:              statusPass,
		InvariantsSignature: "none",
		NotChecked:          slices.Clone(acl.NotChecked),
		ExternallyManaged:   "unknown",
		CheckedAt:           env.Clock().UTC().Format("2006-01-02T15:04:05Z"),
	}
}

// validation is one call of acl_validate: what the caller gave, what it found out so far,
// and the resolver that masks the logins a pseudonym stands for.
type validation struct {
	env *registry.Env
	in  ACLValidateInput
	res *SubjectResolver
	// pos maps a position of the text that was sent back to the caller's own, once pseudonyms
	// in a proposal were replaced by logins; nil before that. patchPos does the same for a
	// patch.
	pos, patchPos *columnMap
	doc           *acl.Doc // the caller's policy text, parsed; nil without one
	inv           *invariantSet
	out           ACLValidateOutput
	// uncapped lifts the cap on the tests a text adds. Only acl_diff sets it, whatever it
	// compares: it sends nothing to Tailscale, and the cap exists for what one validation
	// request can carry.
	uncapped bool
}

// parse reads a policy text so that what a result quotes of it (a key, a pointer, a name) is
// cut after the caller's view of it. The view is the one that echoes a text back: logins
// masked with no pseudonym beside them, which a pseudonym next to an echo would confirm a
// guess at. A comparison shows its sides otherwise (see aclDiff).
func (v *validation) parse(ctx context.Context, src []byte) (*acl.Doc, error) {
	return acl.ParseShown(ctx, src, v.res.Shown(false))
}

func newValidation(env *registry.Env, in ACLValidateInput) *validation {
	return &validation{env: env, in: in, res: NewSubjectResolver(env), out: newValidateOutput(env)}
}

// hide is what every message and pointer of a result passes: tailkeeper's own words and
// Tailscale's alike may quote the caller's text, so logins are masked without pseudonyms
// (a pseudonym beside an echoed text would confirm a guess), a marker is unforged and the
// text is cut after it is masked, at the length a display needs, so that where it is cut
// tells nothing of how long a login is.
func (v *validation) hide(s string) string { return v.res.Hide(s) }

// problem builds a problem with the text hidden.
func (v *validation) problem(kind, severity, source, message string) ACLProblem {
	return ACLProblem{Kind: kind, Severity: severity, Source: source, Message: v.hide(message)}
}

// add files a problem under the list its severity names.
func (v *validation) add(p ACLProblem) {
	if p.Severity == severityNotice {
		v.out.Notices = append(v.out.Notices, p)
		return
	}
	v.out.Errors = append(v.out.Errors, p)
}

// invalid reports whether the text itself showed an error.
func (v *validation) invalid() bool { return len(v.out.Errors) > 0 }

// aclValidate validates the caller's proposal, or the live policy with none.
func aclValidate(ctx context.Context, env *registry.Env, in ACLValidateInput) (ACLValidateOutput, error) {
	v := newValidation(env, in)
	if in.Invariants != "" && in.NoInvariants {
		return ACLValidateOutput{}, tkerr.New(tkerr.ValidationFailed, "give --invariants FILE or --no-invariants, not both: the first replaces the configured invariants and the second removes them", "")
	}
	if in.Offline && in.Patch != "" {
		return ACLValidateOutput{}, tkerr.New(tkerr.ValidationFailed, "a patch is applied to the live policy, so it cannot be checked offline: give the whole policy (--from FILE)", "")
	}
	if in.Offline && in.Policy == "" && in.Invariants == "" {
		return ACLValidateOutput{}, tkerr.New(tkerr.ValidationFailed, "an offline check needs a text to check: give a policy (--from FILE) or an invariants file (--invariants FILE)", "")
	}
	if err := v.checkLocally(ctx); err != nil {
		return ACLValidateOutput{}, err
	}
	if v.invalid() {
		v.out.Status = statusInvalid
		v.out.DependsOnLiveState = false
		v.out.capProblems()
		return v.out, nil
	}
	if in.Offline {
		v.offlineResult()
		v.out.capProblems()
		return v.out, nil
	}
	c, err := env.RequireAPI()
	if err != nil {
		return ACLValidateOutput{}, err
	}
	return v.online(ctx, c)
}

// offlineResult is the pass of a text that was checked here and sent nowhere. It says so:
// serverChecked is false, notChecked names what was skipped, and the verdict line says the
// text was not sent to Tailscale.
func (v *validation) offlineResult() {
	v.out.Status = statusPass
	v.out.ServerChecked = false
	v.out.DependsOnLiveState = false
	v.out.NotChecked = append(v.out.NotChecked, "server_validation", "tests")
	if v.inv != nil || v.invariantsConfigured() {
		// Offline reads no configured file, so a configured one is named here as not run, and
		// the verdict does not read as if there were none.
		v.out.NotChecked = append(v.out.NotChecked, "invariants")
	}
}

// invariantsConfigured says that the configuration names an invariants file this call would
// have applied online.
func (v *validation) invariantsConfigured() bool {
	return !v.in.NoInvariants && v.env.Config != nil && v.env.Config.Config.ACL.InvariantsFile != ""
}

// checkLocally reads the texts the caller gave and records what they show by themselves:
// encoding, syntax, structure, the sections tailkeeper knows and the number of tests. It
// returns an error only for a text past the engine's budgets (too_complex) and for a
// cancelled call.
func (v *validation) checkLocally(ctx context.Context) error {
	if v.in.Policy != "" {
		if err := v.readPolicy(ctx); err != nil {
			return err
		}
	}
	if v.in.Patch != "" {
		if err := v.readPatch(); err != nil {
			return err
		}
	}
	if v.in.Invariants != "" && v.in.Offline {
		// Offline, the invariants file's syntax is all there is to check. Online, the file is
		// read when the call needs it, before the first request.
		inv, problems, err := parseInvariants(ctx, v.in.Invariants)
		if err != nil {
			return v.engineError(err)
		}
		for _, p := range problems {
			v.add(v.hidden(p))
		}
		if len(problems) == 0 {
			v.inv = inv
			n := len(inv.Tests) + len(inv.SSHTests)
			v.add(v.problem(kindNote, severityNotice, sourceInvariants,
				fmt.Sprintf("the invariants file holds %s; its syntax is checked, and nothing runs it here", plural(n, "test"))))
		}
	}
	return nil
}

// hidden returns p with its text hidden.
func (v *validation) hidden(p ACLProblem) ACLProblem {
	p.Message, p.Pointer = v.hide(p.Message), v.hide(p.Pointer)
	return p
}

// readPolicy parses the caller's policy text.
func (v *validation) readPolicy(ctx context.Context) error {
	src := []byte(v.in.Policy)
	d, err := v.parse(ctx, src)
	if err != nil {
		p, perr := v.parseProblem(src, err, sourceFrom)
		if perr != nil {
			return perr
		}
		v.add(p)
		return nil
	}
	v.doc = d
	if v.in.Operator {
		if p, found := v.operatorMarker(src, sourceFrom); found {
			v.add(p)
			return nil
		}
	} else if err := screenMCPText(v.env, src, "a proposal"); err != nil {
		// The caller is not the operator: while masking is on, a literal login in the text is
		// refused, and so is a credential shape, before anything is sent.
		return err
	}
	v.structure(d, sourceFrom, false)
	s, err := acl.Summarise(ctx, d)
	if err != nil {
		return v.engineError(err)
	}
	v.out.TestsAfter, v.out.SSHTestsAfter = s.Tests, s.SSHTests
	return nil
}

// readPatch screens the caller's patch before any request is made: the limits of the guard, the
// subject rule, the credential tripwire and the cap on the tests it adds for an MCP caller; a
// marker of a pseudonym for the operator, whose files hold logins.
func (v *validation) readPatch() error {
	patch := []byte(v.in.Patch)
	if v.in.Operator {
		if p, found := v.operatorMarker(patch, sourcePatch); found {
			v.add(p)
		}
		return nil
	}
	r := guard.Scan(patch, guard.MaxDepth)
	if !r.TooDeep && r.NodeBound <= acl.MaxNodes {
		// The patch is read before the subject rule reads it, so that a syntax error is a
		// result with its place, not a refusal that says the text could not be checked.
		if _, err := hujson.Parse(bytes.Clone(patch)); err != nil {
			msg := strings.TrimPrefix(err.Error(), "hujson: ")
			line, col, positioned := positionIn(msg)
			if positioned {
				msg = msg[strings.Index(msg, ": ")+2:]
			}
			p := v.problem(kindSyntax, severityError, sourcePatch, msg)
			p.Line, p.Column = line, col
			v.add(p)
			return nil
		}
	}
	if err := screenPatch(v.env, patch, v.uncapped); err != nil {
		return err
	}
	if p, found := v.testOperation(patch); found {
		v.add(p)
	}
	return nil
}

// testOperation finds an RFC 6902 test operation in the patch of an MCP caller. The operation
// compares a value with the policy and answers whether they are equal, so a caller could
// confirm a guess at a value that masking hides (the host bits of a public address) as often
// as the API answers, with no validation token spent. The patch is invalid, whether the
// comparison would hold or not, and nothing is sent. The operator's own patch file keeps the
// operation: the operator sees the policy. Every other operation answers by the structure of
// the policy (a key or an index that is there or not), never by comparing a value.
func (v *validation) testOperation(patch []byte) (ACLProblem, bool) {
	val, err := hujson.Parse(bytes.Clone(patch)) // the guard has bounded the nesting
	if err != nil {
		return ACLProblem{}, false
	}
	ops, ok := val.Value.(*hujson.Array)
	if !ok {
		return ACLProblem{}, false
	}
	for i := range ops.Elements {
		obj, ok := ops.Elements[i].Value.(*hujson.Object)
		if !ok {
			continue
		}
		for _, m := range obj.Members {
			name, _ := m.Name.Value.(hujson.Literal)
			if !strings.EqualFold(name.String(), "op") {
				continue
			}
			var op string
			if lit, ok := m.Value.Value.(hujson.Literal); !ok || json.Unmarshal(lit, &op) != nil || !strings.EqualFold(op, "test") {
				continue
			}
			off := ops.Elements[i].StartOffset
			p := v.problem(kindStructure, severityError, sourcePatch, fmt.Sprintf(
				`operation %d is "test", which a patch over MCP may not hold: it compares a value the caller cannot see, and its answer would confirm a guess at a value masking hides; use add, replace, remove or move`, i+1))
			p.Line, p.Column = lineOf(patch, off), off-bytes.LastIndexByte(patch[:off], '\n')
			return p, true
		}
	}
	return ACLProblem{}, false
}

// engineError turns an error of the engine that is not a problem of the text into the
// error a call returns: too_complex, or a cancelled call.
func (v *validation) engineError(err error) error {
	var e *acl.Error
	if errors.As(err, &e) {
		if e.Code == acl.CodeTooComplex {
			return tkerr.New(tkerr.TooComplex, e.Message, "")
		}
		return tkerr.New(tkerr.ValidationFailed, e.Message, "")
	}
	return tkerr.Wrap(tkerr.APIError, err, "request cancelled", "")
}

// parseProblem turns the error of acl.Parse into a problem of the text it read, or, for a
// text past the engine's budgets or a cancelled call, into the error to return.
func (v *validation) parseProblem(src []byte, err error, source string) (ACLProblem, error) {
	var e *acl.Error
	if !errors.As(err, &e) || e.Code != acl.CodeInvalid {
		return ACLProblem{}, v.engineError(err)
	}
	p := v.problem(parseKind(src, e), severityError, source, e.Message)
	if source == sourcePatch {
		// The engine read the patch with the logins in it; the caller wrote the pseudonyms.
		p.Line, p.Column = v.patchPos.back(e.Line, e.Column)
	} else {
		p.Line, p.Column = v.callerPos(source, e.Line, e.Column)
	}
	return p, nil
}

// parseKind says what kind of problem a text that acl.Parse refused has. The encoding rules
// are the engine's, applied first; the other two are told apart by the words the engine
// uses (a test pins them): a top level that is not an object, or nesting past the guard, is
// structure, and what is left is HuJSON syntax.
func parseKind(src []byte, e *acl.Error) string {
	switch {
	case bytes.HasPrefix(src, []byte("\xef\xbb\xbf")), bytes.HasPrefix(src, []byte("\xff\xfe")), bytes.HasPrefix(src, []byte("\xfe\xff")),
		bytes.IndexByte(src, 0) >= 0, !utf8.Valid(src):
		return kindEncoding
	case strings.HasPrefix(e.Message, "the top level must be"), strings.HasPrefix(e.Message, "the text nests deeper"):
		return kindStructure
	}
	return kindSyntax
}

// structure records the structural findings of a parsed text: a key written twice, a pair
// that differs only in case, a section tailkeeper does not know. See structureProblems.
func (v *validation) structure(d *acl.Doc, source string, live bool) {
	ps, omitted := v.structureProblems(d, source, live)
	for _, p := range ps {
		v.add(p)
	}
	v.out.Omitted += omitted
}

// structureProblems are the structural findings of a parsed text, and how many repeated keys
// past the engine's cap were left out. In a proposal a key written twice and a pair that
// differs only in case are errors, since Tailscale refuses them and the text would be
// rejected; in the live policy they are notices, since Tailscale accepted it once. An unknown
// section is a notice in both, worded for the side it is on. A text the caller never wrote
// (the live policy with a patch applied) is placed by pointer: its lines mean nothing. The
// unknown sections are not counted against a cap here, though a text may hold as many as the
// engine accepts (200,000 keys are a 2.4 MB file): each caller cuts what it holds to what its
// result carries (capProblems for acl_validate, capFindings for a side of acl_diff).
func (v *validation) structureProblems(d *acl.Doc, source string, live bool) ([]ACLProblem, int) {
	sev := severityError
	if live {
		sev = severityNotice
	}
	var out []ACLProblem
	for _, f := range d.Findings() {
		kind := kindDuplicateKey
		if f.Code == acl.FindingCaseCollision {
			kind = kindCaseCollision
		}
		p := v.problem(kind, sev, source, findingMessage(f, live))
		p.Line, p.Column = v.callerPos(source, f.Line, f.Column)
		p.Pointer = v.hide(f.Pointer + "/" + pointerEscape.Replace(cutRunes(f.Key, 128)))
		if source == sourcePatch {
			p.Line, p.Column = 0, 0
		}
		out = append(out, p)
	}
	if source != sourcePatch {
		// The names are cut after the Doc shows them (UnknownSectionsShown), and again here
		// only to fit a sentence and a pointer.
		for _, name := range d.UnknownSectionsShown() {
			msg := "Tailscale will probably reject the section " + quoteName(name) + ": it is not one it knows (json: unknown field)"
			if live {
				msg = "Tailscale accepted the section " + quoteName(name) + ", which this version of tailkeeper does not know"
			}
			p := v.problem(kindUnknownSection, severityNotice, source, msg)
			p.Pointer = v.hide("/" + pointerEscape.Replace(cutRunes(name, 128)))
			out = append(out, p)
		}
	}
	return out, d.FindingsOmitted()
}

// findingMessage is the one sentence for a repeated key. Tailscale refuses every repeated
// key, a top-level pair that differs only in case included (probe A-4), so in a proposal
// the text cannot be validated; in the live policy it was accepted once and is refused now.
func findingMessage(f acl.Finding, live bool) string {
	what := "a key written twice"
	if f.Code == acl.FindingCaseCollision {
		what = "two keys that differ only in case"
	}
	if live {
		return fmt.Sprintf("Tailscale stored this policy with %s here (also at line %d) but would refuse it now", what, f.FirstLine)
	}
	return fmt.Sprintf("Tailscale refuses %s here (also at line %d)", what, f.FirstLine)
}

// quoteName shows a name from a policy inside a sentence: cut and quoted.
func quoteName(s string) string { return fmt.Sprintf("%q", cutRunes(s, 64)) }

// cutRunes cuts s to at most n bytes at a rune boundary.
func cutRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// notListed says that n of something were left out of a list: "1 problem is not listed",
// "6 problems are not listed".
func notListed(n int, word string) string {
	if n == 1 {
		return "1 " + word + " is not listed"
	}
	return fmt.Sprintf("%d %ss are not listed", n, word)
}

// plural is "1 test" and "2 tests".
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// invariantSet is an invariants file: the tests and SSH tests it holds, each as the text of
// its entry with its comments, and the file parsed, so that a failure can be placed in it.
type invariantSet struct {
	Tests, SSHTests [][]byte
	Doc             *acl.Doc
	WithSSHCanary   bool // acl_test's SSH path appends an sshTests canary of its own
}

// parseInvariants reads an invariants file: a HuJSON object with optional tests and
// sshTests arrays in the policy's own syntax and no other key. A marker of a pseudonym
// anywhere in it is a problem, since an invariants file holds logins and a key replacement
// would turn every nightly run red. The problems are the file's: their messages are raw, and
// the caller hides them. An error is returned only for a text past the engine's budgets and
// for a cancelled call.
func parseInvariants(ctx context.Context, text string) (*invariantSet, []ACLProblem, error) {
	src := []byte(text)
	problem := func(kind string, line, col int, pointer, msg string) ACLProblem {
		return ACLProblem{Kind: kind, Severity: severityError, Source: sourceInvariants, Line: line, Column: col, Pointer: pointer, Message: msg}
	}
	d, err := acl.Parse(ctx, src)
	if err != nil {
		var e *acl.Error
		if !errors.As(err, &e) || e.Code != acl.CodeInvalid {
			return nil, nil, err
		}
		return nil, []ACLProblem{problem(parseKind(src, e), e.Line, e.Column, "", e.Message)}, nil
	}
	var problems []ACLProblem
	for _, f := range d.Findings() {
		kind := kindDuplicateKey
		if f.Code == acl.FindingCaseCollision {
			kind = kindCaseCollision
		}
		problems = append(problems, problem(kind, f.Line, f.Column, f.Pointer, findingMessage(f, false)))
	}
	if strings.Contains(text, "[p:") {
		problems = append(problems, problem(kindStructure, 0, 0, "", "an invariants file holds logins, never pseudonyms: a pseudonym stops naming anyone when the privacy key is replaced"))
	}
	root, perr := hujson.Parse(src) // acl.Parse has applied the guard, so the nesting is bounded
	if perr != nil {
		return nil, problems, nil
	}
	set := &invariantSet{Doc: d}
	for _, m := range root.Value.(*hujson.Object).Members {
		name := ""
		if lit, ok := m.Name.Value.(hujson.Literal); ok {
			name = lit.String()
		}
		line, col := d.Position(m.Name.StartOffset)
		sec, known := acl.SectionByName(name)
		if !known || (sec.Name != "tests" && sec.Name != "sshTests") {
			problems = append(problems, problem(kindStructure, line, col, "/"+pointerEscape.Replace(cutRunes(name, 128)),
				"an invariants file holds tests and sshTests and nothing else"))
			continue
		}
		list, ok := m.Value.Value.(*hujson.Array)
		if !ok {
			problems = append(problems, problem(kindStructure, line, col, "/"+sec.Name, sec.Name+" must be an array of tests"))
			continue
		}
		for i := range list.Elements {
			el := &list.Elements[i]
			if _, ok := el.Value.(*hujson.Object); !ok {
				l, c := d.Position(el.StartOffset)
				problems = append(problems, problem(kindStructure, l, c, fmt.Sprintf("/%s/%d", sec.Name, i), "a test is an object"))
				continue
			}
			if sec.Name == "tests" {
				set.Tests = append(set.Tests, el.Pack())
			} else {
				set.SSHTests = append(set.SSHTests, el.Pack())
			}
		}
	}
	if len(problems) > 0 {
		return nil, problems, nil
	}
	return set, nil, nil
}

// Report is the human layout: the verdict line, what was not checked, the diff counts by
// class, then the problems, each behind a location. Tailscale's own words are marked
// untrusted so that the layout prints them behind a notice.
func (o ACLValidateOutput) Report() registry.Report {
	rep := registry.Report{NotChecked: slices.Clone(o.NotChecked)}
	rep.Verdict, rep.Level = o.verdict()
	if c := o.Changes; c != nil {
		rep.Classes = []registry.ClassCount{
			{Class: "defaults", Count: c.Defaults},
			{Class: "tests reduced", Count: c.TestsReduced},
			{Class: "widening", Count: c.Widening},
			{Class: "tailscale-written", Count: c.TailscaleWritten, Expected: true},
			{Class: "semantic", Count: c.Semantic},
		}
	}
	located := false
	for _, list := range [][]ACLProblem{o.Errors, o.NewWarnings, o.Notices} {
		for _, p := range list {
			rep.Findings = append(rep.Findings, registry.Finding{Severity: p.Severity, Source: p.Source, Line: p.Line, Column: p.Column,
				Pointer: p.Pointer, Message: p.Message, Untrusted: p.FromTailscale})
			located = located || p.Line > 0
		}
	}
	for _, p := range o.ExistingWarnings {
		// The live policy's own warnings are a baseline and not news: a notice of the live
		// policy, marked as existing. Shown as a warning in the proposal's file, every green
		// pull request of a tailnet with a stale group would carry the same warning for ever,
		// and ten of them would take every annotation slot a new warning needs.
		rep.Findings = append(rep.Findings, registry.Finding{Severity: severityNotice, Source: sourceLive,
			Message: "existing: " + p.Message, Untrusted: p.FromTailscale})
	}
	for _, e := range o.ServerErrors {
		rep.Findings = append(rep.Findings, registry.Finding{Severity: severityError, Source: "live", Message: e, Untrusted: true})
	}
	if o.Omitted > 0 {
		msg := notListed(o.Omitted, "problem")
		if o.NewWarningsOmitted > 0 {
			msg += fmt.Sprintf(" (%d of them new warnings, which --fail-on warnings counts)", o.NewWarningsOmitted)
		}
		rep.Findings = append(rep.Findings, registry.Finding{Severity: severityNotice, Message: msg})
	}
	if located {
		rep.Findings = append(rep.Findings, registry.Finding{Severity: severityNotice,
			Message: "Lines are counted by line feed and columns in bytes, as Tailscale counts them: an editor that counts a lone carriage return may disagree."})
	}
	return rep
}

// verdict is the first line of the report and the level it is shown at. Whatever the status,
// it says when new warnings were cut from the lists: a pass counts them with the listed ones.
func (o ACLValidateOutput) verdict() (string, registry.Level) {
	line, level := o.status()
	if o.Status != statusPass && o.NewWarningsOmitted > 0 {
		line += " · " + plural(o.NewWarningsOmitted, "new warning") + " not listed"
	}
	return line, level
}

// status is the line a status makes by itself.
func (o ACLValidateOutput) status() (string, registry.Level) {
	invariants := "invariants: none"
	if o.InvariantsApplied > 0 {
		invariants = "invariants: " + plural(o.InvariantsApplied, "test") + " ran"
		if o.Status == statusPass {
			invariants = "invariants: " + plural(o.InvariantsApplied, "test") + " passed"
		}
	}
	tests := o.TestsAfter + o.SSHTestsAfter
	switch o.Status {
	case statusPass:
		if !o.ServerChecked {
			return fmt.Sprintf("VALID, CHECKED HERE ONLY, NOT SENT TO TAILSCALE · %s in the proposal, not run · %s", plural(tests, "test"), invariants), registry.LevelWarn
		}
		level := registry.LevelOK
		if o.newWarningCount() > 0 {
			level = registry.LevelWarn
		}
		return fmt.Sprintf("VALID · %s (%d existing) · %s passed · %s",
			plural(o.newWarningCount(), "new warning"), len(o.ExistingWarnings), plural(tests, "test"), invariants), level
	case statusFail:
		return fmt.Sprintf("FAILED · %s · %s", plural(o.counted(o.failedAssertions, kindAssertionFailed, kindInvariantFailed), "failed assertion"), invariants), registry.LevelFail
	case statusInvalid:
		return fmt.Sprintf("INVALID · %s found before anything was sent to Tailscale", plural(len(o.Errors), "problem")), registry.LevelFail
	case statusRejected:
		if !o.ServerChecked {
			// The live policy was stored with errors, and the call stopped there: nothing was sent.
			return fmt.Sprintf("REJECTED · the live policy has errors Tailscale stored with it, so nothing was sent (%s)", plural(o.rejectionMessages(), "message")), registry.LevelFail
		}
		return fmt.Sprintf("REJECTED · Tailscale refused the text (%s)", plural(o.rejectionMessages(), "message")), registry.LevelFail
	case statusUnresolved:
		return fmt.Sprintf("UNRESOLVED · %s cannot be evaluated: a name or destination does not resolve", plural(o.counted(o.unevaluableTests, kindUnevaluable), "test")), registry.LevelFail
	}
	return "UNKNOWN · the answer could not be established; this is not a pass", registry.LevelFail
}

// countKinds counts the errors of the given kinds.
func (o ACLValidateOutput) countKinds(kinds ...string) int {
	n := 0
	for _, p := range o.Errors {
		if slices.Contains(kinds, p.Kind) {
			n++
		}
	}
	return n
}

// counted is the number a verdict states: n, the count the tool made, or, for a result that
// has none, the problems listed under the given kinds.
func (o ACLValidateOutput) counted(n int, kinds ...string) int {
	if n > 0 {
		return n
	}
	return o.countKinds(kinds...)
}

// rejectionMessages is the number of Tailscale's messages a rejection holds: the one it
// answered, the invariants' when that was refused, or the errors it stored with the live
// policy; for a result that has no count, the problems and stored errors it lists.
func (o ACLValidateOutput) rejectionMessages() int {
	if o.rejections > 0 {
		return o.rejections
	}
	return len(o.Errors) + len(o.ServerErrors)
}
