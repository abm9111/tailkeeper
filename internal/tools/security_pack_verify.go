package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/safefile"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/securitypack"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// SecurityVerifyInput names owner-controlled files; the tool reads them with file guards.
type SecurityVerifyInput struct {
	Before     string `json:"before" tk:"short" jsonschema:"private before evidence pack path"`
	Correction string `json:"correction" tk:"short" jsonschema:"correction intent file path"`
	Invariants string `json:"-" cli:"file:invariants" jsonschema:"current owner intent file"`
	Operator   bool   `json:"-" cli:"operator"`
}

// SecurityVerifyTool is an owner-only read tool; it is never exposed over MCP.
func SecurityVerifyTool() registry.Tool {
	m := readMeta("security_verify", "security", "verify", "Verify a correction against a private evidence pack; owner command line only.", aclScopes...)
	m.Credential, m.OpenWorld, m.Title = registry.CredOptional, true, "Verify security correction"
	m.Operations = []string{"GET /tailnet/{tailnet}/devices", "GET /tailnet/{tailnet}/acl", "POST /tailnet/{tailnet}/acl/validate"}
	return registry.Define(m, securityVerify)
}

type VerifyEvidence struct {
	Class      string `json:"class"`
	AgeSeconds int64  `json:"ageSeconds"`
}
type VerifyRow struct {
	Kind          string           `json:"kind"`
	Rule          string           `json:"rule,omitempty" tk:"untrusted"`
	Device        string           `json:"device,omitempty" tk:"untrusted"`
	DeviceRef     string           `json:"deviceRef,omitempty"`
	Expectation   string           `json:"expectation,omitempty" tk:"untrusted"`
	Name          string           `json:"name,omitempty" tk:"untrusted"`
	Role          string           `json:"role,omitempty"`
	AtLeast       string           `json:"atLeast,omitempty" tk:"untrusted"`
	Value         *bool            `json:"value,omitempty"`
	Outcome       string           `json:"outcome"`
	Reason        string           `json:"reason,omitempty"`
	MatcherReason string           `json:"matcherReason,omitempty"`
	Before        string           `json:"before,omitempty"`
	After         string           `json:"after,omitempty"`
	Evidence      []VerifyEvidence `json:"evidence,omitempty"`
	Limits        []string         `json:"limits,omitempty"`
}
type VerifyGuard struct {
	Expectation string   `json:"expectation" tk:"untrusted"`
	Outcome     string   `json:"outcome"`
	Reason      string   `json:"reason,omitempty"`
	Before      string   `json:"before,omitempty"`
	After       string   `json:"after,omitempty"`
	Limits      []string `json:"limits,omitempty"`
}
type SecurityVerifyOutput struct {
	Ref                      string        `json:"ref,omitempty"`
	Seal                     string        `json:"seal"`
	ActionAt                 string        `json:"actionAt"`
	Outcome                  string        `json:"outcome"`
	Targets                  []VerifyRow   `json:"targets" tk:"details"`
	Guards                   []VerifyGuard `json:"guards" tk:"details"`
	CatalogChangedOtherRules bool          `json:"catalogChangedOtherRules"`
	NewOtherFindings         int           `json:"newOtherFindings"`
	PolicyCheck              string        `json:"policyCheck,omitempty"`
	Statement                string        `json:"statement"`
}

func (o SecurityVerifyOutput) ExitCode() int {
	switch o.Outcome {
	case "fixed":
		return 0
	case "not_fixed":
		return 8
	default:
		return 1
	}
}
func (SecurityVerifyOutput) ExitNote() string {
	return "a correction remains open or a selected expectation is unmet"
}
func (o SecurityVerifyOutput) AuditFields() map[string]any {
	fixed, notFixed, incomplete, regressed := o.counts()
	return map[string]any{"pack": "verify", "seal": packAuditSeal(o.Seal), "outcome": o.Outcome, "digest": o.Ref, "fixed": fixed, "not_fixed": notFixed, "incomplete": incomplete, "regressed": regressed}
}
func (o SecurityVerifyOutput) counts() (int64, int64, int64, int64) {
	var fixed, notFixed, incomplete, regressed int64
	for _, r := range o.Targets {
		switch r.Outcome {
		case "fixed":
			fixed++
		case "not_fixed":
			notFixed++
		case "incomplete":
			incomplete++
		}
	}
	for _, r := range o.Guards {
		switch r.Outcome {
		case "regressed", "still_unmet":
			regressed++
		case "unconfirmed", "limits_changed", "intent_changed", "intent_unavailable", "access_not_post_action", "access_not_recent", "access_input_mismatch", "access_judgement_missing":
			incomplete++
		}
	}
	return fixed, notFixed, incomplete, regressed
}
func (o SecurityVerifyOutput) Details() []string {
	lines := []string{fmt.Sprintf("baseline ref: %s; seal: %s; action: %s", o.Ref, o.Seal, o.ActionAt), "verification: " + o.Outcome}
	for _, r := range o.Targets {
		lines = append(lines, fmt.Sprintf("%s · %s %s %s %s %s · role %s · at least %s · before %s · after %s · %s %s", r.Outcome, r.Rule, r.Expectation, r.Name, r.Device, r.DeviceRef, r.Role, r.AtLeast, r.Before, r.After, r.Reason, r.MatcherReason))
		if r.Value != nil {
			lines = append(lines, fmt.Sprintf("expected value: %t", *r.Value))
		}
		for _, e := range r.Evidence {
			lines = append(lines, fmt.Sprintf("evidence: %s, age %d seconds", e.Class, e.AgeSeconds))
		}
		for _, l := range r.Limits {
			lines = append(lines, "limit: "+security.LimitSentence(security.AccessLimit(l)))
		}
	}
	for _, r := range o.Guards {
		if r.Outcome != "held" {
			lines = append(lines, fmt.Sprintf("guard %s: %s · before %s · after %s · %s", r.Expectation, r.Outcome, r.Before, r.After, r.Reason))
		}
		for _, l := range r.Limits {
			lines = append(lines, "limit: "+security.LimitSentence(security.AccessLimit(l)))
		}
	}
	if o.CatalogChangedOtherRules {
		lines = append(lines, fmt.Sprintf("catalog changed other rules; %d new findings elsewhere", o.NewOtherFindings))
	}
	if o.PolicyCheck != "" {
		lines = append(lines, "policy check: "+o.PolicyCheck)
	}
	return append(lines, o.Statement)
}

func verifyRefusal(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, securitypack.ErrBudgetTooSmall) || errors.Is(err, securitypack.ErrStoppedEarly) {
		return tkerr.New(tkerr.APIError, "verification could not complete", "")
	}
	for _, e := range []error{securitypack.ErrCorrectionInvalid, securitypack.ErrTargetUnknown, securitypack.ErrTargetNotOpen, securitypack.ErrDeviceNotInPack, securitypack.ErrExpectationNotSelected, securitypack.ErrActionNotAfterObservation, securitypack.ErrActionInFuture, securitypack.ErrContextMismatch} {
		if errors.Is(err, e) {
			return tkerr.New(tkerr.ValidationFailed, e.Error(), "")
		}
	}
	return packCodecError(err)
}

type verifyFiles struct {
	correction security.CorrectionIntent
	pack       securitypack.EvidencePack
	reading    securitypack.Reading
	ref        string
	prepared   securitypack.PreparedCorrection
}

// readVerifyFiles completes the file-only decisions before any source is asked.
func readVerifyFiles(ctx context.Context, env *registry.Env, in SecurityVerifyInput) (verifyFiles, error) {
	var f verifyFiles
	if err := packPlatform(); err != nil {
		return f, err
	}
	if err := packPrivacyError(env); err != nil {
		return f, err
	}
	if env == nil {
		return f, tkerr.New(tkerr.AuditUnavailable, "pack audit recording is unavailable", "")
	}
	if in.Invariants != "" && !in.Operator {
		return f, validationf("the intent file must be chosen on the command line")
	}
	data, err := safefile.Read(in.Correction, safefile.Options{Cap: securitypack.MaxCorrectionBytes, Code: tkerr.ValidationFailed, Verify: config.OwnedBy(os.Getuid())})
	if err != nil {
		return f, tkerr.New(tkerr.ValidationFailed, "correction_invalid", "")
	}
	f.correction, err = securitypack.DecodeCorrection(data)
	if err != nil {
		return f, verifyRefusal(err)
	}
	f.pack, f.reading, err = readPack(in.Before, env)
	if err != nil {
		return f, packCodecError(err)
	}
	f.ref, err = securitypack.Reference(f.pack, packSealer(env), env.ShowPersonalData())
	if err != nil {
		return f, verifyRefusal(err)
	}
	f.prepared, err = securitypack.PrepareCorrection(ctx, f.pack, f.correction, security.WorkBudget{})
	if ctx.Err() != nil {
		return f, verifyRefusal(ctx.Err())
	}
	if errors.Is(err, securitypack.ErrNotReproduced) {
		return f, err
	}
	if err != nil {
		return f, verifyRefusal(err)
	}
	return f, nil
}

// verifyConfiguration checks identity, time, intent and audit availability before collection.
func verifyConfiguration(ctx context.Context, env *registry.Env, in SecurityVerifyInput, f verifyFiles) (string, *security.IntentSet, error) {
	apiRef := ""
	if f.prepared.Scope() == security.ScopeFleet || f.prepared.AccessContext() != "" {
		var err error
		apiRef, err = apiContextRef(env)
		if err != nil {
			return "", nil, err
		}
		if f.prepared.Scope() == security.ScopeFleet && f.prepared.Context() != apiRef || f.prepared.AccessContext() != "" && f.prepared.AccessContext() != apiRef {
			return "", nil, verifyRefusal(securitypack.ErrContextMismatch)
		}
	}
	if f.correction.ActionAt.After(env.Clock().Add(5 * time.Minute)) {
		return "", nil, verifyRefusal(securitypack.ErrActionInFuture)
	}
	intent, _, err := loadScanIntent(ctx, env, SecurityScanInput{Invariants: in.Invariants, Operator: in.Operator})
	if err != nil {
		return "", nil, err
	}
	if env.RecordPack == nil {
		return "", nil, tkerr.New(tkerr.AuditUnavailable, "pack audit recording is unavailable", "")
	}
	return apiRef, intent, nil
}

// collectVerifyEvidence uses the current catalog and only the compatible current intent.
func collectVerifyEvidence(ctx context.Context, env *registry.Env, f verifyFiles, apiRef string, intent *security.IntentSet) (securitypack.AfterEvidence, error) {
	var after securitypack.AfterEvidence
	sources, err := advisory.ShippedSources()
	if err != nil {
		return after, tkerr.New(tkerr.Internal, "the shipped advisory catalog cannot be read", "")
	}
	catalog, err := advisory.Merge(sources)
	if err != nil {
		return after, tkerr.New(tkerr.Internal, "the shipped advisory catalog cannot be merged", "")
	}
	collection, err := collectSecurity(ctx, env, f.prepared.Scope(), security.RequiredFeatures(catalog))
	if err != nil {
		return after, scanError(err, "verification collection was cancelled")
	}
	var access *securitypack.AfterAccess
	selected, _ := f.prepared.CompatibleIntent(intent)
	if selected != nil && len(selected.Network)+len(selected.SSH) > 0 {
		input, started, err := collectAccessInput(ctx, env, *selected)
		if err != nil {
			return after, scanError(err, "verification access collection was cancelled")
		}
		access = &securitypack.AfterAccess{Context: apiRef, StartedAt: started, Input: input}
	}
	now := env.Clock().UTC().Round(0)
	if now.Before(collection.Snapshot.ObservedAt) {
		now = collection.Snapshot.ObservedAt
	}
	if access != nil && now.Before(access.Input.EvaluatedAt) {
		now = access.Input.EvaluatedAt
	}
	return securitypack.AfterEvidence{Snapshot: collection.Snapshot, Collected: collection.Coverage, Now: now, Catalog: catalog, CatalogSources: sources, Intent: intent, Access: access}, nil
}

func securityVerify(ctx context.Context, env *registry.Env, in SecurityVerifyInput) (SecurityVerifyOutput, error) {
	f, err := readVerifyFiles(ctx, env, in)
	if errors.Is(err, securitypack.ErrNotReproduced) {
		out := SecurityVerifyOutput{Ref: f.ref, Seal: string(f.reading.Seal), ActionAt: timeText(f.correction.ActionAt), Outcome: "not_reproduced", Statement: securitypack.ScopeSentence}
		if err := recordVerify(ctx, env, out); err != nil {
			return SecurityVerifyOutput{}, err
		}
		return out, nil
	}
	if err != nil {
		return SecurityVerifyOutput{}, err
	}
	apiRef, intent, err := verifyConfiguration(ctx, env, in, f)
	if err != nil {
		return SecurityVerifyOutput{}, err
	}
	after, err := collectVerifyEvidence(ctx, env, f, apiRef, intent)
	if err != nil {
		return SecurityVerifyOutput{}, err
	}
	verified, err := securitypack.VerifyCorrection(ctx, f.pack, f.correction, after, security.WorkBudget{})
	if err != nil {
		return SecurityVerifyOutput{}, tkerr.New(tkerr.APIError, "verification could not complete", "")
	}
	out := shapeVerification(env, verified, f.correction.ActionAt, after.Now, f.ref)
	if err := recordVerify(ctx, env, out); err != nil {
		return SecurityVerifyOutput{}, err
	}
	return out, nil
}

func recordVerify(ctx context.Context, env *registry.Env, out SecurityVerifyOutput) error {
	if env == nil || env.RecordPack == nil {
		return tkerr.New(tkerr.AuditUnavailable, "pack audit recording is unavailable", "")
	}
	fixed, notFixed, incomplete, regressed := out.counts()
	return env.RecordPack(ctx, registry.PackRecord{Pack: "verify", Seal: packAuditSeal(out.Seal), Outcome: out.Outcome, Digest: out.Ref, Fixed: &fixed, NotFixed: &notFixed, Incomplete: &incomplete, Regressed: &regressed})
}

func shapeVerification(env *registry.Env, report securitypack.VerificationReport, action, now time.Time, ref string) SecurityVerifyOutput {
	out := SecurityVerifyOutput{Ref: ref, Seal: string(report.Reading.Seal), ActionAt: timeText(action), Outcome: report.Outcome, CatalogChangedOtherRules: report.CatalogChangedOtherRules, NewOtherFindings: report.NewOtherFindings, PolicyCheck: report.PolicyCheck, Statement: report.ScopeSentence}
	for _, r := range report.Targets {
		row := VerifyRow{Kind: r.Kind, Rule: r.RuleID, Expectation: r.ExpectationID, Name: r.Name, Role: string(r.Role), AtLeast: r.AtLeast, Value: r.Value, Outcome: r.Outcome, Reason: r.Reason, MatcherReason: string(r.MatcherReason), Before: r.Before, After: r.After}
		if r.Asset != "" {
			row.Device = maskDeviceID(r.Asset)
			if env.Privacy != nil {
				row.DeviceRef = env.Privacy.APIPseudonym(r.Asset)
			}
		}
		for _, e := range r.Evidence {
			at := e.AcquiredAt
			if e.ObservedAt != nil {
				at = *e.ObservedAt
			}
			age := now.Sub(at)
			if age < 0 {
				age = 0
			}
			row.Evidence = append(row.Evidence, VerifyEvidence{Class: string(e.Origin), AgeSeconds: int64(age / time.Second)})
		}
		for _, l := range r.Limits {
			row.Limits = append(row.Limits, string(l))
		}
		out.Targets = append(out.Targets, row)
	}
	for _, g := range report.Guards {
		row := VerifyGuard{Expectation: g.ExpectationID, Outcome: g.Outcome, Reason: g.Reason, Before: string(g.Before), After: string(g.After)}
		for _, l := range g.Limits {
			row.Limits = append(row.Limits, string(l))
		}
		out.Guards = append(out.Guards, row)
	}
	return out
}
