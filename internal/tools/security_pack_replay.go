package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/safefile"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/securitypack"
)

type SecurityPackInput struct {
	Pack string `json:"pack" tk:"short" jsonschema:"private evidence pack path"`
}
type SecurityRedactInput struct {
	Pack string `json:"pack" tk:"short" jsonschema:"private evidence pack path"`
	Out  string `json:"out,omitempty" tk:"short" jsonschema:"private projection output path"`
}

func (in SecurityRedactInput) Check() error {
	if in.Out == "-" {
		return validationf("projection output cannot be standard output")
	}
	return nil
}
func packLocalMeta(name, verb, summary string) registry.Meta {
	return registry.Meta{Name: name, Area: "security", Verb: verb, Summary: summary, Tier: registry.TierLocal, Stage: registry.StageGA, Credential: registry.CredNone}
}
func SecurityReplayTool() registry.Tool {
	return registry.Define(packLocalMeta("security_replay", "replay", "Replay a private evidence pack; owner command line only."), securityReplay)
}
func SecurityRedactTool() registry.Tool {
	return registry.Define(packLocalMeta("security_redact", "redact", "Write a shareable projection; owner command line only."), securityRedact)
}

type ReplayFreshness struct {
	EvaluatedAt    string `json:"evaluatedAt"`
	ReplayedAt     string `json:"replayedAt"`
	AgeSeconds     int64  `json:"ageSeconds"`
	CatalogState   string `json:"catalogState"`
	StaleReviews   int    `json:"staleReviews"`
	ClockUncertain bool   `json:"clockUncertain"`
}
type ReplayInfo struct {
	Ref         string          `json:"ref,omitempty"`
	Seal        string          `json:"seal"`
	Integrity   string          `json:"integrity"`
	Reproduced  bool            `json:"reproduced"`
	Cause       string          `json:"cause,omitempty"`
	Differences []string        `json:"differences,omitempty" tk:"untrusted"`
	Freshness   ReplayFreshness `json:"freshness"`
}
type ReplayCoverage struct {
	Dimension   string                `json:"dimension"`
	Source      string                `json:"source" tk:"untrusted"`
	Status      string                `json:"status"`
	Explanation string                `json:"explanation,omitempty" tk:"untrusted"`
	Counts      *SecurityScanRowCount `json:"counts,omitempty"`
}
type ReplayEvidence struct {
	Origin     string `json:"origin"`
	AcquiredAt string `json:"acquiredAt"`
	ObservedAt string `json:"observedAt,omitempty"`
	Freshness  string `json:"freshness"`
	Error      string `json:"error,omitempty" tk:"untrusted"`
}
type ReplayFinding struct {
	Rule          string           `json:"rule" tk:"untrusted"`
	RuleRevision  string           `json:"ruleRevision" tk:"untrusted"`
	Device        string           `json:"device" tk:"untrusted"`
	DeviceRef     string           `json:"deviceRef,omitempty"`
	Applicability string           `json:"applicability"`
	Severity      string           `json:"severity"`
	Reason        string           `json:"reason,omitempty"`
	EvidenceState string           `json:"evidenceState"`
	Confidence    string           `json:"confidence"`
	Explanation   string           `json:"explanation" tk:"untrusted"`
	Verification  []string         `json:"verification,omitempty" tk:"untrusted"`
	Evidence      []ReplayEvidence `json:"evidence,omitempty"`
}

// ReplayCatalog describes the catalog embedded in the pack, not the binary's current rules.
type ReplayCatalog struct {
	Revision     uint64 `json:"revision"`
	IssuedAt     string `json:"issuedAt"`
	ExpiresAt    string `json:"expiresAt"`
	Digest       string `json:"digest,omitempty"`
	WithheldNote string `json:"withheldNote,omitempty"`
	Rules        int    `json:"rules"`
	Approved     int    `json:"approved"`
	Pending      int    `json:"pending"`
	Withdrawn    int    `json:"withdrawn"`
}
type ReplayReport struct {
	Status         string                `json:"status"`
	Scope          string                `json:"scope"`
	Threshold      string                `json:"threshold"`
	AtThreshold    SecurityScanThreshold `json:"atThreshold"`
	ObservedAt     string                `json:"observedAt"`
	GeneratedAt    string                `json:"generatedAt"`
	TotalFindings  int                   `json:"totalFindings"`
	Truncated      bool                  `json:"truncated"`
	Counts         SecurityScanCounts    `json:"counts"`
	Catalog        ReplayCatalog         `json:"catalog"`
	IntentDigest   string                `json:"intentDigest,omitempty" tk:"untrusted"`
	IntentRevision string                `json:"intentRevision,omitempty" tk:"untrusted"`
	WithheldNote   string                `json:"withheldNote,omitempty"`
	Coverage       []ReplayCoverage      `json:"coverage"`
	Findings       []ReplayFinding       `json:"findings"`
}
type ReplayAccessRule struct {
	Section     string `json:"section"`
	Index       int    `json:"index"`
	Line        int    `json:"line,omitempty"`
	Column      int    `json:"column,omitempty"`
	Source      string `json:"source" tk:"untrusted,emails"`
	Destination string `json:"destination" tk:"untrusted,emails"`
	Ports       string `json:"ports,omitempty" tk:"untrusted,emails"`
	Broad       bool   `json:"broad,omitempty"`
	Qualified   bool   `json:"qualified,omitempty"`
	AllTraffic  bool   `json:"allTraffic,omitempty"`
	Traffic     string `json:"traffic,omitempty" tk:"untrusted,emails"`
}
type ReplayAccessBlast struct {
	Source      string                 `json:"source" tk:"untrusted,emails"`
	Heading     string                 `json:"heading" tk:"untrusted,emails"`
	Reaches     []SecurityExplainReach `json:"reaches,omitempty"`
	Broad       []ReplayAccessRule     `json:"broad,omitempty"`
	Tags        []string               `json:"tags,omitempty" tk:"untrusted,emails"`
	TagsOmitted int                    `json:"tagsOmitted,omitempty"`
}
type ReplayAccessRow struct {
	ID                string                `json:"id" tk:"untrusted"`
	Kind              string                `json:"kind"`
	Source            string                `json:"source" tk:"untrusted,emails"`
	Status            string                `json:"status"`
	Cells             []SecurityExplainCell `json:"cells,omitempty"`
	Candidates        []ReplayAccessRule    `json:"candidates,omitempty"`
	Limits            []string              `json:"limits,omitempty"`
	PastCap           int                   `json:"pastCap,omitempty"`
	CandidatesOmitted int                   `json:"candidatesOmitted,omitempty"`
}
type ReplayAccess struct {
	Status        string                `json:"status"`
	PolicyVersion string                `json:"policyVersion,omitempty" tk:"untrusted"`
	WithheldNote  string                `json:"withheldNote,omitempty"`
	EvaluatedAt   string                `json:"evaluatedAt,omitempty"`
	Counts        SecurityExplainCounts `json:"counts"`
	PairsJudged   int                   `json:"pairsJudged"`
	PairsPastCap  int                   `json:"pairsPastCap"`
	Expectations  []ReplayAccessRow     `json:"expectations"`
	Omitted       int                   `json:"omitted,omitempty"`
	Blast         []ReplayAccessBlast   `json:"blast,omitempty"`
	Notes         []string              `json:"notes,omitempty" tk:"untrusted"`
}
type SecurityReplayOutput struct {
	Replay     ReplayInfo    `json:"replay" tk:"details"`
	Report     ReplayReport  `json:"report" tk:"details"`
	Access     *ReplayAccess `json:"access,omitempty" tk:"details"`
	Statement  string        `json:"statement" tk:"details"`
	Projection bool          `json:"projection,omitempty"`
}

func (o SecurityReplayOutput) ExitCode() int {
	if !o.Replay.Reproduced {
		return 1
	}
	return 0
}
func (o SecurityReplayOutput) AuditFields() map[string]any {
	outcome := "not_reproduced"
	if o.Replay.Reproduced {
		outcome = "reproduced"
	}
	return map[string]any{"pack": "replay", "seal": packAuditSeal(o.Replay.Seal), "outcome": outcome, "digest": o.Replay.Ref}
}
func (o SecurityReplayOutput) Details() []string {
	if o.Projection {
		return []string{o.Statement}
	}
	f := o.Replay.Freshness
	lines := []string{fmt.Sprintf("pack ref: %s; seal: %s; integrity: %s", o.Replay.Ref, o.Replay.Seal, o.Replay.Integrity), fmt.Sprintf("reproduction: %t; cause: %s", o.Replay.Reproduced, o.Replay.Cause)}
	for _, d := range o.Replay.Differences {
		lines = append(lines, "difference: "+d)
	}
	lines = append(lines, fmt.Sprintf("replay freshness: evaluated %s; replayed %s; age %d seconds; catalog %s; %d stale reviews; clock uncertain: %t", f.EvaluatedAt, f.ReplayedAt, f.AgeSeconds, f.CatalogState, f.StaleReviews, f.ClockUncertain))
	lines = append(lines, replayReportLines(o.Report)...)
	if o.Access != nil {
		lines = append(lines, replayAccessLines(*o.Access)...)
	}
	return append(lines, o.Statement)
}
func replayReportLines(r ReplayReport) []string {
	c := r.Counts
	lines := []string{fmt.Sprintf("%s scan: %s; %d affected, %d potentially affected, %d unknown, %d not affected (%d findings, %d listed)", r.Scope, r.Status, c.Affected, c.PotentiallyAffected, c.Unknown, c.NotAffected, r.TotalFindings, len(r.Findings)), fmt.Sprintf("threshold %s: %d affected and %d potentially affected at or above it", r.Threshold, r.AtThreshold.Affected, r.AtThreshold.PotentiallyAffected)}
	catalog := r.Catalog
	lines = append(lines, fmt.Sprintf("recorded catalog: revision %d, issued %s, expires %s; %d rules (%d approved, %d pending, %d withdrawn); these are the pack's rules", catalog.Revision, catalog.IssuedAt, catalog.ExpiresAt, catalog.Rules, catalog.Approved, catalog.Pending, catalog.Withdrawn))
	if catalog.Digest != "" {
		lines = append(lines, "catalog digest: "+catalog.Digest)
	}
	if catalog.WithheldNote != "" {
		lines = append(lines, catalog.WithheldNote)
	}
	if r.IntentDigest != "" {
		lines = append(lines, fmt.Sprintf("intent: recorded revision %s", r.IntentRevision))
	}
	if r.WithheldNote != "" {
		lines = append(lines, r.WithheldNote)
	}
	for _, c := range r.Coverage {
		lines = append(lines, fmt.Sprintf("coverage %s: %s · %s · %s", c.Dimension, c.Status, c.Source, c.Explanation))
	}
	if r.Truncated {
		lines = append(lines, fmt.Sprintf("output truncated: showing %d of %d findings", len(r.Findings), r.TotalFindings))
	}
	if len(r.Findings) > 0 {
		lines = append(lines, "devices: a device is shown by the start of its node ID; part is always withheld")
	}
	for _, f := range r.Findings {
		lines = append(lines, replayFindingLine(f))
	}
	return lines
}
func replayFindingLine(f ReplayFinding) string {
	device := f.Device
	if f.DeviceRef != "" {
		device += " " + f.DeviceRef
	}
	parts := []string{f.Rule, device, f.Applicability, "severity " + f.Severity}
	if f.Reason != "" {
		parts = append(parts, "reason "+f.Reason)
	}
	parts = append(parts, f.Explanation)
	if len(f.Verification) > 0 {
		parts = append(parts, "verify: "+strings.Join(f.Verification, "; "))
	}
	return strings.Join(parts, " · ")
}
func replayAccessLines(a ReplayAccess) []string {
	v := SecurityExplainOutput{Status: a.Status, PolicyVersion: a.PolicyVersion, EvaluatedAt: a.EvaluatedAt, Counts: a.Counts, PairsJudged: a.PairsJudged, PairsPastCap: a.PairsPastCap, Omitted: a.Omitted, Notes: a.Notes}
	for _, e := range a.Expectations {
		v.Expectations = append(v.Expectations, SecurityExplainRow{ID: e.ID, Kind: e.Kind, Source: e.Source, Status: e.Status, Cells: e.Cells, Candidates: explainReplayRules(e.Candidates), Limits: e.Limits, PastCap: e.PastCap, CandidatesOmitted: e.CandidatesOmitted})
	}
	for _, b := range a.Blast {
		v.Blast = append(v.Blast, SecurityExplainBlast{Source: b.Source, Heading: b.Heading, Reaches: b.Reaches, Broad: explainReplayRules(b.Broad), Tags: b.Tags, TagsOmitted: b.TagsOmitted})
	}
	rep := v.Report()
	lines := []string{"recorded access explanation:", rep.Verdict}
	if a.WithheldNote != "" {
		lines = append(lines, a.WithheldNote)
	}
	for _, f := range rep.Facts {
		lines = append(lines, f.Label+": "+f.Text)
	}
	for _, f := range rep.Findings {
		lines = append(lines, f.Message)
	}
	return lines
}

func packAuditSeal(s string) string {
	if s == "valid" {
		return "keyed"
	}
	return s
}

// recordedToken accepts only tokens validated by securitypack pack validators:
// quoted 64-hex plain tokens or checked-prefix plus 64-hex tokens. Callers must
// preserve that validation boundary.
func recordedToken(env *registry.Env, token string, isPolicy bool) (string, string) {
	if token == "" {
		return "", ""
	}
	keyed := strings.HasPrefix(token, "hmac-sha256:")
	plain := strings.HasPrefix(token, "sha256:") || isPolicy && !keyed
	if env.ShowPersonalData() && plain || !env.ShowPersonalData() && env.Privacy != nil && keyed {
		if strings.HasPrefix(token, "hmac-sha256:") {
			return "hmac-sha256:" + token[len("hmac-sha256:"):len("hmac-sha256:")+12], ""
		}
		if strings.HasPrefix(token, "sha256:") {
			return "sha256:" + token[len("sha256:"):len("sha256:")+12], ""
		}
		return token[:13] + "…", ""
	}
	return "", "recorded token withheld under the current privacy setting"
}
func replayCatalog(env *registry.Env, c securitypack.CatalogSummary) ReplayCatalog {
	out := ReplayCatalog{Revision: c.Revision, IssuedAt: timeText(c.IssuedAt), ExpiresAt: timeText(c.ExpiresAt), Rules: c.Rules, Approved: c.Approved, Pending: c.Pending, Withdrawn: c.Withdrawn}
	public, err := advisory.Shipped()
	if err == nil && c.Digest == public.Digest {
		out.Digest = c.Digest
		return out
	}
	if env.ShowPersonalData() && len(c.Digest) >= 12 {
		out.Digest = c.Digest[:12]
	} else if c.Digest != "" {
		out.WithheldNote = "recorded catalog digest withheld under the current privacy setting"
	}
	return out
}
func shapeReplayReport(env *registry.Env, r security.Report, catalog securitypack.CatalogSummary) (ReplayReport, error) {
	listed, err := security.Truncate(r, scanFindingLimit)
	if err != nil {
		return ReplayReport{}, err
	}
	hits, err := security.CountAtThreshold(r.Findings, security.Severity(defaultScanThreshold))
	if err != nil {
		return ReplayReport{}, err
	}
	out := ReplayReport{Status: string(r.Status), Scope: string(r.Snapshot.Scope), Threshold: defaultScanThreshold, AtThreshold: SecurityScanThreshold{Affected: hits.Affected, PotentiallyAffected: hits.Potential}, ObservedAt: timeText(r.Snapshot.ObservedAt), GeneratedAt: timeText(r.GeneratedAt), TotalFindings: r.TotalFindings, Truncated: listed.Truncated, Counts: countFindings(r.Findings), Catalog: replayCatalog(env, catalog)}
	out.IntentDigest, out.WithheldNote = recordedToken(env, r.IntentDigest, false)
	if out.IntentDigest != "" {
		out.IntentRevision = r.IntentRevision
	}
	for _, c := range listed.Coverage {
		row := ReplayCoverage{Dimension: string(c.Target.Dimension), Source: c.Source, Status: string(c.Status), Explanation: c.Explanation}
		if c.Counts != nil {
			row.Counts = &SecurityScanRowCount{Rules: c.Counts.Rules, Withdrawn: c.Counts.Withdrawn, Devices: c.Counts.Assets, Findings: c.Counts.Findings, Unknown: c.Counts.Unknown, PotentiallyAffected: c.Counts.Potential}
		}
		out.Coverage = append(out.Coverage, row)
	}
	for _, f := range listed.Findings {
		row := ReplayFinding{Rule: f.RuleID, RuleRevision: f.RuleRevision, Device: maskDeviceID(f.Asset), Applicability: string(f.Applicability), Severity: string(f.SourceSeverity), Reason: string(f.Reason), EvidenceState: string(f.EvidenceState), Confidence: string(f.Confidence), Explanation: f.Explanation, Verification: append([]string(nil), f.Verification...)}
		if env.Privacy != nil {
			row.DeviceRef = env.Privacy.APIPseudonym(f.Asset)
		}
		for _, e := range f.Evidence {
			item := ReplayEvidence{Origin: string(e.Origin), AcquiredAt: timeText(e.AcquiredAt), Freshness: string(e.Freshness), Error: e.Error}
			if e.ObservedAt != nil {
				item.ObservedAt = timeText(*e.ObservedAt)
			}
			row.Evidence = append(row.Evidence, item)
		}
		out.Findings = append(out.Findings, row)
	}
	return out, nil
}
func shapeReplayAccess(env *registry.Env, r *security.AccessReport) *ReplayAccess {
	if r == nil {
		return nil
	}
	v := shapeExplain(*r, SecurityExplainIntent{})
	o := &ReplayAccess{Status: v.Status, EvaluatedAt: v.EvaluatedAt, Counts: v.Counts, PairsJudged: v.PairsJudged, PairsPastCap: v.PairsPastCap, Omitted: v.Omitted, Notes: v.Notes}
	o.PolicyVersion, o.WithheldNote = recordedToken(env, r.PolicyVersion, true)
	for _, e := range v.Expectations {
		o.Expectations = append(o.Expectations, ReplayAccessRow{ID: e.ID, Kind: e.Kind, Source: e.Source, Status: e.Status, Cells: e.Cells, Candidates: replayRules(e.Candidates), Limits: e.Limits, PastCap: e.PastCap, CandidatesOmitted: e.CandidatesOmitted})
	}
	for _, b := range v.Blast {
		o.Blast = append(o.Blast, ReplayAccessBlast{Source: b.Source, Heading: b.Heading, Reaches: b.Reaches, Broad: replayRules(b.Broad), Tags: b.Tags, TagsOmitted: b.TagsOmitted})
	}
	return o
}
func replayRules(in []SecurityExplainRule) []ReplayAccessRule {
	var out []ReplayAccessRule
	for _, r := range in {
		out = append(out, ReplayAccessRule(r))
	}
	return out
}
func explainReplayRules(in []ReplayAccessRule) []SecurityExplainRule {
	var out []SecurityExplainRule
	for _, r := range in {
		out = append(out, SecurityExplainRule(r))
	}
	return out
}
func readPack(path string, env *registry.Env) (securitypack.EvidencePack, securitypack.Reading, error) {
	data, err := safefile.ReadPrivate(path)
	if err != nil {
		return securitypack.EvidencePack{}, securitypack.Reading{}, err
	}
	return securitypack.Decode(data, packSealer(env))
}

const projectionRefusal = "This is a redacted projection. It records conclusions made from a private evidence pack and does not carry the facts they rest on, so none of them can be reproduced from this file. Only the owner of the private pack can replay it. A projection is not evidence that its conclusions are true."

func securityReplay(ctx context.Context, env *registry.Env, in SecurityPackInput) (SecurityReplayOutput, error) {
	if err := packPlatform(); err != nil {
		return SecurityReplayOutput{}, err
	}
	if err := packPrivacyError(env); err != nil {
		return SecurityReplayOutput{}, err
	}
	pack, reading, err := readPack(in.Pack, env)
	if errors.Is(err, securitypack.ErrProjectionNotReplayable) {
		return SecurityReplayOutput{Projection: true, Statement: projectionRefusal}, nil
	}
	if err != nil {
		return SecurityReplayOutput{}, packCodecError(err)
	}
	replayed, err := securitypack.Replay(ctx, pack, security.WorkBudget{})
	if err != nil {
		return SecurityReplayOutput{}, packCodecError(err)
	}
	ref, err := securitypack.Reference(pack, packSealer(env), env.ShowPersonalData())
	if err != nil {
		return SecurityReplayOutput{}, packCodecError(err)
	}
	f := securitypack.ReplayFreshness(pack, env.Clock())
	report, err := shapeReplayReport(env, replayed.Report, replayed.CatalogSummary())
	if err != nil {
		return SecurityReplayOutput{}, packCodecError(err)
	}
	return SecurityReplayOutput{Replay: ReplayInfo{Ref: ref, Seal: string(reading.Seal), Integrity: "valid", Reproduced: replayed.Reproduction.Status == "reproduced", Cause: replayed.Reproduction.Cause, Differences: replayed.Reproduction.Differences, Freshness: ReplayFreshness{EvaluatedAt: timeText(f.EvaluatedAt), ReplayedAt: timeText(f.ReplayedAt), AgeSeconds: int64(f.Age.Seconds()), CatalogState: string(f.CatalogState), StaleReviews: f.StaleReviews, ClockUncertain: f.ClockUncertain}}, Report: report, Access: shapeReplayAccess(env, replayed.AccessReport), Statement: securitypack.ScopeSentence}, nil
}
func publicPackCatalog() (securitypack.PublicCatalog, error) {
	c, err := advisory.Shipped()
	if err != nil {
		return securitypack.PublicCatalog{}, err
	}
	out := securitypack.PublicCatalog{Digest: c.Digest}
	for _, r := range c.Records {
		out.Rules = append(out.Rules, securitypack.PublicRule{ID: r.ID, Revision: r.Revision})
	}
	return out, nil
}
func securityRedact(ctx context.Context, env *registry.Env, in SecurityRedactInput) (SecurityPackSummary, error) {
	if err := packPlatform(); err != nil {
		return SecurityPackSummary{}, err
	}
	if err := packPrivacyError(env); err != nil {
		return SecurityPackSummary{}, err
	}
	pack, reading, err := readPack(in.Pack, env)
	if err != nil {
		return SecurityPackSummary{}, packCodecError(err)
	}
	ref, err := securitypack.Reference(pack, packSealer(env), env.ShowPersonalData())
	if err != nil {
		return SecurityPackSummary{}, packCodecError(err)
	}
	public, err := publicPackCatalog()
	if err != nil {
		return SecurityPackSummary{}, packCodecError(err)
	}
	projection, err := securitypack.Project(ctx, pack, security.WorkBudget{}, public, ref)
	if err != nil {
		return SecurityPackSummary{}, packCodecError(err)
	}
	data, err := securitypack.EncodeProjection(projection)
	if err != nil {
		return SecurityPackSummary{}, packCodecError(err)
	}
	path, err := packOutputPath(env, in.Out, "tailkeeper-projection-")
	if err != nil {
		return SecurityPackSummary{}, err
	}
	if err := safefile.WritePrivate(path, data, nil); err != nil {
		return SecurityPackSummary{}, packWriteError(err, in.Out == "")
	}
	return SecurityPackSummary{Path: path, Bytes: int64(len(data)), Ref: ref, Seal: packSealWord(reading.Seal), Outcome: "reproduced", Pack: "redact", Statement: "Projection written; its conclusions cannot be replayed."}, nil
}
