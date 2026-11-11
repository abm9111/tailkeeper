package securitypack

import (
	"bytes"
	"context"
	"errors"
	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/security"
	"slices"
	"time"
)

var (
	ErrTargetUnknown             = errors.New("target_unknown")
	ErrTargetNotOpen             = errors.New("target_not_open")
	ErrDeviceNotInPack           = errors.New("device_not_in_pack")
	ErrExpectationNotSelected    = errors.New("expectation_not_selected")
	ErrActionNotAfterObservation = errors.New("action_not_after_observation")
	ErrActionInFuture            = errors.New("action_in_future")
	ErrContextMismatch           = errors.New("context_mismatch")
)

type PreparedCorrection struct{ replay Replayed }

func (p PreparedCorrection) Scope() security.Scope { return p.replay.inputs.Snapshot.Scope }
func (p PreparedCorrection) Context() string       { return p.replay.inputs.Snapshot.Context }
func (p PreparedCorrection) AccessContext() string {
	if p.replay.inputs.Access == nil {
		return ""
	}
	return p.replay.inputs.Access.Context
}
func (p PreparedCorrection) Selected() []string {
	if p.replay.inputs.Access == nil {
		return nil
	}
	return slices.Clone(p.replay.inputs.Access.Selected)
}

func PrepareCorrection(ctx context.Context, before EvidencePack, c security.CorrectionIntent, budget security.WorkBudget) (PreparedCorrection, error) {
	if err := ValidateCorrection(c); err != nil {
		return PreparedCorrection{}, err
	}
	r, err := Replay(ctx, before, budget)
	if err != nil {
		return PreparedCorrection{}, err
	}
	if r.Reproduction.Status != "reproduced" {
		return PreparedCorrection{}, ErrNotReproduced
	}
	if err := preflightFindings(r, c); err != nil {
		return PreparedCorrection{}, err
	}
	if err := preflightFacts(ctx, r.inputs, c, budget); err != nil {
		return PreparedCorrection{}, err
	}
	if err := preflightAccess(r, c); err != nil {
		return PreparedCorrection{}, err
	}
	if err := preflightTimes(r.inputs, c); err != nil {
		return PreparedCorrection{}, err
	}
	return PreparedCorrection{replay: r}, nil
}
func preflightFindings(r Replayed, c security.CorrectionIntent) error {
	pi := r.inputs
	for _, target := range c.Findings {
		f, ok := finding(r.Report.Findings, security.FindingID(pi.Snapshot.Context, pi.Snapshot.Scope, target.Asset, target.RuleID))
		if !ok {
			return ErrTargetUnknown
		}
		if f.Applicability == security.ApplicabilityNotAffected {
			return ErrTargetNotOpen
		}
	}
	return nil
}
func preflightFacts(ctx context.Context, pi packInput, c security.CorrectionIntent, budget security.WorkBudget) error {
	for _, v := range c.Versions {
		if !hasAsset(pi.Snapshot, v.Asset) {
			return ErrDeviceNotInPack
		}
		j, err := security.JudgeVersion(ctx, pi.Snapshot, pi.EvaluationAt, v.Asset, v.Name, v.Role, v.AtLeast, budget)
		if err != nil {
			return err
		}
		if j.Verdict == security.FactSatisfied {
			return ErrTargetNotOpen
		}
	}
	for _, v := range c.Features {
		if !hasAsset(pi.Snapshot, v.Asset) {
			return ErrDeviceNotInPack
		}
		j, err := security.JudgeFeature(ctx, pi.Snapshot, pi.EvaluationAt, v.Asset, v.Name, v.Role, v.Value, budget)
		if err != nil {
			return err
		}
		if j.Verdict == security.FactSatisfied {
			return ErrTargetNotOpen
		}
	}
	return nil
}
func preflightAccess(r Replayed, c security.CorrectionIntent) error {
	pi := r.inputs
	for _, id := range c.ExpectationIDs {
		if pi.Access == nil || !slices.Contains(pi.Access.Selected, id) {
			return ErrExpectationNotSelected
		}
		j, ok := judgement(r.AccessJudgements, id)
		if !ok {
			return ErrInvalidPack
		}
		if j.Status == security.AccessMet {
			return ErrTargetNotOpen
		}
	}
	return nil
}
func preflightTimes(pi packInput, c security.CorrectionIntent) error {
	latest := pi.EvaluationAt
	if pi.Snapshot.ObservedAt.After(latest) {
		latest = pi.Snapshot.ObservedAt
	}
	visitEvidence(pi.Snapshot, func(e security.EvidenceRef) {
		if e.AcquiredAt.After(latest) {
			latest = e.AcquiredAt
		}
		if e.ObservedAt != nil && e.ObservedAt.After(latest) {
			latest = *e.ObservedAt
		}
	})
	if pi.Access != nil && pi.Access.Input.EvaluatedAt.After(latest) {
		latest = pi.Access.Input.EvaluatedAt
	}
	if !c.ActionAt.After(latest) {
		return ErrActionNotAfterObservation
	}
	return nil
}

func finding(rows []security.Finding, id string) (security.Finding, bool) {
	for _, row := range rows {
		if row.ID == id {
			return row, true
		}
	}
	return security.Finding{}, false
}
func judgement(rows []security.AccessJudgement, id string) (security.AccessJudgement, bool) {
	for _, row := range rows {
		if row.ID == id {
			return row, true
		}
	}
	return security.AccessJudgement{}, false
}
func visitEvidence(s security.Snapshot, fn func(security.EvidenceRef)) {
	for _, f := range s.Versions {
		fn(f.Evidence)
	}
	for _, f := range s.Platforms {
		fn(f.Evidence)
	}
	for _, f := range s.Features {
		fn(f.Evidence)
	}
	for _, f := range s.Policies {
		fn(f.Evidence)
	}
}
func hasAsset(s security.Snapshot, asset string) bool {
	found := false
	visitEvidence(s, func(e security.EvidenceRef) {
		if e.Asset == asset {
			found = true
		}
	})
	return found
}
func postEvidence(e []security.EvidenceRef, at time.Time) bool {
	for _, ref := range e {
		observed := ref.AcquiredAt
		if ref.ObservedAt != nil {
			observed = *ref.ObservedAt
		}
		if !observed.After(at) {
			return false
		}
	}
	return true
}

func guardOutcome(before, after security.AccessJudgement) string {
	confirmed := before.Status == security.AccessMet || before.Status == security.AccessMetWithLimits
	switch after.Status {
	case security.AccessUnmet:
		if confirmed {
			return "regressed"
		}
		return "still_unmet"
	case security.AccessUnknown, security.AccessNotEvaluated:
		if confirmed {
			return "unconfirmed"
		}
		return "unchanged_unconfirmed"
	case security.AccessMetWithLimits:
		return guardLimited(before, after)
	case security.AccessMet:
		if before.Status == security.AccessMet {
			return "held"
		}
		if before.Status == security.AccessMetWithLimits {
			return "limits_changed"
		}
		return "improved"
	default:
		return "access_judgement_missing"
	}
}

func guardLimited(before, after security.AccessJudgement) string {
	if before.Status == security.AccessMet {
		return "limits_changed"
	}
	if before.Status == security.AccessMetWithLimits {
		for _, limit := range after.Limits {
			found := false
			for _, old := range before.Limits {
				if old == limit {
					found = true
					break
				}
			}
			if !found {
				return "limits_changed"
			}
		}
		if len(before.Limits) == len(after.Limits) {
			return "unchanged"
		}
		return "limits_changed"
	}
	return "improved"
}

type AfterEvidence struct {
	Snapshot       security.Snapshot
	Collected      []security.Coverage
	Now            time.Time
	Catalog        security.Catalog
	CatalogSources []advisory.Source
	Intent         *security.IntentSet
	Access         *AfterAccess
}
type AfterAccess struct {
	Context   string
	StartedAt time.Time
	Input     security.AccessInput
}
type VerificationRow struct {
	Role                                                                     security.VersionRole
	AtLeast                                                                  string
	Value                                                                    *bool
	Kind, RuleID, Asset, ExpectationID, Name, Outcome, Reason, Before, After string
	MatcherReason                                                            security.UnknownReason
	Evidence                                                                 []security.EvidenceRef
	Limits                                                                   []security.AccessLimit
}
type VerificationGuard struct {
	ExpectationID, Outcome, Reason string
	Before, After                  security.AccessStatus
	Limits                         []security.AccessLimit
}
type VerificationReport struct {
	Outcome                  string
	Targets                  []VerificationRow
	Guards                   []VerificationGuard
	Reading                  Reading
	ScopeSentence            string
	CatalogChangedOtherRules bool
	NewOtherFindings         int
	PolicyCheck              string
}

func VerifyCorrection(ctx context.Context, before EvidencePack, c security.CorrectionIntent, after AfterEvidence, budget security.WorkBudget) (VerificationReport, error) {
	p, err := PrepareCorrection(ctx, before, c, budget)
	if err != nil {
		return VerificationReport{}, err
	}
	report, err := evaluateAfter(ctx, p, c, after, budget)
	if err != nil {
		return VerificationReport{}, err
	}
	out := VerificationReport{Reading: p.replay.Reading, ScopeSentence: ScopeSentence}
	out.CatalogChangedOtherRules, out.NewOtherFindings = catalogChanges(p.replay.catalog, after.Catalog, p.replay.Report.Findings, report.Findings, c.Findings)
	appendFindingRows(&out, p, c, after, report)
	if err := appendVersionRows(ctx, &out, p, c, after, budget); err != nil {
		return VerificationReport{}, err
	}
	if err := appendFeatureRows(ctx, &out, p, c, after, budget); err != nil {
		return VerificationReport{}, err
	}
	if err := judgeAccess(ctx, &out, p, c, after); err != nil {
		return VerificationReport{}, err
	}
	if err := ctx.Err(); err != nil {
		return VerificationReport{}, err
	}
	out.Outcome = overall(out.Targets, out.Guards, p.replay.Reading)
	return out, nil
}
func evaluateAfter(ctx context.Context, p PreparedCorrection, c security.CorrectionIntent, after AfterEvidence, budget security.WorkBudget) (security.Report, error) {
	if c.ActionAt.After(after.Now.Add(5 * time.Minute)) {
		return security.Report{}, ErrActionInFuture
	}
	old := p.replay.inputs.Snapshot
	if old.Scope != after.Snapshot.Scope || old.Context != after.Snapshot.Context {
		return security.Report{}, ErrContextMismatch
	}
	if len(after.CatalogSources) > maxCatalogSources {
		return security.Report{}, ErrTooLarge
	}
	total := 0
	for _, source := range after.CatalogSources {
		if len(source.Data) > maxCatalogBytes-total {
			return security.Report{}, ErrTooLarge
		}
		total += len(source.Data)
	}
	merged, err := advisory.Merge(after.CatalogSources)
	if err != nil || !sameCatalog(merged, after.Catalog) {
		return security.Report{}, ErrCatalogMismatch
	}
	report, err := security.Evaluate(ctx, security.Input{Catalog: after.Catalog, Snapshot: after.Snapshot, Collected: after.Collected, Now: after.Now, Intent: after.Intent, Budget: budget})
	if err != nil {
		return security.Report{}, err
	}
	if security.StoppedEarly(report) {
		return security.Report{}, ErrStoppedEarly
	}
	return report, nil
}
func appendFindingRows(out *VerificationReport, p PreparedCorrection, c security.CorrectionIntent, after AfterEvidence, report security.Report) {
	old := p.replay.inputs.Snapshot
	for _, target := range c.Findings {
		id := security.FindingID(old.Context, old.Scope, target.Asset, target.RuleID)
		b, _ := finding(p.replay.Report.Findings, id)
		a, ok := finding(report.Findings, id)
		row := VerificationRow{Kind: "finding", RuleID: target.RuleID, Asset: target.Asset, Before: string(b.Applicability)}
		switch {
		case !ok:
			row.Outcome, row.Reason = "incomplete", "target_missing_after"
		case a.Applicability == security.ApplicabilityAffected || a.Applicability == security.ApplicabilityPotential:
			row.Outcome = "not_fixed"
		case a.Applicability == security.ApplicabilityUnknown:
			row.Outcome, row.Reason = "incomplete", "finding_unknown"
		case !sameRule(p.replay.catalog, after.Catalog, target.RuleID):
			row.Outcome, row.Reason = "incomplete", "rules_changed"
		default:
			row.Outcome = "fixed"
		}
		if ok {
			row.After = string(a.Applicability)
			row.MatcherReason = a.Reason
			row.Evidence = slices.Clone(a.Evidence)
		}
		capRow(&row, old, after.Snapshot, c.ActionAt, p.replay.Reading)
		out.Targets = append(out.Targets, row)
	}
}
func appendVersionRows(ctx context.Context, out *VerificationReport, p PreparedCorrection, c security.CorrectionIntent, after AfterEvidence, budget security.WorkBudget) error {
	old := p.replay.inputs.Snapshot
	for _, target := range c.Versions {
		b, err := security.JudgeVersion(ctx, old, p.replay.inputs.EvaluationAt, target.Asset, target.Name, target.Role, target.AtLeast, budget)
		if err != nil {
			return err
		}
		a, err := security.JudgeVersion(ctx, after.Snapshot, after.Now, target.Asset, target.Name, target.Role, target.AtLeast, budget)
		if err != nil {
			return err
		}
		row := factRow("version", target.Asset, target.Name, b, a)
		row.Role, row.AtLeast = target.Role, target.AtLeast
		if row.Role == "" {
			row.Role = security.VersionRunningDaemon
		}
		capRow(&row, old, after.Snapshot, c.ActionAt, p.replay.Reading)
		out.Targets = append(out.Targets, row)
	}
	return nil
}
func appendFeatureRows(ctx context.Context, out *VerificationReport, p PreparedCorrection, c security.CorrectionIntent, after AfterEvidence, budget security.WorkBudget) error {
	old := p.replay.inputs.Snapshot
	for _, target := range c.Features {
		b, err := security.JudgeFeature(ctx, old, p.replay.inputs.EvaluationAt, target.Asset, target.Name, target.Role, target.Value, budget)
		if err != nil {
			return err
		}
		a, err := security.JudgeFeature(ctx, after.Snapshot, after.Now, target.Asset, target.Name, target.Role, target.Value, budget)
		if err != nil {
			return err
		}
		row := factRow("feature", target.Asset, target.Name, b, a)
		row.Role, row.Value = target.Role, ownedBool(&target.Value)
		if row.Role == "" {
			row.Role = security.VersionRunningDaemon
		}
		capRow(&row, old, after.Snapshot, c.ActionAt, p.replay.Reading)
		out.Targets = append(out.Targets, row)
	}
	return nil
}
func factRow(kind, asset, name string, b, a security.FactJudgement) VerificationRow {
	r := VerificationRow{Kind: kind, Asset: asset, Name: name, Before: string(b.Verdict), After: string(a.Verdict), MatcherReason: a.Reason, Evidence: slices.Clone(a.Evidence)}
	switch a.Verdict {
	case security.FactSatisfied:
		r.Outcome = "fixed"
	case security.FactContradicted:
		r.Outcome = "not_fixed"
	default:
		r.Outcome, r.Reason = "incomplete", "unobserved"
	}
	return r
}
func capRow(row *VerificationRow, before, after security.Snapshot, action time.Time, reading Reading) {
	if row.Outcome != "fixed" {
		return
	}
	switch {
	case !after.ObservedAt.After(action) || !postEvidence(row.Evidence, action):
		row.Outcome, row.Reason = "incomplete", "evidence_not_after_action"
	case before.KeyEpoch != after.KeyEpoch:
		row.Outcome, row.Reason = "incomplete", "epoch_mismatch"
	case before.Scope != security.ScopeFleet || before.Context == security.ContextLocalOnly:
		row.Outcome, row.Reason = "incomplete", "context_identity_unavailable"
	case reading.Seal == SealAbsentKeyLoaded:
		row.Outcome, row.Reason = "incomplete", "before_unsealed_key_loaded"
	}
}
func overall(targets []VerificationRow, guards []VerificationGuard, reading Reading) string {
	incomplete := len(targets) == 0 || reading.Seal == SealAbsentKeyLoaded
	for _, r := range targets {
		if r.Outcome == "not_fixed" {
			return "not_fixed"
		}
		if r.Outcome != "fixed" {
			incomplete = true
		}
	}
	for _, g := range guards {
		if g.Outcome == "regressed" || g.Outcome == "still_unmet" {
			return "not_fixed"
		}
		switch g.Outcome {
		case "held", "improved", "unchanged", "unchanged_unconfirmed":
		default:
			incomplete = true
		}
	}
	if incomplete {
		return "incomplete"
	}
	return "fixed"
}

func sameRule(a, b security.Catalog, id string) bool {
	var left, right *security.AdvisoryRecord
	for i := range a.Records {
		if a.Records[i].ID == id {
			left = &a.Records[i]
			break
		}
	}
	for i := range b.Records {
		if b.Records[i].ID == id {
			right = &b.Records[i]
			break
		}
	}
	return left != nil && right != nil && sameRecord(*left, *right)
}
func sameInstant(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
func sameRecord(a, b security.AdvisoryRecord) bool {
	return sameRecordRule(a, b) && sameRecordReview(a, b)
}
func sameRecordRule(a, b security.AdvisoryRecord) bool {
	return a.ID == b.ID && a.Revision == b.Revision && a.Component == b.Component && a.VersionRole == b.VersionRole && a.OS == b.OS && slices.Equal(a.Ranges, b.Ranges) && slices.Equal(a.RequiredFeatures, b.RequiredFeatures) && a.Source == b.Source && a.Severity == b.Severity
}
func sameRecordReview(a, b security.AdvisoryRecord) bool {
	return sameInstant(a.PublishedAt, b.PublishedAt) && sameInstant(a.UpdatedAt, b.UpdatedAt) && a.ReviewedAt.Equal(b.ReviewedAt) && a.ReviewExpiresAt.Equal(b.ReviewExpiresAt) && sameInstant(a.SourceCheckedAt, b.SourceCheckedAt) && a.ReviewState == b.ReviewState && a.Mitigation == b.Mitigation
}
func sameCatalog(a, b security.Catalog) bool {
	if a.SchemaVersion != b.SchemaVersion || a.Revision != b.Revision || !a.IssuedAt.Equal(b.IssuedAt) || !a.ExpiresAt.Equal(b.ExpiresAt) || a.Digest != b.Digest || len(a.Records) != len(b.Records) {
		return false
	}
	for i := range a.Records {
		if !sameRecord(a.Records[i], b.Records[i]) {
			return false
		}
	}
	return true
}

func (p PreparedCorrection) CompatibleIntent(current *security.IntentSet) (*security.IntentSet, []string) {
	return p.compatibleIntent(context.Background(), current)
}
func (p PreparedCorrection) compatibleIntent(ctx context.Context, current *security.IntentSet) (*security.IntentSet, []string) {
	if p.replay.inputs.Access == nil {
		return nil, nil
	}
	selected := p.replay.inputs.Access.Selected
	if current == nil || current.SchemaVersion != security.SchemaVersion {
		return nil, slices.Clone(selected)
	}
	baseline, ok := intentIndex(ctx, p.replay.inputs.Access.Input.Intent)
	currentIndex, ok2 := intentIndex(ctx, *current)
	if !ok || !ok2 {
		return nil, slices.Clone(selected)
	}
	result := &security.IntentSet{SchemaVersion: current.SchemaVersion}
	var changed []string
	for _, id := range selected {
		if ctx.Err() != nil {
			return nil, slices.Clone(selected)
		}
		x, xok := baseline[id]
		y, yok := currentIndex[id]
		if !xok || !yok || !bytes.Equal(x, y) {
			changed = append(changed, id)
			continue
		}
		// Intent lists are visited once below, preserving their native order.
	}
	selectCompatible(ctx, result, current, selected, changed)
	wire, err := intentToPack(result, "")
	if err != nil {
		return nil, slices.Clone(selected)
	}
	clone, _, err := intentFromPack(wire)
	if err != nil {
		return nil, slices.Clone(selected)
	}
	return clone, changed
}
func selectCompatible(ctx context.Context, result *security.IntentSet, current *security.IntentSet, selected, changed []string) {
	changedSet := make(map[string]bool, len(changed))
	for _, id := range changed {
		if ctx.Err() != nil {
			return
		}
		changedSet[id] = true
	}
	selectedSet := make(map[string]bool, len(selected))
	for _, id := range selected {
		if ctx.Err() != nil {
			return
		}
		selectedSet[id] = true
	}
	for _, n := range current.Network {
		if ctx.Err() != nil {
			return
		}
		if selectedSet[n.ID] && !changedSet[n.ID] {
			result.Network = append(result.Network, n)
		}
	}
	for _, v := range current.SSH {
		if ctx.Err() != nil {
			return
		}
		if selectedSet[v.ID] && !changedSet[v.ID] {
			result.SSH = append(result.SSH, v)
		}
	}
}
func intentIndex(ctx context.Context, in security.IntentSet) (map[string][]byte, bool) {
	if !intentWithinBounds(ctx, in) || len(in.Network) > security.MaxObservations || len(in.SSH) > security.MaxObservations-len(in.Network) {
		return nil, false
	}
	index := make(map[string][]byte, len(in.Network)+len(in.SSH))
	for _, n := range in.Network {
		if ctx.Err() != nil {
			return nil, false
		}
		one := security.IntentSet{Network: []security.NetworkExpectation{n}}
		v, ok := intentEntry(one, n.ID)
		if !ok {
			return nil, false
		}
		if _, exists := index[n.ID]; exists {
			return nil, false
		}
		index[n.ID] = v
	}
	for _, v := range in.SSH {
		if ctx.Err() != nil {
			return nil, false
		}
		one := security.IntentSet{SSH: []security.SSHExpectation{v}}
		encoded, ok := intentEntry(one, v.ID)
		if !ok {
			return nil, false
		}
		if _, exists := index[v.ID]; exists {
			return nil, false
		}
		index[v.ID] = encoded
	}
	return index, true
}
func intentEntry(in security.IntentSet, id string) ([]byte, bool) {
	var one security.IntentSet
	one.SchemaVersion = security.SchemaVersion
	count := 0
	for _, v := range in.Network {
		if v.ID == id {
			one.Network = append(one.Network, v)
			count++
		}
	}
	for _, v := range in.SSH {
		if v.ID == id {
			one.SSH = append(one.SSH, v)
			count++
		}
	}
	if count != 1 {
		return nil, false
	}
	wire, err := intentToPack(&one, "")
	if err != nil {
		return nil, false
	}
	var buf bytes.Buffer
	enc := newCanonEncoder(&buf, MaxCanonBytes)
	if writePackIntent(enc, *wire) != nil || enc.finish(false) != nil {
		return nil, false
	}
	return buf.Bytes(), true
}
func sameIntentSet(ctx context.Context, a, b security.IntentSet) bool {
	if a.SchemaVersion != security.SchemaVersion || b.SchemaVersion != security.SchemaVersion {
		return false
	}
	left, ok := intentIndex(ctx, a)
	right, ok2 := intentIndex(ctx, b)
	if !ok || !ok2 || len(left) != len(right) {
		return false
	}
	for id, v := range left {
		other, exists := right[id]
		if !exists || !bytes.Equal(v, other) {
			return false
		}
	}
	return true
}
func judgeAccess(ctx context.Context, out *VerificationReport, p PreparedCorrection, c security.CorrectionIntent, after AfterEvidence) error {
	prior := p.replay.inputs.Access
	if prior == nil {
		return nil
	}
	compatible, changed := p.compatibleIntent(ctx, after.Intent)
	if err := ctx.Err(); err != nil {
		return err
	}
	trust := accessTrust(ctx, prior, c, after, compatible)
	var judgments []security.AccessJudgement
	if trust == "" {
		_, j, err := security.JudgeAccess(after.Access.Input)
		if err != nil {
			trust = "access_input_mismatch"
		} else {
			judgments = j
		}
	}
	unchanged := accessPolicy(out, p, prior, after, trust)
	changedSet := make(map[string]bool, len(changed))
	for _, id := range changed {
		changedSet[id] = true
	}
	targetSet := make(map[string]bool, len(c.ExpectationIDs))
	for _, id := range c.ExpectationIDs {
		targetSet[id] = true
	}
	beforeIndex := indexJudgements(p.replay.AccessJudgements)
	afterIndex := indexJudgements(judgments)
	for _, id := range prior.Selected {
		if err := ctx.Err(); err != nil {
			return err
		}
		reason := trust
		if after.Intent != nil && changedSet[id] {
			reason = "intent_changed"
		}
		before, bok := beforeIndex[id]
		current, aok := afterIndex[id]
		if reason == "" && (!bok || !aok) {
			reason = "access_judgement_missing"
		}
		if targetSet[id] {
			out.Targets = append(out.Targets, accessTarget(id, reason, before, current, unchanged, p, after))
		} else {
			out.Guards = append(out.Guards, accessGuard(id, reason, before, current))
		}
	}
	return ctx.Err()
}
func indexJudgements(rows []security.AccessJudgement) map[string]security.AccessJudgement {
	out := make(map[string]security.AccessJudgement, len(rows))
	for _, row := range rows {
		out[row.ID] = row
	}
	return out
}
func accessTrust(ctx context.Context, prior *accessInput, c security.CorrectionIntent, after AfterEvidence, compatible *security.IntentSet) string {
	switch {
	case after.Intent == nil:
		return "intent_unavailable"
	case after.Access == nil || after.Access.Context != prior.Context || !after.Access.StartedAt.After(c.ActionAt) || after.Access.Input.EvaluatedAt.Before(after.Access.StartedAt) || after.Access.Input.EvaluatedAt.After(after.Now) || after.Access.Input.NoIntent:
		return "access_not_post_action"
	case after.Now.Sub(after.Access.StartedAt) > security.EvidenceMaxAge:
		return "access_not_recent"
	case compatible == nil || !sameIntentSet(ctx, *compatible, after.Access.Input.Intent) || !accessWithinBounds(ctx, after.Access.Input) || (after.Access.Input.Limit != 0 && after.Access.Input.Limit != prior.Input.Limit):
		return "access_input_mismatch"
	}
	return ""
}
func accessPolicy(out *VerificationReport, p PreparedCorrection, prior *accessInput, after AfterEvidence, trust string) bool {
	out.PolicyCheck = "not_checked"
	if trust != "" {
		return false
	}
	form, err := policyForm(after.Access.Input.PolicyVersion)
	if err != nil || form == "" || form != prior.PolicyVersionForm || (form != "plain" && p.replay.Reading.Seal != SealValid) {
		return false
	}
	unchanged := prior.Input.PolicyVersion == after.Access.Input.PolicyVersion
	out.PolicyCheck = "changed"
	if unchanged {
		out.PolicyCheck = "unchanged"
	}
	return unchanged
}
func accessTarget(id, reason string, b, a security.AccessJudgement, unchanged bool, p PreparedCorrection, after AfterEvidence) VerificationRow {
	row := VerificationRow{Kind: "expectation", ExpectationID: id, Before: string(b.Status), After: string(a.Status), Limits: slices.Clone(a.Limits)}
	if reason != "" {
		row.Outcome, row.Reason = "incomplete", reason
		return row
	}
	switch a.Status {
	case security.AccessUnmet:
		row.Outcome = "not_fixed"
	case security.AccessMet:
		row.Outcome = "fixed"
		capAccessRow(&row, b, unchanged, p, after)
	case security.AccessMetWithLimits:
		row.Outcome, row.Reason = "incomplete", "limited"
	default:
		row.Outcome, row.Reason = "incomplete", "access_not_witnessed"
	}
	return row
}
func capAccessRow(row *VerificationRow, b security.AccessJudgement, unchanged bool, p PreparedCorrection, after AfterEvidence) {
	switch {
	case unchanged && b.Status == security.AccessUnmet:
		row.Outcome, row.Reason = "incomplete", "policy_unchanged"
	case p.replay.inputs.Snapshot.KeyEpoch != after.Snapshot.KeyEpoch:
		row.Outcome, row.Reason = "incomplete", "epoch_mismatch"
	case p.Scope() != security.ScopeFleet:
		row.Outcome, row.Reason = "incomplete", "context_identity_unavailable"
	case p.replay.Reading.Seal == SealAbsentKeyLoaded:
		row.Outcome, row.Reason = "incomplete", "before_unsealed_key_loaded"
	}
}
func accessGuard(id, reason string, b, a security.AccessJudgement) VerificationGuard {
	guard := VerificationGuard{ExpectationID: id, Before: b.Status, After: a.Status, Limits: slices.Clone(a.Limits)}
	if reason != "" {
		guard.Outcome, guard.Reason = reason, reason
	} else {
		guard.Outcome = guardOutcome(b, a)
	}
	return guard
}

func catalogChanges(before, after security.Catalog, old, current []security.Finding, targets []security.CorrectionFinding) (bool, int) {
	targeted := make(map[string]bool, len(targets))
	pairs := make(map[string]bool, len(targets))
	for _, t := range targets {
		targeted[t.RuleID] = true
		pairs[t.RuleID+"\x00"+t.Asset] = true
	}
	changed := otherRulesChanged(before, after, targeted)
	oldBad := make(map[string]bool, len(old))
	for _, f := range old {
		if f.Applicability == security.ApplicabilityAffected || f.Applicability == security.ApplicabilityPotential {
			oldBad[f.ID] = true
		}
	}
	count := 0
	for _, f := range current {
		if !pairs[f.RuleID+"\x00"+f.Asset] && !oldBad[f.ID] && (f.Applicability == security.ApplicabilityAffected || f.Applicability == security.ApplicabilityPotential) {
			count++
		}
	}
	return changed, count
}
func otherRulesChanged(before, after security.Catalog, targeted map[string]bool) bool {
	oldRules := make(map[string]security.AdvisoryRecord, len(before.Records))
	newRules := make(map[string]security.AdvisoryRecord, len(after.Records))
	for _, r := range before.Records {
		oldRules[r.ID] = r
	}
	for _, r := range after.Records {
		newRules[r.ID] = r
	}
	changed := false
	for id, r := range oldRules {
		if !targeted[id] {
			other, ok := newRules[id]
			if !ok || !sameRecord(r, other) {
				changed = true
			}
		}
	}
	for id := range newRules {
		if !targeted[id] {
			if _, ok := oldRules[id]; !ok {
				changed = true
			}
		}
	}
	return changed
}

type intentMeter struct{ bytes, nodes int }

func (m *intentMeter) text(s string) bool {
	if len(s) > security.MaxTextBytes || len(s) > MaxPackBytes-m.bytes || m.nodes == MaxPackNodes {
		return false
	}
	m.bytes += len(s)
	m.nodes++
	return true
}
func (m *intentMeter) texts(ctx context.Context, values []string) bool {
	if len(values) > MaxPackNodes-m.nodes {
		return false
	}
	for _, v := range values {
		if ctx.Err() != nil || !m.text(v) {
			return false
		}
	}
	return true
}
func (m *intentMeter) network(ctx context.Context, v security.NetworkExpectation) bool {
	if !m.texts(ctx, []string{v.ID, v.Source, v.Protocol}) || !m.texts(ctx, v.Accept) || !m.texts(ctx, v.Deny) || len(v.SourcePostureAttributes) > MaxPackNodes-m.nodes {
		return false
	}
	for name, value := range v.SourcePostureAttributes {
		if ctx.Err() != nil || !m.texts(ctx, []string{name, string(value.Kind), value.String, value.Number}) {
			return false
		}
	}
	return true
}
func (m *intentMeter) ssh(ctx context.Context, v security.SSHExpectation) bool {
	return m.texts(ctx, []string{v.ID, v.Source}) && m.texts(ctx, v.Destinations) && m.texts(ctx, v.Accept) && m.texts(ctx, v.Deny) && m.texts(ctx, v.Check)
}
func intentWithinBounds(ctx context.Context, in security.IntentSet) bool {
	if ctx == nil || len(in.Network) > security.MaxObservations || len(in.SSH) > security.MaxObservations-len(in.Network) {
		return false
	}
	meter := intentMeter{}
	for _, v := range in.Network {
		if ctx.Err() != nil || !meter.network(ctx, v) {
			return false
		}
	}
	for _, v := range in.SSH {
		if ctx.Err() != nil || !meter.ssh(ctx, v) {
			return false
		}
	}
	return ctx.Err() == nil
}

func accessWithinBounds(ctx context.Context, in security.AccessInput) bool {
	if ctx == nil || len(in.Witnesses) > security.MaxAccessPairs || len(in.Candidates) > security.MaxObservations || len(in.Limits) > security.MaxObservations || len(in.Owners) > security.MaxObservations {
		return false
	}
	m := intentMeter{}
	if !m.text(in.PolicyVersion) {
		return false
	}
	for _, w := range in.Witnesses {
		if !m.texts(ctx, []string{w.Expectation, w.Cell.Expect, w.Cell.Destination, w.Cell.User, string(w.Observed), string(w.Reason)}) {
			return false
		}
	}
	return accessCollectionsBounded(ctx, &m, in)
}
func accessCollectionsBounded(ctx context.Context, m *intentMeter, in security.AccessInput) bool {
	for id, c := range in.Candidates {
		if !m.texts(ctx, []string{id}) || len(c.Rules) > MaxPackNodes-m.nodes {
			return false
		}
		for _, r := range c.Rules {
			if !m.texts(ctx, []string{r.Section, r.Source, r.Destination, r.Ports, r.Traffic}) {
				return false
			}
		}
	}
	for id, limits := range in.Limits {
		if !m.texts(ctx, []string{id}) || len(limits) > MaxPackNodes-m.nodes {
			return false
		}
		for _, l := range limits {
			if !m.texts(ctx, []string{string(l)}) {
				return false
			}
		}
	}
	for _, owner := range in.Owners {
		if !m.texts(ctx, []string{owner.Source}) || !m.texts(ctx, owner.Tags) {
			return false
		}
	}
	return ctx.Err() == nil
}
