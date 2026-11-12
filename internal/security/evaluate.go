package security

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// EvaluatorVersion identifies the semantics of the security evaluator and validators.
const EvaluatorVersion = 1

// EvaluationBudget is the time Evaluate may spend judging. The collection that precedes it
// has its own (45 seconds), and the output that follows has the rest of the call's time.
const EvaluationBudget = 5 * time.Second

// intentSource and evaluationSource name the producers of the rows Evaluate adds.
const (
	intentSource     = "intent evaluation"
	evaluationSource = "security evaluation"
)

// Evaluate judges the snapshot by the catalog and returns the report. It is pure: it reads
// no clock (the time is in the input), calls no source and runs no process, and nothing in
// it is a model's judgement. It calls Match, so a finding is whatever Match says it is.
//
// The report requests the targets in the snapshot's scope that the input asks for: versions
// and features (answered by the rows the collection reported, and by an explicit partial row
// where it reported none), the catalog (Match's row) and, only when an intent set is supplied,
// intent. With no intent set the intent is not requested, and the report says so in a row of
// its own with the status CoverageNotRequested and an explanation, so that the absence is
// stated and not silent; that row never keeps the report from being complete. When an intent
// set is supplied it is requested, its digest and revision are in the report, and its row is
// partial: nothing in this version judges an expectation, so the row says "not evaluated" and
// counts them. Status is complete only when every requested target has a complete row and no
// row is partial. Whether a report is complete is then up to the rest: a pending rule, a
// stale review, an unknown finding or a source that failed each keep it partial.
//
// Findings are ordered affected, then potentially affected, then unknown, then not
// affected, and by source severity (critical first) within each, otherwise in Match's order.
// A collection that left a source out, or a run that was stopped, keeps the findings it made.
//
// The evaluation has EvaluationBudget. It is enforced where the work is done: Match polls
// the context at every step and returns when it ends, so no goroutine is left running when
// Evaluate returns. A run stopped by the budget, by the work budget in the input or by the
// findings limit returns the findings so far in a partial report and no error: the row says
// where it stopped. A run stopped because the caller's context ended returns that report and
// the context's error. Input that is invalid (see Match; a collected row that is not the
// snapshot's, or that is not about versions or features, or a dimension given twice) returns
// no report and an error.
//
// The report owns its data: it shares no slice or pointer with the input, so a change to
// the input afterwards, or a second evaluation of it, leaves the report as it was.
func Evaluate(ctx context.Context, in Input) (Report, error) {
	return evaluate(ctx, in, EvaluationBudget)
}

// evaluate is Evaluate with the time budget a test can shorten.
func evaluate(ctx context.Context, in Input, budget time.Duration) (Report, error) {
	if ctx == nil {
		return Report{}, errors.New("nil context")
	}
	collected, err := checkCollected(in)
	if err != nil {
		return Report{}, err
	}
	bctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	findings, rows, matchErr := Match(bctx, in.Catalog, in.Snapshot, in.Now, in.Budget)
	if rows == nil {
		// Invalid input: nothing was judged, so there is nothing to report.
		return Report{}, matchErr
	}
	snapshot := cloneSnapshot(in.Snapshot)
	scope := snapshot.Scope
	requested := []CoverageTarget{
		{Dimension: CoverageVersions, Scope: scope}, {Dimension: CoverageFeatures, Scope: scope}, {Dimension: CoverageCatalog, Scope: scope},
	}
	if in.Intent != nil {
		requested = append(requested, CoverageTarget{Dimension: CoverageIntent, Scope: scope})
	}
	all := slices.Concat(withCollected(in, collected), rows, []Coverage{intentRow(in)})
	findings = orderFindings(cloneFindings(findings))
	report := Report{
		SchemaVersion: SchemaVersion, Context: snapshot.Context, KeyEpoch: snapshot.KeyEpoch, GeneratedAt: in.Now,
		Status: statusOf(requested, all), TotalFindings: len(findings), Snapshot: snapshot, Findings: findings,
		RequestedCoverage: requested, Coverage: all,
	}
	if in.Intent != nil {
		report.IntentDigest, report.IntentRevision = in.Intent.Digest, in.Intent.Revision
	}
	if err := ValidateReport(report); err != nil {
		return Report{}, fmt.Errorf("evaluation made a report that does not validate: %w", err)
	}
	if matchErr != nil && ctx.Err() != nil {
		return report, ctx.Err()
	}
	return report, nil
}

// checkCollected refuses collected rows that are not the snapshot's or that the collection
// has no business reporting, and returns which of versions and features they answer.
func checkCollected(in Input) (map[CoverageDimension]bool, error) {
	have := map[CoverageDimension]bool{}
	for _, row := range in.Collected {
		switch {
		case row.Target.Dimension != CoverageVersions && row.Target.Dimension != CoverageFeatures:
			return nil, errors.New("collected coverage may describe versions and features only")
		case row.Target.Scope != in.Snapshot.Scope:
			return nil, errors.New("collected coverage is not in the snapshot's scope")
		case row.Context != in.Snapshot.Context:
			return nil, errors.New("collected coverage is not in the snapshot's context")
		case have[row.Target.Dimension]:
			return nil, errors.New("collected coverage describes a dimension twice")
		}
		have[row.Target.Dimension] = true
	}
	return have, nil
}

// withCollected returns the rows the collection reported, then an explicit partial row for each
// of versions and features it did not report: a dimension nobody described is a gap.
func withCollected(in Input, have map[CoverageDimension]bool) []Coverage {
	rows := cloneCoverage(in.Collected)
	for _, d := range []CoverageDimension{CoverageVersions, CoverageFeatures} {
		if !have[d] {
			rows = append(rows, Coverage{Target: CoverageTarget{Dimension: d, Scope: in.Snapshot.Scope}, Context: in.Snapshot.Context,
				Source: evaluationSource, Status: ReportPartial, Explanation: "the collection reported no coverage for this dimension"})
		}
	}
	return rows
}

// intentRow is the intent row. With no intent set it says the intent was not requested (a row
// that is not a gap). With one it is partial, because no expectation is judged in this version,
// and it counts the expectations; it repeats none of the set's text.
func intentRow(in Input) Coverage {
	row := Coverage{Target: CoverageTarget{Dimension: CoverageIntent, Scope: in.Snapshot.Scope}, Context: in.Snapshot.Context, Source: intentSource}
	if in.Intent == nil {
		row.Status, row.Explanation = CoverageNotRequested, "intent not requested: no intent set is configured"
		return row
	}
	n := len(in.Intent.Network) + len(in.Intent.SSH)
	row.Status = ReportPartial
	row.Explanation = fmt.Sprintf("intent not evaluated: this version judges no expectation (%d %s supplied)", n, plural(n, "expectation"))
	return row
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// statusOf is complete only when something was requested, every requested target has a
// complete row, and no row at all is partial (a report cannot be complete beside one). A row
// that says its target was not requested is neither: it answers nothing and blocks nothing.
func statusOf(requested []CoverageTarget, rows []Coverage) ReportStatus {
	complete := make(map[CoverageTarget]bool, len(rows))
	for _, row := range rows {
		if row.Status == CoverageNotRequested {
			continue
		}
		if row.Status != ReportComplete {
			return ReportPartial
		}
		complete[row.Target] = true
	}
	if len(requested) == 0 {
		return ReportPartial
	}
	for _, target := range requested {
		if !complete[target] {
			return ReportPartial
		}
	}
	return ReportComplete
}

// orderFindings sorts findings by applicability (affected first) and then by source
// severity (critical first), keeping Match's order otherwise.
func orderFindings(fs []Finding) []Finding {
	slices.SortStableFunc(fs, func(a, b Finding) int {
		if c := applicabilityRank(a.Applicability) - applicabilityRank(b.Applicability); c != 0 {
			return c
		}
		return severityRank(b.SourceSeverity) - severityRank(a.SourceSeverity)
	})
	return fs
}

func applicabilityRank(a Applicability) int {
	switch a {
	case ApplicabilityAffected:
		return 0
	case ApplicabilityPotential:
		return 1
	case ApplicabilityUnknown:
		return 2
	}
	return 3
}

func severityRank(s Severity) int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	}
	return 0
}

// ThresholdCounts is how many findings are at or above a severity threshold.
type ThresholdCounts struct {
	Affected  int // findings that are affected
	Potential int // findings that are potentially affected
}

// CountAtThreshold counts the affected and potentially affected findings whose source
// severity is at or above the threshold (low, medium, high or critical). A finding whose
// severity is unknown is above every threshold: it cannot be shown to be below it. An
// unknown or not affected finding is never counted (an unknown is a gap in coverage, which
// the report's status carries). It counts the findings it is given; call it on the whole
// report, before Truncate, so that the output limit cannot move the result.
func CountAtThreshold(findings []Finding, threshold Severity) (ThresholdCounts, error) {
	if severityRank(threshold) == 0 {
		return ThresholdCounts{}, errors.New("threshold must be low, medium, high or critical")
	}
	var c ThresholdCounts
	for _, f := range findings {
		rank := severityRank(f.SourceSeverity)
		if rank != 0 && rank < severityRank(threshold) {
			continue
		}
		switch f.Applicability {
		case ApplicabilityAffected:
			c.Affected++
		case ApplicabilityPotential:
			c.Potential++
		}
	}
	return c, nil
}

// Truncate returns a copy of the report with at most limit findings, the first in its order.
// The copy owns its data: it shares no slice or pointer with the report. When it cuts, it says
// so: Truncated is set, TotalFindings keeps the whole count, the status is partial, and the
// coverage rows keep the counts of the whole run. A report within the limit is copied as it
// is. The result is validated. limit must be positive.
func Truncate(r Report, limit int) (Report, error) {
	if limit < 1 {
		return Report{}, errors.New("the finding limit must be at least 1")
	}
	r = cloneReport(r)
	if len(r.Findings) <= limit {
		return r, nil
	}
	r.Findings = r.Findings[:limit:limit]
	r.Truncated, r.Status = true, ReportPartial
	if err := ValidateReport(r); err != nil {
		return Report{}, fmt.Errorf("a truncated report does not validate: %w", err)
	}
	return r, nil
}

// ---- ownership ------------------------------------------------------------------------

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

func cloneEvidence(e EvidenceRef) EvidenceRef {
	e.ObservedAt = cloneTime(e.ObservedAt)
	return e
}

func cloneEvidences(es []EvidenceRef) []EvidenceRef {
	if es == nil {
		return nil
	}
	out := make([]EvidenceRef, len(es))
	for i, e := range es {
		out[i] = cloneEvidence(e)
	}
	return out
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}

// cloneSnapshot copies a snapshot deeply: no slice, value or time in the copy is shared.
func cloneSnapshot(s Snapshot) Snapshot {
	out := s
	if s.Versions != nil {
		out.Versions = make([]VersionFact, len(s.Versions))
		for i, v := range s.Versions {
			v.Value, v.Evidence = clonePtr(v.Value), cloneEvidence(v.Evidence)
			out.Versions[i] = v
		}
	}
	if s.Platforms != nil {
		out.Platforms = make([]PlatformFact, len(s.Platforms))
		for i, p := range s.Platforms {
			p.Evidence = cloneEvidence(p.Evidence)
			out.Platforms[i] = p
		}
	}
	if s.Features != nil {
		out.Features = make([]FeatureFact, len(s.Features))
		for i, f := range s.Features {
			f.Value, f.Evidence = clonePtr(f.Value), cloneEvidence(f.Evidence)
			out.Features[i] = f
		}
	}
	if s.Policies != nil {
		out.Policies = make([]PolicyFact, len(s.Policies))
		for i, p := range s.Policies {
			p.Value, p.Evidence = clonePtr(p.Value), cloneEvidence(p.Evidence)
			out.Policies[i] = p
		}
	}
	return out
}

// cloneCoverage copies coverage rows deeply: a row's counts are reached through a pointer, and a
// pointer shared with the caller is a way for the caller to change a report.
func cloneCoverage(rows []Coverage) []Coverage {
	if rows == nil {
		return nil
	}
	out := make([]Coverage, len(rows))
	for i, row := range rows {
		row.Counts = clonePtr(row.Counts)
		out[i] = row
	}
	return out
}

// cloneReport copies a report deeply: its snapshot, findings, requested coverage and coverage
// rows share no slice or pointer with it.
func cloneReport(r Report) Report {
	r.Snapshot = cloneSnapshot(r.Snapshot)
	if r.Findings != nil {
		r.Findings = cloneFindings(r.Findings)
	}
	r.RequestedCoverage = slices.Clone(r.RequestedCoverage)
	r.Coverage = cloneCoverage(r.Coverage)
	return r
}

// cloneFindings copies findings deeply.
func cloneFindings(fs []Finding) []Finding {
	out := make([]Finding, len(fs))
	for i, f := range fs {
		f.Evidence = cloneEvidences(f.Evidence)
		f.Requirements, f.Verification, f.Remediation = slices.Clone(f.Requirements), slices.Clone(f.Verification), slices.Clone(f.Remediation)
		out[i] = f
	}
	return out
}
