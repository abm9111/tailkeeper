package securitypack

import (
	"context"
	"errors"
	"time"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/security"
)

var (
	ErrUnsupportedEvaluator = errors.New("unsupported_evaluator")
	ErrCatalogMismatch      = errors.New("catalog_mismatch")
	ErrMissingFacts         = errors.New("missing_facts")
	ErrBudgetTooSmall       = errors.New("budget_too_small")
	ErrReportTooLarge       = errors.New("report_too_large")
	ErrStoppedEarly         = errors.New("stopped_early")
	ErrNotReproduced        = errors.New("not_reproduced")
)

const ScopeSentence = "Replay reproduces a decision from the inputs the pack declares. It does not show that those inputs were true, that a host is uncompromised, or that anything is secure now."

// Reproduction states whether the computed decision matches the recorded assertions.
type Reproduction struct {
	Status      string
	Cause       string
	Differences []string
}

// Replayed is private evidence for consumers that will apply their own output shaping.
type Replayed struct {
	Report           security.Report
	AccessReport     *security.AccessReport
	AccessJudgements []security.AccessJudgement
	Reproduction     Reproduction
	Reading          Reading
	CatalogDigest    string
	ScopeSentence    string
	catalog          security.Catalog
	inputs           packInput
}

// CatalogSummary contains metadata from the recorded catalog used by replay.
// Digest is private evidence; callers must apply the current privacy setting before output.
type CatalogSummary struct {
	Revision  uint64
	IssuedAt  time.Time
	ExpiresAt time.Time
	Digest    string
	Rules     int
	Approved  int
	Pending   int
	Withdrawn int
}

// CatalogSummary returns value-only metadata about the recorded merged catalog.
func (r Replayed) CatalogSummary() CatalogSummary {
	c := r.catalog
	out := CatalogSummary{Revision: c.Revision, IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt, Digest: c.Digest, Rules: len(c.Records)}
	for _, rule := range c.Records {
		switch rule.ReviewState {
		case security.ReviewApproved:
			out.Approved++
		case security.ReviewPending:
			out.Pending++
		case security.ReviewWithdrawn:
			out.Withdrawn++
		}
	}
	return out
}

// Replay uses only the embedded inputs and preserves their recorded budget and time.
func Replay(ctx context.Context, pack EvidencePack, ceiling security.WorkBudget) (Replayed, error) {
	if !pack.valid {
		return Replayed{}, ErrInvalidPack
	}
	catalog, err := replayCatalogOf(pack.envelope.Body)
	if err != nil {
		return Replayed{}, err
	}
	pi, err := packInputOf(pack)
	if err != nil {
		return Replayed{}, err
	}
	if security.ValidateSnapshot(pi.Snapshot, pi.EvaluationAt) != nil || snapshotCounts(pi.Snapshot) != pi.Expected.Counts {
		return Replayed{}, ErrMissingFacts
	}
	if !budgetAllows(pi.WorkBudget, ceiling) {
		return Replayed{}, ErrBudgetTooSmall
	}
	if ctx == nil {
		return Replayed{}, ErrInvalidPack
	}
	report, err := security.Evaluate(ctx, security.Input{Catalog: catalog, Snapshot: pi.Snapshot, Intent: pi.Intent, Collected: pi.Collected, Now: pi.EvaluationAt, Budget: pi.WorkBudget})
	if err != nil {
		return Replayed{}, replayEvaluationError(err)
	}
	out := Replayed{Report: report, Reading: pack.reading, CatalogDigest: catalog.Digest, ScopeSentence: ScopeSentence, catalog: catalog, inputs: pi}
	if security.StoppedEarly(report) {
		out.Reproduction = Reproduction{Status: "not_reproduced", Cause: "stopped_early"}
		return out, nil
	}
	actual, err := expectedReport(pi.Snapshot, report)
	if err != nil {
		return Replayed{}, err
	}
	if pi.Access != nil {
		a, judgements, judgeErr := security.JudgeAccess(pi.Access.Input)
		if judgeErr != nil {
			return Replayed{}, ErrInvalidPack
		}
		out.AccessReport, out.AccessJudgements = &a, judgements
		access, accessErr := expectedAccess(a)
		if accessErr != nil {
			return Replayed{}, accessErr
		}
		actual.Access = &access
	}
	differences := compareExpected(pi.Expected, actual)
	out.Reproduction = Reproduction{Status: "reproduced"}
	if len(differences) > 0 {
		out.Reproduction = Reproduction{Status: "not_reproduced", Cause: "differences", Differences: differences}
	}
	return out, nil
}

func replayEvaluationError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrInvalidPack
}

func replayCatalogOf(body packBody) (security.Catalog, error) {
	if body.PackSchemaVersion != PackSchemaVersion {
		return security.Catalog{}, ErrUnsupportedPackSchema
	}
	if body.EvaluatorVersion != security.EvaluatorVersion {
		return security.Catalog{}, ErrUnsupportedEvaluator
	}
	if body.ReportSchemaVersion != security.SchemaVersion {
		return security.Catalog{}, ErrUnsupportedReportSchema
	}
	if body.CatalogSchemaVersion != security.SchemaVersion {
		return security.Catalog{}, ErrUnsupportedCatalogSchema
	}
	sources := make([]advisory.Source, len(body.Catalog.Sources))
	for i, source := range body.Catalog.Sources {
		sources[i] = advisory.Source{Name: source.Name, Data: source.Data}
	}
	catalog, err := advisory.Merge(sources)
	if err != nil || catalog.Digest != body.Catalog.Digest {
		return security.Catalog{}, ErrCatalogMismatch
	}
	if wireSnapshotCounts(body.Snapshot) != body.Expected.Counts {
		return security.Catalog{}, ErrMissingFacts
	}
	return catalog, nil
}

func budgetAllows(recorded, ceiling security.WorkBudget) bool {
	if recorded.Candidates < 0 || recorded.Candidates > security.MaxCandidates || ceiling.Candidates < 0 || ceiling.Candidates > security.MaxCandidates {
		return false
	}
	r, c := recorded.Candidates, ceiling.Candidates
	if r == 0 {
		r = security.MaxCandidates
	}
	if c == 0 {
		c = security.MaxCandidates
	}
	return r <= c
}

func wireSnapshotCounts(s packSnapshot) packExpectedCounts {
	assets := make(map[string]struct{})
	add := func(e packEvidence) {
		if e.Asset != "" {
			assets[e.Asset] = struct{}{}
		}
	}
	for _, f := range s.Versions {
		add(f.Evidence)
	}
	for _, f := range s.Platforms {
		add(f.Evidence)
	}
	for _, f := range s.Features {
		add(f.Evidence)
	}
	for _, f := range s.Policies {
		add(f.Evidence)
	}
	return packExpectedCounts{Devices: len(assets), Versions: len(s.Versions), Platforms: len(s.Platforms), Features: len(s.Features), Policies: len(s.Policies)}
}

func snapshotCounts(s security.Snapshot) packExpectedCounts {
	assets := make(map[string]struct{})
	add := func(e security.EvidenceRef) {
		if e.Asset != "" {
			assets[e.Asset] = struct{}{}
		}
	}
	for _, f := range s.Versions {
		add(f.Evidence)
	}
	for _, f := range s.Platforms {
		add(f.Evidence)
	}
	for _, f := range s.Features {
		add(f.Evidence)
	}
	for _, f := range s.Policies {
		add(f.Evidence)
	}
	return packExpectedCounts{Devices: len(assets), Versions: len(s.Versions), Platforms: len(s.Platforms), Features: len(s.Features), Policies: len(s.Policies)}
}

func expectedReport(s security.Snapshot, report security.Report) (packExpected, error) {
	hash, err := hashReport(report)
	if err != nil {
		return packExpected{}, hashError(err)
	}
	out := packExpected{Counts: snapshotCounts(s), Report: packExpectedReport{Status: string(report.Status), TotalFindings: report.TotalFindings, SHA256: hash}}
	for _, f := range report.Findings {
		switch f.Applicability {
		case security.ApplicabilityAffected:
			out.Report.Affected++
		case security.ApplicabilityPotential:
			out.Report.PotentiallyAffected++
		case security.ApplicabilityUnknown:
			out.Report.Unknown++
		case security.ApplicabilityNotAffected:
			out.Report.NotAffected++
		default:
			return packExpected{}, ErrInvalidPack
		}
	}
	return out, nil
}

func expectedAccess(report security.AccessReport) (packExpectedAccess, error) {
	hash, err := hashAccessReport(report)
	if err != nil {
		return packExpectedAccess{}, hashError(err)
	}
	c := report.Counts
	return packExpectedAccess{Status: string(report.Status), Total: c.Total, Met: c.Met, MetWithLimits: c.MetWithLimits, Unmet: c.Unmet, Unknown: c.Unknown, NotEvaluated: c.NotEvaluated, SHA256: hash}, nil
}

func hashError(err error) error {
	if errors.Is(err, errCanonTooLarge) {
		return ErrReportTooLarge
	}
	return ErrInvalidPack
}

func compareExpected(want, got packExpected) []string {
	var d []string
	add := func(different bool, field string) {
		if different {
			d = append(d, field)
		}
	}
	a, b := want.Report, got.Report
	add(a.Status != b.Status, "report.status")
	add(a.TotalFindings != b.TotalFindings, "report.total_findings")
	add(a.Affected != b.Affected, "report.affected")
	add(a.PotentiallyAffected != b.PotentiallyAffected, "report.potentially_affected")
	add(a.Unknown != b.Unknown, "report.unknown")
	add(a.NotAffected != b.NotAffected, "report.not_affected")
	add(a.SHA256 != b.SHA256, "report.sha256")
	if want.Access == nil || got.Access == nil {
		add((want.Access == nil) != (got.Access == nil), "access")
		return d
	}
	x, y := want.Access, got.Access
	add(x.Status != y.Status, "access.status")
	add(x.Total != y.Total, "access.total")
	add(x.Met != y.Met, "access.met")
	add(x.MetWithLimits != y.MetWithLimits, "access.met_with_limits")
	add(x.Unmet != y.Unmet, "access.unmet")
	add(x.Unknown != y.Unknown, "access.unknown")
	add(x.NotEvaluated != y.NotEvaluated, "access.not_evaluated")
	add(x.SHA256 != y.SHA256, "access.sha256")
	return d
}
