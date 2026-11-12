package security

import (
	"context"
	"testing"
	"time"
)

// A world is one catalog and one snapshot, built from the default of a single approved,
// fresh rule about the client's running daemon (fixed in 1.32.3) and no facts. A case adds
// the facts it is about. Everything here is synthetic.

const (
	mCtx   = "context-m"
	mAsset = "dev"
)

var mNow = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

type world struct {
	now time.Time
	c   Catalog
	s   Snapshot
}

func newWorld(scope Scope) *world {
	w := &world{now: mNow}
	w.s = Snapshot{Context: mCtx, Scope: scope, ObservedAt: w.now.Add(-time.Minute)}
	w.c = Catalog{
		SchemaVersion: SchemaVersion, Revision: 1, IssuedAt: w.now.Add(-48 * time.Hour), ExpiresAt: w.now.Add(48 * time.Hour),
		Records: []AdvisoryRecord{w.rule("RULE-1")},
	}
	return w
}

// rule is an approved rule whose review is fresh at the world's time.
func (w *world) rule(id string) AdvisoryRecord {
	return AdvisoryRecord{
		ID: id, Revision: "1", Component: "client", VersionRole: VersionRunningDaemon,
		Ranges: []VersionRange{{Fixed: "1.32.3"}}, Source: "synthetic source", Severity: SeverityHigh,
		ReviewedAt: w.now.Add(-72 * time.Hour), ReviewExpiresAt: w.now.Add(24 * time.Hour), ReviewState: ReviewApproved,
		Mitigation: "Synthetic mitigation text.",
	}
}

// rec is the first (default) rule, for a case to change.
func (w *world) rec() *AdvisoryRecord { return &w.c.Records[0] }

// An evEdit changes the evidence of the fact being added.
type evEdit func(*EvidenceRef)

// ago sets the acquisition time of the evidence to d before the world's time.
func (w *world) ago(d time.Duration) evEdit {
	return func(e *EvidenceRef) { e.AcquiredAt = w.now.Add(-d) }
}

// observedAgo sets the source's own observation time to d before the world's time.
func (w *world) observedAgo(d time.Duration) evEdit {
	return func(e *EvidenceRef) {
		t := w.now.Add(-d)
		e.ObservedAt = &t
	}
}

func freshness(f Freshness) evEdit { return func(e *EvidenceRef) { e.Freshness = f } }
func failed() evEdit               { return func(e *EvidenceRef) { e.Error = "synthetic read failure" } }

func (w *world) ev(origin Origin, asset string, edit ...evEdit) EvidenceRef {
	e := EvidenceRef{Context: mCtx, Asset: asset, Scope: w.s.Scope, Origin: origin, AcquiredAt: w.now.Add(-time.Minute), Freshness: FreshnessFresh}
	for _, f := range edit {
		f(&e)
	}
	return e
}

func (w *world) versionFact(name, asset string, role VersionRole, origin Origin, channel VersionChannel, value *string, edit ...evEdit) {
	w.s.Versions = append(w.s.Versions, VersionFact{Name: name, Role: role, Channel: channel, Value: value, Evidence: w.ev(origin, asset, edit...)})
}

func (w *world) version(asset string, role VersionRole, origin Origin, channel VersionChannel, value string, edit ...evEdit) {
	w.versionFact("client", asset, role, origin, channel, &value, edit...)
}

// daemon, api and cli add a stable version fact for the world's one device.
func (w *world) daemon(value string, edit ...evEdit) {
	w.version(mAsset, VersionRunningDaemon, OriginLocal, ChannelStable, value, edit...)
}
func (w *world) api(value string, edit ...evEdit) {
	w.version(mAsset, VersionAPIReported, OriginAPI, ChannelStable, value, edit...)
}
func (w *world) cli(value string, edit ...evEdit) {
	w.version(mAsset, VersionLocalCLI, OriginLocal, ChannelStable, value, edit...)
}

func (w *world) feature(asset string, origin Origin, name string, value bool, edit ...evEdit) {
	v := value
	w.s.Features = append(w.s.Features, FeatureFact{Name: name, Value: &v, Evidence: w.ev(origin, asset, edit...)})
}

// connected adds connected_to_control as the API reports it, for the world's one device.
func (w *world) connected(value bool, edit ...evEdit) {
	w.feature(mAsset, OriginAPI, FeatureConnectedToControl, value, edit...)
}

// feat adds a feature fact from the local daemon, for the world's one device.
func (w *world) feat(name string, value bool, edit ...evEdit) {
	w.feature(mAsset, OriginLocal, name, value, edit...)
}

func (w *world) platform(asset string, origin Origin, os string, edit ...evEdit) {
	w.s.Platforms = append(w.s.Platforms, PlatformFact{OS: os, Evidence: w.ev(origin, asset, edit...)})
}

// os adds a platform fact from the local daemon, for the world's one device.
func (w *world) os(os string, edit ...evEdit) { w.platform(mAsset, OriginLocal, os, edit...) }

func (w *world) match(budget WorkBudget) ([]Finding, []Coverage, error) {
	return Match(context.Background(), w.c, w.s, w.now, budget)
}

// reportOf wraps what Match returned in a report that requests the catalog row. The report
// is complete when every row is, as a producer would build it.
func reportOf(s Snapshot, now time.Time, findings []Finding, coverage []Coverage) Report {
	status := ReportComplete
	for _, row := range coverage {
		if row.Status != ReportComplete {
			status = ReportPartial
		}
	}
	return Report{
		SchemaVersion: SchemaVersion, Context: s.Context, GeneratedAt: now, Status: status, TotalFindings: len(findings),
		Snapshot: s, Findings: findings, Coverage: coverage,
		RequestedCoverage: []CoverageTarget{{Dimension: CoverageCatalog, Scope: s.Scope}},
	}
}

// requireValidReport fails the test unless the report built from Match's output validates.
func requireValidReport(t *testing.T, w *world, findings []Finding, coverage []Coverage) {
	t.Helper()
	if err := ValidateReport(reportOf(w.s, w.now, findings, coverage)); err != nil {
		t.Fatalf("a report built from Match's output is refused: %v", err)
	}
}
