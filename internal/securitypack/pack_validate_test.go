package securitypack

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

func TestPackStructuralBoundaries(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snapshot := packSnapshot{Context: "ctx-local-only", Scope: "local", ObservedAt: at}
	if err := checkPackSnapshot(snapshot, at); err != nil {
		t.Fatalf("local empty snapshot: %v", err)
	}
	snapshot.Context = "ctx-0123456789abcdef"
	snapshot.Scope = "fleet"
	if err := checkPackSnapshot(snapshot, at); err != nil {
		t.Fatalf("fleet empty snapshot: %v", err)
	}
	snapshot.Context = "ctx-0123456789abcdeF"
	if err := checkPackSnapshot(snapshot, at); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("bad context: %v", err)
	}
	if countsMatch(int(^uint(0)>>1), int(^uint(0)>>1), 1) {
		t.Fatal("overflowing counts accepted")
	}
	if !countsMatch(2, 0, 1, 1) {
		t.Fatal("valid counts refused")
	}
	if countsMatch(0, -1) {
		t.Fatal("negative count accepted")
	}
	value := packBody{Snapshot: packSnapshot{}, Expected: packExpected{Report: packExpectedReport{Status: "partial", SHA256: strings.Repeat("a", 64)}}}
	if err := checkPackExpected(value); err != nil {
		t.Fatalf("valid empty summary: %v", err)
	}
	value.Expected.Counts.Devices = 1
	if err := checkPackExpected(value); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("bad device count: %v", err)
	}
}

func TestPackWireTextScan(t *testing.T) {
	value := codecFixture()
	if err := checkPackTextLeaves(value); err != nil {
		t.Fatalf("neutral fixture: %v", err)
	}
	value.Body.Access.Witnesses[0].Cell.User = "ts" + "key-" + "api-"
	if err := checkPackTextLeaves(value); !errors.Is(err, ErrSecretShaped) {
		t.Fatalf("leaf secret: %v", err)
	}
}

func TestPackBodyRejectsInvalidSemantics(t *testing.T) {
	base, err := bodyFromInput(validPackInput())
	if err != nil || checkPackBody(base) != nil {
		t.Fatal("valid body control failed")
	}
	tests := []struct {
		name   string
		change func(*packBody)
		want   error
	}{
		{"format", func(b *packBody) { b.Format = "other" }, ErrNotAPack},
		{"pack schema", func(b *packBody) { b.PackSchemaVersion = 2 }, ErrUnsupportedPackSchema},
		{"catalog schema", func(b *packBody) { b.CatalogSchemaVersion = 2 }, ErrUnsupportedCatalogSchema},
		{"report schema", func(b *packBody) { b.ReportSchemaVersion = 2 }, ErrUnsupportedReportSchema},
		{"evaluator", func(b *packBody) { b.EvaluatorVersion = -1 }, ErrInvalidPack},
		{"budget", func(b *packBody) { b.Evaluation.WorkBudget = security.MaxCandidates + 1 }, ErrInvalidPack},
		{"snapshot", func(b *packBody) { b.Snapshot.Context = "invalid" }, ErrInvalidPack},
		{"expected counts", func(b *packBody) { b.Expected.Counts.Devices = 1 }, ErrInvalidPack},
		{"expected report status", func(b *packBody) { b.Expected.Report.Status = "invalid" }, ErrInvalidPack},
		{"expected report total", func(b *packBody) { b.Expected.Report.TotalFindings = 1 }, ErrInvalidPack},
		{"unpaired expected access", func(b *packBody) { b.Expected.Access = &packExpectedAccess{} }, ErrInvalidPack},
		{"collected status", func(b *packBody) {
			b.Collected = []packCoverage{{Context: b.Snapshot.Context, Target: packCoverageTarget{Scope: b.Snapshot.Scope, Dimension: "versions"}, Status: "unknown"}}
		}, ErrInvalidPack},
		{"intent schema", func(b *packBody) { b.Intent = &packIntent{SchemaVersion: 2} }, ErrInvalidPack},
		{"catalog digest", func(b *packBody) { b.Catalog.Digest = "invalid" }, ErrInvalidPack},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			value, err := bodyFromInput(validPackInput())
			if err != nil {
				t.Fatal(err)
			}
			tc.change(&value)
			if err := checkPackBody(value); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	base.EvaluatorVersion = 0
	if err := checkPackBody(base); err != nil {
		t.Fatalf("zero evaluator should be preserved: %v", err)
	}
}

func TestPackCoverageAndEvidenceChecks(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := packSnapshot{Context: "ctx-local-only", Scope: "local", ObservedAt: at}
	e := packEvidence{Context: s.Context, Scope: s.Scope, Asset: "asset", AcquiredAt: at}
	if !validPackEvidence(e, s) {
		t.Fatal("valid evidence rejected")
	}
	e.Asset = strings.Repeat("界", 129)
	if validPackEvidence(e, s) {
		t.Fatal("oversized asset accepted")
	}
	e.Asset = "asset"
	e.Error = strings.Repeat("x", 257)
	if validPackEvidence(e, s) {
		t.Fatal("oversized error accepted")
	}
	e.Error = ""
	e.Context = "different"
	if validPackEvidence(e, s) {
		t.Fatal("different context accepted")
	}
	body := packBody{Snapshot: s, Collected: []packCoverage{{Context: s.Context, Status: "complete", Target: packCoverageTarget{Dimension: "features", Scope: s.Scope}, Counts: &packCoverageCounts{Assets: 1}}}}
	if err := checkPackCoverage(body); err != nil {
		t.Fatal(err)
	}
	body.Collected = append(body.Collected, body.Collected[0])
	if err := checkPackCoverage(body); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("duplicate dimension: %v", err)
	}
	body.Collected = body.Collected[:1]
	body.Collected[0].Counts.Assets = -1
	if err := checkPackCoverage(body); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("negative count: %v", err)
	}
}
