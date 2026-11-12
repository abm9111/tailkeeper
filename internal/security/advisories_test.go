package security

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAdvisoryBoundariesAndUnknown(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		version, channel string
		want             Applicability
	}{
		{"1.30.9", "stable", ApplicabilityAffected}, {"1.32.3", "stable", ApplicabilityNotAffected},
		{"1.33.257", "unstable", ApplicabilityUnknown}, {"1.32.3-rc1", "stable", ApplicabilityUnknown},
		{"1.32.3+backport", "stable", ApplicabilityUnknown}, {"1.32", "stable", ApplicabilityUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			c, s := testInputs(now, tc.version)
			s.Versions[0].Channel = VersionChannel(tc.channel)
			f, _, err := Match(context.Background(), c, s, now, WorkBudget{})
			if err != nil || len(f) != 1 || f[0].Applicability != tc.want {
				t.Fatalf("got %v %v", f, err)
			}
		})
	}
}
func TestPendingSSHNoticeNeverInventsFixedVersion(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, s := testInputs(now, "1.32.3")
	c.Records[0].ReviewState = ReviewPending
	c.Records[0].Ranges = nil
	c.Records[0].RequiredFeatures = []string{"ssh"}
	f, _, err := Match(context.Background(), c, s, now, WorkBudget{})
	// A pending rule neither confirms nor clears a device, and shows no guidance of its own.
	if err != nil || len(f) != 1 || f[0].Applicability != ApplicabilityUnknown || f[0].Reason != ReasonReviewPending || len(f[0].Remediation) != 0 || len(f[0].Verification) != 0 {
		t.Fatalf("got %v %v", f, err)
	}
}
func TestMatchingBudgetPreservesPartialEvidence(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, s := testInputs(now, "1.0.0")
	c.Records = append(c.Records, c.Records[0])
	c.Records[1].ID = "TEST-2"
	f, cov, err := Match(context.Background(), c, s, now, WorkBudget{Candidates: 4})
	if !errors.Is(err, ErrWorkBudget) || len(f) != 1 || len(cov) == 0 || cov[0].Status != ReportPartial {
		t.Fatalf("got %v %v %v", f, cov, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, cov, err = Match(ctx, c, s, now, WorkBudget{})
	if !errors.Is(err, context.Canceled) || len(cov) == 0 || cov[0].Status != ReportPartial {
		t.Fatalf("got %v %v", cov, err)
	}
}
func testInputs(now time.Time, v string) (Catalog, Snapshot) {
	e := EvidenceRef{Context: "test", Asset: "asset", Scope: ScopeLocal, Origin: OriginLocal, AcquiredAt: now, Freshness: FreshnessFresh}
	return Catalog{SchemaVersion: SchemaVersion, Revision: 1, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), Records: []AdvisoryRecord{{ID: "TEST-1", Revision: "1", Component: "client", VersionRole: VersionRunningDaemon, Ranges: []VersionRange{{Fixed: "1.32.3"}}, Source: "synthetic", Severity: SeverityLow, ReviewedAt: now.Add(-time.Hour), ReviewExpiresAt: now.Add(time.Hour), ReviewState: ReviewApproved}}}, Snapshot{Context: "test", Scope: ScopeLocal, ObservedAt: now, Versions: []VersionFact{{Name: "client", Value: &v, Role: VersionRunningDaemon, Channel: ChannelStable, Evidence: e}}}
}

func TestConservativeEvidence(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t.Run("expired retains affected", func(t *testing.T) {
		c, s := testInputs(now, "1.30.0")
		c.ExpiresAt = now
		f, _, err := Match(context.Background(), c, s, now, WorkBudget{})
		if err != nil || f[0].Applicability != ApplicabilityAffected {
			t.Fatalf("%v %v", f, err)
		}
	})
	t.Run("expired cannot clear", func(t *testing.T) {
		c, s := testInputs(now, "1.32.3")
		c.Records[0].ReviewExpiresAt = now
		c.IssuedAt = now
		c.Records[0].SourceCheckedAt = &now
		f, _, err := Match(context.Background(), c, s, now, WorkBudget{})
		if err != nil || f[0].Applicability != ApplicabilityUnknown {
			t.Fatalf("%v %v", f, err)
		}
	})
	t.Run("api old is potential", func(t *testing.T) {
		c, s := testInputs(now, "1.30.0")
		s.Versions[0].Role = VersionAPIReported
		s.Versions[0].Evidence.Origin = OriginAPI
		f, _, err := Match(context.Background(), c, s, now, WorkBudget{})
		if err != nil || f[0].Applicability != ApplicabilityPotential {
			t.Fatalf("%v %v", f, err)
		}
	})
	t.Run("cli fixed cannot clear daemon", func(t *testing.T) {
		c, s := testInputs(now, "1.32.3")
		s.Versions[0].Role = VersionLocalCLI
		f, _, err := Match(context.Background(), c, s, now, WorkBudget{})
		if err != nil || f[0].Applicability != ApplicabilityUnknown {
			t.Fatalf("%v %v", f, err)
		}
	})
	t.Run("feature false needs same evidence scope", func(t *testing.T) {
		c, s := testInputs(now, "1.30.0")
		c.Records[0].RequiredFeatures = []string{"ssh"}
		v := false
		e := s.Versions[0].Evidence
		s.Features = []FeatureFact{{Name: "ssh", Value: &v, Evidence: e}}
		f, _, err := Match(context.Background(), c, s, now, WorkBudget{})
		if err != nil || f[0].Applicability != ApplicabilityNotAffected {
			t.Fatalf("%v %v", f, err)
		}
		s.Features[0].Evidence.Asset = "other"
		f, _, err = Match(context.Background(), c, s, now, WorkBudget{})
		if err != nil || f[0].Applicability != ApplicabilityPotential {
			t.Fatalf("%v %v", f, err)
		}
	})
	t.Run("conflicting versions unknown", func(t *testing.T) {
		c, s := testInputs(now, "1.30.0")
		v := "1.32.3"
		other := s.Versions[0]
		other.Value = &v
		s.Versions = append(s.Versions, other)
		f, _, err := Match(context.Background(), c, s, now, WorkBudget{})
		if err != nil || f[0].Applicability != ApplicabilityUnknown {
			t.Fatalf("%v %v", f, err)
		}
	})
	t.Run("withdrawn never clears", func(t *testing.T) {
		c, s := testInputs(now, "1.32.3")
		c.Records[0].ReviewState = ReviewWithdrawn
		f, cov, err := Match(context.Background(), c, s, now, WorkBudget{})
		// A withdrawn rule produces no finding at all, neither a clearance nor a warning; it is
		// counted, and a catalog with nothing else in it is not a complete assessment.
		if err != nil || len(f) != 0 || cov[0].Status != ReportPartial || cov[0].Counts.Withdrawn != 1 {
			t.Fatalf("%v %v %v", f, cov, err)
		}
	})
}

// The hard candidate budget stops a run before the findings limit does. One device holds the
// most facts a snapshot may (each of them a comparison for every rule), so a run uses its
// budget on a few dozen findings, far below MaxFindings: it is the candidate check that stops
// it, and the findings limit, which the tests of the run pin, cannot be what these assertions
// see. The error and the coverage row both say which.
func TestHardCandidateBound(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, s := testInputs(now, "1.30.0")
	for len(s.Versions) < MaxObservations {
		v := s.Versions[0]
		v.Name = "other"
		s.Versions = append(s.Versions, v)
	}
	for i := 1; i < 100; i++ {
		r := c.Records[0]
		r.ID = fmt.Sprintf("TEST-%d", i+1)
		c.Records = append(c.Records, r)
	}
	f, cov, err := Match(context.Background(), c, s, now, WorkBudget{Candidates: MaxCandidates})
	if !errors.Is(err, ErrWorkBudget) {
		t.Fatalf("error %v, want the work budget", err)
	}
	if errors.Is(err, errFindingsLimit) {
		t.Fatalf("the run stopped at the findings limit, not the candidate budget: %v", err)
	}
	if len(f) == 0 || len(f) >= len(c.Records) || len(f) >= MaxFindings {
		t.Fatalf("%d findings: want some, fewer than the %d rules and far below the %d limit", len(f), len(c.Records), MaxFindings)
	}
	if len(cov) != 1 || cov[0].Status != ReportPartial ||
		!strings.Contains(cov[0].Explanation, "evaluation stopped early: work budget exhausted, at rule ") ||
		strings.Contains(cov[0].Explanation, "findings limit") {
		t.Fatalf("coverage %+v", cov)
	}
	// A budget above the hard maximum is refused, not clamped to it.
	f, cov, err = Match(context.Background(), c, s, now, WorkBudget{Candidates: MaxCandidates + 1})
	if !errors.Is(err, ErrInvalidBudget) || f != nil || cov != nil {
		t.Fatalf("findings %v coverage %v error %v", f, cov, err)
	}
}

func TestMissingAndStaleEvidenceIsPartial(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, s := testInputs(now, "1.30.0")
	s.Versions[0].Evidence.AcquiredAt = now.Add(-31 * time.Minute)
	// Stale evidence does not drop the device: it is judged unknown, for that reason.
	f, cov, err := Match(context.Background(), c, s, now, WorkBudget{})
	if err != nil || len(f) != 1 || f[0].Applicability != ApplicabilityUnknown || f[0].Reason != ReasonStaleEvidence || cov[0].Status != ReportPartial {
		t.Fatalf("%v %v %v", f, cov, err)
	}
	s.Versions = nil
	f, cov, err = Match(context.Background(), c, s, now, WorkBudget{})
	if err != nil || len(f) != 0 || cov[0].Status != ReportPartial {
		t.Fatalf("%v %v %v", f, cov, err)
	}
}
func FuzzStableVersion(f *testing.F) {
	for _, v := range []string{"1.2.3", "1.2.3-rc1", "1.2.3+backport", "01.2.3", "999999999999999999.0.0", "1.104.2-t0123456ab", "1.104.2-t0123456ab-gfedcba987", "1.104.2-g0123456ab", "1.104.2-t012345", "1.104.2-t0123456AB"} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, ok := parseVersion(s)
		if ok {
			canonical := fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
			if s != canonical {
				t.Fatalf("noncanonical %q", s)
			}
		}
		// parseRelease must accept exactly the grammar of the design, whatever the input,
		// and a bare release must read the same through both parsers.
		r, rok := parseRelease(s)
		m := releaseGrammar.FindStringSubmatch(s)
		if rok != (m != nil) {
			t.Fatalf("parseRelease(%q) ok=%v but grammar match=%v", s, rok, m != nil)
		}
		if rok {
			for i := 0; i < 3; i++ {
				if n, err := strconv.ParseUint(m[i+1], 10, 64); err != nil || n != r[i] {
					t.Fatalf("parseRelease(%q) component %d = %d, grammar says %q", s, i, r[i], m[i+1])
				}
			}
		}
		if ok && (!rok || r != v) {
			t.Fatalf("bare release %q reads differently through parseRelease", s)
		}
	})
}

func TestRuntimeExclusionNeedsRuntimeOrigin(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, origin := range []Origin{OriginOperator, OriginAPI, OriginVendor, OriginDerived, OriginLocal, OriginCollector} {
		t.Run(string(origin), func(t *testing.T) {
			c, s := testInputs(now, "1.30.0")
			c.Records[0].RequiredFeatures = []string{"ssh"}
			disabled := false
			e := s.Versions[0].Evidence
			e.Origin = origin
			s.Features = []FeatureFact{{Name: "ssh", Value: &disabled, Evidence: e}}
			f, cov, err := Match(context.Background(), c, s, now, WorkBudget{})
			if err != nil || len(f) != 1 {
				t.Fatalf("%v %v", f, err)
			}
			if origin == OriginLocal || origin == OriginCollector {
				if f[0].Applicability != ApplicabilityNotAffected || cov[0].Status != ReportComplete {
					t.Fatalf("%v %v", f, cov)
				}
			} else if f[0].Applicability == ApplicabilityNotAffected || cov[0].Status != ReportPartial {
				t.Fatalf("untrusted exclusion: %v %v", f, cov)
			}
		})
	}
}
func TestRuntimePlatformExclusionNeedsRuntimeOrigin(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, s := testInputs(now, "1.30.0")
	c.Records[0].OS = "linux"
	e := s.Versions[0].Evidence
	e.Origin = OriginOperator
	s.Platforms = []PlatformFact{{OS: "windows", Evidence: e}}
	f, cov, err := Match(context.Background(), c, s, now, WorkBudget{})
	if err != nil || len(f) != 1 || f[0].Applicability == ApplicabilityNotAffected || cov[0].Status != ReportPartial {
		t.Fatalf("%v %v %v", f, cov, err)
	}
}
func TestStaleOrUnapprovedCatalogCoverageIsPartial(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		change   func(*Catalog)
		findings int
		want     Applicability
	}{
		{"expired", func(c *Catalog) { c.ExpiresAt = now }, 1, ApplicabilityAffected},
		{"future", func(c *Catalog) { c.IssuedAt = now.Add(time.Minute) }, 1, ApplicabilityAffected},
		{"review expired", func(c *Catalog) { c.Records[0].ReviewExpiresAt = now }, 1, ApplicabilityAffected},
		{"pending", func(c *Catalog) { c.Records[0].ReviewState = ReviewPending }, 1, ApplicabilityUnknown},
		{"withdrawn", func(c *Catalog) { c.Records[0].ReviewState = ReviewWithdrawn }, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := testInputs(now, "1.30.0")
			tc.change(&c)
			f, cov, err := Match(context.Background(), c, s, now, WorkBudget{})
			if err != nil || len(f) != tc.findings || cov[0].Status != ReportPartial || (len(f) == 1 && f[0].Applicability != tc.want) {
				t.Fatalf("%v %v %v", f, cov, err)
			}
		})
	}
}

type countingContext struct {
	context.Context
	checks int
	stop   int
}

func (c *countingContext) Err() error {
	c.checks++
	if c.checks >= c.stop {
		return context.Canceled
	}
	return nil
}
func TestCatalogValidationStopsForCancellation(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, s := testInputs(now, "1.30.0")
	for i := 1; i < 30; i++ {
		r := c.Records[0]
		r.ID = fmt.Sprintf("rule-%d", i)
		c.Records = append(c.Records, r)
	}
	c.Records[len(c.Records)-1].Source = ""
	ctx := &countingContext{Context: context.Background(), stop: 5}
	_, cov, err := Match(ctx, c, s, now, WorkBudget{})
	if !errors.Is(err, context.Canceled) || len(cov) != 1 || cov[0].Status != ReportPartial {
		t.Fatalf("%v %v", cov, err)
	}
}
func TestCatalogPreflightsNestedBounds(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, _ := testInputs(now, "1.30.0")
	c.Records[0].RequiredFeatures = make([]string, MaxRanges+1)
	c.Records[0].RequiredFeatures[0] = strings.Repeat("x", MaxTextBytes+1)
	if err := ValidateCatalog(c); err == nil || !strings.Contains(err.Error(), "too many required features") || strings.Contains(err.Error(), "oversized") {
		t.Fatalf("structural bounds not checked first: %v", err)
	}
	c, _ = testInputs(now, "1.30.0")
	c.Records[0].Ranges = make([]VersionRange, MaxRanges+1)
	c.Records[0].Ranges[0] = VersionRange{Introduced: strings.Repeat("9", MaxTextBytes+1)}
	if err := ValidateCatalog(c); err == nil || !strings.Contains(err.Error(), "too many ranges") || strings.Contains(err.Error(), "invalid introduced") {
		t.Fatalf("structural bounds not checked first: %v", err)
	}
}

func TestExclusionOriginMatchesVersionRole(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name           string
		role           VersionRole
		versionOrigin  Origin
		evidenceOrigin Origin
		trusted        bool
	}{
		{"api operator", VersionAPIReported, OriginAPI, OriginOperator, false},
		{"api api", VersionAPIReported, OriginAPI, OriginAPI, true},
		{"cli operator", VersionLocalCLI, OriginLocal, OriginOperator, false},
		{"cli local", VersionLocalCLI, OriginLocal, OriginLocal, true},
		{"cli collector", VersionLocalCLI, OriginCollector, OriginCollector, true},
	} {
		for _, kind := range []string{"feature", "platform"} {
			t.Run(tc.name+" "+kind, func(t *testing.T) {
				c, s := testInputs(now, "1.30.0")
				c.Records[0].VersionRole = tc.role
				s.Versions[0].Role = tc.role
				s.Versions[0].Evidence.Origin = tc.versionOrigin
				e := s.Versions[0].Evidence
				e.Origin = tc.evidenceOrigin
				if kind == "feature" {
					c.Records[0].RequiredFeatures = []string{"ssh"}
					disabled := false
					s.Features = []FeatureFact{{Name: "ssh", Value: &disabled, Evidence: e}}
				} else {
					c.Records[0].OS = "linux"
					s.Platforms = []PlatformFact{{OS: "windows", Evidence: e}}
				}
				f, cov, err := Match(context.Background(), c, s, now, WorkBudget{})
				if err != nil || len(f) != 1 {
					t.Fatalf("%v %v", f, err)
				}
				if tc.trusted {
					if f[0].Applicability != ApplicabilityNotAffected || cov[0].Status != ReportComplete {
						t.Fatalf("trusted exclusion: %v %v", f, cov)
					}
				} else if f[0].Applicability == ApplicabilityNotAffected || cov[0].Status != ReportPartial {
					t.Fatalf("untrusted exclusion: %v %v", f, cov)
				}
			})
		}
	}
}

func TestStoppedEarlyReadsOnlyCatalogPrefix(t *testing.T) {
	row := Coverage{Target: CoverageTarget{Dimension: CoverageCatalog}, Source: coverageSource, Explanation: "evaluation stopped early: work budget exhausted; pending rules: 1"}
	if !StoppedEarly(Report{Coverage: []Coverage{row}}) {
		t.Fatal("missed stopped evaluation")
	}
	row.Source = "another source"
	if StoppedEarly(Report{Coverage: []Coverage{row}}) {
		t.Fatal("matched another source")
	}
	row.Source = coverageSource
	row.Explanation = "pending rules: 1; evaluation stopped early: work budget exhausted"
	if StoppedEarly(Report{Coverage: []Coverage{row}}) {
		t.Fatal("matched a non-prefix")
	}
}
