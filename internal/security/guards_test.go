package security

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Direct tests of guards that the matcher's and the validator's earlier checks make
// unreachable from the public functions: Match refuses a snapshot whose evidence the
// report rules refuse before usable() sees it, and ValidateReport refuses a report before
// the claim checks see its evidence. The guards are still part of the contract of the
// function they are in, and a mutation test removes each one. Each case here changes one
// thing and says which.

// ---- usable() ------------------------------------------------------------------------

func TestUsableRefusesEachViolationAlone(t *testing.T) {
	now := mNow
	snap := Snapshot{Context: mCtx, Scope: ScopeLocal}
	good := func() EvidenceRef {
		return EvidenceRef{Context: mCtx, Asset: mAsset, Scope: ScopeLocal, Origin: OriginLocal, AcquiredAt: now.Add(-time.Minute), Freshness: FreshnessFresh}
	}
	observed := func(d time.Duration) func(e *EvidenceRef) {
		return func(e *EvidenceRef) { t := now.Add(d); e.ObservedAt = &t }
	}
	for _, tc := range []struct {
		name  string
		asset string
		edit  func(e *EvidenceRef)
		want  bool
	}{
		{"a fresh local observation", mAsset, func(e *EvidenceRef) {}, true},
		{"another snapshot's context", mAsset, func(e *EvidenceRef) { e.Context = "other" }, false},
		{"another device", "other", func(e *EvidenceRef) {}, false},
		{"another scope", mAsset, func(e *EvidenceRef) { e.Scope = ScopeFleet }, false},
		{"no scope", mAsset, func(e *EvidenceRef) { e.Scope = "" }, false},
		{"freshness unknown", mAsset, func(e *EvidenceRef) { e.Freshness = FreshnessUnknown }, false},
		{"freshness stale", mAsset, func(e *EvidenceRef) { e.Freshness = FreshnessStale }, false},
		{"freshness not set", mAsset, func(e *EvidenceRef) { e.Freshness = "" }, false},
		{"an error", mAsset, func(e *EvidenceRef) { e.Error = "read failed" }, false},
		{"never acquired", mAsset, func(e *EvidenceRef) { e.AcquiredAt = time.Time{} }, false},
		{"acquired after the evaluation time", mAsset, func(e *EvidenceRef) { e.AcquiredAt = now.Add(time.Nanosecond) }, false},
		{"acquired at the evaluation time", mAsset, func(e *EvidenceRef) { e.AcquiredAt = now }, true},
		{"acquired exactly 30 minutes before", mAsset, func(e *EvidenceRef) { e.AcquiredAt = now.Add(-30 * time.Minute) }, true},
		{"acquired 30 minutes and a nanosecond before", mAsset, func(e *EvidenceRef) { e.AcquiredAt = now.Add(-30*time.Minute - time.Nanosecond) }, false},
		{"observed exactly 30 minutes before", mAsset, observed(-30 * time.Minute), true},
		{"observed 30 minutes and a nanosecond before", mAsset, observed(-30*time.Minute - time.Nanosecond), false},
		{"observed when it was acquired", mAsset, func(e *EvidenceRef) { t := e.AcquiredAt; e.ObservedAt = &t }, true},
		{"observed a nanosecond after it was acquired", mAsset, func(e *EvidenceRef) { t := e.AcquiredAt.Add(time.Nanosecond); e.ObservedAt = &t }, false},
		{"an observation time that is the zero time", mAsset, func(e *EvidenceRef) { t := time.Time{}; e.ObservedAt = &t }, false},
		{"origin api", mAsset, func(e *EvidenceRef) { e.Origin = OriginAPI }, true},
		{"origin collector", mAsset, func(e *EvidenceRef) { e.Origin = OriginCollector }, true},
		{"origin operator", mAsset, func(e *EvidenceRef) { e.Origin = OriginOperator }, true},
		{"origin vendor", mAsset, func(e *EvidenceRef) { e.Origin = OriginVendor }, true},
		{"origin derived", mAsset, func(e *EvidenceRef) { e.Origin = OriginDerived }, true},
		{"no origin", mAsset, func(e *EvidenceRef) { e.Origin = "" }, false},
		{"an origin outside the vocabulary", mAsset, func(e *EvidenceRef) { e.Origin = "rumour" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := good()
			tc.edit(&e)
			if got := usable(e, snap, tc.asset, now); got != tc.want {
				t.Fatalf("usable = %v, want %v for %+v", got, tc.want, e)
			}
		})
	}
}

func TestRoleOriginOKIsTheTableOfAllowedOrigins(t *testing.T) {
	origins := []Origin{OriginAPI, OriginLocal, OriginCollector, OriginOperator, OriginVendor, OriginDerived, "", "rumour"}
	allowed := map[VersionRole][]Origin{
		VersionRunningDaemon: {OriginLocal, OriginCollector},
		VersionLocalCLI:      {OriginLocal, OriginCollector},
		VersionAPIReported:   {OriginAPI},
		"":                   nil,
		"primary":            nil,
	}
	for role, ok := range allowed {
		for _, origin := range origins {
			want := false
			for _, o := range ok {
				want = want || o == origin
			}
			if got := roleOriginOK(role, origin); got != want {
				t.Errorf("roleOriginOK(%q, %q) = %v, want %v", role, origin, got, want)
			}
		}
	}
}

// ---- validateEvidence() ----------------------------------------------------------------

func TestValidateEvidenceChecksEachFieldAlone(t *testing.T) {
	r := Report{Context: mCtx, GeneratedAt: mNow}
	good := func() EvidenceRef {
		return EvidenceRef{Context: mCtx, Asset: mAsset, Scope: ScopeLocal, Origin: OriginLocal, AcquiredAt: mNow, Freshness: FreshnessFresh}
	}
	at := func(t time.Time) *time.Time { return &t }
	for _, tc := range []struct {
		name string
		edit func(e *EvidenceRef)
		want string // empty: accepted
	}{
		{"as it is", func(e *EvidenceRef) {}, ""},
		{"another context", func(e *EvidenceRef) { e.Context = "other" }, "evidence context does not match the report"},
		{"never acquired", func(e *EvidenceRef) { e.AcquiredAt = time.Time{} }, "evidence acquisition time is missing or after the report was generated"},
		{"acquired after the report", func(e *EvidenceRef) { e.AcquiredAt = mNow.Add(time.Nanosecond) }, "evidence acquisition time is missing or after the report was generated"},
		{"observed when it was acquired", func(e *EvidenceRef) { e.ObservedAt = at(e.AcquiredAt) }, ""},
		{"observed at the zero time", func(e *EvidenceRef) { e.ObservedAt = at(time.Time{}) }, "evidence observation time is missing or after its acquisition"},
		{"observed after it was acquired", func(e *EvidenceRef) { e.ObservedAt = at(e.AcquiredAt.Add(time.Nanosecond)) }, "evidence observation time is missing or after its acquisition"},
		{"no scope", func(e *EvidenceRef) { e.Scope = "" }, ""},
		{"scope fleet", func(e *EvidenceRef) { e.Scope = ScopeFleet }, ""},
		{"a scope outside the vocabulary", func(e *EvidenceRef) { e.Scope = "all" }, "invalid evidence scope"},
		{"origin api", func(e *EvidenceRef) { e.Origin = OriginAPI }, ""},
		{"origin collector", func(e *EvidenceRef) { e.Origin = OriginCollector }, ""},
		{"origin operator", func(e *EvidenceRef) { e.Origin = OriginOperator }, ""},
		{"origin vendor", func(e *EvidenceRef) { e.Origin = OriginVendor }, ""},
		{"origin derived", func(e *EvidenceRef) { e.Origin = OriginDerived }, ""},
		{"no origin", func(e *EvidenceRef) { e.Origin = "" }, "invalid evidence origin"},
		{"an origin outside the vocabulary", func(e *EvidenceRef) { e.Origin = "rumour" }, "invalid evidence origin"},
		{"freshness unknown", func(e *EvidenceRef) { e.Freshness = FreshnessUnknown }, ""},
		{"freshness stale", func(e *EvidenceRef) { e.Freshness = FreshnessStale }, ""},
		{"no freshness", func(e *EvidenceRef) { e.Freshness = "" }, "invalid evidence freshness"},
		{"a freshness outside the vocabulary", func(e *EvidenceRef) { e.Freshness = "fresh-ish" }, "invalid evidence freshness"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := good()
			tc.edit(&e)
			err := validateEvidence(e, r)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.want != "" && (err == nil || err.Error() != tc.want):
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// A finding that says a device is, or is not, affected cites evidence about that device in
// that context. ValidateReport reaches these checks only with evidence that already has
// the report's context; the check is still the claim's own.
func TestFindingClaimChecksTheContextAndDeviceOfItsEvidence(t *testing.T) {
	for _, app := range []Applicability{ApplicabilityAffected, ApplicabilityNotAffected} {
		finding := func(edit func(e *EvidenceRef)) (Finding, evidenceSet) {
			e := EvidenceRef{Context: "ctx", Asset: "dev", Freshness: FreshnessFresh}
			edit(&e)
			// The snapshot holds what the finding cites, so that only the context and the
			// device can refuse it.
			return Finding{Context: "ctx", Asset: "dev", Applicability: app, EvidenceState: EvidenceObserved, Confidence: ConfidenceReported, Evidence: []EvidenceRef{e}},
				evidenceSet{keyOfEvidence(e): {}}
		}
		t.Run(string(app), func(t *testing.T) {
			if f, held := finding(func(e *EvidenceRef) {}); validateFindingClaim(f, held) != nil {
				t.Fatalf("refused: %v", validateFindingClaim(f, held))
			}
			for name, edit := range map[string]func(e *EvidenceRef){
				"another context": func(e *EvidenceRef) { e.Context = "other" },
				"another device":  func(e *EvidenceRef) { e.Asset = "other" },
				"both":            func(e *EvidenceRef) { e.Context, e.Asset = "other", "other" },
			} {
				f, held := finding(edit)
				err := validateFindingClaim(f, held)
				if err == nil || err.Error() != "affected or not affected finding cites evidence for another context or device" {
					t.Errorf("%s: %v", name, err)
				}
			}
		})
	}
}

// ---- ranges --------------------------------------------------------------------------------

// rangesOverlap and validateRanges agree with the intervals the ranges describe: two ranges
// overlap exactly when some release is inside both. The bounds include open ends on both
// sides, so every mixture of open and closed ends is tried, and the triples show that a
// range is checked against all the ranges before it and not only the one next to it.
func TestRangesOverlapAgreesWithTheIntervals(t *testing.T) {
	bounds := []string{"", "1.30.0", "1.32.0", "1.34.0"}
	var ranges []VersionRange
	for _, i := range bounds {
		for _, f := range bounds {
			if (i == "" && f == "") || (i != "" && f != "" && i >= f) {
				continue
			}
			ranges = append(ranges, VersionRange{Introduced: i, Fixed: f})
		}
	}
	if len(ranges) != 9 {
		t.Fatalf("%d ranges", len(ranges))
	}
	// One release in each region the bounds make: below, between each pair, and above.
	samples := []numericVersion{{1, 28, 0}, {1, 30, 0}, {1, 31, 0}, {1, 32, 0}, {1, 33, 0}, {1, 34, 0}, {1, 35, 0}, {2, 0, 0}}
	overlap := func(a, b VersionRange) bool {
		for _, s := range samples {
			if insideRange(s, a) && insideRange(s, b) {
				return true
			}
		}
		return false
	}
	ctx := context.Background()
	text := func(rs ...VersionRange) string { return fmt.Sprintf("%+v", rs) }
	for _, a := range ranges {
		for _, b := range ranges {
			want := overlap(a, b)
			if got := rangesOverlap(a, b); got != want {
				t.Errorf("rangesOverlap(%+v, %+v) = %v, want %v", a, b, got, want)
			}
			err := validateRanges(ctx, []VersionRange{a, b})
			if want != (err != nil) || (err != nil && !strings.Contains(err.Error(), "range 1: overlapping ranges")) {
				t.Errorf("validateRanges(%s) = %v, want overlap %v", text(a, b), err, want)
			}
			for _, c := range ranges {
				want3 := overlap(a, b) || overlap(a, c) || overlap(b, c)
				err := validateRanges(ctx, []VersionRange{a, b, c})
				if want3 != (err != nil) || (err != nil && !strings.Contains(err.Error(), "overlapping ranges")) {
					t.Errorf("validateRanges(%s) = %v, want overlap %v", text(a, b, c), err, want3)
				}
			}
		}
	}
}

// ---- vocabularies ------------------------------------------------------------------------

// Every member of each closed vocabulary of a report is accepted, so a check cannot drop
// one without a test failing, and the fixture's own member is not the only one tried.
func TestReportAcceptsEveryMemberOfEachVocabulary(t *testing.T) {
	accept := func(t *testing.T, name string, edit func(r *Report)) {
		t.Helper()
		r := rulesPartial()
		edit(&r)
		if err := ValidateReport(r); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, s := range []Severity{SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		accept(t, "severity "+string(s), func(r *Report) { r.Findings[0].SourceSeverity = s })
	}
	for _, p := range []Priority{PriorityUnknown, PriorityLow, PriorityMedium, PriorityHigh, PriorityUrgent} {
		accept(t, "priority "+string(p), func(r *Report) { r.Findings[0].Priority = p })
	}
	for _, c := range []Confidence{ConfidenceUnknown, ConfidenceReported, ConfidenceDerived} {
		accept(t, "confidence "+string(c), func(r *Report) { r.Findings[0].Confidence = c })
	}
	for _, s := range []EvidenceState{EvidenceObserved, EvidenceUnknown, EvidenceStale, EvidenceAbsent} {
		accept(t, "evidence state "+string(s)+" on a potentially affected finding", func(r *Report) { r.Findings[1].EvidenceState = s })
	}
	for _, d := range []CoverageDimension{CoveragePolicy, CoverageVersions, CoverageFeatures, CoverageIntent, CoverageCatalog} {
		for _, scope := range []Scope{ScopeFleet, ScopeLocal} {
			target := CoverageTarget{Dimension: d, Scope: scope}
			accept(t, fmt.Sprintf("requested target %v", target), func(r *Report) { r.RequestedCoverage = append(r.RequestedCoverage, target) })
			accept(t, fmt.Sprintf("coverage row %v", target), func(r *Report) {
				r.Coverage = append(r.Coverage, Coverage{Target: target, Context: rulesCtx, Status: ReportPartial, Explanation: "synthetic"})
			})
		}
	}
	for _, role := range []VersionRole{VersionAPIReported, VersionLocalCLI, VersionRunningDaemon} {
		for _, ch := range []VersionChannel{ChannelStable, ChannelUnstable, ChannelUnknown} {
			accept(t, fmt.Sprintf("version role %s channel %s", role, ch), func(r *Report) {
				r.Snapshot.Versions[0].Role, r.Snapshot.Versions[0].Channel = role, ch
			})
		}
	}
}

// A target needs both a dimension and a scope of the vocabulary.
func TestReportRefusesATargetWithoutADimensionOrScope(t *testing.T) {
	for name, target := range map[string]CoverageTarget{
		"no scope":          {Dimension: CoverageCatalog},
		"no dimension":      {Scope: ScopeLocal},
		"another dimension": {Dimension: "advisories", Scope: ScopeLocal},
		"another scope":     {Dimension: CoverageCatalog, Scope: "all"},
	} {
		r := rulesPartial()
		r.RequestedCoverage = append(r.RequestedCoverage, target)
		if err := ValidateReport(r); err == nil || err.Error() != "invalid requested coverage" {
			t.Errorf("requested, %s: %v", name, err)
		}
		r = rulesPartial()
		r.Coverage = append(r.Coverage, Coverage{Target: target, Context: rulesCtx, Status: ReportPartial, Explanation: "synthetic"})
		if err := ValidateReport(r); err == nil || err.Error() != "invalid coverage target" {
			t.Errorf("row, %s: %v", name, err)
		}
	}
}

// Every policy fact is checked, not only the first.
func TestReportChecksEveryPolicyFact(t *testing.T) {
	for _, bad := range []int{0, 1, 2} {
		r := rulesPartial()
		extra := r.Snapshot.Policies[0]
		r.Snapshot.Policies = []PolicyFact{extra, extra, extra}
		r.Snapshot.Policies[bad].Evidence.Context = "other"
		err := ValidateReport(r)
		if err == nil || err.Error() != "evidence context does not match the report" {
			t.Errorf("policy fact %d of 3: %v", bad, err)
		}
	}
}

// ---- cancellation -----------------------------------------------------------------------

// Catalog validation looks at the context while it works: at least once per record in each
// of its two passes, and once per range and per earlier range it compares a range with, so
// a large catalog can be abandoned between records and not only at its end.
func TestCatalogValidationLooksAtTheContextWhileItWorks(t *testing.T) {
	const records, rangesEach = 10, 3
	base, _ := catalogFixture()
	c := base
	c.Records = nil
	for i := 0; i < records; i++ {
		r := base.Records[0]
		r.ID = fmt.Sprintf("TEST-%d", i)
		r.Ranges = evenRanges(rangesEach)
		c.Records = append(c.Records, r)
	}
	ctx := &countingContext{Context: context.Background(), stop: 1 << 30}
	if err := validateCatalog(ctx, c); err != nil {
		t.Fatal(err)
	}
	pairs := rangesEach * (rangesEach - 1) / 2
	floor := 2*records + records*rangesEach + records*pairs
	if ctx.checks < floor {
		t.Fatalf("the context was looked at %d times, want at least %d (two passes over %d records, %d ranges, %d comparisons each)",
			ctx.checks, floor, records, rangesEach, pairs)
	}
	requireEveryLookIsHeeded(t, c, ctx.checks)

	// A cancellation is sticky, so a look that was not heeded would be made good by the next
	// one. The last look of a validation has no next: these catalogs end in a record with no
	// range, and in a record with one range.
	for name, build := range map[string]func(r *AdvisoryRecord){
		"a withdrawn record without ranges": func(r *AdvisoryRecord) { r.ReviewState, r.Ranges = ReviewWithdrawn, nil },
		"a record with one range":           func(r *AdvisoryRecord) { r.Ranges = evenRanges(1) },
	} {
		small := base
		small.Records = []AdvisoryRecord{base.Records[0]}
		build(&small.Records[0])
		probe := &countingContext{Context: context.Background(), stop: 1 << 30}
		if err := validateCatalog(probe, small); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Run(name, func(t *testing.T) { requireEveryLookIsHeeded(t, small, probe.checks) })
	}
}

// requireEveryLookIsHeeded checks that validating c, which looks at the context looks times,
// is stopped by a cancellation at any one of them, and is not stopped by one after the last.
func requireEveryLookIsHeeded(t *testing.T, c Catalog, looks int) {
	t.Helper()
	for stop := 1; stop <= looks; stop++ {
		if err := validateCatalog(&countingContext{Context: context.Background(), stop: stop}, c); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled at look %d of %d: %v", stop, looks, err)
		}
	}
	if err := validateCatalog(&countingContext{Context: context.Background(), stop: looks + 1}, c); err != nil {
		t.Fatalf("cancelled after the last look: %v", err)
	}
}

// A snapshot may hold at most 10,000 facts of all four kinds together, and every kind counts
// toward them.
func TestMatchCountsEveryKindOfFactTowardTheSnapshotLimit(t *testing.T) {
	build := func(versions, platforms, features, policies int) *world {
		w := newWorld(ScopeLocal)
		w.c.Records = nil
		for i := 0; i < versions; i++ {
			w.version(fmt.Sprintf("d%d", i), VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
		}
		for i := 0; i < platforms; i++ {
			w.platform(fmt.Sprintf("d%d", i), OriginLocal, "linux")
		}
		for i := 0; i < features; i++ {
			w.feature(fmt.Sprintf("d%d", i), OriginLocal, "ssh", true)
		}
		for i := 0; i < policies; i++ {
			w.s.Policies = append(w.s.Policies, PolicyFact{Name: fmt.Sprintf("p%d", i), Evidence: w.ev(OriginAPI, "")})
		}
		return w
	}
	for _, tc := range []struct {
		name                                    string
		versions, platforms, features, policies int
		refused                                 bool
	}{
		{"10000 of one kind", 10000, 0, 0, 0, false},
		{"2500 of each kind", 2500, 2500, 2500, 2500, false},
		{"one more version fact", 2500, 2500, 2500, 2501, true},
		{"10000 version facts and a platform fact", 10000, 1, 0, 0, true},
		{"10000 version facts and a feature fact", 10000, 0, 1, 0, true},
		{"10000 version facts and a policy fact", 10000, 0, 0, 1, true},
		{"5000 version facts and 5001 feature facts", 5000, 0, 5001, 0, true},
		{"5001 platform facts and 5000 policy facts", 0, 5001, 0, 5000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := build(tc.versions, tc.platforms, tc.features, tc.policies)
			_, _, err := w.match(WorkBudget{})
			switch {
			case tc.refused && (err == nil || err.Error() != "too many snapshot observations"):
				t.Fatalf("accepted %d facts: %v", tc.versions+tc.platforms+tc.features+tc.policies, err)
			case !tc.refused && err != nil:
				t.Fatal(err)
			}
		})
	}
}
