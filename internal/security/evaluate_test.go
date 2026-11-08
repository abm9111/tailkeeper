package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Everything here is synthetic. The cases build a world (see match_world_test.go), give it
// the coverage rows a collection would, and judge it by Evaluate.

// collectedRows are the rows a collection reports for the dimensions it feeds.
func collectedRows(w *world, status ReportStatus) []Coverage {
	rows := make([]Coverage, 0, 2)
	for _, d := range []CoverageDimension{CoverageVersions, CoverageFeatures} {
		row := Coverage{Target: CoverageTarget{Dimension: d, Scope: w.s.Scope}, Context: w.s.Context, Source: "security collection", Status: status}
		if status == ReportPartial {
			row.Explanation = "synthetic gap in " + string(d)
		}
		rows = append(rows, row)
	}
	return rows
}

func (w *world) input(status ReportStatus) Input {
	return Input{Catalog: w.c, Snapshot: w.s, Collected: collectedRows(w, status), Now: w.now}
}

func mustEvaluate(t *testing.T, in Input) Report {
	t.Helper()
	r, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if err := ValidateReport(r); err != nil {
		t.Fatalf("Evaluate returned a report that does not validate: %v", err)
	}
	return r
}

func rowFor(r Report, d CoverageDimension) (Coverage, bool) {
	for _, c := range r.Coverage {
		if c.Target.Dimension == d {
			return c, true
		}
	}
	return Coverage{}, false
}

// affectedWorld has one device whose running daemon is in range of the one approved rule.
func affectedWorld(scope Scope) *world {
	w := newWorld(scope)
	w.daemon("1.30.0")
	return w
}

func TestEvaluateBuildsAValidReportOfTheMatch(t *testing.T) {
	w := affectedWorld(ScopeFleet)
	r := mustEvaluate(t, w.input(ReportComplete))
	if len(r.Findings) != 1 || r.Findings[0].Applicability != ApplicabilityAffected || r.TotalFindings != 1 || r.Truncated {
		t.Fatalf("findings %+v total %d truncated %v", r.Findings, r.TotalFindings, r.Truncated)
	}
	if r.Context != mCtx || !r.GeneratedAt.Equal(w.now) || r.SchemaVersion != SchemaVersion {
		t.Errorf("header: %+v", r)
	}
	// No intent set is configured, so intent is not among what was requested.
	want := []CoverageTarget{{CoverageVersions, ScopeFleet, ""}, {CoverageFeatures, ScopeFleet, ""}, {CoverageCatalog, ScopeFleet, ""}}
	if !reflect.DeepEqual(r.RequestedCoverage, want) {
		t.Errorf("requested coverage %v, want %v", r.RequestedCoverage, want)
	}
	if !reflect.DeepEqual(r.Snapshot, w.s) {
		t.Errorf("the report's snapshot differs from the input's")
	}
}

// Intent that is not configured is not requested: the report says so in a row of its own,
// which is never silent and never what keeps a report from being complete. Everything that was
// requested here is complete, so the report is.
func TestEvaluateUnconfiguredIntentIsAnExplicitNotRequestedRowAndDoesNotBlockCompleteness(t *testing.T) {
	w := newWorld(ScopeLocal)
	w.daemon("1.40.0") // not affected: nothing else is wrong
	r := mustEvaluate(t, w.input(ReportComplete))
	row, ok := rowFor(r, CoverageIntent)
	if !ok {
		t.Fatal("no intent row: an intent that was not requested is silent")
	}
	if row.Status != CoverageNotRequested || !strings.Contains(row.Explanation, "not requested") || !strings.Contains(row.Explanation, "no intent set is configured") ||
		row.Context != mCtx || row.Counts != nil {
		t.Errorf("intent row: %+v", row)
	}
	for _, target := range r.RequestedCoverage {
		if target.Dimension == CoverageIntent {
			t.Errorf("intent is requested: %v", r.RequestedCoverage)
		}
	}
	for _, d := range []CoverageDimension{CoverageVersions, CoverageFeatures, CoverageCatalog} {
		if c, _ := rowFor(r, d); c.Status != ReportComplete {
			t.Fatalf("the premise: %s is %s, and this case needs everything requested to be complete", d, c.Status)
		}
	}
	if r.Status != ReportComplete {
		t.Errorf("a report whose every requested target is complete is %s", r.Status)
	}
	if r.IntentDigest != "" || r.IntentRevision != "" {
		t.Errorf("a report with no intent names one: %q %q", r.IntentDigest, r.IntentRevision)
	}
	// A finding that is affected does not make the catalog row partial: it is a finding.
	w2 := affectedWorld(ScopeLocal)
	if r2 := mustEvaluate(t, w2.input(ReportComplete)); r2.Status != ReportComplete || len(r2.Findings) != 1 {
		t.Errorf("an affected device: status %s, %d findings", r2.Status, len(r2.Findings))
	}
}

// Whatever else is partial still is: not requesting intent hides no gap.
func TestEvaluateUnconfiguredIntentHidesNoOtherGap(t *testing.T) {
	w := newWorld(ScopeLocal)
	w.daemon("1.40.0")
	if r := mustEvaluate(t, w.input(ReportPartial)); r.Status != ReportPartial {
		t.Errorf("a collection with gaps: %s", r.Status)
	}
	w.c.Records[0].ReviewState = ReviewPending
	if r := mustEvaluate(t, w.input(ReportComplete)); r.Status != ReportPartial {
		t.Errorf("a pending rule: %s", r.Status)
	}
}

// An intent set that is supplied is requested, named in the report, and still not judged:
// this version judges no expectation, so claiming it did would be a false all-clear.
func TestEvaluateASuppliedIntentIsRequestedNamedButNotJudged(t *testing.T) {
	w := newWorld(ScopeLocal)
	w.daemon("1.40.0")
	in := w.input(ReportComplete)
	in.Intent = &IntentSet{SchemaVersion: 1, Revision: "r-7", Digest: "d1", Network: []NetworkExpectation{{ID: "n1", Source: "src"}}}
	r := mustEvaluate(t, in)
	row, ok := rowFor(r, CoverageIntent)
	if !ok || row.Status != ReportPartial || !strings.Contains(row.Explanation, "not evaluated") || !strings.Contains(row.Explanation, "1 expectation") {
		t.Errorf("intent row: %+v", row)
	}
	if strings.Contains(row.Explanation, "r-7") {
		t.Errorf("the row echoes the intent's revision: %q", row.Explanation)
	}
	if !slices.Contains(r.RequestedCoverage, CoverageTarget{Dimension: CoverageIntent, Scope: ScopeLocal}) {
		t.Errorf("a supplied intent is not requested: %v", r.RequestedCoverage)
	}
	if r.IntentDigest != "d1" || r.IntentRevision != "r-7" || r.Status != ReportPartial {
		t.Errorf("digest %q revision %q status %s", r.IntentDigest, r.IntentRevision, r.Status)
	}
	// An empty set proves nothing and is not a pass either.
	in.Intent = &IntentSet{SchemaVersion: 1, Revision: "r-0", Digest: "d0"}
	if r := mustEvaluate(t, in); r.Status != ReportPartial {
		t.Errorf("an empty intent set: %s", r.Status)
	}
}

func TestStatusIsCompleteOnlyWhenEveryRequestedTargetIsComplete(t *testing.T) {
	versions := CoverageTarget{Dimension: CoverageVersions, Scope: ScopeFleet}
	catalog := CoverageTarget{Dimension: CoverageCatalog, Scope: ScopeFleet}
	done := func(t CoverageTarget) Coverage { return Coverage{Target: t, Status: ReportComplete} }
	gap := func(t CoverageTarget) Coverage { return Coverage{Target: t, Status: ReportPartial} }
	for _, tc := range []struct {
		name      string
		requested []CoverageTarget
		rows      []Coverage
		want      ReportStatus
	}{
		{"all complete", []CoverageTarget{versions, catalog}, []Coverage{done(versions), done(catalog)}, ReportComplete},
		{"one partial", []CoverageTarget{versions, catalog}, []Coverage{done(versions), gap(catalog)}, ReportPartial},
		{"a requested target without a row", []CoverageTarget{versions, catalog}, []Coverage{done(versions)}, ReportPartial},
		{"a partial row beside a complete one for the same target", []CoverageTarget{versions}, []Coverage{done(versions), gap(versions)}, ReportPartial},
		{"nothing requested", nil, nil, ReportPartial},
		{"a not_requested row beside complete ones", []CoverageTarget{versions, catalog},
			[]Coverage{done(versions), done(catalog), {Target: CoverageTarget{Dimension: CoverageIntent, Scope: ScopeFleet}, Status: CoverageNotRequested}}, ReportComplete},
		{"a not_requested row is no answer to a requested target", []CoverageTarget{versions, catalog},
			[]Coverage{done(versions), {Target: catalog, Status: CoverageNotRequested}}, ReportPartial},
		{"a partial row beside a not_requested one", []CoverageTarget{versions},
			[]Coverage{done(versions), gap(catalog), {Target: CoverageTarget{Dimension: CoverageIntent, Scope: ScopeFleet}, Status: CoverageNotRequested}}, ReportPartial},
	} {
		if got := statusOf(tc.requested, tc.rows); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

// With a collection that left a source out, the findings it did make stay in the report.
func TestEvaluatePartialCollectionKeepsTheFindings(t *testing.T) {
	w := affectedWorld(ScopeFleet)
	r := mustEvaluate(t, w.input(ReportPartial))
	if r.Status != ReportPartial {
		t.Errorf("status %s", r.Status)
	}
	if len(r.Findings) != 1 || r.Findings[0].Applicability != ApplicabilityAffected {
		t.Errorf("a gap in the collection dropped the finding: %+v", r.Findings)
	}
	for _, d := range []CoverageDimension{CoverageVersions, CoverageFeatures} {
		row, ok := rowFor(r, d)
		if !ok || row.Status != ReportPartial || !strings.Contains(row.Explanation, "synthetic gap") {
			t.Errorf("%s row: %+v", d, row)
		}
	}
}

// A collection that reported nothing for a dimension is a gap in that dimension, not a pass.
func TestEvaluateMissingCollectionRowsAreExplicitGaps(t *testing.T) {
	w := newWorld(ScopeLocal)
	w.daemon("1.40.0")
	in := w.input(ReportComplete)
	in.Collected = nil
	r := mustEvaluate(t, in)
	for _, d := range []CoverageDimension{CoverageVersions, CoverageFeatures} {
		row, ok := rowFor(r, d)
		if !ok || row.Status != ReportPartial || row.Explanation == "" {
			t.Errorf("%s row: %+v (present %v)", d, row, ok)
		}
	}
	if r.Status != ReportPartial {
		t.Errorf("status %s", r.Status)
	}
}

func TestEvaluateRefusesCollectedRowsItCannotTrust(t *testing.T) {
	w := newWorld(ScopeFleet)
	w.daemon("1.40.0")
	edit := func(f func(rows []Coverage) []Coverage) Input {
		in := w.input(ReportComplete)
		in.Collected = f(slices.Clone(in.Collected))
		return in
	}
	for name, in := range map[string]Input{
		"another context":         edit(func(r []Coverage) []Coverage { r[0].Context = "elsewhere"; return r }),
		"another scope":           edit(func(r []Coverage) []Coverage { r[0].Target.Scope = ScopeLocal; return r }),
		"a catalog row":           edit(func(r []Coverage) []Coverage { r[0].Target.Dimension = CoverageCatalog; return r }),
		"an intent row":           edit(func(r []Coverage) []Coverage { r[0].Target.Dimension = CoverageIntent; return r }),
		"a policy row":            edit(func(r []Coverage) []Coverage { r[0].Target.Dimension = CoveragePolicy; return r }),
		"a dimension twice":       edit(func(r []Coverage) []Coverage { return append(r, r[0]) }),
		"a partial row, no cause": edit(func(r []Coverage) []Coverage { r[0].Status = ReportPartial; return r }),
	} {
		t.Run(name, func(t *testing.T) {
			if r, err := Evaluate(context.Background(), in); err == nil {
				t.Fatalf("accepted: %+v", r.Coverage)
			}
		})
	}
}

// A catalog row of a snapshot is the matcher's; a caller cannot hand in a better one.
func TestEvaluateIgnoresNoRowOfTheMatcher(t *testing.T) {
	w := affectedWorld(ScopeFleet)
	r := mustEvaluate(t, w.input(ReportComplete))
	row, ok := rowFor(r, CoverageCatalog)
	if !ok || row.Counts == nil || row.Counts.Rules != 1 || row.Counts.Assets != 1 || row.Counts.Findings != 1 {
		t.Errorf("catalog row: %+v", row)
	}
}

func TestEvaluateInvalidInputReturnsNoReport(t *testing.T) {
	good := func() *world { w := newWorld(ScopeFleet); w.daemon("1.30.0"); return w }
	for name, in := range map[string]func() Input{
		"no time": func() Input { in := good().input(ReportComplete); in.Now = time.Time{}; return in },
		"snapshot ahead": func() Input {
			in := good().input(ReportComplete)
			in.Now = in.Snapshot.ObservedAt.Add(-time.Second)
			return in
		},
		"no context":      func() Input { w := good(); w.s.Context = ""; return w.input(ReportComplete) },
		"bad scope":       func() Input { w := good(); w.s.Scope = "all"; return w.input(ReportComplete) },
		"invalid catalog": func() Input { w := good(); w.c.Revision = 0; return w.input(ReportComplete) },
		"bad budget":      func() Input { in := good().input(ReportComplete); in.Budget = WorkBudget{Candidates: -1}; return in },
	} {
		t.Run(name, func(t *testing.T) {
			r, err := Evaluate(context.Background(), in())
			if err == nil {
				t.Fatalf("accepted: %+v", r)
			}
			if !reflect.DeepEqual(r, Report{}) {
				t.Errorf("an error came with a report: %+v", r)
			}
		})
	}
	var nilCtx context.Context // not the literal nil, which staticcheck refuses to let a test pass
	if _, err := Evaluate(nilCtx, good().input(ReportComplete)); err == nil {
		t.Error("a nil context was accepted")
	}
}

func TestEvaluateOrdersAffectedThenPotentialThenUnknownThenNotAffected(t *testing.T) {
	w := newWorld(ScopeFleet)
	w.c.Records = []AdvisoryRecord{w.rule("RULE-1")}
	w.c.Records[0].Severity = SeverityLow
	w.c.Records = append(w.c.Records, w.rule("RULE-2"))
	w.c.Records[1].Severity = SeverityCritical
	// d-clear: out of range of both. d-bad: in range of both. d-api: only the API's report,
	// which can only warn. d-none: no version at all.
	w.version("d-clear", VersionRunningDaemon, OriginLocal, ChannelStable, "1.40.0")
	w.version("d-bad", VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
	w.version("d-api", VersionAPIReported, OriginAPI, ChannelStable, "1.30.0")
	w.versionFact("client", "d-none", VersionAPIReported, OriginAPI, ChannelUnknown, nil)
	r := mustEvaluate(t, w.input(ReportComplete))
	type pair struct {
		asset, rule string
		a           Applicability
	}
	var got []pair
	for _, f := range r.Findings {
		got = append(got, pair{f.Asset, f.RuleID, f.Applicability})
	}
	want := []pair{
		{"d-bad", "RULE-2", ApplicabilityAffected}, {"d-bad", "RULE-1", ApplicabilityAffected}, // critical before low
		{"d-api", "RULE-1", ApplicabilityPotential}, {"d-api", "RULE-2", ApplicabilityPotential},
		{"d-none", "RULE-1", ApplicabilityUnknown}, {"d-none", "RULE-2", ApplicabilityUnknown},
		{"d-clear", "RULE-1", ApplicabilityNotAffected}, {"d-clear", "RULE-2", ApplicabilityNotAffected},
	}
	// d-api's findings are potentially affected only through the fallback; the severity order
	// puts RULE-2 first inside each group, so compare group by group.
	group := func(ps []pair, a Applicability) []pair {
		var out []pair
		for _, p := range ps {
			if p.a == a {
				out = append(out, p)
			}
		}
		return out
	}
	for _, a := range []Applicability{ApplicabilityAffected, ApplicabilityPotential, ApplicabilityUnknown, ApplicabilityNotAffected} {
		g, wg := group(got, a), group(want, a)
		if len(g) != len(wg) {
			t.Fatalf("%s: %v, want %v", a, g, wg)
		}
		for _, p := range wg {
			if !slices.Contains(g, p) {
				t.Errorf("%s: %v lacks %v", a, g, p)
			}
		}
	}
	rank := map[Applicability]int{ApplicabilityAffected: 0, ApplicabilityPotential: 1, ApplicabilityUnknown: 2, ApplicabilityNotAffected: 3}
	for i := 1; i < len(r.Findings); i++ {
		if rank[r.Findings[i-1].Applicability] > rank[r.Findings[i].Applicability] {
			t.Fatalf("finding %d (%s) comes after finding %d (%s)", i, r.Findings[i].Applicability, i-1, r.Findings[i-1].Applicability)
		}
	}
	// Inside a group the more severe rule comes first (RULE-2 is critical, RULE-1 low).
	for _, a := range []Applicability{ApplicabilityAffected, ApplicabilityNotAffected} {
		g := group(got, a)
		if len(g) == 2 && g[0].rule != "RULE-2" {
			t.Errorf("%s: %v lists the low rule before the critical one", a, g)
		}
	}
}

// The order is stable: findings of one group and severity keep the matcher's order.
func TestEvaluateSortIsStable(t *testing.T) {
	w := newWorld(ScopeFleet)
	// Two interleaved groups of many findings, so that an unstable sort would move some of
	// the findings inside a group.
	for i := 0; i < 400; i++ {
		version := "1.30.0" // affected
		if i%2 == 1 {
			version = "1.40.0" // not affected
		}
		w.version(fmt.Sprintf("dev-%03d", i), VersionRunningDaemon, OriginLocal, ChannelStable, version)
	}
	r := mustEvaluate(t, w.input(ReportComplete))
	findings, _, err := w.match(WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, a := range []Applicability{ApplicabilityAffected, ApplicabilityNotAffected} {
		for _, f := range findings {
			if f.Applicability == a {
				want = append(want, f.ID)
			}
		}
	}
	var got []string
	for _, f := range r.Findings {
		got = append(got, f.ID)
	}
	if !slices.Equal(got, want) {
		t.Fatal("findings of one group are not in the matcher's order")
	}
}

func TestEvaluateWorkBudgetStopIsAPartialReportNotAnError(t *testing.T) {
	w := newWorld(ScopeFleet)
	for i := 0; i < 5; i++ {
		w.version(fmt.Sprintf("dev-%d", i), VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
	}
	in := w.input(ReportComplete)
	in.Budget = WorkBudget{Candidates: 12}
	r, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("a spent work budget is an error: %v", err)
	}
	if err := ValidateReport(r); err != nil {
		t.Fatal(err)
	}
	row, _ := rowFor(r, CoverageCatalog)
	if r.Status != ReportPartial || row.Status != ReportPartial || !strings.Contains(row.Explanation, "work budget exhausted") {
		t.Errorf("status %s, catalog row %+v", r.Status, row)
	}
	if len(r.Findings) == 0 || len(r.Findings) >= 5 {
		t.Errorf("%d findings: want some, but not all 5", len(r.Findings))
	}
}

// The caller's own cancellation is an error as well as a partial report.
func TestEvaluateCallerCancellationReturnsTheErrorAndAPartialReport(t *testing.T) {
	w := affectedWorld(ScopeFleet)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := Evaluate(ctx, w.input(ReportComplete))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v", err)
	}
	if verr := ValidateReport(r); verr != nil {
		t.Fatalf("the partial report does not validate: %v", verr)
	}
	row, _ := rowFor(r, CoverageCatalog)
	if r.Status != ReportPartial || !strings.Contains(row.Explanation, "cancelled") {
		t.Errorf("status %s, catalog row %+v", r.Status, row)
	}
}

// bigWorld has devices x rules findings, below the 10,000-finding limit and the work cap,
// so that a full run completes and takes long enough to be cut.
func bigWorld(devices, rules int) *world {
	w := newWorld(ScopeFleet)
	w.c.Records = nil
	for i := 0; i < rules; i++ {
		w.c.Records = append(w.c.Records, w.rule(fmt.Sprintf("RULE-%03d", i)))
	}
	for i := 0; i < devices; i++ {
		w.version(fmt.Sprintf("dev-%04d", i), VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
	}
	return w
}

// matchFrames counts the goroutines that are inside the matcher now.
func matchFrames() int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	return strings.Count(string(buf), "security.Match(") + strings.Count(string(buf), "security.(*matcher)")
}

// The evaluation budget ends the work itself: the matcher loop is stopped by the context, it
// is not left running while the caller gives up (design: a timed-out worker is not left
// running). Three things are observed. The run is cut short (fewer findings than a full run
// makes), the report says where, and when Evaluate has returned no goroutine is inside the
// matcher and the goroutine count is what it was. A budget cannot be told from the time a
// run takes, so the budget shrinks until a run is cut.
func TestEvaluationCancellationStopsWork(t *testing.T) {
	w := bigWorld(100, 99)
	full, err := Evaluate(context.Background(), w.input(ReportComplete))
	if err != nil {
		t.Fatal(err)
	}
	if want := 100 * 99; len(full.Findings) != want {
		t.Fatalf("the full run made %d findings, want %d", len(full.Findings), want)
	}
	began := time.Now()
	if _, err := Evaluate(context.Background(), w.input(ReportComplete)); err != nil {
		t.Fatal(err)
	}
	took := time.Since(began)
	baseline := runtime.NumGoroutine()
	cut := false
	for budget := took / 4; budget >= time.Microsecond && !cut; budget /= 2 {
		r, err := evaluate(context.Background(), w.input(ReportComplete), budget)
		if err != nil {
			t.Fatalf("a spent budget is an error: %v", err)
		}
		if vErr := ValidateReport(r); vErr != nil {
			t.Fatalf("budget %v: the report does not validate: %v", budget, vErr)
		}
		// The matcher is not running any more, whatever the report says.
		if n := matchFrames(); n != 0 {
			t.Fatalf("budget %v: Evaluate returned while %d goroutines were inside the matcher", budget, n)
		}
		if len(r.Findings) >= len(full.Findings) {
			continue // the run beat the budget: shrink it
		}
		cut = true
		row, _ := rowFor(r, CoverageCatalog)
		if r.Status != ReportPartial || row.Status != ReportPartial || !strings.Contains(row.Explanation, "evaluation stopped early") || !strings.Contains(row.Explanation, "deadline exceeded") {
			t.Errorf("budget %v: status %s, catalog row %+v", budget, r.Status, row)
		}
		if row.Counts == nil || row.Counts.Findings != len(r.Findings) {
			t.Errorf("budget %v: the row counts %+v for %d findings", budget, row.Counts, len(r.Findings))
		}
	}
	if !cut {
		t.Fatalf("no budget down to a microsecond cut a run that takes %v: the budget does not stop the work", took)
	}
	// Goroutines started by the runtime for timers may take a moment to leave.
	for i := 0; i < 50 && runtime.NumGoroutine() > baseline; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline {
		t.Errorf("%d goroutines now, %d before", n, baseline)
	}
}

// The five-second budget is the one Evaluate applies.
func TestEvaluateUsesTheFiveSecondBudget(t *testing.T) {
	if EvaluationBudget != 5*time.Second {
		t.Fatalf("EvaluationBudget = %v", EvaluationBudget)
	}
}

// A report owns its data: changing the input afterwards, or evaluating another input at the
// same time, leaves it as it was.
func TestEvaluateReportOwnsItsData(t *testing.T) {
	w := affectedWorld(ScopeFleet)
	observed := w.now.Add(-2 * time.Minute)
	w.s.Versions[0].Evidence.ObservedAt = &observed
	w.feat("tailscale_ssh", true)
	in := w.input(ReportComplete)
	r := mustEvaluate(t, in)
	snapshot := func() string {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	before := snapshot()
	// Change everything a pointer or a slice of the input reaches.
	*in.Snapshot.Versions[0].Value = "9.9.9"
	*in.Snapshot.Versions[0].Evidence.ObservedAt = w.now.Add(-time.Hour)
	*in.Snapshot.Features[0].Value = false
	in.Snapshot.Versions[0].Name = "changed"
	in.Snapshot.Versions = append(in.Snapshot.Versions[:0], VersionFact{})
	in.Collected[0].Explanation = "changed"
	in.Catalog.Records[0].Mitigation = "changed"
	if after := snapshot(); after != before {
		t.Errorf("the report changed with its input:\n%s\n%s", before, after)
	}
	for _, f := range r.Findings {
		for _, e := range f.Evidence {
			if e.ObservedAt != nil && e.ObservedAt == r.Snapshot.Versions[0].Evidence.ObservedAt {
				t.Error("a finding's evidence shares a pointer with the snapshot's")
			}
		}
	}
}

func TestEvaluateConcurrentReportsOwnTheirData(t *testing.T) {
	const n = 8
	var wg sync.WaitGroup
	reports := make([]Report, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := newWorld(ScopeFleet)
			w.s.Context = fmt.Sprintf("ctx-%d", i)
			w.version(fmt.Sprintf("only-%d", i), VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
			// The world's evidence carries the world's context; give the facts this one's.
			for k := range w.s.Versions {
				w.s.Versions[k].Evidence.Context = w.s.Context
			}
			in := w.input(ReportComplete)
			for k := range in.Collected {
				in.Collected[k].Context = w.s.Context
			}
			reports[i], errs[i] = Evaluate(context.Background(), in)
		}()
	}
	wg.Wait()
	for i, r := range reports {
		if errs[i] != nil {
			t.Fatalf("evaluation %d: %v", i, errs[i])
		}
		if err := ValidateReport(r); err != nil {
			t.Fatalf("evaluation %d: %v", i, err)
		}
		if r.Context != fmt.Sprintf("ctx-%d", i) || len(r.Findings) != 1 || r.Findings[0].Asset != fmt.Sprintf("only-%d", i) || r.Findings[0].Context != r.Context {
			t.Errorf("report %d holds another's data: %+v", i, r.Findings)
		}
	}
}

func TestCountAtThreshold(t *testing.T) {
	fs := []Finding{
		{Applicability: ApplicabilityAffected, SourceSeverity: SeverityLow},
		{Applicability: ApplicabilityAffected, SourceSeverity: SeverityHigh},
		{Applicability: ApplicabilityAffected, SourceSeverity: SeverityCritical},
		{Applicability: ApplicabilityAffected, SourceSeverity: SeverityUnknown},
		{Applicability: ApplicabilityPotential, SourceSeverity: SeverityMedium},
		{Applicability: ApplicabilityPotential, SourceSeverity: SeverityHigh},
		{Applicability: ApplicabilityUnknown, SourceSeverity: SeverityCritical},
		{Applicability: ApplicabilityNotAffected, SourceSeverity: SeverityCritical},
	}
	for _, tc := range []struct {
		threshold Severity
		want      ThresholdCounts
	}{
		// An affected finding of unknown severity is above any threshold: it cannot be
		// shown to be below it.
		{SeverityLow, ThresholdCounts{Affected: 4, Potential: 2}},
		{SeverityMedium, ThresholdCounts{Affected: 3, Potential: 2}},
		{SeverityHigh, ThresholdCounts{Affected: 3, Potential: 1}},
		{SeverityCritical, ThresholdCounts{Affected: 2, Potential: 0}},
	} {
		got, err := CountAtThreshold(fs, tc.threshold)
		if err != nil || got != tc.want {
			t.Errorf("threshold %s: %+v, %v; want %+v", tc.threshold, got, err, tc.want)
		}
	}
	for _, bad := range []Severity{"", SeverityUnknown, "urgent", "HIGH"} {
		if _, err := CountAtThreshold(fs, bad); err == nil {
			t.Errorf("threshold %q accepted", bad)
		}
	}
	if got, err := CountAtThreshold(nil, SeverityLow); err != nil || got != (ThresholdCounts{}) {
		t.Errorf("no findings: %+v %v", got, err)
	}
}

func TestTruncateKeepsTheFirstFindingsAndSaysSo(t *testing.T) {
	w := bigWorld(10, 5)
	r := mustEvaluate(t, w.input(ReportComplete))
	if len(r.Findings) != 50 {
		t.Fatalf("%d findings", len(r.Findings))
	}
	cut, err := Truncate(r, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(cut.Findings) != 20 || cut.TotalFindings != 50 || !cut.Truncated || cut.Status != ReportPartial {
		t.Fatalf("findings %d total %d truncated %v status %s", len(cut.Findings), cut.TotalFindings, cut.Truncated, cut.Status)
	}
	if !reflect.DeepEqual(cut.Findings, r.Findings[:20]) {
		t.Error("Truncate did not keep the first findings, in order")
	}
	if len(r.Findings) != 50 || r.Truncated {
		t.Error("Truncate changed its argument")
	}
	if err := ValidateReport(cut); err != nil {
		t.Errorf("the truncated report does not validate: %v", err)
	}
	// Nothing to cut: the same report.
	same, err := Truncate(r, 50)
	if err != nil || !reflect.DeepEqual(same, r) {
		t.Errorf("a report within the limit changed: %v", err)
	}
	for _, bad := range []int{0, -1} {
		if _, err := Truncate(r, bad); err == nil {
			t.Errorf("limit %d accepted", bad)
		}
	}
	// The counts of the catalog row stay those of the whole run.
	row, _ := rowFor(cut, CoverageCatalog)
	if row.Counts == nil || row.Counts.Findings != 50 {
		t.Errorf("catalog row after truncation: %+v", row)
	}
}

// A coverage row of the input can carry counts through a pointer. The report owns its rows: it
// holds no pointer to the caller's counts, so changing them afterwards, even while the report
// is being read, changes nothing in it. The second half runs under the race detector, where a
// shared pointer is a data race.
func TestEvaluateReportKeepsNoPointerToTheCallersCoverageCounts(t *testing.T) {
	w := affectedWorld(ScopeFleet)
	in := w.input(ReportComplete)
	for i := range in.Collected {
		in.Collected[i].Counts = &CoverageCounts{Rules: 1, Assets: 1, Findings: 1}
	}
	r := mustEvaluate(t, in)
	bytes := func() string {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	before := bytes()
	withCounts := 0
	for _, row := range r.Coverage {
		for _, mine := range in.Collected {
			if row.Counts != nil && row.Counts == mine.Counts {
				t.Errorf("the %s row of the report holds the caller's counts pointer", row.Target.Dimension)
			}
		}
		if row.Counts != nil {
			withCounts++
		}
	}
	if withCounts < 3 {
		t.Fatalf("the premise: %d rows with counts (two collected and the catalog's)", withCounts)
	}
	for _, c := range in.Collected {
		*c.Counts = CoverageCounts{Rules: 99, Withdrawn: 98, Assets: 97, Findings: 96, Unknown: 95, Potential: 94}
	}
	if after := bytes(); after != before {
		t.Errorf("the report changed with the caller's counts:\n%s\n%s", before, after)
	}

	// While the caller changes its counts, the report is read: no shared memory, no race.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			for _, c := range in.Collected {
				c.Counts.Rules = i
			}
		}
	}()
	for i := 0; i < 200; i++ {
		if bytes() != before {
			t.Fatal("the report changed while the caller changed its counts")
		}
	}
	close(stop)
	wg.Wait()
}

// A report cut by Truncate owns its rows and findings as well: it shares nothing with the
// report it was cut from.
func TestTruncateOwnsWhatItReturns(t *testing.T) {
	w := bigWorld(10, 5)
	in := w.input(ReportComplete)
	in.Collected[0].Counts = &CoverageCounts{Rules: 1, Assets: 1}
	r := mustEvaluate(t, in)
	for _, limit := range []int{20, 50} { // cut, and within the limit
		cut, err := Truncate(r, limit)
		if err != nil {
			t.Fatal(err)
		}
		for i := range cut.Coverage {
			if cut.Coverage[i].Counts != nil && cut.Coverage[i].Counts == r.Coverage[i].Counts {
				t.Errorf("limit %d: row %d shares its counts with the report it was cut from", limit, i)
			}
		}
		before, _ := json.Marshal(r)
		for i := range cut.Coverage {
			if cut.Coverage[i].Counts != nil {
				cut.Coverage[i].Counts.Rules = 12345
			}
		}
		cut.Coverage[0].Explanation = "changed"
		cut.Findings[0].Explanation = "changed"
		cut.RequestedCoverage[0].Asset = "changed"
		if len(cut.Snapshot.Versions) > 0 {
			cut.Snapshot.Versions[0].Name = "changed"
		}
		if after, _ := json.Marshal(r); string(after) != string(before) {
			t.Errorf("limit %d: changing the cut report changed the report it came from", limit)
		}
	}
}
