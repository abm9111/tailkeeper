package security

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

// Pins for what the table tests of the matcher leave to chance: the exact cost of a run in
// work steps, which makes a budget exact at every place that spends one; the exact words of
// the coverage row and of the reasons; and the cases where two facts of one device differ
// in one component only.

// ---- the budget is exact -------------------------------------------------------------------

// A shape is a world and the number of work steps a run of it takes. The last step of each is
// at a different place in the matcher, so a place that did not enforce the budget would let
// a run with one step less finish.
type stepShape struct {
	name  string
	steps int
	build func(w *world)
}

func stepShapes() []stepShape {
	noRules := func(w *world) { w.c.Records = nil }
	pendingNoRanges := func(w *world) { w.rec().ReviewState, w.rec().Ranges = ReviewPending, nil }
	return []stepShape{
		// Indexing spends one step per fact, versions first, then platforms, then features.
		{"the last step indexes a version fact", 2, func(w *world) {
			noRules(w)
			w.version("d1", VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
			w.version("d2", VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
		}},
		{"the last step indexes a platform fact", 2, func(w *world) { noRules(w); w.daemon("1.30.0"); w.os("linux") }},
		{"the last step indexes a feature fact", 3, func(w *world) { noRules(w); w.daemon("1.30.0"); w.os("linux"); w.feat("ssh", true) }},
		// Judging spends one step per rule and device, one per version fact of the device that
		// is read, one per range tried, and one per platform or feature fact the rule asks about.
		{"the last step starts a rule for a device", 2, func(w *world) { pendingNoRanges(w); w.os("linux") }},
		{"the last step reads a version fact", 3, func(w *world) { pendingNoRanges(w); w.daemon("1.30.0") }},
		{"the last step tries a range, and stops at the first that matches", 4, func(w *world) {
			w.rec().Ranges = []VersionRange{{Fixed: "1.32.3"}, {Introduced: "1.40.0"}}
			w.daemon("1.30.0")
		}},
		{"the last step reads a platform fact", 6, func(w *world) { w.rec().OS = "linux"; w.daemon("1.30.0"); w.os("linux") }},
		{"the last step reads a feature fact", 6, func(w *world) { w.rec().RequiredFeatures = []string{"ssh"}; w.daemon("1.30.0"); w.feat("ssh", true) }},
	}
}

func TestMatchBudgetIsExactAtEveryPlaceThatSpendsAStep(t *testing.T) {
	for _, shape := range stepShapes() {
		t.Run(shape.name, func(t *testing.T) {
			w := newWorld(ScopeLocal)
			shape.build(w)
			if _, _, err := w.match(WorkBudget{Candidates: shape.steps}); err != nil {
				t.Fatalf("a budget of %d steps, the cost of the run, was refused: %v", shape.steps, err)
			}
			findings, cov, err := w.match(WorkBudget{Candidates: shape.steps - 1})
			if !errors.Is(err, ErrWorkBudget) {
				t.Fatalf("a budget of %d steps finished a run that takes %d: %v", shape.steps-1, shape.steps, err)
			}
			requireValidReport(t, w, findings, cov)
			if cov[0].Status != ReportPartial {
				t.Fatalf("a run stopped by the budget has a %s row", cov[0].Status)
			}
		})
	}
}

// The context is looked at once at the start, as often as catalog validation does, and once
// per work step: a run that ignored it at a step could not be cancelled while it works.
func TestMatchLooksAtTheContextAtEveryStep(t *testing.T) {
	for _, shape := range stepShapes() {
		t.Run(shape.name, func(t *testing.T) {
			w := newWorld(ScopeLocal)
			shape.build(w)
			catalog := &countingContext{Context: context.Background(), stop: 1 << 30}
			if err := validateCatalog(catalog, w.c); err != nil {
				t.Fatal(err)
			}
			run := &countingContext{Context: context.Background(), stop: 1 << 30}
			if _, _, err := Match(run, w.c, w.s, w.now, WorkBudget{}); err != nil {
				t.Fatal(err)
			}
			if want := 1 + catalog.checks + shape.steps; run.checks != want {
				t.Fatalf("the context was looked at %d times, want %d (the start, %d for the catalog, %d steps)", run.checks, want, catalog.checks, shape.steps)
			}
			// And each look is heeded: a context that is cancelled at any one of them stops the run.
			for stop := 1; stop <= run.checks; stop++ {
				_, cov, err := Match(&countingContext{Context: context.Background(), stop: stop}, w.c, w.s, w.now, WorkBudget{})
				if !errors.Is(err, context.Canceled) || len(cov) != 1 || cov[0].Status != ReportPartial {
					t.Fatalf("cancelled at look %d of %d: %v %+v", stop, run.checks, err, cov)
				}
			}
		})
	}
}

// A context that is already cancelled stops a run that would otherwise finish without a
// single check: no rule, no device.
func TestMatchCancelledBeforeTheStartWithNothingToJudge(t *testing.T) {
	w := newWorld(ScopeLocal)
	w.c.Records = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	findings, cov, err := Match(ctx, w.c, w.s, w.now, WorkBudget{})
	if !errors.Is(err, context.Canceled) || len(findings) != 0 || len(cov) != 1 || cov[0].Status != ReportPartial {
		t.Fatalf("%+v %+v %v", findings, cov, err)
	}
}

// ---- the words of the coverage row --------------------------------------------------------

func TestStopCauseSaysWhyAndWhere(t *testing.T) {
	m := &matcher{c: Catalog{Records: make([]AdvisoryRecord, 3)}}
	for _, tc := range []struct {
		err      error
		position int
		want     string
	}{
		{ErrWorkBudget, 0, "evaluation stopped early: work budget exhausted, before the first rule"},
		{ErrWorkBudget, 2, "evaluation stopped early: work budget exhausted, at rule 2 of 3"},
		{errFindingsLimit, 3, "evaluation stopped early: findings limit reached, at rule 3 of 3"},
		{context.Canceled, 1, "evaluation stopped early: cancelled, at rule 1 of 3"},
		{fmt.Errorf("wrapped: %w", context.Canceled), 1, "evaluation stopped early: cancelled, at rule 1 of 3"},
		{context.DeadlineExceeded, 1, "evaluation stopped early: deadline exceeded, at rule 1 of 3"},
		{errors.New("a context of another kind"), 1, "evaluation stopped early: error, at rule 1 of 3"},
	} {
		m.position = tc.position
		if got := m.stopCause(tc.err); got != tc.want {
			t.Errorf("stopCause(%v) at %d = %q, want %q", tc.err, tc.position, got, tc.want)
		}
	}
}

func TestMatchCoverageExplanationsAreExact(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(w *world)
		want  string
	}{
		{"nothing wrong", func(w *world) { w.daemon("1.30.0") }, ""},
		{"no rules", func(w *world) { w.c.Records = nil; w.daemon("1.30.0") }, "no rules evaluated"},
		{"only withdrawn rules", func(w *world) {
			w.rec().ReviewState = ReviewWithdrawn
			second := w.rule("RULE-2")
			second.ReviewState = ReviewWithdrawn
			w.c.Records = append(w.c.Records, second)
			w.daemon("1.30.0")
		}, "no rules evaluated (withdrawn rules skipped: 2)"},
		{"no devices", func(w *world) {}, "no devices observed"},
		{"a stale review", func(w *world) { w.daemon("1.30.0"); w.rec().ReviewExpiresAt = w.now }, "rules with a stale review: 1"},
		{"an expired catalog", func(w *world) { w.daemon("1.30.0"); w.c.ExpiresAt = w.now }, "catalog expired or not yet valid"},
		{"a potentially affected device", func(w *world) { w.api("1.30.0") }, "potentially affected findings: 1 (runtime_unobserved 1)"},
		{"several causes are joined in this order", func(w *world) {
			w.daemon("1.30.0")
			w.c.ExpiresAt = w.now
			w.rec().ReviewState = ReviewPending
		}, "catalog expired or not yet valid; pending rules: 1; unknown findings: 1 (review_pending 1)"},
		{"a stale review and an unknown device", func(w *world) {
			w.daemon("1.30.0")
			w.rec().ReviewExpiresAt = w.now
			w.version("d2", VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0-rc1")
		}, "rules with a stale review: 1; unknown findings: 1 (unrecognised_build 1)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(ScopeLocal)
			tc.build(w)
			_, cov, err := w.match(WorkBudget{})
			if err != nil {
				t.Fatal(err)
			}
			if cov[0].Explanation != tc.want {
				t.Fatalf("explanation %q, want %q", cov[0].Explanation, tc.want)
			}
		})
	}
}

// The words of each reason, as the program fixes them. A change of wording is a change of
// this table.
func TestExplanationTextIsPinned(t *testing.T) {
	want := map[UnknownReason]string{
		ReasonCatalogExpired:    "The advisory catalog is not current, so it cannot clear this device.",
		ReasonReviewExpired:     "The review of this advisory rule has expired, so it cannot clear this device.",
		ReasonReviewPending:     "This advisory rule is pending review; it neither confirms nor clears this device.",
		ReasonNoVersion:         "No usable version of this component was reported for this device.",
		ReasonEvidenceError:     "The version evidence for this device carries an error.",
		ReasonStaleEvidence:     "The version evidence for this device is stale.",
		ReasonVersionConflict:   "The usable version reports for this device disagree.",
		ReasonUnrecognisedBuild: "A reported version is outside the release format this assessment reads.",
		ReasonChannelUnknown:    "The reported release does not say whether it is a stable release.",
		ReasonUnstableTrack:     "The reported release is on the unstable track, which the advisory ranges do not cover.",
		ReasonOSUnrecognised:    "The reported operating system is outside the vocabulary this assessment reads.",
		ReasonOSUnknown:         "The operating system the rule names is not established for this device.",
		ReasonFeatureUnknown:    "A feature the rule requires is not established for this device.",
		ReasonRuntimeUnobserved: "The running daemon was not observed; only reports of its version exist.",
	}
	if !reflect.DeepEqual(reasonText, want) {
		t.Fatalf("reasonText differs from the pinned words:\n got %v\nwant %v", reasonText, want)
	}
	if plainExplanation != "Advisory evaluation of reported evidence." || staleExplanation != "The advisory catalog or its review is stale; verify current guidance." {
		t.Fatalf("%q %q", plainExplanation, staleExplanation)
	}
}

func TestMatchNothingToJudgeReturnsAnEmptyListNotNil(t *testing.T) {
	for name, build := range map[string]func(w *world){
		"no rules":      func(w *world) { w.c.Records = nil; w.daemon("1.30.0") },
		"no devices":    func(w *world) {},
		"all withdrawn": func(w *world) { w.rec().ReviewState = ReviewWithdrawn; w.daemon("1.30.0") },
	} {
		w := newWorld(ScopeLocal)
		build(w)
		findings, _, err := w.match(WorkBudget{})
		if err != nil || findings == nil || len(findings) != 0 {
			t.Errorf("%s: %#v %v", name, findings, err)
		}
	}
}

// ---- the evidence a finding cites ---------------------------------------------------------------

// A result that the state of the catalog or of the rule turns into unknown still cites the
// evidence it was judged on.
func TestMatchStateKeepsTheEvidenceItJudged(t *testing.T) {
	for name, state := range map[string]func(w *world){
		"an expired catalog": func(w *world) { w.c.ExpiresAt = w.now },
		"an expired review":  func(w *world) { w.rec().ReviewExpiresAt = w.now },
		"a pending rule":     func(w *world) { w.rec().ReviewState = ReviewPending },
	} {
		t.Run(name, func(t *testing.T) {
			for _, version := range []string{"1.30.0", "1.32.3"} { // in range, and cleared
				w := newWorld(ScopeLocal)
				w.rec().OS = "linux"
				w.daemon(version)
				w.os("linux")
				fresh, _, err := w.match(WorkBudget{})
				if err != nil || len(fresh) != 1 || len(fresh[0].Evidence) == 0 {
					t.Fatalf("%s: %+v %v", version, fresh, err)
				}
				state(w)
				got, _, err := w.match(WorkBudget{})
				if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0].Evidence, fresh[0].Evidence) {
					t.Fatalf("%s: the evidence changed with the state: %+v %v", version, got, err)
				}
				if version == "1.32.3" && got[0].Applicability != ApplicabilityUnknown {
					t.Fatalf("a cleared device was not turned into unknown: %+v", got[0])
				}
			}
		})
	}
}

// With several connected_to_control facts the first usable true one is the one cited.
func TestMatchCitesTheFirstConnectedFact(t *testing.T) {
	w := newWorld(ScopeLocal)
	w.api("1.30.0", w.ago(5*time.Minute))
	w.connected(true, w.ago(3*time.Minute))
	w.connected(true, w.ago(2*time.Minute))
	findings, _, err := w.match(WorkBudget{})
	if err != nil || len(findings) != 1 || findings[0].Applicability != ApplicabilityAffected || len(findings[0].Evidence) != 2 {
		t.Fatalf("%+v %v", findings, err)
	}
	if got := findings[0].Evidence[1].AcquiredAt; !got.Equal(w.now.Add(-3 * time.Minute)) {
		t.Fatalf("the connected fact cited was acquired at %v, want the first, at %v", got, w.now.Add(-3*time.Minute))
	}
}

// The feature that says a device is connected to control has the name the design gives it.
func TestConnectedToControlHasTheDesignsName(t *testing.T) {
	if FeatureConnectedToControl != "connected_to_control" {
		t.Fatalf("%q", FeatureConnectedToControl)
	}
	w := newWorld(ScopeLocal)
	w.api("1.30.0")
	w.feature(mAsset, OriginAPI, "connected_to_control", true)
	findings, _, err := w.match(WorkBudget{})
	if err != nil || len(findings) != 1 || findings[0].Applicability != ApplicabilityAffected {
		t.Fatalf("%+v %v", findings, err)
	}
}

// ---- two facts that differ in one component only -----------------------------------------

func TestMatchReportsDifferingInOneComponentOnlyConflict(t *testing.T) {
	var cs []matchCase
	for _, pair := range []struct{ name, daemon, api string }{
		{"the patch", "1.32.3", "1.32.4"},
		{"the minor", "1.30.5", "1.32.5"},
		{"the major", "1.32.3", "2.32.3"},
		{"the major, the other way", "2.32.3", "1.32.3"},
	} {
		cs = append(cs,
			with(ApplicabilityUnknown, ReasonVersionConflict, 2, "the API and the daemon differ in "+pair.name, func(w *world) { w.daemon(pair.daemon); w.api(pair.api) }),
			with(ApplicabilityUnknown, ReasonVersionConflict, 3, "the connected API and the daemon differ in "+pair.name, func(w *world) {
				w.daemon(pair.daemon)
				w.api(pair.api)
				w.connected(true)
			}),
			with(ApplicabilityUnknown, ReasonVersionConflict, 2, "two daemon facts differ in "+pair.name, func(w *world) { w.daemon(pair.daemon); w.daemon(pair.api) }),
		)
	}
	runMatchCases(t, cs)
}

// An API report that only has to agree with the daemon's is compared by release; its channel
// is not the daemon's, and two exact facts of different channels are judged the same in
// either order.
func TestMatchChannelsOfFactsThatDecide(t *testing.T) {
	daemon := func(w *world, channel VersionChannel) {
		w.version(mAsset, VersionRunningDaemon, OriginLocal, channel, "1.30.0")
	}
	apiOf := func(w *world, channel VersionChannel) {
		w.version(mAsset, VersionAPIReported, OriginAPI, channel, "1.30.0")
	}
	runMatchCases(t, []matchCase{
		with(ApplicabilityAffected, "", 2, "an API report of the unstable channel beside a stable daemon", func(w *world) {
			daemon(w, ChannelStable)
			apiOf(w, ChannelUnstable)
		}),
		with(ApplicabilityAffected, "", 2, "an API report of unknown channel beside a stable daemon", func(w *world) {
			daemon(w, ChannelStable)
			apiOf(w, ChannelUnknown)
		}),
		with(ApplicabilityUnknown, ReasonUnstableTrack, 2, "stable, then unstable, daemon facts", func(w *world) {
			daemon(w, ChannelStable)
			daemon(w, ChannelUnstable)
		}),
		with(ApplicabilityUnknown, ReasonUnstableTrack, 2, "unknown, then unstable, daemon facts", func(w *world) {
			daemon(w, ChannelUnknown)
			daemon(w, ChannelUnstable)
		}),
		with(ApplicabilityUnknown, ReasonUnstableTrack, 2, "unstable, then unknown, daemon facts", func(w *world) {
			daemon(w, ChannelUnstable)
			daemon(w, ChannelUnknown)
		}),
		with(ApplicabilityUnknown, ReasonChannelUnknown, 2, "stable, then unknown, daemon facts", func(w *world) {
			daemon(w, ChannelStable)
			daemon(w, ChannelUnknown)
		}),
		with(ApplicabilityUnknown, ReasonChannelUnknown, 2, "unknown, then stable, daemon facts", func(w *world) {
			daemon(w, ChannelUnknown)
			daemon(w, ChannelStable)
		}),
		with(ApplicabilityUnknown, ReasonUnstableTrack, 3, "the connected API report of the unstable channel decides with the daemon", func(w *world) {
			daemon(w, ChannelStable)
			apiOf(w, ChannelUnstable)
			w.connected(true)
		}),
	})
}
