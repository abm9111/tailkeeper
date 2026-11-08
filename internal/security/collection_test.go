package security

import (
	"strings"
	"testing"
	"time"
)

// The channel of a version string is its release's: even minors are stable, odd ones are
// not, and a string outside the release grammar has none.
func TestChannelOfReadsTheReleaseNotTheSuffix(t *testing.T) {
	for v, want := range map[string]VersionChannel{
		"1.102.5": ChannelStable, "1.102.5-t0123456ab": ChannelStable, "1.102.5-t0123456ab-gfedcba987": ChannelStable, "0.0.0": ChannelStable,
		"1.103.1": ChannelUnstable, "1.103.1-t0123456ab": ChannelUnstable,
		"": ChannelUnknown, "v1.2.3": ChannelUnknown, "1.102": ChannelUnknown, "1.102.5-1-t5fb2a81b0": ChannelUnknown, "1.102.5-dev": ChannelUnknown,
		"01.2.3": ChannelUnknown, "1.102.5 ": ChannelUnknown,
	} {
		if got := ChannelOf(v); got != want {
			t.Errorf("ChannelOf(%q) = %s, want %s", v, got, want)
		}
	}
}

func TestValidTextIsWhatAReportHolds(t *testing.T) {
	for s, want := range map[string]bool{"linux": true, "1.102.5-t0123456ab": true, "": true, "macOS": true, "a\x00b": false, "a\nb": false,
		"a\u202eb": false, "a\u200bb": false, "a\u00a0b": false, strings.Repeat("a", MaxTextBytes): true, strings.Repeat("a", MaxTextBytes+1): false, "\xff": false} {
		if got := ValidText(s); got != want {
			t.Errorf("ValidText(%.20q) = %v, want %v", s, got, want)
		}
	}
}

// ValidateSnapshot is the check Match makes, so a snapshot that passes it can be matched.
func TestValidateSnapshotIsTheCheckMatchMakes(t *testing.T) {
	w := newWorld(ScopeFleet)
	w.daemon("1.30.0")
	if err := ValidateSnapshot(w.s, w.now); err != nil {
		t.Fatal(err)
	}
	bad := w.s
	bad.Versions = append([]VersionFact(nil), w.s.Versions...)
	skewed := w.now.Add(-time.Hour)
	bad.Versions[0].Evidence.ObservedAt = &w.now // later than the acquisition a minute ago
	if err := ValidateSnapshot(bad, w.now); err == nil {
		t.Error("an observation later than its acquisition passed")
	}
	if _, _, err := Match(t.Context(), w.c, bad, w.now, WorkBudget{}); err == nil {
		t.Error("Match took the snapshot that ValidateSnapshot refused")
	}
	if err := ValidateSnapshot(w.s, skewed); err == nil {
		t.Error("a snapshot observed after the evaluation time passed")
	}
}

// The validation requests of an access explanation are sources of the audit record, and the set
// stays closed: those two are valid and a third name is not.
func TestTheValidationRequestsOfAnExplanationAreSourcesOfTheRecord(t *testing.T) {
	for _, src := range []CollectionSource{SourceValidateNetwork, SourceValidateSSH} {
		for _, ev := range []CollectionEvent{
			{Scope: ScopeFleet, Source: src, Phase: PhaseAttempt},
			{Scope: ScopeFleet, Source: src, Phase: PhaseOutcome, Outcome: OutcomeOK, Observed: 3, Millis: 9},
			{Scope: ScopeFleet, Source: src, Phase: PhaseOutcome, Outcome: OutcomeError, Code: "upstream_unavailable", Observed: 3},
		} {
			if err := ev.Validate(); err != nil {
				t.Errorf("%s %s: %v", src, ev.Phase, err)
			}
		}
	}
	if err := (CollectionEvent{Scope: ScopeFleet, Source: "validate_devices", Phase: PhaseAttempt}).Validate(); err == nil {
		t.Error("a source outside the closed set was accepted")
	}
}

func TestCollectionEventsAreClosed(t *testing.T) {
	attempt := CollectionEvent{Scope: ScopeFleet, Source: SourceAPIDevices, Phase: PhaseAttempt}
	outcome := func(edit func(*CollectionEvent)) CollectionEvent {
		e := CollectionEvent{Scope: ScopeLocal, Source: SourceLocalPrefs, Phase: PhaseOutcome, Outcome: OutcomeOK, Observed: 2, Millis: 5}
		if edit != nil {
			edit(&e)
		}
		return e
	}
	for name, tc := range map[string]struct {
		ev   CollectionEvent
		good bool
	}{
		"an attempt": {attempt, true}, "an ok outcome": {outcome(nil), true},
		"a truncated outcome":            {outcome(func(e *CollectionEvent) { e.Outcome, e.Dropped = OutcomeTruncated, 7 }), true},
		"a failed source":                {outcome(func(e *CollectionEvent) { e.Outcome, e.Code = OutcomeError, "scope_missing" }), true},
		"a skipped source":               {outcome(func(e *CollectionEvent) { e.Outcome, e.Code = OutcomeSkipped, SkipBudget }), true},
		"a cancelled source":             {outcome(func(e *CollectionEvent) { e.Outcome = OutcomeCancelled }), true},
		"a timed out source":             {outcome(func(e *CollectionEvent) { e.Outcome = OutcomeTimeout }), true},
		"no scope":                       {CollectionEvent{Source: SourceAPIDevices, Phase: PhaseAttempt}, false},
		"an unknown source":              {CollectionEvent{Scope: ScopeLocal, Source: "peers", Phase: PhaseAttempt}, false},
		"an unknown phase":               {CollectionEvent{Scope: ScopeLocal, Source: SourceLocalPrefs, Phase: "done"}, false},
		"an attempt that has an outcome": {CollectionEvent{Scope: ScopeFleet, Source: SourceAPIDevices, Phase: PhaseAttempt, Outcome: OutcomeOK}, false},
		"an attempt that has a time":     {CollectionEvent{Scope: ScopeFleet, Source: SourceAPIDevices, Phase: PhaseAttempt, Millis: 1}, false},
		"an unknown outcome":             {outcome(func(e *CollectionEvent) { e.Outcome = "fine" }), false},
		"an error without a code":        {outcome(func(e *CollectionEvent) { e.Outcome = OutcomeError }), false},
		"a code on an ok outcome":        {outcome(func(e *CollectionEvent) { e.Code = "scope_missing" }), false},
		"a code that is text":            {outcome(func(e *CollectionEvent) { e.Outcome, e.Code = OutcomeError, "the API said no" }), false},
		"a code with a capital":          {outcome(func(e *CollectionEvent) { e.Outcome, e.Code = OutcomeError, "Scope_missing" }), false},
		"a code that is too long":        {outcome(func(e *CollectionEvent) { e.Outcome, e.Code = OutcomeError, strings.Repeat("a", 49) }), false},
		"a negative count":               {outcome(func(e *CollectionEvent) { e.Observed = -1 }), false},
		"a count past the bound":         {outcome(func(e *CollectionEvent) { e.Dropped = 1 << 21 }), false},
		"a negative time":                {outcome(func(e *CollectionEvent) { e.Millis = -1 }), false},
		"a time past a day":              {outcome(func(e *CollectionEvent) { e.Millis = 25 * 3600 * 1000 }), false},
	} {
		if err := tc.ev.Validate(); (err == nil) != tc.good {
			t.Errorf("%s: Validate() = %v", name, err)
		}
	}
}

// The features a producer must cover are those of the rules that are evaluated: approved and
// pending ones. A withdrawn rule requires nothing, a feature required twice is listed once,
// and the order is by name so that two runs say the same.
func TestRequiredFeaturesAreThoseOfTheRulesEvaluated(t *testing.T) {
	rec := func(state ReviewState, features ...string) AdvisoryRecord {
		return AdvisoryRecord{ReviewState: state, RequiredFeatures: features}
	}
	c := Catalog{Records: []AdvisoryRecord{
		rec(ReviewApproved, FeatureTailscaleSSH, FeatureSSHForwardingAllowed),
		rec(ReviewPending, FeatureTailscaleSSH, FeatureServeUnixBackend),
		rec(ReviewWithdrawn, FeatureServeTLSMultiMount),
		rec(ReviewApproved),
	}}
	got := RequiredFeatures(c)
	want := []string{FeatureServeUnixBackend, FeatureSSHForwardingAllowed, FeatureTailscaleSSH}
	if len(got) != len(want) {
		t.Fatalf("RequiredFeatures = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("RequiredFeatures = %v, want %v", got, want)
		}
	}
	if got := RequiredFeatures(Catalog{}); len(got) != 0 {
		t.Errorf("an empty catalog requires %v", got)
	}
}

// A count is limited to what an event takes: above it the event would be refused, and a list
// that long would end a run as a bug of the program. The limit still says "some were left out".
func TestSaturateCountKeepsAnEventValid(t *testing.T) {
	big := SaturateCount(1 << 30)
	if big <= 0 || SaturateCount(big+1) != big || SaturateCount(big) != big || SaturateCount(-5) != 0 || SaturateCount(7) != 7 {
		t.Fatalf("SaturateCount: %d %d %d %d", big, SaturateCount(big+1), SaturateCount(-5), SaturateCount(7))
	}
	ev := CollectionEvent{Scope: ScopeFleet, Source: SourceAPIDevices, Phase: PhaseOutcome, Outcome: OutcomeTruncated, Observed: SaturateCount(1 << 30), Dropped: big}
	if err := ev.Validate(); err != nil {
		t.Errorf("an event with saturated counts: %v", err)
	}
	ev.Dropped = big + 1
	if ev.Validate() == nil {
		t.Error("the bound is one past SaturateCount: an event over it must be refused")
	}
}
