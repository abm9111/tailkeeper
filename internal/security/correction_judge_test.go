package security

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

// Replacing a fallback old release with an unobserved verdict breaks parity with Match.
func TestJudgeVersionAgreesWithMatchOnEveryWorldFixture(t *testing.T) {
	groups := []struct {
		name  string
		cases []matchCase
	}{
		{"release", releaseCases()}, {"evidence", evidenceCases()}, {"source", versionSourceCases()}, {"condition", conditionCases()}, {"state", stateCases()},
	}
	for _, group := range groups {
		for _, tc := range group.cases {
			for _, scope := range []Scope{ScopeLocal, ScopeFleet} {
				t.Run(group.name+"/"+tc.name+"/"+string(scope), func(t *testing.T) {
					w := newWorld(scope)
					tc.build(w)
					// Keep the fixture's facts and role but remove other rule conditions and state,
					// so Match answers the same single version question.
					role := w.rec().VersionRole
					component := w.rec().Component
					w.c = newWorld(scope).c
					w.rec().VersionRole = role
					w.rec().Component = component
					fs, _, err := w.match(WorkBudget{})
					if err != nil {
						t.Fatalf("Match: %v", err)
					}
					for _, f := range fs {
						got, err := JudgeVersion(context.Background(), w.s, w.now, f.Asset, component, role, "1.32.3", WorkBudget{})
						if err != nil {
							t.Fatalf("JudgeVersion: %v", err)
						}
						want := map[Applicability]FactVerdict{ApplicabilityAffected: FactContradicted, ApplicabilityPotential: FactContradicted, ApplicabilityNotAffected: FactSatisfied, ApplicabilityUnknown: FactUnobserved}[f.Applicability]
						if got.Verdict != want || got.Reason != f.Reason || !reflect.DeepEqual(got.Evidence, f.Evidence) {
							t.Fatalf("Match: %s %s %v; judge: %+v", f.Applicability, f.Reason, f.Evidence, got)
						}
					}
				})
			}
		}
	}
}

func TestExpectedFeatureNeedsTheGuardOrALocalFact(t *testing.T) {
	cases := []struct {
		name     string
		build    func(*world)
		want     FactVerdict
		reason   UnknownReason
		evidence int
	}{
		{"local", func(w *world) { w.feat("tailscale_ssh", false) }, FactSatisfied, "", 1},
		{"connected API", func(w *world) {
			w.connected(true, w.ago(2*time.Minute))
			w.feature(mAsset, OriginAPI, "tailscale_ssh", false)
		}, FactSatisfied, "", 2},
		{"disconnected API", func(w *world) { w.connected(false); w.feature(mAsset, OriginAPI, "tailscale_ssh", false) }, FactUnobserved, ReasonFeatureUnknown, 0},
		{"missing guard", func(w *world) { w.feature(mAsset, OriginAPI, "tailscale_ssh", false) }, FactUnobserved, ReasonFeatureUnknown, 0},
		{"stale guard", func(w *world) {
			w.connected(true, w.ago(31*time.Minute))
			w.feature(mAsset, OriginAPI, "tailscale_ssh", false)
		}, FactUnobserved, ReasonFeatureUnknown, 0},
		{"contradictory guard", func(w *world) {
			w.connected(true)
			w.connected(false)
			w.feature(mAsset, OriginAPI, "tailscale_ssh", false)
		}, FactUnobserved, ReasonFeatureUnknown, 0},
		{"connected API contradicts", func(w *world) {
			w.connected(true, w.ago(2*time.Minute))
			w.feature(mAsset, OriginAPI, "tailscale_ssh", true)
		}, FactContradicted, "", 2},
		{"missing feature", func(w *world) { w.connected(true) }, FactUnobserved, ReasonFeatureUnknown, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(ScopeFleet)
			tc.build(w)
			got, err := JudgeFeature(context.Background(), w.s, w.now, mAsset, "tailscale_ssh", "", false, WorkBudget{})
			if err != nil {
				t.Fatal(err)
			}
			if got.Verdict != tc.want || got.Reason != tc.reason || len(got.Evidence) != tc.evidence {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestExpectedFeatureWithDisagreeingFactsIsUnobserved(t *testing.T) {
	w := newWorld(ScopeFleet)
	w.connected(true, w.ago(2*time.Minute))
	w.feature(mAsset, OriginAPI, "tailscale_ssh", false)
	w.feat("tailscale_ssh", true)
	got, err := JudgeFeature(context.Background(), w.s, w.now, mAsset, "tailscale_ssh", VersionRunningDaemon, false, WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != FactUnobserved || got.Reason != ReasonFeatureUnknown || len(got.Evidence) != 3 {
		t.Fatalf("got %+v", got)
	}
}

func TestJudgeValidationAndBudget(t *testing.T) {
	w := newWorld(ScopeFleet)
	w.daemon("1.32.3")
	for _, s := range []string{"1.32", "1.32.3-t0123456", " 1.32.3", "01.32.3"} {
		if ReleaseOK(s) {
			t.Errorf("accepted %q", s)
		}
	}
	if !ReleaseOK("1.32.3") {
		t.Fatal("valid release refused")
	}
	if _, err := JudgeVersion(context.Background(), w.s, w.now, mAsset, "client", "invalid", "1.32.3", WorkBudget{}); err == nil {
		t.Error("invalid role accepted")
	}
	if _, err := JudgeFeature(context.Background(), w.s, w.now, mAsset, FeatureConnectedToControl, "", true, WorkBudget{}); err == nil {
		t.Error("guard feature accepted")
	}
	if _, err := JudgeVersion(context.Background(), w.s, w.now, mAsset, "client", "", "1.32.3", WorkBudget{Candidates: 1}); !errors.Is(err, ErrWorkBudget) {
		t.Errorf("budget: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := JudgeFeature(ctx, w.s, w.now, mAsset, "tailscale_ssh", "", false, WorkBudget{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancel: %v", err)
	}
}

func TestExpectedVersionUsesTheDisconnectedMatcherResult(t *testing.T) {
	for _, tc := range []struct {
		release   string
		connected bool
		verdict   FactVerdict
		reason    UnknownReason
		evidence  int
	}{
		{"1.30.0", false, FactContradicted, ReasonRuntimeUnobserved, 1},
		{"1.32.3", false, FactUnobserved, ReasonRuntimeUnobserved, 1},
		{"1.32.3", true, FactSatisfied, "", 2},
	} {
		t.Run(tc.release+"/connected="+map[bool]string{true: "yes", false: "no"}[tc.connected], func(t *testing.T) {
			w := newWorld(ScopeFleet)
			w.api(tc.release)
			w.connected(tc.connected, w.ago(2*time.Minute))
			got, err := JudgeVersion(context.Background(), w.s, w.now, mAsset, "client", "", "1.32.3", WorkBudget{})
			if err != nil {
				t.Fatal(err)
			}
			if got.Verdict != tc.verdict || got.Reason != tc.reason || len(got.Evidence) != tc.evidence {
				t.Fatalf("got %+v", got)
			}
			if tc.connected && !reflect.DeepEqual(got.Evidence[1], w.s.Features[0].Evidence) {
				t.Fatalf("guard not cited: %+v", got.Evidence)
			}
		})
	}
}

func TestJudgeRejectsInvalidInputs(t *testing.T) {
	w := newWorld(ScopeFleet)
	w.daemon("1.32.3")
	for _, tc := range []struct {
		name, asset, component string
		role                   VersionRole
		release                string
	}{
		{"empty asset", "", "client", "", "1.32.3"}, {"blank asset", " ", "client", "", "1.32.3"},
		{"unsafe asset", "bad\nasset", "client", "", "1.32.3"}, {"empty component", mAsset, "", "", "1.32.3"},
		{"invalid role", mAsset, "client", "invalid", "1.32.3"}, {"invalid release", mAsset, "client", "", "1.32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := JudgeVersion(context.Background(), w.s, w.now, tc.asset, tc.component, tc.role, tc.release, WorkBudget{}); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	for _, tc := range []struct {
		name      string
		ctx       context.Context
		wantError bool
	}{
		{name: "nil context", ctx: nil, wantError: true},
		{name: "valid context", ctx: context.Background()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := JudgeVersion(tc.ctx, w.s, w.now, mAsset, "client", "", "1.32.3", WorkBudget{})
			if tc.wantError {
				if err == nil {
					t.Fatal("nil context accepted")
				}
				return
			}
			if err != nil || got.Verdict != FactSatisfied {
				t.Fatalf("valid context: got %+v, error %v", got, err)
			}
		})
	}
	if _, err := JudgeFeature(context.Background(), w.s, w.now, mAsset, "tailscale_ssh", "", false, WorkBudget{Candidates: -1}); !errors.Is(err, ErrInvalidBudget) {
		t.Errorf("invalid budget: %v", err)
	}
	invalid := w.s
	invalid.Context = ""
	if _, err := JudgeFeature(context.Background(), invalid, w.now, mAsset, "tailscale_ssh", "", false, WorkBudget{}); err == nil {
		t.Error("invalid snapshot accepted")
	}
}

// Both desired values must be compared with the actual feature, for every role.
func TestJudgeFeatureRespectsDesiredValueForEveryRole(t *testing.T) {
	sources := []struct {
		name   string
		role   VersionRole
		origin Origin
		guard  bool
	}{
		{"daemon-local", VersionRunningDaemon, OriginLocal, false},
		{"daemon-api-guarded", VersionRunningDaemon, OriginAPI, true},
		{"cli-local", VersionLocalCLI, OriginLocal, false},
		{"cli-api-guarded", VersionLocalCLI, OriginAPI, true},
		{"api-direct", VersionAPIReported, OriginAPI, false},
	}
	for _, source := range sources {
		for _, want := range []bool{false, true} {
			for _, observed := range []bool{false, true} {
				name := fmt.Sprintf("%s/want=%t/observed=%t", source.name, want, observed)
				t.Run(name, func(t *testing.T) {
					w := newWorld(ScopeFleet)
					if source.guard {
						w.connected(true, w.ago(2*time.Minute))
					}
					w.feature(mAsset, source.origin, "tailscale_ssh", observed)
					got, err := JudgeFeature(context.Background(), w.s, w.now, mAsset, "tailscale_ssh", source.role, want, WorkBudget{})
					if err != nil {
						t.Fatal(err)
					}
					verdict := FactContradicted
					if want == observed {
						verdict = FactSatisfied
					}
					if got.Verdict != verdict || got.Reason != "" {
						t.Fatalf("got %+v, want %s", got, verdict)
					}
					if source.guard && (len(got.Evidence) != 2 || !reflect.DeepEqual(got.Evidence[1], w.s.Features[0].Evidence)) {
						t.Fatalf("guard not cited: %+v", got.Evidence)
					}
				})
			}
		}
	}
}
