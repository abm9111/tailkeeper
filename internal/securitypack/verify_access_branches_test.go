package securitypack

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

// fullVerifyFixture is a fleet pack with a finding, a version, a feature and three selected
// access expectations (two network, one SSH), plus the evidence collected after the action.
func fullVerifyFixture(t *testing.T) (EvidencePack, security.CorrectionIntent, AfterEvidence) {
	t.Helper()
	in := replayFixture(t)
	in.Input.Snapshot.Scope = security.ScopeFleet
	in.Input.Snapshot.Context = "ctx-0123456789abcdef"
	in.Input.Snapshot.Versions[0].Evidence.Scope = security.ScopeFleet
	in.Input.Snapshot.Versions[0].Evidence.Context = in.Input.Snapshot.Context
	on := true
	in.Input.Snapshot.Features = []security.FeatureFact{{Name: "tailscale_ssh", Value: &on, Evidence: in.Input.Snapshot.Versions[0].Evidence}}
	intent := security.IntentSet{SchemaVersion: security.SchemaVersion,
		Network: []security.NetworkExpectation{
			{ID: "network-1", Source: "synthetic", Accept: []string{"tag:service:443"}},
			{ID: "network-2", Source: "synthetic", Accept: []string{"tag:service:80"}},
		},
		SSH: []security.SSHExpectation{{ID: "ssh-1", Source: "synthetic", Destinations: []string{"tag:service"}, Accept: []string{"root"}}},
	}
	in.Input.Intent = &intent
	var err error
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	selected := []string{"network-1", "network-2", "ssh-1"}
	in.Access = &AccessEvidence{Context: in.Input.Snapshot.Context, Selected: selected, Input: security.AccessInput{Intent: intent, EvaluatedAt: in.Input.Now}}
	_, p, _ := built(t, in, nil)
	action := in.Input.Now.Add(time.Minute)
	snap := in.Input.Snapshot
	snap.ObservedAt = action.Add(time.Minute)
	snap.Versions = append([]security.VersionFact(nil), snap.Versions...)
	fixed := "9.8.9"
	snap.Versions[0].Value = &fixed
	snap.Versions[0].Evidence.AcquiredAt = snap.ObservedAt
	snap.Features = append([]security.FeatureFact(nil), snap.Features...)
	off := false
	snap.Features[0].Value = &off
	snap.Features[0].Evidence.AcquiredAt = snap.ObservedAt
	witness := security.AccessWitness{Expectation: "network-1", Cell: security.AccessCell{Expect: "accept", Destination: "tag:service:443"}, Observed: security.ObservedAllowed, Proof: security.AccessProof{Canary: true, LiveUnchanged: true}}
	after := AfterEvidence{Snapshot: snap, Now: snap.ObservedAt, Catalog: in.Input.Catalog, CatalogSources: in.Sources, Intent: &intent,
		Access: &AfterAccess{Context: in.Access.Context, StartedAt: action.Add(time.Second), Input: security.AccessInput{Intent: intent, EvaluatedAt: snap.ObservedAt, Witnesses: []security.AccessWitness{witness}}}}
	c := security.CorrectionIntent{SchemaVersion: 1, ActionAt: action,
		Findings:       []security.CorrectionFinding{{RuleID: "SYNTHETIC-ONLY", Asset: "synthetic"}},
		Versions:       []security.ExpectedVersion{{Asset: "synthetic", Name: "client", AtLeast: "9.8.9"}},
		Features:       []security.ExpectedFeature{{Asset: "synthetic", Name: "tailscale_ssh", Value: false}},
		ExpectationIDs: []string{"network-1"}}
	return p, c, after
}

// metBaselineFixture is accessVerifyFixture with the expectation already met in the pack.
func metBaselineFixture(t *testing.T) (EvidencePack, security.CorrectionIntent) {
	t.Helper()
	in := replayFixture(t)
	in.Input.Snapshot.Scope = security.ScopeFleet
	in.Input.Snapshot.Context = "ctx-0123456789abcdef"
	in.Input.Snapshot.Versions[0].Evidence.Scope = security.ScopeFleet
	in.Input.Snapshot.Versions[0].Evidence.Context = in.Input.Snapshot.Context
	intent := security.IntentSet{SchemaVersion: security.SchemaVersion, Network: []security.NetworkExpectation{{ID: "network-1", Source: "synthetic", Accept: []string{"tag:service:443"}}}}
	in.Input.Intent = &intent
	var err error
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	witness := security.AccessWitness{Expectation: "network-1", Cell: security.AccessCell{Expect: "accept", Destination: "tag:service:443"}, Observed: security.ObservedAllowed, Proof: security.AccessProof{Canary: true, LiveUnchanged: true}}
	in.Access = &AccessEvidence{Context: in.Input.Snapshot.Context, Selected: []string{"network-1"}, Input: security.AccessInput{Intent: intent, EvaluatedAt: in.Input.Now, Witnesses: []security.AccessWitness{witness}}}
	_, p, _ := built(t, in, nil)
	return p, security.CorrectionIntent{SchemaVersion: 1, ActionAt: in.Input.Now.Add(time.Minute), ExpectationIDs: []string{"network-1"}}
}

func TestPreflightAccessRefusesMissingAndAlreadyMetExpectations(t *testing.T) {
	p, c, _ := accessVerifyFixture(t)
	r, err := Replay(context.Background(), p, security.WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightAccess(r, c); err != nil {
		t.Fatalf("control: %v", err)
	}
	r.AccessJudgements = nil
	if err := preflightAccess(r, c); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("selected expectation without a judgement: %v", err)
	}
	met, mc := metBaselineFixture(t)
	if _, err := PrepareCorrection(context.Background(), met, mc, security.WorkBudget{}); !errors.Is(err, ErrTargetNotOpen) {
		t.Fatalf("expectation already met: %v", err)
	}
}

func TestAccessRowsNameWhyAFixIsNotProven(t *testing.T) {
	p, c, a := accessVerifyFixture(t)
	if r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{}); err != nil || r.Outcome != "fixed" {
		t.Fatalf("control: %+v %v", r, err)
	}
	unsealed := p
	unsealed.reading.Seal = SealAbsentKeyLoaded
	r, err := VerifyCorrection(context.Background(), unsealed, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "incomplete" || r.Targets[0].Reason != "before_unsealed_key_loaded" {
		t.Fatalf("unsealed baseline: %+v %v", r, err)
	}

	// A local pack can still carry access evidence for a fleet context; its snapshot identity is not fleet.
	in := replayFixture(t)
	intent := security.IntentSet{SchemaVersion: security.SchemaVersion, Network: []security.NetworkExpectation{{ID: "network-1", Source: "synthetic", Accept: []string{"tag:service:443"}}}}
	in.Input.Intent = &intent
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	in.Access = &AccessEvidence{Context: "ctx-0123456789abcdef", Selected: []string{"network-1"}, Input: security.AccessInput{Intent: intent, EvaluatedAt: in.Input.Now}}
	_, local, _ := built(t, in, nil)
	action := in.Input.Now.Add(time.Minute)
	snap := in.Input.Snapshot
	snap.ObservedAt = action.Add(time.Minute)
	after := a
	after.Snapshot, after.Now, after.Catalog, after.CatalogSources = snap, snap.ObservedAt, in.Input.Catalog, in.Sources
	after.Access = &AfterAccess{Context: "ctx-0123456789abcdef", StartedAt: action.Add(time.Second), Input: a.Access.Input}
	after.Access.Input.EvaluatedAt = snap.ObservedAt
	c.ActionAt = action
	r, err = VerifyCorrection(context.Background(), local, c, after, security.WorkBudget{})
	if err != nil || r.Outcome != "incomplete" || r.Targets[0].Reason != "context_identity_unavailable" {
		t.Fatalf("local snapshot: %+v %v", r, err)
	}
}

func TestAccessInputThatCannotBeJudgedIsAMismatch(t *testing.T) {
	p, c, a := accessVerifyFixture(t)
	// The input names the same intent, but one witness is for a pair no expectation asks about.
	a.Access.Input.Witnesses = []security.AccessWitness{{Expectation: "network-1", Cell: security.AccessCell{Expect: "accept", Destination: "unplanned:1"}, Observed: security.ObservedAllowed}}
	r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "incomplete" || r.Targets[0].Reason != "access_input_mismatch" {
		t.Fatalf("got %+v %v", r, err)
	}
}

func TestGuardRowsCarryTheReasonTheyCannotBeTrusted(t *testing.T) {
	p, c, a := fullVerifyFixture(t)
	a.Intent = nil
	r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || len(r.Guards) != 2 {
		t.Fatalf("got %+v %v", r, err)
	}
	for _, g := range r.Guards {
		if g.Outcome != "intent_unavailable" || g.Reason != "intent_unavailable" {
			t.Errorf("guard %s: outcome %q reason %q", g.ExpectationID, g.Outcome, g.Reason)
		}
	}
	if r.Outcome != "incomplete" || r.Targets[len(r.Targets)-1].Reason != "intent_unavailable" {
		t.Fatalf("target row: %+v", r)
	}
}

func TestCompatibleIntentKeepsUnchangedSSHAndDropsChangedOnes(t *testing.T) {
	p, c, a := fullVerifyFixture(t)
	prepared, err := PrepareCorrection(context.Background(), p, c, security.WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	got, changed := prepared.CompatibleIntent(a.Intent)
	if got == nil || len(changed) != 0 || len(got.Network) != 2 || len(got.SSH) != 1 || got.SSH[0].ID != "ssh-1" {
		t.Fatalf("unchanged: %+v %v", got, changed)
	}
	current := *a.Intent
	current.SSH = append([]security.SSHExpectation(nil), current.SSH...)
	current.SSH[0].Accept = []string{"other"}
	got, changed = prepared.CompatibleIntent(&current)
	if got == nil || len(changed) != 1 || changed[0] != "ssh-1" || len(got.Network) != 2 || len(got.SSH) != 0 {
		t.Fatalf("changed SSH: %+v %v", got, changed)
	}
}

func TestCompatibleIntentStopsWhenCanceled(t *testing.T) {
	p, c, a := fullVerifyFixture(t)
	prepared, err := PrepareCorrection(context.Background(), p, c, security.WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	selected := prepared.Selected()
	count := func(in security.IntentSet) int64 {
		ctx := newCountdown(1 << 30)
		if _, ok := intentIndex(ctx, in); !ok {
			t.Fatal("control intent not indexed")
		}
		return ctx.calls.Load()
	}
	free := count(prepared.replay.inputs.Access.Input.Intent) + count(*a.Intent)
	// Cancel inside the first index, and at the first check after both indexes are built.
	for _, tc := range []struct {
		name      string
		free      int64
		exactStop bool
	}{{"inside the baseline index", 0, false}, {"after both indexes", free, true}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newCountdown(tc.free)
			got, changed := prepared.compatibleIntent(ctx, a.Intent)
			if got != nil || len(changed) != len(selected) {
				t.Fatalf("a canceled comparison must report every selected expectation as changed: %+v %v", got, changed)
			}
			if tc.exactStop && ctx.calls.Load() != tc.free+1 {
				t.Fatalf("%d checks ran after the cancellation at check %d", ctx.calls.Load()-tc.free-1, tc.free+1)
			}
		})
	}
	if got, changed := prepared.compatibleIntent(newCountdown(1<<30), a.Intent); got == nil || len(changed) != 0 {
		t.Fatalf("control: %+v %v", got, changed)
	}
}

func TestJudgeAccessStopsAtEachCancellationCheck(t *testing.T) {
	p, c, a := fullVerifyFixture(t)
	prepared, err := PrepareCorrection(context.Background(), p, c, security.WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	probe := newCountdown(1 << 30)
	var full VerificationReport
	if err := judgeAccess(probe, &full, prepared, c, a); err != nil {
		t.Fatal(err)
	}
	rows := len(full.Targets) + len(full.Guards)
	if rows != 3 {
		t.Fatalf("control rows: %d", rows)
	}
	total := probe.calls.Load()
	// The last rows+1 checks are one per selected expectation and a final one after them.
	before := total - int64(rows) - 1
	for _, tc := range []struct {
		name     string
		free     int64
		wantRows int
	}{
		{"before the first expectation", before, 0},
		{"before the second expectation", before + 1, 1},
		{"after the last expectation", total - 1, rows},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out VerificationReport
			ctx := newCountdown(tc.free)
			err := judgeAccess(ctx, &out, prepared, c, a)
			if !errors.Is(err, context.Canceled) || len(out.Targets)+len(out.Guards) != tc.wantRows {
				t.Fatalf("err %v rows %d", err, len(out.Targets)+len(out.Guards))
			}
			if ctx.calls.Load() != tc.free+1 {
				t.Fatalf("%d checks ran after the cancellation at check %d", ctx.calls.Load()-tc.free-1, tc.free+1)
			}
		})
	}
	var early VerificationReport
	if err := judgeAccess(newCountdown(0), &early, prepared, c, a); !errors.Is(err, context.Canceled) || len(early.Targets)+len(early.Guards) != 0 {
		t.Fatalf("canceled before any work: %v", err)
	}
}

// stepChecks runs the steps VerifyCorrection is made of, one at a time, and returns how many
// cancellation checks had run when each step finished: prepare, evaluate, versions, features, access.
func stepChecks(t *testing.T, p EvidencePack, c security.CorrectionIntent, a AfterEvidence) [5]int64 {
	t.Helper()
	ctx := newCountdown(1 << 30)
	budget := security.WorkBudget{}
	var done [5]int64
	prepared, err := PrepareCorrection(ctx, p, c, budget)
	if err != nil {
		t.Fatal(err)
	}
	done[0] = ctx.calls.Load()
	report, err := evaluateAfter(ctx, prepared, c, a, budget)
	if err != nil {
		t.Fatal(err)
	}
	done[1] = ctx.calls.Load()
	var out VerificationReport
	appendFindingRows(&out, prepared, c, a, report)
	if err = appendVersionRows(ctx, &out, prepared, c, a, budget); err != nil {
		t.Fatal(err)
	}
	done[2] = ctx.calls.Load()
	if err = appendFeatureRows(ctx, &out, prepared, c, a, budget); err != nil {
		t.Fatal(err)
	}
	done[3] = ctx.calls.Load()
	if err = judgeAccess(ctx, &out, prepared, c, a); err != nil {
		t.Fatal(err)
	}
	done[4] = ctx.calls.Load()
	return done
}

// The verdict is not returned if the context ends after the last step has run.
func TestVerifyCorrectionChecksCancellationAfterItsLastStep(t *testing.T) {
	fixtures := map[string]func(*testing.T) (EvidencePack, security.CorrectionIntent, AfterEvidence){"finding only": fleetVerifyFixture, "with access": fullVerifyFixture}
	for name, fixture := range fixtures {
		t.Run(name, func(t *testing.T) {
			p, c, a := fixture(t)
			steps := stepChecks(t, p, c, a)[4]
			r, err := VerifyCorrection(newCountdown(steps), p, c, a, security.WorkBudget{})
			if !errors.Is(err, context.Canceled) || r.Outcome != "" {
				t.Fatalf("canceled after the last step: %+v %v", r, err)
			}
			if r, err = VerifyCorrection(newCountdown(steps+1), p, c, a, security.WorkBudget{}); err != nil || r.Outcome == "" {
				t.Fatalf("one more free check must give a verdict: %+v %v", r, err)
			}
		})
	}
}

// A single canceled check inside any step ends the verification with that error, even though every
// later check would pass: no step's failure may be dropped in favor of the steps after it.
func TestVerifyCorrectionReturnsTheFirstStepFailure(t *testing.T) {
	p, c, a := fullVerifyFixture(t)
	done := stepChecks(t, p, c, a)
	// Re-evaluating the after evidence runs no cancellation check of its own. The access step reads a
	// transient cancellation as changed input and relies on the context staying canceled, which
	// the sticky sweep below covers; neither has a case here.
	for _, step := range []struct {
		name       string
		first, end int64
	}{
		{"prepare", 1, done[0]},
		{"versions", done[1] + 1, done[2]},
		{"features", done[2] + 1, done[3]},
	} {
		if step.end < step.first {
			t.Fatalf("%s runs no cancellation check", step.name)
		}
		t.Run(step.name, func(t *testing.T) {
			ctx := &onceCanceledContext{Context: context.Background(), at: step.first}
			r, err := VerifyCorrection(ctx, p, c, a, security.WorkBudget{})
			if err == nil || r.Outcome != "" {
				t.Fatalf("a failure at the first check of %s was dropped: %+v %v", step.name, r, err)
			}
		})
	}
}

// A cancellation at any check, in any phase, must come back as an error and never as a verdict.
func TestVerifyCorrectionNeverReturnsAVerdictAfterCancellation(t *testing.T) {
	p, c, a := fullVerifyFixture(t)
	probe := newCountdown(1 << 30)
	if _, err := VerifyCorrection(probe, p, c, a, security.WorkBudget{}); err != nil {
		t.Fatal(err)
	}
	total := probe.calls.Load()
	if total < 20 {
		t.Fatalf("only %d cancellation checks; the sweep would prove little", total)
	}
	for free := int64(0); free < total; free++ {
		r, err := VerifyCorrection(newCountdown(free), p, c, a, security.WorkBudget{})
		if err == nil || r.Outcome != "" || len(r.Targets) != 0 || len(r.Guards) != 0 {
			t.Fatalf("canceled at check %d of %d: outcome %q err %v", free+1, total, r.Outcome, err)
		}
	}
}

// onceCanceledContext reports context.Canceled from exactly one call to Err, the n-th.
type onceCanceledContext struct {
	context.Context
	at    int64
	calls atomic.Int64
}

func (c *onceCanceledContext) Err() error {
	if c.calls.Add(1) == c.at {
		return context.Canceled
	}
	return nil
}

// The baseline judgement runs first; if it fails the row must not be built from the later one alone.
func TestAppendRowsStopWhenTheBaselineJudgementFails(t *testing.T) {
	p, c, a := fullVerifyFixture(t)
	prepared, err := PrepareCorrection(context.Background(), p, c, security.WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	var control VerificationReport
	if err := appendVersionRows(context.Background(), &control, prepared, c, a, security.WorkBudget{}); err != nil || len(control.Targets) != 1 {
		t.Fatalf("version control: %v", err)
	}
	if err := appendFeatureRows(context.Background(), &control, prepared, c, a, security.WorkBudget{}); err != nil || len(control.Targets) != 2 {
		t.Fatalf("feature control: %v", err)
	}
	var versions, features VerificationReport
	if err := appendVersionRows(&onceCanceledContext{Context: context.Background(), at: 1}, &versions, prepared, c, a, security.WorkBudget{}); !errors.Is(err, context.Canceled) || len(versions.Targets) != 0 {
		t.Fatalf("baseline version judgement: %v %+v", err, versions)
	}
	if err := appendFeatureRows(&onceCanceledContext{Context: context.Background(), at: 1}, &features, prepared, c, a, security.WorkBudget{}); !errors.Is(err, context.Canceled) || len(features.Targets) != 0 {
		t.Fatalf("baseline feature judgement: %v %+v", err, features)
	}
}

func TestFullVerifyFixtureIsAGoodControl(t *testing.T) {
	p, c, a := fullVerifyFixture(t)
	r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || len(r.Targets) != 4 || len(r.Guards) != 2 {
		t.Fatalf("got %+v %v", r, err)
	}
	for _, row := range r.Targets {
		if row.Outcome != "fixed" {
			t.Errorf("%s %s: %s %s", row.Kind, row.Name, row.Outcome, row.Reason)
		}
	}
}
