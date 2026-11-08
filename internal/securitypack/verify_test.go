package securitypack

import (
	"context"
	"errors"
	"fmt"
	"github.com/abm9111/tailkeeper/internal/advisory"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

func TestPrepareCorrectionRejectsInvalidPack(t *testing.T) {
	_, err := PrepareCorrection(context.Background(), EvidencePack{}, security.CorrectionIntent{SchemaVersion: 1, ActionAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Findings: []security.CorrectionFinding{{RuleID: "RULE", Asset: "device"}}}, security.WorkBudget{})
	if !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("invalid pack: %v", err)
	}
}

func TestGuardOutcomeTable(t *testing.T) {
	cases := []struct {
		before, after security.AccessStatus
		old, next     []security.AccessLimit
		want          string
	}{
		{security.AccessMet, security.AccessUnmet, nil, nil, "regressed"},
		{security.AccessUnknown, security.AccessUnmet, nil, nil, "still_unmet"},
		{security.AccessMet, security.AccessUnknown, nil, nil, "unconfirmed"},
		{security.AccessMetWithLimits, security.AccessNotEvaluated, nil, nil, "unconfirmed"},
		{security.AccessUnmet, security.AccessUnknown, nil, nil, "unchanged_unconfirmed"},
		{security.AccessMetWithLimits, security.AccessMetWithLimits, []security.AccessLimit{security.LimitPosture, security.LimitRules}, []security.AccessLimit{security.LimitRules, security.LimitPosture}, "unchanged"},
		{security.AccessMetWithLimits, security.AccessMetWithLimits, []security.AccessLimit{security.LimitPosture}, []security.AccessLimit{security.LimitRules}, "limits_changed"},
		{security.AccessMet, security.AccessMetWithLimits, nil, []security.AccessLimit{security.LimitRules}, "limits_changed"},
		{security.AccessUnknown, security.AccessMetWithLimits, nil, []security.AccessLimit{security.LimitRules}, "improved"},
		{security.AccessMet, security.AccessMet, nil, nil, "held"},
		{security.AccessUnmet, security.AccessMet, nil, nil, "improved"},
	}
	for _, tc := range cases {
		got := guardOutcome(security.AccessJudgement{Status: tc.before, Limits: tc.old}, security.AccessJudgement{Status: tc.after, Limits: tc.next})
		if got != tc.want {
			t.Errorf("%s -> %s (%v -> %v): got %s want %s", tc.before, tc.after, tc.old, tc.next, got, tc.want)
		}
	}
}

func TestVerifyFindingRequiresFleetAndPostActionEvidence(t *testing.T) {
	in := replayFixture(t)
	_, pack, _ := built(t, in, nil)
	action := in.Input.Now.Add(time.Minute)
	c := security.CorrectionIntent{SchemaVersion: 1, ActionAt: action, Findings: []security.CorrectionFinding{{RuleID: "SYNTHETIC-ONLY", Asset: "synthetic"}}}
	snap := in.Input.Snapshot
	snap.ObservedAt = action.Add(time.Minute)
	snap.Versions = append([]security.VersionFact(nil), snap.Versions...)
	fixed := "9.8.9"
	snap.Versions[0].Value = &fixed
	snap.Versions[0].Evidence.AcquiredAt = snap.ObservedAt
	after := AfterEvidence{Snapshot: snap, Now: snap.ObservedAt, Catalog: in.Input.Catalog, CatalogSources: in.Sources}
	report, err := VerifyCorrection(context.Background(), pack, c, after, security.WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Outcome != "incomplete" || len(report.Targets) != 1 || report.Targets[0].Reason != "context_identity_unavailable" {
		t.Fatalf("local context: %+v", report)
	}
	snap.Versions[0].Value = in.Input.Snapshot.Versions[0].Value
	after.Snapshot = snap
	report, err = VerifyCorrection(context.Background(), pack, c, after, security.WorkBudget{})
	if err != nil || report.Outcome != "not_fixed" {
		t.Fatalf("still affected: %+v %v", report, err)
	}
}

func TestVerifyAccessRequiresRecentBoundInput(t *testing.T) {
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
	in.Access = &AccessEvidence{Context: in.Input.Snapshot.Context, Selected: []string{"network-1"}, Input: security.AccessInput{Intent: intent, EvaluatedAt: in.Input.Now}}
	_, pack, _ := built(t, in, nil)
	action := in.Input.Now.Add(time.Minute)
	snap := in.Input.Snapshot
	snap.ObservedAt = action.Add(time.Minute)
	access := &AfterAccess{Context: in.Access.Context, StartedAt: action.Add(time.Second), Input: security.AccessInput{Intent: intent, EvaluatedAt: snap.ObservedAt, Witnesses: []security.AccessWitness{{Expectation: "network-1", Cell: security.AccessCell{Expect: "accept", Destination: "tag:service:443"}, Observed: security.ObservedAllowed, Proof: security.AccessProof{Canary: true, LiveUnchanged: true}}}}}
	after := AfterEvidence{Snapshot: snap, Now: snap.ObservedAt, Catalog: in.Input.Catalog, CatalogSources: in.Sources, Intent: &intent, Access: access}
	c := security.CorrectionIntent{SchemaVersion: 1, ActionAt: action, ExpectationIDs: []string{"network-1"}}
	got, err := VerifyCorrection(context.Background(), pack, c, after, security.WorkBudget{})
	if err != nil || got.Outcome != "fixed" {
		t.Fatalf("valid access: %+v %v", got, err)
	}
	access.StartedAt = action
	got, err = VerifyCorrection(context.Background(), pack, c, after, security.WorkBudget{})
	if err != nil || got.Outcome != "incomplete" || got.Targets[0].Reason != "access_not_post_action" {
		t.Fatalf("pre-action: %+v %v", got, err)
	}
	access.StartedAt = action.Add(time.Second)
	access.Input.Limit = 1
	got, err = VerifyCorrection(context.Background(), pack, c, after, security.WorkBudget{})
	if err != nil || got.Targets[0].Reason != "access_input_mismatch" {
		t.Fatalf("limit: %+v %v", got, err)
	}
	access.Input.Limit = 0
	altered := intent
	altered.Network = append([]security.NetworkExpectation(nil), intent.Network...)
	altered.Network[0].Deny = altered.Network[0].Accept
	altered.Network[0].Accept = nil
	access.Input.Intent = altered
	got, err = VerifyCorrection(context.Background(), pack, c, after, security.WorkBudget{})
	if err != nil || got.Targets[0].Reason != "access_input_mismatch" {
		t.Fatalf("substitution: %+v %v", got, err)
	}
	access.Input.Intent = intent
	after.Now = access.StartedAt.Add(31 * time.Minute)
	got, err = VerifyCorrection(context.Background(), pack, c, after, security.WorkBudget{})
	if err != nil || got.Targets[0].Reason != "access_not_recent" {
		t.Fatalf("cache: %+v %v", got, err)
	}
}

func fleetVerifyFixture(t *testing.T) (EvidencePack, security.CorrectionIntent, AfterEvidence) {
	t.Helper()
	in := replayFixture(t)
	in.Input.Snapshot.Context = "ctx-0123456789abcdef"
	in.Input.Snapshot.Scope = security.ScopeFleet
	in.Input.Snapshot.Versions[0].Evidence.Context = in.Input.Snapshot.Context
	in.Input.Snapshot.Versions[0].Evidence.Scope = security.ScopeFleet
	var err error
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	_, p, _ := built(t, in, nil)
	at := in.Input.Now.Add(time.Minute)
	c := security.CorrectionIntent{SchemaVersion: 1, ActionAt: at, Findings: []security.CorrectionFinding{{RuleID: "SYNTHETIC-ONLY", Asset: "synthetic"}}}
	snap := in.Input.Snapshot
	snap.Versions = append([]security.VersionFact(nil), snap.Versions...)
	snap.ObservedAt = at.Add(time.Minute)
	v := "9.8.9"
	snap.Versions[0].Value = &v
	snap.Versions[0].Evidence.AcquiredAt = snap.ObservedAt
	return p, c, AfterEvidence{Snapshot: snap, Now: snap.ObservedAt, Catalog: in.Input.Catalog, CatalogSources: in.Sources}
}
func TestVerifyFindingOutcomeCases(t *testing.T) {
	cases := []struct {
		name, want, reason string
		change             func(*EvidencePack, *security.CorrectionIntent, *AfterEvidence)
	}{
		{"fixed", "fixed", "", func(*EvidencePack, *security.CorrectionIntent, *AfterEvidence) {}},
		{"old", "not_fixed", "", func(_ *EvidencePack, _ *security.CorrectionIntent, a *AfterEvidence) {
			v := "1.30.0"
			a.Snapshot.Versions[0].Value = &v
		}},
		{"stale observation", "incomplete", "evidence_not_after_action", func(_ *EvidencePack, c *security.CorrectionIntent, a *AfterEvidence) {
			v := c.ActionAt
			a.Snapshot.Versions[0].Evidence.ObservedAt = &v
		}},
		{"stale snapshot", "incomplete", "evidence_not_after_action", func(_ *EvidencePack, c *security.CorrectionIntent, a *AfterEvidence) {
			a.Snapshot.ObservedAt = c.ActionAt
		}},
		{"epoch", "incomplete", "epoch_mismatch", func(_ *EvidencePack, _ *security.CorrectionIntent, a *AfterEvidence) {
			a.Snapshot.KeyEpoch = "new-epoch"
		}},
		{"unsealed key", "incomplete", "before_unsealed_key_loaded", func(p *EvidencePack, _ *security.CorrectionIntent, _ *AfterEvidence) {
			p.reading.Seal = SealAbsentKeyLoaded
		}},
		{"missing device", "incomplete", "target_missing_after", func(_ *EvidencePack, _ *security.CorrectionIntent, a *AfterEvidence) { a.Snapshot.Versions = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, c, a := fleetVerifyFixture(t)
			tc.change(&p, &c, &a)
			r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
			if err != nil || r.Outcome != tc.want || len(r.Targets) != 1 || r.Targets[0].Reason != tc.reason {
				t.Fatalf("got %+v err %v", r, err)
			}
		})
	}
}
func TestPreflightFileRefusals(t *testing.T) {
	cases := []struct {
		name   string
		want   error
		change func(*security.CorrectionIntent)
	}{
		{"unknown", ErrTargetUnknown, func(c *security.CorrectionIntent) { c.Findings[0].RuleID = "OTHER" }},
		{"device", ErrDeviceNotInPack, func(c *security.CorrectionIntent) {
			c.Findings = nil
			c.Versions = []security.ExpectedVersion{{Asset: "missing", Name: "client", AtLeast: "9.8.9"}}
		}},
		{"expectation", ErrExpectationNotSelected, func(c *security.CorrectionIntent) { c.Findings = nil; c.ExpectationIDs = []string{"network-1"} }},
		{"old action", ErrActionNotAfterObservation, func(c *security.CorrectionIntent) { c.ActionAt = c.ActionAt.Add(-time.Minute) }},
		{"already satisfied", ErrTargetNotOpen, func(c *security.CorrectionIntent) {
			c.Findings = nil
			c.Versions = []security.ExpectedVersion{{Asset: "synthetic", Name: "client", AtLeast: "1.20.0"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, c, _ := fleetVerifyFixture(t)
			tc.change(&c)
			_, err := PrepareCorrection(context.Background(), p, c, security.WorkBudget{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyRefusesDifferentSnapshotContext(t *testing.T) {
	in := replayFixture(t)
	_, p, _ := built(t, in, nil)
	c := security.CorrectionIntent{SchemaVersion: 1, ActionAt: in.Input.Now.Add(time.Minute), Findings: []security.CorrectionFinding{{RuleID: "SYNTHETIC-ONLY", Asset: "synthetic"}}}
	snap := in.Input.Snapshot
	snap.Context = "ctx-0123456789abcdef"
	snap.Versions = append([]security.VersionFact(nil), snap.Versions...)
	snap.Versions[0].Evidence.Context = snap.Context
	snap.ObservedAt = c.ActionAt.Add(time.Minute)
	_, err := VerifyCorrection(context.Background(), p, c, AfterEvidence{Snapshot: snap, Now: snap.ObservedAt, Catalog: in.Input.Catalog, CatalogSources: in.Sources}, security.WorkBudget{})
	if !errors.Is(err, ErrContextMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyOtherCatalogRulesAreReported(t *testing.T) {
	p, c, a := fleetVerifyFixture(t)
	other := strings.Replace(replayCatalog, "SYNTHETIC-ONLY", "SYNTHETIC-OTHER", 1)
	a.CatalogSources = append(a.CatalogSources, advisory.Source{Name: "other.json", Data: []byte(other)})
	var err error
	a.Catalog, err = advisory.Merge(a.CatalogSources)
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "fixed" || !r.CatalogChangedOtherRules {
		t.Fatalf("got %+v %v", r, err)
	}
}

func TestGuardRowsSurviveMoreThanAHundredExpectations(t *testing.T) {
	in := replayFixture(t)
	in.Input.Snapshot.Context = "ctx-0123456789abcdef"
	in.Input.Snapshot.Scope = security.ScopeFleet
	in.Input.Snapshot.Versions[0].Evidence.Context = in.Input.Snapshot.Context
	in.Input.Snapshot.Versions[0].Evidence.Scope = security.ScopeFleet
	intent := security.IntentSet{SchemaVersion: security.SchemaVersion}
	ids := make([]string, 0, 150)
	witnesses := make([]security.AccessWitness, 0, 64)
	for i := 1; i <= 150; i++ {
		id := fmt.Sprintf("network-%d", i)
		ids = append(ids, id)
		intent.Network = append(intent.Network, security.NetworkExpectation{ID: id, Source: fmt.Sprintf("source-%d", i), Accept: []string{"tag:service:443"}})
		if i <= 64 {
			witnesses = append(witnesses, security.AccessWitness{Expectation: id, Cell: security.AccessCell{Expect: "accept", Destination: "tag:service:443"}, Observed: security.ObservedAllowed, Proof: security.AccessProof{Canary: true, LiveUnchanged: true}})
		}
	}
	in.Input.Intent = &intent
	var err error
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	in.Access = &AccessEvidence{Context: in.Input.Snapshot.Context, Selected: ids, Input: security.AccessInput{Intent: intent, EvaluatedAt: in.Input.Now, Witnesses: witnesses}}
	_, p, base := built(t, in, nil)
	if len(base.AccessJudgements) != 150 {
		t.Fatalf("baseline %d", len(base.AccessJudgements))
	}
	at := in.Input.Now.Add(time.Minute)
	c := security.CorrectionIntent{SchemaVersion: 1, ActionAt: at, Findings: []security.CorrectionFinding{{RuleID: "SYNTHETIC-ONLY", Asset: "synthetic"}}}
	snap := in.Input.Snapshot
	snap.Versions = append([]security.VersionFact(nil), snap.Versions...)
	v := "9.8.9"
	snap.Versions[0].Value = &v
	snap.ObservedAt = at.Add(time.Minute)
	snap.Versions[0].Evidence.AcquiredAt = snap.ObservedAt
	afterWitnesses := append([]security.AccessWitness(nil), witnesses[:14]...)
	afterWitnesses = append(afterWitnesses, witnesses[15:]...)
	after := AfterEvidence{Snapshot: snap, Now: snap.ObservedAt, Catalog: in.Input.Catalog, CatalogSources: in.Sources, Intent: &intent, Access: &AfterAccess{Context: in.Access.Context, StartedAt: at.Add(time.Second), Input: security.AccessInput{Intent: intent, EvaluatedAt: snap.ObservedAt, Witnesses: afterWitnesses}}}
	r, err := VerifyCorrection(context.Background(), p, c, after, security.WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Outcome != "incomplete" || len(r.Guards) != 150 {
		t.Fatalf("outcome %s guards %d", r.Outcome, len(r.Guards))
	}
	got := ""
	for _, g := range r.Guards {
		if g.ExpectationID == "network-15" {
			got = g.Outcome
		}
	}
	if got != "unconfirmed" {
		t.Fatalf("network-15: %s", got)
	}
	denied := witnesses[14]
	denied.Observed = security.ObservedDenied
	after.Access.Input.Witnesses = append(afterWitnesses, denied)
	r, err = VerifyCorrection(context.Background(), p, c, after, security.WorkBudget{})
	if err != nil || r.Outcome != "not_fixed" {
		t.Fatalf("guard unmet: %s %v", r.Outcome, err)
	}
	for _, g := range r.Guards {
		if g.ExpectationID == "network-15" && g.Outcome != "regressed" {
			t.Fatalf("guard: %+v", g)
		}
	}
}

func TestVerifyStopsOnCancellationAndBudget(t *testing.T) {
	p, c, a := fleetVerifyFixture(t)
	_, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{Candidates: 99})
	if !errors.Is(err, ErrBudgetTooSmall) {
		t.Fatalf("ceiling: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := VerifyCorrection(ctx, p, c, a, security.WorkBudget{})
	if err == nil || r.Outcome == "fixed" {
		t.Fatalf("cancel: %+v %v", r, err)
	}
	a.CatalogSources = []advisory.Source{{Name: "oversized.json", Data: make([]byte, maxCatalogBytes+1)}}
	_, err = VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized source: %v", err)
	}
}

func TestPreflightRejectsCorrectionBeforePack(t *testing.T) {
	_, err := PrepareCorrection(context.Background(), EvidencePack{}, security.CorrectionIntent{}, security.WorkBudget{})
	if !errors.Is(err, ErrCorrectionInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestExpectedVersionUsesMatcherAndPostActionEvidence(t *testing.T) {
	cases := []struct {
		name, want, reason string
		change             func(*AfterEvidence, *security.CorrectionIntent)
	}{
		{"satisfied", "fixed", "", func(*AfterEvidence, *security.CorrectionIntent) {}},
		{"old", "not_fixed", "", func(a *AfterEvidence, _ *security.CorrectionIntent) { v := "1.30.0"; a.Snapshot.Versions[0].Value = &v }},
		{"pre-action", "incomplete", "evidence_not_after_action", func(a *AfterEvidence, c *security.CorrectionIntent) {
			a.Snapshot.Versions[0].Evidence.AcquiredAt = c.ActionAt
		}},
		{"missing", "incomplete", "unobserved", func(a *AfterEvidence, _ *security.CorrectionIntent) { a.Snapshot.Versions = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, c, a := fleetVerifyFixture(t)
			c.Findings = nil
			c.Versions = []security.ExpectedVersion{{Asset: "synthetic", Name: "client", AtLeast: "9.8.9"}}
			tc.change(&a, &c)
			r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
			if err != nil || r.Outcome != tc.want || r.Targets[0].Reason != tc.reason {
				t.Fatalf("got %+v %v", r, err)
			}
			if r.Targets[0].AtLeast != "9.8.9" {
				t.Fatalf("missing declared threshold: %+v", r.Targets[0])
			}
		})
	}
}

func accessVerifyFixture(t *testing.T) (EvidencePack, security.CorrectionIntent, AfterEvidence) {
	t.Helper()
	in := replayFixture(t)
	in.Input.Snapshot.Scope = security.ScopeFleet
	in.Input.Snapshot.Context = "ctx-0123456789abcdef"
	in.Input.Snapshot.Versions[0].Evidence.Scope = security.ScopeFleet
	in.Input.Snapshot.Versions[0].Evidence.Context = in.Input.Snapshot.Context
	intent := security.IntentSet{SchemaVersion: 1, Network: []security.NetworkExpectation{{ID: "network-1", Source: "synthetic", Accept: []string{"tag:service:443"}}}}
	in.Input.Intent = &intent
	var err error
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	in.Access = &AccessEvidence{Context: in.Input.Snapshot.Context, Selected: []string{"network-1"}, Input: security.AccessInput{Intent: intent, EvaluatedAt: in.Input.Now}}
	_, p, _ := built(t, in, nil)
	action := in.Input.Now.Add(time.Minute)
	snap := in.Input.Snapshot
	snap.ObservedAt = action.Add(time.Minute)
	after := AfterEvidence{Snapshot: snap, Now: snap.ObservedAt, Catalog: in.Input.Catalog, CatalogSources: in.Sources, Intent: &intent, Access: &AfterAccess{Context: in.Access.Context, StartedAt: action.Add(time.Second), Input: security.AccessInput{Intent: intent, EvaluatedAt: snap.ObservedAt, Witnesses: []security.AccessWitness{{Expectation: "network-1", Cell: security.AccessCell{Expect: "accept", Destination: "tag:service:443"}, Observed: security.ObservedAllowed, Proof: security.AccessProof{Canary: true, LiveUnchanged: true}}}}}}
	return p, security.CorrectionIntent{SchemaVersion: 1, ActionAt: action, ExpectationIDs: []string{"network-1"}}, after
}
func TestVerifyAccessTrustAndOutcomeCases(t *testing.T) {
	cases := []struct {
		name, want, reason string
		change             func(*AfterEvidence)
	}{
		{"nil input", "incomplete", "access_not_post_action", func(a *AfterEvidence) { a.Access = nil }},
		{"different context", "incomplete", "access_not_post_action", func(a *AfterEvidence) { a.Access.Context = "ctx-1111111111111111" }},
		{"evaluated before start", "incomplete", "access_not_post_action", func(a *AfterEvidence) { a.Access.Input.EvaluatedAt = a.Access.StartedAt.Add(-time.Second) }},
		{"evaluated in future", "incomplete", "access_not_post_action", func(a *AfterEvidence) { a.Access.Input.EvaluatedAt = a.Now.Add(time.Second) }},
		{"no intent input", "incomplete", "access_not_post_action", func(a *AfterEvidence) { a.Access.Input.NoIntent = true }},
		{"intent unavailable", "incomplete", "intent_unavailable", func(a *AfterEvidence) { a.Intent = nil }},
		{"changed intent", "incomplete", "intent_changed", func(a *AfterEvidence) {
			i := *a.Intent
			i.Network = append([]security.NetworkExpectation(nil), i.Network...)
			i.Network[0].Source = "other"
			a.Intent = &i
		}},
		{"unknown", "incomplete", "access_not_witnessed", func(a *AfterEvidence) { a.Access.Input.Witnesses = nil }},
		{"limited", "incomplete", "limited", func(a *AfterEvidence) {
			a.Access.Input.Limits = map[string][]security.AccessLimit{"network-1": {security.LimitRules}}
		}},
		{"unmet", "not_fixed", "", func(a *AfterEvidence) { a.Access.Input.Witnesses[0].Observed = security.ObservedDenied }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, c, a := accessVerifyFixture(t)
			tc.change(&a)
			r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
			if err != nil || r.Outcome != tc.want || len(r.Targets) != 1 || r.Targets[0].Reason != tc.reason {
				t.Fatalf("got %+v %v", r, err)
			}
		})
	}
}
func TestPreparedCorrectionReturnsOwnedViews(t *testing.T) {
	p, c, a := accessVerifyFixture(t)
	prepared, err := PrepareCorrection(context.Background(), p, c, security.WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Scope() != security.ScopeFleet || prepared.Context() != a.Snapshot.Context || prepared.AccessContext() != a.Access.Context {
		t.Fatal("context views differ")
	}
	ids := prepared.Selected()
	ids[0] = "altered"
	if prepared.Selected()[0] != "network-1" {
		t.Fatal("selected alias")
	}
	current, changed := prepared.CompatibleIntent(a.Intent)
	if current == nil || len(changed) != 0 {
		t.Fatal("compatible intent")
	}
	current.Network[0].Accept[0] = "altered"
	again, _ := prepared.CompatibleIntent(a.Intent)
	if again.Network[0].Accept[0] != "tag:service:443" {
		t.Fatal("intent alias")
	}
	without, changed := prepared.CompatibleIntent(nil)
	if without != nil || len(changed) != 1 {
		t.Fatal("nil intent")
	}
}

func TestExpectedFeatureAndPreflight(t *testing.T) {
	in := replayFixture(t)
	in.Input.Snapshot.Scope = security.ScopeFleet
	in.Input.Snapshot.Context = "ctx-0123456789abcdef"
	in.Input.Snapshot.Versions[0].Evidence.Scope = security.ScopeFleet
	in.Input.Snapshot.Versions[0].Evidence.Context = in.Input.Snapshot.Context
	on := true
	in.Input.Snapshot.Features = []security.FeatureFact{{Name: "tailscale_ssh", Value: &on, Evidence: in.Input.Snapshot.Versions[0].Evidence}}
	var err error
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	_, p, _ := built(t, in, nil)
	action := in.Input.Now.Add(time.Minute)
	c := security.CorrectionIntent{SchemaVersion: 1, ActionAt: action, Features: []security.ExpectedFeature{{Asset: "synthetic", Name: "tailscale_ssh", Value: false}}}
	snap := in.Input.Snapshot
	snap.Features = append([]security.FeatureFact(nil), snap.Features...)
	off := false
	snap.Features[0].Value = &off
	snap.ObservedAt = action.Add(time.Minute)
	snap.Features[0].Evidence.AcquiredAt = snap.ObservedAt
	a := AfterEvidence{Snapshot: snap, Now: snap.ObservedAt, Catalog: in.Input.Catalog, CatalogSources: in.Sources}
	r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "fixed" || r.Targets[0].Value == nil || *r.Targets[0].Value || r.Targets[0].Role != security.VersionRunningDaemon {
		t.Fatalf("feature: %+v %v", r, err)
	}
	c.Features[0].Value = true
	_, err = PrepareCorrection(context.Background(), p, c, security.WorkBudget{})
	if !errors.Is(err, ErrTargetNotOpen) {
		t.Fatalf("already satisfied: %v", err)
	}
	c.Features[0].Asset = "missing"
	_, err = PrepareCorrection(context.Background(), p, c, security.WorkBudget{})
	if !errors.Is(err, ErrDeviceNotInPack) {
		t.Fatalf("missing: %v", err)
	}
}

func TestVerifyChangedRuleAndCatalogBinding(t *testing.T) {
	p, c, a := fleetVerifyFixture(t)
	src := strings.Replace(replayCatalog, `"revision":"1","component"`, `"revision":"2","component"`, 1)
	a.CatalogSources = []advisory.Source{{Name: "synthetic.json", Data: []byte(src)}}
	var err error
	a.Catalog, err = advisory.Merge(a.CatalogSources)
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "incomplete" || r.Targets[0].Reason != "rules_changed" {
		t.Fatalf("rule: %+v %v", r, err)
	}
	a.Catalog.Records[0].Mitigation = "changed caller catalog"
	_, err = VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if !errors.Is(err, ErrCatalogMismatch) {
		t.Fatalf("binding: %v", err)
	}
}
func TestSameRecordEqualityCoversModelFields(t *testing.T) {
	want := []string{"ID", "Revision", "Component", "VersionRole", "OS", "Ranges", "RequiredFeatures", "Source", "Severity", "PublishedAt", "UpdatedAt", "ReviewedAt", "ReviewExpiresAt", "SourceCheckedAt", "ReviewState", "Mitigation"}
	typ := reflect.TypeOf(security.AdvisoryRecord{})
	if typ.NumField() != len(want) {
		t.Fatalf("record fields changed: %d", typ.NumField())
	}
	for i, n := range want {
		if typ.Field(i).Name != n {
			t.Fatalf("field %d = %s", i, typ.Field(i).Name)
		}
	}
	_, _, a := fleetVerifyFixture(t)
	r := a.Catalog.Records[0]
	later := r.ReviewedAt.Add(time.Second)
	r.PublishedAt = &later
	other := r
	if !sameRecord(r, other) {
		t.Fatal("equal records")
	}
	other.PublishedAt = nil
	if sameRecord(r, other) {
		t.Fatal("different optional times")
	}
	other = r
	other.Ranges = []security.VersionRange{{Fixed: "9.8.10"}}
	if sameRecord(r, other) {
		t.Fatal("different range")
	}
}

func TestExpectedVersionD1GuardIsPostAction(t *testing.T) {
	p, c, a := fleetVerifyFixture(t)
	c.Findings = nil
	c.Versions = []security.ExpectedVersion{{Asset: "synthetic", Name: "client", AtLeast: "9.8.9"}}
	e := a.Snapshot.Versions[0].Evidence
	e.Origin = security.OriginAPI
	a.Snapshot.Versions[0].Evidence = e
	a.Snapshot.Versions[0].Role = security.VersionAPIReported
	connected := true
	guard := e
	observed := c.ActionAt
	guard.ObservedAt = &observed
	a.Snapshot.Features = []security.FeatureFact{{Name: security.FeatureConnectedToControl, Value: &connected, Evidence: guard}}
	r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "incomplete" || r.Targets[0].Reason != "evidence_not_after_action" {
		t.Fatalf("stale guard: %+v %v", r, err)
	}
	observed = a.Snapshot.ObservedAt
	r, err = VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "fixed" {
		t.Fatalf("fresh guard: %+v %v", r, err)
	}
	connected = false
	r, err = VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "incomplete" || r.Targets[0].Reason != "unobserved" {
		t.Fatalf("disconnected new: %+v %v", r, err)
	}
	old := "1.30.0"
	a.Snapshot.Versions[0].Value = &old
	r, err = VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "not_fixed" {
		t.Fatalf("disconnected old: %+v %v", r, err)
	}
}

func TestUnchangedPolicyCannotProveAccessCorrection(t *testing.T) {
	in := replayFixture(t)
	in.Input.Snapshot.Scope = security.ScopeFleet
	in.Input.Snapshot.Context = "ctx-0123456789abcdef"
	in.Input.Snapshot.Versions[0].Evidence.Scope = security.ScopeFleet
	in.Input.Snapshot.Versions[0].Evidence.Context = in.Input.Snapshot.Context
	intent := security.IntentSet{SchemaVersion: 1, Network: []security.NetworkExpectation{{ID: "network-1", Source: "synthetic", Accept: []string{"tag:service:443"}}}}
	in.Input.Intent = &intent
	var err error
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	witness := security.AccessWitness{Expectation: "network-1", Cell: security.AccessCell{Expect: "accept", Destination: "tag:service:443"}, Observed: security.ObservedDenied, Proof: security.AccessProof{Canary: true, LiveUnchanged: true}}
	token := `"` + strings.Repeat("a", 64) + `"`
	in.Access = &AccessEvidence{Context: in.Input.Snapshot.Context, Selected: []string{"network-1"}, Input: security.AccessInput{Intent: intent, EvaluatedAt: in.Input.Now, Witnesses: []security.AccessWitness{witness}, PolicyVersion: token}}
	_, p, _ := built(t, in, nil)
	action := in.Input.Now.Add(time.Minute)
	snap := in.Input.Snapshot
	snap.ObservedAt = action.Add(time.Minute)
	witness.Observed = security.ObservedAllowed
	a := AfterEvidence{Snapshot: snap, Now: snap.ObservedAt, Catalog: in.Input.Catalog, CatalogSources: in.Sources, Intent: &intent, Access: &AfterAccess{Context: in.Access.Context, StartedAt: action.Add(time.Second), Input: security.AccessInput{Intent: intent, EvaluatedAt: snap.ObservedAt, Witnesses: []security.AccessWitness{witness}, PolicyVersion: token}}}
	c := security.CorrectionIntent{SchemaVersion: 1, ActionAt: action, ExpectationIDs: []string{"network-1"}}
	r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Targets[0].Reason != "policy_unchanged" || r.PolicyCheck != "unchanged" {
		t.Fatalf("unchanged: %+v %v", r, err)
	}
	a.Access.Input.PolicyVersion = `"` + strings.Repeat("b", 64) + `"`
	r, err = VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "fixed" || r.PolicyCheck != "changed" {
		t.Fatalf("changed: %+v %v", r, err)
	}
}

func TestPreflightRejectsClosedAndUnreproducedBaseline(t *testing.T) {
	in := replayFixture(t)
	v := "9.8.9"
	in.Input.Snapshot.Versions[0].Value = &v
	var err error
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	_, p, _ := built(t, in, nil)
	c := security.CorrectionIntent{SchemaVersion: 1, ActionAt: in.Input.Now.Add(time.Minute), Findings: []security.CorrectionFinding{{RuleID: "SYNTHETIC-ONLY", Asset: "synthetic"}}}
	_, err = PrepareCorrection(context.Background(), p, c, security.WorkBudget{})
	if !errors.Is(err, ErrTargetNotOpen) {
		t.Fatalf("closed: %v", err)
	}
	pi, err := packInputOf(p)
	if err != nil {
		t.Fatal(err)
	}
	pi.Expected.Report.SHA256 = strings.Repeat("a", 64)
	p, err = newPack(pi, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = PrepareCorrection(context.Background(), p, c, security.WorkBudget{})
	if !errors.Is(err, ErrNotReproduced) {
		t.Fatalf("reproduction: %v", err)
	}
}
func TestNoAccessPreparedViews(t *testing.T) {
	p, c, _ := fleetVerifyFixture(t)
	v, err := PrepareCorrection(context.Background(), p, c, security.WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	if v.AccessContext() != "" || v.Selected() != nil {
		t.Fatal("access should be absent")
	}
	intent, changed := v.CompatibleIntent(nil)
	if intent != nil || changed != nil {
		t.Fatal("no access compatibility")
	}
}

func TestExpectedFeatureD5GuardAndDisagreement(t *testing.T) {
	in := replayFixture(t)
	in.Input.Snapshot.Scope = security.ScopeFleet
	in.Input.Snapshot.Context = "ctx-0123456789abcdef"
	in.Input.Snapshot.Versions[0].Evidence.Scope = security.ScopeFleet
	in.Input.Snapshot.Versions[0].Evidence.Context = in.Input.Snapshot.Context
	on := true
	e := in.Input.Snapshot.Versions[0].Evidence
	in.Input.Snapshot.Features = []security.FeatureFact{{Name: "tailscale_ssh", Value: &on, Evidence: e}}
	var err error
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	_, p, _ := built(t, in, nil)
	action := in.Input.Now.Add(time.Minute)
	c := security.CorrectionIntent{SchemaVersion: 1, ActionAt: action, Features: []security.ExpectedFeature{{Asset: "synthetic", Name: "tailscale_ssh", Value: false}}}
	snap := in.Input.Snapshot
	snap.ObservedAt = action.Add(time.Minute)
	e.Origin = security.OriginAPI
	e.AcquiredAt = snap.ObservedAt
	off := false
	connected := true
	snap.Features = []security.FeatureFact{{Name: "tailscale_ssh", Value: &off, Evidence: e}, {Name: security.FeatureConnectedToControl, Value: &connected, Evidence: e}}
	a := AfterEvidence{Snapshot: snap, Now: snap.ObservedAt, Catalog: in.Input.Catalog, CatalogSources: in.Sources}
	r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "fixed" {
		t.Fatalf("connected: %+v %v", r, err)
	}
	connected = false
	r, err = VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "incomplete" || r.Targets[0].Reason != "unobserved" {
		t.Fatalf("disconnected: %+v %v", r, err)
	}
	connected = true
	local := e
	local.Origin = security.OriginLocal
	a.Snapshot.Features = append(a.Snapshot.Features, security.FeatureFact{Name: "tailscale_ssh", Value: &on, Evidence: local})
	r, err = VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "incomplete" || r.Targets[0].Reason != "unobserved" {
		t.Fatalf("disagree: %+v %v", r, err)
	}
	a.Snapshot.Features = a.Snapshot.Features[:2]
	a.Snapshot.Features[0].Value = &on
	r, err = VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "not_fixed" {
		t.Fatalf("opposite: %+v %v", r, err)
	}
}

func TestAccessFixRequiresMatchingKeyEpoch(t *testing.T) {
	p, c, a := accessVerifyFixture(t)
	r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "fixed" {
		t.Fatalf("matching empty: %+v %v", r, err)
	}
	a.Snapshot.KeyEpoch = "new-epoch"
	r, err = VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "incomplete" || r.Targets[0].Reason != "epoch_mismatch" {
		t.Fatalf("mismatched: %+v %v", r, err)
	}
	pi, err := packInputOf(p)
	if err != nil {
		t.Fatal(err)
	}
	pi.Snapshot.KeyEpoch = "new-epoch"
	in := security.Input{Catalog: a.Catalog, Snapshot: pi.Snapshot, Intent: pi.Intent, Collected: pi.Collected, Now: pi.EvaluationAt, Budget: pi.WorkBudget}
	report, err := security.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	build := BuildInput{Input: in, Report: report, Sources: pi.Sources, Access: &AccessEvidence{Context: pi.Access.Context, Selected: pi.Access.Selected, Input: pi.Access.Input}}
	_, p, _ = built(t, build, nil)
	r, err = VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "fixed" {
		t.Fatalf("matching nonempty: %+v %v", r, err)
	}
	a.Access.Input.Witnesses[0].Observed = security.ObservedDenied
	a.Snapshot.KeyEpoch = "other-epoch"
	r, err = VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "not_fixed" {
		t.Fatalf("unmet precedence: %+v %v", r, err)
	}
}

func TestVerifyRejectsFutureActionAndCatalogMismatch(t *testing.T) {
	p, c, a := fleetVerifyFixture(t)
	a.Now = c.ActionAt.Add(-5*time.Minute - time.Nanosecond)
	_, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if !errors.Is(err, ErrActionInFuture) {
		t.Fatalf("future: %v", err)
	}
	p, c, a = fleetVerifyFixture(t)
	a.CatalogSources = nil
	_, err = VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if !errors.Is(err, ErrCatalogMismatch) {
		t.Fatalf("no sources: %v", err)
	}
}

func TestExpiredCatalogCannotClearFinding(t *testing.T) {
	p, c, a := fleetVerifyFixture(t)
	a.Now = time.Date(2028, 1, 2, 0, 0, 0, 0, time.UTC)
	a.Snapshot.ObservedAt = a.Now
	a.Snapshot.Versions[0].Evidence.AcquiredAt = a.Now
	r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "incomplete" || r.Targets[0].Reason != "finding_unknown" {
		t.Fatalf("expired: %+v %v", r, err)
	}
}

func TestMissingAccessJudgementNeverPasses(t *testing.T) {
	p, c, a := accessVerifyFixture(t)
	prepared, err := PrepareCorrection(context.Background(), p, c, security.WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	prepared.replay.AccessJudgements = nil
	var report VerificationReport
	_ = judgeAccess(context.Background(), &report, prepared, c, a)
	if len(report.Targets) != 1 || report.Targets[0].Reason != "access_judgement_missing" || overall(report.Targets, report.Guards, prepared.replay.Reading) != "incomplete" {
		t.Fatalf("missing judgement: %+v", report)
	}
}

func TestAccessIntentSchemaVersionBinding(t *testing.T) {
	for _, version := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("current-%d", version), func(t *testing.T) {
			p, c, a := accessVerifyFixture(t)
			i := *a.Intent
			i.SchemaVersion = version
			a.Intent = &i
			r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
			if err != nil {
				t.Fatal(err)
			}
			if version == 1 {
				if r.Outcome != "fixed" {
					t.Fatalf("valid: %+v", r)
				}
			} else if r.Outcome != "incomplete" || r.Targets[0].Reason != "intent_changed" {
				t.Fatalf("current version: %+v", r)
			}
		})
		t.Run(fmt.Sprintf("input-%d", version), func(t *testing.T) {
			p, c, a := accessVerifyFixture(t)
			a.Access.Input.Intent.SchemaVersion = version
			r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
			if err != nil {
				t.Fatal(err)
			}
			if version == 1 {
				if r.Outcome != "fixed" {
					t.Fatalf("valid: %+v", r)
				}
			} else if r.Outcome != "incomplete" || r.Targets[0].Reason != "access_input_mismatch" {
				t.Fatalf("input version: %+v", r)
			}
		})
	}
}

func TestVerifyCancellationDuringIntentComparison(t *testing.T) {
	p, c, a := accessVerifyFixture(t)
	large := *a.Intent
	large.Network = append([]security.NetworkExpectation(nil), large.Network...)
	for i := 0; i < 1999; i++ {
		large.Network = append(large.Network, security.NetworkExpectation{ID: fmt.Sprintf("extra-%d", i), Source: fmt.Sprintf("source-%d", i), Accept: []string{"tag:service:443"}})
	}
	a.Intent = &large
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(2*time.Millisecond, cancel)
	defer timer.Stop()
	r, err := VerifyCorrection(ctx, p, c, a, security.WorkBudget{})
	if ctx.Err() == nil {
		t.Fatal("test cancellation did not fire")
	}
	if err == nil || r.Outcome == "fixed" {
		t.Fatalf("canceled returned fixed: %s err %v", r.Outcome, err)
	}
}

func TestVerifyBoundsAggregateIntentInput(t *testing.T) {
	p, c, a := accessVerifyFixture(t)
	large := *a.Intent
	large.Network = append([]security.NetworkExpectation(nil), large.Network...)
	values := make([]string, MaxPackNodes+1)
	for i := range values {
		values[i] = "x"
	}
	large.Network[0].Accept = values
	if intentWithinBounds(context.Background(), large) {
		t.Fatal("oversized intent passed bound")
	}
	a.Intent = &large
	r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome == "fixed" {
		t.Fatalf("unbounded intent: %+v %v", r, err)
	}
}

func TestAccessInputBounds(t *testing.T) {
	_, _, a := accessVerifyFixture(t)
	if !accessWithinBounds(context.Background(), a.Access.Input) {
		t.Fatal("normal input refused")
	}
	a.Access.Input.Witnesses = make([]security.AccessWitness, security.MaxAccessPairs+1)
	if accessWithinBounds(context.Background(), a.Access.Input) {
		t.Fatal("too many witnesses")
	}
}

func TestIntentBoundsCoverSSHPostureAndDuplicateIDs(t *testing.T) {
	intent := security.IntentSet{SchemaVersion: 1, Network: []security.NetworkExpectation{{ID: "network-1", Source: "group", Accept: []string{"service"}, SourcePostureAttributes: security.PostureAttributes{"os": {Kind: security.ScalarString, String: "linux"}}}}, SSH: []security.SSHExpectation{{ID: "ssh-1", Source: "group", Destinations: []string{"service"}, Accept: []string{"user"}}}}
	if !intentWithinBounds(context.Background(), intent) {
		t.Fatal("valid intent")
	}
	idx, ok := intentIndex(context.Background(), intent)
	if !ok || len(idx) != 2 {
		t.Fatal("valid intent index")
	}
	duplicate := intent
	duplicate.SSH = append(append([]security.SSHExpectation(nil), intent.SSH...), security.SSHExpectation{ID: "network-1", Source: "group"})
	if _, ok = intentIndex(context.Background(), duplicate); ok {
		t.Fatal("duplicate id")
	}
	long := intent
	long.SSH = append([]security.SSHExpectation(nil), intent.SSH...)
	long.SSH[0].Source = strings.Repeat("x", security.MaxTextBytes+1)
	if intentWithinBounds(context.Background(), long) {
		t.Fatal("long text")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if intentWithinBounds(ctx, intent) {
		t.Fatal("canceled intent")
	}
}
func TestAccessInputBoundCollectionsAndCancellation(t *testing.T) {
	_, _, a := accessVerifyFixture(t)
	input := a.Access.Input
	input.Candidates = map[string]security.AccessCandidates{"network-1": {Rules: []security.RuleRef{{Section: "acls", Source: "group", Destination: "service"}}}}
	input.Limits = map[string][]security.AccessLimit{"network-1": {security.LimitRules}}
	input.Owners = []security.AccessOwner{{Source: "group", Tags: []string{"tag:service"}}}
	if !accessWithinBounds(context.Background(), input) {
		t.Fatal("normal collections")
	}
	bad := input
	bad.Owners = append([]security.AccessOwner(nil), input.Owners...)
	bad.Owners[0].Tags = []string{strings.Repeat("x", security.MaxTextBytes+1)}
	if accessWithinBounds(context.Background(), bad) {
		t.Fatal("long owner tag")
	}
	bad = input
	bad.Candidates = map[string]security.AccessCandidates{"network-1": {Rules: make([]security.RuleRef, MaxPackNodes+1)}}
	if accessWithinBounds(context.Background(), bad) {
		t.Fatal("too many candidate rules")
	}
	bad = input
	bad.Limits = map[string][]security.AccessLimit{"network-1": make([]security.AccessLimit, MaxPackNodes+1)}
	if accessWithinBounds(context.Background(), bad) {
		t.Fatal("too many limits")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if accessWithinBounds(ctx, input) {
		t.Fatal("canceled access")
	}
}
