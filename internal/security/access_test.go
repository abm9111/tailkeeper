package security

import (
	"fmt"
	"math"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// The owner's admin-path example, synthetic: only group:example-admins reaches
// tag:example-db:22, and tag:example-web must not.
func adminSet() IntentSet {
	return IntentSet{
		SchemaVersion: SchemaVersion, Revision: "0123456789ab", Digest: "hmac-sha256:0123456789abcdef",
		Network: []NetworkExpectation{
			{ID: "network-1", Source: "group:example-admins", Accept: []string{"tag:example-db:22"}},
			{ID: "network-2", Source: "tag:example-web", Deny: []string{"tag:example-db:22"}},
		},
	}
}

var accessAt = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func proven() AccessProof { return AccessProof{Canary: true, LiveUnchanged: true} }

func witness(id, expect, dst, user string, obs AccessObserved, proof AccessProof) AccessWitness {
	return AccessWitness{Expectation: id, Cell: AccessCell{Expect: expect, Destination: dst, User: user}, Observed: obs, Proof: proof}
}

func explainAccess(t *testing.T, in AccessInput) AccessReport {
	t.Helper()
	if in.EvaluatedAt.IsZero() {
		in.EvaluatedAt = accessAt
	}
	r, err := ExplainAccess(in)
	if err != nil {
		t.Fatalf("ExplainAccess: %v", err)
	}
	return r
}

func blastOf(r AccessReport, source string) *AccessBlast {
	for i := range r.Blast {
		if r.Blast[i].Source == source {
			return &r.Blast[i]
		}
	}
	return nil
}

func rowOf(r AccessReport, id string) AccessResult {
	for _, e := range r.Expectations {
		if e.ID == id {
			return e
		}
	}
	return AccessResult{}
}

func statusOfID(r AccessReport, id string) AccessStatus {
	for _, e := range r.Expectations {
		if e.ID == id {
			return e.Status
		}
	}
	return ""
}

// The admin-path invariant in its three variants: met, unmet and unknown.
func TestAdminPathExpectationMetUnmetUnknown(t *testing.T) {
	good := []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}
	t.Run("met: complete, exit 0", func(t *testing.T) {
		r := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: good})
		if r.Status != AccessComplete || r.Counts.Met != 2 || r.ExitCode() != 0 {
			t.Fatalf("status %s counts %+v exit %d, want complete, 2 met, 0", r.Status, r.Counts, r.ExitCode())
		}
	})
	t.Run("unmet: the web tier reaches the database, exit 8", func(t *testing.T) {
		ws := slices.Clone(good)
		ws[1] = witness("network-2", "deny", "tag:example-db:22", "", ObservedAllowed, proven())
		r := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws})
		if statusOfID(r, "network-2") != AccessUnmet || statusOfID(r, "network-1") != AccessMet || r.ExitCode() != 8 || r.Status != AccessIncomplete {
			t.Fatalf("%+v exit %d", r.Counts, r.ExitCode())
		}
		web := blastOf(r, "tag:example-web")
		if web == nil || len(web.Reaches) != 1 || web.Reaches[0].Destination != "tag:example-db:22" || web.Reaches[0].Expectation != "network-2" {
			t.Errorf("blast = %+v, want the web tier reaching the database, from the unmet deny", r.Blast)
		}
	})
	t.Run("unknown: the admin pair has no canary, exit 1", func(t *testing.T) {
		ws := slices.Clone(good)
		ws[0] = witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, AccessProof{LiveUnchanged: true})
		r := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws})
		if statusOfID(r, "network-1") != AccessUnknown || r.ExitCode() != 1 || r.Status != AccessIncomplete {
			t.Fatalf("%+v exit %d", r.Counts, r.ExitCode())
		}
	})
}

// A verdict that is met, or unmet, needs the canary: an allowed or a denied observation
// without one is unknown, and so is a pair nobody witnessed.
func TestAccessNoVerdictWithoutACanary(t *testing.T) {
	cases := map[string]AccessProof{"no canary": {LiveUnchanged: true}, "nothing proven": {}}
	for name, proof := range cases {
		for _, obs := range []AccessObserved{ObservedAllowed, ObservedDenied} {
			set := IntentSet{Network: []NetworkExpectation{{ID: "network-1", Source: "tag:a", Accept: []string{"tag:b:22"}}}}
			r := explainAccess(t, AccessInput{Intent: set, Witnesses: []AccessWitness{witness("network-1", "accept", "tag:b:22", "", obs, proof)}})
			c := r.Expectations[0].Cells[0]
			if c.Verdict != AccessUnknown || c.Reason != ReasonCanary || r.Expectations[0].Status != AccessUnknown {
				t.Errorf("%s, %s: pair %+v, want unknown by the canary", name, obs, c)
			}
		}
	}
	t.Run("an unknown observation keeps the reason it was given", func(t *testing.T) {
		for _, reason := range []AccessReason{ReasonRateLimited, ReasonRefused, ReasonUnresolved, ReasonLiveErrors} {
			w := AccessWitness{Expectation: "network-1", Cell: AccessCell{Expect: "accept", Destination: "tag:b:22"}, Observed: ObservedUnknown, Reason: reason}
			set := IntentSet{Network: []NetworkExpectation{{ID: "network-1", Source: "tag:a", Accept: []string{"tag:b:22"}}}}
			r := explainAccess(t, AccessInput{Intent: set, Witnesses: []AccessWitness{w}})
			if c := r.Expectations[0].Cells[0]; c.Verdict != AccessUnknown || c.Reason != reason {
				t.Errorf("%s: pair %+v, want unknown by that reason, not by the canary", reason, c)
			}
		}
	})
	t.Run("a pair with no witness is unknown", func(t *testing.T) {
		r := explainAccess(t, AccessInput{Intent: adminSet()})
		if r.Counts.Unknown != 2 || r.Expectations[0].Cells[0].Reason != ReasonNoWitness || r.ExitCode() != 1 {
			t.Errorf("%+v", r)
		}
	})
}

// The live policy moving during the check, or not being shown unchanged, makes every pair
// unknown, a failure included: what was witnessed is no longer a claim about the live policy.
func TestAccessLiveChangedMakesEveryPairUnknown(t *testing.T) {
	changed := AccessProof{Canary: true}
	set := IntentSet{Network: []NetworkExpectation{
		{ID: "network-1", Source: "tag:a", Accept: []string{"tag:b:22"}},
		{ID: "network-2", Source: "tag:c", Deny: []string{"tag:b:22"}},
		{ID: "network-3", Source: "tag:d", Accept: []string{"tag:b:22"}},
	}}
	r := explainAccess(t, AccessInput{Intent: set, Witnesses: []AccessWitness{
		witness("network-1", "accept", "tag:b:22", "", ObservedAllowed, changed),
		witness("network-2", "deny", "tag:b:22", "", ObservedAllowed, changed),
		witness("network-3", "accept", "tag:b:22", "", ObservedDenied, changed),
	}})
	for _, id := range []string{"network-1", "network-2", "network-3"} {
		if row := rowOf(r, id); row.Status != AccessUnknown || row.Cells[0].Reason != ReasonLiveChanged || row.Cells[0].Observed != ObservedUnknown {
			t.Errorf("%s on a policy that moved: %+v, want unknown by live_changed", id, row)
		}
	}
	if r.Counts.Unmet != 0 || r.ExitCode() != 1 {
		t.Errorf("counts %+v exit %d: a failure witnessed on a policy that moved must not be unmet, and 8 is for unmet", r.Counts, r.ExitCode())
	}
	if len(r.Blast) != 0 {
		t.Errorf("blast = %+v: nothing is reachable by a policy that is no longer the live one", r.Blast)
	}
}

// Check pairs, unevaluable pairs and not-asked pairs are never met.
func TestAccessCheckUnknownAndNotAsked(t *testing.T) {
	set := IntentSet{SSH: []SSHExpectation{{ID: "ssh-1", Source: "group:example-admins", Destinations: []string{"tag:example-db"}, Check: []string{"root"}, Accept: []string{"ops"}}}}
	r := explainAccess(t, AccessInput{Intent: set, Witnesses: []AccessWitness{
		witness("ssh-1", "check", "tag:example-db", "root", ObservedAllowed, proven()),
		witness("ssh-1", "accept", "tag:example-db", "ops", ObservedAllowed, proven()),
	}})
	res := r.Expectations[0]
	if res.Status != AccessUnknown {
		t.Fatalf("status %s, want unknown: a check user is never a pass", res.Status)
	}
	for _, c := range res.Cells {
		if c.Expect == "check" && (c.Verdict != AccessUnknown || c.Reason != ReasonCheckUser) {
			t.Errorf("check pair = %+v", c)
		}
	}
	r = explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: []AccessWitness{
		{Expectation: "network-1", Cell: AccessCell{Expect: "accept", Destination: "tag:example-db:22"}, Observed: ObservedNotAsked, Reason: ReasonSameSource},
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}})
	if statusOfID(r, "network-1") != AccessNotEvaluated || r.ExitCode() != 1 {
		t.Errorf("a pair not asked is not evaluated: %+v exit %d", r.Counts, r.ExitCode())
	}
}

// Limits: an expectation whose every pair is met and that states a limit is met with limits,
// which is not complete and exits 1; an unmet one stays unmet.
func TestAccessLimitsAreMetWithLimitsNeverComplete(t *testing.T) {
	ws := []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}
	for _, l := range []AccessLimit{LimitPosture, LimitApp, LimitVia, LimitSource, LimitRules} {
		r := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws, Limits: map[string][]AccessLimit{"network-2": {l, l}}})
		if statusOfID(r, "network-2") != AccessMetWithLimits || r.Status != AccessIncomplete || r.ExitCode() != 1 || r.Counts.MetWithLimits != 1 {
			t.Errorf("%s: status %s counts %+v exit %d, want met_with_limits, incomplete, exit 1", l, r.Status, r.Counts, r.ExitCode())
		}
		if got := rowOf(r, "network-2").Limits; LimitSentence(l) == "" || len(got) != 1 || got[0] != l {
			t.Errorf("%s: limits %v (listed once, with a sentence)", l, got)
		}
	}
}

// 8 outranks 1: an unmet row beside unknown ones exits 8; nothing but unknown exits 1; all met 0.
func TestAccessExitCodes(t *testing.T) {
	met := func(id string) AccessWitness { return witness(id, "accept", "tag:b:22", "", ObservedAllowed, proven()) }
	set := IntentSet{Network: []NetworkExpectation{
		{ID: "network-1", Source: "tag:a", Accept: []string{"tag:b:22"}},
		{ID: "network-2", Source: "tag:c", Accept: []string{"tag:b:22"}},
	}}
	cases := []struct {
		name string
		ws   []AccessWitness
		want int
	}{
		{"all met", []AccessWitness{met("network-1"), met("network-2")}, 0},
		{"one unknown", []AccessWitness{met("network-1")}, 1},
		{"one unmet, one met", []AccessWitness{met("network-1"), witness("network-2", "accept", "tag:b:22", "", ObservedDenied, proven())}, 8},
		{"one unmet, one unknown: 8 over 1", []AccessWitness{witness("network-2", "accept", "tag:b:22", "", ObservedDenied, proven())}, 8},
		{"nothing witnessed", nil, 1},
	}
	for _, c := range cases {
		r := explainAccess(t, AccessInput{Intent: set, Witnesses: c.ws})
		if got := r.ExitCode(); got != c.want {
			t.Errorf("%s: exit %d, want %d (%+v)", c.name, got, c.want, r.Counts)
		}
	}
}

func TestAccessNoIntentIsIncompleteWithOneSentence(t *testing.T) {
	for name, in := range map[string]AccessInput{"none": {NoIntent: true}, "empty": {}} {
		r := explainAccess(t, in)
		want := NoteNoIntent
		if name == "empty" {
			want = NoteEmptySet
		}
		if r.Status != AccessIncomplete || r.ExitCode() != 1 || len(r.Notes) != 1 || r.Notes[0] != want || r.NoIntent != (name == "none") {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if NoteNoIntent != "no intent set: nothing explained" {
		t.Errorf("the sentence of a run with no intent set is fixed: %q", NoteNoIntent)
	}
	if _, err := ExplainAccess(AccessInput{NoIntent: true, Intent: adminSet(), EvaluatedAt: accessAt}); err == nil {
		t.Error("an input with no intent set that holds expectations was accepted")
	}
}

// Only the expectations' own pairs are planned, and past the cap they are left out and counted.
func TestPlanAccessIsBoundedAndNeverWidens(t *testing.T) {
	var dsts []string
	for i := 0; i < 100; i++ {
		dsts = append(dsts, fmt.Sprintf("192.0.2.%d:22", i))
	}
	set := IntentSet{Network: []NetworkExpectation{{ID: "network-1", Source: "tag:example-a", Accept: dsts}}}
	plan := PlanAccess(set, 0)
	if len(plan) != 1 || len(plan[0].Cells) != MaxAccessPairs || plan[0].PastCap != 100-MaxAccessPairs {
		t.Fatalf("plan = %d expectations, %d pairs, %d past the cap; want 1, %d and %d", len(plan), len(plan[0].Cells), plan[0].PastCap, MaxAccessPairs, 100-MaxAccessPairs)
	}
	for i, c := range plan[0].Cells {
		if c.Destination != dsts[i] || c.Expect != "accept" || plan[0].Source != "tag:example-a" {
			t.Fatalf("pair %d = %+v: a pair nobody listed", i, c)
		}
	}
	if above := PlanAccess(set, 1000)[0]; len(above.Cells) != MaxAccessPairs || above.PastCap != 100-MaxAccessPairs {
		t.Errorf("a limit of 1000 judged %d pairs and left %d, want the cap of %d and %d", len(above.Cells), above.PastCap, MaxAccessPairs, 100-MaxAccessPairs)
	}
	if cut := PlanAccess(set, 3)[0]; len(cut.Cells) != 3 || cut.PastCap != 97 {
		t.Errorf("a limit of 3 judged %d and left %d", len(cut.Cells), cut.PastCap)
	}
	// Witnesses for the first 64 only; the rest are not evaluated, counted, and not met.
	var ws []AccessWitness
	for _, c := range plan[0].Cells {
		ws = append(ws, witness("network-1", "accept", c.Destination, "", ObservedAllowed, proven()))
	}
	r := explainAccess(t, AccessInput{Intent: set, Witnesses: ws})
	if r.PairsJudged != 64 || r.PairsPastCap != 36 || r.Expectations[0].PastCap != 36 || r.Expectations[0].Status != AccessNotEvaluated || r.ExitCode() != 1 {
		t.Errorf("judged %d past %d status %s exit %d", r.PairsJudged, r.PairsPastCap, r.Expectations[0].Status, r.ExitCode())
	}
	// A witness for a pair past the cap is refused: nothing was asked.
	bad := append(slices.Clone(ws), witness("network-1", "accept", dsts[99], "", ObservedAllowed, proven()))
	if _, err := ExplainAccess(AccessInput{Intent: set, Witnesses: bad, EvaluatedAt: accessAt}); err == nil {
		t.Error("a witness for a pair past the cap was accepted")
	}
}

// An SSH expectation with thousands of destinations and thousands of users names their product,
// and the plan counts it without making it: the memory it takes is that of the lists, not of
// the product. (Ten thousand by ten thousand is a hundred million pairs.)
func TestPlanAccessDoesNotMakeTheProductBeforeTheCap(t *testing.T) {
	const n = 10000
	dsts, users := make([]string, n), make([]string, n)
	for i := range dsts {
		dsts[i], users[i] = fmt.Sprintf("tag:example-%d", i), fmt.Sprintf("user%d", i)
	}
	set := IntentSet{SSH: []SSHExpectation{{ID: "ssh-1", Source: "tag:example-ci", Destinations: dsts, Accept: users}}}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	plan := PlanAccess(set, 0)
	runtime.ReadMemStats(&after)
	if got := after.TotalAlloc - before.TotalAlloc; got > 16<<20 {
		t.Errorf("planning %d x %d pairs allocated %d bytes: the product was made", n, n, got)
	}
	if len(plan) != 1 || len(plan[0].Cells) != MaxAccessPairs || plan[0].PastCap != n*n-MaxAccessPairs {
		t.Fatalf("%d pairs judged and %d past the cap, want %d and %d", len(plan[0].Cells), plan[0].PastCap, MaxAccessPairs, n*n-MaxAccessPairs)
	}
	if c := plan[0].Cells[0]; c.Destination != "tag:example-0" || c.User != "user0" || plan[0].Cells[1].User != "user1" {
		t.Errorf("the first pairs are not the first of the lists, in order: %+v", plan[0].Cells[:2])
	}
	// The same lists with every entry repeated are the same pairs.
	rep := IntentSet{SSH: []SSHExpectation{{ID: "ssh-1", Source: "tag:example-ci", Destinations: slices.Concat(dsts, dsts), Accept: slices.Concat(users, users)}}}
	if p := PlanAccess(rep, 0)[0]; p.PastCap != n*n-MaxAccessPairs {
		t.Errorf("repeated entries counted as pairs: %d past the cap", p.PastCap)
	}
}

// The count of pairs saturates instead of overflowing.
func TestPlanAccessCountsSaturate(t *testing.T) {
	if satMul(math.MaxInt, 2) != math.MaxInt || satMul(0, math.MaxInt) != 0 || satMul(3, 4) != 12 || satMul(math.MaxInt/2+1, 2) != math.MaxInt {
		t.Error("satMul")
	}
	if satAdd(math.MaxInt, 1) != math.MaxInt || satAdd(1, math.MaxInt) != math.MaxInt || satAdd(1, 2) != 3 {
		t.Error("satAdd")
	}
}

// Unmet outranks unknown inside one expectation: a pair that failed is the answer, whatever
// else could not be witnessed.
func TestAccessUnmetOutranksUnknownInOneExpectation(t *testing.T) {
	set := IntentSet{SSH: []SSHExpectation{{ID: "ssh-1", Source: "tag:example-ci", Destinations: []string{"tag:example-a"}, Accept: []string{"deploy", "ops"}}}}
	r := explainAccess(t, AccessInput{Intent: set, Witnesses: []AccessWitness{
		witness("ssh-1", "accept", "tag:example-a", "deploy", ObservedDenied, proven()),
		witness("ssh-1", "accept", "tag:example-a", "ops", ObservedUnknown, proven()),
	}})
	if statusOfID(r, "ssh-1") != AccessUnmet || r.ExitCode() != 8 {
		t.Errorf("status %s exit %d, want unmet and 8", statusOfID(r, "ssh-1"), r.ExitCode())
	}
}

func TestPlanAccessPairsOfAnSSHExpectation(t *testing.T) {
	set := IntentSet{SSH: []SSHExpectation{{ID: "ssh-1", Source: "tag:example-ci", Destinations: []string{"tag:example-a", "tag:example-b"}, Accept: []string{"deploy"}, Deny: []string{"root", "deploy"}, Check: []string{"ops"}}}}
	cells := PlanAccess(set, 0)[0].Cells
	want := []AccessCell{
		{"accept", "tag:example-a", "deploy"}, {"accept", "tag:example-b", "deploy"},
		{"check", "tag:example-a", "ops"}, {"check", "tag:example-b", "ops"},
		{"deny", "tag:example-a", "root"}, {"deny", "tag:example-a", "deploy"},
		{"deny", "tag:example-b", "root"}, {"deny", "tag:example-b", "deploy"},
	}
	if !reflect.DeepEqual(cells, want) {
		t.Errorf("pairs = %v, want %v", cells, want)
	}
	dup := IntentSet{Network: []NetworkExpectation{{ID: "network-1", Source: "tag:a", Accept: []string{"tag:b:1", "tag:b:1"}}}}
	if n := len(PlanAccess(dup, 0)[0].Cells); n != 1 {
		t.Errorf("a pair listed twice is %d pairs", n)
	}
}

// Candidates are capped per expectation, with the rest counted; a broad candidate is named by
// the blast radius; tags come from the owners; and none of it changes a verdict.
func TestAccessCandidatesBlastAndTagOwnership(t *testing.T) {
	var refs []RuleRef
	for i := 1; i <= 12; i++ {
		refs = append(refs, RuleRef{Section: "acls", Index: i, Line: i * 3, Column: 5, Source: "tag:example-web", Destination: "tag:example-db"})
	}
	broad := RuleRef{Section: "grants", Index: 2, Line: 40, Column: 5, Source: "*", Destination: "*", Broad: true, AllTraffic: true}
	refs = append([]RuleRef{broad}, refs...)
	ws := []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}
	owners := []AccessOwner{{Source: "tag:example-web", Tags: []string{"tag:example-x"}}, {Source: "nobody@example.com", Tags: []string{"tag:no"}}}
	with := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws, Candidates: map[string]AccessCandidates{"network-2": {Rules: refs}}, Owners: owners})
	without := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws})
	if with.Counts != without.Counts || with.ExitCode() != without.ExitCode() || with.Status != without.Status {
		t.Errorf("candidate rules changed a verdict: %+v vs %+v", with.Counts, without.Counts)
	}
	var web AccessResult
	for _, e := range with.Expectations {
		if e.ID == "network-2" {
			web = e
		}
	}
	if len(web.Candidates) != MaxAccessCandidates || web.CandidatesOmitted != 13-MaxAccessCandidates {
		t.Errorf("candidates %d omitted %d, want %d and %d", len(web.Candidates), web.CandidatesOmitted, MaxAccessCandidates, 13-MaxAccessCandidates)
	}
	blast := blastOf(with, "tag:example-web")
	if blast == nil || len(blast.Broad) != 1 || blast.Broad[0] != broad || !reflect.DeepEqual(blast.Tags, []string{"tag:example-x"}) || blast.Heading != BlastHeading("tag:example-web") {
		t.Fatalf("blast = %+v, want the broad grant, the tag and the heading", blast)
	}
	if len(blast.Reaches) != 0 {
		t.Errorf("reaches = %+v: a met deny reaches nothing", blast.Reaches)
	}
	if len(with.Blast) != 2 || blastOf(with, "nobody@example.com") != nil {
		t.Errorf("blast = %+v: the admins (an accepted pair, met) and the web tier (a broad rule, a tag); an owner of no selected source is not listed", with.Blast)
	}
}

// The blast radius names a broad candidate only when it is a plain network rule: one with
// srcPosture, app capabilities or via, or an ssh rule, is a candidate and no more; and the note
// that a list of candidates may be incomplete is said once, beside the notes about candidates.
func TestBlastNamesOnlyAPlainNetworkRuleAndNotesSayCandidatesMayBeShort(t *testing.T) {
	plain := RuleRef{Section: "acls", Index: 1, Source: "*", Destination: "*", Broad: true, AllTraffic: true}
	cases := map[string]RuleRef{
		"qualified": {Section: "grants", Index: 2, Source: "*", Destination: "*", Broad: true, AllTraffic: true, Qualified: true},
		"ssh":       {Section: "ssh", Index: 1, Source: "*", Destination: "*", Broad: true, AllTraffic: true},
	}
	ws := []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}
	for name, ref := range cases {
		r := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws, Candidates: map[string]AccessCandidates{"network-2": {Rules: []RuleRef{ref, plain}}}})
		blast := blastOf(r, "tag:example-web")
		if blast == nil || len(blast.Broad) != 1 || blast.Broad[0] != plain {
			t.Errorf("%s: blast = %+v, want only the plain network rule", name, blast)
		}
		only := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws, Candidates: map[string]AccessCandidates{"network-2": {Rules: []RuleRef{ref}}}})
		if b := blastOf(only, "tag:example-web"); b != nil && len(b.Broad) != 0 {
			t.Errorf("%s: blast = %+v: a rule that is not plain was named as granting every destination", name, b)
		}
		for _, e := range only.Expectations {
			if e.ID == "network-2" && len(e.Candidates) != 1 {
				t.Errorf("%s: the candidate itself must still be listed: %+v", name, e.Candidates)
			}
		}
	}
	bad := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws, Candidates: map[string]AccessCandidates{"network-2": {Rules: []RuleRef{plain}}}})
	bad.Blast = []AccessBlast{{Source: "tag:example-web", Heading: BlastHeading("tag:example-web"), Broad: []RuleRef{cases["qualified"]}}}
	if err := ValidateAccessReport(bad); err == nil || !strings.Contains(err.Error(), "plain network rule") {
		t.Errorf("a blast radius that names a qualified rule as granting everything: err = %v", err)
	}
	with := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws, Candidates: map[string]AccessCandidates{"network-2": {Rules: []RuleRef{plain}}}})
	count := func(r AccessReport, note string) int {
		n := 0
		for _, x := range r.Notes {
			if x == note {
				n++
			}
		}
		return n
	}
	if count(with, NoteCandidates) != 1 || count(with, NoteCandidatesShort) != 1 {
		t.Errorf("notes = %q, want both candidate notes, once each", with.Notes)
	}
	if without := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws}); count(without, NoteCandidatesShort) != 0 {
		t.Errorf("notes = %q: a report with no candidate list has nothing to call incomplete", without.Notes)
	}
	if NoteCandidatesShort != "A list of candidate rules may be incomplete: the protocol of a rule is ignored, and autogroup:member and localpart: selectors are not resolved." {
		t.Errorf("the sentence is fixed: %q", NoteCandidatesShort)
	}
}

// A plain rule for * is named by the blast radius with its traffic: every port and protocol, or
// what the rule writes. One whose traffic is unknown is a candidate and is not named, and the
// validator refuses a blast radius that names it, or a rule that is both unlimited and limited.
func TestBlastNamesARuleForEveryDestinationOnlyWithItsTraffic(t *testing.T) {
	ws := []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}
	base := RuleRef{Section: "acls", Index: 1, Line: 3, Column: 5, Source: "*", Destination: "*", Broad: true}
	all, limited, unknown := base, base, base
	all.AllTraffic = true
	limited.Traffic = "ports 22"
	report := func(ref RuleRef) AccessReport {
		return explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws, Candidates: map[string]AccessCandidates{"network-2": {Rules: []RuleRef{ref}}}})
	}
	for name, c := range map[string]struct {
		ref   RuleRef
		named bool
	}{"every port and protocol": {all, true}, "a limit the rule writes": {limited, true}, "nothing to quote": {unknown, false}} {
		r := report(c.ref)
		blast := blastOf(r, "tag:example-web")
		if c.named && (blast == nil || len(blast.Broad) != 1 || blast.Broad[0] != c.ref) {
			t.Errorf("%s: blast = %+v, want the rule named as it is", name, blast)
		}
		if !c.named && blast != nil && len(blast.Broad) != 0 {
			t.Errorf("%s: blast = %+v: a rule with no traffic to state was named", name, blast)
		}
		for _, e := range r.Expectations {
			if e.ID == "network-2" && len(e.Candidates) != 1 {
				t.Errorf("%s: the candidate itself is still listed: %+v", name, e.Candidates)
			}
		}
		if err := ValidateAccessReport(r); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	refuse := func(name string, ref RuleRef, want string) {
		t.Helper()
		bad := report(all)
		bad.Blast = []AccessBlast{{Source: "tag:example-web", Heading: BlastHeading("tag:example-web"), Broad: []RuleRef{ref}}}
		if err := ValidateAccessReport(bad); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want one saying %q", name, err, want)
		}
	}
	refuse("a broad rule with no traffic", unknown, "its traffic")
	both := all
	both.Traffic = "ports 22"
	refuse("a rule that allows everything and is limited", both, "also lists a limit")
	long := limited
	long.Traffic = strings.Repeat("x", MaxTextBytes+1)
	refuse("traffic past the limit", long, "past the limit")
}

// The validator reads the destination itself, and not the flag that says it is *: a broad rule of
// a blast radius whose destination is another is refused, and so is a candidate whose flag and
// destination disagree, and one that is both unlimited and limited.
func TestTheBlastValidatorReadsTheDestinationAndNotTheBroadFlag(t *testing.T) {
	ws := []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}
	good := RuleRef{Section: "acls", Index: 1, Line: 3, Column: 5, Source: "*", Destination: "*", Broad: true, AllTraffic: true}
	report := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws, Candidates: map[string]AccessCandidates{"network-2": {Rules: []RuleRef{good}}}})
	if err := ValidateAccessReport(report); err != nil {
		t.Fatalf("the control: %v", err)
	}
	named := func(ref RuleRef) AccessReport {
		bad := report
		bad.Blast = []AccessBlast{{Source: "tag:example-web", Heading: BlastHeading("tag:example-web"), Broad: []RuleRef{ref}}}
		return bad
	}
	// A rule whose destination is another and whose flag says so, and one whose flag says * over
	// another destination: the second is refused by the flag check, the first by the destination.
	elsewhere, lying := good, good
	elsewhere.Destination, elsewhere.Broad = "tag:example-db", false
	lying.Destination = "tag:example-db"
	if err := ValidateAccessReport(named(elsewhere)); err == nil || !strings.Contains(err.Error(), "destination *") {
		t.Errorf("a broad rule whose destination is a tag: err = %v", err)
	}
	if err := ValidateAccessReport(named(lying)); err == nil {
		t.Error("a broad rule whose destination is a tag and whose flag says *: accepted")
	}
	both, neither := good, good
	both.Traffic = "ports 22"
	neither.AllTraffic = false
	for name, ref := range map[string]RuleRef{"a rule that is unlimited and limited": both, "a rule with no traffic at all": neither} {
		if err := ValidateAccessReport(named(ref)); err == nil {
			t.Errorf("%s was accepted as a broad rule of a blast radius", name)
		}
	}
	// A candidate whose broad flag and destination disagree is refused wherever it is listed.
	flagOnly, destinationOnly := good, good
	flagOnly.Destination = "tag:example-db"
	destinationOnly.Broad = false
	for name, ref := range map[string]RuleRef{"the flag without the destination": flagOnly, "the destination without the flag": destinationOnly} {
		_, err := ExplainAccess(AccessInput{Intent: adminSet(), Witnesses: ws, EvaluatedAt: accessAt, Candidates: map[string]AccessCandidates{"network-2": {Rules: []RuleRef{ref}}}})
		if err == nil || !strings.Contains(err.Error(), "broad flag") {
			t.Errorf("%s: err = %v, want a refusal that names the broad flag", name, err)
		}
		bad := report
		bad.Expectations = slices.Clone(report.Expectations)
		for i := range bad.Expectations {
			if bad.Expectations[i].ID == "network-2" {
				bad.Expectations[i].Candidates = []RuleRef{ref}
			}
		}
		if err := ValidateAccessReport(bad); err == nil || !strings.Contains(err.Error(), "broad flag") {
			t.Errorf("%s: a report that lists it: err = %v", name, err)
		}
	}
}

func TestBlastHeadingIsTheFixedWording(t *testing.T) {
	if got := BlastHeading("tag:example-web"); got != "if tag:example-web were compromised, the live policy would let it reach:" {
		t.Errorf("heading = %q", got)
	}
}

// Reaches are only pairs witnessed as allowed under proof, and an SSH pair and a network pair
// to the same destination are two reaches.
func TestAccessBlastReachesOnlyWitnessedAllowed(t *testing.T) {
	set := IntentSet{
		Network: []NetworkExpectation{{ID: "network-1", Source: "group:example-admins", Accept: []string{"tag:example-db:22", "tag:example-db:5432"}, Deny: []string{"tag:example-vault:22"}}},
		SSH:     []SSHExpectation{{ID: "ssh-1", Source: "group:example-admins", Destinations: []string{"tag:example-db"}, Accept: []string{"ops"}}},
	}
	r := explainAccess(t, AccessInput{Intent: set, Witnesses: []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-1", "accept", "tag:example-db:5432", "", ObservedDenied, proven()),
		witness("network-1", "deny", "tag:example-vault:22", "", ObservedAllowed, proven()),
		witness("ssh-1", "accept", "tag:example-db", "ops", ObservedAllowed, proven()),
	}})
	if len(r.Blast) != 1 {
		t.Fatalf("blast = %+v", r.Blast)
	}
	var got []string
	for _, x := range r.Blast[0].Reaches {
		got = append(got, string(x.Kind)+" "+x.Destination+" "+x.User)
	}
	want := []string{"network tag:example-db:22 ", "network tag:example-vault:22 ", "ssh tag:example-db ops"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("reaches = %q, want %q (the denied pair is not one)", got, want)
	}
	found := false
	for _, n := range r.Notes {
		found = found || n == NoteSSHNotNetwork
	}
	if !found || strings.Count(strings.Join(r.Notes, "|"), NoteSSHNotNetwork) != 1 {
		t.Errorf("notes = %q, want the SSH-is-not-network sentence once", r.Notes)
	}
}

// Rows are ordered by what needs attention and cut at MaxAccessRows; the counts cover all.
func TestAccessRowsAreOrderedAndCut(t *testing.T) {
	var set IntentSet
	var ws []AccessWitness
	for i := 1; i <= 130; i++ {
		id := fmt.Sprintf("network-%d", i)
		set.Network = append(set.Network, NetworkExpectation{ID: id, Source: "tag:example-a", Accept: []string{fmt.Sprintf("192.0.2.1:%d", i)}})
		obs := ObservedAllowed
		if i == 130 {
			obs = ObservedDenied
		}
		if i <= MaxAccessPairs {
			ws = append(ws, witness(id, "accept", fmt.Sprintf("192.0.2.1:%d", i), "", obs, proven()))
		}
	}
	ws[len(ws)-1] = witness("network-64", "accept", "192.0.2.1:64", "", ObservedDenied, proven())
	r := explainAccess(t, AccessInput{Intent: set, Witnesses: ws})
	if len(r.Expectations) != MaxAccessRows || r.Omitted != 30 || r.Counts.Total != 130 {
		t.Fatalf("listed %d omitted %d total %d", len(r.Expectations), r.Omitted, r.Counts.Total)
	}
	if r.Expectations[0].ID != "network-64" || r.Expectations[0].Status != AccessUnmet || r.ExitCode() != 8 {
		t.Errorf("first row = %+v: the unmet one comes first and the exit code counts all", r.Expectations[0])
	}
	if r.Counts.Unmet != 1 || r.Counts.Met != 63 || r.Counts.NotEvaluated != 66 {
		t.Errorf("counts = %+v", r.Counts)
	}
}

// ExplainAccess refuses what is not evidence.
func TestExplainAccessRefusesInputItCannotTie(t *testing.T) {
	ok := witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven())
	cases := map[string]AccessInput{
		"a witness for an expectation that is not selected": {Intent: adminSet(), Witnesses: []AccessWitness{witness("network-9", "accept", "tag:example-db:22", "", ObservedAllowed, proven())}},
		"a witness for a pair nobody asked":                 {Intent: adminSet(), Witnesses: []AccessWitness{witness("network-1", "accept", "tag:example-other:22", "", ObservedAllowed, proven())}},
		"a witness twice":                                   {Intent: adminSet(), Witnesses: []AccessWitness{ok, ok}},
		"a witness with an observation outside the set":     {Intent: adminSet(), Witnesses: []AccessWitness{witness("network-1", "accept", "tag:example-db:22", "", "granted", proven())}},
		"a reason outside the set":                          {Intent: adminSet(), Witnesses: []AccessWitness{{Expectation: "network-1", Cell: ok.Cell, Observed: ObservedUnknown, Reason: "because Tailscale said so"}}},
		"candidates for an expectation not selected":        {Intent: adminSet(), Candidates: map[string]AccessCandidates{"network-7": {}}},
		"a candidate in no section":                         {Intent: adminSet(), Candidates: map[string]AccessCandidates{"network-1": {Rules: []RuleRef{{Section: "tests", Index: 1}}}}},
		"a limit outside the set":                           {Intent: adminSet(), Limits: map[string][]AccessLimit{"network-1": {"hope"}}},
		"limits for an expectation not selected":            {Intent: adminSet(), Limits: map[string][]AccessLimit{"ssh-1": {LimitApp}}},
	}
	for name, in := range cases {
		in.EvaluatedAt = accessAt
		if _, err := ExplainAccess(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The validator refuses a report that claims met without a canary: whoever made the report.
func TestExplainAccessValidatorRefusesUnprovenMet(t *testing.T) {
	good := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}})
	if err := ValidateAccessReport(good); err != nil {
		t.Fatalf("a good report was refused: %v", err)
	}
	mutate := func(f func(r *AccessReport)) AccessReport {
		r := good
		r.Expectations = slices.Clone(good.Expectations)
		for i := range r.Expectations {
			r.Expectations[i].Cells = slices.Clone(good.Expectations[i].Cells)
		}
		r.Blast = slices.Clone(good.Blast)
		r.Notes = slices.Clone(good.Notes)
		f(&r)
		return r
	}
	limited := explainAccess(t, AccessInput{Intent: adminSet(), Limits: map[string][]AccessLimit{"network-1": {LimitApp}}, Witnesses: []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}})
	if err := ValidateAccessReport(limited); err != nil {
		t.Fatalf("a report with a limit was refused: %v", err)
	}
	limited.Status = AccessComplete
	if err := ValidateAccessReport(limited); err == nil || !strings.Contains(err.Error(), "complete beside a row that is not met") {
		t.Errorf("complete beside a met_with_limits row: err = %v", err)
	}
	cases := map[string]struct {
		mod  func(r *AccessReport)
		want string
	}{
		"a met pair with no canary":                           {func(r *AccessReport) { r.Expectations[0].Cells[0].Proof.Canary = false }, "without a canary"},
		"a met pair with the live policy not shown unchanged": {func(r *AccessReport) { r.Expectations[0].Cells[0].Proof.LiveUnchanged = false }, "unchanged"},
		"an unmet pair with no canary": {func(r *AccessReport) {
			c := &r.Expectations[0].Cells[0]
			c.Verdict, c.Observed, c.Proof = AccessUnmet, ObservedDenied, AccessProof{LiveUnchanged: true}
		}, "without a canary"},
		"an unmet pair with the live policy not shown unchanged": {func(r *AccessReport) {
			c := &r.Expectations[0].Cells[0]
			c.Verdict, c.Observed, c.Proof = AccessUnmet, ObservedDenied, AccessProof{Canary: true}
		}, "without the live policy shown unchanged"},
		"a complete report that carries no proof":        {func(r *AccessReport) { r.Proof = AccessProof{} }, "without the proof"},
		"a complete report whose proof lacks the canary": {func(r *AccessReport) { r.Proof = AccessProof{LiveUnchanged: true} }, "without the proof"},
		"a met expectation with an unknown pair": {func(r *AccessReport) {
			c := &r.Expectations[0].Cells[0]
			c.Verdict, c.Reason = AccessUnknown, ReasonCanary
		}, "met without every pair met"},
		"a met expectation beside a limit": {func(r *AccessReport) { r.Expectations[0].Limits = []AccessLimit{LimitApp} }, "beside a limit"},
		"met_with_limits with no limit":    {func(r *AccessReport) { r.Expectations[0].Status = AccessMetWithLimits }, "no limit"},
		"complete beside a row that is not met": {func(r *AccessReport) {
			r.Expectations[0].Status = AccessUnknown
			r.Counts.Met, r.Counts.Unknown = 1, 1
		}, "no pair unknown"},
		"complete with the counts of an incomplete report": {func(r *AccessReport) {
			r.Counts.Met, r.Counts.Unknown = 1, 1
		}, "below the rows it lists"},
		"incomplete with every row met":                        {func(r *AccessReport) { r.Status = AccessIncomplete }, "incomplete with every row met"},
		"a met verdict that disagrees with what was witnessed": {func(r *AccessReport) { r.Expectations[0].Cells[0].Observed = ObservedDenied }, "disagrees"},
		"a reach no witnessed pair shows": {func(r *AccessReport) {
			r.Blast = []AccessBlast{{Source: "tag:example-web", Heading: BlastHeading("tag:example-web"), Reaches: []AccessReach{{Kind: AccessNetwork, Destination: "tag:example-db:22", Expectation: "network-2"}}}}
		}, "no witnessed pair"},
		"a heading in other words": {func(r *AccessReport) {
			r.Blast = []AccessBlast{{Source: "tag:example-web", Heading: "tag:example-web can reach:"}}
		}, "fixed words"},
		"a status outside the set": {func(r *AccessReport) { r.Expectations[0].Status = "mostly_met" }, "outside the closed set"},
		"a reason outside the set": {func(r *AccessReport) { r.Expectations[0].Cells[0].Reason = "Tailscale said so" }, "closed set"},
		"an unknown pair with no reason": {func(r *AccessReport) {
			c := &r.Expectations[0].Cells[0]
			c.Verdict, c.Reason = AccessUnknown, ""
		}, "no reason"},
		"no schema version": {func(r *AccessReport) { r.SchemaVersion = 0 }, "schema"},
		"a report that explains nothing and is complete": {func(r *AccessReport) { *r = AccessReport{SchemaVersion: SchemaVersion, Status: AccessComplete} }, "incomplete"},
	}
	for name, c := range cases {
		err := ValidateAccessReport(mutate(c.mod))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one naming %q", name, err, c.want)
		}
	}
}

// The proof is in the report itself, whether or not rows are omitted: a report that counts a met
// expectation, or is complete, without it is refused, however the rows were cut.
func TestAccessValidatorNeedsTheProofInTheReportWhenRowsAreOmitted(t *testing.T) {
	complete := AccessReport{SchemaVersion: SchemaVersion, Status: AccessComplete, EvaluatedAt: accessAt, Counts: AccessCounts{Total: 1, Met: 1}, Omitted: 1}
	if err := ValidateAccessReport(complete); err == nil || !strings.Contains(err.Error(), "proof") {
		t.Errorf("complete, one met row omitted, no proof and no rows: err = %v", err)
	}
	proved := complete
	proved.Proof = proven()
	if err := ValidateAccessReport(proved); err != nil {
		t.Errorf("the same report carrying the proof was refused: %v", err)
	}
	half := complete
	half.Proof = AccessProof{Canary: true}
	if err := ValidateAccessReport(half); err == nil {
		t.Error("a proof without the unchanged live policy was accepted")
	}
	mixed := AccessReport{SchemaVersion: SchemaVersion, Status: AccessIncomplete, EvaluatedAt: accessAt, Counts: AccessCounts{Total: 2, Met: 1, Unknown: 1}, Omitted: 2}
	if err := ValidateAccessReport(mixed); err == nil || !strings.Contains(err.Error(), "proof") {
		t.Errorf("a met row among omitted ones, no proof: err = %v", err)
	}
	limited := AccessReport{SchemaVersion: SchemaVersion, Status: AccessIncomplete, EvaluatedAt: accessAt, Counts: AccessCounts{Total: 1, MetWithLimits: 1}, Omitted: 1}
	if err := ValidateAccessReport(limited); err == nil || !strings.Contains(err.Error(), "proof") {
		t.Errorf("a row met with limits, omitted, no proof: err = %v", err)
	}
	unknown := AccessReport{SchemaVersion: SchemaVersion, Status: AccessIncomplete, EvaluatedAt: accessAt, Counts: AccessCounts{Total: 1, Unknown: 1}, Omitted: 1}
	if err := ValidateAccessReport(unknown); err != nil {
		t.Errorf("a report with nothing met needs no proof: %v", err)
	}
	// What ExplainAccess makes carries the proof only when something is met and all of it is proven.
	r := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}})
	if r.Proof != proven() {
		t.Errorf("proof = %+v, want the canary and the unchanged live policy", r.Proof)
	}
	none := explainAccess(t, AccessInput{Intent: adminSet()})
	if none.Proof != (AccessProof{}) {
		t.Errorf("proof = %+v for a report with nothing met", none.Proof)
	}
}

// A report that is complete, and so exits 0, has no pair past the cap, whether or not rows are
// omitted: an omitted row is counted met, and a met row has every pair judged. The pair counts
// cannot be reconciled with rows that are not listed, but they cannot fall below the rows that are.
func TestACompleteReportHasNoPairPastTheCapWhateverRowsAreOmitted(t *testing.T) {
	complete := AccessReport{SchemaVersion: SchemaVersion, Status: AccessComplete, EvaluatedAt: accessAt, Counts: AccessCounts{Total: 1, Met: 1}, Omitted: 1, Proof: proven()}
	if err := ValidateAccessReport(complete); err != nil {
		t.Fatalf("the control: %v", err)
	}
	past := complete
	past.PairsPastCap = 1
	if err := ValidateAccessReport(past); err == nil || !strings.Contains(err.Error(), "past the cap") {
		t.Errorf("complete, one met row omitted, one pair past the cap: err = %v, want a refusal", err)
	}
	if past.ExitCode() != 0 {
		t.Fatalf("exit code = %d: a complete report exits 0, which is what the refusal is for", past.ExitCode())
	}
	// With nothing omitted the rows say the same, and the pair counts are checked against them.
	listed := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}})
	if listed.Status != AccessComplete || listed.PairsPastCap != 0 {
		t.Fatalf("the control: status %q, %d pairs past the cap", listed.Status, listed.PairsPastCap)
	}
	listed.PairsPastCap = 1
	if err := ValidateAccessReport(listed); err == nil {
		t.Error("complete, every row listed, one pair past the cap: accepted")
	}
	// A report that is not complete may count them, with rows omitted too.
	incomplete := AccessReport{SchemaVersion: SchemaVersion, Status: AccessIncomplete, EvaluatedAt: accessAt, Counts: AccessCounts{Total: 1, NotEvaluated: 1}, Omitted: 1, PairsPastCap: 1}
	if err := ValidateAccessReport(incomplete); err != nil {
		t.Errorf("incomplete, one row omitted, one pair past the cap: %v", err)
	}
}

// With rows omitted the pair counts include the omitted rows, so they are at least those of the
// rows that are listed: a count below them is refused, and a count above them is not.
func TestThePairCountsOfAReportWithOmittedRowsAreNotBelowItsListedRows(t *testing.T) {
	// 200 expectations, 64 pairs judged: the first ten are unknown (no witness) and listed first, then
	// the 136 not evaluated, of which 90 are listed, and the 54 met are omitted.
	var set IntentSet
	var ws []AccessWitness
	for i := 1; i <= 200; i++ {
		id := fmt.Sprintf("network-%d", i)
		set.Network = append(set.Network, NetworkExpectation{ID: id, Source: "tag:example-a", Accept: []string{fmt.Sprintf("192.0.2.1:%d", i)}})
		if i > 10 && i <= MaxAccessPairs {
			ws = append(ws, witness(id, "accept", fmt.Sprintf("192.0.2.1:%d", i), "", ObservedAllowed, proven()))
		}
	}
	r := explainAccess(t, AccessInput{Intent: set, Witnesses: ws})
	judged, past := 0, 0
	for _, e := range r.Expectations {
		judged += len(e.Cells)
		past += e.PastCap
	}
	if r.Omitted == 0 || judged == 0 || r.PairsJudged <= judged || past == 0 || r.PairsPastCap <= past {
		t.Fatalf("the control: %d omitted, %d/%d pairs judged, %d/%d past the cap in the rows listed", r.Omitted, judged, r.PairsJudged, past, r.PairsPastCap)
	}
	if err := ValidateAccessReport(r); err != nil {
		t.Fatalf("the control: %v", err)
	}
	for name, change := range map[string]func(*AccessReport){
		"fewer pairs judged than the rows list":       func(x *AccessReport) { x.PairsJudged = judged - 1 },
		"fewer pairs past the cap than the rows list": func(x *AccessReport) { x.PairsPastCap = past - 1 },
	} {
		bad := r
		change(&bad)
		if err := ValidateAccessReport(bad); err == nil || !strings.Contains(err.Error(), "pair counts") {
			t.Errorf("%s: err = %v, want a refusal", name, err)
		}
	}
	more := r
	more.PairsJudged, more.PairsPastCap = MaxAccessPairs, r.PairsPastCap+1
	if err := ValidateAccessReport(more); err != nil {
		t.Errorf("more pairs than the rows list, rows omitted: %v", err)
	}
	// With every row listed the counts are those of the rows, above them as well as below.
	whole := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: []AccessWitness{witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven())}})
	if whole.Omitted != 0 || whole.Status != AccessIncomplete || whole.PairsJudged == 0 {
		t.Fatalf("the control: %d omitted, status %q, %d pairs judged", whole.Omitted, whole.Status, whole.PairsJudged)
	}
	for name, change := range map[string]func(*AccessReport){
		"more pairs judged than the rows list":       func(x *AccessReport) { x.PairsJudged++ },
		"more pairs past the cap than the rows list": func(x *AccessReport) { x.PairsPastCap++ },
	} {
		bad := whole
		change(&bad)
		if err := ValidateAccessReport(bad); err == nil || !strings.Contains(err.Error(), "differ from its rows") {
			t.Errorf("%s, every row listed: err = %v, want a refusal", name, err)
		}
	}
}

// The posture limit says what sets a posture-gated rule aside, and that is both things for an SSH
// expectation: a rule is also set aside when it is about other users, not other destinations alone.
// The fixed sentences are the ones the documentation states, word for word.
func TestThePostureLimitNamesOtherUsersAndEverySentenceIsInTheDocs(t *testing.T) {
	if got := LimitSentence(LimitPosture); !strings.Contains(got, "other destinations") || !strings.Contains(got, "SSH expectation") || !strings.Contains(got, "other users") {
		t.Errorf("the posture sentence %q must name other destinations and, for an SSH expectation, other users", got)
	}
	docs, err := os.ReadFile("../../docs/security/access-explanations.md")
	if err != nil {
		t.Fatal(err)
	}
	for limit, sentence := range limitSentences {
		if !strings.Contains(string(docs), "| `"+string(limit)+"` |") || !strings.Contains(string(docs), "| "+sentence+" |") {
			t.Errorf("the documentation does not state the sentence of the %s limit in its table: %q", limit, sentence)
		}
	}
}

// The report owns its data: changing the input afterwards leaves it as it was.
func TestExplainAccessOwnsItsData(t *testing.T) {
	cands := []RuleRef{{Section: "acls", Index: 1, Source: "tag:a", Destination: "tag:b"}}
	limits := []AccessLimit{LimitApp}
	in := AccessInput{Intent: adminSet(), Candidates: map[string]AccessCandidates{"network-1": {Rules: cands}}, Limits: map[string][]AccessLimit{"network-1": limits}}
	r := explainAccess(t, in)
	cands[0].Section, limits[0] = "ssh", LimitVia
	for _, e := range r.Expectations {
		if e.ID == "network-1" && (e.Candidates[0].Section != "acls" || e.Limits[0] != LimitApp) {
			t.Errorf("the report followed a change of its input: %+v", e)
		}
	}
}

// Every reason and limit has a sentence, and none of them holds a word of the intent.
func TestAccessSentencesAreClosed(t *testing.T) {
	for _, r := range []AccessReason{ReasonNoWitness, ReasonCanary, ReasonLiveChanged, ReasonUnparseable, ReasonUnresolved, ReasonUnpaired, ReasonDisagree,
		ReasonRateLimited, ReasonRequestFailed, ReasonRefused, ReasonLiveErrors, ReasonLiveUnreadable, ReasonSameSource, ReasonCheckUser, ReasonPastCap, ReasonNotRecorded, ReasonCanaryCoordinates} {
		if ReasonSentence(r) == "" {
			t.Errorf("reason %s has no sentence", r)
		}
	}
	if len(reasonSentences) != 17 || len(limitSentences) != 5 {
		t.Errorf("%d reasons and %d limits: a new one needs its test", len(reasonSentences), len(limitSentences))
	}
	if ReasonSentence("other") != "" || LimitSentence("other") != "" {
		t.Error("a word outside the sets has a sentence")
	}
}

// A candidate states every destination by its destination, not by the flag that says it, and by
// exactly one of AllTraffic and Traffic.
func TestStatesEveryDestinationReadsTheDestinationAndTheTraffic(t *testing.T) {
	base := RuleRef{Section: "acls", Index: 1, Destination: "*", Broad: true, AllTraffic: true}
	with := func(f func(*RuleRef)) RuleRef { r := base; f(&r); return r }
	for name, c := range map[string]struct {
		ref  RuleRef
		want bool
	}{
		"every port and protocol":            {base, true},
		"a limit the rule writes":            {with(func(r *RuleRef) { r.AllTraffic, r.Traffic = false, "ports 22" }), true},
		"the flag over another destination":  {with(func(r *RuleRef) { r.Destination = "tag:example-db" }), false},
		"the destination * without the flag": {with(func(r *RuleRef) { r.Broad = false }), true},
		"no traffic":                         {with(func(r *RuleRef) { r.AllTraffic = false }), false},
		"unlimited and limited":              {with(func(r *RuleRef) { r.Traffic = "ports 22" }), false},
		"qualified":                          {with(func(r *RuleRef) { r.Qualified = true }), false},
		"an ssh rule":                        {with(func(r *RuleRef) { r.Section = "ssh" }), false},
	} {
		if got := c.ref.statesEveryDestination(); got != c.want {
			t.Errorf("%s: statesEveryDestination = %v, want %v", name, got, c.want)
		}
	}
}

// A reach proves the blast radius of the source of the expectation that was witnessed to allow it,
// and of no other: a blast radius whose source is changed (and whose heading with it) keeps the
// reaches of another and is refused.
func TestABlastReachProvesOnlyTheBlastOfItsOwnSource(t *testing.T) {
	ws := []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}
	report := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws})
	admins := blastOf(report, "group:example-admins")
	if admins == nil || len(admins.Reaches) != 1 || admins.Reaches[0].Expectation != "network-1" {
		t.Fatalf("the control: blast = %+v", report.Blast)
	}
	if err := ValidateAccessReport(report); err != nil {
		t.Fatalf("the control: %v", err)
	}
	moved := report
	moved.Blast = []AccessBlast{*admins}
	moved.Blast[0].Source = "tag:example-web"
	moved.Blast[0].Heading = BlastHeading("tag:example-web")
	if err := ValidateAccessReport(moved); err == nil || !strings.Contains(err.Error(), "no witnessed pair") {
		t.Errorf("the reach of the admins named in the blast radius of the web tier: err = %v", err)
	}
	// A reach that names a row left out cannot be checked against the rows, and the same report
	// passes the part that needs every row.
	moved.Omitted = 1
	moved.Expectations = []AccessResult{rowOf(report, "network-2")}
	if err := validateAccessBlast(moved); err != nil {
		t.Errorf("a report whose rows left out include the one the reach names: %v", err)
	}
}

// With rows left out, a reach that names a row that is listed is still checked against it: the row
// is the proof, and the reach belongs to the blast radius of the row's source, to the destination
// and the user of a pair of the row that was witnessed to allow it, and to no other. Only a reach
// that names a row that is not listed cannot be checked.
func TestAReachNamingAListedRowIsCheckedWhenRowsAreOmitted(t *testing.T) {
	ws := []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}
	report := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws})
	admins := blastOf(report, "group:example-admins")
	if admins == nil || len(admins.Reaches) != 1 || admins.Reaches[0].Expectation != "network-1" {
		t.Fatalf("the control: blast = %+v", report.Blast)
	}
	// Rows B (network-2) left out, A (network-1) listed.
	trimmed := report
	trimmed.Omitted = 1
	trimmed.Expectations = []AccessResult{rowOf(report, "network-1")}
	trimmed.Blast = []AccessBlast{*admins}
	if err := validateAccessBlast(trimmed); err != nil {
		t.Fatalf("the control, with a row left out: %v", err)
	}
	// The reach of A moved to the blast radius of B's source, in a report that lists only A.
	moved := trimmed
	moved.Blast = []AccessBlast{*admins}
	moved.Blast[0].Source = "tag:example-web"
	moved.Blast[0].Heading = BlastHeading("tag:example-web")
	if err := validateAccessBlast(moved); err == nil || !strings.Contains(err.Error(), "no witnessed pair") {
		t.Errorf("the reach of the listed row of the admins, named in the blast radius of the web tier: err = %v", err)
	}
	// A reach of the listed row that no pair of it shows (another destination, another user).
	for name, change := range map[string]func(*AccessReach){
		"a destination the row has no pair for": func(r *AccessReach) { r.Destination = "tag:example-db:23" },
		"a user the row has no pair for":        func(r *AccessReach) { r.User = "root" },
		"another kind":                          func(r *AccessReach) { r.Kind = AccessSSH },
	} {
		forged := trimmed
		forged.Blast = []AccessBlast{*admins}
		forged.Blast[0].Reaches = slices.Clone(admins.Reaches)
		change(&forged.Blast[0].Reaches[0])
		if err := validateAccessBlast(forged); err == nil || !strings.Contains(err.Error(), "no witnessed pair") {
			t.Errorf("%s: err = %v, want a refusal", name, err)
		}
	}
	// A reach that names a row that is not listed cannot be checked and is not refused.
	unlisted := trimmed
	unlisted.Expectations = []AccessResult{rowOf(report, "network-2")}
	if err := validateAccessBlast(unlisted); err != nil {
		t.Errorf("a reach naming a row left out: %v", err)
	}
}

// A broad rule in the blast radius of a source is one of the candidates of that source's own
// expectations, in the rows that are listed: the candidate of one source copied into the blast radius
// of another, with the right heading and no reaches, is refused. With rows left out, the rule may
// belong to a row that is not listed, and is not refused.
func TestABroadRuleOfABlastRadiusIsACandidateOfItsSource(t *testing.T) {
	ws := []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}
	broad := RuleRef{Section: "acls", Index: 1, Line: 3, Column: 5, Source: "*", Destination: "*", Broad: true, AllTraffic: true}
	other := RuleRef{Section: "acls", Index: 2, Line: 4, Column: 5, Source: "*", Destination: "*", Broad: true, Traffic: "proto tcp, ports *"}
	report := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws, Candidates: map[string]AccessCandidates{"network-1": {Rules: []RuleRef{broad}}, "network-2": {Rules: []RuleRef{other}}}})
	if err := ValidateAccessReport(report); err != nil {
		t.Fatalf("the control: %v", err)
	}
	admins, web := blastOf(report, "group:example-admins"), blastOf(report, "tag:example-web")
	if admins == nil || web == nil || len(admins.Broad) != 1 || admins.Broad[0] != broad || len(web.Broad) != 1 || web.Broad[0] != other {
		t.Fatalf("the control: blast = %+v", report.Blast)
	}
	copied := report
	copied.Blast = slices.Clone(report.Blast)
	for i := range copied.Blast {
		if copied.Blast[i].Source == "tag:example-web" {
			copied.Blast[i].Broad = []RuleRef{broad} // the candidate of the admins' expectation
		}
	}
	if err := ValidateAccessReport(copied); err == nil || !strings.Contains(err.Error(), "candidate") {
		t.Errorf("a broad rule that is a candidate of another source's expectation: err = %v, want a refusal", err)
	}
	// A rule that is no candidate of any listed row.
	invented := broad
	invented.Index, invented.Line = 9, 12
	forged := report
	forged.Blast = slices.Clone(report.Blast)
	forged.Blast[0].Broad = []RuleRef{invented}
	if err := ValidateAccessReport(forged); err == nil || !strings.Contains(err.Error(), "candidate") {
		t.Errorf("a broad rule that is no candidate of any row: err = %v, want a refusal", err)
	}
	// With the web tier's row left out, the rule may be its candidate there: nothing shows it is not.
	trimmed := copied
	trimmed.Omitted = 1
	trimmed.Expectations = []AccessResult{rowOf(report, "network-1")}
	if err := validateAccessBlast(trimmed); err != nil {
		t.Errorf("a broad rule that may belong to a row left out: %v", err)
	}
}

// The ports, the traffic and the flag of a candidate agree: a rule that allows every port and protocol
// limits no ports and writes no limit, and a rule that limits ports says what it allows. The sentence
// "all destinations" is not said for a rule whose ports are limited.
func TestTheTrafficFieldsOfARuleAgree(t *testing.T) {
	base := RuleRef{Section: "acls", Index: 1, Source: "*", Destination: "*", Broad: true}
	with := func(f func(*RuleRef)) RuleRef { r := base; f(&r); return r }
	for name, c := range map[string]struct {
		ref   RuleRef
		valid bool
		says  bool
	}{
		"every port and protocol":                  {with(func(r *RuleRef) { r.AllTraffic = true }), true, true},
		"every port and protocol, ports limited":   {with(func(r *RuleRef) { r.AllTraffic, r.Ports = true, "22" }), false, false},
		"every port and protocol, a limit written": {with(func(r *RuleRef) { r.AllTraffic, r.Traffic = true, "ports 22" }), false, false},
		"ports limited and said":                   {with(func(r *RuleRef) { r.Ports, r.Traffic = "22", "ports 22" }), true, true},
		"ports limited and not said":               {with(func(r *RuleRef) { r.Ports = "22" }), false, false},
		"a protocol limited with every port":       {with(func(r *RuleRef) { r.Traffic = "proto tcp, ports *" }), true, true},
		"a grant's entries":                        {with(func(r *RuleRef) { r.Section, r.Traffic = "grants", "tcp:22" }), true, true},
		"nothing to quote":                         {base, true, false},
	} {
		err := validRuleRef(c.ref)
		if (err == nil) != c.valid {
			t.Errorf("%s: validRuleRef = %v, want valid %v", name, err, c.valid)
		}
		if got := c.ref.statesEveryDestination(); got != c.says {
			t.Errorf("%s: statesEveryDestination = %v, want %v", name, got, c.says)
		}
	}
	// A candidate in an input is refused, and so is the same reference in a report's rows and blast radius.
	ws := []AccessWitness{
		witness("network-1", "accept", "tag:example-db:22", "", ObservedAllowed, proven()),
		witness("network-2", "deny", "tag:example-db:22", "", ObservedDenied, proven()),
	}
	bad := with(func(r *RuleRef) { r.AllTraffic, r.Ports = true, "22" })
	if _, err := ExplainAccess(AccessInput{Intent: adminSet(), Witnesses: ws, EvaluatedAt: accessAt, Candidates: map[string]AccessCandidates{"network-2": {Rules: []RuleRef{bad}}}}); err == nil {
		t.Error("a candidate that allows every port and limits them was accepted")
	}
	good := with(func(r *RuleRef) { r.AllTraffic = true })
	report := explainAccess(t, AccessInput{Intent: adminSet(), Witnesses: ws, Candidates: map[string]AccessCandidates{"network-2": {Rules: []RuleRef{good}}}})
	report.Blast = []AccessBlast{{Source: "tag:example-web", Heading: BlastHeading("tag:example-web"), Broad: []RuleRef{bad}}}
	if err := ValidateAccessReport(report); err == nil {
		t.Error("a blast radius that says all destinations for a rule whose ports are limited was accepted")
	}
}

func TestJudgeAccessKeepsEveryJudgementAndPreservesReport(t *testing.T) {
	var set IntentSet
	var ws []AccessWitness
	for i := 1; i <= 150; i++ {
		id, dst := fmt.Sprintf("network-%d", i), fmt.Sprintf("192.0.2.1:%d", i)
		set.Network = append(set.Network, NetworkExpectation{ID: id, Source: "tag:example-a", Accept: []string{dst}})
		if i <= MaxAccessPairs {
			ws = append(ws, witness(id, "accept", dst, "", ObservedAllowed, proven()))
		}
	}
	in := AccessInput{Intent: set, Witnesses: ws, EvaluatedAt: accessAt, Limits: map[string][]AccessLimit{"network-15": {LimitVia}}}
	r, judgements, err := JudgeAccess(in)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, err := ExplainAccess(in)
	if err != nil || !reflect.DeepEqual(r, ordinary) {
		t.Fatalf("report differs from ExplainAccess: %v", err)
	}
	if len(r.Expectations) != 100 || r.Omitted != 50 || len(judgements) != 150 || r.Counts.Total != 150 {
		t.Fatalf("rows=%d omitted=%d judgements=%d counts=%+v", len(r.Expectations), r.Omitted, len(judgements), r.Counts)
	}
	for i, j := range judgements {
		want := AccessNotEvaluated
		if i < MaxAccessPairs {
			want = AccessMet
		}
		if i == 14 {
			want = AccessMetWithLimits
		}
		if j.ID != fmt.Sprintf("network-%d", i+1) || j.Status != want {
			t.Fatalf("judgement %d = %+v, want %s", i, j, want)
		}
	}
	if !slices.Equal(judgements[14].Limits, []AccessLimit{LimitVia}) {
		t.Fatalf("limits = %v", judgements[14].Limits)
	}
	judgements[14].Limits[0] = LimitRules
	if in.Limits["network-15"][0] != LimitVia {
		t.Fatal("judgement aliases input")
	}
	if _, _, err := JudgeAccess(AccessInput{NoIntent: true, Intent: adminSet()}); err == nil {
		t.Fatal("invalid input accepted")
	}
}
