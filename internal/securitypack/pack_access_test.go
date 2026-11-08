package securitypack

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/security"
)

func TestPackAccessNormalization(t *testing.T) {
	in := validPackInput()
	intent := security.IntentSet{SchemaVersion: 1, Network: []security.NetworkExpectation{{ID: "network-1", Source: "group", Accept: []string{"destination"}}}}
	rules := make([]security.RuleRef, 9)
	for i := range rules {
		rules[i] = security.RuleRef{Section: "acls", Index: i + 1, Destination: "destination"}
	}
	in.Intent = &intent
	in.Access = &accessInput{Context: "ctx-0123456789abcdef", Selected: []string{"network-1"}, Input: security.AccessInput{Intent: intent, EvaluatedAt: in.EvaluationAt, Candidates: map[string]security.AccessCandidates{"network-1": {Rules: rules, Omitted: 2}}, Owners: []security.AccessOwner{{Source: "group", Tags: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}, Omitted: 3}}}}
	in.Expected.Access = &packExpectedAccess{SHA256: strings.Repeat("c", 64), Status: "incomplete"}
	pack, err := newPack(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := packInputOf(pack)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Access.Input.Candidates["network-1"]; len(got.Rules) != 8 || got.Omitted != 3 {
		t.Fatal("candidate normalization")
	}
	if got := out.Access.Input.Owners[0]; len(got.Tags) != 8 || got.Omitted != 4 {
		t.Fatal("owner normalization")
	}
	rawReport, err := security.ExplainAccess(in.Access.Input)
	if err != nil {
		t.Fatalf("raw evaluator input: %v", err)
	}
	normalReport, err := security.ExplainAccess(out.Access.Input)
	if err != nil {
		t.Fatalf("normalized evaluator input: %v", err)
	}
	if !reflect.DeepEqual(rawReport, normalReport) {
		t.Fatal("normalization changed evaluator output")
	}
	in.Access.Input.Owners[0].Omitted = 1 << 31
	if _, err := newPack(in, nil); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("overflow: %v", err)
	}
	in.Access.Input.Owners[0].Tags = in.Access.Input.Owners[0].Tags[:8]
	if _, err := newPack(in, nil); err != nil {
		t.Fatalf("inclusive omitted bound: %v", err)
	}
}

func TestPackAccessValidation(t *testing.T) {
	cell := security.AccessCell{Expect: "accept", Destination: "destination"}
	key := witnessKey{id: "network-1", cell: cell}
	w := packWitness{Expectation: key.id, Cell: packCell{Expect: cell.Expect, Destination: cell.Destination}, Observed: "allowed"}
	if err := checkPackWitnesses([]packWitness{w}, map[witnessKey]bool{key: true}); err != nil {
		t.Fatal(err)
	}
	if err := checkPackWitnesses([]packWitness{w, w}, map[witnessKey]bool{key: true}); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := checkPackWitnesses([]packWitness{w}, nil); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("unplanned: %v", err)
	}
	w.Observed = "invalid"
	if err := checkPackWitnesses([]packWitness{w}, map[witnessKey]bool{key: true}); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("bad observed: %v", err)
	}
	limits := limitsToPack(map[string][]security.AccessLimit{"network-1": {"z", "a", "a"}})
	if !slices.Equal(limits[0].Limits, []string{"a", "z"}) {
		t.Fatal("limits did not sort and compact")
	}
	for _, rule := range []packRule{{Section: "other", Index: 1}, {Section: "acls", Index: 0}, {Section: "acls", Index: 1, Destination: "*"}, {Section: "acls", Index: 1, AllTraffic: true, Traffic: "tcp"}, {Section: "acls", Index: 1, Ports: "22"}} {
		if validPackRule(rule) {
			t.Fatal("invalid rule accepted")
		}
	}
}

func TestPackAccessRefusesUnselectedAndMalformed(t *testing.T) {
	selected := map[string]bool{"network-1": true}
	judged := map[string]bool{"network-1": true}
	valid := packAccess{Candidates: []packCandidate{{Expectation: "network-1", Rules: []packRule{}}}, Limits: []packLimits{{Expectation: "network-1", Limits: []string{"posture"}}}, Owners: []packOwner{{Source: "group", Tags: []string{"tag"}}}}
	if err := checkPackAccessLists(&valid, selected, judged); err != nil {
		t.Fatal(err)
	}
	for _, value := range []packAccess{
		{Candidates: []packCandidate{{Expectation: "other"}}},
		{Candidates: []packCandidate{{Expectation: "network-1", Omitted: -1}}},
		{Candidates: []packCandidate{{Expectation: "network-1", Rules: make([]packRule, 9)}}},
		{Candidates: []packCandidate{{Expectation: "network-1", Rules: []packRule{{Section: "invalid"}}}}},
		{Limits: []packLimits{{Expectation: "other"}}},
		{Limits: []packLimits{{Expectation: "network-1", Limits: []string{"invalid"}}}},
		{Limits: []packLimits{{Expectation: "network-1", Limits: []string{"rules", "posture"}}}},
		{Owners: []packOwner{{Omitted: -1}}},
		{Owners: []packOwner{{Tags: make([]string, 9)}}},
	} {
		if err := checkPackAccessLists(&value, selected, judged); !errors.Is(err, ErrInvalidPack) {
			t.Fatalf("invalid access list: %v", err)
		}
	}
	w := packWitness{Expectation: "network-1", Cell: packCell{Expect: "accept", Destination: "destination"}, Observed: "allowed", Reason: "invalid"}
	cells := map[witnessKey]bool{{id: "network-1", cell: security.AccessCell{Expect: "accept", Destination: "destination"}}: true}
	if err := checkPackWitnesses([]packWitness{w}, cells); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("unknown reason: %v", err)
	}
}

func TestPackAccessContextBounds(t *testing.T) {
	at := validPackInput().EvaluationAt
	snapshot := packSnapshot{Context: "ctx-local-only", Scope: "local", ObservedAt: at}
	intent := security.IntentSet{SchemaVersion: 1, Network: []security.NetworkExpectation{{ID: "network-1", Source: "group", Accept: []string{"destination"}}}}
	valid := packAccess{Context: "ctx-0123456789abcdef", EvaluatedAt: at, Selected: []string{"network-1"}}
	if err := checkPackAccess(&valid, snapshot, &intent); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*packAccess){func(v *packAccess) { v.Context = "bad" }, func(v *packAccess) { v.Limit = 65 }, func(v *packAccess) { v.Limit = -1 }, func(v *packAccess) { v.Selected = []string{"other"} }, func(v *packAccess) { v.PolicyVersion = &packToken{Form: "bad"} }} {
		v := valid
		change(&v)
		if err := checkPackAccess(&v, snapshot, &intent); !errors.Is(err, ErrInvalidPack) {
			t.Fatalf("invalid access: %v", err)
		}
	}
	snapshot.Scope = "fleet"
	snapshot.Context = "ctx-1111111111111111"
	if err := checkPackAccess(&valid, snapshot, &intent); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("wrong fleet binding: %v", err)
	}
}

func TestPackAccessMoreThan100Selected(t *testing.T) {
	in := validPackInput()
	intent := security.IntentSet{SchemaVersion: 1}
	selected := make([]string, 0, 101)
	for i := 1; i <= 101; i++ {
		id := fmt.Sprintf("network-%d", i)
		intent.Network = append(intent.Network, security.NetworkExpectation{ID: id, Source: "group"})
		selected = append([]string{id}, selected...)
	}
	in.Intent = &intent
	in.Access = &accessInput{Context: "ctx-0123456789abcdef", Selected: selected, Input: security.AccessInput{Intent: intent, EvaluatedAt: in.EvaluationAt}}
	in.Expected.Access = &packExpectedAccess{SHA256: strings.Repeat("a", 64), Status: "incomplete"}
	pack, err := newPack(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := packInputOf(pack)
	if err != nil || len(out.Access.Selected) != 101 || len(out.Access.Input.Intent.Network) != 101 || out.Access.Input.Intent.Network[0].ID != "network-1" {
		t.Fatalf("selection changed: %v", err)
	}
}
