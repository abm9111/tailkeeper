package tools

import (
	"context"
	"reflect"
	"testing"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/security"
)

// The limits of an ssh expectation come from the ssh rules (and defaultSrcPosture), not from the
// candidate matcher: an ssh rule gated on srcPosture counts unless it is shown to be about other
// users or other destinations.
func TestSSHLimitsAreFoundFromTheSSHRules(t *testing.T) {
	dst := func(sels ...string) []acl.AccessDst {
		var out []acl.AccessDst
		for _, s := range sels {
			out = append(out, acl.AccessDst{Selector: s})
		}
		return out
	}
	ssh := func(users []string, posture bool, dsts ...string) acl.AccessRule {
		return acl.AccessRule{Section: "ssh", Index: 1, Src: []string{"*"}, Dst: dst(dsts...), Users: users, Posture: posture}
	}
	root, posture := []string{"root"}, security.LimitPosture
	cases := []struct {
		name  string
		rules []acl.AccessRule
		users []string
		dsts  []string
		want  []security.AccessLimit
	}{
		{"a gated rule for the user", []acl.AccessRule{ssh(root, true, "tag:example-db")}, root, []string{"tag:example-db"}, []security.AccessLimit{posture}},
		{"a gated rule for every destination", []acl.AccessRule{ssh(root, true, "*")}, root, []string{"tag:example-db"}, []security.AccessLimit{posture}},
		{"a gated rule for every user", []acl.AccessRule{ssh([]string{"*"}, true, "tag:example-db")}, root, []string{"tag:example-db"}, []security.AccessLimit{posture}},
		{"a gated rule for another user", []acl.AccessRule{ssh([]string{"ubuntu"}, true, "tag:example-db")}, root, []string{"tag:example-db"}, nil},
		{"a gated rule for the users that are not root, against root", []acl.AccessRule{ssh([]string{"autogroup:nonroot"}, true, "tag:example-db")}, root, []string{"tag:example-db"}, nil},
		{"the same, against a user that is not root", []acl.AccessRule{ssh([]string{"autogroup:nonroot"}, true, "tag:example-db")}, []string{"root", "deploy"}, []string{"tag:example-db"}, []security.AccessLimit{posture}},
		{"a gated rule for a localpart, which is not resolved", []acl.AccessRule{ssh([]string{"localpart:*@example.com"}, true, "tag:example-db")}, root, []string{"tag:example-db"}, []security.AccessLimit{posture}},
		{"a gated rule for another autogroup, which is not resolved", []acl.AccessRule{ssh([]string{"autogroup:example"}, true, "tag:example-db")}, root, []string{"tag:example-db"}, []security.AccessLimit{posture}},
		{"a user of the expectation that is an autogroup", []acl.AccessRule{ssh([]string{"ubuntu"}, true, "tag:example-db")}, []string{"autogroup:nonroot"}, []string{"tag:example-db"}, []security.AccessLimit{posture}},
		{"a gated rule for another range of addresses", []acl.AccessRule{ssh(root, true, "198.51.100.0/24")}, root, []string{"192.0.2.5"}, nil},
		{"a gated rule for the range that holds the address", []acl.AccessRule{ssh(root, true, "192.0.2.0/24")}, root, []string{"192.0.2.5"}, []security.AccessLimit{posture}},
		{"a gated rule for another tag, which a device may also carry", []acl.AccessRule{ssh(root, true, "tag:example-web")}, root, []string{"tag:example-db"}, []security.AccessLimit{posture}},
		{"one of two destinations of the rule is the expectation's", []acl.AccessRule{ssh(root, true, "198.51.100.0/24", "192.0.2.0/24")}, root, []string{"192.0.2.5"}, []security.AccessLimit{posture}},
		{"a gated rule with no destination", []acl.AccessRule{ssh(root, true)}, root, []string{"tag:example-db"}, nil},
		{"a gated rule and an expectation with no destination", []acl.AccessRule{ssh(root, true, "198.51.100.0/24")}, root, nil, []security.AccessLimit{posture}},
		{"a gated rule and an expectation with no user", []acl.AccessRule{ssh(root, true, "tag:example-db")}, nil, []string{"tag:example-db"}, []security.AccessLimit{posture}},
		{"an ssh rule with no posture", []acl.AccessRule{ssh(root, false, "tag:example-db")}, root, []string{"tag:example-db"}, nil},
		{"a gated rule of acls", []acl.AccessRule{{Section: "acls", Index: 1, Src: []string{"*"}, Dst: dst("*"), Posture: true}}, root, []string{"tag:example-db"}, nil},
		{"a gated grant", []acl.AccessRule{{Section: "grants", Index: 1, Src: []string{"*"}, Dst: dst("*"), IP: []string{"*"}, Posture: true}}, root, []string{"tag:example-db"}, nil},
		{"an ssh rule that cannot be read", []acl.AccessRule{{Section: "ssh", Index: 1, Unreadable: true}}, root, []string{"tag:example-db"}, []security.AccessLimit{security.LimitRules}},
		{"a rule of acls that cannot be read", []acl.AccessRule{{Section: "acls", Index: 1, Unreadable: true}}, root, []string{"tag:example-db"}, nil},
		{"a gated rule and one that cannot be read", []acl.AccessRule{ssh(root, true, "tag:example-db"), {Section: "ssh", Index: 2, Unreadable: true}}, root, []string{"tag:example-db"}, []security.AccessLimit{posture, security.LimitRules}},
	}
	for _, c := range cases {
		got := ruleMatcher{a: accessOf(c.rules...)}.sshLimits(c.dsts, c.users)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: limits = %v, want %v", c.name, got, c.want)
		}
	}
	if got := (ruleMatcher{a: &acl.Access{DefaultPosture: true}}).sshLimits([]string{"tag:example-db"}, root); !reflect.DeepEqual(got, []security.AccessLimit{posture}) {
		t.Errorf("a default posture: limits = %v", got)
	}
	if got := (ruleMatcher{a: &acl.Access{OmittedRules: 1}}).sshLimits([]string{"tag:example-db"}, root); !reflect.DeepEqual(got, []security.AccessLimit{security.LimitRules}) {
		t.Errorf("rules past the cap: limits = %v, want the rules limit", got)
	}
	w := newMatchMeter(context.Background(), 0)
	w.tick(1) // the budget is used
	if got := (ruleMatcher{a: accessOf(ssh(root, true, "tag:example-db")), w: w}).sshLimits([]string{"tag:example-db"}, root); !reflect.DeepEqual(got, []security.AccessLimit{security.LimitRules}) {
		t.Errorf("a spent meter: limits = %v, want the rules limit alone: nothing was walked", got)
	}
}

// The walk of the ssh rules ends at the first refusal of the meter, as the walk of the others does.
func TestTheWalkOfTheSSHRulesEndsAtTheMeter(t *testing.T) {
	const slack = 8
	rules := make([]acl.AccessRule, 4096)
	for i := range rules {
		rules[i] = acl.AccessRule{Section: "ssh", Index: i + 1, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "tag:example-db"}}, Users: []string{"root"}, Posture: true}
	}
	w := newMatchMeter(context.Background(), 0)
	w.tick(1)
	(ruleMatcher{a: &acl.Access{Rules: rules}, w: w}).sshLimits([]string{"tag:example-db"}, []string{"root"})
	if w.asked > 1+slack {
		t.Errorf("4,096 ssh rules were walked after the budget was used: %d requests asked", w.asked)
	}
	// With a budget, the comparisons of users and destinations are steps and the walk is bounded.
	budget := newMatchMeter(context.Background(), 500)
	(ruleMatcher{a: &acl.Access{Rules: rules}, w: budget}).sshLimits([]string{"tag:example-web", "tag:example-db"}, []string{"deploy", "ops"})
	if !budget.spent() || budget.asked > 500+slack {
		t.Errorf("spent %v after %d requests asked, want the walk stopped within a budget of 500", budget.spent(), budget.asked)
	}
}

// The accept, check and deny users of an ssh expectation are all compared with a gated rule's users:
// a rule for the user an expectation accepts, or checks, is a limit of it though it denies another.
func TestAllTheUsersOfAnSSHExpectationAreComparedWithAGatedRule(t *testing.T) {
	gated := acl.AccessRule{Section: "ssh", Index: 1, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "tag:example-db"}}, Users: []string{"root"}, Posture: true}
	facts := &explainFacts{access: accessOf(gated)}
	for name, e := range map[string]security.SSHExpectation{
		"accept root, deny deploy": {ID: "ssh-1", Source: "tag:example-a", Destinations: []string{"tag:example-db"}, Accept: []string{"root"}, Deny: []string{"deploy"}},
		"check root, deny deploy":  {ID: "ssh-1", Source: "tag:example-a", Destinations: []string{"tag:example-db"}, Check: []string{"root"}, Deny: []string{"deploy"}},
		"deny root":                {ID: "ssh-1", Source: "tag:example-a", Destinations: []string{"tag:example-db"}, Deny: []string{"root"}},
	} {
		set := security.IntentSet{SSH: []security.SSHExpectation{e}}
		_, limits, _, _, err := explainRulesWith(newMatchMeter(context.Background(), 1<<30), facts, set, map[string]bool{"ssh-1": true})
		if err != nil || !reflect.DeepEqual(limits["ssh-1"], []security.AccessLimit{security.LimitPosture}) {
			t.Errorf("%s: limits %v err %v, want the posture limit", name, limits["ssh-1"], err)
		}
	}
	other := security.IntentSet{SSH: []security.SSHExpectation{{ID: "ssh-1", Source: "tag:example-a", Destinations: []string{"tag:example-db"}, Accept: []string{"ubuntu"}, Check: []string{"deploy"}, Deny: []string{"ops"}}}}
	if _, limits, _, _, _ := explainRulesWith(newMatchMeter(context.Background(), 1<<30), facts, other, map[string]bool{"ssh-1": true}); len(limits["ssh-1"]) != 0 {
		t.Errorf("a rule for root against three other users: limits %v, want none", limits["ssh-1"])
	}
}
