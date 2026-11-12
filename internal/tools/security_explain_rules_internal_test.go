package tools

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/security"
)

// The text match of a candidate rule, on a policy built by hand. Everything is synthetic.

func accessOf(rules ...acl.AccessRule) *acl.Access {
	return &acl.Access{
		Rules: rules,
		Groups: map[string][]string{
			"group:example-admins": {"Alice@Example.com", "group:example-ops"},
			"group:example-ops":    {"bob@example.com"},
			"group:example-deep":   {"group:example-admins"},
		},
		Hosts:     map[string]string{"example-host": "192.0.2.10", "example-range": "198.51.100.0/24", "bad-host": "not an address"},
		TagOwners: map[string][]string{"tag:example-x": {"alice@example.com"}, "tag:example-y": {"group:example-admins"}, "tag:example-z": {"tag:example-w"}, "tag:example-q": {"autogroup:admin"}},
	}
}

func TestCoversMatchesAsText(t *testing.T) {
	m := ruleMatcher{a: accessOf()}
	cases := []struct {
		sel, x string
		want   bool
	}{
		{"*", "anything", true},
		{"tag:example-a", "tag:example-a", true},
		{"tag:example-a", "tag:example-b", false},
		{"alice@example.com", "ALICE@example.com", true},
		{"tag:example-a", "TAG:EXAMPLE-A", false},
		{"group:example-admins", "alice@example.com", true},
		{"group:example-admins", "bob@example.com", true},
		{"group:example-admins", "carol@example.com", false},
		{"group:example-deep", "bob@example.com", false},
		{"group:example-deep", "alice@example.com", true},
		{"group:example-none", "alice@example.com", false},
		{"autogroup:tagged", "tag:example-a", true},
		{"autogroup:tagged", "alice@example.com", false},
		// The matcher lists candidates as text and does not resolve autogroup:member: the list is
		// short for it (the output says candidate lists may be incomplete), and no limit depends
		// on this answer: see TestLimitsDoNotDependOnTheCandidateMatcher.
		{"autogroup:member", "alice@example.com", false},
		{"192.0.2.0/24", "192.0.2.77", true},
		{"192.0.2.0/24", "192.0.2.0/25", true},
		{"192.0.2.0/25", "192.0.2.0/24", false},
		{"192.0.2.0/24", "198.51.100.1", false},
		{"192.0.2.0/24", "fd7a:115c:a1e0::1", false},
		{"example-host", "192.0.2.10", true},
		{"example-host", "192.0.2.11", false},
		{"example-range", "198.51.100.9", true},
		{"192.0.2.10", "example-host", true},
		{"192.0.2.0/24", "example-host", true},
		{"bad-host", "x", false},
		{"fd7a:115c:a1e0::/48", "fd7a:115c:a1e0::5", true},
	}
	for _, c := range cases {
		if got := m.covers(c.sel, c.x); got != c.want {
			t.Errorf("covers(%q, %q) = %v, want %v", c.sel, c.x, got, c.want)
		}
	}
}

func TestNetworkCandidatesPortsAndGrants(t *testing.T) {
	rules := []acl.AccessRule{
		{Section: "acls", Index: 1, Line: 3, Column: 3, Src: []string{"tag:example-a"}, Dst: []acl.AccessDst{{Selector: "tag:example-db", Ports: "22"}}},
		{Section: "acls", Index: 2, Line: 4, Column: 3, Src: []string{"tag:example-a"}, Dst: []acl.AccessDst{{Selector: "tag:example-db", Ports: "80,443"}}},
		{Section: "acls", Index: 3, Line: 5, Column: 3, Src: []string{"tag:example-a"}, Dst: []acl.AccessDst{{Selector: "*", Ports: "20-30"}}},
		{Section: "grants", Index: 1, Line: 9, Column: 3, Src: []string{"tag:example-a"}, Dst: []acl.AccessDst{{Selector: "tag:example-db"}}, IP: []string{"tcp:22", "icmp:*"}},
		{Section: "grants", Index: 2, Line: 10, Column: 3, Src: []string{"tag:example-a"}, Dst: []acl.AccessDst{{Selector: "tag:example-db"}}, IP: []string{"udp:53"}},
		{Section: "grants", Index: 3, Line: 11, Column: 3, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "tag:example-db"}}, App: true},
		{Section: "grants", Index: 4, Line: 12, Column: 3, Src: []string{"tag:example-a"}, Dst: []acl.AccessDst{{Selector: "tag:example-db"}}, IP: []string{"22"}, Via: true},
		{Section: "acls", Index: 4, Line: 6, Column: 3, Src: []string{"tag:example-a"}, Dst: []acl.AccessDst{{Selector: "tag:example-db", Ports: "22"}}, Posture: true},
		{Section: "acls", Index: 5, Unreadable: true, Src: []string{"*"}},
		{Section: "ssh", Index: 1, Line: 20, Column: 3, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "tag:example-db"}}, Users: []string{"root"}},
	}
	m := ruleMatcher{a: accessOf(rules...)}
	h := m.network("tag:example-a", []string{"tag:example-db:22"})
	var got []string
	for _, r := range h.refs {
		got = append(got, r.Section+" "+string(rune('0'+r.Index))+" "+r.Destination+" "+r.Ports)
	}
	// Broad first, then in the order of the file: the wildcard rule that covers port 22, the acl
	// rules for 22, the grants that name 22 or no port, never the other ports, the ssh section or
	// a rule that cannot be read.
	want := []string{"acls 3 * 20-30", "acls 1 tag:example-db 22", "grants 1 tag:example-db ", "grants 3 tag:example-db ", "grants 4 tag:example-db ", "acls 4 tag:example-db 22"}
	if !reflect.DeepEqual(got, want) || h.total != 6 {
		t.Errorf("candidates = %q (%d), want %q", got, h.total, want)
	}
	for _, r := range h.refs {
		wantQualified := (r.Section == "grants" && (r.Index == 3 || r.Index == 4)) || (r.Section == "acls" && r.Index == 4)
		if r.Qualified != wantQualified {
			t.Errorf("%s[%d] qualified = %v, want %v: a rule with posture, app capabilities or via is marked", r.Section, r.Index, r.Qualified, wantQualified)
		}
	}
	if h.refs[0].Broad != true || h.refs[1].Broad {
		t.Errorf("the wildcard rule is broad and the others are not: %+v", h.refs[:2])
	}
	// A port nobody names has no candidate but the grant that names none and the one whose icmp:*
	// is every port of its protocol: the protocol is not compared, a candidate is a place to look.
	h = m.network("tag:example-a", []string{"tag:example-db:9999"})
	if h.total != 2 || h.refs[0].Section != "grants" || h.refs[0].Index != 1 || h.refs[1].Index != 3 {
		t.Errorf("port 9999: %+v", h.refs)
	}
	// An IPv6 destination in brackets, a host alias and a destination that is no host:port.
	m6 := ruleMatcher{a: accessOf(acl.AccessRule{Section: "acls", Index: 1, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "fd7a:115c:a1e0::/48", Ports: "*"}}})}
	if h := m6.network("tag:a", []string{"[fd7a:115c:a1e0::5]:443"}); h.total != 1 {
		t.Errorf("a bracketed IPv6 destination: %+v", h)
	}
	if h := m6.network("tag:a", []string{"nonsense"}); h.total != 0 {
		t.Errorf("a destination that is no host:port matched: %+v", h)
	}
	mh := ruleMatcher{a: accessOf(acl.AccessRule{Section: "acls", Index: 1, Src: []string{"example-host"}, Dst: []acl.AccessDst{{Selector: "example-range", Ports: "*"}}})}
	if h := mh.network("192.0.2.10", []string{"198.51.100.4:80"}); h.total != 1 {
		t.Errorf("host aliases: %+v", h)
	}
}

// The policy's defaultSrcPosture applies to every rule of acls and grants that has no srcPosture
// of its own: every network candidate is qualified by it, whatever the rule says.
func TestADefaultPostureQualifiesEveryNetworkCandidate(t *testing.T) {
	rules := []acl.AccessRule{
		{Section: "acls", Index: 1, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "*", Ports: "*"}}},
		{Section: "grants", Index: 2, Src: []string{"tag:example-a"}, Dst: []acl.AccessDst{{Selector: "tag:example-db"}}, IP: []string{"22"}},
	}
	for _, defaultPosture := range []bool{false, true} {
		a := accessOf(rules...)
		a.DefaultPosture = defaultPosture
		h := ruleMatcher{a: a}.network("tag:example-a", []string{"tag:example-db:22"})
		if len(h.refs) != 2 {
			t.Fatalf("default posture %v: candidates %+v, want both rules", defaultPosture, h.refs)
		}
		for _, r := range h.refs {
			if r.Qualified != defaultPosture {
				t.Errorf("default posture %v: %s[%d] qualified = %v", defaultPosture, r.Section, r.Index, r.Qualified)
			}
		}
	}
}

// trafficOf is the traffic of a rule for a destination, as a rule prepared without a meter reads it.
func trafficOf(r acl.AccessRule, d acl.AccessDst) (all bool, text string) {
	n, _ := ruleMatcher{}.prepare(r)
	return n.traffic(d)
}

// What a network rule allows of ports and protocols is read as the rule writes it: everything
// only for the wildcard (an acls destination with the ports * and no proto, a grant with the ip
// entry *), else the limit as written, else nothing to quote.
func TestTrafficOfARuleIsEverythingOnlyForTheWildcard(t *testing.T) {
	acls := func(ports string, proto ...string) (acl.AccessRule, acl.AccessDst) {
		d := acl.AccessDst{Selector: "*", Ports: ports}
		return acl.AccessRule{Section: "acls", Dst: []acl.AccessDst{d}, Proto: proto}, d
	}
	grant := func(ip ...string) (acl.AccessRule, acl.AccessDst) {
		d := acl.AccessDst{Selector: "*"}
		return acl.AccessRule{Section: "grants", Dst: []acl.AccessDst{d}, IP: ip}, d
	}
	cases := []struct {
		name string
		rule func() (acl.AccessRule, acl.AccessDst)
		all  bool
		text string
	}{
		{"acls *:*", func() (acl.AccessRule, acl.AccessDst) { return acls("*") }, true, ""},
		{"acls *:22", func() (acl.AccessRule, acl.AccessDst) { return acls("22") }, false, "ports 22"},
		{"acls *:1-65535 is a limit, not the wildcard", func() (acl.AccessRule, acl.AccessDst) { return acls("1-65535") }, false, "ports 1-65535"},
		{"acls *:* with a proto", func() (acl.AccessRule, acl.AccessDst) { return acls("*", "tcp") }, false, "proto tcp, ports *"},
		{"acls *:22 with two protos", func() (acl.AccessRule, acl.AccessDst) { return acls("22", "tcp", "udp") }, false, "proto tcp,udp, ports 22"},
		{"acls with no ports written", func() (acl.AccessRule, acl.AccessDst) { return acls("") }, false, ""},
		{"acls with a proto and no ports written", func() (acl.AccessRule, acl.AccessDst) { return acls("", "tcp") }, false, "proto tcp"},
		{"a grant with ip *", func() (acl.AccessRule, acl.AccessDst) { return grant("*") }, true, ""},
		{"a grant with ip * among others", func() (acl.AccessRule, acl.AccessDst) { return grant("tcp:22", "*") }, true, ""},
		{"a grant with ip tcp:22", func() (acl.AccessRule, acl.AccessDst) { return grant("tcp:22") }, false, "tcp:22"},
		{"a grant with ip tcp:*", func() (acl.AccessRule, acl.AccessDst) { return grant("tcp:*") }, false, "tcp:*"},
		{"a grant with two ip entries", func() (acl.AccessRule, acl.AccessDst) { return grant("tcp:22", "udp:53") }, false, "tcp:22, udp:53"},
		{"a grant with no ip entries", func() (acl.AccessRule, acl.AccessDst) { return grant() }, false, ""},
	}
	for _, c := range cases {
		r, d := c.rule()
		if all, text := trafficOf(r, d); all != c.all || text != c.text {
			t.Errorf("%s: trafficOf = (%v, %q), want (%v, %q)", c.name, all, text, c.all, c.text)
		}
	}
	// A policy's words are short; the text a candidate quotes is cut, whichever kind of rule it is.
	longGrant := acl.AccessRule{Section: "grants", Dst: []acl.AccessDst{{Selector: "*"}}, IP: []string{strings.Repeat("x", 3*maxSelectorText)}}
	longACL := acl.AccessRule{Section: "acls", Proto: []string{strings.Repeat("y", 3*maxSelectorText)}, Dst: []acl.AccessDst{{Selector: "*", Ports: "22"}}}
	longPorts := acl.AccessRule{Section: "acls", Proto: []string{"tcp"}, Dst: []acl.AccessDst{{Selector: "*", Ports: strings.Repeat("1,", 3*maxSelectorText)}}}
	for name, r := range map[string]acl.AccessRule{"a grant": longGrant, "an acls rule": longACL, "an acls rule with a long list of ports": longPorts} {
		if _, text := trafficOf(r, r.Dst[0]); len([]rune(text)) == 0 || len([]rune(text)) > maxSelectorText {
			t.Errorf("traffic of %s with %d runes of text is quoted as %d runes, want it cut to %d", name, 3*maxSelectorText, len([]rune(text)), maxSelectorText)
		}
	}
	// The ports are cut before the text is built, which must give the text that cutting the whole of it gives.
	if _, text := trafficOf(longPorts, longPorts.Dst[0]); text != cutRunes("proto tcp, ports "+longPorts.Dst[0].Ports, maxSelectorText) {
		t.Errorf("traffic of a long list of ports = %q, want the whole text cut", text)
	}
}

// A candidate carries the traffic of the destination it was found by, and of the destinations
// of one rule the one that allows everything is the one it quotes.
func TestACandidateCarriesItsTrafficAndTheRuleThatAllowsEverythingOutranks(t *testing.T) {
	dst := func(sel, ports string) acl.AccessDst { return acl.AccessDst{Selector: sel, Ports: ports} }
	rules := []acl.AccessRule{
		{Section: "acls", Index: 1, Src: []string{"*"}, Dst: []acl.AccessDst{dst("*", "22")}},
		{Section: "acls", Index: 2, Src: []string{"*"}, Dst: []acl.AccessDst{dst("*", "22"), dst("*", "*")}},
		{Section: "acls", Index: 3, Src: []string{"*"}, Dst: []acl.AccessDst{dst("tag:example-db", "*"), dst("*", "22")}},
		{Section: "grants", Index: 4, Src: []string{"*"}, Dst: []acl.AccessDst{dst("*", "")}, IP: []string{"tcp:22"}},
		{Section: "acls", Index: 5, Src: []string{"*"}, Proto: []string{"tcp"}, Dst: []acl.AccessDst{dst("*", "*")}},
		{Section: "acls", Index: 6, Src: []string{"*"}, Dst: []acl.AccessDst{dst("tag:example-db", "22"), dst("tag:example-db", "*")}},
	}
	h := ruleMatcher{a: accessOf(rules...)}.network("tag:example-web", []string{"tag:example-db:22"})
	got := map[int]security.RuleRef{}
	for _, r := range h.refs {
		got[r.Index] = r
	}
	check := func(index int, all bool, text string, broad bool) {
		t.Helper()
		r, ok := got[index]
		if !ok || r.AllTraffic != all || r.Traffic != text || r.Broad != broad {
			t.Errorf("rule %d = %+v (found %v), want all %v traffic %q broad %v", index, r, ok, all, text, broad)
		}
	}
	check(1, false, "ports 22", true)
	check(2, true, "", true)          // the destination * with every port outranks the * with port 22 before it
	check(3, false, "ports 22", true) // a destination * outranks a named one, whichever comes first
	check(4, false, "tcp:22", true)
	check(5, false, "proto tcp, ports *", true)
	check(6, false, "ports 22", false) // of two destinations that are not *, the first found stays
}

func TestSSHCandidates(t *testing.T) {
	rules := []acl.AccessRule{
		{Section: "ssh", Index: 1, Line: 2, Column: 3, Src: []string{"group:example-admins"}, Dst: []acl.AccessDst{{Selector: "tag:example-db"}}, Users: []string{"root"}},
		{Section: "ssh", Index: 2, Line: 3, Column: 3, Src: []string{"group:example-admins"}, Dst: []acl.AccessDst{{Selector: "tag:example-db"}}, Users: []string{"autogroup:nonroot"}},
		{Section: "ssh", Index: 3, Line: 4, Column: 3, Src: []string{"group:example-admins"}, Dst: []acl.AccessDst{{Selector: "tag:example-web"}}, Users: []string{"root"}},
		{Section: "ssh", Index: 4, Line: 5, Column: 3, Src: []string{"tag:example-ci"}, Dst: []acl.AccessDst{{Selector: "tag:example-db"}}, Users: []string{"root"}},
		{Section: "ssh", Index: 5, Line: 6, Column: 3, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "*"}}, Users: []string{"localpart:*@example.com"}},
		{Section: "acls", Index: 1, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "*", Ports: "*"}}},
	}
	m := ruleMatcher{a: accessOf(rules...)}
	h := m.ssh("alice@example.com", []string{"tag:example-db"}, []string{"root"})
	if h.total != 1 || h.refs[0].Index != 1 {
		t.Errorf("root: %+v, want ssh[1] only: nonroot does not cover root, localpart is not resolved, an acl is not an ssh rule", h.refs)
	}
	h = m.ssh("alice@example.com", []string{"tag:example-db"}, []string{"deploy"})
	if h.total != 1 || h.refs[0].Index != 2 {
		t.Errorf("deploy: %+v, want ssh[2]", h.refs)
	}
	h = m.ssh("alice@example.com", []string{"tag:example-db"}, []string{"root", "deploy"})
	if h.total != 2 {
		t.Errorf("both users: %+v", h.refs)
	}
	wide := ruleMatcher{a: accessOf(acl.AccessRule{Section: "ssh", Index: 1, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "tag:example-db"}, {Selector: "*"}}, Users: []string{"*"}})}
	if h := wide.ssh("tag:example-a", []string{"tag:example-db"}, []string{"x"}); h.total != 1 || !h.refs[0].Broad || h.refs[0].Destination != "*" {
		t.Errorf("a rule with a wildcard destination is broad: %+v", h.refs)
	}
}

func TestHitsKeepTheBroadRuleWhenTheListIsCut(t *testing.T) {
	var h ruleHits
	for i := 1; i <= 12; i++ {
		h.add(security.RuleRef{Section: "acls", Index: i})
	}
	h.add(security.RuleRef{Section: "grants", Index: 1, Broad: true})
	h.add(security.RuleRef{Section: "grants", Index: 2, Broad: true})
	c := h.candidates()
	if len(c.Rules) != security.MaxAccessCandidates || c.Omitted != 14-security.MaxAccessCandidates {
		t.Fatalf("%d candidates, %d omitted", len(c.Rules), c.Omitted)
	}
	if !c.Rules[0].Broad || !c.Rules[1].Broad || c.Rules[2].Broad || c.Rules[2].Index != 1 {
		t.Errorf("rules = %+v, want the two broad rules first and then the file's first narrow ones", c.Rules)
	}
}

func TestTagsOwnedByAUserAreTheirsToApplyAndNothingMore(t *testing.T) {
	m := ruleMatcher{a: accessOf()}
	if got := m.tagsOwnedBy("alice@example.com"); !reflect.DeepEqual(got, []string{"tag:example-x", "tag:example-y"}) {
		t.Errorf("alice owns %v", got)
	}
	if got := m.tagsOwnedBy("bob@example.com"); !reflect.DeepEqual(got, []string{"tag:example-y"}) {
		t.Errorf("bob (through the group of ops inside the admins) owns %v", got)
	}
	if got := m.tagsOwnedBy("tag:example-w"); !reflect.DeepEqual(got, []string{"tag:example-z"}) {
		t.Errorf("a tag owned by a tag: %v", got)
	}
	if got := m.tagsOwnedBy("carol@example.com"); len(got) != 0 {
		t.Errorf("carol owns %v: autogroup:admin is not resolved", got)
	}
}

// all marks every expectation as judged.
var all = map[string]bool{"network-1": true, "ssh-1": true}

func TestExplainRulesStatesWhatItCannotListOrRead(t *testing.T) {
	set := security.IntentSet{Network: []security.NetworkExpectation{{ID: "network-1", Source: "autogroup:admin", Accept: []string{"tag:example-db:22"}}},
		SSH: []security.SSHExpectation{{ID: "ssh-1", Source: "tag:example-a", Destinations: []string{"autogroup:self"}, Accept: []string{"root"}}}}
	ctx := context.Background()
	cands, limits, owners, partial, _ := explainRules(ctx, nil, set, all)
	if !partial || len(cands) != 0 || len(owners) != 0 || !reflect.DeepEqual(limits["network-1"], []security.AccessLimit{security.LimitRules, security.LimitSource}) || !reflect.DeepEqual(limits["ssh-1"], []security.AccessLimit{security.LimitRules, security.LimitSource}) {
		t.Errorf("a policy that cannot be read: %v %v %v %v", cands, limits, owners, partial)
	}
	facts := &explainFacts{access: accessOf(acl.AccessRule{Section: "acls", Index: 1, Unreadable: true})}
	if _, _, _, partial, _ := explainRules(ctx, facts, set, all); !partial {
		t.Error("a rule that cannot be read leaves the lists complete")
	}
	facts = &explainFacts{access: &acl.Access{OmittedRules: 3}}
	if _, _, _, partial, _ := explainRules(ctx, facts, set, all); !partial {
		t.Error("rules past the cap leave the lists complete")
	}
	facts = &explainFacts{access: accessOf()}
	if _, _, _, partial, _ := explainRules(ctx, facts, set, all); partial {
		t.Error("a policy that is read whole has partial lists")
	}
	attrs := security.IntentSet{Network: []security.NetworkExpectation{{ID: "network-1", Source: "tag:a", Accept: []string{"tag:b:22"}, SourcePostureAttributes: security.PostureAttributes{"node:os": security.Scalar{}}}}}
	facts = &explainFacts{access: &acl.Access{DefaultPosture: true}}
	if _, limits, _, _, _ := explainRules(ctx, facts, attrs, all); len(limits["network-1"]) != 0 {
		t.Errorf("an expectation that gives posture attributes has the limits %v", limits)
	}
}

func TestSelectIntentAndItsRefusals(t *testing.T) {
	set := security.IntentSet{Network: []security.NetworkExpectation{{ID: "network-1"}, {ID: "network-2"}}, SSH: []security.SSHExpectation{{ID: "ssh-1"}}}
	got, err := selectIntent(set, []string{"ssh-1", "network-2"})
	if err != nil || len(got.Network) != 1 || got.Network[0].ID != "network-2" || len(got.SSH) != 1 {
		t.Fatalf("%+v, %v", got, err)
	}
	if got, err := selectIntent(set, nil); err != nil || len(got.Network) != 2 {
		t.Errorf("no selection keeps all: %+v, %v", got, err)
	}
	_, err = selectIntent(set, []string{"ssh-2"})
	if err == nil || !strings.Contains(err.Error(), "network-1 to network-2 and ssh-1 to ssh-1") || strings.Contains(err.Error(), "ssh-2") {
		t.Errorf("err = %v", err)
	}
	if heldIDs(security.IntentSet{}) != "no expectation" {
		t.Error("heldIDs of nothing")
	}
}

func TestWitnessReasonsComeFromTheReadersOfAclTest(t *testing.T) {
	cases := map[security.AccessReason]destVerdict{
		security.ReasonUnresolved:  {Verdict: verdictUnresolved},
		security.ReasonDisagree:    {Verdict: verdictUnknown, Why: whyProtocolsDiffer},
		security.ReasonUnpaired:    {Verdict: verdictUnknown, Why: whyUnpairedLine},
		security.ReasonUnparseable: {Verdict: verdictUnknown},
	}
	for want, v := range cases {
		if got := networkReason(v); got != want {
			t.Errorf("networkReason(%+v) = %s, want %s", v, got, want)
		}
	}
	ssh := map[security.AccessReason]ACLSSHVerdict{
		security.ReasonCheckUser:   {Verdict: verdictUnknown, Why: whyCheckSilent},
		security.ReasonUnresolved:  {Verdict: verdictUnresolved},
		security.ReasonDisagree:    {Verdict: verdictUnknown, Why: whySSHDisagree},
		security.ReasonUnpaired:    {Verdict: verdictUnknown, Why: whySSHUnpaired},
		security.ReasonUnparseable: {},
	}
	for want, v := range ssh {
		if got := sshReason(v); got != want {
			t.Errorf("sshReason(%+v) = %s, want %s", v, got, want)
		}
	}
}

// The search of the rules is bounded by the pairs judged: an expectation none of whose pairs is
// judged is searched for nothing, and a source whose expectations are all unjudged has no tags
// listed.
func TestExplainRulesSearchesOnlyTheExpectationsThatAreJudged(t *testing.T) {
	facts := &explainFacts{access: accessOf(acl.AccessRule{Section: "acls", Index: 1, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "*", Ports: "*"}}})}
	set := security.IntentSet{Network: []security.NetworkExpectation{
		{ID: "network-1", Source: "alice@example.com", Accept: []string{"tag:b:22"}},
		{ID: "network-2", Source: "bob@example.com", Accept: []string{"tag:b:22"}},
	}}
	cands, _, owners, _, _ := explainRules(context.Background(), facts, set, map[string]bool{"network-1": true})
	if len(cands["network-1"].Rules) != 1 {
		t.Errorf("the judged expectation has no candidate: %+v", cands)
	}
	if _, ok := cands["network-2"]; ok {
		t.Errorf("an expectation with no pair judged was searched: %+v", cands["network-2"])
	}
	if len(owners) != 1 || owners[0].Source != "alice@example.com" {
		t.Errorf("owners = %+v, want the judged source's only", owners)
	}
	plan := security.PlanAccess(set, 1)
	if got := judgedIDs(plan); !got["network-1"] || got["network-2"] {
		t.Errorf("judgedIDs = %v", got)
	}
}

// The cap of pairs is the number of tests one validation call may carry, today and after a change
// to either.
func TestTheCapOfPairsIsTheCapOfTestsAValidationCarries(t *testing.T) {
	if security.MaxAccessPairs != maxCallerTests {
		t.Errorf("security.MaxAccessPairs = %d, maxCallerTests = %d", security.MaxAccessPairs, maxCallerTests)
	}
}

// The limits of a network expectation come from the rules of the policy that carry posture, app
// capabilities or via, and not from the candidate matcher: a rule the matcher cannot match
// (autogroup:member, a localpart, a tag or group the matcher does not follow) still counts
// unless it is shown to be about other destinations.
func TestLimitsDoNotDependOnTheCandidateMatcher(t *testing.T) {
	dst := func(sel, ports string) []acl.AccessDst { return []acl.AccessDst{{Selector: sel, Ports: ports}} }
	posture := acl.AccessRule{Section: "grants", Index: 1, Src: []string{"autogroup:member"}, Dst: dst("tag:example-db", ""), IP: []string{"*"}, Posture: true}
	m := ruleMatcher{a: accessOf(posture)}
	if h := m.network("bob@example.com", []string{"tag:example-db:22"}); h.total != 0 {
		t.Fatalf("the matcher listed %+v: autogroup:member is not resolved, so this is the case the limits must not depend on", h.refs)
	}
	want := func(name string, rules []acl.AccessRule, attrs bool, wantLimits ...security.AccessLimit) {
		t.Helper()
		got := ruleMatcher{a: accessOf(rules...)}.networkLimits([]string{"tag:example-db:22"}, attrs)
		if !reflect.DeepEqual(got, wantLimits) {
			t.Errorf("%s: limits = %v, want %v", name, got, wantLimits)
		}
	}
	want("a posture grant for autogroup:member", []acl.AccessRule{posture}, false, security.LimitPosture)
	want("the same, with posture attributes given", []acl.AccessRule{posture}, true)
	app := acl.AccessRule{Section: "grants", Index: 1, Src: []string{"localpart:*@example.com"}, Dst: dst("tag:example-db", ""), App: true}
	want("an app grant for a source nobody matches", []acl.AccessRule{app}, false, security.LimitApp)
	want("an app grant is not made other by attributes", []acl.AccessRule{app}, true, security.LimitApp)
	via := acl.AccessRule{Section: "grants", Index: 1, Src: []string{"autogroup:member"}, Dst: dst("autogroup:internet", ""), IP: []string{"*"}, Via: true}
	want("a via grant to a destination that is not an address", []acl.AccessRule{via}, false, security.LimitVia)
	both := acl.AccessRule{Section: "acls", Index: 2, Src: []string{"*"}, Dst: dst("*", "*"), Posture: true}
	want("a posture rule for every destination", []acl.AccessRule{both}, false, security.LimitPosture)
	want("rules of every kind", []acl.AccessRule{posture, app, via}, false, security.LimitPosture, security.LimitApp, security.LimitVia)
	want("a plain rule carries no limit", []acl.AccessRule{{Section: "acls", Index: 1, Src: []string{"*"}, Dst: dst("*", "*")}}, false)
	// An ssh rule says nothing of a network pair, whatever it is gated on: the ssh expectations
	// read it (TestSSHLimitsAreFoundFromTheSSHRules).
	want("an ssh rule is no limit of a network expectation", []acl.AccessRule{{Section: "ssh", Index: 1, Src: []string{"*"}, Dst: dst("tag:example-db", ""), Users: []string{"root"}, Posture: true}}, false)
	// What the policy holds and this version did not list or read cannot be ruled out.
	unreadable := acl.AccessRule{Section: "acls", Index: 3, Unreadable: true}
	want("a rule that cannot be read", []acl.AccessRule{unreadable}, false, security.LimitRules)
	want("an unreadable ssh rule is no limit of a network expectation", []acl.AccessRule{{Section: "ssh", Index: 3, Unreadable: true}}, false)
	if got := (ruleMatcher{a: &acl.Access{OmittedRules: 1}}).networkLimits([]string{"tag:example-db:22"}, true); !reflect.DeepEqual(got, []security.AccessLimit{security.LimitRules}) {
		t.Errorf("rules past the cap: limits = %v, want the rules limit, even when attributes are given", got)
	}
	if got := (ruleMatcher{a: &acl.Access{DefaultPosture: true}}).networkLimits([]string{"tag:example-db:22"}, false); !reflect.DeepEqual(got, []security.AccessLimit{security.LimitPosture}) {
		t.Errorf("a default posture: limits = %v", got)
	}
}

// A rule is set aside only when it is shown to be about other destinations: addresses that do not
// overlap, or ports that leave out the port. Tags, groups and autogroups are never shown to
// differ, a device may carry several tags, and an app grant is not made other by its ports.
func TestAPostureRuleIsSetAsideOnlyWhenShownToBeAboutOtherDestinations(t *testing.T) {
	dst := func(sel, ports string) []acl.AccessDst { return []acl.AccessDst{{Selector: sel, Ports: ports}} }
	cases := []struct {
		name  string
		rule  acl.AccessRule
		dsts  []string
		apart bool
	}{
		{"a different range of addresses", acl.AccessRule{Section: "acls", Dst: dst("198.51.100.0/24", "22")}, []string{"192.0.2.5:22"}, true},
		{"a range that holds the address", acl.AccessRule{Section: "acls", Dst: dst("192.0.2.0/24", "22")}, []string{"192.0.2.5:22"}, false},
		{"a host alias for another range", acl.AccessRule{Section: "acls", Dst: dst("example-range", "22")}, []string{"192.0.2.5:22"}, true},
		{"a host alias for the same range", acl.AccessRule{Section: "acls", Dst: dst("example-host", "22")}, []string{"192.0.2.10:22"}, false},
		{"an address of the other family is not shown to differ", acl.AccessRule{Section: "acls", Dst: dst("198.51.100.0/24", "22")}, []string{"[fd7a:115c:a1e0::5]:22"}, false},
		{"another tag, the same port", acl.AccessRule{Section: "acls", Dst: dst("tag:example-web", "22")}, []string{"tag:example-db:22"}, false},
		{"another tag, ports that leave 22 out", acl.AccessRule{Section: "acls", Dst: dst("tag:example-web", "443")}, []string{"tag:example-db:22"}, true},
		{"a grant whose ip entries leave 22 out", acl.AccessRule{Section: "grants", Dst: dst("tag:example-web", ""), IP: []string{"tcp:443", "udp:53"}}, []string{"tag:example-db:22"}, true},
		{"a grant for every port", acl.AccessRule{Section: "grants", Dst: dst("tag:example-web", ""), IP: []string{"*"}}, []string{"tag:example-db:22"}, false},
		{"a grant with no ip entries", acl.AccessRule{Section: "grants", Dst: dst("tag:example-web", "")}, []string{"tag:example-db:22"}, false},
		{"an app grant is not made other by ports", acl.AccessRule{Section: "grants", Dst: dst("tag:example-web", ""), IP: []string{"tcp:443"}, App: true}, []string{"tag:example-db:22"}, false},
		{"an app grant to another range", acl.AccessRule{Section: "grants", Dst: dst("198.51.100.0/24", ""), App: true}, []string{"192.0.2.5:22"}, true},
		{"one of two destinations of the rule is the same", acl.AccessRule{Section: "acls", Dst: []acl.AccessDst{{Selector: "198.51.100.0/24", Ports: "22"}, {Selector: "192.0.2.0/24", Ports: "22"}}}, []string{"192.0.2.5:22"}, false},
		{"one of two destinations of the expectation is the same", acl.AccessRule{Section: "acls", Dst: dst("198.51.100.0/24", "22")}, []string{"192.0.2.5:22", "198.51.100.9:22"}, false},
		{"a destination that is no host:port", acl.AccessRule{Section: "acls", Dst: dst("198.51.100.0/24", "22")}, []string{"nonsense"}, false},
		{"a rule with no destination", acl.AccessRule{Section: "acls"}, []string{"tag:example-db:22"}, true},
		{"the wildcard", acl.AccessRule{Section: "acls", Dst: dst("*", "*")}, []string{"192.0.2.5:22"}, false},
	}
	m := ruleMatcher{a: accessOf()}
	for _, c := range cases {
		if got := m.apart(c.rule, c.dsts); got != c.apart {
			t.Errorf("%s: apart = %v, want %v", c.name, got, c.apart)
		}
	}
}

// A group that lists a large group many times, under many rules, would make the search of the
// rules quadratic or worse in the policy's own size. The search has a budget: a step is a
// selector compared or a member of a group visited, the budget is spent once, and what is left
// unsearched is "not covered": the lists may be short, a limit is raised, and no verdict moves.
func TestTheSearchOfRulesHasABudgetAndHonoursItsContext(t *testing.T) {
	var members, nested []string
	for i := 0; i < 5000; i++ {
		members = append(members, fmt.Sprintf("user%d@example.com", i))
	}
	for i := 0; i < 200; i++ {
		nested = append(nested, "group:example-big")
	}
	a := &acl.Access{Groups: map[string][]string{"group:example-big": members, "group:example-many": nested}}
	for i := 1; i <= 600; i++ {
		a.Rules = append(a.Rules, acl.AccessRule{Section: "acls", Index: i, Src: []string{"group:example-many"}, Dst: []acl.AccessDst{{Selector: "tag:example-db", Ports: "22"}}, Posture: true})
	}
	set := security.IntentSet{Network: []security.NetworkExpectation{{ID: "network-1", Source: "nobody@example.com", Accept: []string{"tag:example-db:22"}}}}
	// Without a budget this is 600 rules x 200 groups x 5,000 members = 600 million steps.
	w := newMatchMeter(context.Background(), 100_000)
	m := ruleMatcher{a: a, w: w}
	if h := m.network("nobody@example.com", []string{"tag:example-db:22"}); h.total != 0 {
		t.Errorf("a source nobody has matched: %+v", h)
	}
	// The meter counts what was asked of it, the refused requests too: a search that walked on after
	// it was refused would show as a count past the budget (an unmoving count of steps used would not).
	if !w.spent() || w.asked > 100_000+8 {
		t.Errorf("the search asked for %d steps against a budget of 100000 (spent %v): it went on past it", w.asked, w.spent())
	}
	// Past the budget a rule is not shown to be about other destinations, so it counts, and what was
	// not searched was not ruled out: the rules limit stands beside the posture limit.
	limits := ruleMatcher{a: a, w: newMatchMeter(context.Background(), 0)}.networkLimits([]string{"tag:example-db:443"}, false)
	if !reflect.DeepEqual(limits, []security.AccessLimit{security.LimitPosture, security.LimitRules}) {
		t.Errorf("limits = %v with the budget spent, want the posture and the rules limits", limits)
	}
	// The command reports the lists as short when the budget ran out, and its steps are bounded.
	_, _, _, partial, err := explainRules(context.Background(), &explainFacts{access: a}, set, all)
	if err != nil || !partial {
		t.Errorf("the search of 600 rules under a large nested group: partial %v err %v, want partial", partial, err)
	}
	// A context that is done stops the search, and the command, with its error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, _, err := explainRules(ctx, &explainFacts{access: a}, set, all); err == nil {
		t.Error("a cancelled call was not stopped by the search of the rules")
	}
	if got := (*matchMeter)(nil); !got.tick(1<<30) || got.spent() {
		t.Error("a nil meter has no limit")
	}
}

// Each comparison of a selector with a name is a step of the budget, groups or no groups: a policy
// of thousands of rules searched for an expectation with thousands of destinations is bounded
// by the budget as much as one with large groups.
func TestEachComparisonOfTheSearchCostsAStep(t *testing.T) {
	var rules []acl.AccessRule
	for i := 1; i <= 50; i++ {
		rules = append(rules, acl.AccessRule{Section: "acls", Index: i, Src: []string{"tag:example-other"}, Dst: []acl.AccessDst{{Selector: "tag:example-db", Ports: "22"}}})
	}
	w := newMatchMeter(context.Background(), 1<<30)
	if h := (ruleMatcher{a: accessOf(rules...), w: w}).network("tag:example-web", []string{"tag:example-db:22"}); h.total != 0 {
		t.Fatalf("candidates = %+v", h)
	}
	if w.used < 50 {
		t.Errorf("the search of 50 rules cost %d steps, want at least 50", w.used)
	}
	// With a budget of ten steps, the rest of the rules are not compared.
	small := newMatchMeter(context.Background(), 10)
	(ruleMatcher{a: accessOf(rules...), w: small}).network("tag:example-web", []string{"tag:example-db:22"})
	if !small.spent() || small.asked > 11 {
		t.Errorf("a budget of 10 steps: %d asked for, spent %v", small.asked, small.spent())
	}
}
