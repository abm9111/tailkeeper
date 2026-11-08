package tools

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/security"
)

// The work budget of the search of the rules is a budget of work, not of counting. A search that is
// refused a step asks for no more: the meter's asked field counts every request, the refused ones
// too, so a search that went on walking after it was refused shows as a count far past its budget.
// The shapes are the review's (rules with a wildcard source and thousands of destinations, an
// expectation with thousands of destinations) scaled to run fast.

// selectors are n selectors named prefix0 ... prefix(n-1), each with the port.
func selectors(prefix, ports string, n int) []acl.AccessDst {
	out := make([]acl.AccessDst, n)
	for i := range out {
		out[i] = acl.AccessDst{Selector: fmt.Sprintf("%s%d", prefix, i), Ports: ports}
	}
	return out
}

// names are n names prefix0 ... prefix(n-1) followed by the suffix.
func names(prefix, suffix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d%s", prefix, i, suffix)
	}
	return out
}

// repeated is n rules of one section with the same source, destinations and users.
func repeated(section string, n int, src []string, dst []acl.AccessDst, users []string) []acl.AccessRule {
	out := make([]acl.AccessRule, n)
	for i := range out {
		out[i] = acl.AccessRule{Section: section, Index: i + 1, Line: i + 2, Column: 3, Src: src, Dst: dst, Users: users}
	}
	return out
}

// The meter counts every request for a step, the refused ones too, and stops counting what it
// grants once it is spent.
func TestTheMeterCountsEveryRequestForAStepTheRefusedOnesToo(t *testing.T) {
	w := newMatchMeter(context.Background(), 3)
	var granted []bool
	for i := 0; i < 5; i++ {
		granted = append(granted, w.tick(1))
	}
	if !reflect.DeepEqual(granted, []bool{true, true, true, false, false}) || w.asked != 5 || w.used != 4 || !w.spent() {
		t.Errorf("granted %v, asked %d, used %d, spent %v, want three steps granted, five asked, four used", granted, w.asked, w.used, w.spent())
	}
}

func TestASpentSearchStopsWalkingAtOnce(t *testing.T) {
	const slack = 8 // the steps a search may ask for past the one that is refused: the levels it unwinds through
	wild := []string{"*"}
	expDsts := names("tag:example-d", ":22", 500)
	cases := []struct {
		name   string
		limit  int64
		cancel bool
		rules  []acl.AccessRule
		run    func(m ruleMatcher)
	}{
		{"wildcard sources, many destinations on both sides", 2000, false,
			repeated("acls", 100, wild, selectors("tag:example-r", "22", 500), nil),
			func(m ruleMatcher) { m.network("tag:example-web", expDsts) }},
		{"a wildcard source costs a step even when there is nothing to compare", 100, false,
			repeated("acls", 1000, wild, nil, nil),
			func(m ruleMatcher) { m.network("tag:example-web", nil) }},
		{"destinations of an expectation against rules that name none", 2000, false,
			repeated("acls", 100, wild, nil, nil),
			func(m ruleMatcher) { m.network("tag:example-web", expDsts) }},
		{"thousands of source selectors in one rule", 100, false,
			repeated("acls", 1, names("tag:example-s", "", 5000), selectors("tag:example-r", "22", 5), nil),
			func(m ruleMatcher) { m.network("tag:example-web", expDsts[:5]) }},
		{"destinations of ssh rules", 1777, false,
			repeated("ssh", 100, wild, selectors("tag:example-r", "", 500), []string{"*"}),
			func(m ruleMatcher) { m.ssh("tag:example-web", names("tag:example-d", "", 500), []string{"root"}) }},
		{"users of an ssh expectation against the users of ssh rules", 2000, false,
			repeated("ssh", 100, wild, selectors("tag:example-db", "", 1), names("u", "", 20)),
			func(m ruleMatcher) { m.ssh("tag:example-web", []string{"tag:example-db0"}, names("x", "", 2000)) }},
		{"a cancelled call", 1 << 40, true,
			repeated("acls", 100, wild, selectors("tag:example-r", "22", 500), nil),
			func(m ruleMatcher) { m.network("tag:example-web", expDsts) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if c.cancel {
				cancel()
			}
			w := newMatchMeter(ctx, c.limit)
			c.run(ruleMatcher{a: accessOf(c.rules...), w: w})
			if !w.spent() {
				t.Fatalf("the search asked for %d steps against a budget of %d and was not stopped (cancelled %v)", w.asked, c.limit, c.cancel)
			}
			if w.asked == 0 {
				t.Fatal("the meter counted no request: the bound below would hold of any search")
			}
			bound := c.limit + slack
			if c.cancel {
				if w.err == nil {
					t.Fatal("the context is done and the meter did not see it")
				}
				bound = 4096 + slack // the context is looked at every 4,096 steps
			}
			if w.asked > bound {
				t.Errorf("the search asked for %d steps and was refused: it went on walking past a bound of %d", w.asked, bound)
			}
		})
	}
}

// What a search that was cut short did not search it did not rule out: a network expectation
// whose search reached the budget has the rules limit, and so has every one searched after it. One
// whose search was whole has none; an ssh expectation is cut short the same way (an ssh rule can
// depend on posture).
func TestASearchCutShortRaisesTheRulesLimitOfTheExpectationsItCut(t *testing.T) {
	facts := &explainFacts{access: accessOf(repeated("acls", 100, []string{"*"}, selectors("tag:example-r", "22", 50), nil)...)}
	set := security.IntentSet{
		Network: []security.NetworkExpectation{
			{ID: "network-1", Source: "tag:example-a", Deny: []string{"tag:example-x0:22"}},
			{ID: "network-2", Source: "tag:example-b", Deny: names("tag:example-x", ":22", 50)},
		},
		SSH: []security.SSHExpectation{{ID: "ssh-1", Source: "tag:example-c", Destinations: []string{"tag:example-db"}, Accept: []string{"root"}}},
	}
	judged := map[string]bool{"network-1": true, "network-2": true, "ssh-1": true}
	hasRules := func(limits map[string][]security.AccessLimit, id string) bool {
		for _, l := range limits[id] {
			if l == security.LimitRules {
				return true
			}
		}
		return false
	}
	// The first expectation costs 10,400 steps (100 rules, each 2 for its sources, 51 for reading its 50 port specs,
	// and 1 x (1 + 50) for the walk); the second costs far more.
	_, limits, _, partial, err := explainRulesWith(newMatchMeter(context.Background(), 11000), facts, set, judged)
	if err != nil {
		t.Fatal(err)
	}
	if !partial {
		t.Error("a search that reached its budget has complete lists")
	}
	if hasRules(limits, "network-1") {
		t.Errorf("network-1 was searched whole and has the limits %v", limits["network-1"])
	}
	if !reflect.DeepEqual(limits["network-2"], []security.AccessLimit{security.LimitRules}) {
		t.Errorf("network-2 was cut short and has the limits %v, want the rules limit", limits["network-2"])
	}
	if !hasRules(limits, "ssh-1") {
		t.Errorf("ssh-1 has the limits %v: it was searched after the budget was used, and an ssh rule can depend on posture, so what was not searched is not ruled out", limits["ssh-1"])
	}
	// The same policy and intent with a budget that is enough: no limit and complete lists.
	_, limits, _, partial, err = explainRulesWith(newMatchMeter(context.Background(), 1<<30), facts, set, judged)
	if err != nil || partial || len(limits) != 0 {
		t.Errorf("a search within its budget: limits %v partial %v err %v, want none", limits, partial, err)
	}
	// A call cancelled in the middle of the search is the context's error, and the walk ends.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := newMatchMeter(ctx, 1<<40)
	if _, _, _, _, err := explainRulesWith(w, facts, set, judged); err == nil || w.asked > 4096+8 {
		t.Errorf("a cancelled call: err %v after %d steps asked", err, w.asked)
	}
}

// A user of the expectation compared with an ssh rule costs a step for each of the rule's users and
// one more, so that a rule with thousands of users against an expectation with thousands of users
// spends the budget as the work it is.
func TestAnSSHUserComparisonCostsAStepForEachUserOfTheRule(t *testing.T) {
	w := newMatchMeter(context.Background(), 1<<30)
	m := ruleMatcher{a: accessOf(), w: w}
	if m.usersCovered(names("u", "", 20), names("x", "", 10)) {
		t.Fatal("users that are none of the rule's were covered")
	}
	if want := int64(10 * (1 + 20)); w.used != want {
		t.Errorf("10 users against a rule of 20 cost %d steps, want %d", w.used, want)
	}
}

// The walks that show a rule to be about other users or other destinations cost a step for every
// comparison they make, and the steps are counted exactly, so that a walk which drops its meter, or
// charges a part of what it reads, is noticed by the count and not by the time it takes: with the
// meter dropped, a posture-gated rule of thousands of users or destinations against an expectation
// of thousands runs unbounded. The shapes are small; the products are what is checked.
func TestTheWalksThatShowARuleToBeAboutOthersCostAStepForEachComparison(t *testing.T) {
	addresses := func(format string, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf(format, i+1)
		}
		return out
	}
	ruleDsts := func(n int, ports string) []acl.AccessDst {
		out := make([]acl.AccessDst, n)
		for i, a := range addresses("192.0.2.%d", n) {
			out[i] = acl.AccessDst{Selector: a, Ports: ports}
		}
		return out
	}
	// One walk: what it is, how to run it on a meter, and what it must cost when it completes.
	walks := []struct {
		name string
		run  func(m ruleMatcher) bool // the walk, which says "apart" when it completes
		cost func(prepared int64) int64
	}{
		{
			"the users of an ssh rule",
			func(m ruleMatcher) bool { return m.usersApart(names("u", "", 20), names("x", "", 10)) },
			func(int64) int64 { return (1 + 20) + 10*(1+20) }, // the look through the rule's users, then each user of the expectation against them
		},
		{
			"the destinations of an ssh rule",
			func(m ruleMatcher) bool {
				return m.destinationsApart(acl.AccessRule{Dst: ruleDsts(7, "")}, addresses("198.51.100.%d", 5))
			},
			func(int64) int64 { return 7 * 5 },
		},
		{
			"the destinations of a network rule",
			func(m ruleMatcher) bool {
				return m.apart(acl.AccessRule{Section: "acls", Dst: ruleDsts(7, "22")}, addresses("198.51.100.%d:22", 5))
			},
			func(prepared int64) int64 { return prepared + 7*5 }, // reading the rule's ports once, then each pair of destinations
		},
	}
	for _, c := range walks {
		// What reading the rule costs before any comparison is made: the preparation of a network rule.
		var prepared int64
		if c.name == "the destinations of a network rule" {
			pw := newMatchMeter(context.Background(), 1<<30)
			ruleMatcher{a: accessOf(), w: pw}.prepare(acl.AccessRule{Section: "acls", Dst: ruleDsts(7, "22")})
			prepared = pw.used
		}
		w := newMatchMeter(context.Background(), 1<<30)
		if !c.run(ruleMatcher{a: accessOf(), w: w}) {
			t.Errorf("%s: disjoint users or destinations were not shown to be apart", c.name)
		}
		if want := c.cost(prepared); w.used != want {
			t.Errorf("%s: the walk cost %d steps, want %d", c.name, w.used, want)
		}
		// A meter that refuses ends the walk at the next request, and a rule not walked to the end is not
		// shown to be about others: the rule counts.
		small := newMatchMeter(context.Background(), c.cost(prepared)/2)
		if c.run(ruleMatcher{a: accessOf(), w: small}) || !small.spent() || small.asked > small.limit+2 {
			t.Errorf("%s: with a budget of %d the walk was spent %v after %d requests; want it stopped, and not apart", c.name, small.limit, small.spent(), small.asked)
		}
	}
}

// The ports a grant's ip entries name are walked for every comparison of a destination with the
// grant, so each entry checked is a step of the budget: a grant with thousands of entries against an
// expectation with thousands of destinations is the product, and the meter charges it. The shape is
// the review's (5,000 tcp:N entries against 5,000 destinations) scaled to run fast.
func TestAGrantsPortEntriesAreMeteredOneByOne(t *testing.T) {
	const limit = 5000
	ip := make([]string, 2000)
	for i := range ip {
		ip[i] = fmt.Sprintf("tcp:%d", i+1)
	}
	dsts := names("tag:example-d", ":60000", 500) // a port no entry names: every entry is checked
	grant := acl.AccessRule{Section: "grants", Index: 1, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "*"}}, IP: ip}
	cases := []struct {
		name string
		run  func(m ruleMatcher)
	}{
		{"candidates", func(m ruleMatcher) { m.network("tag:example-web", dsts) }},
		{"the limits of a rule gated on posture", func(m ruleMatcher) {
			gated := grant
			gated.Posture = true
			m.a.Rules = []acl.AccessRule{gated}
			m.networkLimits(dsts, false)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newMatchMeter(context.Background(), limit)
			c.run(ruleMatcher{a: accessOf(grant), w: w})
			if w.asked == 0 {
				t.Fatal("the meter counted no request")
			}
			if !w.spent() {
				t.Fatalf("1,000,000 port checks asked for %d steps against a budget of %d and were not stopped", w.asked, limit)
			}
			if w.asked > limit+8 {
				t.Errorf("the search asked for %d steps and was refused: it went on walking past a bound of %d", w.asked, limit+8)
			}
		})
	}
}

// A port check the meter refused shows nothing about the rule, so the rule is not a candidate
// for it: the search ends there with no candidate, and the lists are short.
func TestARefusedPortCheckIsNotACandidate(t *testing.T) {
	ip := make([]string, 2000)
	for i := range ip {
		ip[i] = fmt.Sprintf("tcp:%d", i+1)
	}
	grant := acl.AccessRule{Section: "grants", Index: 1, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "*"}}, IP: ip}
	w := newMatchMeter(context.Background(), 2100) // the rule is read (2,001 steps) and its entries run out of budget
	h := ruleMatcher{a: accessOf(grant), w: w}.network("tag:example-web", []string{"tag:example-db:60000"})
	if !w.spent() || h.total != 0 {
		t.Errorf("spent %v, %d candidates: a rule whose port entries were not all checked was listed", w.spent(), h.total)
	}
}

// What a grant allows of ports and protocols is read once for the rule, and not rebuilt for each
// destination that matches it: the port specs of its ip entries and the text of its traffic.
func TestAGrantsPortsAndTrafficAreBuiltOncePerRule(t *testing.T) {
	ip := make([]string, 2000)
	for i := range ip {
		ip[i] = fmt.Sprintf("tcp:%d", i+1)
	}
	grant := acl.AccessRule{Section: "grants", Index: 1, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "*"}}, IP: ip}
	m := ruleMatcher{a: accessOf(grant)}
	dsts := names("tag:example-d", ":22", 500) // port 22 is an entry: every destination matches
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	h := m.network("tag:example-web", dsts)
	runtime.ReadMemStats(&after)
	if h.total != 1 || h.refs[0].Traffic == "" {
		t.Fatalf("candidates = %+v, want the one grant with its traffic", h)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
		t.Errorf("500 destinations matched a grant of 2,000 entries and allocated %d bytes: the ports or the traffic are rebuilt for each", got)
	}
}

// A meter that refuses ends the walks that follow it at the next request, not after the last
// rule or the last tag: the limits of a network expectation and the tags a source can apply.
func TestASpentMeterEndsTheLimitsAndTheTagWalkAtOnce(t *testing.T) {
	const slack = 8
	rule := acl.AccessRule{Section: "acls", Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "tag:example-web", Ports: "22"}}, Posture: true}
	rules := make([]acl.AccessRule, 4096)
	for i := range rules {
		rules[i] = rule
		rules[i].Index = i + 1
	}
	spentMeter := func() *matchMeter {
		w := newMatchMeter(context.Background(), 0)
		w.tick(1) // the budget is used
		return w
	}
	t.Run("the limits of a network expectation", func(t *testing.T) {
		w := spentMeter()
		got := ruleMatcher{a: &acl.Access{Rules: rules}, w: w}.networkLimits([]string{"tag:example-db:22"}, false)
		if w.asked > 1+slack {
			t.Errorf("4,096 rules were walked after the budget was used: %d requests asked", w.asked)
		}
		if !slices.Contains(got, security.LimitRules) {
			t.Errorf("limits = %v: what was not walked was not ruled out, so the rules limit stands", got)
		}
	})
	owners := map[string][]string{}
	for i := 0; i < 3000; i++ {
		owners[fmt.Sprintf("tag:example-t%d", i)] = names("someone", "@example.com", 5)
	}
	t.Run("the tags a source owns, with the budget used", func(t *testing.T) {
		w := spentMeter()
		ruleMatcher{a: &acl.Access{TagOwners: owners}, w: w}.tagsOwnedBy("nobody@example.com")
		if w.asked > 1+slack {
			t.Errorf("the tag walk went on after the budget was used: %d requests asked", w.asked)
		}
	})
	t.Run("the tags a source owns, metered", func(t *testing.T) {
		w := newMatchMeter(context.Background(), 100)
		ruleMatcher{a: &acl.Access{TagOwners: owners}, w: w}.tagsOwnedBy("nobody@example.com")
		if !w.spent() || w.asked > 100+slack {
			t.Errorf("15,000 owners walked: spent %v after %d requests, want the walk stopped within a budget of 100", w.spent(), w.asked)
		}
	})
	t.Run("a cancelled call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		w := newMatchMeter(ctx, 1<<40)
		ruleMatcher{a: &acl.Access{TagOwners: owners}, w: w}.tagsOwnedBy("nobody@example.com")
		if w.err == nil || w.asked > 4096+slack {
			t.Errorf("err %v after %d requests asked, want the context seen within 4,096 and the walk ended", w.err, w.asked)
		}
	})
}

// Reading a rule once costs a step for the rule, one for each proto and one for each part of each port spec it reads,
// and a meter that refuses it makes the rule unread.
func TestPreparingARuleChargesEachEntryItReads(t *testing.T) {
	ip := make([]string, 300)
	for i := range ip {
		ip[i] = fmt.Sprintf("tcp:%d", i+1)
	}
	grant := acl.AccessRule{Section: "grants", Dst: []acl.AccessDst{{Selector: "*"}}, IP: ip}
	rule := acl.AccessRule{Section: "acls", Dst: []acl.AccessDst{{Selector: "*", Ports: "22"}}, Proto: []string{"tcp", "udp"}}
	w := newMatchMeter(context.Background(), 1<<30)
	m := ruleMatcher{a: accessOf(), w: w}
	if _, ok := m.prepare(grant); !ok || w.used != 301 {
		t.Errorf("a grant of 300 entries cost %d steps (ok %v), want 301", w.used, ok)
	}
	w.used = 0
	if _, ok := m.prepare(rule); !ok || w.used != 4 {
		t.Errorf("an acls rule with two protos and one port spec cost %d steps (ok %v), want 4", w.used, ok)
	}
	small := ruleMatcher{a: accessOf(), w: newMatchMeter(context.Background(), 10)}
	if _, ok := small.prepare(grant); ok {
		t.Error("a rule was read past the budget")
	}
	// A port list is paid for by its parts: a destination that lists a thousand ports costs a thousand.
	parts := make([]string, 1000)
	for i := range parts {
		parts[i] = fmt.Sprint(2*i + 1)
	}
	long := acl.AccessRule{Section: "acls", Dst: []acl.AccessDst{{Selector: "*", Ports: strings.Join(parts, ",")}, {Selector: "tag:example-db", Ports: "22"}}}
	w.used = 0
	if _, ok := m.prepare(long); !ok || w.used != 1+1000+1 {
		t.Errorf("an acls rule with a list of 1,000 ports and another port cost %d steps (ok %v), want 1,002", w.used, ok)
	}
}

// Whether a rule's ports include a port is a step of the budget for each destination checked (an acls
// rule) or each ip entry (a grant), a spec that cannot be read may name any port, and a check the
// meter refuses says the rule may.
func TestANamesPortCheckIsAStepAndAnUnreadableSpecNamesAnyPort(t *testing.T) {
	w := newMatchMeter(context.Background(), 1<<30)
	m := ruleMatcher{a: accessOf(), w: w}
	acls, _ := m.prepare(acl.AccessRule{Section: "acls", Dst: []acl.AccessDst{{Selector: "*", Ports: "22,80-90"}, {Selector: "*", Ports: "not ports"}}})
	grant, _ := m.prepare(acl.AccessRule{Section: "grants", Dst: []acl.AccessDst{{Selector: "*"}}, IP: []string{"tcp:22", "udp:53"}})
	none, _ := m.prepare(acl.AccessRule{Section: "grants", Dst: []acl.AccessDst{{Selector: "*"}}})
	w.used = 0
	for name, c := range map[string]struct {
		n    netRule
		i    int
		port int
		want bool
		cost int64
	}{
		"an acls destination that names the port":   {acls, 0, 85, true, 1},
		"an acls destination that does not":         {acls, 0, 91, false, 1},
		"an acls destination that cannot be read":   {acls, 1, 91, true, 1},
		"a grant with an entry that names the port": {grant, 0, 53, true, 2},
		"a grant that names it in the first entry":  {grant, 0, 22, true, 1},
		"a grant with no entry that names the port": {grant, 0, 23, false, 2},
		"a grant with no ip entries (an app grant)": {none, 0, 23, true, 0},
	} {
		w.used = 0
		if got := m.namesPort(c.n, c.i, c.port); got != c.want || w.used != c.cost {
			t.Errorf("%s: namesPort = %v after %d steps, want %v after %d", name, got, w.used, c.want, c.cost)
		}
	}
	refused := ruleMatcher{a: accessOf(), w: newMatchMeter(context.Background(), 0)}
	refused.w.tick(1)
	if !refused.namesPort(acls, 0, 91) || !refused.namesPort(grant, 0, 23) {
		t.Error("a check the meter refused said the rule leaves the port out")
	}
}

// The ports of an acls destination are read once for the rule and charged by their parts: one
// destination listing a thousand ports, compared with a thousand destinations of an expectation, is a
// thousand comparisons of one set and not a thousand readings of the list. The shape is the review's
// (the odd ports below 10,000 against 5,000 destinations) scaled down.
func TestAnACLDestinationsPortListIsReadOnceAndCharged(t *testing.T) {
	parts := make([]string, 1000)
	for i := range parts {
		parts[i] = fmt.Sprint(2*i + 1)
	}
	rule := acl.AccessRule{Section: "acls", Index: 1, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "*", Ports: strings.Join(parts, ",")}}}
	dsts := names("tag:example-d", ":60000", 1000) // no port of the list: every destination is compared
	w := newMatchMeter(context.Background(), 1<<30)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	h := ruleMatcher{a: accessOf(rule), w: w}.network("tag:example-web", dsts)
	runtime.ReadMemStats(&after)
	if h.total != 0 {
		t.Fatalf("candidates = %+v: port 60000 is none of the odd ports below 2,000", h)
	}
	if w.used < 1000 {
		t.Errorf("reading a list of 1,000 ports was charged %d steps in all", w.used)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 2<<20 {
		t.Errorf("1,000 destinations were compared with a list of 1,000 ports and allocated %d bytes: the list is read again for each", got)
	}
	// With less budget than the list has parts, the rule is not read at all and the search ends.
	small := newMatchMeter(context.Background(), 500)
	h = ruleMatcher{a: accessOf(rule), w: small}.network("tag:example-web", dsts)
	if !small.spent() || h.total != 0 || small.asked > 500+8 {
		t.Errorf("spent %v, %d candidates, %d requests asked: a rule whose ports the budget cannot pay for was read", small.spent(), h.total, small.asked)
	}
}

// What an acls destination allows is written once for the rule, and not rebuilt for each destination
// of the expectation that it matches: one wildcard destination listing the odd ports below 2,000,
// compared with 5,000 destinations on a port of the list. The shape is the review's (the odd ports
// below 10,000 against 5,000 destinations on port 1, about 122 MB of copying) with a shorter list;
// the text of the traffic and the ports it quotes are the rule's, cut, as they were before. Reading
// the list takes about 165 KB; building the text for each match, even of a cut list, another 1.5 MB.
func TestAnACLDestinationsTrafficTextIsBuiltOncePerRule(t *testing.T) {
	parts := make([]string, 1000)
	for i := range parts {
		parts[i] = fmt.Sprint(2*i + 1)
	}
	list := strings.Join(parts, ",")
	rule := acl.AccessRule{Section: "acls", Index: 1, Src: []string{"*"}, Dst: []acl.AccessDst{{Selector: "*", Ports: list}}}
	dsts := names("tag:example-d", ":1", 5000) // port 1 is in the list: every destination matches
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	h := ruleMatcher{a: accessOf(rule), w: newMatchMeter(context.Background(), 1<<30)}.network("tag:example-web", dsts)
	runtime.ReadMemStats(&after)
	if h.total != 1 {
		t.Fatalf("candidates = %+v, want the one rule", h)
	}
	want := cutRunes(list, maxSelectorText)
	wantTraffic := cutRunes("ports "+list, maxSelectorText)
	if got := h.refs[0]; got.Ports != want || got.Traffic != wantTraffic || got.AllTraffic {
		t.Errorf("candidate = %+v, want its ports %q and the traffic %q", got, want, wantTraffic)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 600<<10 {
		t.Errorf("5,000 destinations matched a destination listing 1,000 ports and allocated %d bytes: the text of the traffic is rebuilt for each", got)
	}
}

// A tag that has no owners costs the walk a step as much as one that has: a policy of ten thousand
// tags with an empty owner list is walked within the budget like any other, and the walk ends when
// the meter refuses.
func TestTheWalkOfTagsWithNoOwnersIsMetered(t *testing.T) {
	const slack = 8
	owners := map[string][]string{}
	for i := 0; i < 10000; i++ {
		owners[fmt.Sprintf("tag:example-t%d", i)] = nil
	}
	a := &acl.Access{TagOwners: owners}
	w := newMatchMeter(context.Background(), 100)
	if got := (ruleMatcher{a: a, w: w}).tagsOwnedBy("nobody@example.com"); len(got) != 0 || !w.spent() || w.asked > 100+slack {
		t.Errorf("10,000 tags with no owners: %v owned, spent %v after %d requests, want the walk stopped within a budget of 100", got, w.spent(), w.asked)
	}
	w = newMatchMeter(context.Background(), 1<<30)
	(ruleMatcher{a: a, w: w}).tagsOwnedBy("nobody@example.com")
	if w.used < 10000 {
		t.Errorf("10,000 tags with no owners were walked for %d steps, want a step for each", w.used)
	}
}

// The looks through a list for the wildcard source, and for a user selector that cannot be resolved,
// read the whole list, so each costs a step for every selector it reads.
func TestThePrescansOfASelectorListAreCharged(t *testing.T) {
	sels := names("tag:example-s", "", 5000)
	w := newMatchMeter(context.Background(), 1<<30)
	if sel, ok := (ruleMatcher{a: accessOf(), w: w}).firstCovering(append(slices.Clone(sels), "*"), "tag:example-x"); !ok || sel != "*" || w.used < 5000 {
		t.Errorf("the wildcard found at the end of 5,001 selectors: (%q, %v) after %d steps, want at least 5,000", sel, ok, w.used)
	}
	w = newMatchMeter(context.Background(), 1<<30)
	users := append(names("u", "", 5000), "localpart:*@example.com")
	if (ruleMatcher{a: accessOf(), w: w}).usersApart(users, []string{"root"}) || w.used < 5000 {
		t.Errorf("a user selector that cannot be resolved at the end of 5,001: %d steps, want at least 5,000 and not apart", w.used)
	}
	small := newMatchMeter(context.Background(), 100)
	if (ruleMatcher{a: accessOf(), w: small}).usersApart(users, []string{"root"}) || !small.spent() {
		t.Error("a list longer than the budget was read")
	}
}
