package tools

import (
	"context"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/security"
)

// The rules an explanation cites are candidates: rules of the live policy whose selectors match
// a pair as text. This file decides nothing about access. It never decides a verdict (those come
// from Tailscale's validation, in security_explain_witness.go) and it cites a rule only to give
// the owner a place to look. What it matches is deliberately short of guessing: the same name,
// "*", a group that lists the name, a host alias or an address range that contains it, and
// autogroup:tagged for a tag. A selector it cannot resolve without guessing (autogroup:member for
// a login, localpart:*@domain for an ssh user) matches nothing, so a candidate list may be short;
// the report says so when the policy is larger than the list.

// maxSelectorText cuts the selectors a candidate quotes; a policy's names are short, and a
// result is not the place for one of a megabyte.
const maxSelectorText = 256

// maxMatchWork is the most steps one explanation spends matching rules: a selector compared with
// a name, a member of a group visited, a destination of a rule set against one of the
// expectation's. A policy can make the search quadratic or worse in its own size (a group that
// lists a large group many times, under many rules), so the search has a budget as the reading
// of the policy has one (acl.MaxWork). Past it, a match is "not covered" and a rule is "not shown
// to be about other destinations": the candidate lists may be short and a limit is raised, never
// a verdict made or taken away.
const maxMatchWork = 1 << 24

// matchMeter counts the steps of the search and checks the caller's context as it goes.
type matchMeter struct {
	ctx   context.Context
	limit int64
	used  int64
	err   error // the context's error, once it is done
	// asked counts every request for a step, the refused ones too: a search that obeys the meter
	// asks no more once it is refused, so the number is the work it did. A test reads it.
	asked int64
}

func newMatchMeter(ctx context.Context, limit int64) *matchMeter {
	return &matchMeter{ctx: ctx, limit: limit}
}

// tick spends n steps and says whether the search may go on. The context is looked at every
// 4,096 steps. A nil meter has no limit.
func (m *matchMeter) tick(n int) bool {
	if m == nil {
		return true
	}
	m.asked++
	if m.spent() {
		return false // a search that stopped counts nothing more, and must ask for nothing more
	}
	before := m.used
	m.used += int64(n)
	if m.used>>12 != before>>12 && m.err == nil {
		m.err = m.ctx.Err()
	}
	return m.err == nil && m.used <= m.limit
}

// spent says that the search stopped early: its budget is used or the context is done.
func (m *matchMeter) spent() bool { return m != nil && (m.err != nil || m.used > m.limit) }

// ruleMatcher matches the rules of one live policy, within the budget of w (none when nil).
type ruleMatcher struct {
	a *acl.Access
	w *matchMeter
}

// ruleHits is what a search of the rules found for one expectation: the first candidates (broad
// ones first, so that a cut keeps them) and how many matched in all. It decides no limit: what
// the test language cannot express is found by networkLimits, from the rules that are not shown
// to be about other destinations, whatever this matcher could or could not match.
type ruleHits struct {
	refs  []security.RuleRef
	total int
}

// isLogin says that a name is a login: an address with an at sign, and neither a prefix nor a
// colon of a selector.
func isLogin(s string) bool { return strings.Contains(s, "@") && !strings.Contains(s, ":") }

// sameName says that two selectors name the same thing as text. Logins are the one name that
// Tailscale reads without regard to case.
func sameName(a, b string) bool {
	if a == b {
		return true
	}
	return isLogin(a) && isLogin(b) && strings.EqualFold(a, b)
}

// groupHas says that a group lists the name, directly or through one group it lists. Each
// member visited is a step of the budget.
func (m ruleMatcher) groupHas(group, x string, depth int) bool {
	for _, member := range m.a.Groups[group] {
		if !m.w.tick(1) {
			return false
		}
		if sameName(member, x) {
			return true
		}
		if depth > 0 && strings.HasPrefix(member, "group:") && m.groupHas(member, x, depth-1) {
			return true
		}
	}
	return false
}

// prefixOf reads an address or a prefix.
func prefixOf(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// holds says that the range sel contains the address or range x.
func holds(sel, x string) bool {
	p, ok := prefixOf(sel)
	q, ok2 := prefixOf(x)
	return ok && ok2 && p.Addr().BitLen() == q.Addr().BitLen() && p.Bits() <= q.Bits() && p.Contains(q.Addr())
}

// covers says that the selector sel names x as text. It is not symmetric: "*" covers everything
// and nothing covers "*" but "*".
func (m ruleMatcher) covers(sel, x string) bool {
	if !m.w.tick(1) {
		return false
	}
	switch {
	case sel == "*":
		return true
	case sameName(sel, x), holds(sel, x):
		return true
	case strings.HasPrefix(sel, "group:") && m.groupHas(sel, x, 1):
		return true
	case sel == "autogroup:tagged":
		return strings.HasPrefix(x, "tag:")
	}
	if v, ok := m.a.Hosts[sel]; ok && (sameName(v, x) || holds(v, x)) {
		return true
	}
	v, ok := m.a.Hosts[x]
	return ok && (sameName(sel, v) || holds(sel, v))
}

// firstCovering is the first selector of a rule's sources that covers x, preferring "*". Looking
// for the wildcard is a step for each selector it reads, so that a policy of wildcard rules, or a
// source list with the wildcard last, is metered like any other, and the search stops at the
// selector that spends the budget.
func (m ruleMatcher) firstCovering(sels []string, x string) (string, bool) {
	if !m.w.tick(1 + len(sels)) { // the look for the wildcard reads the whole list
		return "", false
	}
	if slices.Contains(sels, "*") {
		return "*", true
	}
	for _, s := range sels {
		if m.covers(s, x) {
			return s, true
		}
		if m.w.spent() {
			break
		}
	}
	return "", false
}

// portNumber reads the port of a destination written host:port.
func portNumber(dst string) (host string, port int, ok bool) {
	h, p, err := splitDestination(dst)
	if err != nil {
		return "", 0, false
	}
	if len(h) > 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	n, err := strconv.Atoi(p)
	return h, n, err == nil
}

// grantPorts reads the port specs of a grant's ip entries ("tcp:22" and "443" are 22 and 443).
func grantPorts(ip []string) []string {
	var out []string
	for _, e := range ip {
		spec := e
		if i := strings.IndexByte(e, ':'); i > 0 {
			spec = e[i+1:]
		}
		out = append(out, spec)
	}
	return out
}

// portSpec is a port spec read once: the set it names, and whether it could be read. A spec that
// could not be read may name any port.
type portSpec struct {
	set      acl.PortSet
	readable bool
}

func readPortSpec(spec string) portSpec {
	set, ok := acl.ParsePortSet(spec)
	return portSpec{set: set, readable: ok}
}

// names says that the spec may name the port.
func (p portSpec) names(port int) bool { return !p.readable || p.set.Contains(port) }

// specEntries is how many parts a port spec is written with: what reading it costs.
func specEntries(spec string) int { return strings.Count(spec, ",") + 1 }

// netRule is a rule of acls or grants prepared once for the comparisons made against it: the ports
// of each of its destinations (an acls rule) or of each of its ip entries (a grant), read once, and
// the text of what the rule allows of protocols, so that no comparison of a destination with the
// rule reads or rebuilds them.
type netRule struct {
	acl.AccessRule
	ports []portSpec // an acls rule: of each destination, in order; a grant: of each ip entry
	ipAll bool       // a grant: the ip entries include *
	text  string     // a grant: its ip entries; an acls rule: its proto; as written, cut
}

// prepare reads a rule's ports and protocols once. It costs a step for the rule, one for each
// proto and one for each part of each port spec it reads; ok is false when the meter refuses.
func (m ruleMatcher) prepare(r acl.AccessRule) (netRule, bool) {
	n := netRule{AccessRule: r}
	var specs []string
	if r.Section == acl.RulesGrants {
		specs = grantPorts(r.IP)
	} else {
		for _, d := range r.Dst {
			specs = append(specs, d.Ports)
		}
	}
	cost := 1 + len(r.Proto)
	for _, spec := range specs {
		cost += specEntries(spec)
	}
	if !m.w.tick(cost) {
		return n, false
	}
	n.ports = make([]portSpec, len(specs))
	for i, spec := range specs {
		n.ports[i] = readPortSpec(spec)
	}
	if r.Section == acl.RulesGrants {
		n.ipAll = slices.Contains(r.IP, "*")
		n.text = cutRunes(strings.Join(r.IP, ", "), maxSelectorText)
	} else if len(r.Proto) > 0 {
		n.text = cutRunes("proto "+strings.Join(r.Proto, ","), maxSelectorText)
	}
	return n, true
}

// dstRef is what the rule quotes of a destination it matches: the destination, its ports when they
// limit the pair, and its traffic. It builds the text of the traffic, so it is made only for a
// destination that is to be quoted.
func (n netRule) dstRef(d acl.AccessDst) security.RuleRef {
	ref := security.RuleRef{Destination: cutRunes(d.Selector, maxSelectorText), Broad: d.Selector == "*"}
	if d.Ports != "" && d.Ports != "*" {
		ref.Ports = cutRunes(d.Ports, maxSelectorText)
	}
	ref.AllTraffic, ref.Traffic = n.traffic(d)
	return ref
}

// namesPort says that the ports of a rule's destination i include the port. A rule that states
// none (an app grant) or whose ports cannot be read may include it, which a list of candidates
// takes as including it. Each destination of an acls rule that is checked, and each port entry of
// a grant, is a step of the budget; a check the meter refuses says that the rule may include the
// port, for nothing shows it leaves it out, and the caller looks at the meter before it takes the
// answer.
func (m ruleMatcher) namesPort(n netRule, i, port int) bool {
	if n.Section != acl.RulesGrants {
		return !m.w.tick(1) || n.ports[i].names(port)
	}
	if len(n.IP) == 0 {
		return true
	}
	for _, p := range n.ports {
		if !m.w.tick(1) || p.names(port) {
			return true
		}
	}
	return false
}

// allTraffic says that the rule allows every port and every protocol to a destination; it builds
// nothing.
func (n netRule) allTraffic(d acl.AccessDst) bool {
	if n.Section == acl.RulesGrants {
		return n.ipAll
	}
	return len(n.Proto) == 0 && d.Ports == "*"
}

// traffic reads what the rule allows of ports and protocols, as it writes it, for a destination.
// all is true when it allows every port and every protocol: an acls destination with the ports *
// and no proto, or a grant whose ip entries include *. Otherwise text is what the rule limits it
// to, the proto and ports of an acls rule or the ip entries of a grant, and is empty when the rule
// writes nothing to quote (a grant with no ip entries, an acls destination with no ports).
// Equivalent spellings are not resolved ("1-65535" is a limit): a rule is said to allow all only
// when it writes the wildcard.
func (n netRule) traffic(d acl.AccessDst) (all bool, text string) {
	if n.allTraffic(d) {
		return true, ""
	}
	if n.Section == acl.RulesGrants {
		return false, n.text
	}
	var parts []string
	if n.text != "" {
		parts = append(parts, n.text)
	}
	if d.Ports != "" {
		parts = append(parts, "ports "+cutRunes(d.Ports, maxSelectorText)) // all that the cut below can keep
	}
	return false, cutRunes(strings.Join(parts, ", "), maxSelectorText)
}

// outranks says that a destination, broad when its selector is * and allowing everything when it
// allows every port and protocol, is a better one to quote than the one found: a destination * over
// another, and among those the one that allows every port and protocol.
func outranks(broad, all bool, found security.RuleRef) bool {
	return broad && (!found.Broad || (all && !found.AllTraffic))
}

// networkDst finds the destination of a rule that covers a destination host:port of the
// expectation, preferring "*" and then the one that allows everything. Its ports are those the
// rule states when they limit the pair, and its traffic is what the rule allows of ports and
// protocols.
func (m ruleMatcher) networkDst(n netRule, dsts []string) (security.RuleRef, bool) {
	var found security.RuleRef
	var ok bool
	for _, dst := range dsts {
		if !m.w.tick(1) {
			break
		}
		host, port, parsed := portNumber(dst)
		if !parsed {
			continue
		}
		for i, d := range n.Dst {
			if !m.covers(d.Selector, host) {
				if m.w.spent() {
					return found, ok // covers says no once the budget is used: the rest is not walked
				}
				continue
			}
			named := m.namesPort(n, i, port)
			if m.w.spent() {
				return found, ok // a check the meter refused is not a match
			}
			if !named {
				continue
			}
			// What is quoted is built only for a destination that is to be quoted: the first that
			// matches, and one that outranks the one found, which is at most twice more. A match that
			// cannot improve the candidate costs the rule's other destinations nothing.
			if ok && !outranks(d.Selector == "*", n.allTraffic(d), found) {
				continue
			}
			found, ok = n.dstRef(d), true
		}
	}
	return found, ok
}

// network searches the rules of acls and grants for the candidates of a network expectation:
// those whose source covers the expectation's and one of whose destinations covers one of its
// destinations on its port. The protocol is not compared: a candidate is a place to look.
func (m ruleMatcher) network(src string, dsts []string) ruleHits {
	var h ruleHits
	for _, r := range m.a.Rules {
		if m.w.spent() {
			break // the budget is used or the call is cancelled: nothing more is searched
		}
		if r.Section == acl.RulesSSH || r.Unreadable {
			continue
		}
		sel, ok := m.firstCovering(r.Src, src)
		if !ok {
			continue
		}
		n, ok := m.prepare(r)
		if !ok {
			continue
		}
		ref, ok := m.networkDst(n, dsts)
		if !ok {
			continue
		}
		ref.Section, ref.Index, ref.Line, ref.Column = r.Section, r.Index, r.Line, r.Column
		ref.Source = cutRunes(sel, maxSelectorText)
		ref.Qualified = r.Posture || r.App || r.Via || m.a.DefaultPosture
		h.add(ref)
	}
	return h
}

// userCovered says that an ssh rule's users include the ssh user: the same name, or
// autogroup:nonroot for any user but root. A localpart selector would need the login it maps to
// and is not resolved.
func userCovered(users []string, user string) bool {
	for _, u := range users {
		if u == user || u == "*" || (u == "autogroup:nonroot" && user != "root") {
			return true
		}
	}
	return false
}

// usersCovered says that an ssh rule's users include one of the expectation's users. Each user
// costs a step for each of the rule's users, and the walk ends when the budget does.
func (m ruleMatcher) usersCovered(ruleUsers, users []string) bool {
	for _, u := range users {
		if !m.w.tick(1 + len(ruleUsers)) {
			return false
		}
		if userCovered(ruleUsers, u) {
			return true
		}
	}
	return false
}

// coversAny says that the selector names one of the destinations as text, and stops walking them
// when the budget is used.
func (m ruleMatcher) coversAny(sel string, xs []string) bool {
	for _, x := range xs {
		if m.covers(sel, x) {
			return true
		}
		if m.w.spent() {
			return false
		}
	}
	return false
}

// sshDst is the destination selector of an ssh rule that covers one of the destinations, "*" in
// preference, or "" when none does or the budget ran out first.
func (m ruleMatcher) sshDst(r acl.AccessRule, dsts []string) string {
	var dstSel string
	for _, d := range r.Dst {
		if m.w.spent() {
			break
		}
		if m.coversAny(d.Selector, dsts) && (dstSel == "" || d.Selector == "*") {
			dstSel = d.Selector
		}
	}
	return dstSel
}

// ssh searches the ssh rules for the candidates of an ssh expectation: those whose source
// covers its source, one of whose destinations covers one of its destinations and whose users
// include one of its users.
func (m ruleMatcher) ssh(src string, dsts, users []string) ruleHits {
	var h ruleHits
	for _, r := range m.a.Rules {
		if m.w.spent() {
			break
		}
		if r.Section != acl.RulesSSH || r.Unreadable {
			continue
		}
		sel, ok := m.firstCovering(r.Src, src)
		if !ok || !m.usersCovered(r.Users, users) {
			continue
		}
		dstSel := m.sshDst(r, dsts)
		if dstSel == "" {
			continue
		}
		h.add(security.RuleRef{Section: r.Section, Index: r.Index, Line: r.Line, Column: r.Column,
			Source: cutRunes(sel, maxSelectorText), Destination: cutRunes(dstSel, maxSelectorText), Broad: dstSel == "*",
			Qualified: r.Posture || m.a.DefaultPosture})
	}
	return h
}

// maxHitsKept is how many candidates are kept before the cut the report makes: broad ones first.
const maxHitsKept = security.MaxAccessCandidates

// add records a match, keeping at most maxHitsKept, broad rules before the others so that a
// cut never drops the rule the blast radius names.
func (h *ruleHits) add(ref security.RuleRef) {
	h.total++
	switch {
	case len(h.refs) < maxHitsKept:
		h.refs = append(h.refs, ref)
	case ref.Broad:
		// Replace the last narrow candidate: a broad rule outranks it.
		for i := len(h.refs) - 1; i >= 0; i-- {
			if !h.refs[i].Broad {
				h.refs[i] = ref
				break
			}
		}
	}
	slices.SortStableFunc(h.refs, func(a, b security.RuleRef) int {
		switch {
		case a.Broad && !b.Broad:
			return -1
		case !a.Broad && b.Broad:
			return 1
		}
		return 0
	})
}

// candidates is the report's form of the hits.
func (h ruleHits) candidates() security.AccessCandidates {
	return security.AccessCandidates{Rules: slices.Clone(h.refs), Omitted: h.total - len(h.refs)}
}

// tagsOwnedBy lists, sorted, the tags whose owners include the name: the name itself or a
// group that lists it. Owning a tag lets a source apply it; it grants nothing the tag's rules
// grant, which is why ownership is a note and never a candidate.
func (m ruleMatcher) tagsOwnedBy(x string) []string {
	var tags []string
	for _, tag := range slices.Sorted(maps.Keys(m.a.TagOwners)) {
		owners := m.a.TagOwners[tag]
		if !m.w.tick(1) {
			break // the budget is used or the call is cancelled: no more tags are looked at
		}
		if m.ownedBy(owners, x) {
			tags = append(tags, tag)
		}
	}
	slices.Sort(tags)
	return tags
}

// ownedBy says that the name is one of the owners of a tag, or in a group that is. Each owner looked
// at is a step of the budget, and the walk ends when the meter refuses.
func (m ruleMatcher) ownedBy(owners []string, x string) bool {
	for _, o := range owners {
		if !m.w.tick(1) {
			return false
		}
		if sameName(o, x) || (strings.HasPrefix(o, "group:") && m.groupHas(o, x, 1)) {
			return true
		}
	}
	return false
}

// explainRules makes, for each selected expectation that has a pair judged, its candidate rules
// and its limits, and, for each of their sources, the tags it can apply. At most MaxAccessPairs
// expectations have a pair judged, and the search of the rules for all of them spends at most
// maxMatchWork steps: that is the bound, not the product of the sizes of the policy's groups.
// partial says that the lists may be short: the policy has more rules than are read, rules that
// cannot be read, or could not be read at all, or the search reached its budget. A network or an
// ssh expectation whose search was cut short (the budget used, the call cancelled) has the rules
// limit, for what was not searched was not ruled out. An error is the context's, when the call
// was cancelled.
func explainRules(ctx context.Context, facts *explainFacts, set security.IntentSet, judged map[string]bool) (cands map[string]security.AccessCandidates, limits map[string][]security.AccessLimit, owners []security.AccessOwner, partial bool, err error) {
	return explainRulesWith(newMatchMeter(ctx, maxMatchWork), facts, set, judged)
}

// explainRulesWith is explainRules with the meter of the search given: the budget, the context,
// and the count of the steps asked for, which a test reads.
func explainRulesWith(w *matchMeter, facts *explainFacts, set security.IntentSet, judged map[string]bool) (cands map[string]security.AccessCandidates, limits map[string][]security.AccessLimit, owners []security.AccessOwner, partial bool, err error) {
	cands, limits = map[string]security.AccessCandidates{}, map[string][]security.AccessLimit{}
	if facts == nil || facts.access == nil {
		// The rules could not be read at all: whether any depends on posture, carries app
		// capabilities or routes through via cannot be ruled out for a network expectation, nor
		// whether one depends on posture for an ssh expectation.
		for _, e := range set.Network {
			setLimits(limits, e.ID, []security.AccessLimit{security.LimitRules}, sourceLimit(e.Source))
		}
		for _, e := range set.SSH {
			setLimits(limits, e.ID, []security.AccessLimit{security.LimitRules}, sourceLimit(e.Source), sourceLimit(slices.Concat(e.Destinations)...))
		}
		return cands, limits, nil, true, nil
	}
	m := ruleMatcher{a: facts.access, w: w}
	partial = facts.access.OmittedRules > 0 || slices.ContainsFunc(facts.access.Rules, func(r acl.AccessRule) bool { return r.Unreadable })
	var sources []string
	for _, e := range set.Network {
		if !judged[e.ID] {
			continue // an expectation none of whose pairs is judged is cited for nothing, and the search is bounded by the pairs
		}
		h := m.network(e.Source, slices.Concat(e.Accept, e.Deny))
		cands[e.ID] = h.candidates()
		setLimits(limits, e.ID, m.networkLimits(slices.Concat(e.Accept, e.Deny), len(e.SourcePostureAttributes) > 0), sourceLimit(e.Source))
		sources = appendOnce(sources, e.Source)
	}
	for _, e := range set.SSH {
		if !judged[e.ID] {
			continue
		}
		users := slices.Concat(e.Accept, e.Check, e.Deny)
		h := m.ssh(e.Source, e.Destinations, users)
		cands[e.ID] = h.candidates()
		setLimits(limits, e.ID, m.sshLimits(e.Destinations, users), sourceLimit(append([]string{e.Source}, e.Destinations...)...))
		sources = appendOnce(sources, e.Source)
	}
	for _, src := range sources {
		if tags := m.tagsOwnedBy(src); len(tags) > 0 {
			owners = append(owners, security.AccessOwner{Source: cutRunes(src, maxSelectorText), Tags: cutAll(tags), Omitted: 0})
		}
	}
	if m.w.err != nil {
		return nil, nil, nil, false, m.w.err
	}
	return cands, limits, owners, partial || m.w.spent(), nil
}

// networkLimits are the limits of a network expectation: what the test language cannot express
// and the live policy may still carry for the pair. They do not depend on the candidate matcher,
// which is deliberately short of guessing: every rule of acls and grants that is gated on
// posture, carries app capabilities or routes through via counts unless it is shown to name only
// other destinations (apart). Posture is a limit only when the expectation gives no attributes:
// with them, Tailscale evaluates the test as a device that reports them, and defaultSrcPosture,
// which applies to every rule, is then also covered. A policy with rules that could not be read
// or were not listed (past the cap), or a search that was cut short, cannot rule any of this
// out, whatever the policy holds.
func (m ruleMatcher) networkLimits(dsts []string, givesAttrs bool) []security.AccessLimit {
	posture, app, via, unknown := m.qualifiers(dsts)
	var out []security.AccessLimit
	if (posture || m.a.DefaultPosture) && !givesAttrs {
		out = append(out, security.LimitPosture)
	}
	if app {
		out = append(out, security.LimitApp)
	}
	if via {
		out = append(out, security.LimitVia)
	}
	if unknown {
		out = append(out, security.LimitRules)
	}
	return out
}

// sshLimits are the limits of an ssh expectation: an ssh rule can be gated on srcPosture, and
// defaultSrcPosture gates the rules that name none, but the witness is a validation of a device that
// reports no posture (an ssh expectation gives no attributes), so a deny that holds for it holds
// for no compliant device. Every ssh rule gated on posture counts unless it is shown to be about
// other users or other destinations (sshApart), and so does a default posture; rules that could
// not be read, were not listed or were not searched cannot be ruled out. The candidate matcher
// plays no part: a rule is counted whether or not its selectors match as text.
func (m ruleMatcher) sshLimits(dsts, users []string) []security.AccessLimit {
	posture, unknown := m.sshQualifiers(dsts, users)
	var out []security.AccessLimit
	if posture || m.a.DefaultPosture {
		out = append(out, security.LimitPosture)
	}
	if unknown {
		out = append(out, security.LimitRules)
	}
	return out
}

// sshQualifiers says whether an ssh rule gated on posture is not shown to be about other users or
// other destinations, and whether an ssh rule cannot be ruled out because it could not be read,
// was not listed, or was not walked (the budget, the call).
func (m ruleMatcher) sshQualifiers(dsts, users []string) (posture, unknown bool) {
	for _, r := range m.a.Rules {
		if m.w.spent() {
			break
		}
		switch {
		case r.Section != acl.RulesSSH:
			// A rule of acls or grants says nothing of ssh.
		case r.Unreadable:
			unknown = true
		case r.Posture && !m.sshApart(r, dsts, users):
			posture = true
		}
	}
	return posture, unknown || m.a.OmittedRules > 0 || m.w.spent()
}

// sshApart says that an ssh rule is shown to be about other users or other destinations than the
// expectation's.
func (m ruleMatcher) sshApart(r acl.AccessRule, dsts, users []string) bool {
	return m.usersApart(r.Users, users) || m.destinationsApart(r, dsts)
}

// usersApart says that none of the expectation's users is one the rule's users could name: the rule
// lists only plain names and autogroup:nonroot (a localpart or another autogroup is not resolved),
// and none covers any user of the expectation. Each user compared is a step for each of the rule's
// users.
func (m ruleMatcher) usersApart(ruleUsers, users []string) bool {
	if !m.w.tick(1 + len(ruleUsers)) { // the look for a selector that cannot be resolved reads the whole list
		return false
	}
	if len(users) == 0 || slices.ContainsFunc(ruleUsers, func(u string) bool {
		return strings.HasPrefix(u, "localpart:") || (strings.HasPrefix(u, "autogroup:") && u != "autogroup:nonroot")
	}) {
		return false
	}
	for _, u := range users {
		if !m.w.tick(1+len(ruleUsers)) || strings.HasPrefix(u, "localpart:") || strings.HasPrefix(u, "autogroup:") || userCovered(ruleUsers, u) {
			return false
		}
	}
	return true
}

// destinationsApart says that every destination of the rule differs from every destination of the
// expectation, as apart reads it for a network rule: only fully resolved addresses of one family
// that do not overlap differ, and a tag or a group is never shown to.
func (m ruleMatcher) destinationsApart(r acl.AccessRule, dsts []string) bool {
	for _, dst := range dsts {
		for _, d := range r.Dst {
			if !m.w.tick(1) || !m.differs(d.Selector, dst) {
				return false
			}
		}
	}
	return len(dsts) > 0
}

// qualifiers says which of posture, app capabilities and via the rules of acls and grants carry
// that are not shown to be about other destinations (apart), and whether some rule cannot be
// ruled out because it could not be read or was not listed, or because the search reached its
// budget or the call was cancelled (what it did not search it did not rule out).
func (m ruleMatcher) qualifiers(dsts []string) (posture, app, via, unknown bool) {
	for _, r := range m.a.Rules {
		if m.w.spent() {
			break // what is not walked is not ruled out: the answer below says so
		}
		switch {
		case r.Section == acl.RulesSSH:
			// An ssh rule says nothing of a network pair (sshLimits reads it for an ssh expectation).
		case r.Unreadable:
			unknown = true
		case (r.Posture || r.App || r.Via) && !m.apart(r, dsts):
			posture, app, via = posture || r.Posture, app || r.App, via || r.Via
		}
	}
	return posture, app, via, unknown || m.a.OmittedRules > 0 || m.w.spent()
}

// apart says that a rule is shown to be about other destinations than the expectation's: every
// destination of the rule differs from every destination of the expectation, or the rule's ports
// leave out the expectation's port. A destination differs only when both are fully resolved
// addresses (an address, a range, or a host alias for one) of one family that do not overlap: a
// tag, a group or an autogroup may include anything, a device may carry several tags, and a device
// has a Tailscale address of each family, so none of those is shown to differ. A rule with app
// capabilities is not made other by its ports, which are the ip entries' and not the app's. A
// destination of the expectation that is no host:port is not shown to differ from anything.
func (m ruleMatcher) apart(r acl.AccessRule, dsts []string) bool {
	n, ok := m.prepare(r)
	if !ok {
		return false // nothing more is shown: the rule counts
	}
	for _, dst := range dsts {
		host, port, ok := portNumber(dst)
		if !ok {
			return false
		}
		for i, d := range r.Dst {
			if !m.w.tick(1) {
				return false // nothing more is shown: the rule counts
			}
			if m.differs(d.Selector, host) || (!r.App && !m.namesPort(n, i, port)) {
				continue
			}
			return false
		}
	}
	return true
}

// resolved reads a destination as an address range when it is one or names one.
func (m ruleMatcher) resolved(x string) (netip.Prefix, bool) {
	if p, ok := prefixOf(x); ok {
		return p.Masked(), true
	}
	if v, ok := m.a.Hosts[x]; ok {
		p, ok := prefixOf(v)
		return p.Masked(), ok
	}
	return netip.Prefix{}, false
}

// differs says that two destinations are fully resolved, of one address family, and overlap in
// no address.
func (m ruleMatcher) differs(sel, host string) bool {
	p, ok := m.resolved(sel)
	q, ok2 := m.resolved(host)
	return ok && ok2 && p.Addr().BitLen() == q.Addr().BitLen() && !p.Overlaps(q)
}

// sourceLimit is the limit of a source (or, for an ssh test, a source or destination) written
// as an autogroup, which Tailscale's test language cannot express.
func sourceLimit(names ...string) []security.AccessLimit {
	if slices.ContainsFunc(names, func(n string) bool { return hasPrefixAny(n, "autogroup:") }) {
		return []security.AccessLimit{security.LimitSource}
	}
	return nil
}

func setLimits(m map[string][]security.AccessLimit, id string, lists ...[]security.AccessLimit) {
	if all := slices.Concat(lists...); len(all) > 0 {
		m[id] = all
	}
}

func appendOnce(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

func cutAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = cutRunes(s, maxSelectorText)
	}
	return out
}
