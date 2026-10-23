package tools

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/abm9111/tailkeeper/internal/api"
)

// The verdicts of one destination. allowed and denied are claims about access. unresolved
// and unknown are not: a line this reader does not recognise, or a line it cannot tie to
// one destination, is never read as a pass.
const (
	verdictAllowed    = "allowed"
	verdictDenied     = "denied"
	verdictUnresolved = "unresolved"
	verdictUnknown    = "unknown"
)

// What a destination was listed to be.
const (
	expectAccept = "accept"
	expectDeny   = "deny"
	expectBoth   = "accept+deny"
)

// The sentences a verdict's Why is chosen from. They are tailkeeper's own words, never a
// line of Tailscale's, and verdictReasons lists every one of them.
const (
	whyProtocolsDiffer = "the lines for this destination do not agree"
	whyBothNeedOneLine = "a destination in accept and deny needs exactly one line"
	whyUnpairedLine    = "an assertion line matches no single destination"
	whyNotEvaluated    = "a line of this test is not in the grammar"
	whyBothLists       = "this destination is in accept and in deny"
	whyHostAddress     = "the server quoted the address of this host alias"
	whyOtherSpelling   = "a result for another source names a destination of this test"
	whySourceSpelling  = "a result is for another spelling of this source"
)

// verdictReasons is every sentence Why can hold. A result field that copies Why is a
// constant only while its values stay inside this list.
var verdictReasons = []string{
	whyProtocolsDiffer, whyBothNeedOneLine, whyUnpairedLine, whyNotEvaluated, whyBothLists, whyHostAddress,
	whyOtherSpelling, whySourceSpelling,
}

// testDest is one destination of a tests-mode test.
type testDest struct {
	Sent   string // the destination exactly as it goes to Tailscale (a login substituted)
	Shown  string // as the caller wrote it
	Accept bool   // listed in accept
	Deny   bool   // listed in deny
}

// destVerdict is what the reply says about one destination.
type destVerdict struct {
	Dst       string   // as the caller wrote it
	Expect    string   // accept, deny or accept+deny
	Verdict   string   // allowed, denied, unresolved or unknown
	Why       string   // one of verdictReasons, or "" when the line or the silence is the whole reason
	Protocols []string // the protocol names of the lines that speak for it, in the order they came
}

// readLine is one error line of the posted source.
type readLine struct {
	Text string // verbatim, Tailscale's text; the caller masks and tags it before showing it
	Kind FailureKind
}

// testReading is what deriveVerdicts makes of a tests-mode reply.
type testReading struct {
	Verdicts  []destVerdict    // one for each destination, in the order given
	Lines     []readLine       // every error line of the posted source, in order
	Unmatched []string         // assertion lines that belong to no single destination, verbatim
	Other     []api.TestResult // entries of other sources: the policy's stored tests
	Status    string           // pass, fail, unresolved or unknown
}

// canonicalDst is the form in which two spellings of one destination are equal: an IP
// address and its port through netip (case, compression and brackets settled), and anything
// else, a tag or a host alias, as written. An IPv4-mapped IPv6 address stays apart from the
// IPv4 address it maps to. A port with a leading zero, or a host that is not an address,
// is returned as written: netip refuses it, and a text comparison would be a guess.
func canonicalDst(d string) string {
	if ap, err := netip.ParseAddrPort(d); err == nil {
		return ap.String()
	}
	return d
}

// hostAddress is the address:port a server may quote for a destination that names a host
// alias, when the policy's hosts section maps that alias to one address. A prefix shorter
// than the address, a value that is not an address, and a destination that is not
// alias:port, have no such spelling: the line is then matched by name or not at all.
func hostAddress(dst string, hosts map[string]string) string {
	if strings.HasPrefix(dst, "[") || hosts == nil {
		return ""
	}
	i := strings.LastIndexByte(dst, ':')
	if i <= 0 || i == len(dst)-1 {
		return ""
	}
	value, ok := hosts[dst[:i]]
	if !ok {
		return ""
	}
	addr, ok := oneHostAddress(value)
	if !ok {
		return ""
	}
	ap, err := netip.ParseAddrPort(net.JoinHostPort(addr.String(), dst[i+1:]))
	if err != nil {
		return ""
	}
	return ap.String()
}

// oneHostAddress reads a hosts value that names exactly one address: an address, or a
// prefix of all of its bits (/32 or /128). Anything wider is a range, and a line that
// quotes one address in it is not that alias.
func oneHostAddress(value string) (netip.Addr, bool) {
	if p, err := netip.ParsePrefix(value); err == nil {
		if p.Bits() != p.Addr().BitLen() {
			return netip.Addr{}, false
		}
		return p.Addr(), true
	}
	a, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, false
	}
	return a, true
}

// destGroup is the destinations of a test that are one destination to Tailscale.
type destGroup struct {
	keys   []string // canonical forms a line can quote: the name, and the hosts address
	accept bool
	deny   bool
	lines  []FailureLine
	via    bool // a paired line quoted the hosts address, not the name
}

func (g *destGroup) expect() string {
	switch {
	case g.accept && g.deny:
		return expectBoth
	case g.deny:
		return expectDeny
	default:
		return expectAccept
	}
}

// takes says whether a line of this direction can describe the group. A destination listed
// on one side only fails by landing on the other side of it; a line that says otherwise is
// not about the test as it was sent.
func (g *destGroup) takes(f FailureLine) bool {
	switch {
	case g.accept && g.deny:
		return true
	case g.accept:
		return f.Want == "Accept"
	default:
		return f.Want == "Drop"
	}
}

// gotWord is the verdict a line states: what the policy does, the word after got.
func gotWord(f FailureLine) string {
	if f.Got == "Accept" || f.Got == "accept" {
		return verdictAllowed
	}
	return verdictDenied
}

// deriveVerdicts reads the reply of one tests-mode source into a verdict for each
// destination. src is the source as it was sent. hosts maps a host alias to the address
// the policy's hosts section gives it; nil matches by name only.
//
// A line pairs with a destination when the canonical form of the address it quotes equals
// the canonical form of the destination, or, for a host alias, the address hosts gives
// that alias. A line that pairs with two destinations pairs with neither. The verdict is
// the line's got word. A destination with no line takes what it was listed to get. The
// rules, in order, and each of them keeps a claim of access from being made:
//
//   - an assertion line that no single destination owns, or whose direction contradicts a
//     destination listed on one side only, is kept verbatim in Unmatched, and every
//     destination is unknown;
//   - a destination in both lists needs exactly one line, and is unknown otherwise;
//   - lines of one destination that do not agree are unknown;
//   - a line that is not an assertion makes every destination unresolved, so none of them
//     is allowed or denied. The status is still fail when a paired assertion failed: a
//     failure is not hidden by a line the reader does not recognise, and that line is
//     never itself a pass;
//   - an entry for the posted source written another way (case, spaces at an edge) belongs
//     to this call: its lines are kept in Unmatched and every destination is unknown;
//   - entries of other sources are the policy's stored tests. They are kept in Other and
//     do not change a verdict, unless they name a destination of this call, which is then
//     unknown.
//
// The status is the worst of those outcomes: unknown, then fail, then unresolved, then
// pass. Nothing here sends, masks or caps.
func deriveVerdicts(dests []testDest, src string, hosts map[string]string, results []api.TestResult) testReading {
	groups, groupOf := groupDests(dests, hosts)
	r := testReading{}
	notEvaluated := false
	forced := map[*destGroup]bool{}
	spelled := false
	var foreign []string
	for _, res := range results {
		if res.User != src {
			if spellsSource(res.User, src) {
				// The posted source written another way (case, spaces at an edge) is the
				// posted source, whatever its lines say: a stored test is never echoed under
				// a spelling of the caller's own. Nothing it holds is a verdict, and every
				// destination is unknown.
				spelled = true
				foreign = append(foreign, res.Errors...)
				continue
			}
			// An entry whose source is not the posted src is another test only when it
			// names none of this call's destinations. One that names one of them belongs
			// to this call, and that destination is unknown.
			named := groupsNamedBy(groups, res)
			if len(named) == 0 {
				r.Other = append(r.Other, res)
				continue
			}
			for _, g := range named {
				forced[g] = true
			}
			foreign = append(foreign, res.Errors...)
			continue
		}
		for _, text := range res.Errors {
			f, kind := readAssertion(text)
			r.Lines = append(r.Lines, readLine{Text: text, Kind: kind})
			if kind != AssertionFailed {
				notEvaluated = true
				continue
			}
			if f.SSH {
				r.Unmatched = append(r.Unmatched, text)
				continue
			}
			hit := groupsQuoting(groups, f.Dst)
			if len(hit) != 1 || !hit[0].takes(f) {
				r.Unmatched = append(r.Unmatched, text)
				continue
			}
			hit[0].lines = append(hit[0].lines, f)
			if canonicalDst(f.Dst) != canonicalDst(hit[0].keys[0]) {
				hit[0].via = true
			}
		}
	}
	failed := false
	outcomes := make([]groupOutcome, len(groups))
	for i, g := range groups {
		o := g.outcome(len(r.Unmatched) > 0, notEvaluated)
		if spelled {
			o = groupOutcome{verdict: verdictUnknown, why: whySourceSpelling}
		} else if forced[g] {
			o = groupOutcome{verdict: verdictUnknown, why: whyOtherSpelling}
		}
		outcomes[i] = o
		if o.failed {
			failed = true
		}
	}
	r.Status = readingStatus(len(r.Unmatched) > 0, failed, notEvaluated, outcomesUnknown(outcomes))
	for i, d := range dests {
		o := outcomes[indexOf(groups, groupOf[i])]
		r.Verdicts = append(r.Verdicts, destVerdict{
			Dst: d.Shown, Expect: groupOf[i].expect(), Verdict: o.verdict, Why: o.why, Protocols: o.protocols,
		})
	}
	// Shown after the verdicts are chosen, so a line of another source does not
	// mark every destination unknown: only the destinations it names are.
	r.Unmatched = append(r.Unmatched, foreign...)
	return r
}

// spellsSource reports whether user is the posted source written another way: the same
// letters in another case, or with spaces at an edge.
func spellsSource(user, src string) bool {
	return user != src && strings.EqualFold(strings.TrimSpace(user), strings.TrimSpace(src))
}

// groupsNamedBy returns the groups an entry of another source names. An assertion
// names the destination it quotes. Any other line names a destination when that
// destination's key appears in the line as its own token.
func groupsNamedBy(groups []*destGroup, res api.TestResult) []*destGroup {
	var named []*destGroup
	seen := map[*destGroup]bool{}
	add := func(list []*destGroup) {
		for _, g := range list {
			if g != nil && !seen[g] {
				seen[g] = true
				named = append(named, g)
			}
		}
	}
	lines := append(append([]string{}, res.Errors...), res.Warnings...)
	for _, text := range lines {
		f, kind := readAssertion(text)
		if kind == AssertionFailed && !f.SSH {
			add(groupsQuoting(groups, f.Dst))
			continue
		}
		var hit []*destGroup
		for _, g := range groups {
			for _, key := range g.keys {
				if tokenNames(text, key) {
					hit = append(hit, g)
				}
			}
		}
		add(hit)
	}
	return named
}

// tokenNames reports whether key appears in text bounded by a character that is
// not part of a destination token, so a shorter name does not match inside a longer one.
func tokenNames(text, key string) bool {
	if key == "" || !strings.Contains(text, key) {
		return false
	}
	for from := 0; ; {
		i := strings.Index(text[from:], key)
		if i < 0 {
			return false
		}
		i += from
		before := i == 0 || !destRune(rune(text[i-1]))
		after := endsToken(text, i+len(key))
		if before && after {
			return true
		}
		from = i + len(key)
	}
}

// endsToken reports whether a destination token that stops at text[end] ends there. A key
// ends in its port, so a colon after it is punctuation unless more token follows the colon:
// "autogroup:internet:22: is not a valid address" names autogroup:internet:22.
func endsToken(text string, end int) bool {
	if end >= len(text) {
		return true
	}
	if text[end] == ':' {
		return end+1 >= len(text) || !destRune(rune(text[end+1]))
	}
	return !destRune(rune(text[end]))
}

func destRune(r rune) bool {
	return r == ':' || r == '.' || r == '-' || r == '_' ||
		(r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

// groupOutcome is one group's verdict before it is copied onto each destination.
type groupOutcome struct {
	verdict   string
	why       string
	protocols []string
	failed    bool
}

func outcomesUnknown(o []groupOutcome) bool {
	for _, x := range o {
		if x.verdict == verdictUnknown {
			return true
		}
	}
	return false
}

func indexOf(groups []*destGroup, g *destGroup) int {
	for i, x := range groups {
		if x == g {
			return i
		}
	}
	return 0
}

// readingStatus is the worst of the outcomes a reading can have.
func readingStatus(unmatched, failed, notEvaluated, unknown bool) string {
	switch {
	case unmatched || unknown:
		return statusUnknown
	case failed:
		return statusFail
	case notEvaluated:
		return statusUnresolved
	default:
		return statusPass
	}
}

// readAssertion reads an error line. A tests-form line whose protocol is not a protocol
// name is not an assertion: the protocol is carried into the result, so it is held to the
// shape of a name, and anything else is a line the reader does not recognise.
func readAssertion(text string) (FailureLine, FailureKind) {
	f := ParseFailureLine(text)
	if f.Kind == AssertionFailed && !f.SSH && f.Protocol != "" && !protoRE.MatchString(f.Protocol) {
		return f, TestUnevaluable
	}
	return f, f.Kind
}

// groupsQuoting returns the groups a quoted address can describe.
func groupsQuoting(groups []*destGroup, dst string) []*destGroup {
	key := canonicalDst(dst)
	var hit []*destGroup
	for _, g := range groups {
		if slices.Contains(g.keys, key) {
			hit = append(hit, g)
		}
	}
	return hit
}

// groupDests puts destinations that are one destination to Tailscale together: equal once
// canonical, whichever list they are in. groupOf[i] is the group of dests[i].
func groupDests(dests []testDest, hosts map[string]string) (groups []*destGroup, groupOf []*destGroup) {
	byKey := map[string]*destGroup{}
	for _, d := range dests {
		key := canonicalDst(d.Sent)
		g, ok := byKey[key]
		if !ok {
			g = &destGroup{keys: []string{key}}
			if via := hostAddress(d.Sent, hosts); via != "" && via != key {
				g.keys = append(g.keys, via)
			}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.accept = g.accept || d.Accept
		g.deny = g.deny || d.Deny
		groupOf = append(groupOf, g)
	}
	return groups, groupOf
}

// outcome is the group's verdict. failed is whether a paired assertion contradicted what
// the destination was listed to get, which stays true when a line outside the grammar
// replaces the verdict with unresolved: the status still says the assertion failed.
func (g *destGroup) outcome(unmatched, notEvaluated bool) groupOutcome {
	word, protocols, agree := agreed(g.lines)
	natural, why := g.natural(word, protocols, agree)
	failed := natural == verdictAllowed || natural == verdictDenied
	if failed && g.accept && !g.deny && natural == verdictAllowed {
		failed = false
	}
	if failed && g.deny && !g.accept && natural == verdictDenied {
		failed = false
	}
	switch {
	case unmatched:
		return groupOutcome{verdict: verdictUnknown, why: whyUnpairedLine}
	case natural == verdictUnknown:
		// Unknown is already the worse reading. A line outside the grammar does not
		// turn it into unresolved, which a caller could rank as the less severe.
		return groupOutcome{verdict: verdictUnknown, why: why}
	case notEvaluated:
		return groupOutcome{verdict: verdictUnresolved, why: whyNotEvaluated, failed: failed}
	default:
		return groupOutcome{verdict: natural, why: why, protocols: protocols, failed: failed}
	}
}

// natural is the verdict the lines give when every line of the reply is in the grammar
// and owned by one destination.
func (g *destGroup) natural(word string, protocols []string, agree bool) (verdict, why string) {
	switch {
	case g.accept && g.deny && len(g.lines) != 1:
		if len(g.lines) > 1 && !agree {
			return verdictUnknown, whyProtocolsDiffer
		}
		return verdictUnknown, whyBothNeedOneLine
	case len(g.lines) > 0 && !agree:
		return verdictUnknown, whyProtocolsDiffer
	case len(g.lines) > 0:
		why = ""
		if g.accept && g.deny {
			why = whyBothLists
		}
		if g.via {
			why = whyHostAddress
		}
		return word, why
	case g.accept:
		return verdictAllowed, ""
	default:
		return verdictDenied, ""
	}
}

// agreed reports whether every line states the same verdict, and the protocols they name.
func agreed(lines []FailureLine) (word string, protocols []string, ok bool) {
	if len(lines) == 0 {
		return "", nil, true
	}
	word = gotWord(lines[0])
	ok = true
	for _, f := range lines {
		if gotWord(f) != word {
			ok = false
		}
		if f.Protocol != "" && !slices.Contains(protocols, f.Protocol) {
			protocols = append(protocols, f.Protocol)
		}
	}
	return word, protocols, ok
}
