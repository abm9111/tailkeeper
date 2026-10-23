package tools

import (
	"fmt"
	"slices"
	"strconv"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
)

// A source the tests below post. Every address is from a documentation range.
const verdictSrc = "group:eng"

func acceptDest(sent string) testDest { return testDest{Sent: sent, Shown: sent, Accept: true} }
func denyDest(sent string) testDest   { return testDest{Sent: sent, Shown: sent, Deny: true} }
func bothDest(sent string) testDest {
	return testDest{Sent: sent, Shown: sent, Accept: true, Deny: true}
}

// gridLine is a line of the grammar as the server writes it, with the destination quoted
// as Go does.
func gridLine(dst, proto, want, got string) string {
	p := ""
	if proto != "" {
		p = " (protocol " + strconv.Quote(proto) + ")"
	}
	return testHeading + "address " + strconv.Quote(dst) + p + ": want: " + want + ", got: " + got
}

// reply is the answer for the posted source with these error lines.
func reply(lines ...string) []api.TestResult {
	if len(lines) == 0 {
		return nil
	}
	return []api.TestResult{{User: verdictSrc, Errors: lines}}
}

// shape returns the line of an observed or constructed shape by name.
func shape(t *testing.T, name string) string {
	t.Helper()
	for _, c := range slices.Concat(observedShapes, constructedShapes, unevaluableShapes) {
		if c.name == name {
			return c.line
		}
	}
	t.Fatalf("no shape called %q", name)
	return ""
}

func summary(v destVerdict) string {
	return fmt.Sprintf("%s %s %s %q %v", v.Dst, v.Expect, v.Verdict, v.Why, v.Protocols)
}

func wantVerdicts(t *testing.T, got testReading, status string, want ...string) {
	t.Helper()
	var have []string
	for _, v := range got.Verdicts {
		have = append(have, summary(v))
	}
	if !slices.Equal(have, want) || got.Status != status {
		t.Errorf("status %q and verdicts\n  %q\nwant status %q and\n  %q", got.Status, have, status, want)
	}
}

func readDests(dests []testDest, lines ...string) testReading {
	return deriveVerdicts(dests, verdictSrc, nil, reply(lines...))
}

// Each shape the probes printed, read from the side its line names. The verdict is the
// word after got, and the test fails. With nothing said about the destination, it behaves
// as it was asked to.
func TestEachObservedShapeOfAnAcceptDestinationReadsAsAllowedOrDenied(t *testing.T) {
	for _, c := range []struct {
		shape, sent, verdict string
		deny                 bool
		protocols            []string
	}{
		{"a tag destination", "tag:db:5432", verdictDenied, false, []string{"tcp"}},
		{"a host alias", "web:443", verdictDenied, false, []string{"tcp"}},
		{"an IPv4 address with its protocol", "192.0.2.10:22", verdictAllowed, true, []string{"tcp"}},
		{"an IPv4 address with no protocol clause", "192.0.2.10:22", verdictAllowed, true, nil},
		{"a bracketed IPv6 address", "[2001:db8::10]:443", verdictDenied, false, []string{"tcp"}},
		{"ICMP, port 0, with its protocol", "192.0.2.10:0", verdictDenied, false, []string{"icmp"}},
		{"ICMP, port 0, no protocol clause", "192.0.2.10:0", verdictDenied, false, nil},
		{"a service (constructed from the grammar, not observed)", "svc:web:443", verdictDenied, false, []string{"tcp"}},
		{"no heading (constructed from the grammar, not observed)", "198.51.100.7:80", verdictDenied, false, []string{"udp"}},
		{"a destination with a quote and a backslash (constructed from the grammar, not observed)", `tag:a"b\c:22`, verdictAllowed, true, []string{"tcp"}},
	} {
		d, expect, quiet := acceptDest(c.sent), expectAccept, verdictAllowed
		if c.deny {
			d, expect, quiet = denyDest(c.sent), expectDeny, verdictDenied
		}
		got := readDests([]testDest{d}, shape(t, c.shape))
		wantVerdicts(t, got, statusFail, summary(destVerdict{Dst: c.sent, Expect: expect, Verdict: c.verdict, Protocols: c.protocols}))
		if len(got.Unmatched) != 0 || len(got.Lines) != 1 || got.Lines[0].Kind != AssertionFailed || got.Lines[0].Text != shape(t, c.shape) {
			t.Errorf("%s: lines %+v, unmatched %q", c.shape, got.Lines, got.Unmatched)
		}
		silent := readDests([]testDest{d})
		wantVerdicts(t, silent, statusPass, summary(destVerdict{Dst: c.sent, Expect: expect, Verdict: quiet}))
	}
}

// The mirror rows of a deny destination: no line is denied, and a want-Drop, got-Accept
// line is allowed. The status follows whether that is what the destination was asked to be.
func TestADenyDestinationWithNoLineIsDeniedAndWithAWantDropGotAcceptLineIsAllowed(t *testing.T) {
	dests := []testDest{acceptDest("tag:web:443"), denyDest("tag:db:5432"), denyDest("192.0.2.10:22")}
	wantVerdicts(t, readDests(dests), statusPass,
		`tag:web:443 accept allowed "" []`,
		`tag:db:5432 deny denied "" []`,
		`192.0.2.10:22 deny denied "" []`)
	one := readDests(dests, gridLine("192.0.2.10:22", "tcp", "Drop", "Accept"))
	wantVerdicts(t, one, statusFail,
		`tag:web:443 accept allowed "" []`,
		`tag:db:5432 deny denied "" []`,
		`192.0.2.10:22 deny allowed "" [tcp]`)
	two := readDests(dests, gridLine("tag:web:443", "tcp", "Accept", "Drop"), gridLine("tag:db:5432", "tcp", "Drop", "Accept"))
	wantVerdicts(t, two, statusFail,
		`tag:web:443 accept denied "" [tcp]`,
		`tag:db:5432 deny allowed "" [tcp]`,
		`192.0.2.10:22 deny denied "" []`)
}

// The canary shape: one destination in both lists, and the verdict is the word after got.
// Zero lines, or two, are not one line.
func TestTheSameDestinationInAcceptAndDenyIsReadFromTheGotWord(t *testing.T) {
	for _, c := range []struct{ name, verdict string }{
		{"the canary with acls absent", verdictAllowed},
		{"the canary with acls empty", verdictDenied},
	} {
		got := readDests([]testDest{bothDest("192.0.2.1:1")}, shape(t, c.name))
		wantVerdicts(t, got, statusFail, `192.0.2.1:1 accept+deny `+c.verdict+` "`+whyBothLists+`" [tcp]`)
	}
	split := deriveVerdicts([]testDest{acceptDest("192.0.2.1:1"), denyDest("192.0.2.1:1")}, verdictSrc, nil, reply(shape(t, "the canary with acls empty")))
	wantVerdicts(t, split, statusFail,
		`192.0.2.1:1 accept+deny denied "`+whyBothLists+`" [tcp]`,
		`192.0.2.1:1 accept+deny denied "`+whyBothLists+`" [tcp]`)
	none := readDests([]testDest{bothDest("192.0.2.1:1")})
	wantVerdicts(t, none, statusUnknown, `192.0.2.1:1 accept+deny unknown "`+whyBothNeedOneLine+`" []`)
	same := readDests([]testDest{bothDest("192.0.2.1:1")},
		gridLine("192.0.2.1:1", "tcp", "Drop", "Accept"), gridLine("192.0.2.1:1", "tcp", "Drop", "Accept"))
	wantVerdicts(t, same, statusUnknown, `192.0.2.1:1 accept+deny unknown "`+whyBothNeedOneLine+`" []`)
}

// With the protocol omitted a deny destination can yield a line for tcp and one for udp.
// Lines that say the same thing are one verdict naming both protocols. Two lines of a
// destination that is in both lists, and that say different things, are not one verdict.
func TestTwoProtocolLinesThatAgreeAreOneVerdictAndThatDifferAreUnknown(t *testing.T) {
	agree := readDests([]testDest{denyDest("192.0.2.10:22")},
		gridLine("192.0.2.10:22", "tcp", "Drop", "Accept"),
		gridLine("192.0.2.10:22", "udp", "Drop", "Accept"),
		gridLine("192.0.2.10:22", "tcp", "Drop", "Accept"))
	wantVerdicts(t, agree, statusFail, `192.0.2.10:22 deny allowed "" [tcp udp]`)
	differ := readDests([]testDest{bothDest("192.0.2.10:22")},
		gridLine("192.0.2.10:22", "tcp", "Drop", "Accept"),
		gridLine("192.0.2.10:22", "udp", "Accept", "Drop"))
	wantVerdicts(t, differ, statusUnknown, `192.0.2.10:22 accept+deny unknown "`+whyProtocolsDiffer+`" []`)
}

// A CIDR, autogroup:internet and a tag the policy does not define come back as lines that
// are not assertions. Every destination of that test is unresolved, never denied, and the
// line is kept verbatim.
func TestALineOutsideTheGrammarMakesTheTestUnresolvedNeverDenied(t *testing.T) {
	for _, name := range []string{"a CIDR", "autogroup:internet", "a tag that is not defined", "a bare message", "an SSH verdict outside accept and deny"} {
		dests := []testDest{acceptDest("198.51.100.0/24:22"), denyDest("tag:db:5432"), acceptDest("tag:web:443")}
		got := readDests(dests, shape(t, name))
		wantVerdicts(t, got, statusUnresolved,
			`198.51.100.0/24:22 accept unresolved "`+whyNotEvaluated+`" []`,
			`tag:db:5432 deny unresolved "`+whyNotEvaluated+`" []`,
			`tag:web:443 accept unresolved "`+whyNotEvaluated+`" []`)
		if len(got.Unmatched) != 0 || len(got.Lines) != 1 || got.Lines[0].Kind != TestUnevaluable || got.Lines[0].Text != shape(t, name) {
			t.Errorf("%s: lines %+v, unmatched %q", name, got.Lines, got.Unmatched)
		}
	}
}

// A line in the grammar that no destination owns is not a verdict. It stays whole in
// Unmatched, and every destination is unknown: borrowing the only destination, or reading
// the line as a denial, would claim an access the reply did not tie to it.
func TestAnAssertionLineNoDestinationMatchesIsUnmatchedAndEveryDestinationUnknown(t *testing.T) {
	quoted := gridLine("192.0.2.10:443", "tcp", "Accept", "Drop")
	got := readDests([]testDest{acceptDest("web:443"), denyDest("tag:db:5432")}, quoted)
	wantVerdicts(t, got, statusUnknown,
		`web:443 accept unknown "`+whyUnpairedLine+`" []`,
		`tag:db:5432 deny unknown "`+whyUnpairedLine+`" []`)
	if !slices.Equal(got.Unmatched, []string{quoted}) || len(got.Lines) != 1 {
		t.Errorf("unmatched %q, lines %+v", got.Unmatched, got.Lines)
	}
	alone := readDests([]testDest{acceptDest("web:443")}, quoted)
	wantVerdicts(t, alone, statusUnknown, `web:443 accept unknown "`+whyUnpairedLine+`" []`)
	ssh := readDests([]testDest{acceptDest("tag:db:5432")}, shape(t, "an SSH test"))
	wantVerdicts(t, ssh, statusUnknown, `tag:db:5432 accept unknown "`+whyUnpairedLine+`" []`)
	if lonely := readDests(nil, quoted); lonely.Status != statusUnknown || len(lonely.Verdicts) != 0 || len(lonely.Unmatched) != 1 {
		t.Errorf("no destinations: %+v", lonely)
	}
}

// A destination listed on one side only is not described by a line of the other direction.
func TestALineThatContradictsASingleListedDestinationIsUnmatched(t *testing.T) {
	accept := readDests([]testDest{acceptDest("192.0.2.10:22")}, gridLine("192.0.2.10:22", "tcp", "Drop", "Accept"))
	wantVerdicts(t, accept, statusUnknown, `192.0.2.10:22 accept unknown "`+whyUnpairedLine+`" []`)
	deny := readDests([]testDest{denyDest("192.0.2.10:22")}, gridLine("192.0.2.10:22", "tcp", "Accept", "Drop"))
	wantVerdicts(t, deny, statusUnknown, `192.0.2.10:22 deny unknown "`+whyUnpairedLine+`" []`)
	if len(accept.Unmatched) != 1 || len(deny.Unmatched) != 1 {
		t.Errorf("unmatched %q and %q", accept.Unmatched, deny.Unmatched)
	}
}

// Addresses are compared as addresses. An IPv4-mapped spelling is not the IPv4 address.
func TestAnIPv6DestinationPairsAcrossCaseAndCompression(t *testing.T) {
	got := readDests([]testDest{denyDest("[2001:DB8:0:0::1]:22")}, gridLine("[2001:db8::1]:22", "tcp", "Drop", "Accept"))
	wantVerdicts(t, got, statusFail, `[2001:DB8:0:0::1]:22 deny allowed "" [tcp]`)
	if len(got.Unmatched) != 0 {
		t.Errorf("unmatched %q", got.Unmatched)
	}
	for in, want := range map[string]string{
		"[2001:DB8:0:0::1]:22":      "[2001:db8::1]:22",
		"[2001:db8:0:0:0:0:0:1]:22": "[2001:db8::1]:22",
		"192.0.2.10:22":             "192.0.2.10:22",
		"[::ffff:192.0.2.10]:22":    "[::ffff:192.0.2.10]:22",
		"tag:db:5432":               "tag:db:5432",
		"Tag:DB:5432":               "Tag:DB:5432",
		"web:443":                   "web:443",
		"192.0.2.10":                "192.0.2.10",
		"192.000.2.10:22":           "192.000.2.10:22",
		"[2001:db8::1]":             "[2001:db8::1]",
		"":                          "",
	} {
		if got := canonicalDst(in); got != want {
			t.Errorf("canonicalDst(%q) = %q, want %q", in, got, want)
		}
	}
	mapped := readDests([]testDest{acceptDest("192.0.2.10:22")}, gridLine("[::ffff:192.0.2.10]:22", "tcp", "Accept", "Drop"))
	if mapped.Status != statusUnknown {
		t.Errorf("an IPv4-mapped spelling paired with the IPv4 destination: %+v", mapped)
	}
}

// An entry for another source is another test only when it names none of this
// call's destinations. One that names a destination makes that destination unknown.
func TestEntriesForOtherSourcesAreOtherTestsNotVerdicts(t *testing.T) {
	stored := api.TestResult{User: "group:ops", Errors: []string{gridLine("tag:other:9", "tcp", "Accept", "Drop")}, Warnings: []string{"a warning"}}
	results := []api.TestResult{stored, {User: verdictSrc, Errors: []string{gridLine("tag:web:443", "tcp", "Accept", "Drop")}}}
	got := deriveVerdicts([]testDest{acceptDest("tag:web:443"), denyDest("tag:db:5432")}, verdictSrc, nil, results)
	wantVerdicts(t, got, statusFail,
		`tag:web:443 accept denied "" [tcp]`,
		`tag:db:5432 deny denied "" []`)
	if len(got.Other) != 1 || got.Other[0].User != "group:ops" || len(got.Lines) != 1 || len(got.Unmatched) != 0 {
		t.Errorf("other %+v, lines %+v, unmatched %q", got.Other, got.Lines, got.Unmatched)
	}
	naming := api.TestResult{User: "group:ops", Errors: []string{gridLine("tag:db:5432", "tcp", "Accept", "Drop")}}
	hit := deriveVerdicts([]testDest{acceptDest("tag:db:5432")}, verdictSrc, nil, []api.TestResult{naming})
	wantVerdicts(t, hit, statusUnknown, `tag:db:5432 accept unknown "`+whyOtherSpelling+`" []`)
	if len(hit.Other) != 0 || len(hit.Unmatched) != 1 || hit.Verdicts[0].Verdict == verdictAllowed {
		t.Errorf("a naming entry was another test or a pass: %+v", hit)
	}
}

// A reply that spells the posted source differently, but names one of its
// destinations, is not another test and is never a pass.
func TestAnEntryForAnotherSpellingOfTheSourceIsNeverAPass(t *testing.T) {
	line := gridLine("tag:db:22", "tcp", "Accept", "Drop")
	dests := []testDest{acceptDest("tag:db:22")}
	for _, user := range []string{"TAG:CI", "tag:ci ", "GROUP:ENG"} {
		src := "tag:ci"
		if user == "GROUP:ENG" {
			src = "group:eng"
			line = gridLine("tag:db:22", "tcp", "Accept", "Drop")
		}
		got := deriveVerdicts(dests, src, nil, []api.TestResult{{User: user, Errors: []string{line}}})
		if got.Status != statusUnknown || len(got.Other) != 0 || len(got.Verdicts) != 1 || got.Verdicts[0].Verdict != verdictUnknown {
			t.Errorf("user %q: status %q other %d verdict %+v", user, got.Status, len(got.Other), got.Verdicts)
		}
	}
}

// A warning is not a failure.
func TestAWarningOnlyEntryIsNoVerdict(t *testing.T) {
	results := []api.TestResult{{User: verdictSrc, Warnings: []string{`host alias "lab" is not used`}}}
	got := deriveVerdicts([]testDest{acceptDest("tag:db:5432"), denyDest("tag:web:443")}, verdictSrc, nil, results)
	wantVerdicts(t, got, statusPass,
		`tag:db:5432 accept allowed "" []`,
		`tag:web:443 deny denied "" []`)
	if len(got.Lines) != 0 || len(got.Unmatched) != 0 || len(got.Other) != 0 {
		t.Errorf("lines %+v, unmatched %q, other %+v", got.Lines, got.Unmatched, got.Other)
	}
	// A warning on another source is that source's entry, and still no verdict.
	other := deriveVerdicts([]testDest{acceptDest("tag:db:5432")}, verdictSrc, nil, []api.TestResult{{User: "group:ops", Warnings: []string{"a warning"}}})
	wantVerdicts(t, other, statusPass, `tag:db:5432 accept allowed "" []`)
	if len(other.Other) != 1 || len(other.Lines) != 0 {
		t.Errorf("other %+v, lines %+v", other.Other, other.Lines)
	}
}

// A host alias pairs with its name and, when the hosts section maps it to one address,
// with that address. A range, a broken value, or any other address, does not pair.
func TestAHostAliasPairsByNameOrThroughTheHostsSectionAndNothingElse(t *testing.T) {
	hosts := map[string]string{
		"web": "192.0.2.10", "net": "192.0.2.0/24", "one": "192.0.2.7/32",
		"v6": "2001:db8::5", "wide6": "2001:db8::/64", "broken": "not an address",
	}
	for dst, want := range map[string]string{
		"web:443": "192.0.2.10:443", "one:22": "192.0.2.7:22", "v6:22": "[2001:db8::5]:22",
		"net:22": "", "wide6:22": "", "broken:22": "", "missing:22": "", "tag:db:5432": "",
		"web:99999": "", "web:http": "", "web:": "", "web": "", ":22": "", "192.0.2.10:1": "",
		"Web:443": "",
	} {
		if got := hostAddress(dst, hosts); got != want {
			t.Errorf("hostAddress(%q) = %q, want %q", dst, got, want)
		}
	}
	alias := acceptDest("web:443")
	byName := deriveVerdicts([]testDest{alias}, verdictSrc, hosts, reply(gridLine("web:443", "tcp", "Accept", "Drop")))
	wantVerdicts(t, byName, statusFail, `web:443 accept denied "" [tcp]`)
	byAddress := deriveVerdicts([]testDest{alias}, verdictSrc, hosts, reply(gridLine("192.0.2.10:443", "tcp", "Accept", "Drop")))
	wantVerdicts(t, byAddress, statusFail, `web:443 accept denied "`+whyHostAddress+`" [tcp]`)
	other := deriveVerdicts([]testDest{alias}, verdictSrc, hosts, reply(gridLine("192.0.2.11:443", "tcp", "Accept", "Drop")))
	wantVerdicts(t, other, statusUnknown, `web:443 accept unknown "`+whyUnpairedLine+`" []`)
	bare := deriveVerdicts([]testDest{alias}, verdictSrc, nil, reply(gridLine("192.0.2.10:443", "tcp", "Accept", "Drop")))
	wantVerdicts(t, bare, statusUnknown, `web:443 accept unknown "`+whyUnpairedLine+`" []`)
	if len(bare.Unmatched) != 1 {
		t.Errorf("unmatched %q", bare.Unmatched)
	}
	// A /32 is one address; a wider prefix is not, so a line quoting its base is unknown.
	one := deriveVerdicts([]testDest{acceptDest("one:22")}, verdictSrc, hosts, reply(gridLine("192.0.2.7:22", "tcp", "Accept", "Drop")))
	wantVerdicts(t, one, statusFail, `one:22 accept denied "`+whyHostAddress+`" [tcp]`)
	net := deriveVerdicts([]testDest{acceptDest("net:22")}, verdictSrc, hosts, reply(gridLine("192.0.2.0:22", "tcp", "Accept", "Drop")))
	wantVerdicts(t, net, statusUnknown, `net:22 accept unknown "`+whyUnpairedLine+`" []`)
}

// A line that two destinations could own is owned by neither.
func TestALineThatTwoDestinationsCouldOwnIsUnmatched(t *testing.T) {
	hosts := map[string]string{"web": "192.0.2.10"}
	got := deriveVerdicts([]testDest{acceptDest("web:443"), acceptDest("192.0.2.10:443")}, verdictSrc, hosts, reply(gridLine("192.0.2.10:443", "tcp", "Accept", "Drop")))
	wantVerdicts(t, got, statusUnknown,
		`web:443 accept unknown "`+whyUnpairedLine+`" []`,
		`192.0.2.10:443 accept unknown "`+whyUnpairedLine+`" []`)
	if len(got.Unmatched) != 1 {
		t.Errorf("unmatched %q", got.Unmatched)
	}
}

// A protocol is carried into the result, so a line whose protocol is not a name is not an
// assertion this reading will pair. The line is then one the reader does not recognise.
func TestAProtocolThatIsNotAProtocolNameMakesTheLineUnevaluable(t *testing.T) {
	for _, proto := range []string{"TCP", "tcp; drop", "a very long protocol name indeed", "<b>"} {
		line := gridLine("tag:db:5432", proto, "Accept", "Drop")
		if f := ParseFailureLine(line); f.Kind != AssertionFailed || f.Protocol != proto {
			t.Fatalf("the control did not discriminate: %q read as %+v", line, f)
		}
		got := readDests([]testDest{acceptDest("tag:db:5432")}, line)
		wantVerdicts(t, got, statusUnresolved, `tag:db:5432 accept unresolved "`+whyNotEvaluated+`" []`)
		if len(got.Lines) != 1 || got.Lines[0].Kind != TestUnevaluable || got.Lines[0].Text != line {
			t.Errorf("%q: lines %+v", proto, got.Lines)
		}
	}
}

// Two spellings of one address are one destination, and each is shown as it was written.
func TestDestinationsThatAreOneToTailscaleShareAVerdict(t *testing.T) {
	dests := []testDest{
		{Sent: "[2001:DB8::1]:22", Shown: "[2001:DB8::1]:22", Accept: true},
		{Sent: "[2001:db8:0:0::1]:22", Shown: "as written", Accept: true},
	}
	got := readDests(dests, gridLine("[2001:db8::1]:22", "tcp", "Accept", "Drop"))
	wantVerdicts(t, got, statusFail,
		`[2001:DB8::1]:22 accept denied "" [tcp]`,
		`as written accept denied "" [tcp]`)
}

// The status is the worst of the parts: unknown, then fail, then unresolved, then pass.
// A line outside the grammar keeps a destination from being called allowed or denied, and
// the status is still fail when a paired assertion failed.
func TestStatusPrecedenceIsUnknownThenFailThenUnresolvedThenPass(t *testing.T) {
	failing := gridLine("tag:db:5432", "tcp", "Accept", "Drop")
	cidr := shape(t, "a CIDR")
	stray := gridLine("192.0.2.99:1", "tcp", "Accept", "Drop")
	dests := []testDest{acceptDest("tag:db:5432"), denyDest("tag:web:443"), bothDest("192.0.2.1:1")}
	canary := gridLine("192.0.2.1:1", "tcp", "Drop", "Accept")
	for name, c := range map[string]struct {
		dests []testDest
		lines []string
		want  string
	}{
		"nothing wrong":                        {dests[:2], nil, statusPass},
		"a destination dropped":                {dests[:2], []string{failing}, statusFail},
		"a name Tailscale cannot resolve":      {dests[:2], []string{cidr}, statusUnresolved},
		"a stray line":                         {dests[:2], []string{stray}, statusUnknown},
		"a failure and an unresolved name":     {dests[:2], []string{failing, cidr}, statusFail},
		"a failure and a stray line":           {dests[:2], []string{failing, stray}, statusUnknown},
		"an unresolved name and a stray line":  {dests[:2], []string{cidr, stray}, statusUnknown},
		"all three":                            {dests[:2], []string{failing, cidr, stray}, statusUnknown},
		"the canary shape alone":               {dests[2:], []string{canary}, statusFail},
		"the canary shape with no line":        {dests[2:], nil, statusUnknown},
		"no line for it and a name unresolved": {dests[2:], []string{cidr}, statusUnknown},
		"a failure and a canary with no line":  {dests, []string{failing}, statusUnknown},
		"a failure and a canary with its line": {dests, []string{failing, canary}, statusFail},
		"no destinations and an unresolved":    {nil, []string{cidr}, statusUnresolved},
		"no destinations and nothing":          {nil, nil, statusPass},
	} {
		got := readDests(c.dests, c.lines...)
		if got.Status != c.want {
			t.Errorf("%s: status %q, want %q (verdicts %+v)", name, got.Status, c.want, got.Verdicts)
		}
		if slices.Contains(c.lines, cidr) && !slices.Contains(c.lines, stray) && c.want != statusUnknown {
			for _, v := range got.Verdicts {
				if v.Verdict == verdictAllowed || v.Verdict == verdictDenied {
					t.Errorf("%s: verdict %s is a claim beside a line outside the grammar", name, v.Verdict)
				}
			}
		}
	}
}

// The words a reading can hold are a closed list.
func TestTheReasonsAreAClosedListOfDistinctSentences(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range verdictReasons {
		if r == "" || seen[r] || stringsHasOnlyWords(r) != r {
			t.Errorf("reason %q is empty, repeated or not a plain sentence", r)
		}
		seen[r] = true
	}
	for _, w := range []string{verdictAllowed, verdictDenied, verdictUnresolved, verdictUnknown, expectAccept, expectDeny, expectBoth} {
		if w == "" || seen[w] {
			t.Errorf("word %q collides with a reason or is empty", w)
		}
	}
}

func stringsHasOnlyWords(s string) string {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == ' ' || r == ',') {
			return ""
		}
	}
	return s
}

// The ssh user of a line is part of what the line says. The tests form has none.
func TestTheSSHUserOfALineIsKept(t *testing.T) {
	s := ParseFailureLine(shape(t, "an SSH test"))
	if s.User != "root" || s.Dst != "tag:db" || !s.SSH || s.Want != "accept" || s.Got != "deny" {
		t.Errorf("SSH line read as %+v", s)
	}
	if f := ParseFailureLine(shape(t, "a tag destination")); f.User != "" {
		t.Errorf("a tests line carried a user %q", f.User)
	}
}
