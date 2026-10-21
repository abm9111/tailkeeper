package tools

import (
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/acl"
)

var updateVerdicts = flag.Bool("update-verdicts", false, "rewrite testdata/verdicts/a9.txt from the cases of TestFailureLineGrammarMatchesEveryObservedShape")

// verdictCase is one line of a validate reply, with documentation addresses and example
// names in place of the tailnet's, and what the line says: the verdict wanted and the one
// got, written by hand from the line. The test compares them with the parse, so the golden
// file is a record of the parse and not the oracle for it. The unevaluable cases say nothing.
type verdictCase struct{ name, line, want, got string }

// observedShapes are the shapes probes A-9 and A-10 printed (20 Oct 2026), one destination
// kind at a time.
var observedShapes = []verdictCase{
	{"a tag destination", `[acl test error]: address "tag:db:5432" (protocol "tcp"): want: Accept, got: Drop`, "Accept", "Drop"},
	{"a host alias", `[acl test error]: address "web:443" (protocol "tcp"): want: Accept, got: Drop`, "Accept", "Drop"},
	{"an IPv4 address with its protocol", `[acl test error]: address "192.0.2.10:22" (protocol "tcp"): want: Drop, got: Accept`, "Drop", "Accept"},
	{"an IPv4 address with no protocol clause", `[acl test error]: address "192.0.2.10:22": want: Drop, got: Accept`, "Drop", "Accept"},
	{"a bracketed IPv6 address", `[acl test error]: address "[2001:db8::10]:443" (protocol "tcp"): want: Accept, got: Drop`, "Accept", "Drop"},
	{"ICMP, port 0, with its protocol", `[acl test error]: address "192.0.2.10:0" (protocol "icmp"): want: Accept, got: Drop`, "Accept", "Drop"},
	{"ICMP, port 0, no protocol clause", `[acl test error]: address "192.0.2.10:0": want: Accept, got: Drop`, "Accept", "Drop"},
	{"the canary with acls absent", `[acl test error]: address "192.0.2.1:1" (protocol "tcp"): want: Drop, got: Accept`, "Drop", "Accept"},
	{"the canary with acls empty", `[acl test error]: address "192.0.2.1:1" (protocol "tcp"): want: Accept, got: Drop`, "Accept", "Drop"},
	{"an SSH test", `[ssh test error]: src "tag:p" at "100.64.0.1", dst "tag:db" at "100.64.0.2", ssh user "root": want: "accept" got: "deny"`, "accept", "deny"},
	{"an SSH test, the other way", `[ssh test error]: src "tag:p" at "100.64.0.1", dst "tag:db" at "100.64.0.2", ssh user "root": want: "deny" got: "accept"`, "deny", "accept"},
}

// constructedShapes are lines that no probe printed. They are built from the grammar of the
// observed ones, and the live run of a later change is where they are checked: A-9's skipped
// list says the live policy names no service, and no probe sent a name with a quote in it
// or took the heading off. They are as good as the grammar they come from.
var constructedShapes = []verdictCase{
	{"a service (constructed from the grammar, not observed)", `[acl test error]: address "svc:web:443" (protocol "tcp"): want: Accept, got: Drop`, "Accept", "Drop"},
	{"no heading (constructed from the grammar, not observed)", `address "198.51.100.7:80" (protocol "udp"): want: Accept, got: Drop`, "Accept", "Drop"},
	{"a destination with a quote and a backslash (constructed from the grammar, not observed)", `[acl test error]: address "tag:a\"b\\c:22" (protocol "tcp"): want: Drop, got: Accept`, "Drop", "Accept"},
	{"an SSH test with no heading (constructed from the grammar, not observed)", `src "group:eng" at "100.64.0.3", dst "tag:db" at "100.64.0.2", ssh user "admin": want: "accept" got: "deny"`, "accept", "deny"},
}

// unevaluableShapes are lines that are not assertions. The first four are what probes A-2
// and A-9 printed (a CIDR and autogroup:internet, kinds tests refuse; a tag the policy does
// not define; the summary line); the others are written by hand, the ways a line near the
// grammar misses it.
var unevaluableShapes = []verdictCase{
	{"a CIDR", `[acl test error]: user or host is invalid: bad user spec given: "198.51.100.0/24"`, "", ""},
	{"autogroup:internet", `[acl test error]: address autogroup:internet:22: is not a valid address`, "", ""},
	{"a tag that is not defined", `[acl test error]: user or host is invalid: tag not found: "tag:missing"`, "", ""},
	{"the summary line", `test(s) failed`, "", ""},
	{"an empty line", ``, "", ""},
	{"the heading alone", `[acl test error]: `, "", ""},
	{"a bare message", `something else went wrong`, "", ""},
	{"both verdicts the same", `[acl test error]: address "192.0.2.10:22" (protocol "tcp"): want: Drop, got: Drop`, "", ""},
	{"a verdict in lower case", `[acl test error]: address "192.0.2.10:22" (protocol "tcp"): want: accept, got: drop`, "", ""},
	{"text after the verdict", `[acl test error]: address "192.0.2.10:22" (protocol "tcp"): want: Accept, got: Drop (twice)`, "", ""},
	{"text before the heading", `error: [acl test error]: address "192.0.2.10:22": want: Accept, got: Drop`, "", ""},
	{"two headings", `[acl test error]: [acl test error]: address "192.0.2.10:22": want: Accept, got: Drop`, "", ""},
	{"an address that is not quoted", `[acl test error]: address 192.0.2.10:22: want: Accept, got: Drop`, "", ""},
	{"an address that does not unquote", `[acl test error]: address "tag:\q:22": want: Accept, got: Drop`, "", ""},
	{"a protocol that is not closed", `[acl test error]: address "192.0.2.10:22" (protocol "tcp": want: Accept, got: Drop`, "", ""},
	{"a missing comma", `[acl test error]: address "192.0.2.10:22": want: Accept got: Drop`, "", ""},
	{"an SSH verdict outside accept and deny", `[ssh test error]: src "tag:p" at "100.64.0.1", dst "tag:db" at "100.64.0.2", ssh user "root": want: "check" got: "deny"`, "", ""},
	{"an SSH line with a field missing", `[ssh test error]: src "tag:p" at "100.64.0.1", dst "tag:db" at "100.64.0.2": want: "accept" got: "deny"`, "", ""},
	{"an SSH line with text after it", `[ssh test error]: src "tag:p" at "100.64.0.1", dst "tag:db" at "100.64.0.2", ssh user "root": want: "accept" got: "deny" `, "", ""},
}

// renderVerdicts is the golden text: for each case, the line and what ParseFailureLine
// makes of it.
func renderVerdicts(cases []verdictCase) string {
	var b strings.Builder
	for _, c := range cases {
		f := ParseFailureLine(c.line)
		fmt.Fprintf(&b, "## %s\nline:  %q\nparse: kind=%s ssh=%t dst=%q protocol=%q want=%q got=%q\n\n",
			c.name, c.line, f.Kind, f.SSH, f.Dst, f.Protocol, f.Want, f.Got)
	}
	return b.String()
}

const verdictGolden = "testdata/verdicts/a9.txt"

func TestFailureLineGrammarMatchesEveryObservedShape(t *testing.T) {
	got := renderVerdicts(observedShapes) + renderVerdicts(constructedShapes) + renderVerdicts(unevaluableShapes)
	if *updateVerdicts {
		if err := os.WriteFile(verdictGolden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(verdictGolden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("the parse of the observed shapes differs from %s (run with -update-verdicts to rewrite it, then read the diff):\n%s", verdictGolden, got)
	}
	// The golden is only as good as its reading, and the file is written by the code it tests:
	// every observed or constructed shape is an assertion with a destination and the two
	// verdicts its line says (written beside the line, not taken from the parse), whatever
	// the file holds.
	for _, c := range append(slices.Clone(observedShapes), constructedShapes...) {
		f := ParseFailureLine(c.line)
		if f.Kind != AssertionFailed || f.Dst == "" || f.Want != c.want || f.Got != c.got || f.Want == f.Got {
			t.Errorf("%s: %q read as %+v, want the verdicts %q and %q", c.name, c.line, f, c.want, c.got)
		}
		if f.SSH != strings.Contains(c.line, "ssh user") {
			t.Errorf("%s: SSH = %v", c.name, f.SSH)
		}
	}
}

func TestUnevaluableLinesAreNotAssertions(t *testing.T) {
	for _, c := range unevaluableShapes {
		if f := ParseFailureLine(c.line); f != (FailureLine{Kind: TestUnevaluable}) {
			t.Errorf("%s: %q read as %+v, want an unevaluable line with nothing else", c.name, c.line, f)
		}
	}
}

// The failure a line makes for the locating code carries the source the caller gives, the
// destination as the server quoted it, and the SSH flag.
func TestAFailureLineMakesTheFailureToLocate(t *testing.T) {
	f := ParseFailureLine(`[acl test error]: address "tag:db:5432" (protocol "tcp"): want: Accept, got: Drop`)
	if got := f.Failure("group:eng"); got != (acl.Failure{Src: "group:eng", Dst: "tag:db:5432"}) {
		t.Errorf("Failure = %+v", got)
	}
	s := ParseFailureLine(`[ssh test error]: src "tag:p" at "100.64.0.1", dst "tag:db" at "100.64.0.2", ssh user "root": want: "accept" got: "deny"`)
	if got := s.Failure("tag:p"); got != (acl.Failure{Src: "tag:p", Dst: "tag:db", SSH: true}) {
		t.Errorf("SSH Failure = %+v", got)
	}
}

// A tag or a host name can hold a quote, a protocol clause, the words want and got, and
// another whole destination. The server quotes the destination like Go's %q does, so the
// hostile name is one quoted field, and the line is read from the end of it.
func TestAHostileNameCannotForgeAVerdict(t *testing.T) {
	hostile := `tag:x" (protocol "udp"): want: Accept, got: Accept address "y:1": want: Accept, got: Drop`
	line := testHeading + `address ` + strconv.Quote(hostile+":22") + ` (protocol "tcp"): want: Drop, got: Accept`
	f := ParseFailureLine(line)
	want := FailureLine{Kind: AssertionFailed, Dst: hostile + ":22", Protocol: "tcp", Want: "Drop", Got: "Accept"}
	if f != want {
		t.Errorf("the hostile line read as %+v, want %+v", f, want)
	}
	// The control: a search for the words, which the grammar replaces, is fooled by the same line.
	naive := regexp.MustCompile(`want: (Accept|Drop), got: (Accept|Drop)`).FindStringSubmatch(line)
	if naive == nil || (naive[1] == f.Want && naive[2] == f.Got) {
		t.Fatalf("the control did not discriminate: a search reads %v", naive)
	}
	// A name that embeds a position or a verdict cannot move a message to the way of another.
	var d, err = acl.Parse(context.Background(), []byte(`{"tests": [{"src": "tag:x", "accept": ["tag:db:5432"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := placeMessage(context.Background(), d, "tag:x", testHeading+`user or host is invalid: tag not found: "line 1, column 1: tag:x"`)
	if err != nil || p.basis != placedByToken || p.line != 0 || len(p.locations) != 0 {
		t.Errorf("a name that spells a position: %+v, %v; want a search for the whole quoted name, which the text does not hold", p, err)
	}
}

func TestPositionInAndQuotedToken(t *testing.T) {
	type pos struct {
		line, col int
		ok        bool
	}
	for in, want := range map[string]pos{
		"line 3, column 5: unexpected token":              {3, 5, true},
		"line 12, column 1: x":                            {12, 1, true},
		"line 999999999, column 999999999: x":             {999999999, 999999999, true},
		"line 4, column 2: " + strings.Repeat("x", 1<<16): {4, 2, true},
		"line 0, column 1: x":                             {},
		"line 1, column 0: x":                             {},
		"line 1000000000, column 1: x":                    {},
		"line 3 column 5: x":                              {},
		"Line 3, column 5: x":                             {},
		"line 3, column 5 x":                              {},
		"line -3, column 5: x":                            {},
		" line 3, column 5: x":                            {},
		"see line 3, column 5: x":                         {},
		"line 3, column :":                                {},
		"":                                                {},
	} {
		line, col, ok := positionIn(in)
		if got := (pos{line, col, ok}); got != want {
			t.Errorf("positionIn(%.40q) = %+v; want %+v", in, got, want)
		}
	}
	for in, want := range map[string]string{
		`src=tag not found: "tag:p"`:       "tag:p",
		`first "a" then "b"`:               "a",
		`escaped "a\"b" end`:               `a"b`,
		`a "tag:x" and a hostile "tag:\q"`: "tag:x",
	} {
		if got, ok := quotedToken(in); !ok || got != want {
			t.Errorf("quotedToken(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"no quotes at all", `unterminated "abc`, `bad escape "tag:\q"`, ""} {
		if got, ok := quotedToken(in); ok || got != "" {
			t.Errorf("quotedToken(%q) = %q, %v; want no token", in, got, ok)
		}
	}
	// A quoted token is cut at 1 KiB, at a rune boundary.
	for name, tok := range map[string]string{
		"a megabyte of one byte": strings.Repeat("a", 1<<20),
		"two-byte characters":    strings.Repeat("é", 1000),
		"three-byte characters":  strings.Repeat("€", 500),
		"exactly the limit":      strings.Repeat("a", 1024),
		"one over the limit":     strings.Repeat("a", 1025),
	} {
		got, ok := quotedToken(`bad "` + tok + `" here`)
		if !ok || len(got) > 1024 || !utf8.ValidString(got) || !strings.HasPrefix(tok, got) || len(got) < 1024-3 && len(tok) > 1024 {
			t.Errorf("%s: %d bytes in, %d out (ok %v, valid %v)", name, len(tok), len(got), ok, utf8.ValidString(got))
		}
	}
	if got, _ := quotedToken(`"` + strings.Repeat("a", 1024) + `"`); len(got) != 1024 {
		t.Errorf("a token of exactly 1 KiB was cut to %d bytes", len(got))
	}
}

// A token with nothing in it names nothing: an empty one, or one of bytes that are not
// UTF-8 (a double-quoted string can hold them as \x80) whose first 1 KiB has no rune start
// to cut at. Looked up, the empty string would be found at every empty entry of the policy,
// and the message would be placed where it does not belong.
func TestAnEmptyQuotedTokenPlacesNothing(t *testing.T) {
	hostile := `bad "` + strings.Repeat(`\x80`, 1100) + `" here`
	for name, msg := range map[string]string{
		"an empty token":               `bad "" here`,
		"bytes with no rune start":     hostile,
		"an empty token after a quote": `say "" and "tag:x"`,
	} {
		if got, ok := quotedToken(msg); ok || got != "" {
			t.Errorf("%s: quotedToken = %q, %v; want no token", name, got, ok)
		}
	}
	// The policy has an empty entry in a group: a placement by the empty string would land on it.
	d := parsed(t, `{"groups": {"group:a": ["", "amy@example.com"]}, "acls": []}`)
	for name, msg := range map[string]string{"an empty token": `bad "" here`, "bytes with no rune start": hostile} {
		p, err := placeMessage(context.Background(), d, "group:a", msg)
		if err != nil || p.basis != notPlaced || len(p.locations) != 0 || p.cut != 0 {
			t.Errorf("%s: placement %+v, %v; want none", name, p, err)
		}
	}
	// A token that names something still places.
	if p, err := placeMessage(context.Background(), d, "group:a", `bad "group:a" here`); err != nil || p.basis != placedByToken || len(p.locations) == 0 {
		t.Errorf("a named token: %+v, %v; want a placement by token", p, err)
	}
}

// policyOfTests builds a policy of n tests over distinct sources, cycling through the given
// number of them: test i has src "group:team-<i mod sources>" and accepts "tag:t<i>:22".
func policyOfTests(n, sources int) string {
	var items []string
	for i := 0; i < n; i++ {
		items = append(items, fmt.Sprintf(`{"src": "group:team-%d", "accept": ["tag:t%d:22"]}`, i%sources, i))
	}
	return `{"tests": [` + strings.Join(items, ",\n") + `]}`
}

func parsed(t *testing.T, text string) *acl.Doc {
	t.Helper()
	d, err := acl.Parse(context.Background(), []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// A generated policy of 50 tests over 10 sources. A failure that names a source
// and a destination is placed on its one test; one that names a destination no test with
// that source lists (the server quoted an address where the test wrote a name) or none at
// all gets every test of the source, labelled as such: never "cannot tell".
func TestLocateFindsEveryCandidateNeverCannotTell(t *testing.T) {
	d := parsed(t, policyOfTests(50, 10))
	ctx := context.Background()
	exact, candidates := 0, 0
	for i := 0; i < 50; i++ {
		src := fmt.Sprintf("group:team-%d", i%10)
		p, err := placeMessage(ctx, d, src, fmt.Sprintf(`%saddress "tag:t%d:22" (protocol "tcp"): want: Accept, got: Drop`, testHeading, i))
		if err != nil || p.basis != placedByTest {
			t.Fatalf("test %d: %+v, %v", i, p, err)
		}
		if len(p.locations) == 1 && p.locations[0].Match == acl.MatchSrcAndDestination && p.locations[0].Pointer == fmt.Sprintf("/tests/%d", i) && p.cut == 0 {
			exact++
		}
		// The same source with an address no test lists: the five tests of the source.
		q, err := placeMessage(ctx, d, src, testHeading+`address "192.0.2.10:22" (protocol "tcp"): want: Accept, got: Drop`)
		if err != nil {
			t.Fatal(err)
		}
		if len(q.locations) == 5 && q.cut == 0 && q.locations[0].Match == acl.MatchSrcOnly {
			candidates++
		}
	}
	if exact != 50 || candidates != 50 {
		t.Errorf("%d of 50 failures placed on their one test, %d of 50 given the 5 tests of their source; want all of both", exact, candidates)
	}
	// A source no test has: no locations and no cut, which is not a verdict on the policy.
	p, err := placeMessage(ctx, d, "group:nobody", testHeading+`address "tag:t1:22": want: Accept, got: Drop`)
	if err != nil || p.basis != placedByTest || len(p.locations) != 0 || p.cut != 0 {
		t.Errorf("an unknown source: %+v, %v; want a test placement with nothing found", p, err)
	}
}

// Locate lists 100 places and counts the rest; the placement carries the count.
func TestAPlacementCarriesLocatesCutCount(t *testing.T) {
	d := parsed(t, policyOfTests(150, 1))
	p, err := placeMessage(context.Background(), d, "group:team-0", testHeading+`address "192.0.2.10:22": want: Accept, got: Drop`)
	if err != nil || len(p.locations) != acl.MaxLocations || p.cut != 50 {
		t.Errorf("150 tests with one source: %d locations, cut %d, %v; want %d and 50", len(p.locations), p.cut, err, acl.MaxLocations)
	}
	// A token that 150 strings hold is cut the same way.
	var items []string
	for i := 0; i < 150; i++ {
		items = append(items, `"tag:shared"`)
	}
	d = parsed(t, `{"groups": {"group:a": [`+strings.Join(items, ",")+`]}}`)
	p, err = placeMessage(context.Background(), d, "", testHeading+`user or host is invalid: tag not found: "tag:shared"`)
	if err != nil || p.basis != placedByToken || len(p.locations) != acl.MaxLocations || p.cut != 50 {
		t.Errorf("150 strings of one token: %+v, %v; want %d locations and a cut of 50", p, err, acl.MaxLocations)
	}
}

func TestAMessageIsPlacedByPositionOrTokenOrNotAtAll(t *testing.T) {
	d := parsed(t, "{\n  \"tagOwners\": {\"tag:db\": []},\n  \"tests\": [{\"src\": \"tag:db\", \"accept\": [\"tag:web:443\"]}]\n}")
	ctx := context.Background()
	for name, c := range map[string]struct {
		msg   string
		basis placeBasis
		line  int
		locs  int
	}{
		"a position":                      {"line 3, column 5: unexpected token", placedByPosition, 3, 0},
		"a quoted name the text holds":    {testHeading + `user or host is invalid: tag not found: "tag:web:443"`, placedByToken, 0, 1},
		"a quoted name it keys":           {testHeading + `user or host is invalid: tag not found: "tag:db"`, placedByToken, 0, 2},
		"a quoted name the text lacks":    {testHeading + `user or host is invalid: tag not found: "tag:nobody"`, placedByToken, 0, 0},
		"a message with nothing to place": {"test(s) failed", notPlaced, 0, 0},
		"an empty message":                {"", notPlaced, 0, 0},
	} {
		p, err := placeMessage(ctx, d, "tag:db", c.msg)
		if err != nil || p.basis != c.basis || p.line != c.line || len(p.locations) != c.locs || p.cut != 0 {
			t.Errorf("%s: %+v, %v; want basis %q, line %d, %d locations", name, p, err, c.basis, c.line, c.locs)
		}
	}
	// A cancelled context stops the search for a token.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := placeMessage(cancelled, d, "tag:db", testHeading+`tag not found: "tag:db"`); err == nil {
		t.Error("a cancelled context did not stop the token search")
	}
	// An SSH failure is placed in sshTests.
	ds := parsed(t, `{"sshTests": [{"src": "tag:p", "dst": ["tag:db"], "accept": ["root"]}]}`)
	p, err := placeMessage(ctx, ds, "tag:p", sshHeading+`src "tag:p" at "100.64.0.1", dst "tag:db" at "100.64.0.2", ssh user "root": want: "accept" got: "deny"`)
	if err != nil || p.basis != placedByTest || len(p.locations) != 1 || p.locations[0].Pointer != "/sshTests/0" {
		t.Errorf("an SSH failure: %+v, %v; want sshTests/0", p, err)
	}
}
