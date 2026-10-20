package acl

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
)

// sweepA and sweepB hold one of everything: every section shape, every kind of rule field,
// and enough difference between the two for every kind of change.
const sweepA = `{
	"groups": {"group:a": ["x"], "group:b": []}, "tagOwners": {"tag:a": []}, "hosts": {"h": "192.0.2.1"},
	"ipsets": {"ipset:s": ["add 192.0.2.1"]}, "postures": {"posture:p": ["a"], "posture:q": {"assertions": ["b"]}},
	"defaultSrcPosture": ["posture:p"],
	"acls": [{"action": "accept", "src": ["group:a", "group:n@example.com"], "dst": ["tag:a:80", "tag:b:22", "group:m@example.com:80"], "proto": "tcp", "srcPosture": ["posture:p"], "future": 1, "other": 2}],
	"grants": [{"src": ["group:b"], "dst": ["tag:c"], "ip": ["tcp:443", "udp:53", "80"], "via": ["tag:r"], "app": {"c": [{"k": 1}]}}],
	"ssh": [{"action": "check", "src": ["group:a"], "dst": ["tag:a"], "users": ["root"]}],
	"nodeAttrs": [{"target": ["tag:a"], "attr": ["funnel", "x"], "ipPool": ["192.0.2.0/24"], "future": 1}],
	"tests": [{"src": "group:a", "accept": ["tag:a:80"], "deny": ["tag:b:22"], "proto": "tcp", "srcPostureAttrs": {"k": 1}, "future": 1}],
	"sshTests": [{"src": "group:a", "dst": ["tag:a"], "accept": ["u"], "check": ["v"], "deny": ["w"]}],
	"autoApprovers": {"routes": {"192.0.2.0/24": ["tag:a"]}, "exitNode": ["tag:a"]},
	"derpMap": {"regions": {"900": {"regionID": 900}}}, "attrConfig": {"a": {"type": "string"}},
	"externalTailnets": {"t": {"externalID": "1"}}, "extraDNSRecords": [{"Name": "n", "Value": "192.0.2.1"}],
	"disableIPv4": false, "futureSection": {"a": 1}, "tests": [{"src": "group:a", "accept": ["tag:a:80"]}, {"src": "group:b", "deny": ["tag:b:22"]}], "groups": {"group:c": ["y"]}
}`

const sweepB = `{
	"groups": {"group:a": ["z"]}, "hosts": {"h": "192.0.2.2"}, "ipsets": {"ipset:s": ["remove 192.0.2.1"]},
	"postures": {"posture:p": ["a2"]},
	"acls": [{"action": "accept", "src": ["group:a", "*"], "dst": ["tag:a:80,81"], "proto": "tcp", "future": 2}],
	"ssh": [{"action": "accept", "src": ["group:a"], "dst": ["tag:a"], "users": ["root"]}],
	"nodeAttrs": [{"target": ["tag:a", "tag:b"], "attr": ["funnel"]}],
	"tests": [{"src": "group:a", "accept": ["tag:a:80"]}, {"src": "group:a", "accept": ["tag:a:80"]}],
	"autoApprovers": {"routes": {"192.0.2.0/24": ["tag:b"]}}, "derpMap": {"regions": {"900": {"regionID": 901}}},
	"futureSection": {"a": 2}, "otherSection": 1, "disableIPv4": true
}`

// sweepC and sweepD are a second pair for the comparison: groups of access atoms that gain
// and lose sources and ports, rules that carry every field an atom writes, entries of the
// node attributes, assertions of tests, and widenings of an ssh rule and of a posture.
const sweepC = `{
	"acls": [
		{"action": "accept", "src": ["a"], "dst": ["x:1"], "proto": "tcp", "srcPosture": ["posture:p"]},
		{"action": "accept", "src": ["b"], "dst": ["x:2"], "proto": "tcp", "srcPosture": ["posture:p"]},
		{"action": "accept", "src": ["c"], "dst": ["y:1-5"]}
	],
	"grants": [
		{"src": ["a", "b"], "dst": ["z"], "ip": ["tcp:80", "udp:53"], "via": ["tag:r"], "srcPosture": ["posture:p"], "app": {"c": [{"k": 1}]}, "extra": 1},
		{"src": ["d"], "dst": ["w"], "ip": ["22"]}
	],
	"ssh": [{"action": "check", "src": ["group:a"], "dst": ["tag:a"], "users": ["root"], "checkPeriod": "1h"}, {"action": "accept", "src": ["group:b"], "dst": ["tag:b"], "users": ["u"]}],
	"nodeAttrs": [{"target": ["tag:a"], "attr": ["x"]}, {"target": ["tag:b"], "attr": ["y", "z"], "ipPool": ["192.0.2.0/24"]}, "whole"],
	"tests": [{"src": "a", "accept": ["x:1", "x:2"], "deny": ["y:9"]}, {"src": "b", "proto": "tcp", "accept": ["z:80"]}],
	"sshTests": [{"src": "group:a", "dst": ["tag:a"], "accept": ["root"]}],
	"postures": {"posture:p": ["a", "b"]}, "defaultSrcPosture": ["posture:p"], "randomizeClientPort": true, "acls2": 1
}`

const sweepD = `{
	"acls": [
		{"action": "accept", "src": ["a", "e"], "dst": ["x:1,3"], "proto": "tcp", "srcPosture": ["posture:p"]},
		{"action": "accept", "src": ["f"], "dst": ["x:2-4"], "proto": "tcp", "srcPosture": ["posture:p"]},
		{"action": "accept", "src": ["*"], "dst": ["y:1-9"]}
	],
	"grants": [
		{"src": ["a", "g"], "dst": ["z"], "ip": ["tcp:80-90", "udp:53"], "via": ["tag:s"], "srcPosture": ["posture:q"], "app": {"c": [{"k": 2}]}, "extra": 2},
		{"src": ["d"], "dst": ["w"], "ip": ["22", "23"]}
	],
	"ssh": [{"action": "accept", "src": ["group:a", "*"], "dst": ["tag:a"], "users": ["root", "u"]}, {"action": "accept", "src": ["group:b"], "dst": ["tag:b"], "users": ["*"]}],
	"nodeAttrs": [{"target": ["tag:a", "tag:c"], "attr": ["x"]}, {"target": ["tag:b"], "attr": ["y"]}, "other"],
	"tests": [{"src": "a", "accept": ["x:1"], "deny": ["y:9", "y:8"]}, {"src": "b", "proto": "udp", "accept": ["z:80"]}, {"src": "c", "accept": ["w:1"]}],
	"sshTests": [{"src": "group:a", "dst": ["tag:a"], "accept": ["root", "u"], "check": ["v"]}],
	"postures": {"posture:p": ["a"]}, "randomizeClientPort": false, "acls3": 1
}`

// sweepE and sweepF are a third pair: the access sections move between absent, empty and
// non-empty, and a comment is swapped for another.
const sweepE = `{
	// the old note
	"acls": [], "grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"]}], "ssh": []
}`

const sweepF = `{
	/* the new note */
	"ssh": [{"action": "accept", "src": ["a"], "dst": ["t"], "users": ["root"]}], "grants": []
}`

// manyOf repeats item n times, as the elements of a JSON list.
func manyOf(item string, n int) string {
	return strings.TrimSuffix(strings.Repeat(item+",", n), ",")
}

// Every point at which the engine spends work can run out of budget, and each one stops
// with a too_complex error: never a panic, never a partial answer that reads as complete.
// The budget is lowered one step at a time until the call succeeds. A step that is swallowed
// and not returned shows as an answer at a lower budget that is not the whole one, which is
// why every result the calls compare holds content in each of its fields: a field that is
// empty at every budget cannot show it. Each call names what its whole answer must hold.
func TestEveryStepOfTheWorkBudgetFailsCleanly(t *testing.T) {
	old := maxWork
	t.Cleanup(func() { maxWork = old })
	ctx := context.Background()
	a, b := mustParse(t, sweepA), mustParse(t, sweepB)
	c, d := mustParse(t, sweepC), mustParse(t, sweepD)
	e, f := mustParse(t, sweepE), mustParse(t, sweepF)
	long := mustParse(t, `{"acls": [{"action": "accept", "src": ["group:`+strings.Repeat("x", maxSyncedRef+10)+`@example.com"], "dst": ["*:*"]}]}`)
	// More places than a list holds, and more findings than a list holds.
	hits := mustParse(t, `{"acls": [{"action": "accept", "src": [`+manyOf(`"tag:z"`, MaxLocations+5)+`], "dst": ["*:*"]}]}`)
	repeatedText := "{" + manyOf(`"hosts": {"h": "192.0.2.1"}`, MaxFindings+5) + "}"
	// Each call returns what it computed, as a value that compares, and whether the result
	// it returned was nil; the error is the engine's.
	type outcome struct {
		result any
		nilled bool
		err    error
	}
	diffOf := func(x, y *Doc) func() outcome {
		return func() outcome {
			r, err := Diff(ctx, x, y, DiffOptions{PageSize: MaxPage})
			if r == nil {
				return outcome{nilled: true, err: err}
			}
			return outcome{result: *r, err: err}
		}
	}
	summaryOf := func(x *Doc) func() outcome {
		return func() outcome {
			s, err := Summarise(ctx, x)
			if s == nil {
				return outcome{nilled: true, err: err}
			}
			return outcome{result: *s, err: err}
		}
	}
	diffHolds := func(r any) string {
		x := r.(DiffResult)
		if len(x.Changes) == 0 || x.Matched == 0 || x.Counts.CommentOnly+x.Counts.FormatOnly+x.Counts.Semantic == 0 {
			return "no changes"
		}
		return ""
	}
	type call struct {
		name string
		run  func() outcome
		// holds says what the whole answer lacks, or "" if it holds what the call is for.
		holds func(result any) string
	}
	calls := []call{
		{"Parse", func() outcome {
			d, err := Parse(ctx, []byte(sweepA))
			if d == nil {
				return outcome{nilled: true, err: err}
			}
			return outcome{result: fmt.Sprint(string(d.src), d.Findings(), d.FindingsOmitted(), d.UnknownSections(), d.Nodes()), err: err}
		}, func(r any) string {
			if !strings.Contains(r.(string), "duplicate_key") {
				return "no finding"
			}
			return ""
		}},
		{"Parse of more findings than a list holds", func() outcome {
			d, err := Parse(ctx, []byte(repeatedText))
			if d == nil {
				return outcome{nilled: true, err: err}
			}
			return outcome{result: fmt.Sprint(len(d.Findings()), d.FindingsOmitted()), err: err}
		}, func(r any) string {
			// The first of the 105 members is no repeat: 104 findings, 100 listed, 4 left out.
			if r.(string) != fmt.Sprint(MaxFindings, " ", 4) {
				return "findings are not cut at the list: " + r.(string)
			}
			return ""
		}},
		{"Normalise", func() outcome {
			n, err := Normalise(ctx, a)
			if n == nil {
				return outcome{nilled: true, err: err}
			}
			return outcome{result: string(n.Bytes()), err: err}
		}, func(r any) string {
			if !strings.Contains(r.(string), `"atom"`) {
				return "no atom"
			}
			return ""
		}},
		{"Diff", diffOf(a, b), diffHolds},
		{"Diff the other way", diffOf(b, a), diffHolds},
		{"Diff of a second pair", diffOf(c, d), diffHolds},
		{"Diff of a second pair the other way", diffOf(d, c), diffHolds},
		{"Diff of a third pair", diffOf(e, f), func(r any) string {
			if x := r.(DiffResult); x.Counts.Defaults == 0 || x.Counts.CommentOnly == 0 {
				return fmt.Sprintf("counts %+v", x.Counts)
			}
			return diffHolds(r)
		}},
		{"Diff of a third pair the other way", diffOf(f, e), func(r any) string {
			if x := r.(DiffResult); x.Counts.Defaults == 0 || x.Counts.CommentOnly == 0 {
				return fmt.Sprintf("counts %+v", x.Counts)
			}
			return diffHolds(r)
		}},
		{"Summarise", summaryOf(a), func(r any) string {
			x := r.(Summary)
			for name, n := range map[string]int{"Groups": len(x.Groups), "TagOwners": len(x.TagOwners), "Hosts": len(x.Hosts),
				"Postures": len(x.Postures), "IPSets": len(x.IPSets), "SyncedGroups": len(x.SyncedGroups), "Tests": x.Tests,
				"SSHTests": x.SSHTests, "Unknown": len(x.Unknown), "Sections": len(x.Sections)} {
				if n == 0 {
					return name + " is empty"
				}
			}
			if fmt.Sprint(x.SyncedGroups) != "[group:m@example.com group:n@example.com]" {
				return fmt.Sprint("synced groups: ", x.SyncedGroups)
			}
			return ""
		}},
		{"Summarise of a reference too long to read", summaryOf(long), func(r any) string {
			if !r.(Summary).NamesTruncated {
				return "the long reference is not reported"
			}
			return ""
		}},
		{"LocateToken", func() outcome {
			locs, more, err := LocateToken(ctx, a, "tag:a")
			if err != nil {
				return outcome{nilled: locs == nil && more == 0, err: err}
			}
			return outcome{result: fmt.Sprint(locs, more), err: err}
		}, func(r any) string {
			if strings.HasPrefix(r.(string), "[] ") {
				return "no location"
			}
			return ""
		}},
		{"LocateToken of more places than a list holds", func() outcome {
			locs, more, err := LocateToken(ctx, hits, "tag:z")
			if err != nil {
				return outcome{nilled: locs == nil && more == 0, err: err}
			}
			return outcome{result: fmt.Sprint(len(locs), more), err: err}
		}, func(r any) string {
			if r.(string) != fmt.Sprint(MaxLocations, " ", 5) {
				return "the places are not cut at the list: " + r.(string)
			}
			return ""
		}},
	}
	for _, c := range calls {
		name, run := c.name, c.run
		maxWork = old
		whole := run()
		if whole.err != nil || whole.nilled {
			t.Fatalf("%s with the whole budget: %v", name, whole.err)
		}
		if why := c.holds(whole.result); why != "" {
			t.Fatalf("%s: the whole answer is empty where the sweep needs content: %s", name, why)
		}
		limit := int64(0)
		for ; ; limit++ {
			maxWork = limit
			got := run()
			if got.err == nil {
				if !reflect.DeepEqual(got.result, whole.result) {
					t.Fatalf("%s with a budget of %d returned an answer unlike the whole one", name, limit)
				}
				break
			}
			var e *Error
			if !errors.As(got.err, &e) || e.Code != CodeTooComplex || e.Message == "" {
				t.Fatalf("%s with a budget of %d: %v, want a too_complex *Error", name, limit, got.err)
			}
			if !got.nilled {
				t.Fatalf("%s with a budget of %d returned a result with its error", name, limit)
			}
			if limit > 20000 {
				t.Fatalf("%s: still out of budget at %d steps", name, limit)
			}
		}
		// The first budget that works is what the call spends: one less is refused.
		if limit < 100 {
			t.Errorf("%s: finished in %d steps: the sweep covers nothing", name, limit)
		}
		maxWork = limit - 1
		if got := run(); !errors.Is(got.err, ErrTooComplex) {
			t.Errorf("%s with a budget of %d, one under what it spends: %v", name, limit-1, got.err)
		}
		t.Logf("%s spends %d steps", name, limit)
	}
}

// Locate has no budget to run out of (it makes one pass over one section's elements, at
// most the size of the text Parse accepted), so a lowered budget changes nothing about it.
func TestLocateIsNotMetered(t *testing.T) {
	old := maxWork
	t.Cleanup(func() { maxWork = old })
	d := mustParse(t, `{"tests": [{"src": "group:a", "accept": ["tag:a:80"], "deny": ["tag:b:22"]}]}`)
	want, _ := Locate(d, Failure{Src: "group:a"})
	if len(want) == 0 {
		t.Fatal("Locate finds nothing for the source of the test")
	}
	maxWork = 0
	if got, _ := Locate(d, Failure{Src: "group:a"}); !reflect.DeepEqual(got, want) {
		t.Errorf("Locate with no budget: %+v, want %+v", got, want)
	}
}

func TestRuleFieldsOfTheWrongTypeAreKeptWhole(t *testing.T) {
	// A string where a list belongs, an object where a string does, a number for the
	// protocol: each is unreadable as the field it should be, so it stays in the rule as
	// it was, and two rules that differ in it differ.
	for _, c := range []struct{ rule, other, kept string }{
		{`{"action": "accept", "src": "tag:a", "dst": ["x:1"]}`, `{"action": "accept", "src": "tag:b", "dst": ["x:1"]}`, `"src":"tag:a"`},
		{`{"action": "accept", "src": ["a"], "dst": {"x": 1}}`, `{"action": "accept", "src": ["a"], "dst": {"x": 2}}`, `"dst":{"x":1}`},
		{`{"action": "accept", "src": ["a"], "dst": ["x:1"], "proto": 6}`, `{"action": "accept", "src": ["a"], "dst": ["x:1"], "proto": 17}`, `"proto":6`},
		{`{"action": "accept", "src": ["a"], "dst": ["x:1"], "srcPosture": "p"}`, `{"action": "accept", "src": ["a"], "dst": ["x:1"], "srcPosture": "q"}`, `"srcPosture":"p"`},
		{`{"action": ["accept", "x"], "src": ["a"], "dst": ["x:1"]}`, `{"action": ["accept", "y"], "src": ["a"], "dst": ["x:1"]}`, `"action":["accept","x"]`},
		{`{"action": "accept", "src": [1], "dst": ["x:1"]}`, `{"action": "accept", "src": [2], "dst": ["x:1"]}`, `"src":[1]`},
	} {
		text, other := `{"acls": [`+c.rule+`]}`, `{"acls": [`+c.other+`]}`
		differ(t, c.rule, text, other)
		same(t, c.rule+" twice", text, `{"acls": [`+c.rule+`, `+c.rule+`]}`)
		// The atom carries the field it could not read as a quoted object of its own.
		if got := string(normalise(t, text).Bytes()); !strings.Contains(got, strconv.Quote("{"+c.kept+"}")) {
			t.Errorf("%s: the normal form %s does not keep %s whole", c.rule, got, c.kept)
		}
	}
	differ(t, "src as a string", `{"acls": [{"action": "accept", "src": "tag:a", "dst": ["x:1"]}]}`, `{"acls": [{"action": "accept", "src": "tag:b", "dst": ["x:1"]}]}`)
	differ(t, "proto as a number", `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"], "proto": 6}]}`, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"], "proto": 17}]}`)
	differ(t, "ip as a string", `{"grants": [{"src": ["a"], "dst": ["x"], "ip": "80"}]}`, `{"grants": [{"src": ["a"], "dst": ["x"], "ip": "81"}]}`)
	// Two fields nothing knows are both kept.
	differ(t, "two unknown fields", `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"], "f1": 1, "f2": 2}]}`, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"], "f1": 1, "f2": 3}]}`)
	// A grant with no destination is still an atom.
	if n := normalise(t, `{"grants": [{"src": ["a"], "ip": ["80"]}]}`); len(n.atoms) != 1 {
		t.Errorf("a grant with no destination: %d atoms", len(n.atoms))
	}
	if n := normalise(t, `{"acls": [{"action": "accept", "src": ["a"]}]}`); len(n.atoms) != 1 {
		t.Errorf("a rule with no destination: %d atoms", len(n.atoms))
	}
	// A test with no source, nothing to assert, and the shapes of ssh tests.
	differ(t, "ssh test with nothing asserted", `{"sshTests": [{"src": "a", "dst": ["t"]}]}`, `{"sshTests": [{"src": "b", "dst": ["t"]}]}`)
	differ(t, "ssh test with an empty user list", `{"sshTests": [{"src": "a", "dst": ["t"], "accept": []}]}`, `{"sshTests": [{"src": "a", "dst": ["u"], "accept": []}]}`)
	differ(t, "a test with an empty accept", `{"tests": [{"src": "a", "accept": []}]}`, `{"tests": [{"src": "b", "accept": []}]}`)
	differ(t, "an ssh test with no destination", `{"sshTests": [{"src": "a", "accept": ["u"]}]}`, `{"sshTests": [{"src": "a", "accept": ["v"]}]}`)
	differ(t, "a test with two sources", `{"sshTests": [{"src": ["a", "b"], "dst": ["t"], "accept": ["u"]}]}`, `{"sshTests": [{"src": ["a"], "dst": ["t"], "accept": ["u"]}]}`)
}

// A rule with an empty source list is still an atom, with no source, and not the atom of a
// rule whose one source is the empty string.
func TestARuleWithNoSourceIsStillAnAtom(t *testing.T) {
	n := normalise(t, `{"acls": [{"action": "accept", "src": [], "dst": ["x:1"]}]}`)
	if len(n.atoms) != 1 || len(n.atoms[0].src.items) != 0 {
		t.Errorf("a rule with no source: %+v", n.atoms)
	}
	differ(t, "no source and an empty source", `{"acls": [{"action": "accept", "src": [], "dst": ["x:1"]}]}`, `{"acls": [{"action": "accept", "src": [""], "dst": ["x:1"]}]}`)
	// An ssh rule whose users are not a list stays as it was, so a change to it is a change.
	differ(t, "ssh users that are not a list", `{"ssh": [{"action": "accept", "src": ["a"], "dst": ["t"], "users": 5}]}`, `{"ssh": [{"action": "accept", "src": ["a"], "dst": ["t"], "users": 6}]}`)
}

// Rules in grants that come before the same rules in acls give the atom the earlier line.
func TestAnAtomKeepsTheEarliestLineOfItsRules(t *testing.T) {
	text := "{\n\"grants\": [{\"src\": [\"a\"], \"dst\": [\"x\"], \"ip\": [\"80\"]}],\n\"acls\": [{\"action\": \"accept\", \"src\": [\"a\"], \"dst\": [\"x:80\"]}]}"
	n := normalise(t, text)
	if len(n.atoms) != 1 {
		t.Fatalf("atoms: %d", len(n.atoms))
	}
	d := mustParse(t, text)
	if line, _ := d.lineOf(n.atoms[0].ref); line != 2 {
		t.Errorf("the atom is placed on line %d, want the grant's line 2", line)
	}
	// Two rules of different sources, merged in stage 2, keep the earlier one too.
	text = "{\n\"acls\": [{\"action\": \"accept\", \"src\": [\"b\"], \"dst\": [\"x:80\"]},\n{\"action\": \"accept\", \"src\": [\"a\"], \"dst\": [\"x:80\"]}],\n\"grants\": [{\"src\": [\"c\"], \"dst\": [\"x\"], \"ip\": [\"80\"]}]}"
	n = normalise(t, text)
	if len(n.atoms) != 1 || n.atoms[0].src.items[0] != "a" || n.atoms[0].origin != originACLs|originGrants {
		t.Errorf("merged atom: %+v", n.atoms)
	}
}

func TestRulesAcrossTheTextAreBoundedToo(t *testing.T) {
	// Five rules of 240 destinations by 240 protocols are 288,000 atoms from a 15 KiB text.
	var b strings.Builder
	b.WriteString(`{"grants": [`)
	for r := range 5 {
		if r > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"src": ["s%d"], "dst": [`, r)
		for i := range 240 {
			fmt.Fprintf(&b, `"t%d",`, i)
		}
		b.WriteString(`"t"], "ip": [`)
		for i := range 240 {
			fmt.Fprintf(&b, `"p%d:80",`, i)
		}
		b.WriteString(`"80"]}`)
	}
	b.WriteString(`]}`)
	_, err := Normalise(context.Background(), mustParse(t, b.String()))
	if !errors.Is(err, ErrTooComplex) || !strings.Contains(err.Error(), "more than") {
		t.Errorf("err = %v, want too_complex from the running total", err)
	}
}

// The guards that no input reaches through Parse, called directly.
func TestInternalGuardsHoldOnOtherInput(t *testing.T) {
	number := hujson.Value{Value: hujson.Literal("1")}
	if got := objectLayers([]*hujson.Value{&number}); got != nil {
		t.Errorf("objectLayers of a number: %v", got)
	}
	m := newMeter(context.Background())
	if fields, err := objectFields(m, []*hujson.Value{&number}, false); err != nil || len(fields) != 0 {
		t.Errorf("objectFields of a number: %v %v", fields, err)
	}
	if got := litString(hujson.Literal(`"\q"`)); got != `"\q"` {
		t.Errorf("litString of a bad escape: %q", got)
	}
	obj := hujson.Value{Value: &hujson.Object{}}
	if got := nameOf(&obj); got != "" {
		t.Errorf("nameOf an object: %q", got)
	}
	if got := nameOf(&hujson.Value{Value: hujson.Literal(`"\q"`)}); got != `"\q"` {
		t.Errorf("nameOf a bad escape: %q", got)
	}
	d := mustParse(t, `{}`)
	if p := d.pointerOf(ref{top: 9}); p != "" {
		t.Errorf("pointerOf an unknown top: %q", p)
	}
	if line, col := d.lineOf(ref{}); line != 0 || col != 0 {
		t.Errorf("lineOf nothing: %d:%d", line, col)
	}
	st := newSetTable()
	s, _ := st.intern(m, []string{"a"})
	if u, err := st.union(m, []*idSet{s, s}); err != nil || u != s {
		t.Errorf("union of a set with itself: %v %v", u, err)
	}
}

func TestCommentScanningEdgeCases(t *testing.T) {
	scan := func(text string) textScan {
		t.Helper()
		sc, err := scanText(newMeter(context.Background()), []byte(text))
		if err != nil {
			t.Fatalf("scanText(%q): %v", text, err)
		}
		return sc
	}
	count := func(text string) int {
		n := 0
		for _, c := range scan(text).comments {
			n += c
		}
		return n
	}
	// A slash that starts nothing is text, not a comment; a comment may end the text.
	for text, want := range map[string]int{
		"{} /": 0, "{\"a\": 1} /x": 0, "{} // c": 1, "{} /* c */": 1, "{\"a\": \"/*\"} // x\n": 1,
		"{} /* a */ // b\n": 2, "{} /* never closed": 1, "{\"a\": \"//\"}": 0,
	} {
		if got := count(text); got != want {
			t.Errorf("%q holds %d comments, want %d", text, got, want)
		}
	}
	if n := commentDifference(scan("{} /* a */ // b\n").comments, scan("{}").comments); n != 2 {
		t.Errorf("two comments against none: %d", n)
	}
	if n := commentDifference(scan("{}").comments, scan("{} // c").comments); n != 1 {
		t.Errorf("none against one comment: %d", n)
	}
	// The layout ignores comments and nothing else.
	if scan("{} // c").layout != scan("{} ").layout {
		t.Error("a comment changes the layout")
	}
	for _, pair := range [][2]string{
		{"{} /", "{}"}, {`{"a": "x"}`, `{"a": "y"}`}, {`{"a": "\\"}`, `{"a": "\\\\"}`},
		{`{"a": "x`, `{"a": "y`}, {`{"a": "\""}`, `{"a": "\\"}`}, {`{"a": "\`, `{"a": "`},
	} {
		if scan(pair[0]).layout == scan(pair[1]).layout {
			t.Errorf("the layouts of %q and %q are the same", pair[0], pair[1])
		}
	}
}

// An entry of nodeAttrs that lists more attributes than the atoms the engine will build is
// refused with the limit named, before the atoms are built.
func TestANodeAttrEntryPastTheAtomLimitIsRefused(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"nodeAttrs": [{"target": ["tag:a"], "attr": [`)
	for i := 0; i <= MaxAtoms; i++ {
		fmt.Fprintf(&b, `"a%d",`, i)
	}
	b.WriteString(`"z"]}]}`)
	n, err := Normalise(context.Background(), mustParse(t, b.String()))
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeTooComplex || n != nil {
		t.Fatalf("Normalise = %v, %v, want a too_complex *Error and no result", n, err)
	}
	if want := fmt.Sprintf("a node attribute entry lists %d attributes, past the limit of %d atoms", MaxAtoms+2, MaxAtoms); e.Message != want {
		t.Errorf("message %q, want %q", e.Message, want)
	}
}

// hexValue reads the digits of an escape the quoter wrote; anything else is 255, which no
// digit is.
func TestHexValue(t *testing.T) {
	for c, want := range map[byte]byte{'0': 0, '9': 9, 'a': 10, 'f': 15, 'A': 10, 'F': 15, 'g': 255, 'G': 255, '/': 255, ':': 255, '@': 255, '`': 255, ' ': 255} {
		if got := hexValue(c); got != want {
			t.Errorf("hexValue(%q) = %d, want %d", c, got, want)
		}
	}
}

// A cut that would fall inside a character falls before it.
func TestCutsFallOnCharacterBoundaries(t *testing.T) {
	e := parseError(t, `{"a":"`+strings.Repeat("\xe2\x82\xac", 400)+`\q"}`)
	if !strings.HasSuffix(e.Message, "\xe2\x82\xac\xe2\x80\xa6") || len(e.Message) > maxMessage+len("\xe2\x80\xa6") {
		t.Errorf("message: %d bytes", len(e.Message))
	}
	if got := capText(strings.Repeat("\xe2\x82\xac", 500)); !strings.HasSuffix(got, "\xe2\x82\xac\xe2\x80\xa6") || len(got) > maxPointer+len("\xe2\x80\xa6") {
		t.Errorf("capText: %d bytes", len(got))
	}
}

func TestMoreKindsOfChange(t *testing.T) {
	// A rule with an action the engine does not know, and one with via, show both in the text.
	r := diff(t, `{"acls": [{"action": "deny", "src": ["a"], "dst": ["x:1"]}], "grants": [{"src": ["a"], "dst": ["y"], "ip": ["1"], "via": ["tag:r"]}]}`, `{}`)
	var texts []string
	for _, c := range r.Changes {
		texts = append(texts, c.Old.Text)
	}
	joined := strings.Join(texts, "\n")
	if !strings.Contains(joined, `"action":"deny"`) || !strings.Contains(joined, `"via":["tag:r"]`) {
		t.Errorf("texts: %s", joined)
	}
	// A repeated test added, a posture added, an ssh entry that is not an object.
	if r := diff(t, `{"tests": [{"src": "a", "accept": ["x:1"]}]}`, `{"tests": [{"src": "a", "accept": ["x:1"]}, {"src": "a", "accept": ["x:1"]}]}`); r.Counts.Semantic != 1 || r.Changes[0].Op != OpAdded || r.Changes[0].NewN != 2 {
		t.Errorf("a repeated test added: %+v", r.Changes)
	}
	if r := diff(t, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}]}`, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"], "srcPosture": ["p"]}]}`); r.Counts.Widening != 0 || r.Counts.Semantic == 0 {
		t.Errorf("a posture added: %+v", r.Counts)
	}
	if r := diff(t, `{"ssh": ["x"]}`, `{"ssh": ["y"]}`); r.Counts.Widening != 0 || r.Counts.Semantic != 2 {
		t.Errorf("ssh entries that are not objects: %+v", r.Counts)
	}
	// A cursor with the Tailscale-written changes ignored, and a page cut by size.
	var a, b strings.Builder
	a.WriteString(`{"groups": {`)
	b.WriteString(`{"nodeAttrs": [{"target": ["a"], "attr": ["funnel"]}], "groups": {`)
	for i := range 60 {
		fmt.Fprintf(&a, `"g%d": ["%s"],`, i, strings.Repeat("o", 3000))
		fmt.Fprintf(&b, `"g%d": ["%s"],`, i, strings.Repeat("n", 3000))
	}
	a.WriteString(`}}`)
	b.WriteString(`}}`)
	first := diff(t, a.String(), b.String(), DiffOptions{IgnoreTailscaleWritten: true, PageSize: MaxPage})
	if !first.Truncated || len(first.Changes) >= 60 || first.Matched != 60 {
		t.Fatalf("a page cut by size: %d listed of %d, truncated %v", len(first.Changes), first.Matched, first.Truncated)
	}
	next := diff(t, a.String(), b.String(), DiffOptions{IgnoreTailscaleWritten: true, PageSize: MaxPage, Cursor: first.NextChange})
	if len(next.Changes) == 0 || len(first.Changes)+len(next.Changes) > 60 {
		t.Errorf("the next page: %d", len(next.Changes))
	}
	// Many atoms in a changed group are shown in part, with the rest counted in the length.
	var old, new strings.Builder
	old.WriteString(`{"acls": [`)
	new.WriteString(`{"acls": [`)
	for i := range 400 {
		fmt.Fprintf(&old, `{"action": "accept", "src": ["s%d"], "dst": ["x:%d"]},`, i, i+1)
		fmt.Fprintf(&new, `{"action": "accept", "src": ["s%d"], "dst": ["x:%d"]},`, i, i+2)
	}
	old.WriteString(`]}`)
	new.WriteString(`]}`)
	r = diff(t, old.String(), new.String())
	if len(r.Changes) != 1 || !r.Changes[0].Old.Truncated || r.Changes[0].Old.Len < 10000 {
		t.Errorf("a group of many atoms: %+v", r.Changes[0].Old.Len)
	}
	// The delta of a group of several atoms is over all their sources and ports.
	r = diff(t, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}, {"action": "accept", "src": ["b"], "dst": ["x:2"]}]}`, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}, {"action": "accept", "src": ["c"], "dst": ["x:3"]}, {"action": "accept", "src": ["d"], "dst": ["x:4"]}]}`)
	if len(r.Changes) != 1 || len(r.Changes[0].Fields) != 2 || fmt.Sprint(r.Changes[0].Fields[0].Added) != "[c d]" || fmt.Sprint(r.Changes[0].Fields[0].Removed) != "[b]" {
		t.Errorf("group delta: %+v", r.Changes)
	}
}

func TestTransformsRefuseWhatTheGuardRefuses(t *testing.T) {
	ctx := context.Background()
	if _, err := ApplyPatch(ctx, []byte(`{}`), []byte(`[1]`)); !errors.Is(err, ErrInvalid) {
		t.Errorf("a patch whose operation is not an object: %v", err)
	}
	if _, err := StripTests(ctx, []byte("\xef\xbb\xbf{}")); !errors.Is(err, ErrInvalid) {
		t.Errorf("StripTests of a text with a byte order mark: %v", err)
	}
	if _, err := AppendTests(ctx, []byte("\xef\xbb\xbf{}"), [][]byte{[]byte(`{}`)}, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("AppendTests of a text with a byte order mark: %v", err)
	}
	if _, err := AppendTests(ctx, []byte(`[1]`), [][]byte{[]byte(`{}`)}, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("AppendTests of an array: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	for name, f := range map[string]func() error{
		"StripTests":  func() error { _, err := StripTests(cancelled, []byte(`{}`)); return err },
		"AppendTests": func() error { _, err := AppendTests(cancelled, []byte(`{}`), nil, nil); return err },
	} {
		if err := f(); !errors.Is(err, context.Canceled) {
			t.Errorf("%s with a context that is done: %v", name, err)
		}
	}
	// A patch the library applies in part is not applied in part: the error is returned and no text.
	if out, err := ApplyPatch(ctx, []byte(`{"a": 1}`), []byte(`[{"op":"add","path":"/b","value":1},{"op":"remove","path":"/zzz"}]`)); err == nil || out != nil {
		t.Errorf("a patch that fails half way: %v %q", err, out)
	}
}
