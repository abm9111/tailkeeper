package acl

import (
	"context"
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
)

func TestLocateMatchesSourceAndDestination(t *testing.T) {
	d := mustParse(t, `{
	"tests": [
		{"src": "group:a", "accept": ["tag:x:80"]},
		{"user": "group:a", "deny": ["tag:y:22"], "allow": ["tag:z:1"]},
		{"src": "group:b", "accept": ["tag:y:22"]},
		"not a test",
		{"src": "group:a", "accept": ["tag:y:22"]}
	]
}`)
	locs, _ := Locate(d, Failure{Src: "group:a", Dst: "tag:y:22"})
	if len(locs) != 2 || locs[0].Pointer != "/tests/1" || locs[0].Line != 4 || locs[0].Column != 3 || locs[1].Pointer != "/tests/4" || locs[1].Line != 7 {
		t.Fatalf("source and destination: %+v", locs)
	}
	for _, l := range locs {
		if l.Match != MatchSrcAndDestination {
			t.Errorf("match = %s", l.Match)
		}
	}
	// A legacy allow list counts as accept.
	if locs, _ := Locate(d, Failure{Src: "group:a", Dst: "tag:z:1"}); len(locs) != 1 || locs[0].Pointer != "/tests/1" {
		t.Errorf("allow: %+v", locs)
	}
	// No destination, or one no test lists: every test with the source, labelled as such.
	for _, dst := range []string{"", "tag:nowhere:1"} {
		locs, _ := Locate(d, Failure{Src: "group:a", Dst: dst})
		if len(locs) != 3 {
			t.Fatalf("dst %q: %+v", dst, locs)
		}
		for _, l := range locs {
			if l.Match != MatchSrcOnly {
				t.Errorf("dst %q: match = %s", dst, l.Match)
			}
		}
	}
	if locs, _ := Locate(d, Failure{Src: "nobody"}); len(locs) != 0 {
		t.Errorf("no such source: %+v", locs)
	}
	// Exact text only: a prefix, another case and a substring are different.
	for _, src := range []string{"group:", "GROUP:A", "group:a ", "roup:a"} {
		if locs, _ := Locate(d, Failure{Src: src}); len(locs) != 0 {
			t.Errorf("%q matched %+v", src, locs)
		}
	}
	// A name that embeds another destination and a verdict word does not confuse it.
	d = mustParse(t, `{"tests": [{"src": "tag:Accept-tag:y:22", "accept": ["tag:x:1"]}, {"src": "tag:p", "accept": ["tag:y:22"]}]}`)
	if locs, _ := Locate(d, Failure{Src: "tag:p", Dst: "tag:y:22"}); len(locs) != 1 || locs[0].Pointer != "/tests/1" {
		t.Errorf("embedded names: %+v", locs)
	}
}

func TestLocateSSHTestsAndTheLastSection(t *testing.T) {
	d := mustParse(t, `{
	"sshTests": [{"src": "group:a", "dst": ["tag:x"], "accept": ["root"]}, {"src": "group:a", "dst": ["tag:y"], "deny": ["root"]}],
	"tests": [{"src": "group:a", "accept": ["tag:y"]}]
}`)
	locs, _ := Locate(d, Failure{Src: "group:a", Dst: "tag:y", SSH: true})
	if len(locs) != 1 || locs[0].Pointer != "/sshTests/1" || locs[0].Line != 2 {
		t.Errorf("ssh: %+v", locs)
	}
	if locs, _ := Locate(d, Failure{Src: "group:a"}); len(locs) != 1 || locs[0].Pointer != "/tests/0" {
		t.Errorf("tests: %+v", locs)
	}
	// With the section written twice Go's decoder keeps the later array, and so does Locate
	// (the server refuses such a text, probe A-4).
	d = mustParse(t, `{"tests": [{"src": "a", "accept": ["x:1"]}], "Tests": [{"src": "b", "accept": ["x:1"]}]}`)
	if locs, _ := Locate(d, Failure{Src: "a"}); len(locs) != 0 {
		t.Errorf("the replaced array: %+v", locs)
	}
	if locs, _ := Locate(d, Failure{Src: "b"}); len(locs) != 1 || locs[0].Pointer != "/Tests/0" {
		t.Errorf("the later array: %+v", locs)
	}
	for _, text := range []string{`{}`, `{"tests": null}`, `{"tests": {"a": 1}}`, `{"tests": "x"}`} {
		if locs, _ := Locate(mustParse(t, text), Failure{Src: "a"}); len(locs) != 0 {
			t.Errorf("%s: %+v", text, locs)
		}
	}
	if locs, _ := Locate(nil, Failure{Src: "a"}); len(locs) != 0 {
		t.Errorf("no document: %+v", locs)
	}
}

// The text is compared as the server reads it: field names without regard to case, escapes
// decoded, a repeated field replaced by the later one.
func TestLocateReadsTheTextAsTheServerDoes(t *testing.T) {
	d := mustParse(t, `{"TESTS": [
		{"SRC": "group:a", "Accept": ["tag:y:22"]},
		{"s\u0072c": "group:a", "accept": ["tag:\u0079:22"]},
		{"src": "group:z", "src": "group:a", "accept": ["tag:y:22"]},
		{"src": "group:a", "accept": ["tag:q:1"], "accept": ["tag:y:22"]},
		{"src": "group:a", "accept": ["tag:y:22"], "accept": ["tag:q:1"]},
		{"`+strings.Repeat("s", 200)+`": "group:a", "src": "group:b"}
	]}`)
	locs, _ := Locate(d, Failure{Src: "group:a", Dst: "tag:y:22"})
	var got []string
	for _, l := range locs {
		got = append(got, l.Pointer)
	}
	// The element that repeats src keeps the later value (group:a); the one that repeats
	// accept keeps the later list, so only the fourth lists the destination.
	if want := []string{"/TESTS/0", "/TESTS/1", "/TESTS/2", "/TESTS/3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if locs, _ := Locate(d, Failure{Src: "group:b"}); len(locs) != 1 || locs[0].Pointer != "/TESTS/5" {
		t.Errorf("a long, unrelated field name: %+v", locs)
	}
}

// With 50 tests and 10 distinct sources a failure that names its destination is placed on
// one test, on this seed always (the measured fraction is 100%), and one that does not is placed
// on the five of its source. A regression in the matching shows as a lower fraction.
func TestLocateWithAGeneratedPolicy(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	var b strings.Builder
	b.WriteString("{\n\"tests\": [\n")
	type test struct{ src, dst string }
	var tests []test
	for i := range 50 {
		src := fmt.Sprintf("group:s%d", i%10)
		dst := fmt.Sprintf("tag:d%d:%d", rng.IntN(40), 1+rng.IntN(3))
		tests = append(tests, test{src, dst})
		fmt.Fprintf(&b, "\t{\"src\": %q, \"accept\": [%q]},\n", src, dst)
	}
	b.WriteString("]}\n")
	d := mustParse(t, b.String())
	one, bySrc := 0, 0
	for i, tc := range tests {
		locs, _ := Locate(d, Failure{Src: tc.src, Dst: tc.dst})
		found := false
		for _, l := range locs {
			if l.Pointer == fmt.Sprintf("/tests/%d", i) {
				found = true
			}
		}
		if !found {
			t.Fatalf("test %d is not among its own candidates: %+v", i, locs)
		}
		if len(locs) == 1 {
			one++
		}
		if all, _ := Locate(d, Failure{Src: tc.src}); len(all) == 5 {
			bySrc++
		}
	}
	if frac := float64(one) / float64(len(tests)); frac < 1 {
		t.Errorf("only %.0f%% of failures were placed on one test", 100*frac)
	}
	if bySrc != len(tests) {
		t.Errorf("a failure with no destination should list the 5 tests of its source: %d of 50", bySrc)
	}
}

// A policy of many tests with one source lists at most MaxLocations of them, those with the
// destination first, and a string that cannot be the one asked for is never decoded.
func TestLocateIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"tests": [`)
	for range 3 * MaxLocations {
		b.WriteString(`{"src": "s", "accept": ["x:1"]},`)
	}
	b.WriteString(`{"src": "s", "accept": ["y:2"]}]}`)
	d := mustParse(t, b.String())
	// The list is cut at MaxLocations and says how many matches it left out: the 301 tests of
	// the source, the 300 of the destination.
	if locs, cut := Locate(d, Failure{Src: "s"}); len(locs) != MaxLocations || locs[0].Match != MatchSrcOnly || cut != 3*MaxLocations+1-MaxLocations {
		t.Errorf("by source: %d listed, %d cut", len(locs), cut)
	}
	if locs, cut := Locate(d, Failure{Src: "s", Dst: "x:1"}); len(locs) != MaxLocations || locs[0].Match != MatchSrcAndDestination || cut != 3*MaxLocations-MaxLocations {
		t.Errorf("by destination: %d listed, %d cut", len(locs), cut)
	}
	// The one test that lists the destination is found past the cap on the source, and a list
	// that was not cut says so.
	locs, cut := Locate(d, Failure{Src: "s", Dst: "y:2"})
	if len(locs) != 1 || cut != 0 || locs[0].Match != MatchSrcAndDestination || locs[0].Pointer != fmt.Sprintf("/tests/%d", 3*MaxLocations) {
		t.Errorf("past the cap: %+v, %d cut", locs, cut)
	}
	if locs, cut := Locate(d, Failure{Src: "nobody"}); len(locs) != 0 || cut != 0 {
		t.Errorf("no match: %+v, %d cut", locs, cut)
	}
	// A string far longer than the one asked for cannot be it: the length rules it out.
	long := strings.Repeat("n", 1<<20)
	d = mustParse(t, `{"tests": [{"src": "`+long+`", "accept": ["`+long+`"]}, {"src": "s", "accept": ["d:1"]}]}`)
	if locs, _ := Locate(d, Failure{Src: "s", Dst: "d:1"}); len(locs) != 1 || locs[0].Pointer != "/tests/1" {
		t.Errorf("a long string: %+v", locs)
	}
	// An escaped string that is as long as the one asked for decodes to it.
	d = mustParse(t, `{"tests": [{"src": "\u0073", "accept": ["\u0064:1"]}]}`)
	if locs, _ := Locate(d, Failure{Src: "s", Dst: "d:1"}); len(locs) != 1 {
		t.Errorf("escapes: %+v", locs)
	}
}

func TestLocateTokenFindsNamesAndStrings(t *testing.T) {
	d := mustParse(t, string(fixture(t, "basic.hujson")))
	locs, more, err := LocateToken(context.Background(), d, "tag:web")
	if err != nil || more != 0 {
		t.Fatalf("%v, more %d", err, more)
	}
	var got []string
	for _, l := range locs {
		got = append(got, fmt.Sprintf("%s:%s:%d", l.Match, l.Pointer, l.Line))
	}
	want := []string{"key:/tagOwners/tag:web:12", "value:/grants/2/dst/0:48", "value:/ssh/0/dst/0:52", "value:/sshTests/0/dst/0:77"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tag:web:\n got  %v\n want %v", got, want)
	}
	// Every hit is a value or a key, in document order.
	last := 0
	for _, l := range locs {
		if l.Line < last {
			t.Errorf("not in document order: %v", got)
		}
		last = l.Line
		if l.Match != MatchKey && l.Match != MatchValue {
			t.Errorf("match = %s", l.Match)
		}
	}
	if locs, _, _ := LocateToken(context.Background(), d, "tag:nonexistent"); len(locs) != 0 {
		t.Errorf("a token that is not there: %+v", locs)
	}
	// The token is exact: not a prefix, not a part of a longer name.
	if locs, _, _ := LocateToken(context.Background(), d, "tag:we"); len(locs) != 0 {
		t.Errorf("a prefix: %+v", locs)
	}
	// Pointers escape, and the list is bounded with the rest counted.
	d = mustParse(t, `{"hosts": {"a/b": "x"}, "groups": {"g": [`+strings.Repeat(`"x",`, MaxLocations+25)+`]}}`)
	locs, more, _ = LocateToken(context.Background(), d, "x")
	if len(locs) != MaxLocations || more != 25+1 {
		t.Errorf("bounded: %d listed, %d more", len(locs), more)
	}
	if locs[0].Pointer != "/hosts/a~1b" || locs[0].Match != MatchValue {
		t.Errorf("escaped pointer: %+v", locs[0])
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := LocateToken(ctx, d, "x"); err == nil {
		t.Error("a context that is done")
	}
	if _, _, err := LocateToken(context.Background(), nil, "x"); err == nil {
		t.Error("no document")
	}
	old := maxWork
	t.Cleanup(func() { maxWork = old })
	maxWork = 5
	if _, _, err := LocateToken(context.Background(), d, "x"); err == nil {
		t.Error("a budget of 5 steps")
	}
	maxWork = old
	// A long path is cut.
	long := strings.Repeat("k", 900)
	d = mustParse(t, `{"groups": {"`+long+`": {"`+long+`": {"`+long+`": "needle"}}}}`)
	locs, _, _ = LocateToken(context.Background(), d, "needle")
	if len(locs) != 1 || len(locs[0].Pointer) > maxPointer+len("\u2026") {
		t.Errorf("long pointer: %+v", locs)
	}
}

// A token is found whether the text spells it plainly or with escapes, in a name or a
// value, and a string much longer or shorter than the token is passed over unread.
func TestLocateTokenDecodesEscapesAndSkipsOnLength(t *testing.T) {
	d := mustParse(t, `{"tagOwners": {"tag:\u0077eb": ["tag:w\u0065b", "tag:webs", "tag:we"], "tag:web": []}}`)
	locs, more, err := LocateToken(context.Background(), d, "tag:web")
	if err != nil || more != 0 {
		t.Fatalf("%v, %d", err, more)
	}
	var got []string
	for _, l := range locs {
		got = append(got, string(l.Match)+":"+l.Pointer)
	}
	want := []string{"key:/tagOwners/tag:web", "value:/tagOwners/tag:web/0", "key:/tagOwners/tag:web"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	long := strings.Repeat("n", 1<<20)
	d = mustParse(t, `{"hosts": {"`+long+`": "`+long+`", "h": "tag:web"}}`)
	// Two strings of a megabyte that cannot be the token cost a step each, not a megabyte.
	old := maxWork
	t.Cleanup(func() { maxWork = old })
	maxWork = 1000
	locs, _, err = LocateToken(context.Background(), d, "tag:web")
	maxWork = old
	if err != nil || len(locs) != 1 || locs[0].Pointer != "/hosts/h" {
		t.Errorf("long strings: %+v, %v", locs, err)
	}
}
