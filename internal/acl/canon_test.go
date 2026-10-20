package acl

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
)

// canonOf writes the canonical JSON of the members named "v" of {"v": ..., "v": ...},
// which are the layers of one value.
func canonOf(t testing.TB, text string, o canonOpts) string {
	t.Helper()
	d := mustParse(t, text)
	var layers []*hujson.Value
	for _, occ := range d.top {
		if occ.name == "v" {
			layers = append(layers, occ.val)
		}
	}
	if len(layers) == 0 {
		t.Fatalf("%s has no member v", text)
	}
	out, err := appendCanon(newMeter(context.Background()), nil, layers, o)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestCanonicalFormIgnoresSpellingButKeepsEveryField(t *testing.T) {
	rule := canonOpts{fold: true, setFields: map[string]bool{"src": true, "dst": true}}
	want := `{"action":"accept","dst":["a","b"],"future":{"a":2,"b":1},"src":["x","y"]}`
	for _, in := range []string{
		`{"v": {"action": "accept", "src": ["y", "x"], "dst": ["b", "a"], "future": {"b": 1, "a": 2}}}`,
		`{"v": {"Future": {"a": 2, "b": 1}, "SRC": ["x", "y", "x"], "Dst": ["a", "b"], "ACTION": "accept"}}`,
		"{\"v\": {\n // comment\n \"src\": [\"x\", \"y\",], \"dst\": [\"a\", \"b\"], \"action\": \"acc\\u0065pt\", \"future\": {\"b\": 1, \"a\": 2,},\n}}",
	} {
		if got := canonOf(t, in, rule); got != want {
			t.Errorf("%s\n got  %s\n want %s", in, got, want)
		}
	}
	// The field nothing knows about is in the text, and a change to it changes the text.
	if a, b := canonOf(t, `{"v": {"src": ["x"], "future": 1}}`, rule), canonOf(t, `{"v": {"src": ["x"], "future": 2}}`, rule); a == b {
		t.Error("a change inside an unknown field is invisible")
	}
	// The keys of a map are exact.
	if got := canonOf(t, `{"v": {"B": 1, "a": 2}}`, canonOpts{}); got != `{"B":1,"a":2}` {
		t.Errorf("map keys: %s", got)
	}
}

func TestCanonicalStringsHaveOneSpelling(t *testing.T) {
	for in, want := range map[string]string{
		`"A\/b"`:       `"A/b"`,
		`"\u0041"`:     `"A"`,
		`"\ud800"`:     "\"\ufffd\"",
		`"tab\there"`:  `"tab\there"`,
		`"q\"uote"`:    `"q\"uote"`,
		`"\u0001"`:     `"\u0001"`,
		`"\u007f"`:     `"\u007f"`,
		"\"\u00e9\"":   "\"\u00e9\"",
		`"\u00e9"`:     "\"\u00e9\"",
		`"line\nfeed"`: `"line\nfeed"`,
		`"cr\rhere"`:   `"cr\rhere"`,
		`1.50`:         `1.50`,
		`true`:         `true`,
		`null`:         `null`,
	} {
		if got := canonOf(t, `{"v": `+in+`}`, canonOpts{}); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
	if got := string(appendJSONString(nil, "a\xffb")); got != "\"a\ufffdb\"" {
		t.Errorf("invalid UTF-8: %q", got)
	}
}

func TestCanonicalSetsAreSortedWithoutRepeatsAndListsKeepTheirOrder(t *testing.T) {
	set := canonOpts{sets: true}
	// Elements sort by their canonical text: "a" < "b" < 3 < null.
	if got := canonOf(t, `{"v": ["b", "a", "b", 3, null]}`, set); got != `["a","b",3,null]` {
		t.Errorf("set: %s", got)
	}
	if got := canonOf(t, `{"v": ["b", "a", "b"]}`, set); got != `["a","b"]` {
		t.Errorf("set: %s", got)
	}
	if got := canonOf(t, `{"v": ["b", "a", "b"]}`, canonOpts{}); got != `["b","a","b"]` {
		t.Errorf("list: %s", got)
	}
	// An array with an object in it is a list even where sets are asked for.
	if got := canonOf(t, `{"v": [{"b": 1}, "a"]}`, set); got != `[{"b":1},"a"]` {
		t.Errorf("mixed: %s", got)
	}
	// A set field of a struct is a set; the next field is not.
	rule := canonOpts{fold: true, setFields: map[string]bool{"src": true}}
	if got := canonOf(t, `{"v": {"src": ["b", "a"], "other": ["b", "a"]}}`, rule); got != `{"other":["b","a"],"src":["a","b"]}` {
		t.Errorf("set field: %s", got)
	}
}

// A repeated section is layers: objects merge, the later array or scalar replaces.
func TestCanonicalLayersFollowTheDecoder(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`{"v": [1], "v": [2]}`, `[2]`},
		// A repeated entry of a map is replaced whole, not merged.
		{`{"v": {"x": {"p": 1}}, "v": {"x": {"q": 2}}}`, `{"x":{"q":2}}`},
		{`{"v": {"x": {"p": 1}}, "v": {"x": {"p": 3}}}`, `{"x":{"p":3}}`},
		{`{"v": {"x": [1]}, "v": {"x": [2]}}`, `{"x":[2]}`},
		{`{"v": {"x": 1}, "v": 5}`, `5`},
		{`{"v": 5, "v": {"x": 1}}`, `{"x":1}`},
		{`{"v": {"a": 1}, "v": [1], "v": {"b": 2}}`, `{"b":2}`},
		// Different keys of two layers of a map are both kept.
		{`{"v": {"x": {"p": 1}}, "v": {"y": {"q": 2}}}`, `{"x":{"p":1},"y":{"q":2}}`},
	} {
		if got := canonOf(t, c.in, canonOpts{}); got != c.want {
			t.Errorf("%s: got %s, want %s", c.in, got, c.want)
		}
	}
	// Inside a struct, "Src" repeating "src" is one field and the later replaces.
	if got := canonOf(t, `{"v": {"src": ["a"], "Src": ["b"]}}`, canonOpts{fold: true}); got != `{"src":["b"]}` {
		t.Errorf("struct repeat: %s", got)
	}
}

// A repeated key keeps the later value for a map entry, while a repeated struct-valued field
// merges.
func TestCanonicalMapEntriesReplaceAndStructFieldsMerge(t *testing.T) {
	// A map: the later entry replaces the earlier one whole, inside one object or across layers.
	for _, in := range []string{
		`{"v": {"k": {"a": 1}, "k": {"b": 2}}}`,
		`{"v": {"k": {"a": 1}}, "v": {"k": {"b": 2}}}`,
		`{"v": {"k": {"a": 1}}, "v": {"k": {"z": 9}, "k": {"b": 2}}}`,
	} {
		if got := canonOf(t, in, canonOpts{}); got != `{"k":{"b":2}}` {
			t.Errorf("map %s: got %s, want {\"k\":{\"b\":2}}", in, got)
		}
	}
	// A map entry that is replaced by a non-object, and an object after a scalar.
	if got := canonOf(t, `{"v": {"k": {"a": 1}, "k": 5}}`, canonOpts{}); got != `{"k":5}` {
		t.Errorf("map entry replaced by a scalar: %s", got)
	}
	// A struct: a repeated object-valued field merges, in one object and across layers.
	for _, in := range []string{
		`{"v": {"k": {"a": 1}, "k": {"b": 2}}}`,
		`{"v": {"k": {"a": 1}}, "v": {"k": {"b": 2}}}`,
		`{"v": {"k": {"a": 1}, "K": {"b": 2}}}`,
	} {
		if got := canonOf(t, in, canonOpts{fold: true}); got != `{"k":{"a":1,"b":2}}` {
			t.Errorf("struct %s: got %s, want {\"k\":{\"a\":1,\"b\":2}}", in, got)
		}
	}
	// Under a map the entry keeps the later value even when the entries inside it merge in a struct.
	if got := canonOf(t, `{"v": {"k": {"a": 1}, "k": {"A": 2}}}`, canonOpts{}); got != `{"k":{"A":2}}` {
		t.Errorf("map entry: got %s, want {\"k\":{\"A\":2}}", got)
	}
}

// fieldsOf reads the fields of the members named "v" the way appendCanon does.
func fieldsOf(t testing.TB, text string, fold bool) []field {
	t.Helper()
	d := mustParse(t, text)
	var layers []*hujson.Value
	for _, occ := range d.top {
		if occ.name == "v" {
			layers = append(layers, occ.val)
		}
	}
	fs, err := objectFields(newMeter(context.Background()), objectLayers(layers), fold)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// The names of a field are parallel to its layers: Locate reads them to point at the
// member that won, so a reset must clear both.
func TestObjectFieldsKeepNamesParallelToLayers(t *testing.T) {
	for _, c := range []struct {
		in         string
		fold       bool
		wantLayers int
	}{
		{`{"v": {"k": {"a": 1}, "k": {"b": 2}}}`, false, 1},
		{`{"v": {"k": {"a": 1}}, "v": {"k": {"z": 9}, "k": {"b": 2}}}`, false, 1},
		{`{"v": {"k": {"a": 1}, "k": {"b": 2}}}`, true, 2},
		{`{"v": {"k": {"a": 1}}, "v": {"K": {"b": 2}}}`, true, 2},
	} {
		fs := fieldsOf(t, c.in, c.fold)
		if len(fs) != 1 {
			t.Fatalf("%s: %d fields, want 1", c.in, len(fs))
		}
		if f := fs[0]; len(f.names) != len(f.layers) || len(f.layers) != c.wantLayers {
			t.Errorf("%s (fold %v): %d names, %d layers, want %d of each", c.in, c.fold, len(f.names), len(f.layers), c.wantLayers)
		}
	}
}

// A nested object the caller does not describe is read as a map: no case folding, and a
// repeated object-valued field is replaced, not merged. A caller that knows the object is a
// struct says so, and then the server's reading is the one written.
func TestCanonicalNestedStructsAreDescribedByTheCaller(t *testing.T) {
	a := `{"v": {"outer": {"regionID": 1, "RegionID": 2}}}`
	b := `{"v": {"outer": {"RegionID": 2, "regionID": 1}}}`
	// Undescribed: the inner object is a map, so the two texts are equal here.
	plain := canonOpts{fold: true}
	if x, y := canonOf(t, a, plain), canonOf(t, b, plain); x != y || x != `{"outer":{"RegionID":2,"regionID":1}}` {
		t.Errorf("undescribed: %s and %s", x, y)
	}
	// Described: the server reads 2 in one and 1 in the other.
	described := canonOpts{fold: true, fields: map[string]canonOpts{"outer": {fold: true}}}
	if got := canonOf(t, a, described); got != `{"outer":{"regionID":2}}` {
		t.Errorf("described a: %s", got)
	}
	if got := canonOf(t, b, described); got != `{"outer":{"regionID":1}}` {
		t.Errorf("described b: %s", got)
	}
	// A described array of structs folds the keys of its elements.
	arr := `{"v": [{"regionID": 1, "RegionID": 2}]}`
	if got := canonOf(t, arr, canonOpts{}); got != `[{"RegionID":2,"regionID":1}]` {
		t.Errorf("undescribed array: %s", got)
	}
	if got := canonOf(t, arr, canonOpts{elem: &canonOpts{fold: true}}); got != `[{"regionID":2}]` {
		t.Errorf("described array: %s", got)
	}
	// The values of a described map are read with the given options.
	mp := `{"v": {"1": {"regionID": 1, "RegionID": 2}, "2": {"x": 1}}}`
	if got := canonOf(t, mp, canonOpts{elem: &canonOpts{fold: true}}); got != `{"1":{"regionID":2},"2":{"x":1}}` {
		t.Errorf("described map: %s", got)
	}
	// Descriptions nest: a derpMap is a struct, its regions a map of structs, their nodes an
	// array of structs.
	derp := canonOpts{fold: true, fields: map[string]canonOpts{
		"regions": {elem: &canonOpts{fold: true, fields: map[string]canonOpts{
			"nodes": {elem: &canonOpts{fold: true}},
		}}},
	}}
	in := `{"v": {"Regions": {"1": {"RegionID": 1, "regionid": 2, "nodes": [{"HostName": "a", "hostName": "b"}]}}}}`
	if got := canonOf(t, in, derp); got != `{"regions":{"1":{"nodes":[{"hostName":"b"}],"regionID":2}}}` {
		t.Errorf("nested: %s", got)
	}
	// What is not described reads as before: sets are inherited, and fields mean nothing to a map.
	if got := canonOf(t, `{"v": [["b", "a"]]}`, canonOpts{sets: true, elem: &canonOpts{}}); got != `[["a","b"]]` {
		t.Errorf("sets inherited: %s", got)
	}
	if got := canonOf(t, `{"v": {"x": ["b", "a"]}}`, canonOpts{fields: map[string]canonOpts{"x": {sets: true}}}); got != `{"x":["b","a"]}` {
		t.Errorf("fields on a map: %s", got)
	}
	// elem describes the values of a map and the elements of an array, not the fields of a
	// struct: a struct's field that fields does not describe is a map whatever elem says.
	if got := canonOf(t, `{"v": {"x": {"A": 1, "a": 2}}}`, canonOpts{fold: true, elem: &canonOpts{fold: true}}); got != `{"x":{"A":1,"a":2}}` {
		t.Errorf("elem on a struct: %s", got)
	}
	// A struct field described as a set field and with its own options keeps both.
	both := canonOpts{fold: true, setFields: map[string]bool{"x": true}, fields: map[string]canonOpts{"x": {elem: &canonOpts{fold: true}}}}
	if got := canonOf(t, `{"v": {"x": [{"B": 1}, {"b": 2}], "y": ["b", "a"]}}`, both); got != `{"x":[{"b":1},{"b":2}],"y":["b","a"]}` {
		t.Errorf("set field with options: %s", got)
	}
}

// An unknown field is spelled in lower case, unless lowering would make it the same field as
// another: U+0130 (I with a dot) lowers to "i", which is a different field to the server.
func TestUnknownFieldSpellingStaysInItsFoldClass(t *testing.T) {
	in := `{"v": {"\u0130": 1, "i": 2}}`
	got := canonOf(t, in, canonOpts{fold: true})
	if want := "{\"i\":2,\"\u0130\":1}"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	// The ordinary case still lowers.
	if got := canonOf(t, `{"v": {"Future": 1, "OTHER": 2}}`, canonOpts{fold: true}); got != `{"future":1,"other":2}` {
		t.Errorf("lowered: %s", got)
	}
	if got := fieldSpelling(foldKey("\u212a")); foldKey(got) != foldKey("\u212a") {
		t.Errorf("Kelvin sign spelled %q, which is another field", got)
	}
}

func TestCanonicalFormSpendsTheBudget(t *testing.T) {
	old := maxWork
	t.Cleanup(func() { maxWork = old })
	var b strings.Builder
	b.WriteString(`{"v": [`)
	for i := range 300 {
		fmt.Fprintf(&b, `"s%03d",`, (i*7)%300)
	}
	b.WriteString(`]}`)
	d := mustParse(t, b.String())
	v := []*hujson.Value{d.top[0].val}

	// The sort's comparisons are work too: 300 distinct strings cost well over 300.
	m := newMeter(context.Background())
	if _, err := appendCanon(m, nil, v, canonOpts{sets: true}); err != nil || m.used < 1500 {
		t.Errorf("used = %d, err = %v, want at least 1500 steps", m.used, err)
	}
	maxWork = 100
	_, err := appendCanon(newMeter(context.Background()), nil, v, canonOpts{sets: true})
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("err = %v, want the work limit", err)
	}
	// A budget spent by the comparisons alone is caught after the sort.
	maxWork = 600
	m = newMeter(context.Background())
	m.used = 0
	if _, err := appendCanon(m, nil, v, canonOpts{sets: true}); err == nil {
		t.Error("a budget of 600 steps should not cover the sort")
	}
}
