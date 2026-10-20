package acl

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
)

func TestParseFindsEveryRepeatedKeyAtAnyDepth(t *testing.T) {
	d := mustParse(t, string(fixture(t, "duplicates.hujson")))
	type f struct {
		code            FindingCode
		pointer, key    string
		first           string
		line, firstLine int
		keeps           Keeps
	}
	var got []f
	for _, x := range d.Findings() {
		got = append(got, f{x.Code, x.Pointer, x.Key, x.FirstKey, x.Line, x.FirstLine, x.Keeps})
	}
	want := []f{
		// a group defined twice inside "groups": a duplicate at depth 1
		{FindingDuplicateKey, "/groups", "group:a", "group:a", 5, 3, KeepsLater},
		// groups and Groups: the server's decoder folds the name and merges the objects
		{FindingCaseCollision, "", "Groups", "groups", 7, 2, KeepsMerged},
		// acls twice: the later array replaces the earlier
		{FindingDuplicateKey, "", "acls", "acls", 10, 9, KeepsLater},
		// a rule that names its source three times, in two spellings
		{FindingDuplicateKey, "/tests/0", "src", "src", 12, 12, KeepsLater},
		{FindingCaseCollision, "/tests/0", "Src", "src", 12, 12, KeepsLater},
		// a route defined twice inside a nested map
		{FindingDuplicateKey, "/autoApprovers/routes", "192.0.2.0/24", "192.0.2.0/24", 14, 14, KeepsLater},
		// nodeAttr and NodeAttr: an unknown section still repeats
		{FindingCaseCollision, "", "NodeAttr", "nodeAttr", 16, 15, KeepsLater},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings:\n got  %+v\n want %+v", got, want)
	}
	if d.FindingsOmitted() != 0 {
		t.Errorf("omitted = %d", d.FindingsOmitted())
	}
}

// A map entry written twice keeps the later value whatever the values are: only a
// struct-valued field merges. The entries of derpMap's Regions are a map.
func TestAMapEntryWrittenTwiceKeepsTheLaterNotAMerge(t *testing.T) {
	d := mustParse(t, `{"derpMap": {"Regions": {"1": {"RegionID": 1}, "1": {"RegionID": 1, "Avoid": true}}}}`)
	fs := d.Findings()
	if len(fs) != 1 {
		t.Fatalf("findings: %+v", fs)
	}
	x := fs[0]
	if x.Code != FindingDuplicateKey || x.Pointer != "/derpMap/Regions" || x.Key != "1" || x.Keeps != KeepsLater {
		t.Errorf("finding: %+v, want duplicate_key at /derpMap/Regions, key 1, keeping the later", x)
	}
	// The same holds for a group written twice with object values anywhere a map is read,
	// while a repeated struct field (top-level groups, derpMap) still merges.
	d = mustParse(t, `{"hosts": {"a": {}, "a": {}}, "derpMap": {}, "DerpMap": {}}`)
	var keeps []Keeps
	for _, f := range d.Findings() {
		keeps = append(keeps, f.Keeps)
	}
	if !reflect.DeepEqual(keeps, []Keeps{KeepsLater, KeepsMerged}) {
		t.Errorf("keeps = %v, want [later merged]: %+v", keeps, d.Findings())
	}
}

// Keys of a map are exact: "Build" and "build" are two hosts, not a collision.
func TestParseDoesNotFoldTheKeysOfAMap(t *testing.T) {
	d := mustParse(t, `{"hosts": {"Build": "192.0.2.1", "build": "192.0.2.2"}, "groups": {"group:A": [], "group:a": []}}`)
	if len(d.Findings()) != 0 {
		t.Errorf("findings: %+v", d.Findings())
	}
}

// The structs the normal form folds are the structs Parse looks into: a collision inside one
// of them is a finding, at the pointer of the object that holds the two spellings. The values
// of postures, attrConfig and externalTailnets, the regions of derpMap and the nodes of a
// region are such structs; the keys of the maps around them are exact.
func TestParseFindsACaseCollisionInsideEveryNestedStruct(t *testing.T) {
	for name, c := range map[string]struct{ text, pointer string }{
		"posture":         {`{"postures": {"posture:a": {"assertions": ["x"], "Assertions": ["y"]}}}`, "/postures/posture:a"},
		"attrConfig":      {`{"attrConfig": {"x": {"broadcastToPeers": ["a"], "BroadcastToPeers": ["b"]}}}`, "/attrConfig/x"},
		"externalTailnet": {`{"externalTailnets": {"x": {"allowExternalReferencesTo": ["a"], "AllowExternalReferencesTo": ["b"]}}}`, "/externalTailnets/x"},
		"derpMap region":  {`{"derpMap": {"regions": {"1": {"regionID": 1, "RegionID": 2}}}}`, "/derpMap/regions/1"},
		"derpMap node":    {`{"derpMap": {"regions": {"1": {"nodes": [{"name": "a", "Name": "b"}]}}}}`, "/derpMap/regions/1/nodes/0"},
		"autoApprovers":   {`{"autoApprovers": {"routes": {}, "Routes": {}}}`, "/autoApprovers"},
		"derpMap":         {`{"derpMap": {"regions": {}, "Regions": {}}}`, "/derpMap"},
	} {
		d := mustParse(t, c.text)
		var got []string
		for _, f := range d.Findings() {
			if f.Code == FindingCaseCollision {
				got = append(got, f.Pointer)
			}
		}
		if !reflect.DeepEqual(got, []string{c.pointer}) {
			t.Errorf("%s: case collisions at %q, want %q (%+v)", name, got, c.pointer, d.Findings())
		}
	}
	// The map around a struct stays exact, and so does the map of regions.
	d := mustParse(t, `{"postures": {"posture:a": {}, "Posture:a": {}}, "derpMap": {"regions": {"a": {}, "A": {}}}}`)
	if len(d.Findings()) != 0 {
		t.Errorf("exact keys of a map: %+v", d.Findings())
	}
}

func TestParseReportsPositionsOfBothKeys(t *testing.T) {
	d := mustParse(t, "{\n  \"tests\": [],\n\t\"Tests\": []}")
	fs := d.Findings()
	if len(fs) != 1 {
		t.Fatalf("findings: %+v", fs)
	}
	x := fs[0]
	if x.Line != 3 || x.Column != 2 || x.FirstLine != 2 || x.FirstColumn != 3 || x.Keeps != KeepsLater {
		t.Errorf("finding: %+v", x)
	}
}

func TestUnknownSectionsAreListedOnceAsFirstSpelled(t *testing.T) {
	d := mustParse(t, string(fixture(t, "duplicates.hujson")))
	if got := d.UnknownSections(); !reflect.DeepEqual(got, []string{"nodeAttr", "futureSection"}) {
		t.Errorf("unknown sections: %v", got)
	}
	d = mustParse(t, string(fixture(t, "basic.hujson")))
	if len(d.UnknownSections()) != 0 || len(d.Findings()) != 0 {
		t.Errorf("basic.hujson: unknown %v, findings %v", d.UnknownSections(), d.Findings())
	}
	// A known section spelled in another case is known.
	d = mustParse(t, `{"ACLs": [], "TagOwners": {}}`)
	if len(d.UnknownSections()) != 0 {
		t.Errorf("unknown: %v", d.UnknownSections())
	}
}

// Findings are cut at MaxFindings and the rest counted; a deep path with long keys does not
// make a pointer longer than the cap.
func TestFindingsAreBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"groups": {`)
	for i := range MaxFindings + 50 {
		fmt.Fprintf(&b, `"group:a": [], "group:b%d": [],`, i)
	}
	b.WriteString(`}}`)
	d := mustParse(t, b.String())
	// "group:a" repeats 149 times after its first appearance.
	if len(d.Findings()) != MaxFindings || d.FindingsOmitted() != 49 {
		t.Errorf("findings = %d, omitted = %d, want %d and 49", len(d.Findings()), d.FindingsOmitted(), MaxFindings)
	}

	long := strings.Repeat("k", 900)
	deep := `{"groups": {"` + long + `": {"` + long + `": {"` + long + `": {"x": 1, "x": 2}}}}}`
	d = mustParse(t, deep)
	if len(d.Findings()) != 1 {
		t.Fatalf("findings: %+v", d.Findings())
	}
	if p := d.Findings()[0].Pointer; len(p) > maxPointer+len("\u2026") || !strings.HasSuffix(p, "\u2026") {
		t.Errorf("pointer of %d bytes was not cut", len(p))
	}
	d = mustParse(t, `{"groups": {"`+strings.Repeat("\u00e9", 2000)+`": 1, "`+strings.Repeat("\u00e9", 2000)+`": 2}}`)
	if k := d.Findings()[0].Key; len(k) > maxPointer+len("\u2026") || !strings.HasSuffix(k, "\u2026") {
		t.Errorf("key of %d bytes was not cut", len(k))
	}
}

// Objects of up to eight members are checked pair by pair and larger ones with a map; the
// two must find the same repeats.
func TestSmallAndLargeObjectsFindTheSameRepeats(t *testing.T) {
	for n := 2; n <= 20; n++ {
		var b strings.Builder
		b.WriteString(`{"groups": {`)
		for i := range n {
			fmt.Fprintf(&b, `"k%d": [],`, i%(n-1)) // one key repeats: k0
		}
		b.WriteString(`}}`)
		d := mustParse(t, b.String())
		if fs := d.Findings(); len(fs) != 1 || fs[0].Key != "k0" || fs[0].Code != FindingDuplicateKey {
			t.Errorf("%d members: findings %+v", n, fs)
		}
	}
}

// The top level is looked up by the section key, which folds case; a name that only
// differs in case is one section.
func TestTopLevelNamesFoldCase(t *testing.T) {
	d := mustParse(t, `{"ACLs": [], "acls": [], "AcLs": []}`)
	if got := d.byKey[sectionKey("acls")]; len(got) != 3 {
		t.Errorf("occurrences of acls: %v", got)
	}
	if len(d.Findings()) != 2 {
		t.Errorf("findings: %+v", d.Findings())
	}
}

func TestPointersEscapeTheirTokensAndNamesAreDecoded(t *testing.T) {
	d := mustParse(t, `{"groups": {"a/b~c": {"x": 1, "x": 2}, "group:\"q\"": {"y": 1, "y": 2}, "\u00e9": {"z": 1, "z": 2}}}`)
	var got []string
	for _, f := range d.Findings() {
		got = append(got, f.Pointer)
	}
	want := []string{"/groups/a~1b~0c", `/groups/group:"q"`, "/groups/\u00e9"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pointers: got %q, want %q", got, want)
	}
	// A section whose name is spelled with an escape is the section.
	d = mustParse(t, `{"gr\u006fups": {}, "ACLS": [], "t\u0065sts": []}`)
	if len(d.UnknownSections()) != 0 {
		t.Errorf("unknown: %v", d.UnknownSections())
	}
}

// Building a finding costs about 1 KiB however long the keys above it are, and a repeat
// past the cap costs nothing: the meter sees one tick per repeat, so the allocation is the
// only thing that bounds a long parent key wrapping many repeated members.
func TestARepeatPastTheCapDoesNotPayForALongParentKey(t *testing.T) {
	const keyLen, repeats = 300 << 10, 3000
	var b strings.Builder
	b.WriteString(`{"groups": {"` + strings.Repeat("k", keyLen) + `": {`)
	for range repeats {
		b.WriteString(`"a":1,`)
	}
	b.WriteString(`}}}`)
	src := []byte(b.String())

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	d, err := Parse(context.Background(), src)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Findings()) != MaxFindings || d.FindingsOmitted() != repeats-1-MaxFindings {
		t.Fatalf("findings = %d, omitted = %d", len(d.Findings()), d.FindingsOmitted())
	}
	// Paying for the parent key on every repeat would allocate keyLen * repeats = 900 MB.
	// The parse itself needs a few MB.
	got := after.TotalAlloc - before.TotalAlloc
	t.Logf("Parse allocated %d bytes for a %d-byte text", got, len(src))
	if got > 24<<20 {
		t.Errorf("Parse allocated %d bytes for a %d-byte text; a repeat must not rebuild the path", got, len(src))
	}
}

// pointerOf stops building once it passes the cap, and must still agree with building the
// whole pointer and cutting it.
func TestPointerOfEqualsTheWholePointerCut(t *testing.T) {
	lit := func(s string) pathElem { return pathElem{key: &hujson.Value{Value: hujson.Literal(`"` + s + `"`)}} }
	bs := string(rune(92))
	long := strings.Repeat("k", 5000)
	esc := strings.Repeat(bs+"u0041", 3000)
	paths := map[string][]pathElem{
		"empty":        nil,
		"short":        {lit("groups"), {idx: 7}, lit("a/b~c")},
		"long key":     {lit("groups"), lit(long), {idx: 1}},
		"escaped key":  {lit(esc), lit("x")},
		"slash escape": {lit(strings.Repeat(bs+"u002f", 1500)), lit("x")},
		"multibyte":    {lit(strings.Repeat("\u00e9", 3000)), lit("x")},
		"surrogates":   {lit(strings.Repeat(bs+"ud83d"+bs+"ude00", 800)), lit("x")},
		"many shallow": nil,
		"just under":   {lit(strings.Repeat("k", maxPointer-1))},
		"just over":    {lit(strings.Repeat("k", maxPointer))},
		"exactly cap":  {lit(strings.Repeat("k", maxPointer-1)), {idx: 3}},
	}
	for range 2000 {
		paths["many shallow"] = append(paths["many shallow"], pathElem{idx: 12345})
	}
	for name, p := range paths {
		var whole []byte
		for _, e := range p {
			whole = append(whole, '/')
			if e.key != nil {
				whole = append(whole, escapePointer(nameOf(e.key))...)
			} else {
				whole = strconv.AppendInt(whole, int64(e.idx), 10)
			}
		}
		want := capText(string(whole))
		if got := pointerOf(p); got != want {
			t.Errorf("%s: pointerOf (%d bytes) differs from the cut whole pointer (%d bytes)", name, len(got), len(want))
		}
	}
}
