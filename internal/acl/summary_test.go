package acl

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func summarise(t testing.TB, text string) *Summary {
	t.Helper()
	s, err := Summarise(context.Background(), mustParse(t, text))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSummaryOfTheFixture(t *testing.T) {
	s := summarise(t, string(fixture(t, "basic.hujson")))
	row := func(name string) SectionSummary {
		for _, r := range s.Sections {
			if r.Name == name {
				return r
			}
		}
		t.Fatalf("no row %s", name)
		return SectionSummary{}
	}
	for name, want := range map[string]struct {
		state State
		count int
	}{
		"acls": {StateNonEmpty, 4}, "grants": {StateNonEmpty, 3}, "ssh": {StateNonEmpty, 2},
		"derpMap": {StateAbsent, 0}, "randomizeClientPort": {StateNonEmpty, 1},
	} {
		if r := row(name); r.State != want.state || r.Count != want.count || !r.Known {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if r := row("randomizeClientPort"); r.Scalar != "true" {
		t.Errorf("scalar: %+v", r)
	}
	if r := row("disableIPv4"); r.Scalar != "false" {
		t.Errorf("scalar: %+v", r)
	}
	if len(s.Sections) != len(sections) {
		t.Errorf("%d rows for %d known sections", len(s.Sections), len(sections))
	}
	if !reflect.DeepEqual(s.Groups, []string{"group:eng", "group:finance team@example.com", "group:ops"}) ||
		!reflect.DeepEqual(s.TagOwners, []string{"tag:ci", "tag:db", "tag:router", "tag:web"}) ||
		!reflect.DeepEqual(s.Hosts, []string{"build-box", "lan"}) ||
		!reflect.DeepEqual(s.Postures, []string{"posture:latest", "posture:managed"}) ||
		!reflect.DeepEqual(s.IPSets, []string{"ipset:servers"}) {
		t.Errorf("names: %+v", s)
	}
	if s.Tests != 2 || s.SSHTests != 1 || s.NamesTruncated || len(s.Unknown) != 0 {
		t.Errorf("counts: %+v", s)
	}
	if len(s.SyncedGroups) != 0 {
		t.Errorf("the synced group is defined in groups here: %v", s.SyncedGroups)
	}
}

func TestSummaryListsSyncedGroupsAndUnknownSections(t *testing.T) {
	s := summarise(t, `{
	"groups": {"group:local": ["a@example.com"]},
	"acls": [{"action": "accept", "src": ["group:Finance Team@example.com", "group:local", "group:eng@example.org"], "dst": ["group:eng@example.org:22"]}],
	"tagOwners": {"tag:a": ["group:owners@example.com"]},
	"nodeAttr": [], "futureSection": {}
}`)
	want := []string{"group:Finance Team@example.com", "group:eng@example.org", "group:owners@example.com"}
	if !reflect.DeepEqual(s.SyncedGroups, want) {
		t.Errorf("synced groups: %v, want %v", s.SyncedGroups, want)
	}
	if !reflect.DeepEqual(s.Unknown, []string{"nodeAttr", "futureSection"}) {
		t.Errorf("unknown: %v", s.Unknown)
	}
	var names []string
	for _, r := range s.Sections[len(sections):] {
		if r.Known || r.State != StateNonEmpty {
			t.Errorf("unknown row: %+v", r)
		}
		names = append(names, r.Name)
	}
	if !reflect.DeepEqual(names, []string{"futureSection", "nodeAttr"}) {
		t.Errorf("unknown rows: %v", names)
	}
	// A group in a key of groups is a definition, not a reference.
	if s := summarise(t, `{"groups": {"group:x@example.com": []}}`); len(s.SyncedGroups) != 0 || len(s.Groups) != 1 {
		t.Errorf("%+v", s)
	}
	// A section of the wrong type defines nothing and does not stop the summary.
	if s := summarise(t, `{"groups": "oops", "hosts": [1]}`); len(s.Groups) != 0 || len(s.Hosts) != 0 {
		t.Errorf("%+v", s)
	}
	// A string that splits at its colon into less than the prefix is no name.
	if s := summarise(t, `{"acls": [{"dst": ["group:80", "group::80", "group:", "grou:1@x"]}]}`); len(s.SyncedGroups) != 0 {
		t.Errorf("not names: %v", s.SyncedGroups)
	}
	// A name written with escapes is the name it decodes to, and ports are not part of it.
	if s := summarise(t, `{"acls": [{"dst": ["gro\u0075p:a@example.com:22,80"]}]}`); !reflect.DeepEqual(s.SyncedGroups, []string{"group:a@example.com"}) {
		t.Errorf("escaped: %v", s.SyncedGroups)
	}
}

func TestSummaryIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"groups": {`)
	for i := range MaxNames + 10 {
		fmt.Fprintf(&b, `"group:g%04d": [],`, i)
	}
	b.WriteString(`}, "acls": [{"action": "accept", "src": [`)
	for i := range MaxNames + 10 {
		fmt.Fprintf(&b, `"group:s%04d@example.com",`, i)
	}
	b.WriteString(`], "dst": ["x:1"]}]}`)
	s := summarise(t, b.String())
	if len(s.Groups) != MaxNames || len(s.SyncedGroups) != MaxNames || !s.NamesTruncated {
		t.Errorf("groups %d, synced %d, truncated %v", len(s.Groups), len(s.SyncedGroups), s.NamesTruncated)
	}
	long := strings.Repeat("n", 3000)
	if s := summarise(t, `{"hosts": {"`+long+`": "x"}}`); len(s.Hosts[0]) > maxPointer+len("\u2026") {
		t.Errorf("a name of %d bytes was not cut", len(s.Hosts[0]))
	}
}

// A section written as [] or {} is empty, not absent, and counts nothing; one written null is
// absent.
func TestSummaryOfEmptySections(t *testing.T) {
	s := summarise(t, `{"acls": [], "groups": {}, "hosts": null}`)
	for name, want := range map[string]SectionSummary{
		"acls":   {Name: "acls", Known: true, State: StateEmpty},
		"groups": {Name: "groups", Known: true, State: StateEmpty},
		"hosts":  {Name: "hosts", Known: true, State: StateAbsent},
		"grants": {Name: "grants", Known: true, State: StateAbsent},
	} {
		var got *SectionSummary
		for i := range s.Sections {
			if s.Sections[i].Name == name {
				got = &s.Sections[i]
			}
		}
		if got == nil || *got != want {
			t.Errorf("%s: %+v, want %+v", name, got, want)
		}
	}
	if len(s.Groups) != 0 || len(s.Hosts) != 0 || s.Tests != 0 {
		t.Errorf("an empty section defines nothing: %+v", s)
	}
}

// The sections the table does not know are bounded like the names: a row and a name for at
// most MaxNames of them, and a flag when there are more. The rows hold the first of them by
// name and Unknown the same ones in the order they were written. A section whose value is null
// is absent: it has no row and is not in Unknown.
func TestSummaryBoundsTheUnknownSectionsAndListsThemAsItsRowsDo(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{`)
	for i := MaxNames + 49; i >= 0; i-- { // written in descending order
		fmt.Fprintf(&b, `"u%04d": 1,`, i)
	}
	b.WriteString(`"acls": []}`)
	s := summarise(t, b.String())
	if !s.NamesTruncated {
		t.Error("1,050 unknown sections, and the summary does not say it cut them")
	}
	rows := s.Sections[len(sections):]
	if len(rows) != MaxNames || len(s.Unknown) != MaxNames {
		t.Fatalf("%d unknown rows and %d unknown names, want %d of each", len(rows), len(s.Unknown), MaxNames)
	}
	for i, r := range rows {
		if want := fmt.Sprintf("u%04d", i); r.Name != want || r.Known {
			t.Fatalf("row %d is %+v, want the unknown section %s", i, r, want)
		}
	}
	// The same names, in the order they were written: the highest first.
	for i, name := range s.Unknown {
		if want := fmt.Sprintf("u%04d", MaxNames-1-i); name != want {
			t.Fatalf("Unknown[%d] = %s, want %s", i, name, want)
		}
	}
	// Below the cap nothing is flagged, and a null section is in neither list.
	s = summarise(t, `{"zzz": null, "yyy": 1, "xxx": 1, "XXX": null, "acls": []}`)
	if s.NamesTruncated || !reflect.DeepEqual(s.Unknown, []string{"yyy"}) || len(s.Sections) != len(sections)+1 || s.Sections[len(sections)].Name != "yyy" {
		t.Errorf("null unknown sections: unknown %v, %d rows, truncated %v", s.Unknown, len(s.Sections), s.NamesTruncated)
	}
}

// A group defined past the cap on the list is still defined: it is not a synced group, and
// a reference too long to be a name is flagged, not silently dropped.
func TestSummaryDefinitionsPastTheCapAndLongReferences(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"groups": {`)
	for i := range MaxNames + 10 {
		fmt.Fprintf(&b, `"group:g%04d@example.com": [],`, i)
	}
	fmt.Fprintf(&b, `}, "acls": [{"src": ["group:g%04d@example.com"]}]}`, MaxNames+5)
	s := summarise(t, b.String())
	if len(s.SyncedGroups) != 0 || !s.NamesTruncated || len(s.Groups) != MaxNames {
		t.Errorf("synced %v, truncated %v, groups %d", s.SyncedGroups, s.NamesTruncated, len(s.Groups))
	}
	long := strings.Repeat("n", 1<<20)
	s = summarise(t, `{"acls": [{"src": ["group:`+long+`@example.com", "group:`+long+`", "`+long+`", "group:a@b"]}]}`)
	if !reflect.DeepEqual(s.SyncedGroups, []string{"group:a@b"}) || !s.NamesTruncated {
		t.Errorf("long references: %d names, truncated %v", len(s.SyncedGroups), s.NamesTruncated)
	}
	// An oversize string that is not a group reference does not set the flag.
	s = summarise(t, `{"acls": [{"src": ["`+long+`"]}]}`)
	if s.NamesTruncated || len(s.SyncedGroups) != 0 {
		t.Errorf("a long string that is no group: %+v", s)
	}
	// Written with escapes, too: a literal of many escapes is not decoded whole.
	esc := strings.Repeat(`\u0061`, 5000)
	s = summarise(t, `{"acls": [{"src": ["gro\u0075p:`+esc+`@example.com"]}]}`)
	if len(s.SyncedGroups) != 0 || !s.NamesTruncated {
		t.Errorf("escaped long reference: %d names, truncated %v", len(s.SyncedGroups), s.NamesTruncated)
	}
}

func TestSummariseSpendsABudgetAndHonoursTheContext(t *testing.T) {
	d := mustParse(t, string(fixture(t, "basic.hujson")))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Summarise(ctx, d); err == nil {
		t.Error("a context that is done")
	}
	if _, err := Summarise(context.Background(), nil); err == nil {
		t.Error("no document")
	}
	old := maxWork
	t.Cleanup(func() { maxWork = old })
	nf, _ := Normalise(context.Background(), d)
	maxWork = nf.Ops() + 3 // the normal form fits; the walk for synced groups does not
	if _, err := Summarise(context.Background(), d); err == nil {
		t.Error("a budget the walk for synced groups cannot fit in")
	}
}

func TestNormalFormBytesOfAText(t *testing.T) {
	a, err := NormalFormBytes(context.Background(), mustParse(t, string(fixture(t, "basic.hujson"))))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NormalFormBytes(context.Background(), mustParse(t, string(fixture(t, "crlf.hujson"))))
	if string(a) != string(b) || !strings.HasPrefix(string(a), normalFormVersion) {
		t.Error("the bytes depend on the line ends")
	}
	if _, err := NormalFormBytes(context.Background(), nil); err == nil {
		t.Error("no document")
	}
}
