package sanitize

import (
	"reflect"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tripwire"
)

type capGroup struct {
	Label string    `json:"label"` // no tag of its own: it is untrusted for being inside a tagged field
	Pair  [2]string `json:"pair"`
}

type capHolder struct {
	Group      capGroup  `json:"group" tk:"untrusted"`
	Array      [2]string `json:"array" tk:"untrusted"`
	PlainGroup capGroup  `json:"plainGroup"`
	PlainArray [2]string `json:"plainArray"`
}

// A tagged struct or array has everything inside it treated as untrusted: capped and
// redacted, though nothing inside carries a tag. An array is walked as a slice is, and a
// struct or an array that is not tagged is escaped and not capped.
func TestFieldsTreatsEverythingInsideATaggedStructOrArrayAsUntrusted(t *testing.T) {
	// Assembled at run time so that no credential shape sits in the source.
	key := "tskey" + "-auth-" + "kTEST1CNTRL-" + "notarealsecretvalue"
	long := strings.Repeat("x", 40) + r(0x1B)
	h := capHolder{
		Group:      capGroup{Label: long, Pair: [2]string{"a " + key, long}},
		Array:      [2]string{long, "b " + key},
		PlainGroup: capGroup{Label: long, Pair: [2]string{"a " + key, long}},
		PlainArray: [2]string{long, "b " + key},
	}
	Fields(&h, 40) // room for "a " and the notice that replaces the credential shape
	capped := strings.Repeat("x", 40-len(truncatedSuffix)) + truncatedSuffix
	for name, got := range map[string]string{
		"Group.Label": h.Group.Label, "Group.Pair[1]": h.Group.Pair[1], "Array[0]": h.Array[0],
	} {
		if got != capped {
			t.Errorf("%s = %q, want %q", name, got, capped)
		}
	}
	for name, got := range map[string]string{"Group.Pair[0]": h.Group.Pair[0], "Array[1]": h.Array[1]} {
		if strings.Contains(got, "tskey") || !strings.Contains(got, tripwire.Redacted) {
			t.Errorf("%s = %q, want the credential shape replaced", name, got)
		}
	}
	escaped := strings.Repeat("x", 40) + `\u{001B}`
	for name, got := range map[string]string{
		"PlainGroup.Label": h.PlainGroup.Label, "PlainGroup.Pair[1]": h.PlainGroup.Pair[1], "PlainArray[0]": h.PlainArray[0],
	} {
		if got != escaped {
			t.Errorf("%s = %q, want it escaped and not capped: %q", name, got, escaped)
		}
	}
	for name, got := range map[string]string{"PlainGroup.Pair[0]": h.PlainGroup.Pair[0], "PlainArray[1]": h.PlainArray[1]} {
		if !strings.Contains(got, key) {
			t.Errorf("%s = %q, want the untagged field to keep the credential shape (the tripwire withholds the result)", name, got)
		}
	}
}

// A type that holds itself, by a pointer or in a slice, is read once: UntrustedPaths does not
// follow it again, and Fields still escapes every level of a value that does.
type listNode struct {
	Name string     `json:"name" tk:"untrusted"`
	Next *listNode  `json:"next"`
	Kids []listNode `json:"kids"`
}

func TestRecursiveTypesAreReadOnceAndFieldsStillWalkEveryLevel(t *testing.T) {
	if got := UntrustedPaths(reflect.TypeFor[listNode]()); !reflect.DeepEqual(got, []string{"name"}) {
		t.Errorf("UntrustedPaths = %v, want [name]", got)
	}
	n := listNode{Name: "a" + r(0x0A), Next: &listNode{Name: "b" + r(0x0A), Next: &listNode{Name: "c" + r(0x0A)}},
		Kids: []listNode{{Name: "d" + r(0x0A), Kids: []listNode{{Name: "e" + r(0x0A)}}}}}
	Fields(&n, 0)
	for name, got := range map[string]string{
		"Name": n.Name, "Next.Name": n.Next.Name, "Next.Next.Name": n.Next.Next.Name,
		"Kids[0].Name": n.Kids[0].Name, "Kids[0].Kids[0].Name": n.Kids[0].Kids[0].Name,
	} {
		if !strings.HasSuffix(got, `\u{000A}`) {
			t.Errorf("%s = %q, want it escaped", name, got)
		}
	}
	// The same type in two fields of one struct is read for each: it is out of the way of the
	// second once the first is read.
	type pair struct {
		A listNode `json:"a"`
		B listNode `json:"b"`
	}
	if got := UntrustedPaths(reflect.TypeFor[pair]()); !reflect.DeepEqual(got, []string{"a.name", "b.name"}) {
		t.Errorf("UntrustedPaths = %v, want [a.name b.name]", got)
	}
}

type skipsFields struct {
	Shown   string `json:"shown" tk:"untrusted"`
	Named   string `json:",omitempty" tk:"untrusted"`
	hidden  any    // an unexported interface: no one can set it, so no one can leave text in it
	private string `tk:"untrusted"`
	Gone    any    `json:"-" tk:"untrusted"` // never encoded, so never in a result
	Dash    string `json:"-" tk:"untrusted"`
}

// A field that is unexported, or that encoding/json never writes, is not a path of the
// result: UntrustedPaths leaves it out, and does not refuse the interface in it.
func TestUntrustedPathsSkipsUnexportedAndUnencodedFields(t *testing.T) {
	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("UntrustedPaths refused a field that is not part of the result: %v", p)
			}
		}()
		if got, want := UntrustedPaths(reflect.TypeFor[skipsFields]()), []string{"Named", "shown"}; !reflect.DeepEqual(got, want) {
			t.Errorf("UntrustedPaths = %v, want %v", got, want)
		}
	}()
	// Fields leaves what it cannot set as it is, and escapes what json never writes.
	v := skipsFields{Shown: "a" + r(0x0A), hidden: "h" + r(0x0A), private: "p" + r(0x0A), Dash: "d" + r(0x0A)}
	Fields(&v, 0)
	if v.Shown != `a\u{000A}` || v.Dash != `d\u{000A}` {
		t.Errorf("Shown = %q, Dash = %q, want both escaped", v.Shown, v.Dash)
	}
	if v.hidden != "h"+r(0x0A) || v.private != "p"+r(0x0A) {
		t.Errorf("an unexported field was rewritten: %q, %q", v.hidden, v.private)
	}
}
