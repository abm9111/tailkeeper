package tools_test

import (
	"encoding"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// A type with MarshalJSON or MarshalText writes its own text into a result, after the
// sanitizer has walked the value: Fields escapes the strings in the fields it reaches and
// never sees what a method makes of them. So no type a tool returns may have one, unless it
// is listed here with the reason it is safe. A key of a map counts: encoding/json writes it
// with MarshalText.
var marshalerAllowed = map[reflect.Type]string{}

var (
	jsonMarshaler = reflect.TypeFor[json.Marshaler]()
	textMarshaler = reflect.TypeFor[encoding.TextMarshaler]()
)

// marshalers lists, as paths from t, every type reachable from it that can write its own
// JSON or text, and every interface (whatever it holds is written unseen), except the types
// in allowed. used collects the allowed types it met.
func marshalers(t reflect.Type, allowed map[reflect.Type]string, used map[reflect.Type]bool) []string {
	var found []string
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type, path string)
	walk = func(t reflect.Type, path string) {
		if path == "" {
			path = "(result)"
		}
		if _, ok := allowed[t]; ok {
			used[t] = true
			return
		}
		if t.Implements(jsonMarshaler) || reflect.PointerTo(t).Implements(jsonMarshaler) {
			found = append(found, path+" ("+t.String()+" has MarshalJSON)")
			return
		}
		if t.Implements(textMarshaler) || reflect.PointerTo(t).Implements(textMarshaler) {
			found = append(found, path+" ("+t.String()+" has MarshalText)")
			return
		}
		switch t.Kind() {
		case reflect.Interface:
			found = append(found, path+" ("+t.String()+" is an interface: what it holds is written unseen)")
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(t.Elem(), path+"[]")
		case reflect.Map:
			walk(t.Key(), path+"{key}")
			walk(t.Elem(), path+"{}")
		case reflect.Struct:
			if seen[t] {
				return
			}
			seen[t] = true
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				if !f.IsExported() || f.Tag.Get("json") == "-" {
					continue
				}
				walk(f.Type, path+"."+f.Name)
			}
			delete(seen, t)
		}
	}
	walk(t, "")
	return found
}

func TestNoToolResultTypeWritesItsOwnText(t *testing.T) {
	reg := newRegistry(t)
	used := map[reflect.Type]bool{}
	tools := reg.All()
	if len(tools) < 40 {
		t.Fatalf("found %d tools: want the whole registry", len(tools))
	}
	for _, tool := range tools {
		for _, f := range marshalers(tool.OutputType, marshalerAllowed, used) {
			t.Errorf("%s: %s: its text is not sanitized; give the field a plain type, or list the type in marshalerAllowed with the reason it is safe", tool.Meta.Name, f)
		}
	}
	var stale []string
	for typ := range marshalerAllowed {
		if !used[typ] {
			stale = append(stale, typ.String())
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("marshalerAllowed lists types no tool returns: %s", strings.Join(stale, ", "))
	}
}

// selfJSON, selfText and ptrText write their own text.
type selfJSON struct{ S string }

func (selfJSON) MarshalJSON() ([]byte, error) { return []byte(`"x"`), nil }

type selfText string

func (selfText) MarshalText() ([]byte, error) { return []byte("x"), nil }

type ptrText struct{ S string }

func (*ptrText) MarshalText() ([]byte, error) { return []byte("x"), nil }

// The walk finds a method wherever a result can hold the type, so a field added to a tool's
// result later is caught: in a struct, a pointer, a slice, a map's values and its keys, a
// field two levels down, and an interface; and it passes plain types, and listed ones.
func TestMarshalerWalkFindsAThrowawayTypeWherever(t *testing.T) {
	type deep struct {
		Inner struct{ Rows []map[string]*ptrText }
	}
	for name, typ := range map[string]reflect.Type{
		"MarshalJSON in a field":         reflect.TypeFor[struct{ A selfJSON }](),
		"MarshalText on a string type":   reflect.TypeFor[struct{ A selfText }](),
		"a pointer receiver":             reflect.TypeFor[struct{ A ptrText }](),
		"behind a pointer":               reflect.TypeFor[struct{ A *selfJSON }](),
		"in a slice":                     reflect.TypeFor[struct{ A []selfText }](),
		"in a map's values":              reflect.TypeFor[struct{ A map[string]selfJSON }](),
		"in a map's keys":                reflect.TypeFor[struct{ A map[selfText]string }](),
		"two levels down":                reflect.TypeFor[deep](),
		"an interface":                   reflect.TypeFor[struct{ A any }](),
		"the result itself":              reflect.TypeFor[selfJSON](),
		"time.Time, which is not listed": reflect.TypeFor[struct{ At time.Time }](),
	} {
		if got := marshalers(typ, nil, map[reflect.Type]bool{}); len(got) != 1 {
			t.Errorf("%s: found %q, want one", name, got)
		}
	}
	for name, typ := range map[string]reflect.Type{
		"plain fields": reflect.TypeFor[struct {
			A, B string
			C    int
			D    []string
			E    map[string]bool
		}](),
		"unexported": reflect.TypeFor[struct{ a selfJSON }](),
		"not encoded": reflect.TypeFor[struct {
			A selfJSON `json:"-"`
		}](),
		"a recursive type": reflect.TypeFor[node](),
	} {
		if got := marshalers(typ, nil, map[reflect.Type]bool{}); len(got) != 0 {
			t.Errorf("%s: found %q, want none", name, got)
		}
	}
	used := map[reflect.Type]bool{}
	allowed := map[reflect.Type]string{reflect.TypeFor[time.Time](): "digits only"}
	if got := marshalers(reflect.TypeFor[struct{ At time.Time }](), allowed, used); len(got) != 0 || !used[reflect.TypeFor[time.Time]()] {
		t.Errorf("a listed type: found %q, used %v", got, used)
	}
}

type node struct {
	Name     string
	Children []node
	Parent   *node
}
