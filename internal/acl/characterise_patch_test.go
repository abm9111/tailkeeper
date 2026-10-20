package acl

import (
	"testing"

	"github.com/tailscale/hujson"
)

// TestCharacteriseHuJSONPatch pins what hujson.Patch does with the operations the engine
// builds or passes on: where a new member goes, what it does to the comments and layout
// around it, and the text of its errors. ApplyPatch, StripTests and AppendTests stand on
// this. A bump of the pseudo-version that changes a row fails here first.
func TestCharacteriseHuJSONPatch(t *testing.T) {
	rows := []struct {
		name, text, patch string
		out               string // the packed result, when the patch applies
		err               string // the library's error, when it does not
	}{
		{"a member added at the end keeps the comments", "{\n  // c\n  \"a\": 1, // t\n}\n", `[{"op":"add","path":"/b","value":2}]`,
			"{\n  // c\n  \"a\": 1, // t\n\"b\":2\n}\n", ""},
		{"an array added", "{\n  // c\n  \"a\": 1, // t\n}\n", `[{"op":"add","path":"/b","value":[1,2]}]`,
			"{\n  // c\n  \"a\": 1, // t\n\"b\":[1,2]\n}\n", ""},
		{"a section and its tests appended", `{"a": 1}`, `[{"op":"add","path":"/tests","value":[]},{"op":"add","path":"/tests/-","value":{"src":"x"}}]`,
			`{"a": 1,"tests":[{"src":"x"}]}`, ""},
		{"remove takes the first of two equal names", `{"a":1,"a":2,"b":3}`, `[{"op":"remove","path":"/a"}]`, `{"a":2,"b":3}`, ""},
		{"remove by two spellings", `{"tests": [], "Tests": [1]}`, `[{"op":"remove","path":"/tests"},{"op":"remove","path":"/Tests"}]`, `{}`, ""},
		{"an insert into an array", `{"a": {"b": [1,2]}}`, `[{"op":"add","path":"/a/b/1","value":9}]`, `{"a": {"b": [1,9,2]}}`, ""},
		{"a patch with comments", `{"a":1}`, "// c\n[{\"op\":\"add\",\"path\":\"/b\",\"value\":/*x*/2}]", `{"a":1,"b":2}`, ""},
		{"add at the root replaces the document", `{"a":1}`, `[{"op":"add","path":"","value":[1]}]`, `[1]`, ""},
		{"copy is accepted by the library (the engine refuses it)", `{"a":1}`, `[{"op":"copy","from":"/a","path":"/b"}]`, `{"a":1,"b":1}`, ""},
		{"a test that fails", `{"a":1}`, `[{"op":"test","path":"/a","value":2}]`, "", `hujson: patch operation 0: values differ at "/a"`},
		{"an unknown operation", `{"a":1}`, `[{"op":"frob","path":"/a"}]`, "", `hujson: patch operation 0: unknown operation "frob"`},
		{"a path that is not there", `{"a":1}`, `[{"op":"remove","path":"/zzz"}]`, "", `hujson: patch operation 0: value not found`},
		{"an index past the end", `{"a": {"b": [1,2]}}`, `[{"op":"replace","path":"/a/b/5","value":9}]`, "", `hujson: patch operation 0: value not found`},
		{"a patch that is not an array", `{"a":1}`, `{"op":"add"}`, "", `hujson: patch must be a JSON array`},
		{"a missing value", `{"a":1}`, `[{"op":"add","path":"/b"}]`, "", `hujson: patch operation 0: missing required member "value"`},
	}
	for _, r := range rows {
		v, err := hujson.Parse([]byte(r.text))
		if err != nil {
			t.Fatalf("%s: %v", r.name, err)
		}
		err = v.Patch([]byte(r.patch))
		switch {
		case r.err == "" && err != nil:
			t.Errorf("%s: the library now rejects it: %v", r.name, err)
		case r.err != "" && err == nil:
			t.Errorf("%s: the library now accepts it", r.name)
		case r.err != "" && err.Error() != r.err:
			t.Errorf("%s: the error text changed:\n got  %q\n want %q", r.name, err.Error(), r.err)
		case r.err == "" && string(v.Pack()) != r.out:
			t.Errorf("%s: the result changed:\n got  %q\n want %q", r.name, v.Pack(), r.out)
		}
	}
}
