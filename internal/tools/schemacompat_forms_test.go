package tools_test

import (
	"strings"
	"testing"
)

// A schema that changed form is a break even when no type differs, and two
// unreadable keywords changed at one place are one violation, so that one waiver
// excuses the place and the report never lists a key twice.
func TestCompareSchemasFormChangesAndRepeatedKeys(t *testing.T) {
	for _, c := range []struct {
		name, io, old, new string
		want               []string
	}{
		{"an untyped schema became a boolean", "output", `{"properties":{"a":{}}}`, `{"properties":{"a":true}}`, []string{"output $.a type-changed"}},
		{"a boolean became an untyped schema", "output", `{"properties":{"a":true}}`, `{"properties":{"a":{}}}`, []string{"output $.a type-changed"}},
		{"a boolean stayed a boolean", "output", `{"properties":{"a":true}}`, `{"properties":{"a":true}}`, nil},
		{"a removed property does not hide a later change", "output", `{"properties":{"a":{"type":"string"},"b":{"type":"string"}}}`, `{"properties":{"b":{"type":"integer"}}}`, []string{"output $.a removed-property", "output $.b type-changed"}},
		{"the types of a union reordered", "output", `{"properties":{"a":{"type":["null","string"]}}}`, `{"properties":{"a":{"type":["string","null"]}}}`, nil},
		{"the types of a union changed", "output", `{"properties":{"a":{"type":["null","string"]}}}`, `{"properties":{"a":{"type":["integer","null"]}}}`, []string{"output $.a type-changed"}},
		{"two unreadable keywords changed", "output", `{"properties":{"a":{"oneOf":[{}],"anyOf":[{}]}}}`, `{"properties":{"a":{"oneOf":[{"type":"string"}],"anyOf":[{"type":"string"}]}}}`, []string{"output $.a unsupported-keyword"}},
	} {
		got := ruleKeys(compareSchemas("t", c.io, schema(t, c.old), schema(t, c.new)))
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: found %v, want %v", c.name, got, c.want)
		}
	}
}
