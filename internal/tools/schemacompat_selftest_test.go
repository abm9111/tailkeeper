package tools_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

func schema(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return v
}

// ruleKeys lists "io path rule" for each break compareSchemas finds.
func ruleKeys(vs []violation) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v.IO+" "+v.Path+" "+v.Rule)
	}
	sort.Strings(out)
	return out
}

// Every kind of break the compatibility rules name is planted here and must be
// found, in the direction it breaks a consumer; every additive change must pass.
// A comparison that finds nothing is not evidence the rules work.
func TestCompareSchemasFindsEachBreak(t *testing.T) {
	obj := func(props, extra string) string {
		return `{"type":"object","properties":{` + props + `}` + extra + `}`
	}
	str, num := `{"type":"string"}`, `{"type":"integer"}`
	for _, c := range []struct {
		name, io, old, new string
		want               []string
	}{
		{"a property removed (output)", "output", obj(`"a":`+str+`,"b":`+str, ""), obj(`"a":`+str, ""), []string{"output $.b removed-property"}},
		{"a property removed (input)", "input", obj(`"a":`+str+`,"b":`+str, ""), obj(`"a":`+str, ""), []string{"input $.b removed-property"}},
		{"a property renamed", "output", obj(`"a":`+str, ""), obj(`"z":`+str, ""), []string{"output $.a removed-property"}},
		{"a type changed", "output", obj(`"a":`+str, ""), obj(`"a":`+num, ""), []string{"output $.a type-changed"}},
		{"a null type dropped", "output", obj(`"a":{"type":["null","array"],"items":`+str+`}`, ""), obj(`"a":{"type":"array","items":`+str+`}`, ""), []string{"output $.a type-changed"}},
		{"an enum value removed (output)", "output", obj(`"a":{"type":"string","enum":["pass","fail"]}`, ""), obj(`"a":{"type":"string","enum":["pass"]}`, ""), []string{"output $.a=fail enum-value-removed"}},
		{"an enum value removed (input)", "input", obj(`"a":{"type":"string","enum":["x","y"]}`, ""), obj(`"a":{"type":"string","enum":["x"]}`, ""), []string{"input $.a=y enum-value-removed"}},
		{"an enum put on an input", "input", obj(`"a":`+str, ""), obj(`"a":{"type":"string","enum":["x"]}`, ""), []string{"input $.a input-enum-added"}},
		{"a new required input", "input", obj(`"a":`+str, `,"required":["a"]`), obj(`"a":`+str+`,"b":`+str, `,"required":["a","b"]`), []string{"input $.b new-required-input"}},
		{"an input becomes required", "input", obj(`"a":`+str, ""), obj(`"a":`+str, `,"required":["a"]`), []string{"input $.a new-required-input"}},
		{"an output stops being required", "output", obj(`"a":`+str, `,"required":["a"]`), obj(`"a":`+str, ""), []string{"output $.a required-output-lost"}},
		{"an untrusted marker lost", "output", obj(`"a":{"type":"string","x-tailkeeper-untrusted":true}`, ""), obj(`"a":`+str, ""), []string{"output $.a marker-lost"}},
		{"items removed", "output", obj(`"a":{"type":"array","items":`+str+`}`, ""), obj(`"a":{"type":"array"}`, ""), []string{"output $.a[] removed-items"}},
		{"a break inside items", "output", obj(`"rows":{"type":"array","items":`+obj(`"id":`+str, "")+`}`, ""), obj(`"rows":{"type":"array","items":`+obj(`"id":`+num, "")+`}`, ""), []string{"output $.rows[].id type-changed"}},
		{"a keyword the rules cannot compare", "output", obj(`"a":{"oneOf":[`+str+`]}`, ""), obj(`"a":{"oneOf":[`+num+`]}`, ""), []string{"output $.a unsupported-keyword"}},
		{"a schema became a boolean", "output", obj(`"a":`+str, ""), obj(`"a":true`, ""), []string{"output $.a type-changed"}},
		// Two breaks at one place are two violations, each named by what broke.
		{"two required outputs lost", "output", obj(`"a":`+str+`,"b":`+str, `,"required":["a","b"]`), obj(`"a":`+str+`,"b":`+str, ""), []string{"output $.a required-output-lost", "output $.b required-output-lost"}},
		{"two inputs become required", "input", obj(`"a":`+str+`,"b":`+str+`,"c":`+str, `,"required":["a"]`), obj(`"a":`+str+`,"b":`+str+`,"c":`+str, `,"required":["a","b","c"]`), []string{"input $.b new-required-input", "input $.c new-required-input"}},
		{"two enum values removed", "output", obj(`"k":{"type":"string","enum":["a","b","c"]}`, ""), obj(`"k":{"type":"string","enum":["a"]}`, ""), []string{"output $.k=b enum-value-removed", "output $.k=c enum-value-removed"}},
		{"an enum value with a space and a number removed", "output", obj(`"k":{"enum":["x y",3,"z"]}`, ""), obj(`"k":{"enum":["z"]}`, ""), []string{"output $.k=3 enum-value-removed", "output $.k=x%20y enum-value-removed"}},
		{"a retyped property and a removed one", "output", obj(`"a":`+str+`,"b":`+str, ""), obj(`"a":`+num, ""), []string{"output $.a type-changed", "output $.b removed-property"}},
		// The values of a map (additionalProperties holding a schema) are compared.
		{"a map value retyped", "output", obj(`"m":{"type":"object","additionalProperties":`+num+`}`, ""), obj(`"m":{"type":"object","additionalProperties":`+str+`}`, ""), []string{"output $.m{} type-changed"}},
		{"a break inside a map value", "output", obj(`"m":{"type":"object","additionalProperties":`+obj(`"x":`+str, "")+`}`, ""), obj(`"m":{"type":"object","additionalProperties":`+obj(`"y":`+str, "")+`}`, ""), []string{"output $.m{}.x removed-property"}},
		{"map values no longer described", "output", obj(`"m":{"type":"object","additionalProperties":`+num+`}`, ""), obj(`"m":{"type":"object"}`, ""), []string{"output $.m{} removed-map-values"}},
		{"map values became a boolean", "output", obj(`"m":{"type":"object","additionalProperties":`+num+`}`, ""), obj(`"m":{"type":"object","additionalProperties":true}`, ""), []string{"output $.m{} removed-map-values"}},
		{"map values described where none were", "output", obj(`"m":{"type":"object","additionalProperties":false}`, ""), obj(`"m":{"type":"object","additionalProperties":`+num+`}`, ""), nil},
		{"a map value gains a property", "output", obj(`"m":{"type":"object","additionalProperties":`+obj(`"x":`+str, "")+`}`, ""), obj(`"m":{"type":"object","additionalProperties":`+obj(`"x":`+str+`,"y":`+str, "")+`}`, ""), nil},
		// Additive changes pass.
		{"an optional output added", "output", obj(`"a":`+str, ""), obj(`"a":`+str+`,"b":`+str, ""), nil},
		{"a required output added", "output", obj(`"a":`+str, ""), obj(`"a":`+str+`,"b":`+str, `,"required":["b"]`), nil},
		{"an optional input added", "input", obj(`"a":`+str, ""), obj(`"a":`+str+`,"b":`+str, ""), nil},
		{"an enum value added (output)", "output", obj(`"a":{"type":"string","enum":["x"]}`, ""), obj(`"a":{"type":"string","enum":["x","y"]}`, ""), nil},
		{"an enum value added (input)", "input", obj(`"a":{"type":"string","enum":["x"]}`, ""), obj(`"a":{"type":"string","enum":["x","y"]}`, ""), nil},
		{"a description changed and a marker added", "output", obj(`"a":{"type":"string","description":"old"}`, ""), obj(`"a":{"type":"string","description":"new","x-tailkeeper-untrusted":true}`, ""), nil},
		{"required output widened", "output", obj(`"a":`+str, ""), obj(`"a":`+str, `,"required":["a"]`), nil},
		{"input required dropped", "input", obj(`"a":`+str, `,"required":["a"]`), obj(`"a":`+str, ""), nil},
	} {
		got := ruleKeys(compareSchemas("t", c.io, schema(t, c.old), schema(t, c.new)))
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: found %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCheckWaiversNeedsADateAReasonAndTheChangelog(t *testing.T) {
	changelog := "# Changelog\n\n## 0.6.0 — unreleased\n\n### Upgrading\n\n- `acl_test` `$.status` no longer says fail.\n\n## 0.5.0 — 2026-10-16\n\n`dns_get` `$.x` is only here.\n"
	good := "2026-10-20 acl_test output $.status=fail enum-value-removed the fail status moved to verdicts"
	if got, ws := checkWaivers([]string{"# a comment", "", good}, changelog); len(got) != 0 || len(ws) != 1 || ws[0].key() != "acl_test output $.status=fail enum-value-removed" {
		t.Errorf("a good waiver: problems %v, waivers %+v", got, ws)
	}
	// A removed tool is spelled "<tool> input $ removed-tool" and needs only the tool's name in the CHANGELOG.
	if got, ws := checkWaivers([]string{"2026-10-20 acl_test input $ removed-tool the tool moved"}, changelog); len(got) != 0 || len(ws) != 1 {
		t.Errorf("a removed-tool waiver: problems %v, waivers %+v", got, ws)
	}
	if got, _ := checkWaivers([]string{"2026-10-20 ghost_tool input $ removed-tool the tool moved"}, changelog); len(got) != 1 {
		t.Errorf("a removed-tool waiver for a tool the CHANGELOG does not name: problems = %v, want exactly one", got)
	}
	for name, line := range map[string]string{
		"no reason":              "2026-10-20 acl_test output $.status enum-value-removed",
		"bad date":               "20-10-2026 acl_test output $.status enum-value-removed why",
		"impossible date":        "2026-13-45 acl_test output $.status enum-value-removed why",
		"bad io":                 "2026-10-20 acl_test both $.status enum-value-removed why",
		"unknown rule":           "2026-10-20 acl_test output $.status renamed-ish why",
		"not in the changelog":   "2026-10-20 acl_test output $.other=x enum-value-removed why",
		"only in an old release": "2026-10-20 dns_get output $.x type-changed why",
		"too few fields":         "2026-10-20 acl_test",
	} {
		if got, _ := checkWaivers([]string{line}, changelog); len(got) != 1 {
			t.Errorf("%s: problems = %v, want exactly one", name, got)
		}
	}
}

// A waiver is for one break found now: one that excuses nothing is a problem, and
// a waiver for one break does not excuse its neighbour at the same place.
func TestStaleWaiversAreFound(t *testing.T) {
	break1 := violation{Tool: "t", IO: "output", Path: "$.k=b", Rule: "enum-value-removed"}
	break2 := violation{Tool: "t", IO: "output", Path: "$.k=c", Rule: "enum-value-removed"}
	w1 := waiver{Tool: "t", IO: "output", Path: "$.k=b", Rule: "enum-value-removed"}
	gone := waiver{Tool: "t", IO: "output", Path: "$.a", Rule: "removed-property"}
	if got := staleWaivers([]waiver{w1}, []violation{break1, break2}); len(got) != 0 {
		t.Errorf("a waiver for a break that exists: %v", got)
	}
	got := staleWaivers([]waiver{w1, gone}, []violation{break2})
	if len(got) != 2 || !strings.Contains(got[0], "t output $.k=b enum-value-removed") || !strings.Contains(got[1], "t output $.a removed-property") {
		t.Errorf("stale waivers = %v, want both named", got)
	}
	if got := staleWaivers(nil, []violation{break1}); len(got) != 0 {
		t.Errorf("no waivers, got %v", got)
	}
}
