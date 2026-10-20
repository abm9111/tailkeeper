package tools_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"
)

// A tool's input and output schemas are a contract with every script and agent
// that was written against a release. The rules of the compatibility test,
// from a consumer's side:
//
//   - Allowed: a new optional input property; a new output property, optional or
//     required; a new enum value; changed descriptions; a new x-tailkeeper marker.
//   - Breaks: a property removed or renamed; a type changed; an enum value
//     removed, or an enum put on an input; a property that is newly required in an
//     input, or no longer always present in an output; an x-tailkeeper marker
//     lost; a map's value schema removed; a schema keyword the comparison cannot
//     read.
//
// One break is one violation, and a waiver excuses exactly one: the path of a
// violation names the property or the value it is about (see violation).
//
// A break passes only with a dated waiver line in testdata/schemas/waivers.txt
// that the top section of CHANGELOG.md mentions.

// violation is one break of the rules. Path says where, down to the thing that
// broke, so that two breaks never share a key:
//
//	$.a.b       a property (removed, retyped, newly required in an input, no longer
//	            always present in an output, marker lost)
//	$.a[]       the items of an array; $.a{} the value schema of a map
//	$.a=value   an enum value removed from $.a (a string without its quotes, any
//	            other value as JSON text; white space written %20)
//	$           the schema itself: a tool that was removed is "input $ removed-tool"
type violation struct {
	Tool, IO, Path, Rule, Detail string
}

func (v violation) key() string { return v.Tool + " " + v.IO + " " + v.Path + " " + v.Rule }

// rules are the names of the breaks a waiver may excuse.
var rules = []string{"removed-property", "type-changed", "enum-value-removed", "input-enum-added", "new-required-input",
	"required-output-lost", "marker-lost", "removed-items", "removed-map-values", "unsupported-keyword", "removed-tool"}

// unreadable are keywords whose effect the comparison does not model: a change in
// one is a break to be waived on purpose, not a change that slips by.
var unreadable = []string{"oneOf", "anyOf", "allOf", "not", "if", "then", "else", "$ref", "$defs", "patternProperties",
	"prefixItems", "dependentSchemas"}

type comparer struct {
	tool, io string
	out      []violation
	seen     map[string]bool
}

// compareSchemas returns the breaks in moving from old to new, both decoded
// JSON, for the input or the output ("input" or "output") of tool.
func compareSchemas(tool, io string, old, new any) []violation {
	c := &comparer{tool: tool, io: io, seen: map[string]bool{}}
	c.node("$", old, new)
	return c.out
}

func (c *comparer) add(path, rule, detail string) {
	v := violation{Tool: c.tool, IO: c.io, Path: path, Rule: rule, Detail: detail}
	if !c.seen[v.key()] {
		c.seen[v.key()] = true
		c.out = append(c.out, v)
	}
}

func (c *comparer) node(path string, old, new any) {
	om, oldMap := old.(map[string]any)
	nm, newMap := new.(map[string]any)
	if !oldMap || !newMap {
		if !reflect.DeepEqual(old, new) {
			c.add(path, "type-changed", "the schema changed form")
		}
		return
	}
	if ot, nt := typeSet(om), typeSet(nm); !slices.Equal(ot, nt) {
		c.add(path, "type-changed", fmt.Sprintf("type %v became %v", ot, nt))
	}
	for _, k := range unreadable {
		if !reflect.DeepEqual(om[k], nm[k]) {
			c.add(path, "unsupported-keyword", k+" changed")
		}
	}
	for k, v := range om {
		if strings.HasPrefix(k, "x-tailkeeper-") && v == true && nm[k] != true {
			c.add(path, "marker-lost", k+" was dropped")
		}
	}
	oe, ne := enumSet(om), enumSet(nm)
	switch {
	case oe != nil && ne != nil:
		for _, v := range oe {
			if !slices.Contains(ne, v) {
				c.add(path+"="+enumPath(v), "enum-value-removed", "enum value "+v+" was removed")
			}
		}
	case oe == nil && ne != nil && c.io == "input":
		c.add(path, "input-enum-added", "the input now accepts only an enum")
	}
	op, np := properties(om), properties(nm)
	names := make([]string, 0, len(op))
	for name := range op {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		child, ok := np[name]
		if !ok {
			c.add(path+"."+name, "removed-property", "the property was removed or renamed")
			continue
		}
		c.node(path+"."+name, op[name], child)
	}
	or, nr := required(om), required(nm)
	if c.io == "input" {
		for _, r := range nr {
			if !slices.Contains(or, r) {
				c.add(path+"."+r, "new-required-input", r+" is now required")
			}
		}
	} else {
		for _, r := range or {
			if !slices.Contains(nr, r) {
				c.add(path+"."+r, "required-output-lost", r+" is no longer always present")
			}
		}
	}
	if oa, ok := om["additionalProperties"].(map[string]any); ok { // the value schema of a map
		if na, ok := nm["additionalProperties"].(map[string]any); ok {
			c.node(path+"{}", oa, na)
		} else {
			c.add(path+"{}", "removed-map-values", "the value schema of the map was removed")
		}
	}
	if oi, ok := om["items"]; ok {
		ni, ok := nm["items"]
		if !ok {
			c.add(path+"[]", "removed-items", "the item schema was removed")
		} else {
			c.node(path+"[]", oi, ni)
		}
	}
}

// typeSet is a schema's type or types, sorted.
func typeSet(m map[string]any) []string {
	var out []string
	switch t := m["type"].(type) {
	case string:
		out = []string{t}
	case []any:
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
	}
	sort.Strings(out)
	return out
}

// enumPath spells an enum value (JSON text) for a violation path: a string
// without its quotes, white space as %20, so a waiver line stays one field.
func enumPath(v string) string {
	var s string
	if json.Unmarshal([]byte(v), &s) != nil {
		s = v
	}
	return strings.NewReplacer(" ", "%20", "\t", "%09", "\n", "%0A").Replace(s)
}

// enumSet is a schema's enum values as JSON text, or nil when it has none.
func enumSet(m map[string]any) []string {
	list, ok := m["enum"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, len(list))
	for i, v := range list {
		b, _ := json.Marshal(v)
		out[i] = string(b)
	}
	return out
}

func properties(m map[string]any) map[string]any {
	p, _ := m["properties"].(map[string]any)
	return p
}

func required(m map[string]any) []string {
	list, _ := m["required"].([]any)
	out := make([]string, len(list))
	for i, v := range list {
		out[i] = fmt.Sprint(v)
	}
	return out
}

// waiver excuses one break: the date it was decided and why.
type waiver struct {
	Date, Tool, IO, Path, Rule, Reason string
}

func (w waiver) key() string { return w.Tool + " " + w.IO + " " + w.Path + " " + w.Rule }

// mention is the path the CHANGELOG must name: the property, without the =value
// of an enum value. A break of the tool as a whole ($) is covered by the tool's name.
func (w waiver) mention() string {
	p, _, _ := strings.Cut(w.Path, "=")
	return p
}

// staleWaivers lists the waivers that excuse no break found now. A change that is
// in the baseline needs no waiver, and a waiver left behind would excuse the next
// break at the same place.
func staleWaivers(waivers []waiver, breaks []violation) []string {
	found := map[string]bool{}
	for _, v := range breaks {
		found[v.key()] = true
	}
	var out []string
	for _, w := range waivers {
		if !found[w.key()] {
			out = append(out, "a waiver excuses no break found now (the release PR clears the waivers whose change is in the baseline): "+w.key())
		}
	}
	return out
}

// checkWaivers parses the lines of waivers.txt: "# comments" and blank lines are
// skipped; a waiver is
//
//	YYYY-MM-DD <tool> <input|output> <path> <rule> <reason...>
//
// and must name a rule from rules and appear, as `tool` and `path`, in the top
// section of changelog (the Upgrading paragraph of the release being prepared).
func checkWaivers(lines []string, changelog string) (problems []string, waivers []waiver) {
	top := changelog
	if i := strings.Index(top, "\n## "); i >= 0 {
		top = top[i+1:]
		if j := strings.Index(top[3:], "\n## "); j >= 0 {
			top = top[:j+3]
		}
	}
	for n, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		at := fmt.Sprintf("waivers.txt line %d", n+1)
		f := strings.Fields(line)
		if len(f) < 6 {
			problems = append(problems, at+": want <date> <tool> <input|output> <path> <rule> <reason>")
			continue
		}
		w := waiver{Date: f[0], Tool: f[1], IO: f[2], Path: f[3], Rule: f[4], Reason: strings.Join(f[5:], " ")}
		switch {
		case !validDate(w.Date):
			problems = append(problems, at+": "+w.Date+" is not a YYYY-MM-DD date")
		case w.IO != "input" && w.IO != "output":
			problems = append(problems, at+": "+w.IO+" is not input or output")
		case !slices.Contains(rules, w.Rule):
			problems = append(problems, at+": "+w.Rule+" is not a rule ("+strings.Join(rules, ", ")+")")
		case !strings.Contains(top, "`"+w.Tool+"`") || w.mention() != "$" && !strings.Contains(top, "`"+w.mention()+"`"):
			problems = append(problems, at+": the top section of CHANGELOG.md must mention `"+w.Tool+"` and `"+w.mention()+"`")
		default:
			waivers = append(waivers, w)
		}
	}
	return problems, waivers
}

func validDate(s string) bool {
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}
