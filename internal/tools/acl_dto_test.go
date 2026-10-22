package tools_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/mcpserver"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// aclResultTypes are the result types of the policy tools. A tool that adds one lists it
// here, so that the class test below holds its strings to the rule.
var aclResultTypes = []reflect.Type{reflect.TypeFor[tools.ACLGetOutput](), reflect.TypeFor[tools.ACLValidateOutput](), reflect.TypeFor[tools.ACLDiffOutput]()}

// aclConstantStrings are the string fields of the policy tools' results that hold
// tailkeeper's own words, a digest, a time or a version token, never text from a policy or
// from Tailscale. Everything else must be tagged untrusted, and tagged emails where it can
// hold an address. The key is "Type.Field", the value says why the field is constant.
var aclConstantStrings = map[string]string{
	"ACLGetOutput.SHA256":                     "a digest",
	"ACLGetOutput.ETag":                       "the version token Tailscale sends, shown only with personalData show",
	"ACLGetOutput.PolicyVersion":              "a keyed digest, or the ETag with personalData show",
	"ACLGetOutput.PolicySHA256":               "a digest",
	"ACLGetOutput.CheckedAt":                  "a time",
	"ACLGetOutput.ExternallyManaged":          "true, false or unknown",
	"ACLGetOutput.ExternallyManagedNote":      "tailkeeper's words and an error code",
	"ACLSummary.NamesDigest":                  "a keyed digest",
	"ACLSummary.SemanticDigest":               "a keyed digest",
	"ACLSectionRow.State":                     "absent, empty or non-empty",
	"ACLValidateOutput.Status":                "one of six words",
	"ACLValidateOutput.InvariantsSignature":   "the constant none",
	"ACLValidateOutput.NotChecked":            "names of what is not established, from a fixed list",
	"ACLValidateOutput.PolicyVersion":         "a keyed digest, or the ETag with personalData show",
	"ACLValidateOutput.PolicySHA256":          "a digest",
	"ACLValidateOutput.CheckedAt":             "a time",
	"ACLValidateOutput.ExternallyManaged":     "true, false or unknown",
	"ACLValidateOutput.ExternallyManagedNote": "tailkeeper's words and an error code",
	"ACLValidateOutput.PatchedDigest":         "a keyed digest",
	"ACLDiffOutput.Status":                    "equal, changed or invalid",
	"ACLDiffOutput.Section":                   "a section name in the engine's spelling, or unknown",
	"ACLDiffOutput.NextChange":                "a cursor the engine issues",
	"ACLDiffOutput.NormalFormLimits":          "the engine's fixed sentences",
	"ACLDiffOutput.NotChecked":                "names of what is not established, from a fixed list",
	"ACLDiffOutput.TailscaleWrittenAsOf":      "a date",
	"ACLDiffOutput.ExternallyManaged":         "true, false or unknown",
	"ACLDiffOutput.ExternallyManagedNote":     "tailkeeper's words and an error code",
	"ACLDiffOutput.CheckedAt":                 "a time",
	"ACLDiffSide.Source":                      "live, text, file or patch",
	"ACLDiffSide.PolicyVersion":               "a keyed digest, or the ETag with personalData show",
	"ACLDiffSide.PolicySHA256":                "a digest",
	"ACLChange.Class":                         "one of the five classes of a change",
	"ACLChange.Op":                            "added, removed or changed",
	"ACLChange.Note":                          "one of the engine's fixed sentences (acl.ChangeNotes)",
	"ACLProblem.Kind":                         "one of a fixed list of kinds",
	"ACLProblem.Severity":                     "error, warning or notice",
	"ACLProblem.Source":                       "from, against, patch, invariants or live",
}

// aclClosedLists are, for the constant fields that hold words and not a digest, a time or a
// version token, every value the field can take. A field is constant because tailkeeper wrote
// its text; a policy string that reaches one is a leak the registry does not see, because the
// field is not masked, escaped or capped. The list of a field is not a promise the author
// makes: TestTheFixedSentencesOfAResultComeFromTheirClosedLists holds real results to it.
var aclClosedLists = map[string][]string{
	"ACLChange.Class":                       {"defaults", "testsReduced", "widening", "tailscaleWritten", "semantic"},
	"ACLChange.Op":                          {"added", "removed", "changed"},
	"ACLChange.Note":                        acl.ChangeNotes(),
	"ACLDiffOutput.Status":                  {"equal", "changed", "invalid"},
	"ACLDiffOutput.NotChecked":              acl.NotChecked,
	"ACLDiffOutput.NormalFormLimits":        {"A rule re-split along both its sources and its ports at once is not reduced to the same atoms, so it can read as changed when the access is the same. That is the safe direction."},
	"ACLDiffOutput.Section":                 append(sectionNames(), "unknown"),
	"ACLDiffSide.Source":                    {"live", "text", "file", "patch"},
	"ACLProblem.Kind":                       {"syntax", "encoding", "structure", "duplicate_key", "case_collision", "unknown_section", "assertion_failed", "test_unevaluable", "invariant", "server_message", "warning", "note"},
	"ACLProblem.Severity":                   {"error", "warning", "notice"},
	"ACLProblem.Source":                     {"from", "against", "invariants", "live", "patch"},
	"ACLValidateOutput.Status":              {"pass", "fail", "invalid", "rejected", "unresolved", "unknown"},
	"ACLValidateOutput.NotChecked":          append(append([]string{}, acl.NotChecked...), "server_validation", "tests", "invariants", "invariants_file", "invariants_signature"),
	"ACLValidateOutput.InvariantsSignature": {"none"},
}

func sectionNames() []string {
	var names []string
	for _, s := range acl.Sections() {
		names = append(names, s.Name)
	}
	return names
}

// closedViolations walks a result and returns, as "Type.Field = value", every string a field
// with a closed list holds that the list does not.
func closedViolations(v reflect.Value, lists map[string][]string) []string {
	var out []string
	var walk func(v reflect.Value, field string)
	walk = func(v reflect.Value, field string) {
		switch v.Kind() {
		case reflect.Pointer:
			if !v.IsNil() {
				walk(v.Elem(), field)
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i), field)
			}
		case reflect.String:
			// An empty string is a field left out of the result (omitempty), not a word.
			if list, ok := lists[field]; ok && v.String() != "" && !slices.Contains(list, v.String()) {
				out = append(out, fmt.Sprintf("%s = %q", field, v.String()))
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if f := v.Type().Field(i); f.IsExported() {
					walk(v.Field(i), v.Type().Name()+"."+f.Name)
				}
			}
		}
	}
	walk(v, "")
	return out
}

// untaggedStrings walks a result type and returns, as "Type.Field", every string field (a
// string, a list of strings or a map to strings, at any depth) that is neither tagged
// untrusted nor a listed constant. A tagged struct or list is not walked: everything in it
// is already treated as untrusted. It also returns the constants that name no field.
func untaggedStrings(types []reflect.Type, constants map[string]string) (untagged, stale []string) {
	used := map[string]bool{}
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || seen[t] {
			return
		}
		seen[t] = true
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			key := t.Name() + "." + f.Name
			ft := f.Type
			for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array || ft.Kind() == reflect.Map {
				ft = ft.Elem()
			}
			switch {
			case sanitize.HasTag(f.Tag, "untrusted"):
			case ft.Kind() == reflect.String:
				if _, ok := constants[key]; ok {
					used[key] = true
				} else {
					untagged = append(untagged, key)
				}
			case ft.Kind() == reflect.Struct:
				walk(ft)
			}
		}
	}
	for _, t := range types {
		walk(t)
	}
	for key := range constants {
		if !used[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(untagged)
	sort.Strings(stale)
	return untagged, stale
}

func TestEveryStringOfAnACLResultIsTaggedOrAConstant(t *testing.T) {
	untagged, stale := untaggedStrings(aclResultTypes, aclConstantStrings)
	if len(untagged) > 0 {
		t.Errorf("these strings are neither tagged untrusted nor listed as constants: %v", untagged)
	}
	if len(stale) > 0 {
		t.Errorf("these constants name no field of the result types: %v", stale)
	}
	// The untrusted strings that can hold an address are masked as such.
	for _, p := range []string{"Pointer", "Message"} {
		f, _ := reflect.TypeFor[tools.ACLProblem]().FieldByName(p)
		if !sanitize.HasTag(f.Tag, "emails") {
			t.Errorf("ACLProblem.%s is untrusted but not tagged emails", p)
		}
	}
	for _, p := range []string{"Section", "Entry", "Old", "New", "OldPointer", "NewPointer"} {
		f, _ := reflect.TypeFor[tools.ACLChange]().FieldByName(p)
		if !sanitize.HasTag(f.Tag, "untrusted") || !sanitize.HasTag(f.Tag, "emails") {
			t.Errorf("ACLChange.%s holds text of a policy but is not tagged untrusted and emails", p)
		}
	}
	for _, p := range []string{"Field", "Added", "Removed"} {
		f, _ := reflect.TypeFor[tools.ACLFieldDelta]().FieldByName(p)
		if !sanitize.HasTag(f.Tag, "untrusted") || !sanitize.HasTag(f.Tag, "emails") {
			t.Errorf("ACLFieldDelta.%s holds text of a policy but is not tagged untrusted and emails", p)
		}
	}
}

// The test can fail: a planted string field with no tag is found, as is a constant that
// names nothing, and a tagged one is not.
func TestTheClassTestFindsAPlantedUntaggedString(t *testing.T) {
	type nested struct {
		Words []string
		Note  string `tk:"untrusted,emails"`
	}
	type planted struct {
		Name   string
		Tagged string `tk:"untrusted"`
		List   []nested
	}
	untagged, stale := untaggedStrings([]reflect.Type{reflect.TypeFor[planted]()}, map[string]string{"planted.Gone": "was a field"})
	if got := fmt.Sprint(untagged); got != "[nested.Words planted.Name]" {
		t.Errorf("untagged = %s, want [nested.Words planted.Name]", got)
	}
	if strings.Join(stale, ",") != "planted.Gone" {
		t.Errorf("stale = %v", stale)
	}
}

// The words an agent reads in the schema carry two rules of a position: lines are counted by
// line feed, and a problem about a text as a whole has an empty source.
func TestTheSchemaOfAProblemSaysHowLinesAreCountedAndWhenSourceIsEmpty(t *testing.T) {
	tool, ok := newRegistry(t).Get("acl_validate")
	if !ok {
		t.Fatal("acl_validate is not registered")
	}
	schema, err := mcpserver.OutputSchema(tool)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"counting line feeds", "empty for a message about the text as a whole"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the output schema of acl_validate does not say %q", want)
		}
	}
}

// Every constant field that holds words has a closed list, and the list is the field's
// values: the fields that hold a digest, a time or a version token are the only constants
// without one.
func TestEveryFixedSentenceOfAResultHasAClosedList(t *testing.T) {
	computed := map[string]bool{
		"ACLGetOutput.SHA256": true, "ACLGetOutput.ETag": true, "ACLGetOutput.PolicyVersion": true, "ACLGetOutput.PolicySHA256": true,
		"ACLGetOutput.CheckedAt": true, "ACLSummary.NamesDigest": true, "ACLSummary.SemanticDigest": true,
		"ACLValidateOutput.PolicyVersion": true, "ACLValidateOutput.PolicySHA256": true, "ACLValidateOutput.CheckedAt": true,
		"ACLValidateOutput.PatchedDigest": true, "ACLDiffOutput.NextChange": true, "ACLDiffOutput.TailscaleWrittenAsOf": true,
		"ACLDiffOutput.CheckedAt": true, "ACLDiffSide.PolicyVersion": true, "ACLDiffSide.PolicySHA256": true,
		// An error code and tailkeeper's words around it: the code is from tkerr's list.
		"ACLGetOutput.ExternallyManagedNote": true, "ACLValidateOutput.ExternallyManagedNote": true, "ACLDiffOutput.ExternallyManagedNote": true,
		// true, false or unknown, and an enumeration of three states.
		"ACLGetOutput.ExternallyManaged": true, "ACLValidateOutput.ExternallyManaged": true, "ACLDiffOutput.ExternallyManaged": true,
		"ACLSectionRow.State": true,
	}
	for key, why := range aclConstantStrings {
		if _, ok := aclClosedLists[key]; ok || computed[key] {
			continue
		}
		t.Errorf("%s is a constant (%s) with no closed list of its values and is not a computed one", key, why)
	}
	for key := range aclClosedLists {
		if _, ok := aclConstantStrings[key]; !ok {
			t.Errorf("%s has a closed list but is not a constant field", key)
		}
	}
}

// The test can fail: a value outside a list is found, in a nested struct and a slice, and a
// value in it is not.
func TestTheClosedListsCatchAValueOutsideThem(t *testing.T) {
	type change struct{ Note string }
	type result struct{ Changes []change }
	lists := map[string][]string{"change.Note": {"a fixed sentence"}}
	got := closedViolations(reflect.ValueOf(result{Changes: []change{{"a fixed sentence"}, {"a rule with * in src is new for amy@example.com"}}}), lists)
	if len(got) != 1 || !strings.Contains(got[0], "amy@example.com") {
		t.Errorf("violations = %v, want the one note that quotes a login", got)
	}
}

// Real results hold the lists: a comparison of policies that put a login in every position
// leaves every fixed-sentence field a word of its list, in the notes of the changes above all.
func TestTheFixedSentencesOfAResultComeFromTheirClosedLists(t *testing.T) {
	const amy = "amy@example.com"
	rule := func(src, dst string) string {
		return `{"action": "accept", "src": [` + src + `], "dst": [` + dst + `]}`
	}
	pairs := [][2]string{
		{`{"acls": [` + rule(`"tag:ci"`, `"`+amy+`:22"`) + `]}`, `{"acls": [` + rule(`"*"`, `"`+amy+`:22"`) + `]}`},
		{`{"acls": [` + rule(`"`+amy+`"`, `"tag:x:22"`) + `]}`, `{"acls": [` + rule(`"`+amy+`"`, `"tag:x:22", "autogroup:internet:*"`) + `]}`},
		{`{"groups": {"group:a": ["` + amy + `"]}}`, `{"groups": "` + amy + `"}`},
		{`{}`, `{"acls": []}`},
		{`{"acls": [` + rule(`"`+amy+`"`, `"`+amy+`:1"`) + `]}`, `{}`},
		{`{"ssh": [{"action": "accept", "src": ["` + amy + `"], "dst": ["tag:t"], "users": ["u"]}]}`, `{}`},
		{`{"tests": [{"src": "` + amy + `", "accept": ["tag:x:1"]}], "nodeAttrs": [{"target": ["` + amy + `"], "attr": ["a"]}], "` + amy + `": 1}`, `{}`},
	}
	for i, p := range pairs {
		for _, order := range [][2]string{{p[0], p[1]}, {p[1], p[0]}} {
			out := twoFiles(t, order[0], order[1])
			if bad := closedViolations(reflect.ValueOf(out), aclClosedLists); len(bad) > 0 {
				t.Errorf("pair %d: %v", i, bad)
			}
		}
	}
	for i, text := range []string{`{"groups": {"group:a": ["` + amy + `"], "group:a": []}, "` + amy + `": 1}`, `not a policy ` + amy, `{"acls": [` + rule(`"`+amy+`"`, `"`+amy+`:1"`) + `]}`} {
		out := offlineValidate(t, text)
		if bad := closedViolations(reflect.ValueOf(out), aclClosedLists); len(bad) > 0 {
			t.Errorf("validate %d: %v", i, bad)
		}
	}
}
