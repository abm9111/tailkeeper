package tools_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// A diff class is spelled five ways: the engine's name, the key of its count in the result,
// the field of registry.Findings that --fail-on reads, the --fail-on token, and the label
// of the human layout. Nothing but this table ties the five together, so a class added to
// the engine without a row fails here, and so does a row that no class has.
//
// finding is the field of registry.Findings the class fills ("" for a class that only
// feeds change); token is the --fail-on token that fires for it; label is its row in the
// layout ("" for a class that is only counted).
var diffSpellings = map[string]struct{ finding, token, label string }{
	"defaults":         {"Defaults", "defaults", "defaults"},
	"testsReduced":     {"TestsReduced", "tests-reduced", "tests reduced"},
	"widening":         {"Widenings", "widening", "widening"},
	"tailscaleWritten": {"", "change", "tailscale-written"},
	"semantic":         {"", "change", "semantic"},
	"commentOnly":      {"", "", ""},
	"formatOnly":       {"", "", ""},
}

// engineClasses reads the Class constants out of the engine's source, so that the table
// cannot fall behind the engine: the values of every constant declared with the type Class.
func engineClasses(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "../acl/diff.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var classes []string
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Class" {
				continue
			}
			for _, v := range vs.Values {
				lit, ok := v.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("a Class constant that is not a string literal: %v", fset.Position(v.Pos()))
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				classes = append(classes, s)
			}
		}
	}
	return classes
}

// countsKey sets the count of the class named by its JSON key on c, or reports that there is
// no such key.
func countsKey(c *tools.ACLChangeCounts, class string) bool {
	v := reflect.ValueOf(c).Elem()
	for i := 0; i < v.NumField(); i++ {
		if strings.Split(v.Type().Field(i).Tag.Get("json"), ",")[0] == class {
			v.Field(i).SetInt(1)
			return true
		}
	}
	return false
}

func TestTheDiffClassesHaveOneSpellingEach(t *testing.T) {
	classes := engineClasses(t)
	if len(classes) != len(diffSpellings) {
		t.Fatalf("found %d Class constants in internal/acl/diff.go (%v), the table has %d rows", len(classes), classes, len(diffSpellings))
	}
	for _, class := range classes {
		row, ok := diffSpellings[class]
		if !ok {
			t.Errorf("class %q has no row in the table of spellings", class)
			continue
		}
		var counts tools.ACLChangeCounts
		if !countsKey(&counts, class) {
			t.Errorf("class %q is no JSON key of ACLChangeCounts", class)
			continue
		}
		// What --fail-on reads: the field the class fills, and change for the five changes.
		out := tools.ACLDiffOutput{Status: "changed", Counts: counts}
		f := out.Findings()
		fv := reflect.ValueOf(f)
		for i := 0; i < fv.NumField(); i++ {
			name := fv.Type().Field(i).Name
			want := 0
			switch {
			case name == row.finding:
				want = 1
			case name == "Changes" && row.token != "":
				want = 1
			}
			if got := int(fv.Field(i).Int()); got != want {
				t.Errorf("class %q: Findings().%s = %d, want %d", class, name, got, want)
			}
		}
		if row.token != "" && !slices.Contains(out.FailOnKinds(), row.token) {
			t.Errorf("class %q fires --fail-on %s, which acl_diff does not list among %v", class, row.token, out.FailOnKinds())
		}
		// A Tailscale-written change is not counted by the gate when it is ignored.
		if class == "tailscaleWritten" {
			out.TailscaleWrittenIgnored = true
			if got := out.Findings().Changes; got != 0 {
				t.Errorf("ignored Tailscale-written change: Findings().Changes = %d", got)
			}
		}
		// The layout's row for the class, among the five.
		rep := tools.ACLDiffOutput{Status: "changed", Counts: counts}.Report()
		var rows []string
		for _, c := range rep.Classes {
			if c.Count > 0 {
				rows = append(rows, c.Class)
				if c.Expected != (class == "tailscaleWritten") {
					t.Errorf("class %q: row %+v, expected = %v", class, c, c.Expected)
				}
			}
		}
		if row.label == "" && len(rows) != 0 || row.label != "" && !slices.Equal(rows, []string{row.label}) {
			t.Errorf("class %q: the layout counts %v, want [%s]", class, rows, row.label)
		}
	}
	var order []string
	for _, c := range (tools.ACLDiffOutput{Status: "changed"}).Report().Classes {
		order = append(order, c.Class)
	}
	if want := []string{"defaults", "tests reduced", "widening", "tailscale-written", "semantic"}; !slices.Equal(order, want) {
		t.Errorf("the layout lists %v, want %v", order, want)
	}
}

// The scan fails when it finds nothing, not passes on an empty table: a table keyed on
// constants that are no longer found would otherwise check no class at all.
func TestTheSpellingScanFindsTheClasses(t *testing.T) {
	if got := engineClasses(t); len(got) < 7 {
		t.Fatalf("found %d Class constants, want at least the 7 of the engine: %v", len(got), got)
	}
}

// Every kind a diff lists as gateable is computed: a planted change of the class that feeds
// it makes the count non-zero, so --fail-on cannot name a kind that is always zero.
func TestEveryKindADiffListsIsComputed(t *testing.T) {
	for kind, class := range map[string]string{"tests-reduced": "testsReduced", "defaults": "defaults", "widening": "widening", "change": "semantic"} {
		if !slices.Contains((tools.ACLDiffOutput{}).FailOnKinds(), kind) {
			t.Errorf("acl_diff does not list %s", kind)
		}
		var counts tools.ACLChangeCounts
		if !countsKey(&counts, class) {
			t.Fatalf("no count %s", class)
		}
		f := tools.ACLDiffOutput{Counts: counts}.Findings()
		got := map[string]int{"tests-reduced": f.TestsReduced, "defaults": f.Defaults, "widening": f.Widenings, "change": f.Changes}[kind]
		if got == 0 {
			t.Errorf("a planted %s change leaves --fail-on %s at 0", class, kind)
		}
	}
	if slices.Contains((tools.ACLDiffOutput{}).FailOnKinds(), "warnings") {
		t.Error("acl_diff lists warnings, which it never computes")
	}
	var _ registry.Gated = tools.ACLDiffOutput{}
}
