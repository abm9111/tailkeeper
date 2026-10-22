package tkerr

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// declaredCodes returns every constant of type Code that tkerr.go declares: its value
// mapped to its name. It reads the source, so a code added to the file is found without
// anyone adding it to a list.
func declaredCodes(t *testing.T) map[Code]string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "tkerr.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[Code]string{}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Code" {
				continue
			}
			for i, name := range vs.Names {
				var lit *ast.BasicLit
				if i < len(vs.Values) {
					lit, _ = vs.Values[i].(*ast.BasicLit)
				}
				if lit == nil || lit.Kind != token.STRING {
					t.Fatalf("tkerr.go: the constant %s is a Code that is not a string literal", name.Name)
				}
				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				out[Code(value)] = name.Name
			}
		}
	}
	if len(out) < 30 {
		t.Fatalf("found %d Code constants in tkerr.go (%v): the reading is broken, because 33 were declared when this test was written", len(out), out)
	}
	return out
}

// wantExit is what the CLI exits with for each code (docs/design.md §16, §19), written out so a
// code cannot be added to tkerr.go, or its exit changed in ExitCode, without a change
// here that a reviewer sees. Every code that is not listed in a case of ExitCode exits 1.
var wantExit = map[Code]int{
	Usage:                 2,
	ScopeMissing:          5,
	CredentialUnavailable: 5,
	TokenRejected:         5,
	ValidationFailed:      2,
	PaymentRequired:       1,
	FeatureUnavailable:    1,
	NotFound:              1,
	Conflict:              1,
	UnsupportedTarget:     1,
	APIRateLimited:        1,
	UpstreamUnavailable:   1,
	APIError:              1,
	ConfigMissing:         6,
	ConfigInvalid:         6,
	ConfigUnsafe:          6,
	AuditUnavailable:      7,
	FindingsPresent:       8,
	FilterRefused:         2,
	PrivacyKeyUnavailable: 5,
	ToolHidden:            2,

	LocalBinaryMissing:      1,
	LocalDaemonUnreachable:  1,
	LocalPermissionDenied:   1,
	LocalStopped:            1,
	LocalNeedsLogin:         1,
	LocalNeedsMachineAuth:   1,
	LocalTimeout:            1,
	LocalOutputUnrecognized: 1,
	LocalRateLimited:        1,
	LocalCommandFailed:      1,

	Internal:       1,
	OutputWithheld: 1,

	PolicyRejectedOrServerError: 1,
	ValidateRateLimited:         1,
	TooComplex:                  2,
	// New codes go here, with the exit the design (§19) gives them.
}

// exitTableProblems compares the declared codes with a table of expected exits and with
// what exit returns for each: a code without a row, a row whose exit differs, and a row
// for a code that is not declared.
func exitTableProblems(declared map[Code]string, table map[Code]int, exit func(Code) int) []string {
	var out []string
	for code, name := range declared {
		want, ok := table[code]
		if !ok {
			out = append(out, fmt.Sprintf("%s (%q) has no row in the expected exit table", name, code))
			continue
		}
		if got := exit(code); got != want {
			out = append(out, fmt.Sprintf("%s (%q): ExitCode is %d, the table says %d", name, code, got, want))
		}
	}
	for code := range table {
		if _, ok := declared[code]; !ok {
			out = append(out, fmt.Sprintf("the expected exit table has a row for %q, which tkerr.go does not declare", code))
		}
	}
	sort.Strings(out)
	return out
}

// Every Code constant has an expected exit, and ExitCode returns it. A new code that
// falls into the default case (exit 1) by accident, or a changed case, fails here.
func TestExitCodeCoversEveryCode(t *testing.T) {
	exit := func(c Code) int { return ExitCode(New(c, "m", "")) }
	for _, problem := range exitTableProblems(declaredCodes(t), wantExit, exit) {
		t.Error(problem)
	}
}

// The comparison is run on inputs that have each fault, so it cannot pass by reading
// nothing.
func TestExitTableProblemsFindsWhatIsWrong(t *testing.T) {
	declared := map[Code]string{"a": "A", "b": "B", "c": "C"}
	table := map[Code]int{"a": 2, "b": 5, "d": 1}
	exit := func(c Code) int {
		return map[Code]int{"a": 2, "b": 6, "c": 1}[c]
	}
	got := exitTableProblems(declared, table, exit)
	want := []string{
		`B ("b"): ExitCode is 6, the table says 5`,
		`C ("c") has no row in the expected exit table`,
		`the expected exit table has a row for "d", which tkerr.go does not declare`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if p := exitTableProblems(map[Code]string{"a": "A"}, map[Code]int{"a": 2}, func(Code) int { return 2 }); len(p) != 0 {
		t.Errorf("a matching table reports %v", p)
	}
}
