package workflows

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The complexity ratchet. A function that is hard to follow is hard to review, and the
// masking and policy code that the privacy and policy claims rest on is the code that most
// needs a reviewer to follow it (VIGIL-CODE-001: a function of 90 branches, 100 above 15).
// The ratchet lets that number fall and never rise.
//
// A function's score is its cyclomatic complexity as gocyclo counts it (the linter VIGIL ran,
// with min-complexity 15; the rule is cyclomatic below): 1, plus 1 for each if, for and range
// statement, each case of a switch or a type switch other than default, each case of a select
// other than default, and each && and ||. A case that lists several values counts once. The
// branches of a function literal count toward the function that holds it, as gocyclo counts
// them; a function literal anywhere in the value of a package-level variable is a function of
// its own, named by the variable. Methods are named (T).m or (*T).m. Test files, directories named
// testdata and everything outside cmd/ and internal/ are not scanned.
//
// testdata/complexity-baseline.txt lists every function that scores above complexityLimit,
// with its score. The test fails when
//
//   - a function not in the baseline scores above the limit: split it;
//   - a listed function scores more than its line says: split it, do not raise the line;
//   - a listed function scores less than its line says, but still above the limit: lower the
//     line, so that the function cannot grow back to its old score;
//   - a listed function scores at or below the limit, or is gone: delete the line.
//
// The baseline therefore only shrinks. There is no flag that rewrites it: a line is added or
// raised by hand, in a diff a reviewer sees, and only with the owner's ruling. The test
// prints the line each failure needs.
const complexityLimit = 15

// complexityBaselineFile is the baseline, relative to this package.
const complexityBaselineFile = "testdata/complexity-baseline.txt"

// cyclomatic is the score of fn, a *ast.FuncDecl or a *ast.FuncLit.
func cyclomatic(fn ast.Node) int {
	score := 1
	ast.Inspect(fn, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt:
			score++
		case *ast.CaseClause:
			if n.List != nil { // not default
				score++
			}
		case *ast.CommClause:
			if n.Comm != nil { // not default
				score++
			}
		case *ast.BinaryExpr:
			if n.Op == token.LAND || n.Op == token.LOR {
				score++
			}
		}
		return true
	})
	return score
}

// receiverName writes the receiver type of a method: T, *T, or either with its type
// parameters (*Set[K]).
func receiverName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + receiverName(t.X)
	case *ast.IndexExpr:
		return receiverName(t.X) + "[" + exprName(t.Index) + "]"
	case *ast.IndexListExpr:
		names := make([]string, len(t.Indices))
		for i, x := range t.Indices {
			names[i] = exprName(x)
		}
		return receiverName(t.X) + "[" + strings.Join(names, ",") + "]"
	}
	return "?"
}

func exprName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return "?"
}

// funcScores returns the score of each function of a file, in the order they appear: the
// declared functions and methods, and the function literals anywhere in the value of a
// package-level variable (bare, in parentheses, in a call or in a composite literal), each
// named by its variable.
func funcScores(f *ast.File) []funcScore {
	var out []funcScore
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			name := d.Name.Name
			if d.Recv != nil && len(d.Recv.List) > 0 {
				name = "(" + receiverName(d.Recv.List[0].Type) + ")." + name
			}
			out = append(out, funcScore{name, cyclomatic(d)})
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				v, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, value := range v.Values {
					name := v.Names[min(i, len(v.Names)-1)].Name
					ast.Inspect(value, func(n ast.Node) bool {
						lit, ok := n.(*ast.FuncLit)
						if ok {
							out = append(out, funcScore{name, cyclomatic(lit)})
						}
						return !ok
					})
				}
			}
		}
	}
	return out
}

type funcScore struct {
	name  string
	score int
}

// scanComplexity scores every function of the non-test Go files under root/cmd and
// root/internal. The key of a function is its file, a tab and its name (a second function of
// the same name in a file, such as init, gets #2, #3, ... after it).
func scanComplexity(root string) (map[string]int, error) {
	scores := map[string]int{}
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			for _, fn := range funcScores(f) {
				key := filepath.ToSlash(rel) + "\t" + fn.name
				for n := 2; ; n++ {
					if _, taken := scores[key]; !taken {
						break
					}
					key = filepath.ToSlash(rel) + "\t" + fn.name + "#" + strconv.Itoa(n)
				}
				scores[key] = fn.score
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return scores, nil
}

// parseComplexityBaseline reads the baseline: one function a line, as the score, the file
// and the function, separated by tabs, sorted by file and then function. Blank lines and
// lines that start with # are skipped.
func parseComplexityBaseline(text string) (map[string]int, error) {
	baseline := map[string]int{}
	var prev string
	for n, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return nil, fmt.Errorf("line %d: want the score, the file and the function, separated by tabs: %q", n+1, line)
		}
		score, err := strconv.Atoi(fields[0])
		if err != nil || score <= complexityLimit {
			return nil, fmt.Errorf("line %d: %q is not a score above %d", n+1, fields[0], complexityLimit)
		}
		key := fields[1] + "\t" + fields[2]
		if _, dup := baseline[key]; dup {
			return nil, fmt.Errorf("line %d: %s is listed twice", n+1, fields[2])
		}
		if prev != "" && key < prev {
			return nil, fmt.Errorf("line %d: %s is out of order; the lines are sorted by file and then function", n+1, fields[2])
		}
		baseline[key], prev = score, key
	}
	return baseline, nil
}

// complexityProblems compares what was measured with the baseline and says what must change.
// measured holds every function, so that a function that fell is told by how much.
func complexityProblems(measured, baseline map[string]int) []string {
	var problems []string
	name := func(key string) string { return strings.Replace(key, "\t", " ", 1) }
	for key, score := range measured {
		if _, listed := baseline[key]; !listed && score > complexityLimit {
			problems = append(problems, fmt.Sprintf("%s scores %d, above %d, and is not in the baseline: split it into smaller functions (the baseline lists only what was above %d when it was written; do not add a line)", name(key), score, complexityLimit, complexityLimit))
		}
	}
	for key, listed := range baseline {
		score, exists := measured[key]
		switch {
		case !exists:
			problems = append(problems, fmt.Sprintf("%s is in the baseline but is gone: delete its line from the baseline", name(key)))
		case score <= complexityLimit:
			problems = append(problems, fmt.Sprintf("%s now scores %d, within %d: delete its line from the baseline", name(key), score, complexityLimit))
		case score > listed:
			problems = append(problems, fmt.Sprintf("%s rose from %d to %d: split it; the baseline is not raised", name(key), listed, score))
		case score < listed:
			problems = append(problems, fmt.Sprintf("%s fell from %d to %d: change its score in the baseline to %d, so that it cannot grow back", name(key), listed, score, score))
		}
	}
	sort.Strings(problems)
	return problems
}

func TestNoFunctionGrowsMoreComplexThanTheBaselineAllows(t *testing.T) {
	root := repoRoot(t)
	measured, err := scanComplexity(root)
	if err != nil {
		t.Fatal(err)
	}
	// A scan that finds nothing would pass every comparison.
	if len(measured) < 1000 {
		t.Fatalf("the scan found %d functions under cmd and internal: it is not reading the repository", len(measured))
	}
	text, err := os.ReadFile(complexityBaselineFile)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := parseComplexityBaseline(string(text))
	if err != nil {
		t.Fatalf("%s: %v", complexityBaselineFile, err)
	}
	if len(baseline) == 0 {
		t.Fatalf("%s lists no function: a repository this size has some above %d, so it is not being read", complexityBaselineFile, complexityLimit)
	}
	for _, p := range complexityProblems(measured, baseline) {
		t.Error(p)
	}
}

// Each source below is a function with the score gocyclo gives it. The rule is the one in
// the comment of complexityLimit; a construct that must not count has a case of its own.
func TestComplexityCountsTheBranchesGocycloCounts(t *testing.T) {
	for _, c := range []struct {
		name string
		src  string
		want map[string]int
	}{
		{"nothing", `func f() {}`, map[string]int{"f": 1}},
		{"if", `func f(a bool) { if a {} }`, map[string]int{"f": 2}},
		{"if and else if", `func f(a, b bool) { if a {} else if b {} else {} }`, map[string]int{"f": 3}},
		{"for", `func f(a bool) { for a {} }`, map[string]int{"f": 2}},
		{"range", `func f(a []int) { for range a {} }`, map[string]int{"f": 2}},
		{"switch cases, default left out", `func f(a int) { switch a { case 1: case 2: default: } }`, map[string]int{"f": 3}},
		{"one case of several values", `func f(a int) { switch a { case 1, 2, 3: } }`, map[string]int{"f": 2}},
		{"switch without a tag", `func f(a int) { switch { case a > 1: case a < 0: } }`, map[string]int{"f": 3}},
		{"type switch", `func f(a any) { switch a.(type) { case int: case string: default: } }`, map[string]int{"f": 3}},
		{"select, default left out", `func f(c chan int) { select { case <-c: case c <- 1: default: } }`, map[string]int{"f": 3}},
		{"and, or", `func f(a, b, c bool) bool { return a && b || c }`, map[string]int{"f": 3}},
		{"other operators", `func f(a, b int) bool { return a == b || a < b }`, map[string]int{"f": 2}},
		{"goto, break, defer, go", `func f() { defer g(); go g(); L: for { break L }; goto L }; func g() {}`, map[string]int{"f": 2, "g": 1}},
		{"a function literal counts toward the function", `func f(a bool) { g := func(b bool) { if b {} }; if a { g(a) } }`, map[string]int{"f": 3}},
		{"a literal in a package variable is a function", `var h = func(a bool) { if a {} }; func f() {}`, map[string]int{"h": 2, "f": 1}},
		{"a literal in parentheses", `var h = (func(a bool) { if a {} })`, map[string]int{"h": 2}},
		{"a literal in a call", `var h = g(func(a bool) { if a {} }); func g(x any) any { return x }`, map[string]int{"h": 2, "g": 1}},
		{"a literal in a composite literal", `var h = map[string]func(bool){"x": func(a bool) { if a {} }}`, map[string]int{"h": 2}},
		{"a literal inside a literal counts toward the outer one", `var h = func(a bool) { _ = func(b bool) { if b {} }; if a {} }`, map[string]int{"h": 3}},
		{"each variable of a spec is named", `var h, k = func(a bool) { if a {} }, func(a bool) { for a {} }`, map[string]int{"h": 2, "k": 2}},
		{"a method", `type T struct{}; func (T) m(a bool) { if a {} }; func (*T) n(a bool) { for a {} }`, map[string]int{"(T).m": 2, "(*T).n": 2}},
		{"a generic method", `type S[K any] struct{}; func (s *S[K]) m(a bool) { if a {} }`, map[string]int{"(*S[K]).m": 2}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package x\n"+c.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]int{}
			for _, fn := range funcScores(f) {
				got[fn.name] = fn.score
			}
			if fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Errorf("scores %v, want %v", got, c.want)
			}
		})
	}
}

// The scan reads cmd and internal, names a function by its file, and leaves out test files,
// testdata and everything else.
func TestComplexityScanReadsTheNonTestFilesUnderCmdAndInternal(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("internal/a/a.go", "package a\nfunc f(x bool) { if x {} }\nfunc init() {}\nfunc init() { if true {} }\n")
	write("internal/a/a_test.go", "package a\nfunc g(x bool) { if x {} }\n")
	write("internal/a/testdata/t.go", "package t\nfunc g(x bool) { if x {} }\n")
	write("cmd/b/b.go", "package main\nfunc main() { for {} }\n")
	write("scripts/c.go", "package main\nfunc main() { for {} }\n")
	got, err := scanComplexity(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"internal/a/a.go\tf": 2, "internal/a/a.go\tinit": 1, "internal/a/a.go\tinit#2": 2, "cmd/b/b.go\tmain": 2}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("scan found %v, want %v", got, want)
	}
}

// Each way the comparison can fail, and the ways it must not.
func TestComplexityRatchetFailsOnGrowthAndOnSlack(t *testing.T) {
	const f, g, h, k = "p/f.go\tf", "p/g.go\tg", "p/h.go\th", "p/k.go\tk"
	baseline := map[string]int{f: 30, g: 20, h: 18, k: 17}
	for _, c := range []struct {
		name     string
		measured map[string]int
		want     []string // each must be in a problem; none when empty
	}{
		{"unchanged", map[string]int{f: 30, g: 20, h: 18, k: 17, "p/n.go\tn": 15, "p/m.go\tm": 3}, nil},
		{"a new function above the limit", map[string]int{f: 30, g: 20, h: 18, k: 17, "p/n.go\tn": 16}, []string{"p/n.go n scores 16, above 15, and is not in the baseline"}},
		{"a listed function rises by one", map[string]int{f: 31, g: 20, h: 18, k: 17}, []string{"p/f.go f rose from 30 to 31"}},
		{"a listed function falls and is still above the limit", map[string]int{f: 29, g: 20, h: 18, k: 17}, []string{"p/f.go f fell from 30 to 29: change its score in the baseline to 29"}},
		{"a listed function falls to the limit", map[string]int{f: 15, g: 20, h: 18, k: 17}, []string{"p/f.go f now scores 15, within 15: delete its line"}},
		{"a listed function is gone", map[string]int{g: 20, h: 18, k: 17}, []string{"p/f.go f is in the baseline but is gone: delete its line"}},
		{"a listed function moves to another file", map[string]int{"p/z.go\tf": 30, g: 20, h: 18, k: 17}, []string{"p/z.go f scores 30, above 15, and is not in the baseline", "p/f.go f is in the baseline but is gone"}},
		{"one rises and one is new", map[string]int{f: 31, g: 20, h: 18, k: 17, "p/n.go\tn": 99}, []string{"p/f.go f rose from 30 to 31", "p/n.go n scores 99"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := complexityProblems(c.measured, baseline)
			if len(got) != len(c.want) {
				t.Fatalf("problems %q, want %d about %q", got, len(c.want), c.want)
			}
			for _, w := range c.want {
				found := false
				for _, p := range got {
					found = found || strings.Contains(p, w)
				}
				if !found {
					t.Errorf("no problem says %q in %q", w, got)
				}
			}
		})
	}
}

func TestComplexityBaselineIsReadStrictly(t *testing.T) {
	good := "# comment\n\n20\ta/a.go\t(*T).m\n16\ta/b.go\tf\n"
	got, err := parseComplexityBaseline(good)
	if err != nil || len(got) != 2 || got["a/a.go\t(*T).m"] != 20 || got["a/b.go\tf"] != 16 {
		t.Fatalf("parse %q = %v, %v", good, got, err)
	}
	if got, err := parseComplexityBaseline(strings.ReplaceAll(good, "\n", "\r\n")); err != nil || len(got) != 2 {
		t.Errorf("a file with CRLF line ends: %v, %v", got, err)
	}
	for name, text := range map[string]string{
		"a score at the limit":      "15\ta/a.go\tf\n",
		"a score that is no number": "many\ta/a.go\tf\n",
		"a missing field":           "20\ta/a.go\n",
		"spaces for tabs":           "20 a/a.go f\n",
		"a function listed twice":   "20\ta/a.go\tf\n20\ta/a.go\tf\n",
		"lines out of order":        "20\ta/b.go\tf\n20\ta/a.go\tf\n",
	} {
		if got, err := parseComplexityBaseline(text); err == nil {
			t.Errorf("%s: accepted %q as %v", name, text, got)
		}
	}
}
