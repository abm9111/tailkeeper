package api_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The raw ValidatePolicy sends one request with no bucket, no deadline and no retry: the
// probes need exactly that, and nothing else may have it, or the limit on validation
// requests (30 a minute, two in flight) has a way round. internal/api holds the metered
// calls that use the same endpoint; internal/probe is the harness.

// unmeteredCalls returns file:line for every reference to a method named ValidatePolicy in
// the Go source src (the file name is used in the result): a call, and also a method value
// (g := c.ValidatePolicy), the method handed on as an argument and a method expression
// (T.ValidatePolicy), which send the same request later.
func unmeteredCalls(name string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, err
	}
	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "ValidatePolicy" {
			found = append(found, fset.Position(sel.Pos()).String())
		}
		return true
	})
	return found, nil
}

// sourceFiles lists the non-test Go files under the top-level directories of root that
// hold the module's code. It only lists: the files are read after the walk.
func sourceFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	for _, top := range []string{"cmd", "internal", "scripts"} {
		dir := filepath.Join(root, top)
		if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return err
			case d.IsDir() && d.Name() == "testdata":
				return filepath.SkipDir
			case !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go"):
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

// callersOfTheUnmeteredValidate returns the references to ValidatePolicy outside internal/api
// and internal/probe in the tree at root.
func callersOfTheUnmeteredValidate(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	for _, path := range sourceFiles(t, root) {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "internal/api/") || strings.HasPrefix(rel, "internal/probe/") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		calls, err := unmeteredCalls(rel, src)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		found = append(found, calls...)
	}
	return found
}

func TestOnlyTheProbesCallTheUnmeteredValidate(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const call = "package p\nfunc f(c interface{ ValidatePolicy(...any) }) { c.ValidatePolicy() }\n"
	// The detector can fail: a call in any other package is found, and the two homes and
	// the tests are not.
	write("internal/tools/bad.go", call)
	write("cmd/tailkeeper/bad.go", call)
	write("internal/probe/ok.go", call)
	write("internal/api/ok.go", call)
	write("internal/api/apitest/ok.go", call)
	write("internal/tools/bad_test.go", call)
	write("internal/tools/testdata/ok.go", call)
	// A reference that is not a call sends the same request later: a method value, the
	// method passed on as a function, and a method expression.
	const value = "package p\nfunc f(c interface{ ValidatePolicy(...any) }) { g := c.ValidatePolicy; g() }\n"
	const passed = "package p\nfunc f(c interface{ ValidatePolicy(...any) }) { h(c.ValidatePolicy) }\nfunc h(func(...any)) {}\n"
	const expression = "package p\ntype T interface{ ValidatePolicy(...any) }\nvar m = T.ValidatePolicy\n"
	write("internal/tools/value.go", value)
	write("internal/registry/passed.go", passed)
	write("internal/app/expression.go", expression)
	got := callersOfTheUnmeteredValidate(t, root)
	joined := strings.Join(got, " ")
	for _, want := range []string{"cmd/tailkeeper/bad.go", "internal/tools/bad.go", "internal/tools/value.go", "internal/registry/passed.go", "internal/app/expression.go"} {
		if !strings.Contains(joined, want) {
			t.Errorf("on a planted tree: %v does not name %s", got, want)
		}
	}
	if len(got) != 5 {
		t.Fatalf("on a planted tree: %v, want the five references outside the homes", got)
	}
	if _, err := unmeteredCalls("p.go", []byte("package p\nfunc (")); err == nil {
		t.Error("a file that does not parse was accepted")
	}

	// The tree itself.
	files := sourceFiles(t, "../..")
	if len(files) < 100 {
		t.Fatalf("found %d Go files in the module: the walk is not seeing them", len(files))
	}
	for _, c := range callersOfTheUnmeteredValidate(t, "../..") {
		t.Errorf("%s refers to ValidatePolicy, which is unmetered: use a ValidateCall (api.Client.BeginValidate)", c)
	}
}
