package apitest

import (
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

// A test may not write validate or details JSON by hand: the fake would then answer
// with whatever its author imagined, and the reader would be written to match.
// The shapes come from the ledger (shapes.go). This test walks every
// _test.go file of the module and fails on a string that holds both "message" and
// "data" (a validate answer), or both "acl" and "warnings" (a details answer).

// allowed lists the files that may hold such strings. internal/api/acl_test.go feeds
// raw bodies to the reader on purpose, to see what it refuses, and so do the table and the
// fuzz seeds of the policy-mode reader and the refusals of the details reader; nothing
// else is here.
var allowed = map[string]bool{
	"internal/api/acl_test.go":              true,
	"internal/api/policy_details_test.go":   true,
	"internal/api/policy_read_test.go":      true,
	"internal/api/policy_read_fuzz_test.go": true,
}

// looksLikeValidateJSON reports whether s is shaped like a validate or a details answer.
func looksLikeValidateJSON(s string) bool {
	has := func(key string) bool { return strings.Contains(s, strconv.Quote(key)) }
	return has("message") && has("data") || has("acl") && has("warnings")
}

// stringsOf returns the text of the string literals in e, where e is a literal or a
// chain of + over literals and other operands (strings.Join(...), a variable). The
// operands that are not literals are skipped; the literals are joined with a NUL.
func stringsOf(e ast.Expr) (parts []string, ok bool) {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return nil, false
		}
		s, err := strconv.Unquote(e.Value)
		return []string{s}, err == nil
	case *ast.ParenExpr:
		return stringsOf(e.X)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return nil, false
		}
		l, lok := stringsOf(e.X)
		r, rok := stringsOf(e.Y)
		return append(l, r...), lok || rok
	}
	return nil, false
}

// handWritten returns the position of every string in src (a Go file named name) that
// looks like validate or details JSON.
func handWritten(name string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, err
	}
	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		e, isExpr := n.(ast.Expr)
		if !isExpr {
			return true
		}
		switch e.(type) {
		case *ast.BasicLit, *ast.BinaryExpr:
		default:
			return true
		}
		parts, ok := stringsOf(e)
		if !ok {
			return true
		}
		if looksLikeValidateJSON(strings.Join(parts, "\x00")) {
			found = append(found, fset.Position(e.Pos()).String())
			return false // the pieces of a chain are one finding
		}
		return true
	})
	return found, nil
}

// moduleRoot finds the directory with go.mod above the test's working directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above " + dir)
		}
		dir = parent
	}
}

// skipDir reports whether the walk leaves the directory rel (named name, below root)
// alone: the ones go test ./... does not enter (a name that starts with . or _, testdata,
// vendor, node_modules, and a directory with a go.mod of its own, such as a git worktree
// of this repository under .worktrees), and the build output, the docs and the ledger's own package.
func skipDir(root, rel, name string) bool {
	if rel == "." {
		return false
	}
	switch rel {
	case "bin", "dist", "docs", "internal/api/apitest":
		return true
	}
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
		return true
	}
	switch name {
	case "testdata", "vendor", "node_modules":
		return true
	}
	_, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel), "go.mod"))
	return err == nil
}

// lintTree returns the findings of every _test.go file under root, except the
// apitest package itself (it builds the shapes) and the allowed files, and the
// allowed files that had no finding (a stale entry).
func lintTree(t *testing.T, root string) (findings, stale []string) {
	t.Helper()
	hit := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skipDir(root, rel, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		got, err := handWritten(rel, src)
		if err != nil {
			return err
		}
		if allowed[rel] {
			if len(got) > 0 {
				hit[rel] = true
			}
			return nil
		}
		findings = append(findings, got...) // handWritten named the file by its path below root
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for f := range allowed {
		if !hit[f] {
			stale = append(stale, f)
		}
	}
	sort.Strings(findings)
	sort.Strings(stale)
	return findings, stale
}

func TestNoHandWrittenValidateJSON(t *testing.T) {
	findings, stale := lintTree(t, moduleRoot(t))
	for _, f := range findings {
		t.Errorf("%s writes validate or details JSON by hand: build it with a shape from internal/api/apitest/shapes.go", f)
	}
	for _, f := range stale {
		t.Errorf("%s is on the allowlist but holds no such string: remove it from allowed", f)
	}
}

// The detector can fail: each source below is a known positive or a known negative.
func TestHandWrittenFindsValidateJSON(t *testing.T) {
	const head = "package p\n"
	for _, c := range []struct {
		name, body string
		want       int
	}{
		{"a raw validate answer", "var a = `{\"message\":\"x\",\"data\":[]}`", 1},
		{"an interpreted validate answer", `var a = "{\"message\":\"x\",\"data\":[]}"`, 1},
		{"a concatenation split across the keys", "var a = `{\"message\":\"x\",` + b + `\"data\":[]}`", 1},
		{"a concatenation of a call and literals", "var a = `{\"message\":\"x\",\"data\":[{\"user\":\"a\",\"errors\":[` + strings.Join(e, \",\") + `]}]}`", 1},
		{"a details answer", "var a = `{\"acl\":\"e30=\",\"warnings\":null}`", 1},
		{"a bare message", "var a = `{\"message\":\"forbidden\"}`", 0},
		{"data alone", "var a = `{\"data\":[]}`", 0},
		{"acl alone", "var a = `{\"acl\":\"e30=\"}`", 0},
		{"the words in prose", "var a = \"message and data\"", 0},
		{"two findings", "var a = `{\"message\":\"x\",\"data\":[]}`\nvar b = `{\"acl\":\"\",\"warnings\":[]}`", 2},
	} {
		got, err := handWritten("p_test.go", []byte(head+c.body))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(got) != c.want {
			t.Errorf("%s: %d findings %v, want %d", c.name, len(got), got, c.want)
		}
	}
	if _, err := handWritten("p_test.go", []byte("package p\nvar a = ")); err == nil {
		t.Error("a file that does not parse was accepted")
	}
}

// The walk applies the allowlist both ways: a hit in an allowed file is not a finding,
// a hit anywhere else is, and an allowed file with no hit is reported as stale.
func TestLintTreeAppliesTheAllowlist(t *testing.T) {
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
	bad := "package p\nvar a = `{\"message\":\"x\",\"data\":[]}`\n"
	write("internal/x/x_test.go", bad)
	write("internal/api/apitest/shapes_test.go", bad) // the ledger's own package is exempt
	write("internal/x/notatest.go", bad)              // only _test.go files are read
	write("docs/y_test.go", bad)
	// What go test ./... does not enter, the walk does not enter either.
	write(".worktrees/x/internal/x/x_test.go", bad)
	write("_old/x_test.go", bad)
	write("internal/testdata/x_test.go", bad)
	write("vendor/m/x_test.go", bad)
	write("node_modules/m/x_test.go", bad)
	write("sub/go.mod", "module example.org/sub\n")
	write("sub/x_test.go", bad) // a nested module is not this module's
	findings, stale := lintTree(t, root)
	if len(findings) != 1 || !strings.HasPrefix(findings[0], "internal/x/x_test.go:2:") {
		t.Errorf("findings = %v", findings)
	}
	if len(stale) != len(allowed) {
		t.Errorf("stale = %v, want every allowlisted file, none of which is in the tree yet", stale)
	}
	for f := range allowed {
		write(f, bad)
	}
	if findings, stale = lintTree(t, root); len(stale) != 0 || len(findings) != 1 {
		t.Errorf("with the allowed file: findings %v, stale %v", findings, stale)
	}
}
