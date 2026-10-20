package apitest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// PermitProbeRequests switches the validate spy off for one fake. Only the probe harness
// sends requests whose content type and body disagree, so only its tests may ask for that.
// A test anywhere else that calls it could send an array as HuJSON and read a pass for a
// policy that was never validated, and the spy would not say so.

// mayPermit says whether the test file rel (slash-separated, from the module root) may call
// PermitProbeRequests: every test file below internal/probe, the spy's own tests, and
// internal/api/policy_test.go, whose cases send deliberately mismatched bodies through
// ValidatePolicy.
func mayPermit(rel string) bool {
	return strings.HasPrefix(rel, "internal/probe/") ||
		rel == "internal/api/policy_test.go" ||
		rel == "internal/api/apitest/spy_test.go"
}

// permitCalls returns the position of every use of PermitProbeRequests (a call or a method
// value) in the _test.go files under root, and the files that are allowed to use it and do.
// The walk skips what go test ./... does not enter (see skipDir), and, unlike the lint of
// hand-written JSON, enters the apitest package: its other tests may not call it either.
func permitCalls(t *testing.T, root string) (findings []string, allowedHits map[string]bool) {
	t.Helper()
	allowedHits = map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "internal/api/apitest" && skipDir(root, rel, d.Name()) {
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
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, rel, src, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			// A method: x.PermitProbeRequests() or the method value x.PermitProbeRequests.
			if sel, ok := n.(*ast.SelectorExpr); !ok || sel.Sel.Name != "PermitProbeRequests" {
				return true
			}
			if mayPermit(rel) {
				allowedHits[rel] = true
			} else {
				findings = append(findings, fset.Position(n.Pos()).String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(findings)
	return findings, allowedHits
}

func TestOnlyTheProbeTestsPermitProbeRequests(t *testing.T) {
	findings, hits := permitCalls(t, moduleRoot(t))
	for _, f := range findings {
		t.Errorf("%s calls PermitProbeRequests; only the tests of internal/probe, apitest/spy_test.go and internal/api/policy_test.go may", f)
	}
	// The detector sees the calls that are allowed: without this, a walk that found
	// nothing anywhere would read as clean.
	for _, want := range []string{"internal/probe/probes_test.go", "internal/probe/world_test.go", "internal/api/policy_test.go", "internal/api/apitest/spy_test.go"} {
		if !hits[want] {
			t.Errorf("the walk did not see the call in %s: it is not reading the tree", want)
		}
	}
}

// The detector can fail: a call in any other test file is found, a call in an allowed
// file is not, and the directories go test does not enter are not entered.
func TestPermitCallsFindsACallAnywhereElse(t *testing.T) {
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
	call := "package p\nfunc f(x *Fake) { x.PermitProbeRequests() }\n"
	value := "package p\nfunc f(x *Fake) { g := x.PermitProbeRequests; g() }\n"
	write("internal/tools/x_test.go", call)
	write("internal/tools/y_test.go", value)
	write("internal/api/apitest/fake_test.go", call) // the apitest package is walked
	write("internal/probe/x_test.go", call)
	write("internal/probe/sub/x_test.go", call)
	write("internal/api/policy_test.go", call)
	write("internal/api/apitest/spy_test.go", call)
	write("internal/tools/notatest.go", call) // only _test.go files are read
	write("internal/testdata/x_test.go", call)
	write(".worktrees/x/internal/tools/x_test.go", call)
	write("vendor/m/x_test.go", call)
	write("sub/go.mod", "module example.org/sub\n")
	write("sub/x_test.go", call)
	findings, hits := permitCalls(t, root)
	if len(findings) != 3 {
		t.Fatalf("findings = %v, want internal/tools/x_test.go, internal/tools/y_test.go and internal/api/apitest/fake_test.go", findings)
	}
	for i, want := range []string{"internal/api/apitest/fake_test.go:2:", "internal/tools/x_test.go:2:", "internal/tools/y_test.go:2:"} {
		if !strings.HasPrefix(findings[i], want) {
			t.Errorf("finding %d is %q, want it to start with %q", i, findings[i], want)
		}
	}
	for _, want := range []string{"internal/probe/x_test.go", "internal/probe/sub/x_test.go", "internal/api/policy_test.go", "internal/api/apitest/spy_test.go"} {
		if !hits[want] {
			t.Errorf("an allowed call in %s was not seen", want)
		}
	}
}
