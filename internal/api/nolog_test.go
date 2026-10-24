package api_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A policy and a details body are the owner's text, and the POST body of a validation is
// the proposal itself. Nothing may write them to a log, and the way to make sure of that
// is that the packages which handle them cannot log at all: internal/api sends and reads
// them, internal/tools holds the tools that do, internal/doctor sends the live policy
// and one synthetic document for its probes, and internal/registry runs the tools and
// is where an audit line is made (its allowlist of fields is the other half of this).

// loggerImports returns the imports of the Go source src that are the standard loggers.
func loggerImports(name string, src []byte) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var found []string
	for _, imp := range file.Imports {
		if path, err := strconv.Unquote(imp.Path.Value); err == nil && (path == "log" || path == "log/slog") {
			found = append(found, path)
		}
	}
	return found, nil
}

// importersOfALogger returns "file: path" for each logger a non-test file of the packages
// below root imports.
func importersOfALogger(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	for _, path := range sourceFiles(t, root) {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasPrefix(rel, "internal/api/") && !strings.HasPrefix(rel, "internal/tools/") && !strings.HasPrefix(rel, "internal/registry/") && !strings.HasPrefix(rel, "internal/doctor/") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		imports, err := loggerImports(rel, src)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		for _, imp := range imports {
			found = append(found, rel+": "+imp)
		}
	}
	return found
}

func TestNoPackageThatSendsAPolicyImportsALogger(t *testing.T) {
	// The detector can fail: both loggers are found in the packages it guards, aliased
	// or not, and are not found elsewhere.
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
	write("internal/api/a.go", "package a\nimport \"log\"\nvar _ = log.Println\n")
	write("internal/tools/b.go", "package b\nimport l \"log/slog\"\nvar _ = l.Info\n")
	write("internal/registry/c.go", "package c\nimport (\n\t\"fmt\"\n\t\"log\"\n)\nvar _, _ = fmt.Sprint, log.Println\n")
	write("internal/doctor/f.go", "package f\nimport \"log\"\nvar _ = log.Println\n")
	write("internal/cli/d.go", "package d\nimport \"log\"\nvar _ = log.Println\n")
	write("internal/tools/e_test.go", "package e\nimport \"log\"\nvar _ = log.Println\n")
	write("internal/api/ok.go", "package a\nimport \"fmt\"\nvar _ = fmt.Sprint\n")
	if got := importersOfALogger(t, root); len(got) != 4 {
		t.Fatalf("on a planted tree: %v, want the four imports in the guarded packages", got)
	}
	if _, err := loggerImports("p.go", []byte("package p\nimport (")); err == nil {
		t.Error("a file that does not parse was accepted")
	}

	// The tree itself.
	for _, f := range importersOfALogger(t, "../..") {
		t.Errorf("%s: a package that handles policies must not log", f)
	}
}
