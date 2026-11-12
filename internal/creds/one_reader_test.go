package creds

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every credential read goes through the checked reader (config.ReadSecretFile, or the
// fake a test puts in its place). System once also held ReadFile, an unchecked by-path
// reader that no credential read used any more; leaving it assignable invited a bypass
// (VIGIL-SEC-001), so it is gone, and so is any other field that could read a file.
func TestSystemHasNoFileReaderButTheCheckedOne(t *testing.T) {
	reader := reflect.TypeOf(func(string) ([]byte, error) { return nil, nil })
	st := reflect.TypeFor[System]()
	if _, ok := st.FieldByName("ReadFile"); ok {
		t.Error("System still has the unchecked ReadFile field")
	}
	var readers []string
	for i := 0; i < st.NumField(); i++ {
		if f := st.Field(i); f.Type == reader {
			readers = append(readers, f.Name)
		}
	}
	if len(readers) != 1 || readers[0] != "ReadSecretFile" {
		t.Errorf("System's fields that read a file by path: %v, want only ReadSecretFile", readers)
	}
}

// The production code of this package reads no file itself: a call to os.ReadFile, os.Open
// or os.OpenFile (or ioutil.ReadFile) here would be a read that skips the checks of
// config.ReadSecretFile. The detector is shown to see a planted call.
func TestCredentialCodeReadsNoFileByItself(t *testing.T) {
	banned := func(fset *token.FileSet, f *ast.File) []string {
		var hits []string
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch pkg.Name + "." + sel.Sel.Name {
			case "os.ReadFile", "os.Open", "os.OpenFile", "ioutil.ReadFile":
				hits = append(hits, fset.Position(sel.Pos()).String()+": "+pkg.Name+"."+sel.Sel.Name)
			}
			return true
		})
		return hits
	}

	fset := token.NewFileSet()
	planted, err := parser.ParseFile(fset, "planted.go", "package p\nimport \"os\"\nfunc f() { os.ReadFile(\"x\") }\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := banned(fset, planted); len(got) != 1 {
		t.Fatalf("the detector saw %v in a planted os.ReadFile call, want one hit", got)
	}

	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files: %v", err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, hit := range banned(fset, f) {
			t.Errorf("credential code reads a file by itself: %s", hit)
		}
	}
}
