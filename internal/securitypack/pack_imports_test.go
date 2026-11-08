package securitypack

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func codecForbiddenSource(src []byte) bool {
	file, err := parser.ParseFile(token.NewFileSet(), "codec.go", src, 0)
	if err != nil {
		return true
	}
	allowed := map[string]bool{"bytes": true, "context": true, "crypto/sha256": true, "encoding/base64": true, "encoding/json": true, "errors": true, "fmt": true, "io": true, "slices": true, "strings": true, "time": true, "unicode/utf8": true, "github.com/abm9111/tailkeeper/internal/security": true, "github.com/abm9111/tailkeeper/internal/advisory": true, "github.com/abm9111/tailkeeper/internal/guard": true, "github.com/abm9111/tailkeeper/internal/tripwire": true}
	for _, imp := range file.Imports {
		name, err := strconv.Unquote(imp.Path.Value)
		if err != nil || !allowed[name] || imp.Name != nil {
			return true
		}
	}
	forbidden := false
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		owner, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		if owner.Name == "security" && (selector.Sel.Name == "Evaluate" || selector.Sel.Name == "ExplainAccess") {
			forbidden = true
		}
		if owner.Name == "advisory" && (selector.Sel.Name == "Merge" || selector.Sel.Name == "Shipped" || selector.Sel.Name == "ShippedSources") {
			forbidden = true
		}
		if owner.Name == "time" && selector.Sel.Name == "Now" {
			forbidden = true
		}
		if owner.Name == "json" && (selector.Sel.Name == "Marshal" || selector.Sel.Name == "NewEncoder") {
			forbidden = true
		}
		return true
	})
	return forbidden
}

func TestPackNoImplicitImportsOrCalls(t *testing.T) {
	if !codecForbiddenSource([]byte("package p\nimport \"os\"\n")) {
		t.Fatal("import detector positive control failed")
	}
	if !codecForbiddenSource([]byte("package p\nimport \"time\"\nfunc f(){ time.Now() }\n")) {
		t.Fatal("call detector positive control failed")
	}
	files, err := filepath.Glob("pack_*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no pack files found")
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if codecForbiddenSource(src) {
			t.Errorf("forbidden import or call in %s", name)
		}
	}
}
