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

func verifyForbiddenSource(src []byte) bool {
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		return true
	}
	allowed := map[string]bool{"bytes": true, "context": true, "crypto/sha256": true, "encoding/base64": true, "encoding/json": true, "errors": true, "fmt": true, "io": true, "slices": true, "strings": true, "time": true, "unicode/utf8": true, "github.com/abm9111/tailkeeper/internal/security": true, "github.com/abm9111/tailkeeper/internal/advisory": true, "github.com/abm9111/tailkeeper/internal/guard": true, "github.com/abm9111/tailkeeper/internal/tripwire": true}
	for _, i := range f.Imports {
		name, e := strconv.Unquote(i.Path.Value)
		if e != nil || !allowed[name] || i.Name != nil {
			return true
		}
	}
	bad := false
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		s, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		o, ok := s.X.(*ast.Ident)
		if !ok {
			return true
		}
		if (o.Name == "time" && s.Sel.Name == "Now") || (o.Name == "advisory" && (s.Sel.Name == "Shipped" || s.Sel.Name == "ShippedSources")) || (o.Name == "json" && (s.Sel.Name == "Marshal" || s.Sel.Name == "NewEncoder")) {
			bad = true
		}
		return true
	})
	return bad
}
func TestVerifyPackagePurity(t *testing.T) {
	for _, src := range []string{"package x; import \"os\"", "package x; import \"time\"; func x(){time.Now()}", "package x; import \"advisory\"; func x(){advisory.Shipped()}"} {
		if !verifyForbiddenSource([]byte(src)) {
			t.Fatal("positive control missed")
		}
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		count++
		src, e := os.ReadFile(f)
		if e != nil {
			t.Fatal(e)
		}
		if verifyForbiddenSource(src) {
			t.Errorf("forbidden import or call in %s", f)
		}
	}
	if count == 0 {
		t.Fatal("no production files")
	}
}

func TestPurityAllowlistIsUsed(t *testing.T) {
	allowed := map[string]bool{"bytes": false, "context": false, "crypto/sha256": false, "encoding/base64": false, "encoding/json": false, "errors": false, "fmt": false, "io": false, "slices": false, "strings": false, "time": false, "unicode/utf8": false, "github.com/abm9111/tailkeeper/internal/security": false, "github.com/abm9111/tailkeeper/internal/advisory": false, "github.com/abm9111/tailkeeper/internal/guard": false, "github.com/abm9111/tailkeeper/internal/tripwire": false}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, e := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if e != nil {
			t.Fatal(e)
		}
		for _, i := range f.Imports {
			path, e := strconv.Unquote(i.Path.Value)
			if e != nil {
				t.Fatal(e)
			}
			if _, ok := allowed[path]; !ok {
				t.Errorf("unknown import %s", path)
			} else {
				allowed[path] = true
			}
		}
	}
	for path, used := range allowed {
		if !used {
			t.Errorf("unused allowlist entry %s", path)
		}
	}
}
