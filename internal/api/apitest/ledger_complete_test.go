package apitest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"
)

// shapeBuilders returns the name of every exported function of shapes.go whose single
// result is a Shape.
func shapeBuilders(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "shapes.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
			continue
		}
		if id, ok := fn.Type.Results.List[0].Type.(*ast.Ident); ok && id.Name == "Shape" {
			names = append(names, fn.Name.Name)
		}
	}
	sort.Strings(names)
	return names
}

// Every exported builder is in AllShapes, so a new one cannot escape the loops that walk
// the ledger, and each shape's Name is its builder's name.
func TestEveryBuilderIsInAllShapes(t *testing.T) {
	builders := shapeBuilders(t)
	if len(builders) < 20 {
		t.Fatalf("found only %d builders in shapes.go (%v): the parse is not seeing them", len(builders), builders)
	}
	var names []string
	for _, s := range AllShapes() {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	inLedger := map[string]bool{}
	for _, n := range names {
		inLedger[n] = true
	}
	for _, b := range builders {
		if !inLedger[b] {
			t.Errorf("the builder %s is not in AllShapes, or its Name is not %q", b, b)
		}
	}
	isBuilder := map[string]bool{}
	for _, b := range builders {
		isBuilder[b] = true
	}
	for _, n := range names {
		if !isBuilder[n] {
			t.Errorf("AllShapes holds a shape named %q, which is no builder of shapes.go", n)
		}
	}
	if len(builders) != len(names) {
		t.Errorf("%d builders, %d shapes in AllShapes", len(builders), len(names))
	}
}
