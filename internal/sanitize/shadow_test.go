package sanitize

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"
)

// predeclaredFuncs are the builtin functions a name in this package must not hide: a
// parameter called max stopped the body from using the builtin, and nothing said so.
var predeclaredFuncs = []string{"append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len",
	"make", "max", "min", "new", "panic", "print", "println", "real", "recover"}

// shadowed lists, as file:line:column and name, every parameter, result, variable, range
// variable, short declaration, top-level function and type in f that is named like a
// predeclared function. The field names of a struct and the method names of an interface
// are not reported: they live in the type's own namespace and hide nothing.
func shadowed(fset *token.FileSet, f *ast.File) []string {
	var found []string
	report := func(id *ast.Ident) {
		if id != nil && slices.Contains(predeclaredFuncs, id.Name) {
			found = append(found, fset.Position(id.Pos()).String()+" "+id.Name)
		}
	}
	var visit func(n ast.Node) bool
	// fieldTypes walks only the types of a struct's fields or an interface's methods, so
	// the parameters of a method signature are still seen and the names are not.
	fieldTypes := func(list *ast.FieldList) {
		if list == nil {
			return
		}
		for _, fl := range list.List {
			ast.Inspect(fl.Type, visit)
		}
	}
	visit = func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.StructType:
			fieldTypes(x.Fields)
			return false
		case *ast.InterfaceType:
			fieldTypes(x.Methods)
			return false
		case *ast.FuncDecl:
			if x.Recv == nil {
				report(x.Name)
			}
		case *ast.TypeSpec:
			report(x.Name)
		case *ast.Field:
			for _, id := range x.Names {
				report(id)
			}
		case *ast.ValueSpec:
			for _, id := range x.Names {
				report(id)
			}
		case *ast.AssignStmt:
			if x.Tok == token.DEFINE {
				for _, l := range x.Lhs {
					id, _ := l.(*ast.Ident)
					report(id)
				}
			}
		case *ast.RangeStmt:
			if x.Tok == token.DEFINE {
				id, _ := x.Key.(*ast.Ident)
				report(id)
				id, _ = x.Value.(*ast.Ident)
				report(id)
			}
		}
		return true
	}
	ast.Inspect(f, visit)
	return found
}

func TestNoPredeclaredFunctionIsShadowed(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		files++
		for _, s := range shadowed(fset, f) {
			t.Errorf("%s hides the predeclared function of that name: rename it (limit, most, lo, hi, n)", s)
		}
	}
	// The denominator: a directory read that found nothing would pass.
	if files < 8 {
		t.Fatalf("read %d Go files of internal/sanitize, want at least 8: the guard looked at nothing", files)
	}
}

// The guard must be able to fail: a parameter, a short declaration, a range variable, a var,
// a named result, a func-literal parameter, a top-level function and a type all named like a
// builtin are all seen. A name that only contains one is not, nor is a struct field, an
// interface method or a method: those live in the type's own namespace.
func TestShadowGuardSeesAPlantedShadow(t *testing.T) {
	src := "package p\n" +
		"func f(max int) int { return max }\n" +
		"func g() { min := 1; _ = min }\n" +
		"func h(xs []int) { for _, len := range xs { _ = len } }\n" +
		"func i() { var copy int; _ = copy }\n" +
		"func j(maximum, limit int) int { return maximum + limit }\n" +
		"func k() (max int) { return }\n" +
		"var _ = func(len int) {}\n" +
		"func max(a, b int) int { return a }\n" +
		"type real int\n" +
		"type fieldHolder struct{ len int }\n" +
		"type methodHolder interface{ close() }\n" +
		"type recvHolder struct{}\n" +
		"func (recvHolder) len() int { return 0 }\n" +
		"type sigHolder interface{ cut(cap int) }\n"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "planted.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := shadowed(fset, f)
	want := []string{"planted.go:2:8 max", "planted.go:3:12 min", "planted.go:4:27 len", "planted.go:5:16 copy",
		"planted.go:7:11 max", "planted.go:8:14 len", "planted.go:9:6 max", "planted.go:10:6 real",
		"planted.go:15:31 cap"}
	if !slices.Equal(got, want) {
		t.Errorf("shadowed = %q, want %q", got, want)
	}
}
