package tools

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/safefile"
)

// An array length must not be negative, so each pair below stops this package's tests from
// compiling when one of the three caps drifts from guard.MaxPolicyBytes in either direction.
var (
	_ [acl.MaxBytes - guard.MaxPolicyBytes]struct{}
	_ [guard.MaxPolicyBytes - acl.MaxBytes]struct{}
	_ [safefile.MaxBytes - guard.MaxPolicyBytes]struct{}
	_ [guard.MaxPolicyBytes - safefile.MaxBytes]struct{}
	_ [maxPolicyPage - guard.MaxPolicyBytes]struct{}
	_ [guard.MaxPolicyBytes - maxPolicyPage]struct{}
)

// policyCap is 4 MiB, the size every policy cap shares.
const policyCap = 4194304

// constInt evaluates an integer written as literals, parentheses, "<<" and "*", the ways a
// size is spelled. ok is false for anything else.
func constInt(e ast.Expr) (v int64, ok bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.INT {
			return 0, false
		}
		n, err := strconv.ParseInt(x.Value, 0, 64)
		return n, err == nil
	case *ast.ParenExpr:
		return constInt(x.X)
	case *ast.BinaryExpr:
		a, okA := constInt(x.X)
		b, okB := constInt(x.Y)
		if !okA || !okB {
			return 0, false
		}
		switch x.Op {
		case token.SHL:
			if b < 0 || b > 40 {
				return 0, false
			}
			return a << b, true
		case token.MUL:
			return a * b, true
		}
	}
	return 0, false
}

// policyCapSpellings lists the places a file writes the policy cap: an integer expression
// that comes to 4 MiB, or a string that holds the number 4194304. A struct tag is a string
// that cannot be computed; TestTheSchemaNamesThePolicyCap holds the one that names the cap.
func policyCapSpellings(fset *token.FileSet, f *ast.File) []string {
	tags := map[ast.Node]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if fld, ok := n.(*ast.Field); ok && fld.Tag != nil {
			tags[fld.Tag] = true
		}
		return true
	})
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BinaryExpr:
			if v, ok := constInt(x); ok && v == policyCap {
				out = append(out, fset.Position(n.Pos()).String())
			}
		case *ast.BasicLit:
			if v, ok := constInt(x); ok && v == policyCap {
				out = append(out, fset.Position(n.Pos()).String())
			}
			if x.Kind == token.STRING && !tags[x] && strings.Contains(x.Value, strconv.Itoa(policyCap)) {
				out = append(out, fset.Position(n.Pos()).String())
			}
		}
		return true
	})
	return out
}

// spellingsIn parses the non-test Go files of dir and lists their policy-cap spellings.
func spellingsIn(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no Go files in %s (%v)", dir, err)
	}
	var out []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, policyCapSpellings(fset, f)...)
	}
	return out
}

// The detector first: a file that spells the cap in each way it can be spelled is found, a
// file that spells other sizes is not.
func TestThePolicyCapDetectorFindsEverySpelling(t *testing.T) {
	const planted = `package p

const (
	a = 4 << 20
	b = 1 << 22
	c = 4 * 1024 * 1024
	d = (2 << 20) * 2
	e = 4194304
)

var f = "limit 4194304"
var g = ` + "`" + `{"maxBytes":4194304}` + "`" + `

type T struct {
	N int ` + "`" + `jsonschema:"1 to 4194304"` + "`" + `
}
`
	const other = `package p

const (
	a = 64 << 20
	b = 3 << 20
	c = 150 << 10
	d = "limit 41943"
)
`
	count := func(src string) int {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "p.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return len(policyCapSpellings(fset, f))
	}
	if got := count(planted); got != 7 {
		t.Errorf("the planted file has 7 spellings, the detector found %d", got)
	}
	if got := count(other); got != 0 {
		t.Errorf("a file of other sizes has %d spellings, want 0", got)
	}
}

// One 4 MiB for every policy: the engine, the file reader and the page of acl_get take their
// cap from internal/guard, and no other file of those packages (or of the doctor, which asks
// acl_get for the largest page) spells it. The other 4 MiB caps of the repository (the audit
// line, a local command's output) are different quantities and are not scanned.
func TestThePolicyCapIsDefinedOnce(t *testing.T) {
	if guard.MaxPolicyBytes != policyCap {
		t.Errorf("guard.MaxPolicyBytes = %d, want %d", guard.MaxPolicyBytes, policyCap)
	}
	if acl.MaxBytes != guard.MaxPolicyBytes || safefile.MaxBytes != guard.MaxPolicyBytes || maxPolicyPage != guard.MaxPolicyBytes {
		t.Errorf("caps: acl %d, safefile %d, the page %d; want %d each", acl.MaxBytes, safefile.MaxBytes, maxPolicyPage, guard.MaxPolicyBytes)
	}
	if got := spellingsIn(t, filepath.Join("..", "guard")); len(got) != 1 {
		t.Errorf("internal/guard spells the cap %d times, want once: %v", len(got), got)
	}
	for _, pkg := range []string{"acl", "safefile", "tools", "doctor"} {
		if got := spellingsIn(t, filepath.Join("..", pkg)); len(got) != 0 {
			t.Errorf("internal/%s spells the policy cap itself; use guard.MaxPolicyBytes: %v", pkg, got)
		}
	}
}

// The one place the number has to be written as text is the description of acl_get's maxBytes,
// a struct tag. It must say the cap that is in force.
func TestTheSchemaNamesThePolicyCap(t *testing.T) {
	f, ok := reflect.TypeOf(ACLGetInput{}).FieldByName("MaxBytes")
	if !ok {
		t.Fatal("ACLGetInput has no MaxBytes")
	}
	if tag := f.Tag.Get("jsonschema"); !strings.Contains(tag, "to "+strconv.Itoa(guard.MaxPolicyBytes)) {
		t.Errorf("the description of maxBytes does not name the cap %d: %q", guard.MaxPolicyBytes, tag)
	}
}
