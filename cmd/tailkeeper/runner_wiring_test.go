package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The command line reads standard input for a flag such as --from -, and the
// runner it runs reads that from its Stdin field: a runner built without it reads
// an empty input and the flag silently gets nothing. main builds the runner in one
// literal, so the literal is what is checked.
func TestMainGivesTheRunnerTheRealStandardInput(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if sel, ok := lit.Type.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Runner" {
			return true
		}
		for _, e := range lit.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, _ := kv.Key.(*ast.Ident)
			if sel, ok := kv.Value.(*ast.SelectorExpr); ok && key != nil {
				if pkg, ok := sel.X.(*ast.Ident); ok {
					fields[key.Name] = pkg.Name + "." + sel.Sel.Name
				}
			}
		}
		return false
	})
	for field, want := range map[string]string{"Stdin": "os.Stdin", "Stdout": "os.Stdout", "Stderr": "os.Stderr"} {
		if fields[field] != want {
			t.Errorf("the runner's %s is %q, want %q", field, fields[field], want)
		}
	}
}
