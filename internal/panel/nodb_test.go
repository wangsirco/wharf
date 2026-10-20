package panel

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
)

// These run inside loops over open query results. If any of them (or what they
// call) used the database, concurrent page loads could exhaust the connection pool
// while each waits for one more connection — the panel hung until restarted.
var noDB = []string{"identify", "nameUnknown", "bestProbe", "identifyDevice", "dnsHints", "pveGuest", "countryName", "displayName", "fallbackName"}

func TestHotPathsAvoidDatabase(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || !contains(noDB, fn.Name.Name) {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok {
						if x, ok := sel.X.(*ast.SelectorExpr); ok && x.Sel.Name == "db" {
							t.Errorf("%s uses the database (%s)", fn.Name.Name, fset.Position(sel.Pos()))
						}
						if sel.Sel.Name == "setting" || sel.Sel.Name == "settingInt" {
							t.Errorf("%s reads settings from the database (%s)", fn.Name.Name, fset.Position(sel.Pos()))
						}
					}
					return true
				})
			}
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
