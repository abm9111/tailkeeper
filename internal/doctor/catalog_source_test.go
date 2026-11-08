package doctor

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Doctor reads the catalog and the intent file by the code a scan does (tools.ScanCatalogSummary
// and tools.ConfiguredIntentSummary), so that the two cannot disagree about which catalog or
// which file they speak of. The test holds the package to it at the source: no file of it opens
// the advisory files, and none reads the configured invariants path itself.
func TestDoctorReadsTheCatalogAndTheIntentThroughTheScansOwnCode(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files: %v", err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		checked++
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range parsed.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if strings.HasSuffix(path, "/internal/advisory") || strings.HasSuffix(path, "/data/advisories") {
				t.Errorf("%s imports %s: the catalog is read through tools.ScanCatalogSummary, which is the scan's own", f, path)
			}
		}
		if strings.Contains(string(src), "InvariantsFile") {
			t.Errorf("%s reads the invariants path itself: the intent is read through tools.ConfiguredIntentSummary, which is the scan's own", f)
		}
	}
	if checked < 3 {
		t.Fatalf("checked %d files: the walk found too little to judge", checked)
	}
	// And the file that does read them calls those two functions.
	src, err := os.ReadFile("doctor.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{"tools.ScanCatalogSummary(", "tools.ConfiguredIntentSummary("} {
		if !strings.Contains(string(src), call) {
			t.Errorf("doctor.go does not call %s", call)
		}
	}
}
