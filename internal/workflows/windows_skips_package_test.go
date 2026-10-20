package workflows

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A test is known by its package and its name. The skip lines of a `go test -v ./...` log
// carry only the name; the package is on the "ok" or "FAIL" line that ends the package's
// output. Compared by name alone, a test that skips in two packages counted once, and a
// skip in the wrong package was accepted for the right one. The cases are canned logs in
// the shape of the real ones, with full import paths, as `go test` prints them.
func TestWindowsSkipCheckKnowsATestByPackageAndName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the check it runs is a POSIX shell script")
	}
	script, err := filepath.Abs("../../scripts/windows-skips.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	const mod = "github.com/example/mod/"
	skip := func(name string) string { return "=== RUN   " + name + "\n--- SKIP: " + name + " (0.00s)\n" }
	end := func(pkg string) string { return "ok  \t" + mod + pkg + "\t0.1s\n" }
	listing := func(lines ...string) string {
		return "<!-- windows-skipped:begin -->\n" + strings.Join(lines, "\n") + "\n<!-- windows-skipped:end -->\n"
	}
	onlyA := write("only-a.md", listing("- `TestSame` (`pkg/a`): a shell script."))
	both := write("both.md", listing("- `TestSame` (`pkg/a`): a shell script.", "- `TestSame` (`pkg/b`): a shell script."))

	for _, c := range []struct {
		name string
		log  string
		doc  string
		exit int
		out  string
	}{
		{"the same name skips in a second package the document does not list it for",
			skip("TestSame") + end("pkg/a") + skip("TestSame") + end("pkg/b"), onlyA, 1, "pkg/b.TestSame skipped"},
		{"the document lists the same name for two packages and it skips in one",
			skip("TestSame") + end("pkg/a"), both, 1, "pkg/b.TestSame, which did not skip"},
		{"the same name skips in both packages the document lists, and counts as two",
			skip("TestSame") + end("pkg/a") + skip("TestSame") + end("pkg/b"), both, 0, "2 tests skipped, exactly the 2"},
		{"a test that skips in the package the document names, with a full import path",
			skip("TestSame") + end("pkg/a"), onlyA, 0, "1 tests skipped, exactly the 1"},
		{"a test that skips in another package than the one listed",
			skip("TestSame") + end("pkg/z"), onlyA, 1, "pkg/z.TestSame skipped"},
		{"a package whose path only ends in the same letters",
			skip("TestSame") + "ok  \t" + mod + "notpkg/a\t0.1s\n", onlyA, 1, "notpkg/a.TestSame skipped"},
		{"a skip in a package that failed",
			skip("TestSame") + "FAIL\t" + mod + "pkg/a\t0.1s\n", onlyA, 0, "1 tests skipped, exactly the 1"},
		{"the same, with CRLF line ends as on Windows",
			strings.ReplaceAll(skip("TestSame")+end("pkg/a"), "\n", "\r\n"), onlyA, 0, "1 tests skipped, exactly the 1"},
		{"a skip that no package line follows (a truncated log)",
			"--- PASS: TestOther (0.00s)\n" + end("pkg/a") + skip("TestSame"), onlyA, 1, "TestSame skipped and no package result line"},
	} {
		out, code := runSkipCheckOut(t, script, write("log.txt", c.log), c.doc)
		if code != c.exit {
			t.Errorf("%s: exit %d, want %d; output:\n%s", c.name, code, c.exit, out)
		}
		if !strings.Contains(out, c.out) {
			t.Errorf("%s: output lacks %q:\n%s", c.name, c.out, out)
		}
	}
}

// runSkipCheckOut is runSkipCheck with the output first.
func runSkipCheckOut(t *testing.T, script, log, doc string) (string, int) {
	t.Helper()
	code, out := runSkipCheck(t, script, log, doc)
	return out, code
}
