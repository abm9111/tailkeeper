package workflows

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const windowsDoc = "../../docs/windows.md"

// listLine is one line of a list in docs/windows.md: the test, its package, the reason.
var listLine = regexp.MustCompile("^- `([^`]+)` \\(`([^`]+)`\\): (.+)\\.$")

// windowsList reads the list of docs/windows.md between its two markers: test name to
// package. It fails on a missing or doubled marker, a line that is not a list line,
// and a name listed twice, so a list that matched nothing cannot read as a list.
func windowsList(t *testing.T, doc, name string) map[string]string {
	t.Helper()
	begin, end := "<!-- "+name+":begin -->", "<!-- "+name+":end -->"
	if strings.Count(doc, begin) != 1 || strings.Count(doc, end) != 1 {
		t.Fatalf("docs/windows.md must have exactly one %s and one %s", begin, end)
	}
	start := strings.Index(doc, begin) + len(begin)
	stop := strings.Index(doc, end)
	if stop < start {
		t.Fatalf("docs/windows.md: %s comes before %s", end, begin)
	}
	list := map[string]string{}
	for _, line := range strings.Split(doc[start:stop], "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		m := listLine.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("docs/windows.md, %s: not a list line of the form \"- `Test` (`package`): reason.\": %q", name, line)
		}
		if _, dup := list[m[1]]; dup {
			t.Fatalf("docs/windows.md, %s: %s is listed twice", name, m[1])
		}
		list[m[1]] = m[2]
	}
	if len(list) == 0 {
		t.Fatalf("docs/windows.md, %s: the list is empty", name)
	}
	return list
}

// testFunc is a test or fuzz target in a _test.go file, at the start of a line.
var testFunc = regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)\w*)\(`)

// declaredTests maps every test and fuzz target under root's cmd and internal to its
// package (slash-separated, from root), split by whether the Go tool compiles its file for
// windows/amd64. The build constraints are read by go/build with GOOS=windows, so a file
// that leaves Windows by any of its ways is found: a "//go:build !windows", "unix" or
// "linux || darwin" line, or a file name that ends in a system's name (_linux_test.go,
// _darwin_test.go). Such a file is not compiled there, and no run on Windows can show its
// tests missing.
func declaredTests(t *testing.T, root string) (windows, notWindows map[string]string) {
	t.Helper()
	windows, notWindows = map[string]string{}, map[string]string{}
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = "windows", "amd64", false
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(dir string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return err
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				return err
			}
			var all []string
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), "_test.go") {
					all = append(all, e.Name())
				}
			}
			if len(all) == 0 {
				return nil
			}
			// A directory whose files are all left out of the build is a NoGoError that still
			// says which files were left in, which is none.
			pkg, err := ctx.ImportDir(dir, 0)
			var noGo *build.NoGoError
			if err != nil && !errors.As(err, &noGo) {
				return err
			}
			compiled := map[string]bool{}
			for _, f := range append(append([]string{}, pkg.TestGoFiles...), pkg.XTestGoFiles...) {
				compiled[f] = true
			}
			rel, err := filepath.Rel(root, dir)
			if err != nil {
				return err
			}
			for _, f := range all {
				data, err := os.ReadFile(filepath.Join(dir, f))
				if err != nil {
					return err
				}
				dst := notWindows
				if compiled[f] {
					dst = windows
				}
				for _, m := range testFunc.FindAllStringSubmatch(string(data), -1) {
					dst[m[1]] = filepath.ToSlash(rel)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return windows, notWindows
}

// windowsDocProblems compares docs/windows.md's two lists with the tests found by
// declaredTests, and returns what differs.
func windowsDocProblems(skipped, excluded, onWindows, notOnWindows map[string]string) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	for name, pkg := range notOnWindows {
		if got, ok := excluded[name]; !ok {
			add("%s (%s) is in a test file that is not compiled for Windows and docs/windows.md does not list it as not compiled on Windows", name, pkg)
		} else if got != pkg {
			add("%s: docs/windows.md says package %s, it is in %s", name, got, pkg)
		}
	}
	for name, pkg := range excluded {
		if got, ok := notOnWindows[name]; !ok {
			add("docs/windows.md lists %s (%s) as not compiled on Windows, but no test file left out of the Windows build declares it", name, pkg)
		} else if got != pkg {
			add("%s: docs/windows.md says package %s, it is in %s", name, pkg, got)
		}
	}
	for name, pkg := range skipped {
		if _, both := excluded[name]; both {
			add("%s is listed both as skipped and as not compiled on Windows", name)
		}
		if got, ok := onWindows[name]; !ok {
			add("docs/windows.md lists %s (%s) as skipped on Windows, but no test file compiled there declares it", name, pkg)
		} else if got != pkg {
			add("%s: docs/windows.md says package %s, it is in %s", name, pkg, got)
		}
	}
	sort.Strings(out)
	return out
}

// docs/windows.md says which tests do not run on Windows, and the Windows job holds the
// first of its two lists true (scripts/windows-skips.sh). The second list is held true
// here: a test file that the Go tool leaves out of the Windows build (any build
// constraint or file-name suffix that excludes windows/amd64) is not compiled there, so
// no run there can show its tests missing, and a test added to one, or moved out of one,
// must change the list. Every test of the first list must exist, in the package the list
// names, in a file that is compiled on Windows (a skip in a file that is not could
// never report), and no test is in both lists.
func TestWindowsDocListsEveryTestThatDoesNotRunThere(t *testing.T) {
	data, err := os.ReadFile(windowsDoc)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	skipped := windowsList(t, doc, "windows-skipped")
	excluded := windowsList(t, doc, "windows-excluded")
	onWindows, notOnWindows := declaredTests(t, "../..")

	if len(notOnWindows) < 20 || len(onWindows) < 500 {
		t.Fatalf("found %d tests compiled out and %d compiled on Windows: the walk found too little to judge", len(notOnWindows), len(onWindows))
	}
	for _, problem := range windowsDocProblems(skipped, excluded, onWindows, notOnWindows) {
		t.Error(problem)
	}
}

// The ways a test file leaves the Windows build are all found, not only the exact line
// "//go:build !windows": a file named _linux_test.go, a "//go:build unix" file and one that
// names the systems it is for ("linux || darwin") disappeared from Windows unlisted. A copy
// of the tree's shape holds one of each, one that stays (plain, and one for Windows only),
// and a document that lists none of them.
func TestTheWindowsListSeesEveryWayAFileLeavesWindows(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"plain_test.go":       "package x\n\nfunc TestPlain(t *testing.T) {}\n",
		"winonly_test.go":     "//go:build windows\n\npackage x\n\nfunc TestWindowsOnly(t *testing.T) {}\n",
		"name_linux_test.go":  "package x\n\nfunc TestLinuxSuffix(t *testing.T) {}\n",
		"unixtag_test.go":     "//go:build unix\n\npackage x\n\nfunc TestUnixTag(t *testing.T) {}\n",
		"bang_test.go":        "//go:build !windows\n\npackage x\n\nfunc TestBang(t *testing.T) {}\n",
		"either_test.go":      "//go:build linux || darwin\n\npackage x\n\nfunc TestEither(t *testing.T) {}\n",
		"fuzz_darwin_test.go": "package x\n\nfunc FuzzDarwinSuffix(f *testing.F) {}\n",
	}
	dir := filepath.Join(root, "internal", "x")
	if err := os.MkdirAll(dir, 0o750); err != nil || os.Mkdir(filepath.Join(root, "cmd"), 0o750) != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	onWindows, notOnWindows := declaredTests(t, root)
	for _, name := range []string{"TestPlain", "TestWindowsOnly"} {
		if onWindows[name] != "internal/x" {
			t.Errorf("%s is compiled for Windows and was not found there: %v", name, onWindows)
		}
	}
	for _, name := range []string{"TestLinuxSuffix", "TestUnixTag", "TestBang", "TestEither", "FuzzDarwinSuffix"} {
		if notOnWindows[name] != "internal/x" {
			t.Errorf("%s leaves the Windows build and was not found: %v", name, notOnWindows)
		}
	}
	problems := strings.Join(windowsDocProblems(map[string]string{}, map[string]string{}, onWindows, notOnWindows), "\n")
	for _, name := range []string{"TestLinuxSuffix", "TestUnixTag", "TestBang", "TestEither", "FuzzDarwinSuffix"} {
		if !strings.Contains(problems, name+" (internal/x)") {
			t.Errorf("a document that lists nothing is not refused for %s:\n%s", name, problems)
		}
	}
}

// runSkipCheck runs scripts/windows-skips.sh and returns its exit status and output.
func runSkipCheck(t *testing.T, script, log, doc string) (int, string) {
	t.Helper()
	out, err := exec.Command("sh", script, log, doc).CombinedOutput()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		return ee.ExitCode(), string(out)
	case err != nil:
		t.Fatal(err)
	}
	return 0, string(out)
}

// TestWindowsSkipCheckJudgesALog runs scripts/windows-skips.sh, which the Windows job
// uses to compare its skipped tests with docs/windows.md, against canned logs: it must
// accept the exact set, refuse a test that skipped without being listed and one listed
// that did not skip, and refuse a missing log, a log with no result, and a document with
// no list. Each refusal names the test or the reason.
func TestWindowsSkipCheckJudgesALog(t *testing.T) {
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
	const doc = "# Windows\n\n<!-- windows-skipped:begin -->\n" +
		"- `TestOne` (`pkg/a`): a shell script.\n" +
		"- `TestTwo` (`pkg/b`): no strict mode.\n" +
		"<!-- windows-skipped:end -->\n\n<!-- windows-excluded:begin -->\n- `TestThree` (`pkg/c`): not compiled.\n<!-- windows-excluded:end -->\n"
	const pass = "=== RUN   TestPassing\n--- PASS: TestPassing (0.00s)\n"
	// The log names a skip's package only on the "ok" line that ends the package's output.
	const one = "=== RUN   TestOne\n    a_test.go:9: a shell script\n--- SKIP: TestOne (0.00s)\nok  \tgithub.com/example/mod/pkg/a\t0.1s\n"
	const two = "=== RUN   TestTwo\n--- SKIP: TestTwo (0.00s)\nok  \tgithub.com/example/mod/pkg/b\t0.1s\n"
	docPath := write("doc.md", doc)

	for _, c := range []struct {
		name string
		log  string
		doc  string
		exit int
		out  string
	}{
		{"exactly the listed tests", pass + one + two + "ok  \tpkg/a\t0.1s\n", docPath, 0, "2 tests skipped, exactly the 2"},
		{"the same, with CRLF line ends as on Windows", strings.ReplaceAll(pass+one+two, "\n", "\r\n"), docPath, 0, "2 tests skipped, exactly the 2"},
		{"a skip line with no duration and a CR, as a stripped CR leaves \"TestOne\\r\"", strings.ReplaceAll("--- PASS: TestPassing (0.00s)\n--- SKIP: TestOne\nok  \tpkg/a\t0.1s\n--- SKIP: TestTwo\nok  \tpkg/b\t0.1s\n", "\n", "\r\n"), docPath, 0, "2 tests skipped, exactly the 2"},
		{"a document with CRLF line ends, whose markers are only found without the CR", pass + one + two, write("crlf.md", strings.ReplaceAll(doc, "\n", "\r\n")), 0, "2 tests skipped, exactly the 2"},
		{"a subtest skip alone is a skip, not the test", pass + one + two + "    --- SKIP: TestTwo/sub (0.00s)\nok  \tpkg/b\t0.1s\n", docPath, 1, "TestTwo/sub skipped"},
		{"a test skipped that is not listed", pass + one + two + "--- SKIP: TestNew (0.00s)\nok  \tpkg/c\t0.1s\n", docPath, 1, "TestNew skipped and"},
		{"a listed test did not skip", pass + one, docPath, 1, "TestTwo, which did not skip"},
		{"a listed test passed", pass + one + "--- PASS: TestTwo (0.00s)\n", docPath, 1, "TestTwo, which did not skip"},
		{"nothing skipped, so the whole list is wrong", pass, docPath, 1, "TestOne, which did not skip"},
		{"a log with no result", "go: downloading something\n", docPath, 1, "no test result"},
		{"an empty log", "", docPath, 1, "no test result"},
		{"a document without its markers", pass + one + two, write("nomarkers.md", "# Windows\n- `TestOne` (`pkg/a`): x.\n"), 1, "exactly one windows-skipped:begin"},
		{"a document with an empty list", pass + one + two, write("empty.md", "<!-- windows-skipped:begin -->\n<!-- windows-skipped:end -->\n"), 1, "lists no skipped test"},
		{"an empty document", pass + one + two, write("blank.md", ""), 1, "exactly one windows-skipped:begin"},
	} {
		code, out := runSkipCheck(t, script, write("log.txt", c.log), c.doc)
		if code != c.exit {
			t.Errorf("%s: exit %d, want %d; output:\n%s", c.name, code, c.exit, out)
		}
		if !strings.Contains(out, c.out) {
			t.Errorf("%s: output lacks %q:\n%s", c.name, c.out, out)
		}
	}
	// A log or a document that does not exist is not a pass.
	if code, out := runSkipCheck(t, script, filepath.Join(dir, "absent.log"), docPath); code != 1 || !strings.Contains(out, "no test log") {
		t.Errorf("a missing log: exit %d, output %q", code, out)
	}
	if code, out := runSkipCheck(t, script, write("log.txt", pass+one+two), filepath.Join(dir, "absent.md")); code != 1 || !strings.Contains(out, "no document") {
		t.Errorf("a missing document: exit %d, output %q", code, out)
	}

	// The real document: a log in which exactly its listed tests skip is accepted, and
	// the same log with one more skip, or with one fewer, is not. This is the parse of
	// docs/windows.md itself, not of a canned one.
	real, err := os.ReadFile(windowsDoc)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0)
	for name := range windowsList(t, string(real), "windows-skipped") {
		names = append(names, name)
	}
	sort.Strings(names)
	// Each package's skips, then the "ok" line that ends the package.
	listed := windowsList(t, string(real), "windows-skipped")
	byPkg := map[string][]string{}
	for _, name := range names {
		byPkg[listed[name]] = append(byPkg[listed[name]], name)
	}
	pkgs := make([]string, 0, len(byPkg))
	for pkg := range byPkg {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)
	var log strings.Builder
	log.WriteString(pass)
	for _, pkg := range pkgs {
		for _, name := range byPkg[pkg] {
			log.WriteString("--- SKIP: " + name + " (0.00s)\n")
		}
		log.WriteString("ok  \tgithub.com/abm9111/tailkeeper/" + pkg + "\t0.1s\n")
	}
	realDoc, err := filepath.Abs(windowsDoc)
	if err != nil {
		t.Fatal(err)
	}
	if code, out := runSkipCheck(t, script, write("real.txt", log.String()), realDoc); code != 0 {
		t.Errorf("the real list, all skipped: exit %d:\n%s", code, out)
	}
	if code, out := runSkipCheck(t, script, write("real-extra.txt", log.String()+"--- SKIP: TestUnlistedExtra (0.00s)\nok  \tgithub.com/abm9111/tailkeeper/internal/app\t0.1s\n"), realDoc); code != 1 || !strings.Contains(out, "TestUnlistedExtra skipped") {
		t.Errorf("the real list plus an extra skip: exit %d:\n%s", code, out)
	}
	dropped := strings.Replace(log.String(), "--- SKIP: "+names[0]+" (0.00s)\n", "", 1)
	if code, out := runSkipCheck(t, script, write("real-fewer.txt", dropped), realDoc); code != 1 || !strings.Contains(out, names[0]+", which did not skip") {
		t.Errorf("the real list minus %s: exit %d:\n%s", names[0], code, out)
	}
}

type matrix struct {
	OS []string `yaml:"os"`
}

type strategy struct {
	Matrix matrix `yaml:"matrix"`
}

type verifyJob struct {
	Strategy strategy `yaml:"strategy"`
	Steps    []step   `yaml:"steps"`
	RunsOn   string   `yaml:"runs-on"`
}

type verifyWorkflow struct {
	Jobs map[string]verifyJob `yaml:"jobs"`
}

// The comparison is only worth its script if the Windows job runs it, on the log the
// tests wrote, against the document, and whatever the test step did: a step that was
// skipped, or read another file, or whose failure ended in "no skipped tests", would
// leave the list unchecked and look green.
func TestTheWindowsJobComparesItsSkipsWithTheDocument(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/verify.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf verifyWorkflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatal(err)
	}
	job, ok := wf.Jobs["test-os"]
	if !ok {
		t.Fatal("verify.yml has no test-os job")
	}
	if !contains(job.Strategy.Matrix.OS, "windows-2025") {
		t.Fatalf("test-os runs on %v, not on windows-2025", job.Strategy.Matrix.OS)
	}
	const log = `"$RUNNER_TEMP/test.log"`
	var tests, compare []step
	for _, s := range job.Steps {
		switch {
		case strings.Contains(s.Run, "go test") && strings.Contains(s.Run, "tee "+log):
			tests = append(tests, s)
		case strings.Contains(s.Run, "windows-skips.sh"):
			compare = append(compare, s)
		}
	}
	if len(tests) != 1 {
		t.Fatalf("test-os has %d steps that run go test and tee %s, want 1", len(tests), log)
	}
	if len(compare) != 1 {
		t.Fatalf("test-os has %d steps that run windows-skips.sh, want 1", len(compare))
	}
	c := compare[0]
	if !strings.Contains(c.Run, "scripts/windows-skips.sh "+log+" docs/windows.md") {
		t.Errorf("the comparison runs %q: it must pass the log the test step wrote (%s) and docs/windows.md", c.Run, log)
	}
	// The script is run by bash (Git Bash on Windows): the default shell there is PowerShell.
	if c.Shell != "bash" {
		t.Errorf("the comparison's shell is %q, want bash", c.Shell)
	}
	// The Windows job gets a longer go test limit than the others: the growth guard is slow
	// on its clock, and a timeout would end the package with no word about the guard.
	if !strings.Contains(tests[0].Run, `-timeout "$timeout"`) || !strings.Contains(tests[0].Run, "timeout=900s") || !strings.Contains(tests[0].Run, "[ \"$RUNNER_OS\" = Windows ]") {
		t.Errorf("the test step does not give the Windows leg a 900s go test timeout: %q", tests[0].Run)
	}
	// always(): the comparison still runs when the tests failed, and then reports the skips too.
	if !strings.Contains(c.If, "always()") || !strings.Contains(c.If, "runner.os == 'Windows'") {
		t.Errorf("the comparison's condition is %q, want always() and the Windows runner", c.If)
	}
	// Anything after the script that could turn its failure into a pass.
	for _, bad := range []string{"||", "|", ";", "&&", "set +e"} {
		if strings.Contains(c.Run, bad) {
			t.Errorf("the comparison's command %q holds %q, which could hide its exit status", c.Run, bad)
		}
	}
	// The listing for the other leg must fail on a missing log too, not read as "no skipped tests".
	for _, s := range job.Steps {
		if strings.Contains(s.Run, "--- SKIP") && !strings.Contains(s.Run, "-f "+log) {
			t.Errorf("step %q lists skipped tests without checking that the log exists", s.Name)
		}
		if strings.Contains(s.Run, `\s`) {
			t.Errorf("step %q uses \\s in a pattern, which not every grep reads", s.Name)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// skipFacts is what one function of a _test.go file does about skipping, found without
// running it: whether it skips on Windows (a t.Skip, t.Skipf or t.SkipNow under an
// "if runtime.GOOS == \"windows\"" or one of the named predicates below) and whether it
// skips at all, each directly or through a helper of the same package that it calls.
type skipFacts struct {
	windows, any bool
	callees      []string
}

// windowsPredicates are conditions other than runtime.GOOS that are true only on
// Windows in this tree: audit.RotateSupported() is false only there. A skip under
// "!audit.RotateSupported()" is a Windows skip.
var windowsPredicates = []string{"RotateSupported"}

// windowsSkipHelpers are helpers that skip for a reason that is a Windows one but is not
// written as a test of the platform: controlCharDir skips when the file system refuses a
// control character in a name, which Windows does. A renamed helper shows as listed
// tests that no longer skip on Windows.
var windowsSkipHelpers = []string{"controlCharDir"}

// isWindowsCondition reports whether an if condition names Windows: runtime.GOOS ==
// "windows" anywhere in it, or a call of one of windowsPredicates.
func isWindowsCondition(cond ast.Expr) bool {
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BinaryExpr:
			if n.Op != token.EQL {
				return true
			}
			for _, pair := range [][2]ast.Expr{{n.X, n.Y}, {n.Y, n.X}} {
				sel, isSel := pair[0].(*ast.SelectorExpr)
				lit, isLit := pair[1].(*ast.BasicLit)
				if !isSel || !isLit {
					continue
				}
				if pkg, isID := sel.X.(*ast.Ident); isID && pkg.Name == "runtime" && sel.Sel.Name == "GOOS" && lit.Value == `"windows"` {
					found = true
				}
			}
		case *ast.CallExpr:
			if sel, isSel := n.Fun.(*ast.SelectorExpr); isSel {
				for _, p := range windowsPredicates {
					if sel.Sel.Name == p {
						found = true
					}
				}
			}
		}
		return true
	})
	return found
}

// isSkipCall reports whether n is a call of a method named Skip, Skipf or SkipNow.
func isSkipCall(n ast.Node) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && (sel.Sel.Name == "Skip" || sel.Sel.Name == "Skipf" || sel.Sel.Name == "SkipNow")
}

// scanSkips reads one function body. A function literal is not entered: a skip inside a
// t.Run closure skips the subtest, which the Windows job reports as "Test/sub", not as the
// test, so it does not make the test a skipped one.
func scanSkips(body *ast.BlockStmt) skipFacts {
	var f skipFacts
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.IfStmt:
			if isWindowsCondition(n.Cond) {
				ast.Inspect(n.Body, func(m ast.Node) bool {
					if _, lit := m.(*ast.FuncLit); lit {
						return false
					}
					if isSkipCall(m) {
						f.windows = true
					}
					return true
				})
			}
		case *ast.CallExpr:
			if isSkipCall(n) {
				f.any = true
			}
			if id, ok := n.Fun.(*ast.Ident); ok {
				f.callees = append(f.callees, id.Name)
			}
		}
		return true
	})
	return f
}

// skippingTests parses every _test.go file under root's cmd and internal (whatever its
// build constraints) and returns, keyed "package.Test" with the package slash-separated
// from root, the tests that skip on Windows and the tests that skip at all, each directly
// or through a helper function of the same directory (any depth). The forms that occur in
// the tree are: an "if runtime.GOOS == \"windows\" { t.Skip(...) }" in the test or in a
// helper (stubBinary, newFakeCLI, fakeCLI), "if !audit.RotateSupported() { t.Skip(...) }",
// the helper controlCharDir, and the unconditional-on-Windows skips for a missing
// environment variable (liveOnly, the OpenAPI comparison). A skip written some other way
// is not found; the Windows job then reports it and the list must name it.
func skippingTests(t *testing.T, root string) (onWindows, anywhere map[string]bool) {
	t.Helper()
	onWindows, anywhere = map[string]bool{}, map[string]bool{}
	fset := token.NewFileSet()
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(dir string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return err
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				return err
			}
			facts := map[string]*skipFacts{}
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
					continue
				}
				file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
				if err != nil {
					return err
				}
				for _, decl := range file.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if !ok || fn.Recv != nil || fn.Body == nil {
						continue
					}
					f := scanSkips(fn.Body)
					facts[fn.Name.Name] = &f
				}
			}
			if len(facts) == 0 {
				return nil
			}
			for _, name := range windowsSkipHelpers {
				if f, ok := facts[name]; ok && f.any {
					f.windows = true
				}
			}
			for changed := true; changed; {
				changed = false
				for _, f := range facts {
					for _, c := range f.callees {
						if g, ok := facts[c]; ok {
							if g.windows && !f.windows {
								f.windows, changed = true, true
							}
							if g.any && !f.any {
								f.any, changed = true, true
							}
						}
					}
				}
			}
			rel, err := filepath.Rel(root, dir)
			if err != nil {
				return err
			}
			for name, f := range facts {
				if !strings.HasPrefix(name, "Test") && !strings.HasPrefix(name, "Fuzz") {
					continue
				}
				key := filepath.ToSlash(rel) + "." + name
				if f.windows {
					onWindows[key] = true
				}
				if f.any {
					anywhere[key] = true
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return onWindows, anywhere
}

// windowsReasons maps each listed test's name to the reason on its line of the document.
func windowsReasons(doc string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(doc, "\n") {
		if m := listLine.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			out[m[1]] = m[3]
		}
	}
	return out
}

// skipListProblems compares docs/windows.md's list of skipped tests with the tests found
// to skip. A line whose reason says the test is "skipped on every platform" is not a
// Windows skip: it must exist and skip somewhere. Every other line must be a test that
// skips on Windows, and every test that skips on Windows must have its line.
func skipListProblems(skipped, reasons map[string]string, onWindows, anywhere map[string]bool) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	listed := map[string]bool{}
	for name, pkg := range skipped {
		key := pkg + "." + name
		if strings.Contains(reasons[name], "skipped on every platform") {
			if !anywhere[key] {
				add("docs/windows.md lists %s (%s) as skipped on every platform, but no skip call was found in it", name, pkg)
			}
			continue
		}
		listed[key] = true
		if !onWindows[key] {
			add("docs/windows.md lists %s (%s) as skipped on Windows, but it has no skip under a test for Windows", name, pkg)
		}
	}
	for key := range onWindows {
		if !listed[key] {
			add("%s skips on Windows and docs/windows.md does not list it", key)
		}
	}
	sort.Strings(out)
	return out
}

// The Windows job compares the tests that report SKIP with the list, and fails on a
// difference; the Linux gate could not see that, and a skipping test added without its
// line failed only on the first Windows run. This reads the same fact from the source:
// every test whose body (or a helper it calls) skips under a test of the platform is on
// the list, and every listed test, but those the list says skip on every platform, is one.
func TestWindowsDocListsEveryTestThatSkipsThere(t *testing.T) {
	data, err := os.ReadFile(windowsDoc)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	skipped := windowsList(t, doc, "windows-skipped")
	onWindows, anywhere := skippingTests(t, "../..")
	if len(onWindows) < 50 || len(anywhere) < len(onWindows) {
		t.Fatalf("found %d tests that skip on Windows and %d that skip at all: the walk found too little to judge", len(onWindows), len(anywhere))
	}
	for _, problem := range skipListProblems(skipped, windowsReasons(doc), onWindows, anywhere) {
		t.Error(problem)
	}
}

// The reader is held to the forms it claims: a skip in the test, in a helper, behind a
// named predicate, in a closure (which skips only a subtest and so does not count), and a
// skip that is not for Windows.
func TestTheSkipReaderSeesEachWayATestSkipsOnWindows(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "internal", "x")
	if err := os.MkdirAll(dir, 0o750); err != nil || os.Mkdir(filepath.Join(root, "cmd"), 0o750) != nil {
		t.Fatal(err)
	}
	src := `package x

import ("runtime"; "testing")

func helper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script")
	}
}
func outer(t *testing.T) { helper(t) }
func controlCharDir(t *testing.T) { t.Skip("refused") }

func TestDirect(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("direct")
	}
}
func TestViaHelper(t *testing.T) { outer(t) }
func TestViaNamedHelper(t *testing.T) { controlCharDir(t) }
func TestNamedPredicate(t *testing.T) {
	if !audit.RotateSupported() {
		t.SkipNow()
	}
}
func TestOnlyInASubtest(t *testing.T) {
	t.Run("a", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("subtest")
		}
	})
}
func TestNotWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("not here")
	}
	if os.Getenv("X") == "" {
		t.Skip("env")
	}
}
func TestNeverSkips(t *testing.T) {}
`
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	onWindows, anywhere := skippingTests(t, root)
	for _, name := range []string{"TestDirect", "TestViaHelper", "TestViaNamedHelper", "TestNamedPredicate"} {
		if !onWindows["internal/x."+name] {
			t.Errorf("%s skips on Windows and was not found: %v", name, onWindows)
		}
	}
	for _, name := range []string{"TestOnlyInASubtest", "TestNotWindows", "TestNeverSkips"} {
		if onWindows["internal/x."+name] {
			t.Errorf("%s does not skip on Windows and was found: %v", name, onWindows)
		}
	}
	if !anywhere["internal/x.TestNotWindows"] || anywhere["internal/x.TestNeverSkips"] {
		t.Errorf("the tests that skip at all are wrong: %v", anywhere)
	}
	// And the comparison: a list that misses TestDirect, lists TestNeverSkips as a Windows
	// skip, and marks TestNeverSkips as skipping everywhere, is refused each way.
	problems := strings.Join(skipListProblems(
		map[string]string{"TestNeverSkips": "internal/x", "TestViaHelper": "internal/x"},
		map[string]string{"TestNeverSkips": "x", "TestViaHelper": "x"},
		onWindows, anywhere), "\n")
	for _, want := range []string{"internal/x.TestDirect skips on Windows and docs/windows.md does not list it", "lists TestNeverSkips (internal/x) as skipped on Windows"} {
		if !strings.Contains(problems, want) {
			t.Errorf("problems lack %q:\n%s", want, problems)
		}
	}
	every := strings.Join(skipListProblems(
		map[string]string{"TestNeverSkips": "internal/x"},
		map[string]string{"TestNeverSkips": "reads a tailnet; skipped on every platform unless asked"},
		onWindows, anywhere), "\n")
	if !strings.Contains(every, "lists TestNeverSkips (internal/x) as skipped on every platform, but no skip call was found") {
		t.Errorf("a test that never skips, listed as skipping everywhere, is not refused:\n%s", every)
	}
}
