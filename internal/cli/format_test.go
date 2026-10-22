package cli

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// formatCase is one report the GitHub and Markdown formats are checked on.
type formatCase struct {
	name  string
	rep   registry.Report
	names map[string]string
}

// stopCommandsCase is what a pull request author can write: workflow commands in a
// comment of the policy, in a message of the server, in a file name and in the
// verdict, and the escapes of the commands themselves.
var stopCommandsCase = formatCase{"stop commands", registry.Report{
	Verdict:    "::add-mask::value FAILED · 3 problems",
	Level:      registry.LevelFail,
	NotChecked: []string{"lockout"},
	Classes:    []registry.ClassCount{{Class: "semantic", Count: 1}},
	Findings: []registry.Finding{
		{Severity: "error", Source: "from", Line: 5, Column: 3, Message: "the comment above says // ::stop-commands::abc %0A %0D 100%"},
		{Severity: "error", Source: "from", Message: "::add-mask::secret\n::error::a second line", Untrusted: true},
		{Severity: "warning", Source: "patch", Line: 2, Message: "a file name with a comma and a colon"},
		{Severity: "error", Source: "invariants", Line: 1, Message: "a file name with a line feed in it"},
		{Severity: "notice", Source: "live", Message: "##[error]x and ##vso[task.complete result=Failed;]"},
	},
}, map[string]string{
	"from":       "dir/policy,v2:final%0A.hujson",
	"patch":      `..\evil.json`,
	"invariants": "inv\n::stop-commands::x.hujson",
}}

// formatCases are the cases of the human layout and the one above.
func formatCases() []formatCase {
	var cases []formatCase
	for _, c := range layoutCases {
		cases = append(cases, formatCase(c))
	}
	return append(cases, stopCommandsCase)
}

// renderFormat runs a format the way the command line does: the writer is a guard,
// and the annotations go to the writer behind it.
func renderFormat(t *testing.T, f formatter, c formatCase, color bool) string {
	t.Helper()
	var out bytes.Buffer
	g := &lineGuard{w: &out}
	if err := f(g, c.rep, formatOptions{Names: c.names, Color: color, Trusted: g.Trusted()}); err != nil {
		t.Fatal(err)
	}
	if err := g.Flush(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// checkFormatGoldens compares a format with testdata/format/<format>-<case>.golden.
// The goldens are the contract: read them in a diff.
func checkFormatGoldens(t *testing.T, format string) {
	t.Helper()
	for _, c := range formatCases() {
		got := renderFormat(t, formatters[format], c, false)
		if coloured := renderFormat(t, formatters[format], c, true); coloured != got {
			t.Errorf("%s: colour changes the %s output:\n%q\n%q", c.name, format, got, coloured)
		}
		path := filepath.Join("testdata", "format", format+"-"+strings.ReplaceAll(c.name, " ", "-")+".golden")
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: %v (run the test with -update to write it)", c.name, err)
			continue
		}
		if got != string(want) {
			// Quoted: the text of a failing case may be the very bug under test, a command that a
			// runner would act on in the log of this test.
			t.Errorf("%s differs from %s:\n--- got\n%q\n--- want\n%q", c.name, path, got, want)
		}
	}
}

func TestGitHubFormatMatchesItsGoldens(t *testing.T)   { checkFormatGoldens(t, "github") }
func TestMarkdownFormatMatchesItsGoldens(t *testing.T) { checkFormatGoldens(t, "markdown") }

// splitLines is the lines of s, which ends with a line feed or is empty.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// GitHub keeps ten annotations of each severity and drops the rest in silence: the
// formatter writes ten, and says in a line of its own how many it left out.
func TestAnnotationsAreCappedAtTenPerSeverity(t *testing.T) {
	var rep registry.Report
	for i := 0; i < 25; i++ {
		rep.Findings = append(rep.Findings, registry.Finding{Severity: "error", Message: "e" + strconv.Itoa(i)})
	}
	for i := 0; i < 12; i++ {
		rep.Findings = append(rep.Findings, registry.Finding{Severity: "warning", Message: "w" + strconv.Itoa(i)})
	}
	for i := 0; i < 3; i++ {
		rep.Findings = append(rep.Findings, registry.Finding{Severity: "notice", Message: "n" + strconv.Itoa(i)})
	}
	// A severity that is not ours reads as an error, and counts with the errors.
	rep.Findings = append(rep.Findings, registry.Finding{Severity: "fatal", Message: "f0"})
	var ann, layout bytes.Buffer
	if err := formatGitHub(&layout, rep, formatOptions{Trusted: &ann}); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, l := range splitLines(ann.String()) {
		counts[strings.Fields(l)[0]]++
	}
	if counts["::error"] != 10 || counts["::warning"] != 10 || counts["::notice"] != 3 || len(counts) != 3 {
		t.Errorf("annotations by command = %v, want 10 errors, 10 warnings and 3 notices", counts)
	}
	// The first ten of each severity are the ones kept, in their order.
	for _, kept := range []string{"e0", "e9", "w0", "w9", "n2"} {
		if !strings.Contains(ann.String(), "tailkeeper::"+kept+"\n") {
			t.Errorf("annotation %q is missing:\n%s", kept, ann.String())
		}
	}
	for _, dropped := range []string{"e10", "w10", "f0"} {
		if strings.Contains(ann.String(), "tailkeeper::"+dropped+"\n") {
			t.Errorf("annotation %q is there:\n%s", dropped, ann.String())
		}
	}
	// 26 errors and 12 warnings: 16 and 2 are left out. The line is not an annotation.
	if layout.String() != "  18 more, see the summary\n" {
		t.Errorf("the line that says how many were left out is %q", layout.String())
	}
	// At the cap exactly nothing is left out and nothing is said.
	rep.Findings = rep.Findings[:10]
	ann.Reset()
	layout.Reset()
	if err := formatGitHub(&layout, rep, formatOptions{Trusted: &ann}); err != nil || len(splitLines(ann.String())) != 10 || layout.Len() != 0 {
		t.Errorf("ten errors: %v, %d annotations, layout %q", err, len(splitLines(ann.String())), layout.String())
	}
}

// Without a trusted writer the annotations go to the writer that was given.
func TestWithoutATrustedWriterTheAnnotationsGoToTheWriter(t *testing.T) {
	var b bytes.Buffer
	rep := registry.Report{Verdict: "FAILED", Findings: []registry.Finding{{Severity: "error", Message: "m"}}}
	if err := formatGitHub(&b, rep, formatOptions{}); err != nil {
		t.Fatal(err)
	}
	if want := "  FAILED\n::error title=tailkeeper::m\n"; b.String() != want {
		t.Errorf("got %q, want %q", b.String(), want)
	}
}

// The file of an annotation is the path from the root of the repository, with forward
// slashes, when the path as typed is a file of it; otherwise there is none. Typed at the
// root it is the path itself; typed from a directory below the root it is that directory
// and the path.
func TestTheFileIsRepoRelativeOrOmitted(t *testing.T) {
	for _, c := range []struct{ name, typed, dir, want string }{
		{"a relative path", "policies/acl.hujson", "", "policies/acl.hujson"},
		{"a name with a dot slash", "./x", "", "x"},
		{"backslashes are separators", `dir\acl.hujson`, "", "dir/acl.hujson"},
		{"a comma and a percent sign are kept (and escaped later)", "dir/a,b%c.hujson", "", "dir/a,b%c.hujson"},
		{"an absolute POSIX path", "/etc/acl.hujson", "", ""},
		{"a Windows drive", `C:\x`, "", ""},
		{"a Windows drive in lower case, with a slash", "c:/x", "", ""},
		{"a UNC path", `\\server\share\x`, "", ""},
		{"a parent segment", `..\x`, "", ""},
		{"a parent segment in the middle", "a/../b", "", ""},
		{"a line feed in the name", "a\nb.hujson", "", ""},
		{"an escape in the name", "a\x1bb.hujson", "", ""},
		{"invalid UTF-8", "a\xffb", "", ""},
		{"standard input", "<stdin>", "", ""},
		{"nothing", "", "", ""},
		{"the directory itself", ".", "", ""},
		{"a file below the directory the command ran in", "acl.hujson", "infra", "infra/acl.hujson"},
		{"a path with a dot slash below it", "./p/acl.hujson", "infra/prod", "infra/prod/p/acl.hujson"},
		{"a parent segment is refused whatever the directory", "../acl.hujson", "infra", ""},
		{"the directory itself, below the root", ".", "infra", ""},
		{"standard input, below the root", "<stdin>", "infra", ""},
		{"a directory with an escape in its name", "x.hujson", "in\x1bfra", ""},
		{"a directory with a line feed in its name", "x.hujson", "in\nfra", ""},
	} {
		if got := repoPath(c.typed, c.dir, ""); got != c.want {
			t.Errorf("%s: repoPath(%q, %q) = %q, want %q", c.name, c.typed, c.dir, got, c.want)
		}
	}
	// An absolute path is a file of the repository when the root the runner names is a
	// directory above it, whatever directory the command ran in; with no root, or with
	// the path elsewhere, it is none.
	for _, c := range []struct{ name, typed, dir, root, want string }{
		{"below the root", "/work/repo/policies/acl.hujson", "", "/work/repo", "policies/acl.hujson"},
		{"below the root, which ends in a separator", "/work/repo/acl.hujson", "", "/work/repo/", "acl.hujson"},
		{"the command ran below the root", "/work/repo/acl.hujson", "infra", "/work/repo", "acl.hujson"},
		{"a Windows path under a Windows root", `D:\a\repo\policies\acl.hujson`, "", `D:\a\repo`, "policies/acl.hujson"},
		{"a path that is not segment-wise below the root", "/work/repository/acl.hujson", "", "/work/repo", ""},
		{"elsewhere", "/etc/acl.hujson", "", "/work/repo", ""},
		{"the root itself", "/work/repo", "", "/work/repo", ""},
		{"a parent segment below the root", "/work/repo/../etc/acl.hujson", "", "/work/repo", ""},
		{"no root is known", "/work/repo/acl.hujson", "", "", ""},
		{"a Windows drive and no root", `C:\x`, "", "", ""},
		{"a line feed in the name", "/work/repo/a\nb.hujson", "", "/work/repo", ""},
		{"a line feed in the root", "/work/repo/acl.hujson", "", "/work/re\npo", ""},
		{"a relative path is not changed by the root", "acl.hujson", "infra", "/work/repo", "infra/acl.hujson"},
	} {
		if got := repoPath(c.typed, c.dir, c.root); got != c.want {
			t.Errorf("%s: repoPath(%q, %q, %q) = %q, want %q", c.name, c.typed, c.dir, c.root, got, c.want)
		}
	}
	f := registry.Finding{Severity: "error", Source: "from", Line: 1, Message: "m"}
	for typed, want := range map[string]string{
		"dir/a,b:c%d.hujson": "::error file=dir/a%2Cb%3Ac%25d.hujson,line=1,title=tailkeeper::m",
		"<stdin>":            "::error line=1,title=tailkeeper::<stdin>:1: m",
		`C:\x`:               `::error line=1,title=tailkeeper::C:\x:1: m`,
	} {
		if got := annotation("error", f, formatOptions{Names: map[string]string{"from": typed}}); got != want {
			t.Errorf("a file named %q: %q, want %q", typed, got, want)
		}
	}
	// A command that ran below the root names the file from the root; one that ran outside
	// the repository names none, and the location stands in the message.
	named := map[string]string{"from": "policy.hujson"}
	if got, want := annotation("error", f, formatOptions{Names: named, Dir: "infra"}), "::error file=infra/policy.hujson,line=1,title=tailkeeper::m"; got != want {
		t.Errorf("below the root: %q, want %q", got, want)
	}
	if got, want := annotation("error", f, formatOptions{Names: named, Dir: "infra", Outside: true}), "::error line=1,title=tailkeeper::policy.hujson:1: m"; got != want {
		t.Errorf("outside the repository: %q, want %q", got, want)
	}
	// A source nobody named has no file, and the layout's own name stands in for it.
	if got := annotation("error", registry.Finding{Source: "live", Message: "m"}, formatOptions{}); got != "::error title=tailkeeper::live policy: m" {
		t.Errorf("the live policy: %q", got)
	}
}

func TestOnlyPositiveLinesAndColumnsAreRendered(t *testing.T) {
	for _, c := range []struct {
		line, col int
		want      string
	}{
		{0, 0, "title=tailkeeper"},
		{3, 0, "line=3,title=tailkeeper"},
		{3, 4, "line=3,col=4,title=tailkeeper"},
		{-1, -1, "title=tailkeeper"},
		{-1, 5, "col=5,title=tailkeeper"},
		{0, 5, "col=5,title=tailkeeper"},
	} {
		got := annotation("error", registry.Finding{Line: c.line, Column: c.col, Message: "m"}, formatOptions{})
		if want := "::error " + c.want + "::m"; got != want {
			t.Errorf("line %d column %d: %q, want %q", c.line, c.col, got, want)
		}
	}
}

// A runner names the root of the checkout in GITHUB_WORKSPACE, and the file of an annotation
// is a path from it. The Runner reads the variable and the formatter reads nothing: a command
// that ran in a directory below the root names its files by that directory and the path, one
// that ran at the root or where no root is known names them as typed, and one that ran outside
// the checkout names none, with the location in the message.
func TestTheRunnerNamesTheFileFromTheRepositoryRoot(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "infra")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	for _, name := range []string{"policy.hujson", "change.json"} {
		if err := os.WriteFile(name, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The directory as the process sees it, which is not always the path the test made
	// (a temporary directory behind a link): the root is its parent.
	here, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	const tail = "the comment above says // ::stop-commands::abc %250A %250D 100%25\n"
	for name, c := range map[string]struct{ workspace, from, want string }{
		"below the root":    {filepath.Dir(here), "policy.hujson", "::error file=infra/policy.hujson,line=5,col=3,title=tailkeeper::" + tail},
		"at the root":       {here, "policy.hujson", "::error file=policy.hujson,line=5,col=3,title=tailkeeper::" + tail},
		"no root is known":  {"", "policy.hujson", "::error file=policy.hujson,line=5,col=3,title=tailkeeper::" + tail},
		"outside the root":  {filepath.Join(filepath.Dir(here), "elsewhere"), "policy.hujson", "::error line=5,col=3,title=tailkeeper::policy.hujson:5:3: " + tail},
		"a root not a path": {"\x00", "policy.hujson", "::error line=5,col=3,title=tailkeeper::policy.hujson:5:3: " + tail},
		// The command ran in the parent of the root: the working directory is not below it.
		"the root is below the working directory": {filepath.Join(here, "child"), "policy.hujson", "::error line=5,col=3,title=tailkeeper::policy.hujson:5:3: " + tail},
		// The flag written with the workspace in front, as a workflow often does.
		"an absolute path below the root":   {filepath.Dir(here), filepath.Join(here, "policy.hujson"), "::error file=infra/policy.hujson,line=5,col=3,title=tailkeeper::" + tail},
		"an absolute path at the root":      {here, filepath.Join(here, "policy.hujson"), "::error file=policy.hujson,line=5,col=3,title=tailkeeper::" + tail},
		"an absolute path outside the root": {filepath.Join(here, "child"), filepath.Join(here, "policy.hujson"), "::error line=5,col=3,title=tailkeeper::" + filepath.Join(here, "policy.hujson") + ":5:3: " + tail},
		"an absolute path and no root":      {"", filepath.Join(here, "policy.hujson"), "::error line=5,col=3,title=tailkeeper::" + filepath.Join(here, "policy.hujson") + ":5:3: " + tail},
	} {
		h := reportHarness(t)
		h.r.Getenv = func(k string) string {
			if k == "GITHUB_WORKSPACE" {
				return c.workspace
			}
			return ""
		}
		if code := h.run("report", "check", "--case", "stop commands", "--format", "github", "--from", c.from, "--patch", "change.json"); code != 2 {
			t.Fatalf("%s: exit %d, stderr %q", name, code, h.err)
		}
		if !strings.Contains(h.out.String(), c.want) {
			t.Errorf("%s: standard output lacks %q:\n%s", name, c.want, h.out)
		}
	}
}

// Data and properties are escaped as GitHub documents them; a property also loses
// the two characters that end it.
func TestTheEscapesAreGitHubs(t *testing.T) {
	const in = "a%b\rc\nd:e,f"
	if got, want := dataEscaper.Replace(in), "a%25b%0Dc%0Ad:e,f"; got != want {
		t.Errorf("data: %q, want %q", got, want)
	}
	if got, want := propertyEscaper.Replace(in), "a%25b%0Dc%0Ad%3Ae%2Cf"; got != want {
		t.Errorf("property: %q, want %q", got, want)
	}
	// A percent sign is escaped once, not again by the escapes it makes.
	if got := dataEscaper.Replace("%0A"); got != "%250A" {
		t.Errorf("a literal %%0A is %q", got)
	}
}

// The command line puts every line it prints through the CI-log guard; the
// annotations are the lines it must not touch. A text that begins ::add-mask:: is
// data in an annotation and an escaped line in the layout, in the same run.
func TestTheRunnerLeavesTheFormattersOwnAnnotationsAlone(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, name := range []string{"policy.hujson", "change.json"} {
		if err := os.WriteFile(name, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h := reportHarness(t)
	if code := h.run("report", "check", "--case", "stop commands", "--format", "github", "--from", "policy.hujson", "--patch", "change.json"); code != 2 || h.err.Len() != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.err)
	}
	out := h.out.String()
	var annotations int
	for _, l := range splitLines(out) {
		if !strings.HasPrefix(strings.TrimLeft(l, " \t"), "::") {
			continue
		}
		annotations++
		if !strings.HasPrefix(l, "::error ") && !strings.HasPrefix(l, "::warning ") && !strings.HasPrefix(l, "::notice ") {
			t.Errorf("a line that is a command and is not the formatter's annotation: %q", l)
		}
	}
	if annotations != 5 {
		t.Errorf("%d annotation lines on standard output, want 5:\n%s", annotations, out)
	}
	for _, want := range []string{
		// The file the flag named, the position, and the comment's own commands as data.
		"::error file=policy.hujson,line=5,col=3,title=tailkeeper::the comment above says // ::stop-commands::abc %250A %250D 100%25\n",
		"::warning file=change.json,line=2,title=tailkeeper::a file name with a comma and a colon\n",
		// A message that begins with a command is escaped by the guard, with a line feed made %0A.
		"::error file=policy.hujson,title=tailkeeper::\\u{003A}:add-mask::secret%0A::error::a second line\n",
		// The verdict is a layout line: indented, and its first character escaped.
		"  \\u{003A}:add-mask::value FAILED · 3 problems\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("standard output lacks %q:\n%s", want, out)
		}
	}
}

// The GitHub formatter reads no environment variable and opens no file: a runner's
// $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY stay as they are.
func TestGitHubFormatterTouchesNoGitHubFile(t *testing.T) {
	src, err := os.ReadFile("format_github.go")
	if err != nil {
		t.Fatal(err)
	}
	if uses := githubFileUses(t, string(src)); len(uses) != 0 {
		t.Errorf("format_github.go reaches for %v", uses)
	}
	// The scan can fail: a planted source that does both is found.
	planted := "package p\n\nimport \"os\"\n\nfunc f() { _ = os.WriteFile(os.Getenv(\"GITHUB_OUTPUT\"), nil, 0o600) }\n"
	if uses := githubFileUses(t, planted); len(uses) != 4 {
		t.Errorf("the scan of a planted source found %v, want the import, os.WriteFile, os.Getenv and the name", uses)
	}
}

// The files a runner reads its commands from, named by environment variables: nothing the
// product is made of writes to one, so that a policy or a message can never reach a later step
// as an output, a variable, a path, a state or a summary through tailkeeper.
var runnerCommandFiles = []string{"GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_STATE", "GITHUB_STEP_SUMMARY"}

// runnerFileNames lists the string literals of a Go source that name one of those files.
func runnerFileNames(t *testing.T, src string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "src.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	ast.Inspect(file, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			for _, name := range runnerCommandFiles {
				if strings.Contains(lit.Value, name) {
					names = append(names, name)
				}
			}
		}
		return true
	})
	return names
}

func TestNoSourceOfTheProductNamesAFileARunnerReadsCommandsFrom(t *testing.T) {
	// The walk only collects the paths; the files are read after it, because a file read
	// inside the walk's callback is what the linter's rule about walks catches.
	var paths []string
	for _, root := range []string{filepath.Join("..", "..", "internal"), filepath.Join("..", "..", "cmd")} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			paths = append(paths, path)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	scanned := 0
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		if names := runnerFileNames(t, string(src)); len(names) != 0 {
			t.Errorf("%s names %v", path, names)
		}
	}
	// A scan that found no file is not a clean scan, and one that cannot find a name is not
	// a check: the product has well over fifty sources, and a planted source with all five is found.
	if scanned < 50 {
		t.Errorf("%d sources scanned: the walk is not looking where the product is", scanned)
	}
	planted := "package p\n\nvar names = []string{\"GITHUB_OUTPUT\", \"GITHUB_ENV\", \"GITHUB_PATH\", \"GITHUB_STATE\", \"GITHUB_STEP_SUMMARY\"}\n"
	if names := runnerFileNames(t, planted); len(names) != len(runnerCommandFiles) {
		t.Errorf("the scan of a planted source found %v, want all of %v", names, runnerCommandFiles)
	}
}

// githubFileUses lists what a Go source could reach a file or the environment with:
// an import of os, io/ioutil or syscall, a selector on a package called os, and a
// string literal that names a GITHUB_ variable.
func githubFileUses(t *testing.T, src string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "src.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var uses []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ImportSpec:
			if p, _ := strconv.Unquote(x.Path.Value); p == "os" || p == "io/ioutil" || p == "syscall" {
				uses = append(uses, "import "+p)
			}
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && id.Name == "os" {
				uses = append(uses, "os."+x.Sel.Name)
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING && strings.Contains(x.Value, "GITHUB_") {
				uses = append(uses, x.Value)
			}
		}
		return true
	})
	return uses
}

// unescapedSpecials lists the characters of s that Markdown would read as syntax or
// as a mention: those not behind a backslash, and every & that does not start one of
// the entities mdEscape writes.
func unescapedSpecials(s string) []string {
	var found []string
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++ // the next character is escaped
		case strings.IndexByte("`*_[]<>|!~@", c) >= 0:
			found = append(found, string(c))
		case c == '&':
			ok := false
			for _, e := range []string{"&amp;", "&#64;", "&#35;", "&#45;", "&#47;", "&#46;"} {
				ok = ok || strings.HasPrefix(s[i:], e)
			}
			if !ok {
				found = append(found, "&")
			}
		}
	}
	return found
}

// readSpan reads s as one code span and returns what it holds; false when s is not
// exactly one, or the text could end the span early.
func readSpan(s string) (string, bool) {
	n := 0
	for n < len(s) && s[n] == '`' {
		n++
	}
	if n == 0 || len(s) < 2*n || !strings.HasSuffix(s, strings.Repeat("`", n)) {
		return "", false
	}
	inner := s[n : len(s)-n]
	if strings.Contains(inner, strings.Repeat("`", n)) {
		return "", false
	}
	if len(inner) >= 2 && inner[0] == ' ' && inner[len(inner)-1] == ' ' && strings.Trim(inner, " ") != "" {
		inner = inner[1 : len(inner)-1] // one space is taken off each side
	}
	return inner, true
}

func TestMarkdownNeutralisesMentionsLinksHTMLAndTables(t *testing.T) {
	const hostileText = "@octocat fixes #12 and GH-12 at http://example.org/x and www.example.org <script>alert(1)</script> | a ``` b ![i](u) [l](u) ~~s~~ **b** _i_ &amp; \\"
	rep := registry.Report{
		Verdict:    "# " + hostileText,
		NotChecked: []string{"- " + hostileText},
		Classes:    []registry.ClassCount{{Class: "1. " + hostileText, Count: 2}},
		Findings: []registry.Finding{
			{Severity: "error", Source: "from", Line: 3, Message: hostileText},
			{Severity: "error", Source: "from", Pointer: "/a`b", Message: hostileText, Untrusted: true},
		},
	}
	var b bytes.Buffer
	if err := formatMarkdown(&b, rep, formatOptions{Names: map[string]string{"from": "p`olicy.hujson"}}); err != nil {
		t.Fatal(err)
	}
	lines := splitLines(b.String())
	if len(lines) != 17 {
		t.Fatalf("%d lines:\n%s", len(lines), b.String())
	}
	// The text written by tailkeeper's code: the verdict, the two lists, the first
	// finding's message (its location is a code span, and a code span is made of
	// backticks).
	_, message, _ := strings.Cut(lines[12], " error: ")
	verdict := strings.TrimSuffix(strings.TrimPrefix(lines[0], "**"), "**")
	for i, text := range map[int]string{0: verdict, 4: lines[4], 8: lines[8], 12: message} {
		if bad := unescapedSpecials(text); len(bad) != 0 {
			t.Errorf("line %d holds %v that Markdown would act on: %s", i+1, bad, text)
		}
		for _, raw := range []string{"@octocat", "#12", "GH-12", "://", "www.", "<script>"} {
			if strings.Contains(text, raw) {
				t.Errorf("line %d holds %q: %s", i+1, raw, text)
			}
		}
	}
	// A text that begins like a heading, a list item or a numbered list does not start one.
	for i, prefix := range map[int]string{4: `- \- &#64;octocat`, 8: `- 1\. &#64;octocat`} {
		if !strings.HasPrefix(lines[i], prefix) {
			t.Errorf("line %d starts a block of its own: %s", i+1, lines[i])
		}
	}
	if !strings.HasPrefix(lines[0], `**\# &#64;octocat`) {
		t.Errorf("the verdict starts a block of its own: %s", lines[0])
	}
	// The location is a code span that holds a backtick of the file name.
	where, _, _ := strings.Cut(strings.TrimPrefix(lines[12], "- "), " error: ")
	if got, ok := readSpan(where); !ok || got != "p`olicy.hujson:3" {
		t.Errorf("the location %q reads back as %q (%v)", where, got, ok)
	}
	// Tailscale's text is one code span, whatever it holds, behind the notice.
	if lines[14] != registry.UntrustedReasonsNotice {
		t.Errorf("line 15 is %q, want the notice", lines[14])
	}
	_, rest, _ := strings.Cut(lines[16], " error: ")
	pointer, text, ok := strings.Cut(rest, ": ")
	if got, isSpan := readSpan(pointer); !ok || !isSpan || got != "/a`b" {
		t.Errorf("the pointer is not a code span of itself: %q", rest)
	}
	if got, isSpan := readSpan(text); !isSpan || got != hostileText {
		t.Errorf("Tailscale's message is not a code span of itself: %q (read %q, %v)", text, got, isSpan)
	}
	for i, l := range lines {
		if strings.ContainsAny(l, "\r\x1b") {
			t.Errorf("line %d holds a control character: %q", i+1, l)
		}
	}
	// Each printable character alone, between two letters, is neutralised.
	for c := byte(0x20); c < 0x7f; c++ {
		in := "a" + string(rune(c)) + "b"
		if bad := unescapedSpecials(mdEscape(in)); len(bad) != 0 {
			t.Errorf("mdEscape(%q) = %q leaves %v", in, mdEscape(in), bad)
		}
	}
	// And at the start of a line, where a character can begin a block.
	for in, want := range map[string]string{
		"# heading": `\# heading`, "- item": `\- item`, "+ item": `\+ item`, "> quote": `\> quote`,
		"1. one": `1\. one`, "12) one": `12\) one`, "2024 is a year": "2024 is a year", "a - b": "a - b",
		"@x": "&#64;x", "#12": "&#35;12", "GH-12": "GH&#45;12", "see gh-7": "see gh&#45;7", "GH-x": "GH-x", "GH-": "GH-", "# 12": `\# 12`, "#x": `\#x`, "WWW.x": "WWW&#46;x", "a://b": "a:&#47;&#47;b",
		"a&b": "a&amp;b", "": "",
	} {
		if got := mdEscape(in); got != want {
			t.Errorf("mdEscape(%q) = %q, want %q", in, got, want)
		}
	}
	// A code span is longer than any run of backticks inside it, and keeps a backtick at its ends.
	for _, in := range []string{"x", "a`b", "``", "`", "a``b```c", " x ", "`x`", "  ", "a" + strings.Repeat("`", 5) + "b"} {
		if got, ok := readSpan(codeSpan(in)); !ok || (got != in && strings.Trim(in, " ") != "") {
			t.Errorf("codeSpan(%q) = %q reads back as %q (%v)", in, codeSpan(in), got, ok)
		}
	}
	if codeSpan("") != "" {
		t.Errorf("codeSpan of nothing is %q", codeSpan(""))
	}
}

// Tailscale's text with none of ours: the notice follows the heading directly.
func TestMarkdownShowsTailscalesTextAloneBehindItsNotice(t *testing.T) {
	var b bytes.Buffer
	rep := registry.Report{Findings: []registry.Finding{{Severity: "error", Message: "m", Untrusted: true}}}
	if err := formatMarkdown(&b, rep, formatOptions{}); err != nil {
		t.Fatal(err)
	}
	if want := "Findings:\n\n" + registry.UntrustedReasonsNotice + "\n\n- error: `m`\n"; b.String() != want {
		t.Errorf("got %q, want %q", b.String(), want)
	}
}

// formatNames lists the four formats the commands offer, and the flag says so.
func TestFormatNamesNowListFourFormats(t *testing.T) {
	if got := strings.Join(formatNames(), ","); got != "text,json,github,markdown" {
		t.Errorf("formatNames = %s", got)
	}
	h := reportHarness(t)
	if code := h.run("report", "check", "--case", "valid", "--format", "sarif"); code != 2 || !strings.Contains(h.err.String(), `--format: "sarif" is not one of text, json, github, markdown`) {
		t.Errorf("exit %d, stderr %q", code, h.err)
	}
	h = reportHarness(t)
	h.run("report", "check", "--help")
	if !strings.Contains(h.err.String()+h.out.String(), "output format: text, json, github, markdown (default text; json is --json)") {
		t.Errorf("the usage does not list the formats:\n%s%s", h.err, h.out)
	}
	// --json and a format of the table contradict each other, as for text.
	for _, format := range []string{"github", "markdown"} {
		h = reportHarness(t)
		if code := h.run("report", "check", "--case", "valid", "--format", format, "--json"); code != 2 || !strings.Contains(h.out.String(), "--json and --format "+format+" contradict each other") {
			t.Errorf("%s with --json: exit %d, stdout %q", format, code, h.out)
		}
	}
}

// The guard hands out the writer behind it, after the unfinished line it holds has
// been written, guarded, and ended.
func TestTheGuardHandsOutTheWriterBehindIt(t *testing.T) {
	var out bytes.Buffer
	g := &lineGuard{w: &out}
	if _, err := io.WriteString(g, "complete\n::x partial"); err != nil {
		t.Fatal(err)
	}
	trusted := g.Trusted()
	if trusted != io.Writer(&out) {
		t.Fatalf("Trusted() = %v, want the writer behind the guard", trusted)
	}
	if _, err := io.WriteString(trusted, "::error::ok\n"); err != nil {
		t.Fatal(err)
	}
	if want := "complete\n\\u{003A}:x partial\n::error::ok\n"; out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
	// A guard whose writer failed writes nothing more, and Trusted() does not try.
	w := &failingWriter{at: 1}
	bad := &lineGuard{w: w}
	_, _ = io.WriteString(bad, "x\n")
	_, _ = io.WriteString(bad, "y")
	if bad.Trusted() != io.Writer(w) || w.n != 1 {
		t.Errorf("after a failed write: %d writes", w.n)
	}
}

// Every write of the two formats is checked, on either writer: a write that fails
// anywhere is returned.
func TestEveryWriteOfTheNewFormatsIsChecked(t *testing.T) {
	for _, format := range []string{"github", "markdown"} {
		for _, c := range formatCases() {
			for _, target := range []string{"layout", "annotations"} {
				if format == "markdown" && target == "annotations" {
					continue
				}
				for at := 1; ; at++ {
					layout, ann := &failingWriter{}, &failingWriter{}
					if target == "layout" {
						layout.at = at
					} else {
						ann.at = at
					}
					err := formatters[format](layout, c.rep, formatOptions{Names: c.names, Trusted: ann})
					if !layout.tripped && !ann.tripped {
						if err != nil {
							t.Errorf("%s %s %s: a working writer failed: %v", format, c.name, target, err)
						}
						break
					}
					if err == nil {
						t.Errorf("%s %s: write %d to the %s writer failed and the format returned nil", format, c.name, at, target)
						break
					}
				}
			}
		}
	}
}

// The layouts that print the report's own findings before Tailscale's get the two groups from
// one function, each in the order the report holds them.
func TestFindingsSplitIntoTheReportsOwnAndTailscales(t *testing.T) {
	in := []registry.Finding{
		{Message: "a1"}, {Message: "t1", Untrusted: true}, {Message: "a2"}, {Message: "t2", Untrusted: true},
	}
	ours, theirs := splitByTrust(in)
	messages := func(fs []registry.Finding) string {
		var b []string
		for _, f := range fs {
			b = append(b, f.Message)
		}
		return strings.Join(b, ",")
	}
	if got := messages(ours); got != "a1,a2" {
		t.Errorf("the report's own findings: %q", got)
	}
	if got := messages(theirs); got != "t1,t2" {
		t.Errorf("Tailscale's findings: %q", got)
	}
	if ours, theirs := splitByTrust(nil); ours != nil || theirs != nil {
		t.Errorf("no findings: %v, %v", ours, theirs)
	}
}
