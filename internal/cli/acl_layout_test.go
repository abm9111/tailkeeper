package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// The policy commands through the real command line, against the fake API: every case of
// aclLayoutCases is run once for each rendering the command offers, and the output is
// compared with a golden file. The goldens are the contract: read them in a diff. They hold
// no tailnet value, and the working directory of a run is a new temporary directory, so a
// file name in a golden is the name the command line gave.

// layoutLines joins lines into a text that ends with a line feed.
func layoutLines(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

var (
	// layoutProposal is a proposal with two tests, the second at line 8.
	layoutProposal = layoutLines(
		"// a proposal",
		"{",
		"\t\"groups\": {\"group:eng\": [\"amy@example.com\"]},",
		"\t\"tagOwners\": {\"tag:web\": [\"group:eng\"], \"tag:ci\": [\"autogroup:admin\"]},",
		"\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"tag:web:22\"]}],",
		"\t\"tests\": [",
		"\t\t{\"src\": \"tag:ci\", \"accept\": [\"tag:web:22\"]},",
		"\t\t{\"src\": \"tag:web\", \"deny\": [\"tag:ci:22\"]},",
		"\t],",
		"}")
	// layoutDuplicate writes the key groups twice.
	layoutDuplicate = layoutLines("{", "\t\"groups\": {},", "\t\"acls\": [],", "\t\"groups\": {\"group:a\": []},", "}")
	// layoutOld and its two successors: the same meaning written differently, and a policy
	// that widens a rule, adds a group and adds a construct Tailscale writes itself.
	layoutOld = layoutLines("{",
		"\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"]},",
		"\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"tag:ci:22\"]}],",
		"}")
	layoutSame = layoutLines("// reformatted, the same meaning", "{",
		"\t\"tagOwners\": {",
		"\t\t\"tag:ci\": [\"autogroup:admin\"],",
		"\t},",
		"\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"tag:ci:22\"]}],",
		"}")
	layoutWider = layoutLines("{",
		"\t\"groups\": {\"group:eng\": [\"amy@example.com\"]},",
		"\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"]},",
		"\t\"acls\": [{\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"tag:ci:22\"]}],",
		"\t\"nodeAttrs\": [{\"target\": [\"autogroup:member\"], \"attr\": [\"funnel\"]}],",
		"}")
)

// layoutFake serves the live policy (the details read, the plain read the re-check makes, and
// the settings) with the warnings Tailscale reports for it, and answers a validation with
// answer when there is one.
func layoutFake(live string, warnings []string, answer *apitest.Shape) func(t *testing.T) *apitest.Fake {
	return func(t *testing.T) *apitest.Fake {
		t.Helper()
		f := apitest.New(t)
		serveLayoutLive(f, func() string { return live }, warnings)
		if answer != nil {
			f.ServeValidate(*answer)
		}
		return f
	}
}

// layoutManyErrors is n messages of a test that names something Tailscale cannot resolve.
func layoutManyErrors(n int) []string {
	var errs []string
	for i := range n {
		errs = append(errs, fmt.Sprintf("user or host is invalid: tag:t%02d not found", i))
	}
	return errs
}

// serveLayoutLive registers the live reads; text is asked for on every read.
func serveLayoutLive(f *apitest.Fake, text func() string, warnings []string) {
	f.Handle("GET", "/api/v2/tailnet/T1234CNTRL/acl", func(w http.ResponseWriter, r *http.Request) {
		body := text()
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(body, api.ETagOf([]byte(body)), warnings, nil).Write(w)
			return
		}
		apitest.PolicyText(body, api.ETagOf([]byte(body))).Write(w)
	})
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/settings", 200, `{"aclsExternallyManagedOn":false}`)
}

// answerWith is a pointer to a shape, for layoutFake.
func answerWith(s apitest.Shape) *apitest.Shape { return &s }

// liveChangesFake serves a live policy that is another one from its second read on: the
// check reads it, sends the text, and reads it again.
func liveChangesFake(t *testing.T) *apitest.Fake {
	t.Helper()
	f := apitest.New(t)
	var reads atomic.Int32
	serveLayoutLive(f, func() string {
		if reads.Add(1) > 1 {
			return layoutLines("{", "\t\"acls\": [],", "}")
		}
		return "{}\n"
	}, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	return f
}

// aclCase is one run of a policy command.
type aclCase struct {
	name    string
	files   map[string]string // written to the working directory before the run
	stdin   string
	args    []string // the area, the verb and the arguments after them; the format goes after the verb
	exit    int
	stderr  string                           // the whole of standard error
	formats []string                         // the renderings the command offers; nil means all five
	fake    func(t *testing.T) *apitest.Fake // nil: no API is needed
}

// The renderings, and the arguments each one adds after the verb.
var aclRenderings = map[string][]string{
	"text": nil, "color": nil, "github": {"--format", "github"}, "markdown": {"--format", "markdown"}, "json": {"--json"},
}

var allRenderings = []string{"text", "color", "github", "markdown", "json"}

func (c aclCase) renderings() []string {
	if c.formats != nil {
		return c.formats
	}
	return allRenderings
}

// run runs the command in a new directory holding the case's files, with a clock that does
// not move. Only the colour rendering runs on a terminal with NO_COLOR unset; the others run
// on one too when the rendering is not text, to show that colour is never written there.
func (c aclCase) run(t *testing.T, rendering string, extra ...string) (code int, stdout, stderr string) {
	t.Helper()
	t.Chdir(t.TempDir())
	for name, body := range c.files {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var f *apitest.Fake
	if c.fake != nil {
		f = c.fake(t)
	}
	h := newHarness(t, f)
	fixed := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	h.app.Env.Now = func() time.Time { return fixed }
	h.r.Now = func() time.Time { return fixed }
	h.r.Getenv = func(string) string { return "" }
	h.r.IsTerminal = func(io.Writer) bool { return rendering != "text" }
	h.r.Stdin = strings.NewReader(c.stdin)
	args := slices.Concat(c.args[:2], aclRenderings[rendering], extra, c.args[2:])
	code = h.run(args...)
	return code, h.out.String(), h.err.String()
}

// aclLayoutCases is the one list of the goldens. Their names are the names of the files.
var aclLayoutCases = []aclCase{
	{name: "validate-pass", args: []string{"acl", "validate", "--from", "policy.hujson"},
		files: map[string]string{"policy.hujson": layoutProposal},
		fake: layoutFake("{}\n", []string{`host alias "old" is unused`},
			answerWith(apitest.TestsWarned(apitest.Entry{User: "old", Warnings: []string{`host alias "old" is unused`}})))},
	{name: "validate-warned", args: []string{"acl", "validate", "--fail-on", "warnings", "--from", "policy.hujson"},
		files: map[string]string{"policy.hujson": layoutProposal},
		exit:  8, stderr: "tailkeeper: findings_present: --fail-on matched warnings (1)\n",
		fake: layoutFake("{}\n", nil,
			answerWith(apitest.TestsWarned(apitest.Entry{User: "group:eng", Warnings: []string{"group:eng has one member"}})))},
	{name: "validate-fail", args: []string{"acl", "validate", "--from", "policy.hujson"},
		files: map[string]string{"policy.hujson": layoutProposal}, exit: 9,
		fake: layoutFake("{}\n", nil,
			answerWith(apitest.TestsFailed(apitest.Entry{User: "tag:web", Errors: []string{`[acl test error]: address "tag:ci:22" (protocol "tcp"): want: Drop, got: Accept`}})))},
	{name: "validate-invalid", args: []string{"acl", "validate", "--from", "policy.hujson"},
		files: map[string]string{"policy.hujson": layoutDuplicate}, exit: 2, fake: layoutFake("{}\n", nil, nil)},
	{name: "validate-rejected", args: []string{"acl", "validate", "--from", "policy.hujson"},
		files: map[string]string{"policy.hujson": layoutProposal}, exit: 2,
		fake: layoutFake("{}\n", nil, answerWith(apitest.PolicySyntaxError(3, 5, "unexpected token")))},
	{name: "validate-unknown", args: []string{"acl", "validate", "--from", "policy.hujson"},
		files: map[string]string{"policy.hujson": layoutProposal}, exit: 1, fake: liveChangesFake},
	{name: "validate-offline", args: []string{"acl", "validate", "--offline", "--from", "policy.hujson"},
		files: map[string]string{"policy.hujson": layoutProposal}},
	{name: "validate-stdin-fail", args: []string{"acl", "validate", "--from", "-"},
		stdin: layoutProposal, exit: 9,
		fake: layoutFake("{}\n", nil,
			answerWith(apitest.TestsFailed(apitest.Entry{User: "tag:web", Errors: []string{`[acl test error]: address "tag:ci:22" (protocol "tcp"): want: Drop, got: Accept`}})))},
	{name: "validate-hostile-reply", args: []string{"acl", "validate", "--from", "policy.hujson"},
		files: map[string]string{"policy.hujson": layoutProposal}, exit: 2,
		fake: layoutFake("{}\n", nil, answerWith(apitest.BareMessage200("::add-mask::secret\n##[error]forged ##vso[task.complete result=Failed;] %0A")))},
	{name: "validate-live", args: []string{"acl", "validate"},
		fake: layoutFake("{}\n", nil, answerWith(apitest.TestsPassEmptyObject()))},
	{name: "validate-cut", args: []string{"acl", "validate", "--from", "policy.hujson"},
		files: map[string]string{"policy.hujson": layoutProposal}, exit: 2,
		fake: layoutFake("{}\n", nil, answerWith(apitest.TestsFailed(apitest.Entry{User: "tag:web", Errors: layoutManyErrors(65)})))},
	{name: "diff-equal", args: []string{"acl", "diff", "old.hujson", "new.hujson"},
		files: map[string]string{"old.hujson": layoutOld, "new.hujson": layoutSame}},
	{name: "diff-changed", args: []string{"acl", "diff", "old.hujson", "new.hujson"},
		files: map[string]string{"old.hujson": layoutOld, "new.hujson": layoutWider}},
	{name: "diff-filtered", args: []string{"acl", "diff", "--section", "tagOwners", "old.hujson", "new.hujson"},
		files: map[string]string{"old.hujson": layoutOld, "new.hujson": layoutWider}},
	{name: "get-page", args: []string{"acl", "get"}, formats: []string{"text", "json"},
		fake: layoutFake(layoutProposal, []string{`host alias "old" is unused`}, nil)},
	{name: "get-summary", args: []string{"acl", "get", "--view", "summary"}, formats: []string{"text", "json"},
		fake: layoutFake(layoutProposal, nil, nil)},
}

// goldenPath is where a case's rendering is kept: the human layout beside the framework's,
// the formats of a report in testdata/format.
func goldenPath(name, rendering string) string {
	switch rendering {
	case "text":
		return filepath.Join(packageDir, "testdata", "layout", "acl-"+name+".golden")
	case "color":
		return filepath.Join(packageDir, "testdata", "layout", "acl-"+name+".color.golden")
	}
	return filepath.Join(packageDir, "testdata", "format", "acl-"+name+"."+rendering+".golden")
}

// shown is a path under this package as the messages name it: relative, with forward slashes.
func shown(path string) string {
	if rel, err := filepath.Rel(packageDir, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return path
}

// packageDir is the directory of this package, where the tests start: a run changes the
// working directory, and the goldens stay where they are.
var packageDir = func() string {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return wd
}()

// checkGolden compares got with the file, or writes the file when the test runs with -update.
func checkGolden(t *testing.T, path, got string) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s does not exist (run the test with -update to write it)", shown(path))
		return
	}
	if err != nil {
		t.Errorf("%s: %v", shown(path), err)
		return
	}
	if got != string(want) {
		// Quoted: what a failing case holds may be the bug under test, a line that a runner
		// would act on in the log of this test.
		t.Errorf("differs from %s:\n--- got\n%q\n--- want\n%q", shown(path), got, want)
	}
}

var ansiCode = regexp.MustCompile("\x1b\\[[0-9;]*m")

func TestTheACLCommandsMatchTheirGoldens(t *testing.T) {
	for _, c := range aclLayoutCases {
		got := map[string]string{}
		for _, rendering := range c.renderings() {
			t.Run(c.name+"/"+rendering, func(t *testing.T) {
				code, stdout, stderr := c.run(t, rendering)
				got[rendering] = stdout
				if code != c.exit || stderr != c.stderr {
					t.Errorf("exit %d, stderr %q; want exit %d, stderr %q", code, stderr, c.exit, c.stderr)
				}
				if stdout == "" {
					t.Error("nothing on standard output")
				}
				if rendering == "json" && !json.Valid([]byte(stdout)) {
					t.Errorf("not JSON: %q", stdout)
				}
				if rendering != "color" && strings.Contains(stdout, "\x1b") {
					t.Errorf("colour written where none was asked for: %q", stdout)
				}
				checkGolden(t, goldenPath(c.name, rendering), stdout)
			})
		}
		// The colour layout is the plain one with colour codes around some lines, and has some.
		if colour, plain := got["color"], got["text"]; colour != "" {
			if stripped := ansiCode.ReplaceAllString(colour, ""); stripped != plain {
				t.Errorf("%s: the coloured layout is not the plain one with codes:\n%q\n%q", c.name, stripped, plain)
			}
			if colour == plain {
				t.Errorf("%s: the coloured layout holds no colour", c.name)
			}
		}
	}
}

// Every golden belongs to a case and every case has its goldens: a renamed or removed case
// leaves no file that nothing compares.
func TestEveryACLGoldenBelongsToACase(t *testing.T) {
	if *update {
		t.Skip("the goldens are being written")
	}
	want := map[string]bool{}
	for _, c := range aclLayoutCases {
		for _, rendering := range c.renderings() {
			want[goldenPath(c.name, rendering)] = true
		}
	}
	var have []string
	for _, pattern := range []string{filepath.Join(packageDir, "testdata", "layout", "acl-*.golden"), filepath.Join(packageDir, "testdata", "format", "acl-*.golden")} {
		files, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		have = append(have, files...)
	}
	for _, f := range have {
		if !want[f] {
			t.Errorf("%s belongs to no case of aclLayoutCases", shown(f))
		}
		delete(want, f)
	}
	missing := make([]string, 0, len(want))
	for f := range want {
		missing = append(missing, f)
	}
	slices.Sort(missing)
	for _, f := range missing {
		t.Errorf("%s is named by a case and does not exist", shown(f))
	}
}

// --quiet prints nothing when the command succeeds, and prints what it printed otherwise.
func TestQuietPrintsNothingOnExit0ForValidateAndDiff(t *testing.T) {
	for _, c := range aclLayoutCases {
		if c.args[1] == "get" {
			continue
		}
		code, quiet, _ := c.run(t, "text", "--quiet")
		_, loud, _ := c.run(t, "text")
		switch {
		case code != c.exit:
			t.Errorf("%s: --quiet exit %d, want %d", c.name, code, c.exit)
		case c.exit == 0 && quiet != "":
			t.Errorf("%s: --quiet printed %q on exit 0", c.name, quiet)
		case c.exit != 0 && quiet != loud:
			t.Errorf("%s: --quiet changed what a failing run prints:\n%q\n%q", c.name, quiet, loud)
		}
	}
}

// pointerPlaces finds the JSON pointers an output holds: the value of each "pointer" key of
// a JSON document, and in the other renderings a word that starts with a slash right after
// "error: ", "warning: " or "notice: " (text), after the two colons that open the data of an
// annotation (GitHub) or after a backtick (markdown). A pointer is written with forward
// slashes on every system.
func pointerPlaces(output string) []string {
	var found []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if s, ok := e.(string); ok && k == "pointer" {
					found = append(found, s)
				}
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	var doc any
	if json.Unmarshal([]byte(output), &doc) == nil {
		walk(doc)
	}
	for _, m := range regexp.MustCompile("(?:error: |warning: |notice: |::|`)(/[^\\s:`]*)").FindAllStringSubmatch(output, -1) {
		found = append(found, m[1])
	}
	return found
}

func TestGoldenPointersUseForwardSlashes(t *testing.T) {
	// The detector first: a pointer with a separator of the system is found in both forms.
	for _, planted := range []string{`{"errors":[{"pointer":"/tests\\1"}]}`, "policy.hujson:8:3: error: /tests\\1: x"} {
		if places := pointerPlaces(planted); len(places) != 1 || !strings.Contains(places[0], `\`) {
			t.Fatalf("the detector found %v in %q, want the one pointer with a backslash", places, planted)
		}
	}
	seen := 0
	for _, c := range aclLayoutCases {
		for _, rendering := range c.renderings() {
			_, stdout, _ := c.run(t, rendering)
			for _, p := range pointerPlaces(ansiCode.ReplaceAllString(stdout, "")) {
				seen++
				if strings.Contains(p, `\`) || !strings.HasPrefix(p, "/") && p != "" {
					t.Errorf("%s (%s): the pointer %q is not written with forward slashes", c.name, rendering, p)
				}
			}
		}
	}
	t.Logf("%d pointers in the renderings of %d cases", seen, len(aclLayoutCases))
	if seen < 14 {
		t.Errorf("only %d pointers were seen in all the goldens; the cases no longer reach the pointers", seen)
	}
}

// The text a command prints in place of a file name is the name the command line gave, and
// the working directory is a new one for each run, so no golden holds a path of this machine.
func TestNoACLGoldenHoldsAPathOfThisMachine(t *testing.T) {
	if *update {
		t.Skip("the goldens are being written")
	}
	tmp := os.TempDir()
	for _, c := range aclLayoutCases {
		for _, rendering := range c.renderings() {
			b, err := os.ReadFile(goldenPath(c.name, rendering))
			if err != nil {
				t.Fatalf("%s cannot be read (run TestTheACLCommandsMatchTheirGoldens with -update to write it)", shown(goldenPath(c.name, rendering)))
			}
			if bytes.Contains(b, []byte(tmp)) || bytes.Contains(b, []byte("/private/")) || bytes.Contains(b, []byte("/var/folders")) {
				t.Errorf("%s (%s) names a directory of this machine", c.name, rendering)
			}
		}
	}
}
