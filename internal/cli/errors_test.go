package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/audit"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/doctor"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// brokenWriter fails every write, like a closed pipe.
type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// jsonError parses stdout as one JSON error document and returns its code.
func jsonError(t *testing.T, label, stdout string) string {
	t.Helper()
	var e struct {
		Error struct{ Code, Message, Hint string } `json:"error"`
	}
	dec := json.NewDecoder(strings.NewReader(stdout))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil || e.Error.Code == "" || e.Error.Message == "" {
		t.Errorf("%s: stdout is not a JSON error: %q (%v)", label, stdout, err)
	}
	if dec.More() {
		t.Errorf("%s: more than one JSON document on stdout: %q", label, stdout)
	}
	return e.Error.Code
}

// With --json, a script reads one JSON document from stdout on every path that
// fails, and nothing from stderr: the exit code was already right on all of them.
func TestJSONOnEveryErrorPath(t *testing.T) {
	missingDocs := filepath.Join(t.TempDir(), "missing.md")
	staleDocs := filepath.Join(t.TempDir(), "stale.md")
	if err := os.WriteFile(staleDocs, []byte("not the generated reference\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args []string
		exit int
		code string
	}{
		{[]string{"--json", "--bogus"}, 2, "usage"},
		{[]string{"--json", "--context"}, 2, "usage"},
		{[]string{"--json"}, 2, "usage"},
		{[]string{"--json", "nowhere", "list"}, 2, "usage"},
		{[]string{"--json", "nowhere"}, 2, "usage"},
		{[]string{"--json", "devices", "frobnicate"}, 2, "usage"},
		{[]string{"--json", "devices"}, 2, "usage"},
		{[]string{"devices", "--json"}, 2, "usage"},
		{[]string{"devices", "frobnicate", "--json"}, 2, "usage"},
		{[]string{"nowhere", "--json"}, 2, "usage"},
		{[]string{"nowhere", "list", "--json"}, 2, "usage"},
		{[]string{"--bogus", "--json"}, 2, "usage"},
		{[]string{"--bogus", "devices", "list", "--json"}, 2, "usage"},
		{[]string{"--context", "--json", "--bogus"}, 2, "usage"},
		{[]string{"--json", "nowhere", "--help"}, 2, "usage"},
		{[]string{"devices", "list", "--bogus", "--json", "--", "web-1"}, 2, "usage"},
		{[]string{"devices", "list", "--json", "--", "web-1"}, 2, "usage"},
		{[]string{"--json", "devices", "list", "--bogus"}, 2, "usage"},
		{[]string{"devices", "list", "--bogus", "--json"}, 2, "usage"},
		{[]string{"devices", "list", "--stale-days", "soon", "--json"}, 2, "usage"},
		{[]string{"devices", "get", "--json"}, 2, "usage"},
		{[]string{"--json", "docs", "--bogus"}, 2, "usage"},
		{[]string{"--json", "docs", "extra"}, 2, "usage"},
		{[]string{"--json", "docs", "--check", missingDocs}, 2, "usage"},
		{[]string{"--json", "docs", "--check", staleDocs}, 1, "conflict"},
		{[]string{"docs", "--bogus", "--json"}, 2, "usage"},
		{[]string{"--json", "scopes", "--bogus"}, 2, "usage"},
		{[]string{"scopes", "--bogus", "--json"}, 2, "usage"},
		{[]string{"--json", "scopes", "extra"}, 2, "usage"},
		{[]string{"--json", "doctor", "--bogus"}, 2, "usage"},
		{[]string{"doctor", "--bogus", "--json"}, 2, "usage"},
		{[]string{"--json", "audit", "verify", "--bogus"}, 2, "usage"},
		{[]string{"--json", "audit", "verify", "extra"}, 2, "usage"},
		{[]string{"audit", "tail", "extra", "--json"}, 2, "usage"},
		{[]string{"devices", "list", "--format", "json", "--bogus"}, 2, "usage"},
		{[]string{"devices", "list", "-format", "json", "--bogus"}, 2, "usage"},
		{[]string{"devices", "list", "--format=json", "--bogus"}, 2, "usage"},
		{[]string{"devices", "list", "-format=json", "--bogus"}, 2, "usage"},
		{[]string{"--bogus", "devices", "list", "--format=json"}, 2, "usage"},
		{[]string{"scopes", "--format", "json", "--bogus"}, 2, "usage"},
		{[]string{"doctor", "--format=json", "--bogus"}, 2, "usage"},
	} {
		h := newHarness(t, nil)
		if code := h.run(c.args...); code != c.exit {
			t.Errorf("%v: exit %d, want %d (stderr %q)", c.args, code, c.exit, h.err)
		}
		if got := jsonError(t, strings.Join(c.args, " "), h.out.String()); got != c.code {
			t.Errorf("%v: error code %q, want %q", c.args, got, c.code)
		}
		if h.err.Len() != 0 {
			t.Errorf("%v: stderr = %q, want nothing", c.args, h.err)
		}
	}
}

// A "--json" after the terminator is an argument, not the switch: the error is text.
func TestJSONAfterTheTerminatorIsNotTheSwitch(t *testing.T) {
	for _, args := range [][]string{
		{"devices", "list", "--bogus", "--", "--json"},
		{"scopes", "--bogus", "--", "--json"},
		{"doctor", "--bogus", "--", "--json"},
		{"audit", "tail", "extra", "--", "--json"},
		{"devices", "list", "--bogus", "--", "--format", "json"},
		{"devices", "list", "--format", "text", "--bogus"},
		{"devices", "list", "--format=text", "--bogus"},
		{"devices", "list", "--bogus", "--json=yes"},
		{"devices", "list", "--bogus", "--json=0"},
	} {
		h := newHarness(t, nil)
		if code := h.run(args...); code != 2 || h.out.Len() != 0 || !strings.Contains(h.err.String(), "tailkeeper: usage:") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want the text form on stderr and nothing on stdout", args, code, h.out, h.err)
		}
	}
	for _, c := range []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"--json"}, true},
		{[]string{"-json"}, true},
		{[]string{"--json=false"}, false},
		{[]string{"--json", "--json=false"}, false},
		{[]string{"--json=false", "--json"}, true},
		{[]string{"--json", "--", "x"}, true},
		{[]string{"--", "--json"}, false},
		{[]string{"x", "--", "--json"}, false},
		{[]string{"--json=false", "--", "--json"}, false},
		{[]string{"--json", "--", "--json=false"}, true},
		// Two known approximations: jsonRequested does not know which flags take a
		// value, so it only reads the arguments. A flag's value that spells --json
		// counts as the switch (a command line that failed to parse is the only
		// place this answer is used), and scanning stops at a "--" even when a flag
		// took it as its value.
		{[]string{"devices", "list", "--tag", "--json", "--bogus"}, true},
		{[]string{"devices", "routes", "--context", "--", "--bogus", "--json"}, false},
		// --format json is --json, in all four spellings; the two-token form
		// consumes its value, and the last --format wins.
		{[]string{"--format", "json"}, true},
		{[]string{"-format", "json"}, true},
		{[]string{"--format=json"}, true},
		{[]string{"-format=json"}, true},
		{[]string{"--format", "text"}, false},
		{[]string{"--format=text", "--bogus"}, false},
		{[]string{"--format", "json", "--format", "text"}, false},
		{[]string{"--format=text", "--format=json"}, true},
		{[]string{"--format", "json", "--json=false"}, true},
		{[]string{"--format", "--json"}, false},
		{[]string{"--format"}, false},
		{[]string{"--format", "json", "--", "x"}, true},
		{[]string{"--", "--format", "json"}, false},
		{[]string{"--format", "--", "json"}, false},
		{[]string{"--format=text", "--json"}, true},
		// --json takes every spelling of a boolean that the flag package takes; a
		// value that is not one is not the switch.
		{[]string{"--json=1"}, true},
		{[]string{"--json=t"}, true},
		{[]string{"--json=T"}, true},
		{[]string{"--json=TRUE"}, true},
		{[]string{"--json=True"}, true},
		{[]string{"-json=1"}, true},
		{[]string{"--json=0"}, false},
		{[]string{"--json=f"}, false},
		{[]string{"--json=F"}, false},
		{[]string{"--json=FALSE"}, false},
		{[]string{"--json=False"}, false},
		{[]string{"--json", "--json=0"}, false},
		{[]string{"--json=0", "--json=1"}, true},
		{[]string{"--json=yes"}, false},
		{[]string{"--json=tRuE"}, false},
		{[]string{"--json="}, false},
		{[]string{"--json=2"}, false},
		{[]string{"--json", "--json=yes"}, true},
		{[]string{"--json=1", "--", "--json=0"}, true},
		{[]string{"--format=text", "--json=1"}, true},
	} {
		if got := jsonRequested(c.args); got != c.want {
			t.Errorf("jsonRequested(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

// A failed re-exec and a result that cannot be printed are error paths too.
func TestJSONForAFailedReexecAndAnUnprintableResult(t *testing.T) {
	h := newHarness(t, nil)
	h.app.Env.APIErr = creds.ErrReexecRequired
	h.app.Provider = config.Provider{Provider: "exec", Command: []string{"/usr/local/bin/op", "run", "--"}}
	if code := h.run("--json", "devices", "list"); code != 5 || jsonError(t, "reexec", h.out.String()) != "credential_unavailable" || h.err.Len() != 0 {
		t.Errorf("failed re-exec: exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
	h = newHarness(t, nil)
	h.app.Env.APIErr = creds.ErrReexecRequired
	h.r.Reexec = nil
	if code := h.run("--json", "devices", "list"); code != 5 || jsonError(t, "no reexec", h.out.String()) != "credential_unavailable" {
		t.Errorf("no re-exec: exit %d, stdout %q", code, h.out)
	}
	// Standard output is gone: the JSON error cannot be delivered there, so the text
	// form goes to standard error and the exit code still says the print failed.
	h = newHarness(t, nil)
	h.r.Stdout = brokenWriter{}
	if code := h.run("--json", "version"); code != 1 || !strings.Contains(h.err.String(), "cannot print the result") {
		t.Errorf("unprintable: exit %d, stderr %q", code, h.err)
	}
	h = newHarness(t, nil)
	h.r.Stdout = brokenWriter{}
	if code := h.run("--json", "nowhere", "list"); code != 2 || !strings.Contains(h.err.String(), "usage") {
		t.Errorf("unprintable error: exit %d, stderr %q; want the text form on stderr", code, h.err)
	}
}

// Without --json a mistyped flag gets the message and the way to the usage, not
// the flag package's list of every flag.
func TestAFlagErrorDoesNotDumpEveryFlag(t *testing.T) {
	h := newHarness(t, nil)
	if code := h.run("devices", "list", "--bogus"); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if got := h.err.String(); !strings.Contains(got, "flag provided but not defined: -bogus") || strings.Contains(got, "-os value") ||
		!strings.Contains(got, "see `tailkeeper devices list --help`") {
		t.Errorf("stderr = %q", got)
	}
	// --help is not an error: the usage, and exit 0.
	h = newHarness(t, nil)
	if code := h.run("devices", "list", "--help"); code != 0 || !strings.Contains(h.err.String(), "Usage: tailkeeper devices list") || !strings.Contains(h.err.String(), "-os value") {
		t.Errorf("--help: exit %d, stderr %q", code, h.err)
	}
	for _, cmd := range []string{"docs", "scopes", "doctor", "mcp"} {
		h = newHarness(t, nil)
		if code := h.run(cmd, "--help"); code != 0 || !strings.Contains(h.err.String(), "Usage of tailkeeper "+cmd) {
			t.Errorf("%s --help: exit %d, stderr %q", cmd, code, h.err)
		}
	}
}

// A "--" that a flag takes as its value does not end the flags.
func TestDoubleDashAsAFlagValueIsNotATerminator(t *testing.T) {
	parse := func(args ...string) (ctx string, json bool, pos []string, err error) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		c := fs.String("context", "", "")
		j := fs.Bool("json", false, "")
		pos, err = parseInterspersed(fs, args)
		return *c, *j, pos, err
	}
	for _, c := range []struct {
		name string
		args []string
		ctx  string
		json bool
		pos  []string
	}{
		{"the value of a flag", []string{"--context", "--", "web-1", "--json"}, "--", true, []string{"web-1"}},
		{"the value after an equals sign", []string{"--context=--", "web-1", "--json"}, "--", true, []string{"web-1"}},
		{"a real terminator", []string{"web-1", "--", "--json"}, "", false, []string{"web-1", "--json"}},
		{"a real terminator first", []string{"--", "a", "b"}, "", false, []string{"a", "b"}},
		{"a flag, then a real terminator", []string{"--json", "--", "-x"}, "", true, []string{"-x"}},
		{"a value of a flag, then a real terminator", []string{"--context", "--", "--", "a"}, "--", false, []string{"a"}},
		{"a bare dash is an argument", []string{"-", "--json"}, "", true, []string{"-"}},
		{"no arguments", nil, "", false, nil},
	} {
		ctx, js, pos, err := parse(c.args...)
		if err != nil || ctx != c.ctx || js != c.json || strings.Join(pos, "|") != strings.Join(c.pos, "|") {
			t.Errorf("%s: context %q, json %v, positional %v, err %v; want %q, %v, %v", c.name, ctx, js, pos, err, c.ctx, c.json, c.pos)
		}
	}
	// End to end: the issue's own example.
	f := apitest.New(t)
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/devices", 200, `{"devices":[{"nodeId":"nAAA1CNTRL","hostname":"web-1"}]}`)
	f.JSON("GET", "/api/v2/device/nAAA1CNTRL/routes", 200, `{"advertisedRoutes":[],"enabledRoutes":[]}`)
	h := newHarness(t, f)
	if code := h.run("devices", "routes", "--context", "--", "web-1", "--json"); code != 0 || !strings.HasPrefix(strings.TrimSpace(h.out.String()), "{") {
		t.Errorf("devices routes --context -- web-1 --json: exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
}

// version, audit verify and audit rotate print JSON under --json, as design.md
// says --json does everywhere.
func TestJSONSuccessForVersionAndAudit(t *testing.T) {
	h := newDNSHarness(t)
	if code := h.run("--json", "version"); code != 0 {
		t.Fatalf("version: exit %d", code)
	}
	var v struct{ Version string }
	if err := json.Unmarshal(h.out.Bytes(), &v); err != nil || v.Version == "" {
		t.Errorf("version JSON = %q (%v)", h.out, err)
	}
	h.run("dns", "get")
	h.out.Reset()
	if code := h.run("--json", "audit", "verify"); code != 0 {
		t.Fatalf("audit verify: exit %d, %s", code, h.err)
	}
	var segs struct {
		Segments []struct {
			Path    string
			Lines   int
			Missing bool
		}
	}
	if err := json.Unmarshal(h.out.Bytes(), &segs); err != nil || len(segs.Segments) != 1 || segs.Segments[0].Lines != 1 ||
		segs.Segments[0].Path != h.app.AuditPath {
		t.Errorf("audit verify JSON = %q (%v)", h.out, err)
	}
	h.out.Reset()
	if code := h.run("audit", "verify", "--json"); code != 0 || !strings.HasPrefix(strings.TrimSpace(h.out.String()), "{") {
		t.Errorf("audit verify --json: exit %d, %q", code, h.out)
	}
	if !audit.RotateSupported() {
		return
	}
	h.out.Reset()
	if code := h.run("--json", "audit", "rotate"); code != 0 {
		t.Fatalf("audit rotate: exit %d, %s", code, h.err)
	}
	var rot struct{ Log, Archive string }
	if err := json.Unmarshal(h.out.Bytes(), &rot); err != nil || rot.Log != h.app.AuditPath || rot.Archive == "" {
		t.Errorf("audit rotate JSON = %q (%v)", h.out, err)
	}
}

// scopes takes --json after the command too, as the tool commands do.
func TestScopesTakesJSONAfterTheCommand(t *testing.T) {
	h := newHarness(t, nil)
	if code := h.run("scopes", "--json"); code != 0 || !strings.HasPrefix(strings.TrimSpace(h.out.String()), "{") {
		t.Errorf("scopes --json: exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
}

// docs writes the reference to standard output: a write that fails is exit 1, not 0.
func TestDocsFailsWhenItCannotWrite(t *testing.T) {
	h := newHarness(t, nil)
	h.r.Stdout = brokenWriter{}
	if code := h.run("docs"); code != 1 || !strings.Contains(h.err.String(), "cannot print the result") {
		t.Errorf("exit %d, stderr %q", code, h.err)
	}
}

// doctor keeps its own exit code unless the report could not be printed, which is
// exit 1 where it would have been 0.
func TestFoldWriteError(t *testing.T) {
	broken := errors.New("broken pipe")
	for _, c := range []struct {
		rc   int
		err  error
		want int
	}{{0, nil, 0}, {8, nil, 8}, {0, broken, 1}, {8, broken, 8}, {7, broken, 7}} {
		if got := foldWriteError(c.rc, c.err); got != c.want {
			t.Errorf("foldWriteError(%d, %v) = %d, want %d", c.rc, c.err, got, c.want)
		}
	}
}

// Build errors keep their own codes and still arrive as JSON.
func TestJSONForABuildError(t *testing.T) {
	h := newHarness(t, nil)
	h.r.Build = func(context.Context, string) (*app.App, error) {
		return nil, tkerr.New(tkerr.ConfigMissing, "no configuration", "")
	}
	if code := h.run("--json", "audit", "tail"); code != 6 || jsonError(t, "audit tail", h.out.String()) != "config_missing" {
		t.Errorf("exit %d, stdout %q", code, h.out)
	}
}

// A stale reference file keeps exit 1 and its message, in the error form: the same
// text for people, the JSON document under --json, and the program hint's place
// taken by the command that regenerates it.
func TestDocsCheckOfAStaleFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale.md")
	if err := os.WriteFile(path, []byte("not the generated reference\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, nil)
	if code := h.run("docs", "--check", path); code != 1 || h.out.Len() != 0 ||
		!strings.Contains(h.err.String(), "tailkeeper: conflict: ") || !strings.Contains(h.err.String(), "is stale") ||
		!strings.Contains(h.err.String(), "fix: regenerate it with `tailkeeper docs > ") {
		t.Errorf("text: exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
	h = newHarness(t, nil)
	if code := h.run("--json", "docs", "--check", path); code != 1 {
		t.Fatalf("json: exit %d", code)
	}
	var e struct {
		Error struct{ Message, Hint string }
	}
	if err := json.Unmarshal(h.out.Bytes(), &e); err != nil || !strings.Contains(e.Error.Message, "is stale") ||
		!strings.Contains(e.Error.Hint, "regenerate it with `tailkeeper docs > ") {
		t.Errorf("json: %q (%v)", h.out, err)
	}
}

// writeCounter fails every write and counts them.
type writeCounter struct{ n int }

func (w *writeCounter) Write([]byte) (int, error) { w.n++; return 0, errors.New("broken pipe") }

// doctor with a standard output that cannot be written: the report's own exit code
// stays (8 stays 8, 0 becomes 1), the error is said in text on standard error, and
// nothing more is written to the dead output after the first failed write.
func TestDoctorWhenStandardOutputIsGone(t *testing.T) {
	failing := func(h *harness) {
		h.r.Build = func(context.Context, string) (*app.App, error) {
			return nil, tkerr.New(tkerr.ConfigUnsafe, "config.hujson is writable by others", "chmod 600 config.hujson")
		}
	}
	for _, c := range []struct {
		name string
		args []string
		pre  func(*harness)
		exit int
	}{
		{"findings, text", []string{"doctor"}, failing, 8},
		{"findings, json", []string{"--json", "doctor"}, failing, 8},
	} {
		h := newHarness(t, nil)
		if c.pre != nil {
			c.pre(h)
		}
		w := &writeCounter{}
		h.r.Stdout = w
		if code := h.run(c.args...); code != c.exit || !strings.Contains(h.err.String(), "cannot print the result") {
			t.Errorf("%s: exit %d, want %d; stderr %q", c.name, code, c.exit, h.err)
		}
		if w.n != 1 {
			t.Errorf("%s: %d writes to the dead standard output, want 1", c.name, w.n)
		}
	}
}

// A report with no finding has exit code 0: when it cannot be printed that becomes
// 1, and a hint line after the table is not written to the dead output either.
func TestPrintReportWhenStandardOutputIsGone(t *testing.T) {
	rep := doctor.Report{Checks: []doctor.Check{{Name: "audit log", Status: doctor.Warn, Detail: "d", Hint: "fix it"}}}
	for _, asJSON := range []bool{false, true} {
		h := newHarness(t, nil)
		w := &writeCounter{}
		h.r.Stdout = w
		if code := h.r.printReport(rep, asJSON); code != 1 || w.n != 1 || !strings.Contains(h.err.String(), "cannot print the result") {
			t.Errorf("json %v: exit %d, %d writes, stderr %q; want exit 1, one write, the text error", asJSON, code, w.n, h.err)
		}
	}
	h := newHarness(t, nil)
	if code := h.r.printReport(rep, false); code != 0 || !strings.Contains(h.out.String(), "fix audit log: fix it") || h.err.Len() != 0 {
		t.Errorf("working output: exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
}

// The text form of an error keeps CI log commands out of both of its lines: a
// message or a hint can hold text from the tailnet or from the command line.
func TestTheTextFormOfAnErrorHoldsNoCILogCommand(t *testing.T) {
	h := newHarness(t, nil)
	code := h.r.fail(tkerr.New(tkerr.NotFound, "no such thing ##vso[task.setvariable variable=x]y", "try ##teamcity[buildProblem description='x'] again"), false)
	if code == 0 || h.out.Len() != 0 {
		t.Errorf("exit %d, stdout %q", code, h.out)
	}
	got := h.err.String()
	if strings.Contains(got, "##vso[") || strings.Contains(got, "##teamcity[") {
		t.Errorf("the error text holds a CI log command: %q", got)
	}
	if !strings.HasPrefix(got, "tailkeeper: not_found: no such thing ") || !strings.Contains(got, "#vso[task.setvariable variable=x]y") ||
		!strings.Contains(got, "\n  fix: try ") || !strings.Contains(got, "#teamcity[buildProblem") {
		t.Errorf("the error text lost its words: %q", got)
	}
}

// Every spelling of true that the flag package takes asks for JSON when the command
// line cannot be parsed, as --json=true does.
func TestAnErrorIsJSONForEveryBooleanSpellingOfTheSwitch(t *testing.T) {
	for _, spelling := range []string{"true", "1", "t", "T", "TRUE", "True"} {
		h := newHarness(t, nil)
		code := h.run("devices", "list", "--bogus", "--json="+spelling)
		if code != 2 || h.err.Len() != 0 || jsonError(t, spelling, h.out.String()) != "usage" {
			t.Errorf("--json=%s: exit %d, stdout %q, stderr %q; want a JSON usage error", spelling, code, h.out, h.err)
		}
	}
}
