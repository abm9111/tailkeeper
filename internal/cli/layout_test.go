package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/layout and testdata/format")

// hostile is text no output may carry through: a line of its own that looks like a
// workflow command, and a sequence that moves a terminal.
const hostile = "\n::error::x\x1b[2J"

// layoutCases are the reports the human layout is checked on. Each is rendered
// without colour and with it, and compared with testdata/layout/<name>.golden and
// <name>.color.golden. The goldens are the contract: read them in a diff.
var layoutCases = []struct {
	name  string
	rep   registry.Report
	names map[string]string
}{
	{"valid", registry.Report{
		Verdict:    "VALID · 0 new warnings (3 existing) · 14 tests passed · invariants: none",
		Level:      registry.LevelOK,
		NotChecked: []string{"lockout", "downgrades", "access change"},
		Classes: []registry.ClassCount{{Class: "defaults"}, {Class: "tests reduced"}, {Class: "widening"},
			{Class: "tailscale-written", Count: 2, Expected: true}, {Class: "semantic", Count: 1}},
	}, nil},
	{"gated", registry.Report{
		Verdict: "VALID · 1 new warning (0 existing) · 9 tests passed · invariants: 4",
		Level:   registry.LevelWarn,
		Classes: []registry.ClassCount{{Class: "defaults", Count: 1}, {Class: "tests reduced", Count: 3}, {Class: "widening", Count: 2},
			{Class: "semantic", Count: 14}},
		Findings: []registry.Finding{{Severity: "warning", Source: "from", Line: 7, Column: 3, Message: "the group group:eng is not used"}},
	}, map[string]string{"from": "policy.hujson"}},
	{"failed", registry.Report{
		Verdict: "FAILED · 2 assertions failed · 12 tests passed · invariants: 4",
		Level:   registry.LevelFail,
		Findings: []registry.Finding{
			{Severity: "error", Source: "from", Line: 31, Column: 9, Message: "tag:ci must reach tag:prod:22 and cannot"},
			{Severity: "error", Source: "invariants", Line: 4, Message: "invariant 2: group:admins must not reach tag:db:5432"},
		},
	}, map[string]string{"from": "policy.hujson", "invariants": "invariants.hujson"}},
	{"rejected", registry.Report{
		Verdict: "REJECTED · the server refused the policy",
		Level:   registry.LevelFail,
		Findings: []registry.Finding{
			{Severity: "error", Source: "from", Line: 12, Column: 5, Message: "unknown section nodeAttr; did you mean nodeAttrs?"},
			{Severity: "error", Source: "from", Message: "json: unknown field \"nodeAttr\"", Untrusted: true},
			{Severity: "error", Source: "patch", Pointer: "/grants/0/ip", Message: "a grant needs ip or app", Untrusted: true},
			{Severity: "error", Source: "live", Message: "the live policy does not validate", Untrusted: true},
			{Severity: "notice", Message: "no location known"},
		},
	}, map[string]string{"from": "policy.hujson", "patch": "change.json"}},
	{"stdin and hostile text", registry.Report{
		Verdict:    "##[error]INVALID ##vso[task.setvariable variable=x]y · 1 problem" + hostile,
		Level:      registry.LevelFail,
		NotChecked: []string{"lockout" + hostile},
		Classes:    []registry.ClassCount{{Class: "semantic" + hostile, Count: 1}, {Class: "::error::x", Count: 2}, {Class: "##[x", Count: 3}},
		Findings: []registry.Finding{
			{Severity: "error", Source: "from", Line: 1, Column: 1, Message: "evil\n::error::forged\x1b[2J\xe2\x80\xae"},
			{Severity: "error", Source: "from", Message: "from Tailscale\n##[error]forged", Untrusted: true},
			{Severity: "warning" + hostile, Source: "against", Line: 2, Message: "a severity that is not ours"},
			{Severity: "error", Source: "elsewhere" + hostile, Message: "a source nobody named"},
			{Severity: "error", Source: "patch", Pointer: "/grants/0" + hostile, Message: "a pointer", Untrusted: true},
			// Text that starts a line is the worst place for it: a log parser acts on
			// a line that begins with :: or ##[ , so these never print at line start.
			{Severity: "error", Source: "invariants", Line: 3, Message: "a path that starts like a command"},
			{Severity: "::x", Message: "a severity that starts like a command"},
			{Severity: "error", Source: "##[x", Message: "a source that starts like a command"},
			{Severity: "error", Source: "live", Message: "a path that starts like an Azure command", Untrusted: true},
			// Azure's logging commands and TeamCity's service messages are acted on
			// wherever they stand in a line, not only at its start.
			{Severity: "error", Source: "from", Line: 4, Message: "mid-line ##vso[task.logissue type=error]boom and again ##vso[task.complete result=Failed;]"},
			{Severity: "error", Source: "from", Message: "##teamcity[buildProblem description='x']", Untrusted: true},
		},
	}, map[string]string{"from": "<stdin>", "patch": "evil.json" + hostile, "invariants": "::error::x", "live": "##[error]forged"}},
	{"verdict only", registry.Report{Verdict: "VALID · 0 new warnings", Level: registry.LevelOK}, nil},
	{"empty", registry.Report{}, nil},
	// The report acl test returns: a verdict, one caveat, and Tailscale's line behind the notice.
	{"test verdict", registry.Report{
		Verdict:    "FAILED · 1 destination not as asked",
		Level:      registry.LevelFail,
		NotChecked: []string{"with proto omitted, a destination that must be denied can yield one line for tcp and one for udp"},
		Findings: []registry.Finding{
			{Severity: "error", Message: "failed  tag:ci: address \"tag:web:22\": want: Accept, got: Drop", Untrusted: true},
		},
	}, nil},
}

func TestTheHumanLayoutMatchesItsGoldens(t *testing.T) {
	for _, c := range layoutCases {
		for _, color := range []bool{false, true} {
			var b bytes.Buffer
			if err := formatText(&b, c.rep, formatOptions{Names: c.names, Color: color}); err != nil {
				t.Fatal(err)
			}
			name := strings.ReplaceAll(c.name, " ", "-")
			if color {
				name += ".color"
			}
			path := filepath.Join("testdata", "layout", name+".golden")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s: %v (run the test with -update to write it)", c.name, err)
			}
			if !bytes.Equal(b.Bytes(), want) {
				t.Errorf("%s (colour %v) differs from %s:\n--- got\n%s--- want\n%s", c.name, color, path, b.String(), want)
			}
		}
	}
}

// The layout, in words: a verdict, what was not checked, counts by class, then
// details with a clickable location; nothing the text holds can start a line of
// its own or move a terminal.
func TestTheLayoutProperties(t *testing.T) {
	var b bytes.Buffer
	rep := layoutCases[3].rep
	if err := formatText(&b, rep, formatOptions{Names: layoutCases[3].names}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.HasPrefix(out, "REJECTED · the server refused the policy\n") {
		t.Errorf("the verdict is not the first line:\n%s", out)
	}
	if !strings.Contains(out, "policy.hujson:12:5: error: unknown section nodeAttr") || !strings.Contains(out, "change.json: error: /grants/0/ip: a grant needs ip or app") {
		t.Errorf("locations are not file:line:column: or file: :\n%s", out)
	}
	// Tailscale's text comes after the notice, our own before it.
	notice := strings.Index(out, registry.UntrustedReasonsNotice+"\n")
	trusted, untrusted := strings.Index(out, "unknown section nodeAttr"), strings.Index(out, "json: unknown field")
	if notice < 0 || trusted > notice || untrusted < notice {
		t.Errorf("the notice does not separate trusted from untrusted text:\n%s", out)
	}
	var h bytes.Buffer
	if err := formatText(&h, layoutCases[4].rep, formatOptions{Names: layoutCases[4].names, Color: false}); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(h.String(), "\n"), "\n") {
		if strings.HasPrefix(line, "::") || strings.HasPrefix(line, "##[") || strings.ContainsAny(line, "\x1b\xe2\x80\xae") {
			t.Errorf("a line of the output can act on its reader: %q", line)
		}
	}
	// No line of any case, plain or coloured, starts with what a log parser acts on.
	for _, c := range layoutCases {
		for _, color := range []bool{false, true} {
			var b bytes.Buffer
			if err := formatText(&b, c.rep, formatOptions{Names: c.names, Color: color}); err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n") {
				// A colour code in front of the text is the layout's own.
				for _, code := range []string{ansiRed, ansiGreen, ansiYellow} {
					line = strings.TrimPrefix(line, code)
				}
				// A runner trims leading white space, of any kind, before it looks.
				line = strings.TrimLeftFunc(line, unicode.IsSpace)
				if strings.HasPrefix(line, "::") || strings.HasPrefix(line, "##[") {
					t.Errorf("%s (colour %v): a line starts like a log command: %q", c.name, color, line)
				}
				// Azure's and TeamCity's commands are acted on anywhere in a line.
				if strings.Contains(line, "##vso[") || strings.Contains(line, "##teamcity[") {
					t.Errorf("%s (colour %v): a line holds a log command: %q", c.name, color, line)
				}
			}
		}
	}
	// A path the user typed can be anything, as the first thing on its line.
	for _, names := range []map[string]string{{"from": "::error::forged"}, {"from": "##[error]forged"}} {
		var b bytes.Buffer
		rep := registry.Report{Findings: []registry.Finding{{Severity: "error", Source: "from", Line: 1, Message: "m"}}}
		if err := formatText(&b, rep, formatOptions{Names: names}); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(b.String(), "::") || strings.HasPrefix(b.String(), "##[") || !strings.Contains(b.String(), ": error: m") {
			t.Errorf("%v: %q", names, b.String())
		}
	}
	// With colour, the only escapes are the layout's own: nothing the text holds adds one.
	var hc bytes.Buffer
	if err := formatText(&hc, layoutCases[4].rep, formatOptions{Names: layoutCases[4].names, Color: true}); err != nil {
		t.Fatal(err)
	}
	ours := hc.String()
	for _, code := range []string{ansiReset, ansiRed, ansiGreen, ansiYellow} {
		ours = strings.ReplaceAll(ours, code, "")
	}
	if strings.ContainsAny(ours, "\x1b\xe2\x80\xae") {
		t.Errorf("a coloured line holds an escape of its own text: %q", hc.String())
	}
	for _, line := range strings.Split(strings.TrimSuffix(hc.String(), "\n"), "\n") {
		if strings.HasPrefix(line, "::") || strings.HasPrefix(line, "##[") {
			t.Errorf("a coloured line can act on its reader: %q", line)
		}
	}
	// Colour only where it is asked for: the plain layout holds no escape at all.
	for _, c := range layoutCases {
		var plain bytes.Buffer
		if err := formatText(&plain, c.rep, formatOptions{Names: c.names}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(plain.String(), "\x1b") {
			t.Errorf("%s: plain output holds an escape: %q", c.name, plain.String())
		}
	}
	// A zero report prints nothing, and does not fail.
	var z bytes.Buffer
	if err := formatText(&z, registry.Report{}, formatOptions{}); err != nil || z.Len() != 0 {
		t.Errorf("zero report: %q, %v", z.String(), err)
	}
}

// The guard skips the layout's own colour code and any white space a runner would
// trim, keeps that prefix as it is, and escapes the first byte after it; and it
// escapes the first # of every Azure logging command and TeamCity service message,
// wherever it stands in the line.
func TestGuardLine(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                                 "plain",
		"::x":                                   `\u{003A}:x`,
		"##[x":                                  `\u{0023}#[x`,
		"  ::x":                                 `  \u{003A}:x`,
		"\t##[x":                                "\t" + `\u{0023}#[x`,
		"\xc2\xa0::x":                           "\xc2\xa0" + `\u{003A}:x`,
		"\xe2\x80\x83 ##[x":                     "\xe2\x80\x83 " + `\u{0023}#[x`,
		ansiRed + "::x":                         ansiRed + `\u{003A}:x`,
		ansiYellow + "  ##[x":                   ansiYellow + "  " + `\u{0023}#[x`,
		": :x":                                  ": :x",
		"  #[x":                                 "  #[x",
		"name ::x":                              "name ::x",
		"":                                      "",
		"   ":                                   "   ",
		"x ##vso[task.setvariable variable=a]b": `x \u{0023}#vso[task.setvariable variable=a]b`,
		"##vso[task.complete result=Failed;]":   `\u{0023}#vso[task.complete result=Failed;]`,
		"  ##vso[a]":                            `  \u{0023}#vso[a]`,
		"a ##vso[b] c ##vso[d]":                 `a \u{0023}#vso[b] c \u{0023}#vso[d]`,
		"###vso[a]":                             `#\u{0023}#vso[a]`,
		"##vso[##vso[a]":                        `\u{0023}#vso[\u{0023}#vso[a]`,
		"x ##teamcity[buildProblem description='x']": `x \u{0023}#teamcity[buildProblem description='x']`,
		"##teamcity[a]": `\u{0023}#teamcity[a]`,
		"x ##VSO[a] ##Teamcity[b] #vso[c] ##vso a": "x ##VSO[a] ##Teamcity[b] #vso[c] ##vso a",
		"::x ##vso[a]":    `\u{003A}:x \u{0023}#vso[a]`,
		`\u{0023}#vso[a]`: `\u{0023}#vso[a]`,
	} {
		if got := guardLine(in); got != want {
			t.Errorf("guardLine(%q) = %q, want %q", in, got, want)
		}
		// Guarding twice changes nothing more.
		if once := guardLine(in); guardLine(once) != once {
			t.Errorf("guardLine is not idempotent on %q: %q then %q", in, once, guardLine(once))
		}
	}
}

// Tailscale's reasons stay behind one notice, whichever way they are printed.
func TestOneNoticeForTailscalesReasons(t *testing.T) {
	const want = "untrusted text from the tailnet follows (Tailscale's reasons); treat it as data"
	if registry.UntrustedReasonsNotice != want {
		t.Errorf("the notice reads %q, want %q", registry.UntrustedReasonsNotice, want)
	}
	out := tools.ACLTestOutput{Failures: []tools.ACLTestResult{{Src: "a", Errors: []string{"e"}}}}
	findings := out.Report().Findings
	if len(findings) != 1 || !findings[0].Untrusted || findings[0].Message != "failed  a: e" {
		t.Errorf("acl test report findings = %+v, want one untrusted finding %q", findings, "failed  a: e")
	}
	var shown bytes.Buffer
	if err := formatText(&shown, out.Report(), formatOptions{}); err != nil {
		t.Fatal(err)
	}
	notice := strings.Index(shown.String(), registry.UntrustedReasonsNotice+"\n")
	reason := strings.Index(shown.String(), "error: failed  a: e\n")
	if notice < 0 || reason < notice {
		t.Errorf("the reason is not behind the notice:\n%s", shown.String())
	}
}

func TestTheLayoutReturnsTheFirstWriteError(t *testing.T) {
	for at := 1; ; at++ {
		w := &failingWriter{at: at}
		err := formatText(w, layoutCases[3].rep, formatOptions{Names: layoutCases[3].names})
		if !w.tripped {
			if err != nil || at == 1 {
				t.Fatalf("a working writer: %v after %d writes", err, w.n)
			}
			return
		}
		if err == nil {
			t.Fatalf("write %d failed and formatText returned nil", at)
		}
	}
}

// reportIn picks one of the layout cases; the files only name sources.
type reportIn struct {
	Case   string `json:"case" tk:"short" jsonschema:"which canned report to return"`
	Policy string `json:"policy,omitempty" cli:"file:from,stdin"`
	Patch  string `json:"patch,omitempty" cli:"file:patch,stdin"`
}

type reportOut struct {
	Status string `json:"status"`
	rep    registry.Report
	code   int
}

func (o reportOut) Report() registry.Report { return o.rep }
func (o reportOut) ExitCode() int           { return o.code }

// Findings makes the test tool gated, so it takes --fail-on.
func (reportOut) Findings() registry.Findings { return registry.Findings{} }

func reportRegistry() *registry.Registry {
	reg := registry.New()
	reg.MustAdd(registry.Define(registry.Meta{Name: "report_check", Area: "report", Verb: "check", Summary: "A test tool with a human layout.",
		Tier: registry.TierLocal, Stage: registry.StageGA, Credential: registry.CredNone},
		func(_ context.Context, _ *registry.Env, in reportIn) (reportOut, error) {
			for _, c := range formatCases() {
				if c.name == in.Case {
					return reportOut{Status: "reported", rep: c.rep, code: map[registry.Level]int{registry.LevelFail: 2}[c.rep.Level]}, nil
				}
			}
			return reportOut{Status: "reported"}, nil
		}))
	return reg
}

func reportHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, nil)
	reg := reportRegistry()
	h.r.Registry = func() *registry.Registry { return reg }
	return h
}

func TestFormatSelectsTheRenderer(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("policy.hujson", []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := reportHarness(t)
	if code := h.run("report", "check", "--case", "rejected", "--from", "policy.hujson"); code != 2 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	if out := h.out.String(); !strings.HasPrefix(out, "REJECTED · the server refused the policy\n") || !strings.Contains(out, "policy.hujson:12:5: error:") {
		t.Errorf("the default is the human layout, with the file the flag named:\n%s", out)
	}
	for _, args := range [][]string{{"--format", "text"}, {"--format=text"}} {
		h.out.Reset()
		h.run(append([]string{"report", "check", "--case", "valid"}, args...)...)
		if !strings.HasPrefix(h.out.String(), "VALID · 0 new warnings (3 existing)") {
			t.Errorf("%v:\n%s", args, h.out)
		}
	}
	for _, args := range [][]string{{"--format", "json"}, {"--json"}, {"--format", "json", "--json"}} {
		h.out.Reset()
		h.run(append([]string{"report", "check", "--case", "valid"}, args...)...)
		var out struct{ Status string }
		if err := json.Unmarshal(h.out.Bytes(), &out); err != nil || out.Status != "reported" {
			t.Errorf("%v: stdout %q (%v)", args, h.out, err)
		}
	}
	// A format that does not exist, or that contradicts --json, is a usage error.
	for args, want := range map[string]string{
		"--format sarif":       `--format: "sarif" is not one of text, json, github, markdown`,
		"--format xml":         `--format: "xml" is not one of text, json, github, markdown`,
		"--format text --json": "--json and --format text contradict each other",
	} {
		h.err.Reset()
		h.out.Reset()
		// With --json the error arrives as JSON on stdout, otherwise as text on stderr.
		if code := h.run(append([]string{"report", "check", "--case", "valid"}, strings.Fields(args)...)...); code != 2 || !strings.Contains(h.err.String()+h.out.String(), want) {
			t.Errorf("%s: exit %d, stderr %q, stdout %q; want %q", args, code, h.err, h.out, want)
		}
	}
	// A command whose result has no layout takes text and json, nothing else.
	h = newHarness(t, nil)
	if code := h.run("devices", "list", "--format", "text"); code != 2 {
		t.Errorf("devices list --format: exit %d (the flag exists only for results with a layout)", code)
	}
}

// --format json is --json on every error path, including the ones after the flags
// parsed: a stray argument and a bad --fail-on value are checked after the parse.
func TestFormatJSONIsJSONOnTheLaterErrorPaths(t *testing.T) {
	for _, c := range []struct {
		name string
		rest []string
	}{
		{"a stray argument", []string{"extra"}},
		{"a bad --fail-on value", []string{"--fail-on", "bogus"}},
		{"a format that does not exist", []string{"--format", "xml"}},
	} {
		var outs []string
		for _, spelling := range [][]string{{"--format", "json"}, {"--format=json"}, {"--json"}} {
			if c.name == "a format that does not exist" && spelling[0] != "--json" {
				continue // --format cannot be given twice with different values
			}
			h := reportHarness(t)
			args := append([]string{"report", "check", "--case", "valid"}, spelling...)
			if code := h.run(append(args, c.rest...)...); code != 2 {
				t.Errorf("%s %v: exit %d, want 2 (stdout %q, stderr %q)", c.name, spelling, code, h.out, h.err)
			}
			if h.err.Len() != 0 || jsonError(t, c.name, h.out.String()) != "usage" {
				t.Errorf("%s %v: want a JSON usage error on stdout and nothing on stderr: stdout %q, stderr %q", c.name, spelling, h.out, h.err)
			}
			outs = append(outs, h.out.String())
		}
		for _, o := range outs[1:] {
			if o != outs[0] {
				t.Errorf("%s: --format json and --json differ: %q vs %q", c.name, outs[0], o)
			}
		}
	}
	// The same mistakes without --json stay text errors on standard error.
	h := reportHarness(t)
	if code := h.run("report", "check", "--case", "valid", "--format", "text", "extra"); code != 2 || h.out.Len() != 0 || !strings.Contains(h.err.String(), "tailkeeper: usage:") {
		t.Errorf("text: exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
}

// Other formats register in the same table; this test registers one to show the table is the hook.
func TestAFormatInTheTableIsOfferedAndUsed(t *testing.T) {
	formatters["probe"] = func(w io.Writer, rep registry.Report, o formatOptions) error {
		_, err := io.WriteString(w, "PROBE "+rep.Verdict+" "+o.Names["from"]+"\n")
		return err
	}
	defer delete(formatters, "probe")
	h := reportHarness(t)
	if code := h.run("report", "check", "--case", "valid", "--format", "probe"); code != 0 || h.out.String() != "PROBE VALID · 0 new warnings (3 existing) · 14 tests passed · invariants: none \n" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
	h.err.Reset()
	if code := h.run("report", "check", "--case", "valid", "--format", "probe", "--json"); code != 2 || !strings.Contains(h.out.String(), "--json and --format probe contradict each other") {
		t.Errorf("a format of the table with --json: exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
	h.err.Reset()
	if code := h.run("report", "check", "--case", "valid", "--format", "xml"); code != 2 || !strings.Contains(h.err.String(), "not one of text, json, github, markdown, probe") {
		t.Errorf("exit %d, stderr %q; want the table's names listed", code, h.err)
	}
}

// Colour only when standard output is a terminal and NO_COLOR is unset.
func TestColourNeedsATerminalAndNoNoColor(t *testing.T) {
	for _, c := range []struct {
		name     string
		terminal bool
		env      map[string]string
		want     bool
	}{
		{"a terminal", true, nil, true},
		{"not a terminal", false, nil, false},
		{"NO_COLOR set", true, map[string]string{"NO_COLOR": "1"}, false},
		{"NO_COLOR empty is unset", true, map[string]string{"NO_COLOR": ""}, true},
		{"a dumb terminal", true, map[string]string{"TERM": "dumb"}, false},
	} {
		h := reportHarness(t)
		h.r.IsTerminal = func(io.Writer) bool { return c.terminal }
		h.r.Getenv = func(k string) string { return c.env[k] }
		h.run("report", "check", "--case", "valid")
		if got := strings.Contains(h.out.String(), "\x1b[32m"); got != c.want {
			t.Errorf("%s: colour %v, want %v:\n%q", c.name, got, c.want, h.out)
		}
	}
	// The real check: a buffer is not a terminal, a regular file is not one either.
	if isTerminal(&bytes.Buffer{}) {
		t.Error("a buffer is a terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if isTerminal(f) {
		t.Error("a regular file is a terminal")
	}
}

// --quiet and the layout: a pass prints nothing, a failure prints the layout.
func TestQuietWithALayout(t *testing.T) {
	h := reportHarness(t)
	if code := h.run("report", "check", "--case", "valid", "--quiet"); code != 0 || h.out.Len() != 0 {
		t.Errorf("exit %d, stdout %q", code, h.out)
	}
	h.out.Reset()
	if code := h.run("report", "check", "--case", "failed", "--quiet"); code != 2 || !strings.HasPrefix(h.out.String(), "FAILED") {
		t.Errorf("exit %d, stdout %q", code, h.out)
	}
}
