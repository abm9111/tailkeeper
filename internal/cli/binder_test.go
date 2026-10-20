package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/safefile"
)

// countingReader records how many times it is read.
type countingReader struct {
	data  *bytes.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) { c.reads++; return c.data.Read(p) }

func newCounting(s string) *countingReader { return &countingReader{data: bytes.NewReader([]byte(s))} }

// fixtureHarness is a harness for the test tool whose credential has to come from
// the exec provider's wrapper, with counts of Build runs and tool runs.
func fixtureHarness(t *testing.T) (h *harness, builds, ran *int) {
	t.Helper()
	h = newHarness(t, nil)
	ran = withFixture(t, h)
	h.app.Env.APIErr = creds.ErrReexecRequired
	h.app.Provider = config.Provider{Provider: "exec", Command: []string{"/usr/local/bin/op", "run", "--"}}
	builds = new(int)
	h.r.Build = func(context.Context, string) (*app.App, error) { *builds++; return h.app, nil }
	return h, builds, ran
}

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func decodeFixture(t *testing.T, stdout string) fixtureOut {
	t.Helper()
	var out fixtureOut
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not the tool's JSON: %q (%v)", stdout, err)
	}
	return out
}

// The files reach the tool byte for byte: a BOM and CRLF are the engine's to count.
func TestFilesFillTheFieldsTheirFlagsNameAndNothingElse(t *testing.T) {
	h, _, ran := fixtureHarness(t)
	h.app.Env.APIErr = nil // the credential is there: this test is about the fields
	const policy = "\xef\xbb\xbf{\r\n  // comment\r\n}\r\n"
	from, against, inv := writeFile(t, "new.hujson", policy), writeFile(t, "old.hujson", "{}\n"), writeFile(t, "inv.hujson", `{"tests":[]}`)
	if code := h.run("--json", "fixture", "check", "--name", "x", "--from", from, "--against", against, "--invariants", inv, "--no-invariants"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	out := decodeFixture(t, h.out.String())
	// The tool's result shows every invisible character as a visible escape, so the
	// BOM and each CR and LF of the file are checked byte for byte through it: a
	// binder that stripped the BOM or turned CRLF into LF would change this text.
	const wantPolicy = `\u{FEFF}{\u{000D}\u{000A}  // comment\u{000D}\u{000A}}\u{000D}\u{000A}`
	if out.Name != "x" || out.Policy != wantPolicy || out.Against != `{}\u{000A}` || out.Invariants != `{"tests":[]}` ||
		out.Patch != "" || !out.NoInvariants || out.Offline || *ran != 1 {
		t.Errorf("out = %+v after %d runs", out, *ran)
	}
}

// A policy never travels in argv, and the invariants and the offline switch are not
// part of what an MCP caller can send.
func TestNoFlagOrMCPFieldCarriesTheTextOrThePath(t *testing.T) {
	h, _, _ := fixtureHarness(t)
	for _, flag := range []string{"--policy", "--patch-text", "--invariants-text", "--no-invariants=maybe"} {
		h.err.Reset()
		if code := h.run("fixture", "check", flag, "x"); code != 2 {
			t.Errorf("%s: exit %d, want 2 (stderr %q)", flag, code, h.err)
		}
	}
	h.err.Reset()
	if code := h.run("fixture", "check", "--policy", "{}"); code != 2 || !strings.Contains(h.err.String(), "flag provided but not defined: -policy") {
		t.Errorf("--policy: exit %d, stderr %q; want it undefined: the text must not travel in argv", code, h.err)
	}
	reg := fixtureRegistry(new(int))
	tool, _ := reg.Get("fixture_check")
	for _, name := range []string{"invariants", "noInvariants", "offline"} {
		if _, ok := tool.InputSchema.Properties[name]; ok {
			t.Errorf("the MCP schema has a %q property: a caller could send what only the command line may", name)
		}
		_, err := tool.Validate(json.RawMessage(`{"` + name + `":"x"}`))
		if err == nil {
			t.Errorf("an MCP call with %q was accepted", name)
		}
	}
	for _, name := range []string{"policy", "patch", "against", "name"} {
		if _, ok := tool.InputSchema.Properties[name]; !ok {
			t.Errorf("the MCP schema lacks %q", name)
		}
	}
}

// Everything the binder can refuse without reading is refused before Build and
// before the wrapper, and nothing was read.
func TestTheBinderRefusesBeforeBuildAndBeforeAnyRead(t *testing.T) {
	good := writeFile(t, "good.hujson", "{}")
	big := writeFile(t, "big.hujson", strings.Repeat("x", safefile.MaxBytes+1))
	link := filepath.Join(t.TempDir(), "link.hujson")
	haveLink := os.Symlink(good, link) == nil
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"a missing file":                 {[]string{"--from", filepath.Join(t.TempDir(), "nope.hujson")}, "cannot inspect"},
		"a directory":                    {[]string{"--from", t.TempDir()}, "is not a regular file"},
		"a file over the cap":            {[]string{"--from", big}, "more than the 4194304 bytes"},
		"two sources of one proposal":    {[]string{"--from", good, "--patch", good}, "--from and --patch both give the proposal"},
		"standard input for two sources": {[]string{"--from", "-", "--against", "-"}, "standard input can be read once"},
		"an empty path":                  {[]string{"--from", ""}, "--from needs a file name"},
		"a symlink":                      {[]string{"--from", link}, "symbolic link"},
	} {
		if name == "a symlink" && !haveLink {
			continue
		}
		h, builds, ran := fixtureHarness(t)
		stdin := newCounting("{}")
		h.r.Stdin = stdin
		code := h.run(append([]string{"fixture", "check"}, c.args...)...)
		if code != 2 || !strings.Contains(h.err.String(), c.want) {
			t.Errorf("%s: exit %d, stderr %q; want 2 and %q", name, code, h.err, c.want)
		}
		if h.reexecProvider != nil || *builds != 0 || *ran != 0 || stdin.reads != 0 {
			t.Errorf("%s: wrapper started %v, Build ran %d times, the tool ran %d times, stdin read %d times; want none", name, h.reexecProvider != nil, *builds, *ran, stdin.reads)
		}
	}
}

// --against live names the live policy: the field stays empty, as if the flag were
// not there, and a file named live is reached as ./live.
func TestAgainstLiveLeavesTheFieldEmpty(t *testing.T) {
	h, _, ran := fixtureHarness(t)
	h.app.Env.APIErr = nil
	if code := h.run("--json", "fixture", "check", "--against", "live"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	if out := decodeFixture(t, h.out.String()); out.Against != "" || *ran != 1 {
		t.Errorf("out = %+v", out)
	}
	if runtime.GOOS == "windows" {
		return
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "live"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(wd) }()
	h.out.Reset()
	if code := h.run("--json", "fixture", "check", "--against", "./live"); code != 0 || decodeFixture(t, h.out.String()).Against != "{}" {
		t.Errorf("./live: exit %d, %s", code, h.out)
	}
}

// Whether the wrapper starts follows the flags: --offline, or a file on both
// sides, needs no credential; one file and the live policy does.
func TestOfflineFlagsDecideWhetherTheWrapperStarts(t *testing.T) {
	a, b := writeFile(t, "a.hujson", "{}"), writeFile(t, "b.hujson", "{}")
	for name, c := range map[string]struct {
		args    []string
		wrapper bool
	}{
		"--offline":               {[]string{"--offline", "--from", a}, false},
		"a file on both sides":    {[]string{"--from", a, "--against", b}, false},
		"one side and live":       {[]string{"--from", a}, true},
		"--offline=false":         {[]string{"--offline=false", "--from", a}, true},
		"one side, against live":  {[]string{"--from", a, "--against", "live"}, true},
		"no file":                 {nil, true},
		"patch against live only": {[]string{"--patch", a}, true},
	} {
		h, builds, ran := fixtureHarness(t)
		h.run(append([]string{"--json", "fixture", "check"}, c.args...)...)
		if started := h.reexecProvider != nil; started != c.wrapper || *builds != 1 {
			t.Errorf("%s: wrapper started %v (want %v), Build ran %d times (want 1)", name, started, c.wrapper, *builds)
		}
		if !c.wrapper && (*ran != 1 || h.out.Len() == 0) {
			t.Errorf("%s: the tool ran %d times and printed %q; an offline call runs in this process", name, *ran, h.out)
		}
	}
}

// Standard input is read once, by the process that runs the tool, and not before
// the wrapper starts.
func TestStandardInputIsReadOnceAfterTheWrapper(t *testing.T) {
	h, _, _ := fixtureHarness(t)
	stdin := newCounting("{\"a\": 1}")
	h.r.Stdin = stdin
	h.run("--json", "fixture", "check", "--from", "-")
	if h.reexecProvider == nil || stdin.reads != 0 {
		t.Fatalf("before the wrapper: started %v, stdin read %d times; want the wrapper started and stdin untouched", h.reexecProvider != nil, stdin.reads)
	}
	// After the wrapper (the credential is there) the same command reads it once.
	h.app.Env.APIErr = nil
	h.out.Reset()
	if code := h.run("--json", "fixture", "check", "--from", "-"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	if out := decodeFixture(t, h.out.String()); out.Policy != "{\"a\": 1}" || stdin.reads == 0 {
		t.Errorf("out = %+v, stdin read %d times", out, stdin.reads)
	}
	// The cap applies to a stream too.
	h.r.Stdin = strings.NewReader(strings.Repeat("x", safefile.MaxBytes+1))
	h.err.Reset()
	if code := h.run("fixture", "check", "--from", "-"); code != 2 || !strings.Contains(h.err.String(), "standard input is more than the 4194304 bytes") {
		t.Errorf("a long stream: exit %d, stderr %q", code, h.err)
	}
}

// Every flag the binder builds is checked against the ones that exist, and every
// tool's tags are well formed, so a typo in a tag fails here, not in a user's shell.
func TestEveryToolBindsToFlags(t *testing.T) {
	regs := map[string]*registry.Registry{"product": newRegistry(), "fixture": fixtureRegistry(new(int))}
	for which, reg := range regs {
		for _, tool := range reg.All() {
			fs := newFlags("t")
			// The flags the command line registers before the tool's own: a field of
			// a tool that takes one of these names must fail here.
			fs.Bool("json", false, "")
			fs.String("context", "", "")
			fs.String("format", "", "")
			fs.Bool("quiet", false, "")
			fs.Var(&listValue{}, "fail-on", "")
			if _, err := bind(fs.FlagSet, tool.InputType, func(string) string { return "" }); err != nil {
				t.Errorf("%s tool %s: %v", which, tool.Meta.Name, err)
			}
		}
	}
	type bad struct {
		A string `json:"a" cli:"file:from,teapot"`
	}
	type clash struct {
		A string `json:"-" cli:"file:json"`
	}
	type wrongKind struct {
		A int `json:"-" cli:"file:from"`
	}
	type twice struct {
		A string `json:"-" cli:"file:from"`
		B string `json:"-" cli:"file:from"`
	}
	type unknownKind struct {
		A string `json:"-" cli:"banana:from"`
	}
	for name, typ := range map[string]any{"unknown option": bad{}, "reserved flag": clash{}, "wrong field kind": wrongKind{}, "a flag twice": twice{}, "unknown kind": unknownKind{}} {
		fs := newFlags("t")
		fs.Bool("json", false, "")
		if _, err := bind(fs.FlagSet, reflectTypeOf(typ), func(string) string { return "" }); err == nil {
			t.Errorf("%s: bind accepted a bad tag", name)
		}
	}
}

// untaggedTextFields lists the fields of an input type whose JSON name says they
// hold a policy, a patch or invariants but which carry no cli tag. Without a tag
// such a field becomes a flag named after it, and a policy would travel in argv.
func untaggedTextFields(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		switch name {
		case "policy", "patch", "against", "invariants", "proposal", "text":
			if f.Tag.Get("cli") == "" {
				out = append(out, f.Name)
			}
		}
	}
	return out
}

func TestPolicyTextNeverBecomesAFlag(t *testing.T) {
	for which, reg := range map[string]*registry.Registry{"product": newRegistry(), "fixture": fixtureRegistry(new(int))} {
		for _, tool := range reg.All() {
			if bad := untaggedTextFields(tool.InputType); len(bad) > 0 {
				t.Errorf("%s tool %s: fields %v hold policy text and have no cli tag, so they would be flags", which, tool.Meta.Name, bad)
			}
		}
	}
	// The check must be able to fail.
	type planted struct {
		Policy string `json:"policy,omitempty"`
		Ok     string `json:"patch,omitempty" cli:"file:patch"`
		Other  string `json:"name,omitempty"`
	}
	if got := untaggedTextFields(reflect.TypeOf(planted{})); len(got) != 1 || got[0] != "Policy" {
		t.Errorf("untaggedTextFields(planted) = %v, want [Policy]", got)
	}
}
