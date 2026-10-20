//go:build !windows

package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/registry"
)

// TestHelperProcess is the process the stand-in wrapper starts in place of the
// re-executed tailkeeper: a Runner with the credential present, the test tool, and
// the real standard input. It does nothing in an ordinary test run.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("TK_CLI_HELPER") != "1" {
		t.Skip("only runs as the re-executed process of the tests below")
	}
	args := os.Args
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	ran := 0
	reg := fixtureRegistry(&ran)
	a := &app.App{Registry: reg, Env: &registry.Env{Now: time.Now}, Context: "helper", Tailnet: apitest.Tailnet, AuditReads: "none"}
	r := &Runner{Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin,
		Registry: func() *registry.Registry { return reg },
		Build:    func(context.Context, string) (*app.App, error) { return a, nil }}
	os.Exit(r.Run(context.Background(), args))
}

// fileReader counts the reads of a file.
type fileReader struct {
	f     *os.File
	reads int
}

func (r *fileReader) Read(p []byte) (int, error) { r.reads++; return r.f.Read(p) }

const pipedPolicy = "// piped in\n{\"acls\": []}\n"

// standIn runs the exec provider's wrapper the way creds.Reexec does, except that
// the wrapper starts the helper process and this one waits: a script that records
// each time it runs, then execs the rest of its arguments.
type standIn struct {
	marker string
	out    bytes.Buffer
	stdin  *os.File
	args   []string
}

func newStandIn(t *testing.T, args []string) *standIn {
	t.Helper()
	dir := t.TempDir()
	s := &standIn{marker: filepath.Join(dir, "wrapper-ran"), args: args}
	script := filepath.Join(dir, "wrapper.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho ran >> \"$TK_MARKER\"\nexec \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(pw, pipedPolicy); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	t.Cleanup(func() { _ = pr.Close() })
	s.stdin = pr
	return s
}

func (s *standIn) reexec(wrapper string) func(config.Provider) error {
	return func(config.Provider) error {
		argv := append([]string{os.Args[0], "-test.run=^TestHelperProcess$", "--"}, s.args...)
		cmd := exec.Command(wrapper, argv...)
		cmd.Env = append(os.Environ(), "TK_CLI_HELPER=1", "TK_MARKER="+s.marker, creds.EnvReexec+"=1")
		cmd.Stdin, cmd.Stdout = s.stdin, &s.out
		return cmd.Run()
	}
}

func (s *standIn) wrapperRuns(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile(s.marker)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "ran\n")
}

// escaped is how the registry shows a policy in a result: line feeds as \u{000A}.
func escaped(s string) string { return strings.ReplaceAll(s, "\n", `\u{000A}`) }

// A policy piped to a command whose credential comes from the exec provider
// reaches the process that holds the credential: the first process starts the
// wrapper without having read standard input, and the process the wrapper starts
// reads it, once. A tool that read it early would hand the wrapper's process an
// empty document.
func TestAPipedPolicyReachesTheProcessThatHoldsTheCredential(t *testing.T) {
	args := []string{"--json", "fixture", "check", "--from", "-"}
	s := newStandIn(t, args)
	h := newHarness(t, nil)
	ran := withFixture(t, h)
	h.app.Env.APIErr = creds.ErrReexecRequired
	h.app.Provider = config.Provider{Provider: "exec", Command: []string{"/ignored"}}
	stdin := &fileReader{f: s.stdin}
	h.r.Stdin = stdin
	h.r.Reexec = s.reexec(filepath.Join(filepath.Dir(s.marker), "wrapper.sh"))
	h.run(args...)
	if stdin.reads != 0 || *ran != 0 {
		t.Errorf("the first process read standard input %d times and ran the tool %d times; want neither", stdin.reads, *ran)
	}
	if n := s.wrapperRuns(t); n != 1 {
		t.Errorf("the wrapper ran %d times, want 1", n)
	}
	if out := decodeFixture(t, s.out.String()); out.Policy != escaped(pipedPolicy) {
		t.Errorf("the re-executed process saw the policy %q, want %q", out.Policy, escaped(pipedPolicy))
	}
}

// With --offline nothing needs the credential: this process reads standard input,
// runs the tool, and the wrapper never starts.
func TestAnOfflineCommandReadsItsOwnStandardInputAndSkipsTheWrapper(t *testing.T) {
	args := []string{"--json", "fixture", "check", "--offline", "--from", "-"}
	s := newStandIn(t, args)
	h := newHarness(t, nil)
	ran := withFixture(t, h)
	h.app.Env.APIErr = creds.ErrReexecRequired
	h.app.Provider = config.Provider{Provider: "exec", Command: []string{"/ignored"}}
	stdin := &fileReader{f: s.stdin}
	h.r.Stdin = stdin
	h.r.Reexec = s.reexec(filepath.Join(filepath.Dir(s.marker), "wrapper.sh"))
	if code := h.run(args...); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	if n := s.wrapperRuns(t); n != 0 || *ran != 1 || stdin.reads == 0 {
		t.Errorf("wrapper ran %d times, the tool %d times, standard input read %d times; want 0, 1 and some", n, *ran, stdin.reads)
	}
	if out := decodeFixture(t, h.out.String()); out.Policy != escaped(pipedPolicy) || !out.Offline {
		t.Errorf("out = %+v", out)
	}
}

// A bad path never starts the wrapper, which the marker proves: the stand-in
// records each run.
func TestABadPathNeverStartsTheStandInWrapper(t *testing.T) {
	args := []string{"--json", "fixture", "check", "--from", filepath.Join(t.TempDir(), "missing.hujson")}
	s := newStandIn(t, args)
	h := newHarness(t, nil)
	ran := withFixture(t, h)
	h.app.Env.APIErr = creds.ErrReexecRequired
	h.app.Provider = config.Provider{Provider: "exec", Command: []string{"/ignored"}}
	h.r.Reexec = s.reexec(filepath.Join(filepath.Dir(s.marker), "wrapper.sh"))
	if code := h.run(args...); code != 2 {
		t.Errorf("exit %d, want 2 (stderr %q, stdout %q)", code, h.err, h.out)
	}
	if n := s.wrapperRuns(t); n != 0 || *ran != 0 || s.out.Len() != 0 {
		t.Errorf("the wrapper ran %d times, the tool %d times, the child printed %q; want none", n, *ran, s.out.String())
	}
}
