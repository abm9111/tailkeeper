package cli

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/audit"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// probeCalls records what a Runner's Probe was given.
type probeCalls struct {
	n    int
	args []string
	c    *api.Client
}

func withProbe(h *harness, live string, exit int) *probeCalls {
	calls := &probeCalls{}
	h.r.Probe = func(_ context.Context, c *api.Client, args []string, stdout, _ io.Writer) int {
		calls.n++
		calls.args, calls.c = args, c
		_, _ = io.WriteString(stdout, "the probes ran\n")
		return exit
	}
	h.r.Getenv = func(k string) string {
		if k == "TAILKEEPER_LIVE" {
			return live
		}
		return ""
	}
	return calls
}

// probe-acl is a command only of a build that sets Probe: without it the command is an
// unknown area, not in the help, and nothing reaches the network or the credential.
func TestProbeACLDoesNotExistWithoutAProbe(t *testing.T) {
	f := apitest.New(t)
	h := newHarness(t, f)
	for args, want := range map[string]string{"probe-acl": `unknown area "probe-acl"`, "probe-acl --out": "unknown command `tailkeeper probe-acl --out`"} {
		h.err.Reset()
		if code := h.run(strings.Fields(args)...); code != 2 || !strings.Contains(h.err.String(), want) {
			t.Errorf("%s: exit %d, stderr %q", args, code, h.err)
		}
	}
	h.out.Reset()
	h.err.Reset()
	h.run("help")
	if strings.Contains(h.out.String(), "probe-acl") {
		t.Errorf("the help lists probe-acl:\n%s", h.out)
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d requests", n)
	}
}

// With a Probe, the command still refuses to start unless TAILKEEPER_LIVE=1, and it does so
// before the configuration is read or the credential wrapper runs.
func TestProbeACLNeedsTheLiveSwitch(t *testing.T) {
	for _, live := range []string{"", "0", "true", "yes"} {
		f := apitest.New(t)
		h := newHarness(t, f)
		calls := withProbe(h, live, 0)
		built := false
		h.r.Build = func(context.Context, string) (*app.App, error) { built = true; return h.app, nil }
		if code := h.run("probe-acl"); code != 2 || !strings.Contains(h.err.String(), "make probe-acl") || calls.n != 0 || built || len(f.Requests()) != 0 {
			t.Errorf("TAILKEEPER_LIVE=%q: exit %d, stderr %q, probe called %d times, built %v", live, code, h.err, calls.n, built)
		}
	}
}

// With the switch set, the command hands the client and the arguments to the Probe, passes
// its output and exit code on, and records one audit line like a tool call.
func TestProbeACLRunsTheProbeAndAuditsIt(t *testing.T) {
	for _, exit := range []int{0, 1} {
		f := apitest.New(t)
		h := newHarness(t, f)
		calls := withProbe(h, "1", exit)
		if code := h.run("--context", "work", "probe-acl", "--out", "dir", "--only", "A-1"); code != exit {
			t.Errorf("exit %d, want %d (%s)", code, exit, h.err)
		}
		if calls.n != 1 || strings.Join(calls.args, " ") != "--out dir --only A-1" || calls.c != h.app.Env.API || h.out.String() != "the probes ran\n" {
			t.Errorf("probe called %d times with %v; output %q", calls.n, calls.args, h.out)
		}
		entries, err := audit.Tail(h.app.AuditPath, 1)
		if err != nil || len(entries) != 1 || entries[0]["tool"] != "probe_acl" || entries[0]["tier"] != "read" {
			t.Fatalf("audit entries: %v, %v", entries, err)
		}
		want := "ok"
		if exit != 0 {
			want = "error"
		}
		if entries[0]["status"] != want {
			t.Errorf("audit status %v, want %s", entries[0]["status"], want)
		}
	}
}

// No credential, or a credential only the exec wrapper can supply, stops the command before
// the Probe: the wrapper is run (the process is replaced) or the error is shown.
func TestProbeACLNeedsACredential(t *testing.T) {
	h := newHarness(t, nil)
	calls := withProbe(h, "1", 0)
	if code := h.run("probe-acl"); code == 0 || calls.n != 0 || !strings.Contains(h.err.String(), "no read credential") {
		t.Errorf("no credential: exit %d, probe called %d times, stderr %q", code, calls.n, h.err)
	}
	h = newHarness(t, nil)
	calls = withProbe(h, "1", 0)
	h.app.Env.APIErr = creds.ErrReexecRequired
	h.app.Provider = config.Provider{Provider: "exec", Command: []string{"/bin/wrapper"}}
	h.run("probe-acl")
	if h.reexecProvider == nil || h.reexecProvider.Command[0] != "/bin/wrapper" || calls.n != 0 {
		t.Errorf("exec provider: re-exec %v, probe called %d times", h.reexecProvider, calls.n)
	}
	h = newHarness(t, nil)
	h.r.Build = func(context.Context, string) (*app.App, error) {
		return nil, tkerr.New(tkerr.ConfigInvalid, "bad configuration", "")
	}
	calls = withProbe(h, "1", 0)
	if code := h.run("probe-acl"); code != 6 || calls.n != 0 {
		t.Errorf("a configuration error: exit %d, probe called %d times", code, calls.n)
	}
}

// The real environment is read when no Getenv is injected.
func TestProbeACLReadsTheRealEnvironmentByDefault(t *testing.T) {
	t.Setenv("TAILKEEPER_LIVE", "")
	h := newHarness(t, apitest.New(t))
	calls := withProbe(h, "1", 0)
	h.r.Getenv = nil
	if code := h.run("probe-acl"); code != 2 || calls.n != 0 {
		t.Errorf("exit %d, probe called %d times", code, calls.n)
	}
	t.Setenv("TAILKEEPER_LIVE", "1")
	if code := h.run("probe-acl"); code != 0 || calls.n != 1 {
		t.Errorf("with the switch: exit %d, probe called %d times", code, calls.n)
	}
}
