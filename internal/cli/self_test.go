package cli

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/app"
)

// App.Build resolves credentials, privacy providers and the local runner. An
// offline self-info command must never call it, even with --context supplied.
func TestSelfInfoSkipsConfiguredProviders(t *testing.T) {
	h := newHarness(t, nil)
	calls := 0
	h.r.Build = func(context.Context, string) (*app.App, error) {
		calls++
		return nil, errors.New("provider initialization must not run")
	}
	code := h.run("--context", "unused", "self", "info", "--json")
	if code != 0 || calls != 0 || !strings.Contains(h.out.String(), `"version": "dev"`) {
		t.Fatalf("exit %d; Build calls %d; stderr %s; stdout %s", code, calls, h.err, h.out)
	}
}

// An empty list is an answer, and the text form gives it: all three lists of self info are
// printed, as none when empty. Without the lines a reader cannot tell a build with no
// assessor from a text that left them out.
func TestSelfInfoTextPrintsAllThreeListsAndNoneWhenEmpty(t *testing.T) {
	h := newHarness(t, nil)
	if code := h.run("self", "info"); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, h.err)
	}
	for _, want := range []string{"name: tailkeeper\n", "reportSchemas: none\n", "catalogSchemas: none\n", "assessmentCapabilities: none\n"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("the text lacks %q:\n%s", want, h.out)
		}
	}
}

// self info reads no configuration, so it has no context to select: --context is refused
// like any flag the command does not take (a usage error, exit 2, in the shape --json asks
// for), and is not listed in its help. The global form, which every command may be given,
// is still accepted and ignored (TestSelfInfoSkipsConfiguredProviders). A command that does
// use a context keeps the flag.
func TestSelfInfoRefusesAContext(t *testing.T) {
	h := newHarness(t, nil)
	calls := 0
	h.r.Build = func(context.Context, string) (*app.App, error) {
		calls++
		return nil, errors.New("self info must not build the app")
	}
	for _, args := range [][]string{{"self", "info", "--context", "work"}, {"self", "info", "--context=work"}, {"self", "info", "-context", "work"}} {
		h.out.Reset()
		h.err.Reset()
		if code := h.run(args...); code != 2 || !strings.Contains(h.err.String(), "usage") || !strings.Contains(h.err.String(), "context") || h.out.Len() != 0 {
			t.Errorf("%v: exit %d, stdout %q, stderr %q, want exit 2 and a usage error", args, code, h.out, h.err)
		}
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("self", "info", "--context", "work", "--json"); code != 2 || !strings.Contains(h.out.String(), `"code": "usage"`) {
		t.Errorf("with --json: exit %d, stdout %q, stderr %q, want the usage error as JSON", code, h.out, h.err)
	}
	if calls != 0 {
		t.Errorf("Build ran %d times", calls)
	}
	h.out.Reset()
	h.err.Reset()
	if code := h.run("self", "info", "--help"); code != 0 || strings.Contains(h.err.String(), "-context") || !strings.Contains(h.err.String(), "-json") {
		t.Errorf("self info --help: exit %d, stderr %q, want the flags without -context", code, h.err)
	}
	h.err.Reset()
	if code := h.run("devices", "list", "--help"); code != 0 || !strings.Contains(h.err.String(), "-context") {
		t.Errorf("devices list --help: exit %d, stderr %q, want -context listed", code, h.err)
	}
}

// The description says the CLI form is not audited: nothing is written to the audit log,
// and nothing warns about it.
func TestSelfInfoIsNotAuditedOnTheCommandLine(t *testing.T) {
	h := newHarness(t, nil)
	if code := h.run("self", "info"); code != 0 || h.err.Len() != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.err)
	}
	if data, err := os.ReadFile(h.app.AuditPath); err == nil && len(data) != 0 {
		t.Errorf("self info wrote to the audit log: %s", data)
	}
}
