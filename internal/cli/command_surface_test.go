package cli

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

type surfaceIn struct {
	Name string `json:"name,omitempty"`
}

// One output type per capability, so a command offers --quiet, --fail-on and
// --format for exactly the capabilities its result has.
type plainOut struct {
	Name string `json:"name"`
}
type codedOnlyOut struct {
	Name string `json:"name"`
}

func (codedOnlyOut) ExitCode() int { return 0 }

type gatedOnlyOut struct {
	Name string `json:"name"`
}

func (gatedOnlyOut) Findings() registry.Findings { return registry.Findings{} }

type reportedOnlyOut struct {
	Name string `json:"name"`
}

func (reportedOnlyOut) Report() registry.Report { return registry.Report{Verdict: "VALID"} }

type panickyOut struct {
	Name string `json:"name"`
}

func (panickyOut) Report() registry.Report { panic("report-payload-must-not-surface") }

func surfaceMeta(name string) registry.Meta {
	return registry.Meta{Name: name + "_check", Area: name, Verb: "check", Summary: "A test tool.", Tier: registry.TierLocal,
		Stage: registry.StageGA, Credential: registry.CredNone}
}

func defineSurface[O any](name string, out O) registry.Tool {
	return registry.Define(surfaceMeta(name), func(context.Context, *registry.Env, surfaceIn) (O, error) { return out, nil })
}

func surfaceHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, nil)
	reg := registry.New()
	reg.MustAdd(defineSurface("plain", plainOut{Name: "p"}), defineSurface("coded", codedOnlyOut{Name: "c"}),
		defineSurface("gated", gatedOnlyOut{Name: "g"}), defineSurface("reported", reportedOnlyOut{Name: "r"}),
		defineSurface("panicky", panickyOut{Name: "x"}))
	h.r.Registry = func() *registry.Registry { return reg }
	return h
}

// A result that can carry a verdict takes --quiet, one that can be gated takes
// --fail-on, one with a layout takes --format: each for its own capability, and
// a command without the capability does not offer the flag.
func TestACommandOffersTheFlagsItsResultCanHonour(t *testing.T) {
	for _, c := range []struct {
		area                  string
		quiet, failOn, format bool
	}{
		{"plain", false, false, false},
		{"coded", true, false, false},
		{"gated", true, true, false},
		{"reported", true, false, true},
	} {
		for flagName, want := range map[string]bool{"--quiet": c.quiet, "--fail-on": c.failOn, "--format": c.format} {
			h := surfaceHarness(t)
			arg := "change"
			if flagName == "--format" {
				arg = "text"
			}
			args := []string{c.area, "check", flagName}
			if flagName != "--quiet" {
				args = append(args, arg)
			}
			code := h.run(args...)
			undefined := strings.Contains(h.err.String(), "flag provided but not defined: -"+strings.TrimPrefix(flagName, "--"))
			if want && (code != 0 || undefined) {
				t.Errorf("%s check %s: exit %d, stderr %q, want it accepted", c.area, flagName, code, h.err)
			}
			if !want && (code != 2 || !undefined) {
				t.Errorf("%s check %s: exit %d, stderr %q, want it undefined", c.area, flagName, code, h.err)
			}
		}
	}
}

// A panic while building the report is an internal error, not an empty report.
func TestAPanickingReportIsAnInternalError(t *testing.T) {
	h := surfaceHarness(t)
	code := h.run("panicky", "check")
	if code != tkerr.ExitCode(tkerr.New(tkerr.Internal, "", "")) || h.out.Len() != 0 ||
		!strings.Contains(h.err.String(), "internal_error") || strings.Contains(h.err.String(), "payload") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
}

// An area without a verb, and the help forms, are usage: exit 2 for a missing verb,
// 0 for a request for help, and the list holds the verbs of that area alone.
func TestAreaUsageForAMissingVerbAndForHelp(t *testing.T) {
	h := newHarness(t, nil)
	for _, c := range []struct {
		args []string
		exit int
	}{{[]string{"devices"}, 2}, {[]string{"devices", "-h"}, 0}, {[]string{"devices", "--help"}, 0}, {[]string{"devices", "help"}, 0},
		{[]string{"devices", "-h", "--json"}, 0}} {
		h.out.Reset()
		h.err.Reset()
		if code := h.run(c.args...); code != c.exit {
			t.Errorf("%v: exit %d, want %d (stderr %q)", c.args, code, c.exit, h.err)
		}
		e := h.err.String()
		if !strings.Contains(e, "Usage: tailkeeper devices <verb>") || !strings.Contains(e, "  list ") || !strings.Contains(e, "  routes ") ||
			strings.Contains(e, "  test ") || strings.Contains(e, "  query ") || strings.Contains(e, "  validate ") || h.out.Len() != 0 {
			t.Errorf("%v: stdout %q, stderr %q, want the verbs of devices alone on stderr", c.args, h.out, e)
		}
	}
	// With --json, a missing verb is an error document that says so.
	h.out.Reset()
	h.err.Reset()
	if code := h.run("devices", "--json"); code != 2 || !strings.Contains(h.out.String(), "needs a verb") || h.err.Len() != 0 {
		t.Errorf("devices --json: exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
	// An unknown verb names the area and the verb that were typed.
	h.out.Reset()
	h.err.Reset()
	if code := h.run("devices", "frobnicate"); code != 2 || !strings.Contains(h.err.String(), "unknown command `tailkeeper devices frobnicate`") {
		t.Errorf("unknown verb: exit %d, stderr %q", code, h.err)
	}
}

// Nothing at all is a usage text on standard error without --json, and an error
// document on standard output with it.
func TestNoCommandIsUsageOrAJSONError(t *testing.T) {
	h := newHarness(t, nil)
	if code := h.run(); code != 2 || h.out.Len() != 0 || !strings.Contains(h.err.String(), "Usage:") {
		t.Errorf("no arguments: exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
	h = newHarness(t, nil)
	if code := h.run("--json"); code != 2 || !strings.Contains(h.out.String(), "a command is required") || h.err.Len() != 0 {
		t.Errorf("--json alone: exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
}

// A runner without standard input reads an empty one, and a failing error shows a
// fix line only when it has a fix to show.
func TestARunnerWithoutStandardInputReadsNone(t *testing.T) {
	if got, _ := io.ReadAll((&Runner{}).stdin()); len(got) != 0 {
		t.Errorf("a nil Stdin read %q", got)
	}
	if (&Runner{Stdin: strings.NewReader("x")}).stdin() == nil {
		t.Error("a given Stdin was dropped")
	}
	h := newHarness(t, nil)
	if code := h.r.fail(tkerr.New("no_such_code", "something failed", ""), false); code == 0 ||
		!strings.Contains(h.err.String(), "tailkeeper: no_such_code: something failed") || strings.Contains(h.err.String(), "fix:") {
		t.Errorf("exit %d, stderr %q, want no fix line for an error without a hint", code, h.err)
	}
	h = newHarness(t, nil)
	h.r.fail(tkerr.New(tkerr.NotFound, "no such thing", ""), false)
	if !strings.Contains(h.err.String(), "  fix: "+tkerr.ProgramHint(tkerr.NotFound)) {
		t.Errorf("stderr %q, want the program hint as the fix", h.err)
	}
}

// --json given as --json=true, and the last --format on the line, decide the shape
// of an error found before the flags were parsed.
func TestJSONRequestedReadsTheLastWordOnTheLine(t *testing.T) {
	for args, want := range map[string]bool{
		"--json":                      true,
		"--json=true":                 true,
		"-json=true":                  true,
		"--json=true --json=false":    false,
		"--json=false --json":         true,
		"--format json":               true,
		"--format=json":               true,
		"--format=json --format=text": false,
		"--format json --format text": false,
		"--format=json --format=yaml": false,
		"--format text --format=json": true,
		"--format -- --json":          false,
		"--json --format --":          true,
		"--format":                    false,
		"--format --json":             false,
		"--bogus -- --json":           false,
		"--json -- x":                 true,
		"--format=json --json=false":  true,
		"--format=text --json":        true,
		"-format=json -format=table":  false,
	} {
		if got := jsonRequested(strings.Fields(args)); got != want {
			t.Errorf("jsonRequested(%q) = %v, want %v", args, got, want)
		}
	}
}
