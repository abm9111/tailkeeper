package cli

import (
	"strings"
	"testing"
)

// A --fail-on element over the flag cap is a usage error that names the flag and the size,
// before anything loads. It used to be dropped, so a malformed gate was ignored and the
// command passed where the pipeline meant it to fail.
func TestAFailOnElementOverTheFlagCapIsRefusedBeforeAnythingLoads(t *testing.T) {
	big := strings.Repeat("x", maxFlagText+1)
	for name, args := range map[string][]string{
		"alone":                  {"--fail-on", big},
		"after a valid element":  {"--fail-on", "defaults", "--fail-on", big},
		"before a valid element": {"--fail-on", big, "--fail-on", "defaults"},
	} {
		h, builds, ran := fixtureHarness(t)
		code := h.run(append([]string{"partial", "check", "--status", "pass"}, args...)...)
		got := h.err.String()
		if code != 2 || !strings.Contains(got, "--fail-on takes a short value, not a document") || !strings.Contains(got, "8193 bytes") ||
			!strings.Contains(got, "the limit is 8192") || strings.Contains(got, "xxxxxxxx") {
			t.Errorf("%s: exit %d, stderr %q; want 2, the flag, the size and no echo", name, code, got)
		}
		if h.reexecProvider != nil || *builds != 0 || *ran != 0 {
			t.Errorf("%s: wrapper started %v, Build ran %d times, tool ran %d times; want none", name, h.reexecProvider != nil, *builds, *ran)
		}
	}
	// With --json the refusal is the usage error document.
	h, _, _ := fixtureHarness(t)
	if code := h.run("--json", "partial", "check", "--status", "pass", "--fail-on", big); code != 2 ||
		!strings.Contains(h.out.String(), `"code": "usage"`) || h.err.Len() != 0 {
		t.Errorf("--json: exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
	// An element of exactly the cap is not refused for its size: it is not a kind.
	h, _, _ = fixtureHarness(t)
	code := h.run("partial", "check", "--status", "pass", "--fail-on", strings.Repeat("x", maxFlagText))
	if got := h.err.String(); code != 2 || strings.Contains(got, "takes a short value") {
		t.Errorf("exactly the cap: exit %d, stderr %.200q; want 2 for an unknown kind, not for its size", code, got)
	}
}

// An argument that no command slot takes is named by its length when it is over the flag
// cap, never echoed: the document would otherwise be repeated in the error. A shorter
// one is quoted as before.
func TestAnUnexpectedArgumentOverTheFlagCapIsNamedByItsLengthNotEchoed(t *testing.T) {
	big := strings.Repeat("x", 9000)
	h := newHarness(t, nil)
	if code := h.run("devices", "list", big); code != 2 || !strings.Contains(h.err.String(), "an unexpected argument of 9000 bytes") ||
		strings.Contains(h.err.String(), "xxxxxxxx") || h.err.Len() > 600 {
		t.Errorf("one long argument: exit %d, stderr (%d bytes) %.300q", code, h.err.Len(), h.err)
	}
	// Several: the long one is named by its length among the short ones.
	h = newHarness(t, nil)
	if code := h.run("devices", "list", "one", big); code != 2 || !strings.Contains(h.err.String(), "an argument of 9000 bytes") ||
		!strings.Contains(h.err.String(), "one") || strings.Contains(h.err.String(), "xxxxxxxx") || h.err.Len() > 600 {
		t.Errorf("a short and a long argument: exit %d, stderr (%d bytes) %.300q", code, h.err.Len(), h.err)
	}
	// The cap itself is still quoted.
	short := strings.Repeat("y", maxFlagText)
	h = newHarness(t, nil)
	if code := h.run("devices", "list", short); code != 2 || !strings.Contains(h.err.String(), `unexpected argument "yyyy`) {
		t.Errorf("an argument of exactly the cap: exit %d, stderr %.200q; want it quoted", code, h.err)
	}
	h = newHarness(t, nil)
	if code := h.run("devices", "list", "stray"); code != 2 || !strings.Contains(h.err.String(), `unexpected argument "stray"`) {
		t.Errorf("a short argument: exit %d, stderr %q", code, h.err)
	}
}

// A JSON flag is a flag: a value over 8 KiB is a usage error that names the flag and the
// size, before anything loads, and the text is not repeated.
func TestAJSONFlagOverTheFlagCapIsRefusedWithoutEcho(t *testing.T) {
	big := `{"k":"` + strings.Repeat("x", maxFlagText) + `"}`
	for name, args := range map[string][]string{
		"a separate value": {"attr", "check", "--device-attrs", big},
		"the equals form":  {"attr", "check", "--device-attrs=" + big},
	} {
		h, builds, ran := fixtureHarness(t)
		code := h.run(args...)
		got := h.err.String()
		if code != 2 || !strings.Contains(got, "--device-attrs takes a short value, not a document") ||
			!strings.Contains(got, "the limit is 8192") || strings.Contains(got, "xxxxxxxx") {
			t.Errorf("%s: exit %d, stderr %.300q; want 2, the flag, the size and no echo", name, code, got)
		}
		if h.reexecProvider != nil || *builds != 0 || *ran != 0 {
			t.Errorf("%s: wrapper started %v, Build %d, ran %d; want none", name, h.reexecProvider != nil, *builds, *ran)
		}
	}
}
