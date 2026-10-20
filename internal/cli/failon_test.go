package cli

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

func TestParseFailOn(t *testing.T) {
	for name, c := range map[string]struct {
		in   []string
		want []string // tokens set, in the order the tokens are documented
	}{
		"none given":            {nil, nil},
		"one token":             {[]string{"warnings"}, []string{"warnings"}},
		"comma separated":       {[]string{"warnings,widening"}, []string{"warnings", "widening"}},
		"repeated":              {[]string{"change", "tests-reduced"}, []string{"tests-reduced", "change"}},
		"repeated and comma":    {[]string{"defaults", "warnings,change"}, []string{"warnings", "defaults", "change"}},
		"a token twice":         {[]string{"change,change", "change"}, []string{"change"}},
		"spaces around a token": {[]string{" warnings , defaults "}, []string{"warnings", "defaults"}},
		"every token":           {[]string{"warnings,tests-reduced,defaults,widening,change"}, []string{"warnings", "tests-reduced", "defaults", "widening", "change"}},
	} {
		got, err := parseFailOn(c.in)
		if err != nil || strings.Join(got.tokens(), ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, %v; want %v", name, got.tokens(), err, c.want)
		}
	}
	for name, in := range map[string][]string{
		"an unknown token":   {"bogus"},
		"an empty value":     {""},
		"an empty token":     {"warnings,"},
		"a leading comma":    {",warnings"},
		"a near miss":        {"warning"},
		"a different case":   {"Warnings"},
		"one bad of several": {"warnings", "nope"},
	} {
		_, err := parseFailOn(in)
		if err == nil || !strings.Contains(err.Error(), "warnings, tests-reduced, defaults, widening, change") {
			t.Errorf("%s: err = %v, want it to list the tokens", name, err)
		}
	}
}

func TestFailOnMatchesTheFindingsItNames(t *testing.T) {
	f := registry.Findings{NewWarnings: 1, TestsReduced: 0, Defaults: 2, Widenings: 0, Changes: 5}
	for name, c := range map[string]struct {
		set  string
		want string
	}{
		"warnings":                {"warnings", "warnings (1)"},
		"tests reduced is absent": {"tests-reduced", ""},
		"defaults":                {"defaults", "defaults (2)"},
		"widening is absent":      {"widening", ""},
		"change":                  {"change", "change (5)"},
		"several, in token order": {"change,warnings,widening", "warnings (1), change (5)"},
		"nothing set":             {"", ""},
	} {
		var in []string
		if c.set != "" {
			in = []string{c.set}
		}
		fo, err := parseFailOn(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(fo.matches(f), ", "); got != c.want {
			t.Errorf("%s: matches = %q, want %q", name, got, c.want)
		}
	}
}

// Precedence when several apply: 1, then 9, then 2, then 8, then 0. The result
// carries one code of its own; --fail-on adds 8 only when nothing outranks it.
func TestExitPolicyPrecedence(t *testing.T) {
	for _, c := range []struct {
		own     int
		matched bool
		want    int
	}{
		{0, false, 0}, {0, true, 8}, {1, false, 1}, {1, true, 1}, {9, false, 9}, {9, true, 9}, {2, false, 2}, {2, true, 2},
		// A code the policy does not know is kept: 8 never hides it.
		{7, true, 7}, {5, false, 5},
	} {
		if got := exitPolicy(c.own, c.matched); got != c.want {
			t.Errorf("exitPolicy(%d, %v) = %d, want %d", c.own, c.matched, got, c.want)
		}
	}
}

// gate runs the gate tool with a status, counts and arguments.
func gate(t *testing.T, status string, counts map[string]int, extra ...string) (*harness, int) {
	t.Helper()
	h := newHarness(t, nil)
	withFixture(t, h)
	h.app.Env.APIErr = nil
	args := []string{"gate", "check", "--status", status}
	for name, n := range counts {
		args = append(args, "--"+name, strconv.Itoa(n))
	}
	return h, h.run(append(args, extra...)...)
}

func TestFailOnTurnsFindingsIntoExit8(t *testing.T) {
	for _, c := range []struct {
		name   string
		status string
		counts map[string]int
		extra  []string
		exit   int
	}{
		{"no gate, findings present", "pass", map[string]int{"widenings": 2}, nil, 0},
		{"a gate that matches", "pass", map[string]int{"widenings": 2}, []string{"--fail-on", "widening"}, 8},
		{"a gate that does not match", "pass", map[string]int{"widenings": 2}, []string{"--fail-on", "warnings"}, 0},
		{"a gate on nothing found", "pass", nil, []string{"--fail-on", "widening,change,warnings"}, 0},
		{"repeated and comma separated", "pass", map[string]int{"changes": 1}, []string{"--fail-on", "warnings", "--fail-on", "tests-reduced,change"}, 8},
		{"warnings", "pass", map[string]int{"new-warnings": 1}, []string{"--fail-on", "warnings"}, 8},
		{"tests reduced", "pass", map[string]int{"tests-reduced": 3}, []string{"--fail-on", "tests-reduced"}, 8},
		{"defaults", "pass", map[string]int{"defaults": 1}, []string{"--fail-on", "defaults"}, 8},
		// The verdict outranks the gate: 1, then 9, then 2, then 8.
		{"unknown outranks a match", "unknown", map[string]int{"widenings": 1}, []string{"--fail-on", "widening"}, 1},
		{"fail outranks a match", "fail", map[string]int{"widenings": 1}, []string{"--fail-on", "widening"}, 9},
		{"invalid outranks a match", "invalid", map[string]int{"widenings": 1}, []string{"--fail-on", "widening"}, 2},
		{"unresolved outranks a match", "unresolved", map[string]int{"widenings": 1}, []string{"--fail-on", "widening"}, 2},
		{"a verdict without a gate", "fail", nil, nil, 9},
	} {
		h, code := gate(t, c.status, c.counts, c.extra...)
		if code != c.exit {
			t.Errorf("%s: exit %d, want %d (stderr %q)", c.name, code, c.exit, h.err)
		}
		if c.exit == 8 && !strings.Contains(h.err.String(), "findings_present: --fail-on matched") {
			t.Errorf("%s: stderr = %q, want the findings_present notice", c.name, h.err)
		}
		if c.exit != 8 && strings.Contains(h.err.String(), "findings_present") {
			t.Errorf("%s: stderr = %q, a notice for a gate that did not decide", c.name, h.err)
		}
	}
}

// With --json the result is still printed, and carries its status: the exit code
// is the gate's, the document is the result's.
func TestFailOnWithJSONPrintsTheResult(t *testing.T) {
	h, code := gate(t, "pass", map[string]int{"widenings": 2}, "--fail-on", "widening", "--json")
	if code != 8 {
		t.Fatalf("exit %d", code)
	}
	var out gateOut
	if err := json.Unmarshal(h.out.Bytes(), &out); err != nil || out.Status != "pass" || out.Widenings != 2 {
		t.Errorf("stdout = %q (%v)", h.out, err)
	}
	if !strings.Contains(h.err.String(), "--fail-on matched widening (2)") {
		t.Errorf("stderr = %q", h.err)
	}
}

func TestQuietPrintsNothingOnExitZero(t *testing.T) {
	if h, code := gate(t, "pass", nil, "--quiet"); code != 0 || h.out.Len() != 0 || h.err.Len() != 0 {
		t.Errorf("quiet pass: exit %d, stdout %q, stderr %q; want nothing", code, h.out, h.err)
	}
	if h, code := gate(t, "pass", nil); code != 0 || h.out.Len() == 0 {
		t.Errorf("a pass without --quiet printed nothing: exit %d", code)
	}
	for _, c := range []struct {
		status string
		extra  []string
		exit   int
	}{{"fail", nil, 9}, {"unknown", nil, 1}, {"invalid", nil, 2}, {"pass", []string{"--fail-on", "change"}, 8}} {
		counts := map[string]int{"changes": 1}
		if h, code := gate(t, c.status, counts, append([]string{"--quiet"}, c.extra...)...); code != c.exit || h.out.Len() == 0 {
			t.Errorf("quiet %s: exit %d (want %d), stdout %q; want the result printed", c.status, code, c.exit, h.out)
		}
	}
}

// A bad token is a usage error before anything loads, and the flags exist only on
// commands whose result can be gated.
func TestFailOnIsRefusedBeforeBuildAndOnlyWhereItApplies(t *testing.T) {
	h, builds, _ := fixtureHarness(t)
	if code := h.run("gate", "check", "--status", "pass", "--fail-on", "bogus"); code != 2 || !strings.Contains(h.err.String(), `--fail-on: "bogus" is not one of warnings, tests-reduced, defaults, widening, change`) || *builds != 0 {
		t.Errorf("bad token: exit %d, builds %d, stderr %q", code, *builds, h.err)
	}
	h = newHarness(t, nil)
	for _, flag := range []string{"--fail-on", "--quiet"} {
		h.err.Reset()
		if code := h.run("devices", "list", flag, "change"); code != 2 || !strings.Contains(h.err.String(), "flag provided but not defined: -"+strings.TrimPrefix(flag, "--")) {
			t.Errorf("devices list %s: exit %d, stderr %q; want it undefined for a result that cannot be gated", flag, code, h.err)
		}
	}
	// acl test has a verdict of its own (exit 9), so it takes --quiet and not --fail-on.
	h.err.Reset()
	if code := h.run("acl", "test", "tag:ci", "--accept", "tag:prod:22", "--fail-on", "change"); code != 2 {
		t.Errorf("acl test --fail-on: exit %d, stderr %q", code, h.err)
	}
}
