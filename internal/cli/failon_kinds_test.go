package cli

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// A --fail-on token that the tool never computes is refused before anything loads: a
// gate on a count that is always 0 would never fire, and the pipeline that relies on it
// would be green for good.
func TestAFailOnTokenTheToolNeverComputesIsRefusedBeforeAnythingLoads(t *testing.T) {
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"the one it lacks":         {[]string{"--fail-on", "warnings"}, "`partial check` does not compute `warnings`; it computes tests-reduced, defaults, widening, change"},
		"among others it computes": {[]string{"--fail-on", "defaults,warnings,change"}, "does not compute `warnings`"},
		"in a repeated flag":       {[]string{"--fail-on", "widening", "--fail-on", "warnings"}, "does not compute `warnings`"},
	} {
		h, builds, ran := fixtureHarness(t)
		code := h.run(append([]string{"partial", "check", "--status", "pass"}, c.args...)...)
		if code != 2 || !strings.Contains(h.err.String(), c.want) {
			t.Errorf("%s: exit %d, stderr %q; want 2 and %q", name, code, h.err, c.want)
		}
		if h.reexecProvider != nil || *builds != 0 || *ran != 0 {
			t.Errorf("%s: wrapper started %v, Build ran %d times; want neither", name, h.reexecProvider != nil, *builds)
		}
	}
	// With --json the refusal is the usage error document.
	h, _, _ := fixtureHarness(t)
	if code := h.run("--json", "partial", "check", "--status", "pass", "--fail-on", "warnings"); code != 2 ||
		!strings.Contains(h.out.String(), `"code": "usage"`) || h.err.Len() != 0 {
		t.Errorf("--json: exit %d, stdout %q, stderr %q", code, h.out, h.err)
	}
	// The kinds it computes gate as before, and the verdict still outranks them.
	for _, tok := range []string{"tests-reduced", "defaults", "widening", "change"} {
		h := newHarness(t, nil)
		withFixture(t, h)
		counts := map[string]string{"tests-reduced": "--tests-reduced", "defaults": "--defaults", "widening": "--widenings", "change": "--changes"}
		if code := h.run("partial", "check", "--status", "pass", counts[tok], "2", "--fail-on", tok); code != 8 {
			t.Errorf("--fail-on %s with findings: exit %d, want 8 (stderr %q)", tok, code, h.err)
		}
	}
}

// A gated result type that does not say which kinds it computes takes all five: the
// behaviour a tool had before there was a way to say.
func TestAGatedToolWithoutComputesTakesEveryToken(t *testing.T) {
	for _, tok := range failOnTokens {
		h, code := gate(t, "pass", nil, "--fail-on", tok)
		if code != 0 {
			t.Errorf("--fail-on %s: exit %d, want 0 (stderr %q)", tok, code, h.err)
		}
	}
	h, code := gate(t, "pass", nil, "--fail-on", strings.Join(failOnTokens, ","))
	if code != 0 {
		t.Errorf("every token at once: exit %d (stderr %q)", code, h.err)
	}
}

type plantedIn struct {
	Status string `json:"status,omitempty"`
}

// The planted result types are flat structs: the registry refuses an embedded one.
type plainGated struct {
	Status string `json:"status"`
}

func (plainGated) Findings() registry.Findings { return registry.Findings{} }

type badKind struct {
	Status string `json:"status"`
}

func (badKind) Findings() registry.Findings { return registry.Findings{} }
func (badKind) FailOnKinds() []string       { return []string{"warnings", "bogus"} }

type noKinds struct {
	Status string `json:"status"`
}

func (noKinds) Findings() registry.Findings { return registry.Findings{} }
func (noKinds) FailOnKinds() []string       { return nil }

type goodKinds struct {
	Status string `json:"status"`
}

func (goodKinds) Findings() registry.Findings { return registry.Findings{} }
func (goodKinds) FailOnKinds() []string       { return []string{"defaults", "change"} }

func plantedRegistry[O any](name string) *registry.Registry {
	reg := registry.New()
	reg.MustAdd(registry.Define(registry.Meta{Name: name, Area: "planted", Verb: "check", Summary: "A planted tool.",
		Tier: registry.TierLocal, Stage: registry.StageGA, Credential: registry.CredNone},
		func(context.Context, *registry.Env, plantedIn) (O, error) { var zero O; return zero, nil }))
	return reg
}

// kindProblems says what is wrong with the --fail-on kinds of the gated tools of reg:
// a tool that lists no kind or a word that is not a token. With require, a gated tool
// that does not list its kinds at all is a problem too (the product's tools must say).
// gated counts the gated tools it saw, so that a walk over nothing shows.
func kindProblems(reg *registry.Registry, require bool) (problems []string, gated int) {
	for _, tool := range reg.All() {
		if !tool.OutputType.Implements(reflect.TypeFor[registry.Gated]()) {
			continue
		}
		gated++
		kinds, ok := computedKinds(tool)
		switch {
		case !ok && require:
			problems = append(problems, tool.Meta.Name+" is gated and does not implement Computes")
		case ok && len(kinds) == 0:
			problems = append(problems, tool.Meta.Name+" lists no kind it computes")
		case ok:
			for _, k := range kinds {
				if !slices.Contains(failOnTokens, k) {
					problems = append(problems, tool.Meta.Name+" lists "+k+", which is not a --fail-on token")
				}
			}
		}
	}
	return problems, gated
}

func TestEveryComputedKindIsAKnownToken(t *testing.T) {
	// The fixture's tools are the ones that exist today: no problem, and the walk saw
	// the gated ones.
	if problems, gated := kindProblems(fixtureRegistry(new(int)), false); len(problems) > 0 || gated < 2 {
		t.Errorf("fixture: %d gated tools, problems %v", gated, problems)
	}
	// The product's gated tools must list their kinds; none is gated yet, and the day
	// one is, this is the test that holds it to the rule.
	if problems, _ := kindProblems(newRegistry(), true); len(problems) > 0 {
		t.Errorf("product: %v", problems)
	}
	// The check can fail, in each of its three ways.
	for name, c := range map[string]struct {
		reg     *registry.Registry
		require bool
		want    string
	}{
		"a word that is no token":      {plantedRegistry[badKind]("planted_bad"), false, "lists bogus, which is not a --fail-on token"},
		"an empty list":                {plantedRegistry[noKinds]("planted_empty"), false, "lists no kind it computes"},
		"a missing list when required": {plantedRegistry[plainGated]("planted_plain"), true, "does not implement Computes"},
	} {
		problems, gated := kindProblems(c.reg, c.require)
		if gated != 1 || len(problems) != 1 || !strings.Contains(problems[0], c.want) {
			t.Errorf("%s: %d gated, problems %v, want %q", name, gated, problems, c.want)
		}
	}
	if problems, gated := kindProblems(plantedRegistry[goodKinds]("planted_good"), true); len(problems) > 0 || gated != 1 {
		t.Errorf("a good list: %d gated, %v", gated, problems)
	}
	if problems, _ := kindProblems(plantedRegistry[plainGated]("planted_plain"), false); len(problems) > 0 {
		t.Errorf("a gated tool without Computes is allowed when not required: %v", problems)
	}
}
