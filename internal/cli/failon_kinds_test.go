package cli

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
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
	// The product's gated tools must list their kinds, and there are some to hold to it:
	// acl_validate and acl_diff.
	if problems, gated := kindProblems(newRegistry(), true); len(problems) > 0 || gated != 2 {
		t.Errorf("product: %d gated tools, problems %v; want 2 and none", gated, problems)
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

// The help line of --fail-on lists the kinds the command computes: a command that cannot
// find a kind must not offer it. A command whose result does not say lists all five.
func TestTheFailOnHelpListsTheKindsTheCommandComputes(t *testing.T) {
	const prefix = "exit 8 when the result has findings of these kinds: "
	const suffix = " (comma-separated, repeatable)"
	seen := 0
	for _, tool := range newRegistry().All() {
		kinds, ok := computedKinds(tool)
		if !ok {
			continue
		}
		seen++
		h := newHarness(t, nil)
		h.run(tool.Meta.Area, tool.Meta.Verb, "--help")
		if want := prefix + strings.Join(kinds, ", ") + suffix; !strings.Contains(h.err.String(), want) {
			t.Errorf("%s %s --help does not say %q:\n%s", tool.Meta.Area, tool.Meta.Verb, want, h.err)
		}
	}
	if seen != 2 {
		t.Errorf("%d commands of the product say which kinds they compute, want 2 (acl validate and acl diff)", seen)
	}
	// The planted tools: four kinds listed for one that computes four, five for one that does not say.
	for command, want := range map[string]string{
		"partial": "tests-reduced, defaults, widening, change", "gate": "warnings, tests-reduced, defaults, widening, change",
	} {
		h, _, _ := fixtureHarness(t)
		h.run(command, "check", "--help")
		if !strings.Contains(h.err.String(), prefix+want+suffix) {
			t.Errorf("%s check --help:\n%s", command, h.err)
		}
	}
}

// An offline check compares nothing with the live policy and sends nothing, so it computes
// none of the five kinds: --fail-on is refused with --offline, whatever the kind, before
// anything loads. Without the refusal the gate would read a count that is 0 for ever, and
// the pull-request step that relied on it would stay green.
func TestAnOfflineCheckRefusesEveryFailOnKindBeforeAnythingLoads(t *testing.T) {
	policy := writeFile(t, "policy.hujson", layoutProposal)
	for _, tok := range failOnTokens {
		h, builds := execHarness(t)
		code := h.run("acl", "validate", "--offline", "--from", policy, "--fail-on", tok)
		want := "`acl validate --offline` does not compute `" + tok + "`; it computes no kind"
		if code != 2 || !strings.Contains(h.err.String(), want) || !strings.Contains(h.err.String(), "run the command without --offline") {
			t.Errorf("--fail-on %s: exit %d, stderr %q; want 2 and %q", tok, code, h.err, want)
		}
		if h.reexecProvider != nil || *builds != 0 || h.out.Len() != 0 {
			t.Errorf("--fail-on %s: wrapper started %v, Build ran %d times, stdout %q; want nothing", tok, h.reexecProvider != nil, *builds, h.out)
		}
	}
	// With several kinds the first in the order of the help is named; with --json the refusal
	// is the usage error document; and the flag in front of --offline changes nothing.
	h, _ := execHarness(t)
	if code := h.run("acl", "validate", "--fail-on", "change,warnings", "--offline", "--from", policy); code != 2 || !strings.Contains(h.err.String(), "does not compute `warnings`") {
		t.Errorf("two kinds: exit %d, stderr %q", code, h.err)
	}
	h, _ = execHarness(t)
	if code := h.run("--json", "acl", "validate", "--offline", "--from", policy, "--fail-on", "change"); code != 2 || !strings.Contains(h.out.String(), `"code": "usage"`) {
		t.Errorf("--json: exit %d, stdout %q", code, h.out)
	}
	// Offline and without --fail-on it is exit 0, and a diff of two files, which compares them
	// here, gates on its four kinds as before.
	h, _ = execHarness(t)
	if code := h.run("acl", "validate", "--offline", "--from", policy); code != 0 {
		t.Errorf("offline without a gate: exit %d, stderr %q", code, h.err)
	}
	old, wider := writeFile(t, "old.hujson", layoutOld), writeFile(t, "wider.hujson", layoutWider)
	h, _ = execHarness(t)
	if code := h.run("acl", "diff", "--offline", "--fail-on", "widening", old, wider); code != 8 {
		t.Errorf("a diff of two files offline, --fail-on widening: exit %d, stderr %q; want 8", code, h.err)
	}
}

// A result type that fills fewer kinds offline says which: the check names --offline and the
// kinds it computes there, and does not apply them to a command line without the flag.
func TestACommandThatComputesFewerKindsOfflineIsHeldToThem(t *testing.T) {
	some := plantedRegistry[offlineSome]("offline_some").All()[0]
	same := plantedRegistry[goodKinds]("same_both_ways").All()[0]
	for name, c := range map[string]struct {
		tool    registry.Tool
		set     failOnSet
		offline bool
		want    string // "" is no refusal
	}{
		"a kind it fills offline":          {some, failOnSet{"defaults": true}, true, ""},
		"a kind it fills only online":      {some, failOnSet{"change": true}, true, "`planted check --offline` does not compute `change`; it computes defaults"},
		"the same kind online":             {some, failOnSet{"change": true}, false, ""},
		"a kind it never fills":            {some, failOnSet{"widening": true}, false, "`planted check` does not compute `widening`; it computes warnings, defaults, change"},
		"a tool that says nothing offline": {same, failOnSet{"change": true}, true, ""},
		"and one of its kinds, still":      {same, failOnSet{"widening": true}, true, "`planted check` does not compute `widening`; it computes defaults, change"},
	} {
		err := checkKinds(c.tool, c.set, c.offline)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v, want none", name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}

type offlineSome struct {
	Status string `json:"status"`
}

func (offlineSome) Findings() registry.Findings  { return registry.Findings{} }
func (offlineSome) FailOnKinds() []string        { return []string{"warnings", "defaults", "change"} }
func (offlineSome) OfflineFailOnKinds() []string { return []string{"defaults"} }

// Every kind of --fail-on fires on its own finding through the real command: a proposal that
// removes a test, one that widens a rule, one that moves a default, one that only changes
// something, one that only draws a new warning and one that changes nothing. Each scenario
// lists, as a literal, the kinds that must fire and the exit of every other kind is 0: a
// removed test, a widened rule and a moved default are changes too, so "change" fires with
// them, and no scenario fires a kind it is not named for. The exit codes come from the
// command itself, so that a gate wired to the wrong count is found, and the counts from its
// own JSON must show the finding each scenario is named for.
func TestEveryFailOnKindFiresOnItsFindingThroughTheCommand(t *testing.T) {
	const withTest = "{\n\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"]},\n\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"tag:ci:22\"]}],\n\t\"tests\": [{\"src\": \"tag:ci\", \"accept\": [\"tag:ci:22\"]}],\n}\n"
	scenarios := []struct {
		name, live, proposal string
		warns                []apitest.Entry
		own                  string   // the kind it is named for
		fires                []string // every kind that must fire, as a literal
	}{
		{"a removed test", withTest, strings.Replace(withTest, "\t\"tests\": [{\"src\": \"tag:ci\", \"accept\": [\"tag:ci:22\"]}],\n", "", 1), nil, "tests-reduced", []string{"tests-reduced", "change"}},
		{"a widened rule", withTest, strings.Replace(withTest, `"src": ["tag:ci"]`, `"src": ["*"]`, 1), nil, "widening", []string{"widening", "change"}},
		{"a default that moves", "{\n\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"]},\n}\n", withTest, nil, "defaults", []string{"defaults", "change"}},
		{"a change that is none of those", withTest, strings.Replace(withTest, "\"tagOwners\"", "\"hosts\": {\"edge\": \"192.0.2.9\"},\n\t\"tagOwners\"", 1), nil, "change", []string{"change"}},
		{"a new warning", withTest, withTest + "// a comment\n", []apitest.Entry{{User: "tag:ci", Warnings: []string{"tag:ci owns nothing"}}}, "warnings", []string{"warnings"}},
		{"nothing", withTest, withTest + "// a comment\n", nil, "", nil},
	}
	for _, s := range scenarios {
		fake := func() *apitest.Fake {
			f := layoutFake(s.live, nil, nil)(t)
			if len(s.warns) > 0 {
				f.ServeValidate(apitest.TestsWarned(s.warns...))
			} else {
				f.ServeValidate(apitest.TestsPassEmptyObject())
			}
			return f
		}
		proposal := writeFile(t, "proposal.hujson", s.proposal)
		h := newHarness(t, fake())
		if code := h.run("--json", "acl", "validate", "--from", proposal); code != 0 {
			t.Fatalf("%s: exit %d: %s", s.name, code, h.err)
		}
		out := validateJSON(t, h.out.String())
		counts := map[string]int{"warnings": len(out.NewWarnings) + out.NewWarningsOmitted}
		if c := out.Changes; c != nil {
			counts["tests-reduced"], counts["defaults"], counts["widening"] = c.TestsReduced, c.Defaults, c.Widening
			counts["change"] = c.Defaults + c.TestsReduced + c.Widening + c.TailscaleWritten + c.Semantic
		}
		if s.own != "" && counts[s.own] == 0 {
			t.Errorf("%s: the result shows no %s finding (%v): the scenario does not test its kind", s.name, s.own, counts)
		}
		if s.own == "" && counts["warnings"]+counts["change"] != 0 {
			t.Errorf("%s: the result shows findings (%v)", s.name, counts)
		}
		for _, tok := range failOnTokens {
			h := newHarness(t, fake())
			want := 0
			if slices.Contains(s.fires, tok) {
				want = 8
			}
			if code := h.run("acl", "validate", "--from", proposal, "--fail-on", tok); code != want {
				t.Errorf("%s, --fail-on %s: exit %d, want %d (counts %v, stderr %q)", s.name, tok, code, want, counts, h.err)
			}
		}
	}
}
