package cli

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// failOnTokens are the kinds of finding --fail-on names, in the order help lists
// them. The set is closed: a sixth token later is additive.
var failOnTokens = []string{"warnings", "tests-reduced", "defaults", "widening", "change"}

// failOnSet is the set of kinds a command line asked to fail on.
type failOnSet map[string]bool

// parseFailOn reads the values of every --fail-on flag: each is a comma-separated
// list, and the flag may repeat. An empty value or token, or one that is not in
// failOnTokens, is a usage error that lists the tokens.
func parseFailOn(values []string) (failOnSet, error) {
	set := failOnSet{}
	for _, v := range values {
		for _, tok := range strings.Split(v, ",") {
			tok = strings.TrimSpace(tok)
			known := false
			for _, k := range failOnTokens {
				known = known || k == tok
			}
			if !known {
				return nil, tkerr.New(tkerr.Usage, fmt.Sprintf("--fail-on: %q is not one of %s", tok, strings.Join(failOnTokens, ", ")),
					"give kinds of finding separated by commas, or repeat the flag")
			}
			set[tok] = true
		}
	}
	return set, nil
}

// tokens returns the set in the order help lists them.
func (f failOnSet) tokens() []string {
	var out []string
	for _, k := range failOnTokens {
		if f[k] {
			out = append(out, k)
		}
	}
	return out
}

// matches returns "token (count)" for each token in the set that fi has findings
// of, in token order.
func (f failOnSet) matches(fi registry.Findings) []string {
	counts := map[string]int{"warnings": fi.NewWarnings, "tests-reduced": fi.TestsReduced, "defaults": fi.Defaults,
		"widening": fi.Widenings, "change": fi.Changes}
	var out []string
	for _, k := range f.tokens() {
		if counts[k] > 0 {
			out = append(out, fmt.Sprintf("%s (%d)", k, counts[k]))
		}
	}
	return out
}

// exitPolicy is the exit code of a typed result: its own code (0, 1, 2 or 9) when
// that is not 0, else 8 when a --fail-on gate matched, else 0. The order of
// precedence is 1, 9, 2, 8, 0; a code the policy does not know is kept, and 8 never
// hides it.
func exitPolicy(own int, matched bool) int {
	switch {
	case own != 0:
		return own
	case matched:
		return 8
	}
	return 0
}

// exitFor applies the policy to a result: the code, and the gates that matched.
func exitFor(out any, f failOnSet) (code int, matched []string) {
	own := 0
	if ec, ok := out.(registry.ExitCoder); ok {
		own = ec.ExitCode()
	}
	if g, ok := out.(registry.Gated); ok {
		matched = f.matches(g.Findings())
	}
	return exitPolicy(own, len(matched) > 0), matched
}

// computedKinds returns the --fail-on tokens a tool's result computes, and whether the
// result type says so (registry.Computes). It asks the zero value of the output type, so
// the method has a value receiver and reads no field.
func computedKinds(t registry.Tool) ([]string, bool) {
	c, ok := reflect.New(t.OutputType).Elem().Interface().(registry.Computes)
	if !ok {
		return nil, false
	}
	return c.FailOnKinds(), true
}

// offlineKinds returns the --fail-on tokens a tool's result computes when the command runs
// with --offline, and whether the result type says so (registry.ComputesOffline).
func offlineKinds(t registry.Tool) ([]string, bool) {
	c, ok := reflect.New(t.OutputType).Elem().Interface().(registry.ComputesOffline)
	if !ok {
		return nil, false
	}
	return c.OfflineFailOnKinds(), true
}

// checkKinds refuses a --fail-on token that the tool never computes: a usage error that
// names the token and lists the ones the tool does compute. A tool that does not say
// which kinds it computes takes every token. With --offline the kinds are the ones the
// tool computes offline, if its result says they differ, and the refusal names --offline:
// an offline check compares nothing with the live policy, so a gate on what it would find
// there could never fire.
func checkKinds(t registry.Tool, set failOnSet, offline bool) error {
	kinds, ok := computedKinds(t)
	if !ok {
		return nil
	}
	command, hint := t.Meta.Area+" "+t.Meta.Verb, "drop the token from --fail-on, or use one the command computes"
	if off, has := offlineKinds(t); has && offline {
		kinds, command = off, command+" --offline"
		hint = "drop --fail-on, or run the command without --offline"
		if len(off) > 0 {
			hint = "drop the token from --fail-on, use one the command computes, or run the command without --offline"
		}
	}
	list := "no kind"
	if len(kinds) > 0 {
		list = strings.Join(kinds, ", ")
	}
	for _, tok := range set.tokens() {
		if !slices.Contains(kinds, tok) {
			return tkerr.New(tkerr.Usage, fmt.Sprintf("`%s` does not compute `%s`; it computes %s", command, tok, list), hint)
		}
	}
	return nil
}
