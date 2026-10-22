package cli

import (
	"bytes"
	"strings"
	"testing"
)

// The GitHub formatter's own layout lines start no command by themselves: with nothing in
// front of the formatter (no guard, as a caller that forgot to put one there would have it),
// no line it writes except an annotation can act on a runner. The goldens and the test of
// the Runner cannot see this, because the guard in front of the formatter hides a missing
// one; the fuzz target does, and so does this test, which names it.
func TestTheGitHubFormatterGuardsItsOwnLayoutLines(t *testing.T) {
	for _, c := range formatCases() {
		var plain, annotations bytes.Buffer
		if err := formatGitHub(&plain, c.rep, formatOptions{Names: c.names, Trusted: &annotations}); err != nil {
			t.Fatal(err)
		}
		if plain.Len() == 0 && len(c.rep.Findings) > 0 {
			t.Errorf("%s: nothing was written", c.name)
		}
		for _, line := range splitLines(plain.String()) {
			if startsACommand(line) || strings.Contains(line, "##vso[") || strings.Contains(line, "##teamcity[") {
				t.Errorf("%s: a layout line the formatter wrote acts on a runner: %q", c.name, line)
			}
		}
	}
}
