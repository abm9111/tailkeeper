package tools_test

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// The prose that states how many tools there are: the opening paragraph of the README, and the
// comment in the Makefile that says how many calls the live run makes. (docs/tools.md says it in
// a generated header that make docs keeps right, and the tests of the registry hold the numbers
// themselves.) A tool added without these changed would leave them wrong where no reader of
// the code would look.
var (
	readmeAPITools   = regexp.MustCompile(`reads the Tailscale API \(([0-9]+) tools, two of them for alpha features`)
	readmeLocalTools = regexp.MustCompile(`this node's Tailscale state \(([0-9]+) tools\)`)
	makefileCalls    = regexp.MustCompile(`Each of the ([0-9]+) calls may take`)
)

// countProblems says what the README and the Makefile state wrongly: a number that is not the
// registry's, or a sentence that is no longer there (a count that cannot be found is a problem,
// not a pass).
func countProblems(readme, makefile string, api, local, calls int) []string {
	var out []string
	for _, c := range []struct {
		what string
		re   *regexp.Regexp
		text string
		want int
	}{
		{"the README's count of the API tools", readmeAPITools, readme, api},
		{"the README's count of the local tools", readmeLocalTools, readme, local},
		{"the Makefile's count of the live calls", makefileCalls, makefile, calls},
	} {
		m := c.re.FindStringSubmatch(c.text)
		if m == nil {
			out = append(out, fmt.Sprintf("%s is not stated: the sentence this test reads has changed", c.what))
			continue
		}
		if n, _ := strconv.Atoi(m[1]); n != c.want {
			out = append(out, fmt.Sprintf("%s is %d, the registry has %d", c.what, n, c.want))
		}
	}
	return out
}

func TestTheCountsInTheReadmeAndTheMakefileAreTheRegistrys(t *testing.T) {
	reg := newRegistry(t)
	var api, local int
	for _, tool := range reg.All() {
		if tool.Meta.Tier == registry.TierLocal {
			local++
		} else {
			api++
		}
	}
	read := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	readme, makefile := read("../../README.md"), read("../../Makefile")
	// The live run starts one process per tool, and seven more at most: an empty
	// patch, a copy of the policy that is not byte-identical, its second spelling, a
	// stored version compared with itself, one acl_test by pseudonym, the GitOps
	// oracle's diff and doctor --probe.
	const further = 7
	for _, p := range countProblems(readme, makefile, api, local, api+local+further) {
		t.Error(p)
	}
	// The check can fail, in each of its ways. The samples are written here, so that a
	// wrong sentence in the real files does not hide whether the check can see one.
	sample := func(api, local, calls int) (readme, makefile string) {
		return fmt.Sprintf("tailkeeper reads the Tailscale API (%d tools, two of them for alpha features, which MCP lists only with `--enable-alpha`) and this node's Tailscale state (%d tools).", api, local),
			fmt.Sprintf("# The go test timeout is 1500s. Each of the %d calls may take up to 90s (live_test.go),", calls)
	}
	goodReadme, goodMakefile := sample(api, local, api+local+further)
	if p := countProblems(goodReadme, goodMakefile, api, local, api+local+further); len(p) != 0 {
		t.Errorf("samples with the registry's counts: %v", p)
	}
	for name, c := range map[string]struct {
		api, local, calls int
		want              string
	}{
		"a README count of the API tools that is not the registry's":   {api - 1, local, api + local, fmt.Sprintf("the README's count of the API tools is %d, the registry has %d", api-1, api)},
		"a README count of the local tools that is not the registry's": {api, local + 1, api + local, fmt.Sprintf("the README's count of the local tools is %d, the registry has %d", local+1, local)},
		"a Makefile count that is not the registry's":                  {api, local, api + local + 1, fmt.Sprintf("the Makefile's count of the live calls is %d, the registry has %d", api+local+1, api+local)},
	} {
		readmeText, makefileText := sample(c.api, c.local, c.calls)
		if got := strings.Join(countProblems(readmeText, makefileText, api, local, api+local), "\n"); !strings.Contains(got, c.want) {
			t.Errorf("%s: problems %q, want one that says %q", name, got, c.want)
		}
	}
	if got := strings.Join(countProblems("no counts here", "nor here", api, local, api+local), "\n"); strings.Count(got, "is not stated") != 3 {
		t.Errorf("text with no counts: %q, want the three sentences reported as not stated", got)
	}
}
