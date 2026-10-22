package cli

import (
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// An empty patch, from a file or from standard input, is no patch: the tool reads an empty
// field as "validate the live policy", so a step whose patch render produced nothing would
// go green on a policy nobody changed. It is refused with exit 2 and no request, as an empty
// policy is.
func TestACLValidateRefusesAnEmptyPatch(t *testing.T) {
	empty := writeFile(t, "empty.json", "")
	for name, args := range map[string][]string{
		"--patch":                   {"--patch", empty},
		"--patch on standard input": {"--patch", "-"},
	} {
		f := apitest.New(t)
		h := newHarness(t, f)
		h.r.Stdin = strings.NewReader("")
		if code := h.run(append([]string{"acl", "validate"}, args...)...); code != 2 || !strings.Contains(h.err.String(), " is empty; ") {
			t.Errorf("%s: exit %d, stderr %q; want 2 and a refusal that says the text is empty", name, code, h.err)
		}
		if h.out.Len() != 0 || len(f.Requests()) != 0 {
			t.Errorf("%s: stdout %q, %d requests; want none", name, h.out, len(f.Requests()))
		}
	}
}
