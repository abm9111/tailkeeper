package cli

import (
	"bytes"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// One of a kind is shown like many: a single class prints the changes block, and
// a single finding of Tailscale's own sits behind the notice.
func TestTheLayoutShowsASingleClassAndASingleUntrustedFinding(t *testing.T) {
	rep := registry.Report{
		Verdict:  "VALID",
		Classes:  []registry.ClassCount{{Class: "defaults", Count: 1, Expected: true}},
		Findings: []registry.Finding{{Severity: "warning", Source: "from", Line: 3, Column: 2, Message: "from Tailscale", Untrusted: true}},
	}
	var b bytes.Buffer
	if err := formatText(&b, rep, formatOptions{Names: map[string]string{"from": "policy.hujson"}}); err != nil {
		t.Fatal(err)
	}
	want := "VALID\nchanges\n  defaults           1  (expected)\n" + registry.UntrustedReasonsNotice + "\npolicy.hujson:3:2: warning: from Tailscale\n"
	if b.String() != want {
		t.Errorf("layout:\n%q\nwant:\n%q", b.String(), want)
	}
}
