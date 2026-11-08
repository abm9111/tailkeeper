package tools_test

import (
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tools"
)

// Tests of the eighth round of the review of `security explain`.

// A grant whose via or app is not what the reader understands is not a grant without them: a via that
// is not a list of strings, and an app that is not an object or null, are read as set, and the
// expectation they could apply to is at best met with the limit. The same grant with a via that is
// an empty list, or an app that is null or an empty object, is met with no limit, so that the limit is
// the malformed field's and nothing else's.
func TestAGrantWhoseViaOrAppCannotBeReadKeepsItsLimit(t *testing.T) {
	run := func(t *testing.T, field string) (row tools.SecurityExplainRow, exit int, met int) {
		t.Helper()
		policy := `{"grants": [{"src": ["*"], "dst": ["tag:example-db"], "ip": ["*"]` + field + `}]}`
		m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{}}
		_, env := explainEnv(t, policy, m)
		out, err := explainOnce(t, env, `{"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}]}`)
		if err != nil {
			t.Fatal(err)
		}
		return rowOf(out, "network-1"), out.ExitCode(), out.Counts.Met
	}
	for _, c := range []struct{ name, field, limit string }{
		{"a via that is a string", `, "via": "tag:example-exit"`, "via"},
		{"a via that is a number", `, "via": 7`, "via"},
		{"a via that is a list with a non-string", `, "via": ["tag:example-exit", 7]`, "via"},
		{"a via that is a list", `, "via": ["tag:example-exit"]`, "via"},
		{"an app that is a string", `, "app": "tailscale.com/cap/example"`, "app"},
		{"an app that is a number", `, "app": 7`, "app"},
		{"an app that is a list", `, "app": ["tailscale.com/cap/example"]`, "app"},
		{"an app that is an object", `, "app": {"tailscale.com/cap/example": [{}]}`, "app"},
	} {
		t.Run(c.name, func(t *testing.T) {
			row, exit, met := run(t, c.field)
			if row.Status != "met_with_limits" || strings.Join(row.Limits, ",") != c.limit || exit != 1 || met != 0 {
				t.Errorf("network-1 = %s with limits %v, exit %d, %d met, want met_with_limits by %s and exit 1", row.Status, row.Limits, exit, met, c.limit)
			}
		})
	}
	for name, field := range map[string]string{"no via or app": ``, "a via that is an empty list": `, "via": []`, "an app that is null": `, "app": null`, "an app that is an empty object": `, "app": {}`} {
		t.Run(name, func(t *testing.T) {
			if row, exit, met := run(t, field); row.Status != "met" || len(row.Limits) != 0 || exit != 0 || met != 1 {
				t.Errorf("network-1 = %s with limits %v, exit %d, %d met, want met with no limit and exit 0", row.Status, row.Limits, exit, met)
			}
		})
	}
}
