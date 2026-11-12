package tools_test

import (
	"fmt"
	"strings"
	"testing"
)

// Tests of the third follow-up to the review of `security explain`. Every name is a reserved one.

// "policy grants this source all destinations" is said only for a rule that allows every
// destination on every port and every protocol: an acls rule with the destination *:* and no proto,
// or a grant with the destination * and the ip entry *. A rule with the destination * that limits
// the ports or the protocol stays a candidate and is not said to grant all of anything; where the
// blast radius lists it, it says what the rule writes.
func TestAWildcardRuleLimitedByPortOrProtocolDoesNotGrantAllDestinations(t *testing.T) {
	const all = "policy grants this source all destinations"
	intent := `{"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}]}`
	cases := []struct {
		name, policy string
		every        string // what the rule is said to grant every destination on; "" when it is said to grant all
	}{
		{"acls *:*", `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`, ""},
		{"a grant for * with ip *", `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`, ""},
		{"a grant for * with ip * beside a limited entry", `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["tcp:22", "*"]}]}`, ""},
		{"acls *:22", `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:22"]}]}`, "ports 22"},
		{"acls *:22,443", `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:22,443"]}]}`, "ports 22,443"},
		{"acls *:* with a proto", `{"acls": [{"action": "accept", "src": ["*"], "proto": "tcp", "dst": ["*:*"]}]}`, "proto tcp, ports *"},
		{"acls *:22 with protos", `{"acls": [{"action": "accept", "src": ["*"], "proto": ["tcp", "udp"], "dst": ["*:22"]}]}`, "proto tcp,udp, ports 22"},
		{"a grant for * with ip tcp:22", `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["tcp:22"]}]}`, "tcp:22"},
		{"a grant for * with two ip entries", `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["tcp:22", "udp:53"]}]}`, "tcp:22, udp:53"},
		{"acls with a narrow and an all-ports destination", `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:22", "*:*"]}]}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &policyModel{allow: map[string]bool{"tag:example-web|tag:example-db:22": true}}
			_, env := explainEnv(t, c.policy, m)
			out, err := explainOnce(t, env, intent)
			if err != nil {
				t.Fatal(err)
			}
			row := rowOf(out, "network-1")
			if row.Status != "unmet" || len(row.Candidates) != 1 || !row.Candidates[0].Broad || row.Candidates[0].Qualified {
				t.Fatalf("row = %+v, want unmet with the one plain rule for * as a candidate", row)
			}
			text := reportText(out)
			if c.every == "" {
				if !strings.Contains(text, all+" (candidate rule at ") {
					t.Errorf("a rule that allows every port and protocol is not said to grant all destinations:\n%s", text)
				}
				return
			}
			if strings.Contains(text, all) {
				t.Errorf("a rule limited to %q is said to grant all destinations:\n%s", c.every, text)
			}
			if want := fmt.Sprintf("policy grants this source every destination on %s (candidate rule at ", c.every); !strings.Contains(text, want) {
				t.Errorf("the blast radius does not say what the rule writes, %q:\n%s", want, text)
			}
		})
	}
	t.Run("a rule that states nothing to quote is a candidate and is not listed", func(t *testing.T) {
		// A grant with no ip entries and no app capabilities allows no traffic that can be quoted.
		policy := `{"grants": [{"src": ["*"], "dst": ["*"]}]}`
		m := &policyModel{allow: map[string]bool{"tag:example-web|tag:example-db:22": true}}
		_, env := explainEnv(t, policy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		if len(rowOf(out, "network-1").Candidates) != 1 {
			t.Fatalf("candidates = %+v", rowOf(out, "network-1").Candidates)
		}
		if text := reportText(out); strings.Contains(text, "policy grants this source") {
			t.Errorf("a rule that allows nothing quotable is said to grant something:\n%s", text)
		}
	})
}
