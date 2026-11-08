package tools_test

import (
	"strings"
	"testing"
)

// A candidate and a blast radius carry what the rule allows of ports and protocols, as the rule
// writes it, beside the sentence: every port and protocol, or the limit. The text is a tailnet
// string, tagged untrusted by the output's type like the ports of a rule.
func TestACandidateAndTheBlastRadiusCarryTheTrafficOfTheRule(t *testing.T) {
	intent := `{"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}]}`
	for _, c := range []struct {
		name, policy string
		all          bool
		traffic      string
	}{
		{"acls *:*", `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`, true, ""},
		{"acls *:22 with a proto", `{"acls": [{"action": "accept", "src": ["*"], "proto": "tcp", "dst": ["*:22"]}]}`, false, "proto tcp, ports 22"},
		{"a grant with ip tcp:22", `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["tcp:22"]}]}`, false, "tcp:22"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := &policyModel{allow: map[string]bool{"tag:example-web|tag:example-db:22": true}}
			_, env := explainEnv(t, c.policy, m)
			out, err := explainOnce(t, env, intent)
			if err != nil {
				t.Fatal(err)
			}
			row := rowOf(out, "network-1")
			if len(row.Candidates) != 1 || row.Candidates[0].AllTraffic != c.all || row.Candidates[0].Traffic != c.traffic {
				t.Errorf("candidates = %+v, want all %v traffic %q", row.Candidates, c.all, c.traffic)
			}
			blast := blastOf(out, "tag:example-web")
			if blast == nil || len(blast.Broad) != 1 || blast.Broad[0].AllTraffic != c.all || blast.Broad[0].Traffic != c.traffic {
				t.Errorf("blast = %+v, want the same rule with the same traffic", blast)
			}
		})
	}
}

// The line of the blast radius that quotes a rule's traffic holds a word of the policy's, so it is
// marked untrusted like every finding that does: the layouts print it behind the notice and escape it.
func TestTheBlastLineThatQuotesTrafficIsMarkedUntrusted(t *testing.T) {
	for _, policy := range []string{
		`{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`,
		`{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["tcp:22"]}]}`,
	} {
		m := &policyModel{allow: map[string]bool{"tag:example-web|tag:example-db:22": true}}
		_, env := explainEnv(t, policy, m)
		out, err := explainOnce(t, env, `{"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}]}`)
		if err != nil {
			t.Fatal(err)
		}
		seen := 0
		for _, f := range out.Report().Findings {
			if strings.Contains(f.Message, "policy grants this source") {
				seen++
				if !f.Untrusted {
					t.Errorf("%q is not marked untrusted", f.Message)
				}
			}
		}
		if seen != 1 {
			t.Errorf("%d blast lines about the rule, want 1", seen)
		}
	}
}
