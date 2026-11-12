package tools_test

import (
	"strings"
	"testing"
)

// Tests of the fifth item of the fourth follow-up (the VIGIL audit). Every name is a reserved one.

// An ssh rule can carry srcPosture, and defaultSrcPosture gates it: the witness is a validation of
// a device that reports no posture, so a deny that holds for it holds for no compliant device. An
// SSH expectation is met_with_limits (posture), never met, beside a posture-gated ssh rule or a
// default posture that is not shown to be about other users or other destinations, and beside ssh
// rules that were not listed or could not be read. A network expectation is not touched by an ssh
// rule: it is a different question.
func TestAPostureGatedSSHRuleIsALimitOfAnSSHExpectation(t *testing.T) {
	const postures = `"postures": {"posture:example": ["node:os == 'linux'"]}`
	deny := `{"sshTests": [{"src": "group:example-admins", "dst": ["tag:example-db"], "deny": ["root"]}]}`
	cases := []struct {
		name, policy, intent string
		status               string
		limits               []string
	}{
		{"a posture-gated ssh rule for the user", `{"ssh": [{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db"], "users": ["root"], "srcPosture": ["posture:example"]}], ` + postures + `}`,
			deny, "met_with_limits", []string{"posture"}},
		{"a posture-gated ssh rule for autogroup:nonroot against root and another user", `{"ssh": [{"action": "accept", "src": ["*"], "dst": ["tag:example-db"], "users": ["autogroup:nonroot"], "srcPosture": ["posture:example"]}], ` + postures + `}`,
			`{"sshTests": [{"src": "group:example-admins", "dst": ["tag:example-db"], "deny": ["root", "deploy"]}]}`, "met_with_limits", []string{"posture"}},
		{"a posture-gated ssh rule and an accept expectation", `{"ssh": [{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db"], "users": ["root"], "srcPosture": ["posture:example"]}], ` + postures + `}`,
			`{"sshTests": [{"src": "group:example-admins", "dst": ["tag:example-db"], "accept": ["root"]}]}`, "met_with_limits", []string{"posture"}},
		{"a default posture and a plain ssh rule", `{"ssh": [{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db"], "users": ["root"]}], "defaultSrcPosture": ["posture:example"], ` + postures + `}`,
			deny, "met_with_limits", []string{"posture"}},
		{"a default posture and no ssh rule at all", `{"defaultSrcPosture": ["posture:example"], ` + postures + `}`,
			deny, "met_with_limits", []string{"posture"}},
		{"an ssh rule that cannot be read", `{"ssh": ["not a rule"]}`, deny, "met_with_limits", []string{"rules"}},
		{"a posture-gated ssh rule for another user", `{"ssh": [{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db"], "users": ["ubuntu"], "srcPosture": ["posture:example"]}], ` + postures + `}`,
			deny, "met", nil},
		{"a posture-gated ssh rule for another address", `{"ssh": [{"action": "accept", "src": ["group:example-admins"], "dst": ["198.51.100.0/24"], "users": ["root"], "srcPosture": ["posture:example"]}], ` + postures + `}`,
			`{"sshTests": [{"src": "group:example-admins", "dst": ["192.0.2.5"], "deny": ["root"]}]}`, "met", nil},
		{"an ssh rule with no posture", `{"ssh": [{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db"], "users": ["root"]}]}`,
			deny, "met", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{}}
			if strings.Contains(c.intent, `"accept"`) {
				m.sshAllow["group:example-admins|tag:example-db|root"] = true
			}
			_, env := explainEnv(t, c.policy, m)
			out, err := explainOnce(t, env, c.intent)
			if err != nil {
				t.Fatal(err)
			}
			row := rowOf(out, "ssh-1")
			if row.Status != c.status || strings.Join(row.Limits, ",") != strings.Join(c.limits, ",") {
				t.Fatalf("ssh-1 = %s with limits %v, want %s with %v", row.Status, row.Limits, c.status, c.limits)
			}
			wantMet := 0
			if c.status == "met" {
				wantMet = 1
			}
			if out.Counts.Met != wantMet || (c.status == "met") != (out.ExitCode() == 0) {
				t.Errorf("counts %+v exit %d status %s: a met_with_limits is not met and is not exit 0", out.Counts, out.ExitCode(), out.Status)
			}
		})
	}
	t.Run("the fixed sentence of the limit is stated", func(t *testing.T) {
		policy := `{"ssh": [{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db"], "users": ["root"], "srcPosture": ["posture:example"]}], ` + postures + `}`
		m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{}}
		_, env := explainEnv(t, policy, m)
		out, err := explainOnce(t, env, deny)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(reportText(out), "depends on device posture") {
			t.Errorf("the sentence is not stated:\n%s", reportText(out))
		}
	})
	t.Run("an ssh rule is not a limit of a network expectation", func(t *testing.T) {
		policy := `{"ssh": [{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db"], "users": ["root"], "srcPosture": ["posture:example"]}], ` + postures + `}`
		m := &policyModel{allow: map[string]bool{}}
		_, env := explainEnv(t, policy, m)
		out, err := explainOnce(t, env, `{"tests": [{"src": "group:example-admins", "deny": ["tag:example-db:22"]}]}`)
		if err != nil {
			t.Fatal(err)
		}
		if row := rowOf(out, "network-1"); row.Status != "met" || len(row.Limits) != 0 || out.ExitCode() != 0 {
			t.Errorf("network-1 = %s with limits %v, exit %d, want met: an ssh rule says nothing of network reachability", row.Status, row.Limits, out.ExitCode())
		}
	})
}
