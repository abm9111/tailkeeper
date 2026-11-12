package tools_test

import (
	"strings"
	"testing"
)

// Tests of the fifth round of the review of `security explain`. Every name is a reserved one.

// An ssh rule whose users are not a list the reader understands is a rule it cannot read, not a rule
// with no users: with no users it would be shown to be about no one, and a posture-gated rule would
// keep nothing from being met.
func TestAnSSHRuleWhoseUsersCannotBeReadKeepsTheRulesLimit(t *testing.T) {
	const postures = `"postures": {"posture:example": ["node:os == 'linux'"]}`
	for name, users := range map[string]string{
		"a string":                 `"root"`,
		"a number":                 `7`,
		"an object":                `{"root": true}`,
		"a list with a non-string": `["root", 7]`,
	} {
		t.Run(name, func(t *testing.T) {
			policy := `{"ssh": [{"action": "accept", "src": ["*"], "dst": ["tag:example-db"], "users": ` + users + `, "srcPosture": ["posture:example"]}], ` + postures + `}`
			m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{}}
			_, env := explainEnv(t, policy, m)
			out, err := explainOnce(t, env, `{"sshTests": [{"src": "group:example-admins", "dst": ["tag:example-db"], "deny": ["root"]}]}`)
			if err != nil {
				t.Fatal(err)
			}
			row := rowOf(out, "ssh-1")
			if row.Status != "met_with_limits" || !strings.Contains(strings.Join(row.Limits, ","), "rules") || out.ExitCode() != 1 || out.Counts.Met != 0 {
				t.Errorf("ssh-1 = %s with limits %v, exit %d, counts %+v, want met_with_limits by rules and exit 1", row.Status, row.Limits, out.ExitCode(), out.Counts)
			}
		})
	}
}

// A default posture that is not a list is not "no default posture": it keeps an SSH expectation, and a
// network one, from being met.
func TestAMalformedDefaultPostureStillLimitsTheExpectations(t *testing.T) {
	for _, value := range []string{`"posture:example"`, `7`, `{"posture:example": true}`} {
		policy := `{"ssh": [{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db"], "users": ["root"]}], "defaultSrcPosture": ` + value + `}`
		m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{}}
		_, env := explainEnv(t, policy, m)
		out, err := explainOnce(t, env, `{
			"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}],
			"sshTests": [{"src": "group:example-admins", "dst": ["tag:example-db"], "deny": ["root"]}],
		}`)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"network-1", "ssh-1"} {
			if row := rowOf(out, id); row.Status != "met_with_limits" || strings.Join(row.Limits, ",") != "posture" {
				t.Errorf("defaultSrcPosture %s: %s = %s with limits %v, want met_with_limits by posture", value, id, row.Status, row.Limits)
			}
		}
		if out.ExitCode() != 1 || out.Counts.Met != 0 {
			t.Errorf("defaultSrcPosture %s: exit %d counts %+v", value, out.ExitCode(), out.Counts)
		}
	}
}

// The accept and check users of an SSH expectation take part in the test for other users, not the deny
// users alone: a posture-gated rule for the user an expectation accepts is not about other users because
// the user it denies is another.
func TestTheAcceptUsersOfAnSSHExpectationTakePartInTheOtherUsersTest(t *testing.T) {
	policy := `{"ssh": [{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db"], "users": ["root"], "srcPosture": ["posture:example"]}], "postures": {"posture:example": ["node:os == 'linux'"]}}`
	m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{"group:example-admins|tag:example-db|root": true}}
	_, env := explainEnv(t, policy, m)
	out, err := explainOnce(t, env, `{"sshTests": [{"src": "group:example-admins", "dst": ["tag:example-db"], "accept": ["root"], "deny": ["deploy"]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if row := rowOf(out, "ssh-1"); row.Status != "met_with_limits" || strings.Join(row.Limits, ",") != "posture" || out.ExitCode() != 1 || out.Counts.Met != 0 {
		t.Errorf("ssh-1 = %s with limits %v, exit %d, counts %+v, want met_with_limits by posture and exit 1", row.Status, row.Limits, out.ExitCode(), out.Counts)
	}
}

// An ssh candidate is marked as qualified when srcPosture or defaultSrcPosture gates it, as the others
// are, and is not otherwise; the marker is said in the candidate's line.
func TestAnSSHCandidateIsMarkedQualifiedWhenPostureGatesIt(t *testing.T) {
	const gate = `"srcPosture": ["posture:example"]`
	const postures = `"postures": {"posture:example": ["node:os == 'linux'"]}`
	rule := func(extra string) string {
		return `{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db"], "users": ["root"]` + extra + `}`
	}
	for name, c := range map[string]struct {
		policy string
		want   bool
	}{
		"a rule gated on srcPosture":  {`{"ssh": [` + rule(", "+gate) + `], ` + postures + `}`, true},
		"a default posture":           {`{"ssh": [` + rule("") + `], "defaultSrcPosture": ["posture:example"], ` + postures + `}`, true},
		"a malformed default posture": {`{"ssh": [` + rule("") + `], "defaultSrcPosture": "posture:example"}`, true},
		"a rule with no posture":      {`{"ssh": [` + rule("") + `]}`, false},
	} {
		m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{}}
		_, env := explainEnv(t, c.policy, m)
		out, err := explainOnce(t, env, `{"sshTests": [{"src": "group:example-admins", "dst": ["tag:example-db"], "deny": ["root"]}]}`)
		if err != nil {
			t.Fatal(err)
		}
		cands := rowOf(out, "ssh-1").Candidates
		if len(cands) != 1 || cands[0].Qualified != c.want || cands[0].Section != "ssh" {
			t.Errorf("%s: candidates %+v, want one ssh rule with qualified = %v", name, cands, c.want)
		}
		if has := strings.Contains(reportText(out), "qualified by srcPosture or defaultSrcPosture"); has != c.want {
			t.Errorf("%s: the marker is said = %v, want %v", name, has, c.want)
		}
		if strings.Contains(reportText(out), "policy grants this source") {
			t.Errorf("%s: an ssh rule is said to grant every destination", name)
		}
	}
}
