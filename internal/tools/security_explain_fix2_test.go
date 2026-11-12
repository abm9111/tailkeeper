package tools_test

import (
	"strings"
	"testing"
)

// Tests of the second follow-up to the review of `security explain`. Every name is a reserved one.

// The SSH canary proves that sshTests ran, and its entry is the canary's own: the line in it must
// quote the canary's tag as its source. A failure of an expectation's source filed under the
// canary's tag is that source's failure, not the canary: taken for the canary it would leave the
// source with no failure, and silence is a pass. The expectation asks about a pair of its own (the
// canary's coordinates are set aside, see TestAnExpectationThatNamesTheCanaryCoordinates...), and
// the line filed under the canary's tag is the canary's in every way but its source.
func TestASSHFailureFiledUnderTheCanaryTagIsNotTheCanary(t *testing.T) {
	for _, c := range []struct {
		name, intent, quoted, want, got string
	}{
		{"the source of an accept expectation",
			`{"sshTests": [{"src": "tag:example-a", "dst": ["tag:example-db"], "accept": ["root"]}]}`,
			"tag:example-a", "accept", "deny"},
		{"the source of a deny expectation",
			`{"sshTests": [{"src": "tag:example-a", "dst": ["tag:example-db"], "deny": ["root"]}]}`,
			"tag:example-a", "deny", "accept"},
		{"a source nobody asked about",
			`{"sshTests": [{"src": "tag:example-a", "dst": ["tag:example-db"], "accept": ["root"]}]}`,
			"tag:example-zz", "accept", "deny"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{"tag:example-a|tag:example-db|root": c.want == "accept"}}
			m.sshCanaryLines = func(string) []string {
				return []string{sshLine(c.quoted, "192.0.2.1", "canary", c.want, c.got)}
			}
			_, env := explainEnv(t, explainPolicy, m)
			out, err := explainOnce(t, env, c.intent)
			if err != nil {
				t.Fatal(err)
			}
			row := rowOf(out, "ssh-1")
			if len(row.Cells) != 1 {
				t.Fatalf("cells = %+v", row.Cells)
			}
			if row.Status != "unknown" || row.Cells[0].Reason != "canary" || row.Cells[0].Canary {
				t.Errorf("ssh-1 = %s by %q (canary %v): a line that quotes %s is not the canary, and no canary is no verdict", row.Status, row.Cells[0].Reason, row.Cells[0].Canary, c.quoted)
			}
			if out.Counts.Met != 0 || out.ExitCode() != 1 || out.Status != "incomplete" {
				t.Errorf("counts %+v exit %d status %s, want nothing met and exit 1", out.Counts, out.ExitCode(), out.Status)
			}
		})
	}
}

// The tests canary's line (address, want, got) quotes no source: its entry is its only
// attribution, as it is for every line of the tests form. What the entry must hold is the
// canary's one line, and a second line of its text filed beside it makes two.
func TestAFailureFiledBesideTheTestsCanaryIsNotProof(t *testing.T) {
	intent := `{"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}]}`
	m := &policyModel{allow: map[string]bool{}}
	m.canaryExtra = func() []string {
		return []string{`[acl test error]: address "192.0.2.1:1": want: Drop, got: Accept`}
	}
	_, env := explainEnv(t, explainPolicy, m)
	out, err := explainOnce(t, env, intent)
	if err != nil {
		t.Fatal(err)
	}
	row := rowOf(out, "network-1")
	if row.Status != "unknown" || row.Cells[0].Reason != "canary" || out.Counts.Met != 0 || out.ExitCode() != 1 {
		t.Errorf("network-1 = %s by %q, counts %+v, exit %d: an entry with two lines is not the canary", row.Status, row.Cells[0].Reason, out.Counts, out.ExitCode())
	}
}

// A policy's defaultSrcPosture gates every rule that has no srcPosture of its own, so a rule
// of it is qualified whether or not the rule names a posture, and "policy grants this source all
// destinations" is not said for it, with the expectation's posture attributes or without them.
func TestADefaultPostureQualifiesTheBroadRuleAndTheSentenceIsNotSaid(t *testing.T) {
	policy := `{
	"acls": [
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
	],
	"defaultSrcPosture": ["posture:example"],
	"postures": {"posture:example": ["node:os == 'linux'"]},
}`
	const sentence = "policy grants this source all destinations"
	t.Run("a denial witnessed for a device that reports no posture", func(t *testing.T) {
		intent := `{"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}]}`
		m := &policyModel{allow: map[string]bool{}}
		_, env := explainEnv(t, policy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		row := rowOf(out, "network-1")
		if row.Status != "met_with_limits" || len(row.Limits) != 1 || row.Limits[0] != "posture" || out.ExitCode() != 1 {
			t.Fatalf("status %s limits %v exit %d, want met_with_limits by posture", row.Status, row.Limits, out.ExitCode())
		}
		if len(row.Candidates) != 1 || !row.Candidates[0].Broad || !row.Candidates[0].Qualified {
			t.Errorf("candidates = %+v, want the broad rule, qualified by the default posture", row.Candidates)
		}
		if text := reportText(out); strings.Contains(text, sentence) {
			t.Errorf("the blast radius says the policy grants every destination, beside the posture limit:\n%s", text)
		}
		if blast := blastOf(out, "tag:example-web"); blast != nil && len(blast.Broad) != 0 {
			t.Errorf("blast = %+v, want no broad rule", blast)
		}
	})
	t.Run("a device that reports the posture reaches the database", func(t *testing.T) {
		intent := `{"tests": [{"src": "tag:example-web", "srcPostureAttrs": {"node:os": "linux"}, "deny": ["tag:example-db:22"]}]}`
		m := &policyModel{allow: map[string]bool{"tag:example-web|tag:example-db:22": true}}
		_, env := explainEnv(t, policy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		if row := rowOf(out, "network-1"); row.Status != "unmet" || len(row.Candidates) != 1 || !row.Candidates[0].Qualified {
			t.Fatalf("row = %+v, want unmet with the broad rule qualified: the attributes remove the limit, not the gate", row)
		}
		if text := reportText(out); strings.Contains(text, sentence) {
			t.Errorf("the policy is said to grant every destination to a source whose every rule is gated on posture:\n%s", text)
		}
		if blast := blastOf(out, "tag:example-web"); blast == nil || len(blast.Reaches) != 1 || len(blast.Broad) != 0 {
			t.Errorf("blast = %+v, want the witnessed pair and no broad rule", out.Blast)
		}
	})
	t.Run("without a default posture the plain rule is still said", func(t *testing.T) {
		plain := `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`
		intent := `{"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}]}`
		m := &policyModel{allow: map[string]bool{"tag:example-web|tag:example-db:22": true}}
		_, env := explainEnv(t, plain, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		if row := rowOf(out, "network-1"); len(row.Candidates) != 1 || row.Candidates[0].Qualified {
			t.Errorf("candidates = %+v, want the plain rule unqualified", row.Candidates)
		}
		if text := reportText(out); !strings.Contains(text, sentence) {
			t.Errorf("a plain broad rule is not said to grant every destination:\n%s", text)
		}
	})
}
