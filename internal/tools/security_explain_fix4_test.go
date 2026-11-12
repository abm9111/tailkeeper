package tools_test

import (
	"strings"
	"testing"
)

// Tests of the fourth follow-up to the review of `security explain`. Every name is a reserved one.

// An expectation that names the coordinates of tailkeeper's own canary (the address 192.0.2.1 on
// port 1 for a network pair; the user canary on 192.0.2.1 for an SSH pair) is never judged from
// silence: a reply that proves the canary and holds nothing for the source reads, there, exactly as
// the canary's own line does. Its pairs are unknown, and are not put to Tailscale.
func TestAnExpectationThatNamesTheCanaryCoordinatesIsNeverJudgedFromSilence(t *testing.T) {
	const allowAll = `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`
	cases := []struct {
		name, policy, intent string
		model                func() *policyModel
	}{
		{"a network deny of the canary's destination, the policy allows everything", allowAll,
			`{"tests": [{"src": "tag:example-web", "deny": ["192.0.2.1:1"]}]}`,
			func() *policyModel { return &policyModel{allow: map[string]bool{}} }},
		{"a network accept of the canary's destination, the policy allows nothing", `{"acls": []}`,
			`{"tests": [{"src": "tag:example-web", "accept": ["192.0.2.1:1"]}]}`,
			func() *policyModel {
				return &policyModel{allow: map[string]bool{"tag:example-web|192.0.2.1:1": true},
					canaryText: `[acl test error]: address "192.0.2.1:1": want: Accept, got: Drop`}
			}},
		{"an SSH accept of the canary's user on the canary's destination", allowAll,
			`{"sshTests": [{"src": "tag:example-a", "dst": ["192.0.2.1"], "accept": ["canary"]}]}`,
			func() *policyModel {
				return &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{"tag:example-a|192.0.2.1|canary": true}}
			}},
		{"an SSH deny of the canary's user on the canary's destination", allowAll,
			`{"sshTests": [{"src": "tag:example-a", "dst": ["192.0.2.1"], "deny": ["canary"]}]}`,
			func() *policyModel { return &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{}} }},
		{"a host alias for the canary's address", `{"hosts": {"example-canary": "192.0.2.1"}, "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`,
			`{"tests": [{"src": "tag:example-web", "deny": ["example-canary:1"]}]}`,
			func() *policyModel { return &policyModel{allow: map[string]bool{}} }},
		{"the canary's address written as a port range that holds port 1", allowAll,
			`{"tests": [{"src": "tag:example-web", "deny": ["192.0.2.1:1-100"]}]}`,
			func() *policyModel { return &policyModel{allow: map[string]bool{}} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := c.model()
			f, env := explainEnv(t, c.policy, m)
			out, err := explainOnce(t, env, c.intent)
			if err != nil {
				t.Fatal(err)
			}
			row := rowOf(out, "network-1")
			if row.ID == "" {
				row = rowOf(out, "ssh-1")
			}
			if row.Status != "unknown" || len(row.Cells) != 1 || row.Cells[0].Reason != "canary_coordinates" || row.Cells[0].Canary {
				t.Errorf("row = %+v, want unknown by canary_coordinates", row)
			}
			if out.Counts.Met != 0 || out.ExitCode() != 1 || out.Status != "incomplete" {
				t.Errorf("counts %+v exit %d status %s, want nothing met and exit 1", out.Counts, out.ExitCode(), out.Status)
			}
			if got := posts(f); got != 0 {
				t.Errorf("%d validation requests for pairs that are not put to Tailscale, want none", got)
			}
		})
	}
}

// What is not at the canary's coordinates is judged as before, beside a pair that is: the pair
// that names the canary is unknown and is not in the request, the others are asked.
func TestOnlyThePairsAtTheCanaryCoordinatesAreSetAside(t *testing.T) {
	t.Run("other ports, users and addresses are judged", func(t *testing.T) {
		intent := `{
		"tests": [{"src": "tag:example-web", "deny": ["192.0.2.1:2", "192.0.2.2:1", "192.0.2.10:1"]}],
		"sshTests": [{"src": "tag:example-a", "dst": ["192.0.2.1"], "accept": ["root"]}, {"src": "tag:example-b", "dst": ["192.0.2.2"], "accept": ["canary"]}],
	}`
		m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{"tag:example-a|192.0.2.1|root": true, "tag:example-b|192.0.2.2|canary": true}}
		_, env := explainEnv(t, allowNothingPolicy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		if out.Counts.Met != 3 || out.ExitCode() != 0 {
			t.Errorf("counts %+v exit %d, want all three met: %+v", out.Counts, out.ExitCode(), out.Expectations)
		}
	})
	t.Run("a pair beside one that names the canary", func(t *testing.T) {
		intent := `{"tests": [{"src": "tag:example-web", "deny": ["192.0.2.1:1", "tag:example-db:22"]}]}`
		m := &policyModel{allow: map[string]bool{}}
		_, env := explainEnv(t, allowNothingPolicy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		row := rowOf(out, "network-1")
		if len(row.Cells) != 2 || row.Cells[0].Reason != "canary_coordinates" || row.Cells[1].Verdict != "met" {
			t.Fatalf("cells = %+v, want the canary's destination unknown and the other met", row.Cells)
		}
		if row.Status != "unknown" || out.ExitCode() != 1 {
			t.Errorf("status %s exit %d, want unknown and exit 1", row.Status, out.ExitCode())
		}
		for _, sent := range m.sentTexts(t) {
			for _, test := range sent.Tests {
				if strings.HasPrefix(test.Src, "tag:example-web") && (len(test.Deny) != 1 || test.Deny[0] != "tag:example-db:22") {
					t.Errorf("the request holds %v, want only the destination that does not name the canary", test.Deny)
				}
			}
		}
	})
}

// A policy that allows nothing the intents above ask about.
const allowNothingPolicy = `{"acls": [{"action": "accept", "src": ["tag:example-x"], "dst": ["tag:example-y:22"]}]}`
