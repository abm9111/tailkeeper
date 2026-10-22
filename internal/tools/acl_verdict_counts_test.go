package tools_test

import (
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// validateDirect validates a proposal and returns the result as the command line sees it,
// not decoded from JSON: the verdict is read from what the tool counted.
func validateDirect(t *testing.T, live string, storedErrors []string, answer apitest.Shape, proposal string) tools.ACLValidateOutput {
	t.Helper()
	f, _, env := apiEnv(t)
	serveLive(f, live, nil, storedErrors)
	f.ServeValidate(answer)
	out, err := runValidate(t, env, func(in *tools.ACLValidateInput) { in.Policy = proposal })
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	return out
}

// The first line of the report counts what Tailscale said, not the places tailkeeper filed it
// at: one failing assertion whose source matches two tests is one failed assertion, and one
// message that quotes a name held in three places is one message.
func TestTheVerdictCountsTailscalesMessagesNotTheirPlaces(t *testing.T) {
	twoTests := "{\n\"tests\": [\n{\"src\": \"tag:ci\", \"accept\": [\"tag:ci:22\"]},\n{\"src\": \"tag:ci\", \"accept\": [\"tag:ci:80\"]},\n],\n}\n"
	fails := func(user string, lines ...string) apitest.Entry { return apitest.Entry{User: user, Errors: lines} }
	assertion := func(dst string) string {
		return `[acl test error]: address "` + dst + `": want: Accept, got: Drop`
	}
	for _, c := range []struct {
		name, proposal string
		answer         apitest.Shape
		places         int
		verdict        string
	}{
		{"one failing assertion at two tests", twoTests, apitest.TestsFailed(fails("tag:ci", assertion("192.0.2.9:22"))), 2,
			"FAILED · 1 failed assertion · invariants: none"},
		{"two failing assertions", placedProposal, apitest.TestsFailed(fails("tag:b", assertion("tag:b:22")), fails("tag:a", assertion("tag:a:22"))), 2,
			"FAILED · 2 failed assertions · invariants: none"},
		{"one unevaluable test named in three places", placedProposal,
			apitest.TestsFailed(fails("tag:x", `[acl test error]: user or host is invalid: tag not found: "tag:x"`)), 3,
			"UNRESOLVED · 1 test cannot be evaluated: a name or destination does not resolve"},
		{"one rejection quoted in three places", placedProposal, apitest.PolicyTagNotFound("tag:x"), 3,
			"REJECTED · Tailscale refused the text (1 message)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			out := validateDirect(t, liveText, nil, c.answer, c.proposal)
			if len(out.Errors) != c.places {
				t.Fatalf("%d problems, want %d places for the one message: %+v", len(out.Errors), c.places, out.Errors)
			}
			if v := out.Report().Verdict; v != c.verdict {
				t.Errorf("verdict = %q, want %q", v, c.verdict)
			}
		})
	}
	// The messages Tailscale stored with the live policy are its messages too; tailkeeper's own
	// note about them is not.
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, []string{"policy no longer parses: tag:gone", "tag:other is unknown"})
	f.ServeValidate(apitest.TestsPassEmptyObject())
	out, err := runValidate(t, env, func(in *tools.ACLValidateInput) {})
	if err != nil || out.Status != "rejected" {
		t.Fatalf("status %q, err %v", out.Status, err)
	}
	if v := out.Report().Verdict; v != "REJECTED · the live policy has errors Tailscale stored with it, so nothing was sent (2 messages)" {
		t.Errorf("stored errors: verdict = %q", v)
	}
	// A result decoded from JSON has no counts, and its verdict counts what it lists.
	if v := (tools.ACLValidateOutput{Status: "rejected", Errors: []tools.ACLProblem{{Kind: "server_message"}}}).Report().Verdict; !strings.HasSuffix(v, "(1 message)") {
		t.Errorf("a result without counts: verdict = %q", v)
	}
}
