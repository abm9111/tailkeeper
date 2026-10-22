package mcpserver

import (
	"net/http"
	"strings"
	"testing"
)

// The login canary through acl_diff: a user is named by pseudonym in a policy, an old policy
// and a patch, the login (one with a slash, which the registry's address scan does not read as
// part of a local part) takes the pseudonym's place in the text the engine compares, and no
// field of the result, no line of the audit log, no error and no _meta carries any of it while
// masking is on. The comparison sends nothing: the login is in the engine and in the live
// policy of the next case, and nowhere else.
func TestALoginAPseudonymStandsForReachesOnlyTheComparisonOfADiff(t *testing.T) {
	member := func(ref string) string { return "{\n\"groups\": {\"group:eng\": [\"" + ref + "\"]}\n}\n" }
	cases := map[string]func(ref string) map[string]any{
		"a new policy": func(ref string) map[string]any { return map[string]any{"policy": member(ref)} },
		"an old policy": func(ref string) map[string]any {
			return map[string]any{"against": member(ref), "policy": "{\n\"groups\": {\"group:eng\": []}\n}\n"}
		},
		"a patch": func(ref string) map[string]any {
			return map[string]any{"patch": `[{"op":"add","path":"/groups/group:eng/-","value":"` + ref + `"}]`}
		},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			cs, a, f, ref := canaryServer(t, false, failureReply)
			servePolicy(f, "{\n\"groups\": {\"group:eng\": []}\n}\n")
			res := callTool(t, cs, "acl_diff", args(ref))
			all := everything(t, a, res)
			if got := leaks(all); len(got) > 0 {
				t.Errorf("the result, _meta or audit log shows %v:\n%s", got, all)
			}
			if !strings.Contains(all, `"tool":"acl_diff"`) || !strings.Contains(all, `"changes"`) {
				t.Errorf("the audit log has no line for the call or the result lists no change, so the test checked nothing:\n%s", all)
			}
			// The user is named by the pseudonym the caller holds.
			if !strings.Contains(all, ref) {
				t.Errorf("the pseudonym %s is not in the result:\n%s", ref, all)
			}
			for _, r := range f.Requests() {
				if r.Method == http.MethodPost {
					t.Errorf("acl_diff sent %s %s", r.Method, r.Path)
				}
			}
		})
	}
}
