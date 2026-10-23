package cli

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// The destinations of --accept and --deny reach Tailscale in accept and in deny, each on its
// own side and in the order given. Nothing about the answer shows a swap: the fake does not
// know which side a destination should have been on, so the body is read.
func TestTheCommandSendsAcceptInAcceptAndDenyInDeny(t *testing.T) {
	f := apitest.New(t)
	serveLiveFor(f, "{}\n")
	f.ServeValidate(apitest.TestsPass())
	h := newHarness(t, f)
	args := []string{"acl", "test", "tag:ci", "--proto", "tcp",
		"--accept", "tag:web:22", "--accept", "100.64.0.5:443",
		"--deny", "tag:db:5432", "--deny", "[fd7a:115c:a1e0::5]:22"}
	if code := h.run(args...); code != 0 {
		t.Fatalf("exit %d: %s", code, h.err)
	}
	var body []byte
	for _, r := range f.Requests() {
		if r.Method == "POST" {
			body = r.Body
		}
	}
	var sent []struct {
		Src    string   `json:"src"`
		Proto  string   `json:"proto"`
		Accept []string `json:"accept"`
		Deny   []string `json:"deny"`
	}
	if err := json.Unmarshal(body, &sent); err != nil || len(sent) != 1 {
		t.Fatalf("request body %q: %v", body, err)
	}
	got := sent[0]
	if got.Src != "tag:ci" || got.Proto != "tcp" ||
		!slices.Equal(got.Accept, []string{"tag:web:22", "100.64.0.5:443"}) ||
		!slices.Equal(got.Deny, []string{"tag:db:5432", "[fd7a:115c:a1e0::5]:22"}) {
		t.Errorf("request = %+v", got)
	}
}
