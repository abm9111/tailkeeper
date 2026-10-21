package doctor

import (
	"encoding/json"
	"testing"

	"github.com/abm9111/tailkeeper/internal/guard"
)

// The probe of acl_get asks for the largest page, which is the policy cap: a probe that asked
// for less would not show that a policy at the cap can be read in one page.
func TestTheAclGetProbeAsksForTheLargestPage(t *testing.T) {
	for _, p := range probeList {
		if p.tool != "acl_get" {
			continue
		}
		var in struct {
			MaxBytes int `json:"maxBytes"`
		}
		if err := json.Unmarshal([]byte(p.args), &in); err != nil {
			t.Fatalf("the acl_get probe arguments %q: %v", p.args, err)
		}
		if in.MaxBytes != guard.MaxPolicyBytes {
			t.Errorf("the acl_get probe asks for %d bytes, want guard.MaxPolicyBytes = %d", in.MaxBytes, guard.MaxPolicyBytes)
		}
		return
	}
	t.Fatal("probeList has no acl_get")
}
