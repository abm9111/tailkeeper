package doctor

import (
	"context"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// An answer tailkeeper cannot read says "run tailkeeper doctor --probe" in every
// other command. In doctor that sends the reader in a circle.
func TestDoctorDoesNotSendTheReaderBackToItself(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client"}`)
	f.ServeDetails(apitest.DetailsOK(canaryPolicy, `"e1"`, nil, nil))
	f.Raw("POST", "/api/v2/tailnet/T1234CNTRL/acl/validate", 200, `{"errors":["tag not found"]}`, nil)
	r := Run(context.Background(), Input{App: a, Now: now, Probe: true})
	for _, c := range r.Checks {
		if c.Name != "probe acl_test" {
			continue
		}
		if want := "the API may have changed; report this with `tailkeeper version`"; c.Status != Warn || c.Hint != want {
			t.Errorf("probe acl_test = %+v, want a warning with the hint %q", c, want)
		}
		return
	}
	t.Fatal("no probe acl_test check")
}
