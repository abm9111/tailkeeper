package tools

import (
	"fmt"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
)

// The verdicts of the widest call are derived in work that grows with its users and its lines
// together, not with their product. The work is counted in allocations, which a host's load
// does not change: reading a line against a user costs one, so the product would be 16
// million.
func TestTheSSHVerdictsOfTheWidestCallAreDerivedInLinearWork(t *testing.T) {
	var tests []ACLSSHTestInput
	var errs []string
	for i := 0; i < maxSSHTests; i++ {
		test := ACLSSHTestInput{}
		for d := 0; d < maxDestinations; d++ {
			test.Dst = append(test.Dst, fmt.Sprintf("tag:t%d-d%02d", i, d))
		}
		for u := 0; u < maxSSHUsers; u++ {
			test.Accept = append(test.Accept, fmt.Sprintf("user%02d", u))
		}
		tests = append(tests, test)
	}
	// One line for each user and destination, and a line for none of them.
	for _, test := range tests {
		for _, dst := range test.Dst {
			for _, user := range test.Accept {
				errs = append(errs, fmt.Sprintf(`[ssh test error]: src "tag:ci" at "100.64.0.1", dst %q at "100.64.0.2", ssh user %q: want: "accept" got: "deny"`, dst, user))
			}
		}
	}
	results := []api.TestResult{{User: "tag:ci", Errors: errs}}
	var v []ACLSSHVerdict
	allocs := testing.AllocsPerRun(1, func() {
		v, _, _, _ = deriveSSHVerdicts("tag:ci", tests, results)
	})
	if len(v) != 8*maxDestinations*maxSSHUsers {
		t.Fatalf("%d verdicts", len(v))
	}
	for _, one := range v {
		if one.Verdict != verdictDenied {
			t.Fatalf("the derivation changed: %+v", one)
		}
	}
	if allocs > 500_000 {
		t.Errorf("%.0f allocations for %d users and %d lines: the work is not linear", allocs, len(v), len(errs))
	}
}

// The status of an SSH call is unknown for a check user whatever the verdict beside it says,
// so a verdict that read a check user as allowed could not make the call a pass.
func TestACheckUserNeverLeavesAnSSHStatusOfPass(t *testing.T) {
	for _, verdict := range []string{verdictAllowed, verdictDenied, verdictUnknown, verdictUnresolved} {
		if got := sshStatus([]ACLSSHVerdict{{Expect: expectCheck, Verdict: verdict}}); got != statusUnknown {
			t.Errorf("a check user with the verdict %s gives the status %s", verdict, got)
		}
	}
	if got := sshStatus([]ACLSSHVerdict{{Expect: expectAccept, Verdict: verdictAllowed}, {Expect: expectDeny, Verdict: verdictDenied}}); got != statusPass {
		t.Errorf("the control: %s", got)
	}
}
