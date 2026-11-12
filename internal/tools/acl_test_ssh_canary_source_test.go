package tools_test

import (
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// The SSH canary of acl_test shares its reading with the access explanation (takeSSHCanary). Its
// entry is the canary's own, so the one line in it must quote the canary's tag as its source: a
// failure of the caller's source, or of another, filed under the canary's tag is not the canary.
// Taken for it, it would leave the caller's pair with no line, which reads as allowed.
func TestTheSSHCanaryMustQuoteItsOwnSource(t *testing.T) {
	for _, c := range []struct{ name, quoted string }{
		{"the caller's source", "tag:db"},
		{"a source nobody asked about", "tag:other"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, reg, env := apiEnv(t)
			serveSSHCanary(f, "{}\n", func(tag string) apitest.Shape {
				return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
			}, func(tag string) []apitest.Entry {
				return []apitest.Entry{{User: tag, Errors: sshFailedEntry(t, c.quoted, "192.0.2.1", "canary").Errors}}
			})
			var out tools.ACLTestOutput
			mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept"), &out)
			if out.Status != "unknown" || out.ExitCode() != 1 {
				t.Fatalf("status %q, exit %d: a line that quotes %s is not the SSH canary: %+v", out.Status, out.ExitCode(), c.quoted, out)
			}
			if len(out.SSHVerdicts) != 1 || out.SSHVerdicts[0].Verdict != "unknown" || out.SSHVerdicts[0].Why != "the SSH tests were not shown to have run" {
				t.Errorf("verdicts %+v: a canary that is not the canary left a verdict", out.SSHVerdicts)
			}
		})
	}
}
