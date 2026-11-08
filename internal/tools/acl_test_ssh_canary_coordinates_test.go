package tools_test

import (
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// An SSH test of acl_test that names the SSH canary's own coordinates (the user canary on
// 192.0.2.1) is not judged from silence: a reply that proves the canary and holds nothing for the
// caller's source reads, there, as the canary's own line does. The verdict is unknown, with its
// own sentence, and a test of another user or another destination is read as it always was.
func TestAnSSHTestThatNamesTheSSHCanaryCoordinatesIsUnknown(t *testing.T) {
	// The reply proves both canaries and holds nothing for the caller's source.
	run := func(args string) tools.ACLTestOutput {
		f, reg, env := apiEnv(t)
		serveSSH(f, "{}\n", func(tag string) apitest.Shape {
			return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
		})
		var out tools.ACLTestOutput
		mustCall(t, reg, env, "acl_test", args, &out)
		return out
	}
	for _, list := range []string{"accept", "deny"} {
		out := run(sshCall("192.0.2.1", "canary", list))
		if out.Status != "unknown" || out.ExitCode() != 1 || len(out.SSHVerdicts) != 1 {
			t.Fatalf("%s: status %q exit %d: %+v", list, out.Status, out.ExitCode(), out)
		}
		if v := out.SSHVerdicts[0]; v.Verdict != "unknown" || v.Why != "it names the user and destination of the SSH canary tailkeeper adds, so no reply can show it apart from the canary" {
			t.Errorf("%s: verdict %+v, want unknown by the sentence about the canary's coordinates", list, v)
		}
	}
	for name, args := range map[string]string{
		"another user":        sshCall("192.0.2.1", "root", "accept"),
		"another destination": sshCall("192.0.2.2", "canary", "accept"),
		"a tag":               sshCall("tag:db", "canary", "accept"),
	} {
		out := run(args)
		if out.Status != "pass" || len(out.SSHVerdicts) != 1 || out.SSHVerdicts[0].Verdict != "allowed" {
			t.Errorf("%s: %+v, want it read as it always was", name, out)
		}
	}
}

// A host alias for the canary's address names the canary's coordinates too, and acl_test resolves it
// from the live policy it already reads, in the accept form and the deny form. Any other alias, and a
// user that is not the canary's, are read as they always were.
func TestAnSSHTestThatNamesTheSSHCanaryByAHostAliasIsUnknown(t *testing.T) {
	const policy = `{"hosts": {"example-canary": "192.0.2.1", "example-other": "192.0.2.2"}}` + "\n"
	run := func(args string) tools.ACLTestOutput {
		f, reg, env := apiEnv(t)
		serveSSH(f, policy, func(tag string) apitest.Shape {
			return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
		})
		var out tools.ACLTestOutput
		mustCall(t, reg, env, "acl_test", args, &out)
		return out
	}
	for _, list := range []string{"accept", "deny"} {
		out := run(sshCall("example-canary", "canary", list))
		if out.Status != "unknown" || out.ExitCode() != 1 || len(out.SSHVerdicts) != 1 {
			t.Fatalf("%s: status %q exit %d: %+v", list, out.Status, out.ExitCode(), out)
		}
		if v := out.SSHVerdicts[0]; v.Verdict != "unknown" || v.Why != "it names the user and destination of the SSH canary tailkeeper adds, so no reply can show it apart from the canary" {
			t.Errorf("%s: verdict %+v, want unknown by the sentence about the canary's coordinates", list, v)
		}
	}
	for name, args := range map[string]string{
		"another alias":    sshCall("example-other", "canary", "accept"),
		"another user":     sshCall("example-canary", "root", "accept"),
		"a tag":            sshCall("tag:db", "canary", "deny"),
		"another literal":  sshCall("192.0.2.2", "canary", "accept"),
		"an unknown alias": sshCall("example-missing", "canary", "accept"),
	} {
		out := run(args)
		if out.Status != "pass" || len(out.SSHVerdicts) != 1 || (out.SSHVerdicts[0].Verdict != "allowed" && out.SSHVerdicts[0].Verdict != "denied") {
			t.Errorf("%s: %+v, want it read as it always was", name, out)
		}
	}
}
