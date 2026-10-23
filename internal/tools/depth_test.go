package tools_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// The HuJSON parser recurses once per level of nesting, and a Go stack overflow is fatal: a
// test that gave it a million levels would end the test binary. So the tool is run on such a
// text in a child process (this test binary again, with an environment switch), and the
// parent asserts that the child finished and saw a typed invalid result. A tool that reached
// the library before the guard shows up here as a dead child and its stack trace.

const validateDepthChildEnv = "TAILKEEPER_VALIDATE_DEPTH_CHILD"

func TestValidateDepthChild(t *testing.T) {
	if os.Getenv(validateDepthChildEnv) == "" {
		return // the parent test runs this one in a child; on its own it has nothing to do
	}
	env := &registry.Env{Now: func() time.Time { return now }}
	for name, text := range map[string]string{
		"a million levels of arrays":  strings.Repeat("[", 1<<20),
		"deep inside a section":       `{"groups": {"group:a": ` + strings.Repeat("[", 1<<20) + `}}`,
		"a million levels of objects": strings.Repeat(`{"a":`, 1<<20/5),
	} {
		out, err := runValidate(t, env, func(in *tools.ACLValidateInput) { in.Policy, in.Offline, in.Operator = text, true, true })
		if err != nil || out.Status != "invalid" || len(out.Errors) != 1 || out.Errors[0].Kind != "structure" ||
			out.Errors[0].Line < 1 || !strings.Contains(out.Errors[0].Message, "nests deeper") {
			t.Fatalf("%s: err = %v, out = %+v, want a typed invalid result from the depth guard", name, err, out)
		}
	}
	// An invariants file is read by the same guard.
	inv, err := runValidate(t, env, func(in *tools.ACLValidateInput) {
		in.Invariants, in.Offline, in.Operator = strings.Repeat("[", 1<<20), true, true
	})
	if err != nil || inv.Status != "invalid" || len(inv.Errors) != 1 || inv.Errors[0].Source != "invariants" || !strings.Contains(inv.Errors[0].Message, "nests deeper") {
		t.Fatalf("an invariants file: err = %v, out = %+v, want a typed invalid result from the depth guard", err, inv)
	}
	// And the same text over MCP, which is the call a hostile caller makes.
	var out tools.ACLValidateOutput
	mustCall(t, newRegistry(t), env, "acl_validate", `{"policy":"`+strings.Repeat("[", 1<<19)+`"}`, &out)
	if out.Status != "invalid" || len(out.Errors) != 1 || out.Errors[0].Kind != "structure" {
		t.Fatalf("over MCP: %+v, want a typed invalid result", out)
	}
	fmt.Println("DEPTH-OK acl_validate")
}

func TestAMillionLevelsOfNestingIsAnInvalidResult(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestValidateDepthChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), validateDepthChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "DEPTH-OK acl_validate") {
		t.Fatalf("the child did not finish cleanly: %v\n%s", err, tailOf(string(out), 1500))
	}
}

const sshDepthChildEnv = "TAILKEEPER_SSH_DEPTH_CHILD"

func TestSSHDepthChild(t *testing.T) {
	if os.Getenv(sshDepthChildEnv) == "" {
		return
	}
	f, reg, env := apiEnv(t)
	servePolicy(f, strings.Repeat("[", 1<<20), `"e1"`)
	s, err := call(t, reg, env, "acl_test", `{"src":"tag:db","ssh":[{"dst":["tag:db"],"accept":["root"]}]}`)
	if err != nil || strings.Contains(s, `"status":"unknown"`) {
		fmt.Println("DEPTH-OK acl_test_ssh")
		return
	}
	fmt.Printf("DEPTH-FAIL %v %s\n", err, s)
}

func TestTheSSHPathSurvivesAMillionLevelsOfNestingInTheLivePolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSSHDepthChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), sshDepthChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "DEPTH-OK acl_test_ssh") {
		t.Fatalf("the child did not finish cleanly: %v\n%s", err, tailOf(string(out), 1500))
	}
}

func tailOf(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}
