package acl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// The HuJSON parser recurses once per level of nesting, and a Go stack overflow is fatal:
// it cannot be recovered, so a test that sends it a million levels would end the test
// binary. So each entry point is run in a child process (this test binary again, with an
// environment switch) and the parent asserts the child exits cleanly having seen a typed
// error. An entry point that reached the library before the guard shows up here as a dead
// child and the stack trace in its output.

const depthChildEnv = "TAILKEEPER_ACL_DEPTH_CHILD"

// depthEntries are the entry points that take text. Each runs with a million levels of
// nesting (the text is at most 1 MiB, the size an MCP argument may have) and returns the
// error the entry point gave. Tasks that add an entry point register it from their own
// test file.
var depthEntries = map[string]func(levels int) error{}

// Only the array entry and the deep-inside-a-section entry can overflow the stack, so they
// are the ones that prove the scan runs before the parser. The object entry is held under
// the size cap (a million bytes of "{"a":" is about 209,000 levels, which the parser
// refuses with its own error before it overflows), so it proves only that the guard
// refuses object nesting; the child requires the guard's own message for that reason.
func init() {
	depthEntries["Parse of arrays"] = func(levels int) error {
		_, err := Parse(context.Background(), []byte(strings.Repeat("[", levels)))
		return err
	}
	depthEntries["Parse of objects"] = func(levels int) error {
		_, err := Parse(context.Background(), []byte(strings.Repeat(`{"a":`, levels/5)))
		return err
	}
	depthEntries["Parse of a policy that is deep inside a section"] = func(levels int) error {
		_, err := Parse(context.Background(), []byte(`{"groups": {"group:a": `+strings.Repeat("[", levels)+`}}`))
		return err
	}
}

func TestDepthChild(t *testing.T) {
	name := os.Getenv(depthChildEnv)
	if name == "" {
		return // the parent test runs this one in a child; on its own it has nothing to do
	}
	entry, ok := depthEntries[name]
	if !ok {
		t.Fatalf("no entry point named %q", name)
	}
	err := entry(1 << 20)
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeInvalid || e.Line < 1 || !strings.Contains(e.Message, "nests deeper") {
		t.Fatalf("%s: err = %v, want the guard's invalid error with a line", name, err)
	}
	fmt.Println("DEPTH-OK", name)
}

func TestEveryEntryPointRefusesAMillionLevelsCleanly(t *testing.T) {
	names := make([]string, 0, len(depthEntries))
	for name := range depthEntries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDepthChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), depthChildEnv+"="+name)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "DEPTH-OK "+name) {
			t.Errorf("%s: the child did not finish cleanly: %v\n%s", name, err, tail(string(out), 1500))
		}
	}
	if len(names) < 3 {
		t.Fatalf("only %d entry points are registered", len(names))
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "\u2026" + s[len(s)-n:]
}
