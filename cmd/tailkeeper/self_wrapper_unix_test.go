//go:build !windows

package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// runEnv runs the built binary with exactly env, so that several runs share one home and
// so one configuration, and returns standard output, standard error and the exit code.
func runEnv(t *testing.T, env []string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		return stdout.String(), stderr.String(), ee.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	return stdout.String(), stderr.String(), 0
}

// The exec provider's wrapper is what unlocks a secret manager, so a command that needs no
// credential must never start it. `self info` reads no configuration and needs none: beside
// an exec provider with a wrapper that works, it prints the build and starts nothing. The wrapper records each start in a marker file, and the
// same wrapper is started by a command that does need the credential, so the missing marker
// is a measurement and not a wrapper that never worked. (That the provider is not read at
// all is the job of the Build sentinel in internal/cli; a marker alone cannot see that.)
func TestSelfInfoBesideAnExecProviderNeverStartsTheWrapper(t *testing.T) {
	env := isolated(t)
	dir := t.TempDir()
	marker, wrapper := filepath.Join(dir, "wrapper-ran"), filepath.Join(dir, "wrapper.sh")
	script := "#!/bin/sh\necho ran >> " + strconv.Quote(marker) + "\n" +
		"TAILKEEPER_READ_CLIENT_ID=e2e-client TAILKEEPER_READ_CLIENT_SECRET=e2e-value exec \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, env, `{"contexts": {"e2e": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "exec", "command": ["/bin/sh", `+strconv.Quote(wrapper)+`]}}}}}`)
	// An unreachable proxy keeps every request on this machine, as in the MCP test above.
	env = append(env, "HTTPS_PROXY=http://127.0.0.1:1", "NO_PROXY=")
	wrapperStarted := func() bool {
		t.Helper()
		_, err := os.Stat(marker)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		return err == nil
	}

	stdout, stderr, code := runEnv(t, env, "self", "info", "--json")
	var info struct {
		Name string `json:"name"`
	}
	if code != 0 || json.Unmarshal([]byte(stdout), &info) != nil || info.Name != "tailkeeper" || stderr != "" {
		t.Fatalf("self info --json: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	stdout, stderr, code = runEnv(t, env, "self", "info")
	if code != 0 || !strings.Contains(stdout, "name: tailkeeper\n") || stderr != "" {
		t.Fatalf("self info: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	// The global flag, which every command may be given, is accepted and ignored.
	if _, stderr, code = runEnv(t, env, "--context", "e2e", "self", "info", "--json"); code != 0 || stderr != "" {
		t.Fatalf("--context e2e self info: exit %d, stderr %q", code, stderr)
	}
	if wrapperStarted() {
		t.Fatal("self info started the exec provider's wrapper")
	}

	// The control: a command that needs the credential starts the very same wrapper, whose
	// start the marker records, and the process it re-executes reaches the network, which
	// the proxy refuses.
	stdout, stderr, code = runEnv(t, env, "dns", "get")
	if !wrapperStarted() {
		t.Fatalf("dns get did not start the wrapper, so the marker cannot tell a start: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if code != 1 || !strings.Contains(stderr, "upstream_unavailable") {
		t.Errorf("dns get under the wrapper: exit %d, stderr %q, want upstream_unavailable from the re-executed process", code, stderr)
	}
}
