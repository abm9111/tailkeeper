package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// TestClientDisconnectEndsAHungLocalCall closes the server's standard input, as a client
// that goes away does, while a call waits on a local tailscale CLI that never finishes. The
// server must exit and the CLI must not outlive it. The comment in internal/mcpserver
// that a running handler ends when the server does is about signals; this is the same
// for end of file, which the SDK has to turn into a cancellation by itself.
func TestClientDisconnectEndsAHungLocalCall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in tailscale CLI is a shell script")
	}
	env := isolated(t)
	pidFile := hungLocalCLI(t, env)
	s := startRawServer(t, env, "mcp")
	s.initialize()
	s.callTool(2, "local_status")
	pid := waitForPID(t, pidFile) // the call has reached the CLI and is hanging
	if err := s.stdin.Close(); err != nil {
		t.Fatal(err)
	}
	s.waitExit(10*time.Second, "its standard input was closed")
	requireGone(t, pid, "the tailscale CLI")
}

// TestSecondInterruptEndsTheServerAtOnce sends Ctrl-C more than once. The first cancels the serving
// context and the server waits for its in-flight call; main restores the default handling
// after it, so the second ends the process by the signal instead of waiting out the call and
// the 2-second grace. The call waits on a stand-in CLI that left a child of its own process
// group behind, which holds the output pipes: cancelling kills the CLI, and the runner then
// waits 2 seconds for the pipes, so the server is still alive after the first signal.
func TestSecondInterruptEndsTheServerAtOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Interrupt cannot be sent to another process on Windows")
	}
	env := isolated(t)
	dir := t.TempDir()
	fake, readyFile, childFile := filepath.Join(dir, "tailscale"), filepath.Join(dir, "pid"), filepath.Join(dir, "child")
	// The background sleep must leave the CLI's process group, so that killing the group
	// leaves it running with the pipes open. setsid does that where it exists (Linux). set -m
	// does it on macOS, but a shell without a terminal, such as dash on Linux, turns job
	// control off, and the sleep would stay in the group and die with the CLI.
	script := "#!/bin/sh\nif command -v setsid >/dev/null 2>&1; then\n  setsid sleep 60 &\nelse\n  set -m\n  sleep 60 &\nfi\n" +
		"echo $! > " + strconv.Quote(childFile) + "\necho $$ > " + strconv.Quote(readyFile) + "\nwait\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, env, `{"contexts": {"e2e": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "env"}}}},
		"local": {"tailscaleBinary": `+strconv.Quote(fake)+`}}`)
	// Registered before any wait, so a failure cannot leave the sleep running.
	t.Cleanup(func() { killFromPIDFile(childFile) })
	s := startRawServer(t, env, "mcp")
	s.initialize()
	s.callTool(2, "local_status")
	waitForPID(t, readyFile)
	waitForPID(t, childFile)

	first := time.Now()
	if err := s.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	// main's goroutine restores the default handling once the first signal arrives, and the
	// server cannot say when. Ctrl-C is sent again every 100 ms: one that lands before the
	// handling is restored is absorbed, and the first after it ends the process. Without
	// the restore, every one is absorbed and the server ends by itself after the call's
	// 2-second grace, with an exit status and not by the signal.
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(10 * time.Second)
wait:
	for {
		select {
		case <-s.exited:
			break wait
		case <-tick.C:
			_ = s.cmd.Process.Signal(os.Interrupt) // fails only once the process is gone
		case <-deadline:
			t.Fatalf("the server was still running 10 s after the first Ctrl-C; stderr: %q", s.stderr.String())
		}
	}
	if d := time.Since(first); d > 1500*time.Millisecond {
		t.Errorf("the server took %s to end after the first Ctrl-C, near the 2 s in which it ends by itself", d)
	}
	ws, ok := s.cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGINT {
		t.Errorf("the server's end = %v, want it ended by the second SIGINT, not exited by itself", s.cmd.ProcessState)
	}
}

// TestMCPStandardOutputCarriesOnlyProtocolWhileAWarningFires runs the real binary with an audit
// log that cannot be opened, so that the first call fires the "reads are not being audited"
// warning. The warning must reach standard error and nothing but JSON-RPC messages may reach
// standard output, where one stray line breaks the client.
func TestMCPStandardOutputCarriesOnlyProtocolWhileAWarningFires(t *testing.T) {
	env := isolated(t)
	// A file where the logs directory belongs: the log cannot be created. A file cannot
	// hold the directory's parents either, so the parents are made and the directory is the file.
	home := envHome(t, env)
	logs := filepath.Join(home, ".state", "tailkeeper")
	switch runtime.GOOS {
	case "darwin":
		logs = filepath.Join(home, "Library", "Logs", "tailkeeper")
	case "windows":
		logs = filepath.Join(home, "AppData", "Local", "tailkeeper")
	}
	if err := os.MkdirAll(filepath.Dir(logs), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logs, []byte("not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := startRawServer(t, env, "mcp")
	s.initialize()
	s.callTool(2, "dns_get")
	s.reply(2, 15*time.Second)
	if err := s.stdin.Close(); err != nil {
		t.Fatal(err)
	}
	s.waitExit(10*time.Second, "its standard input was closed")

	if e := s.stderr.String(); !strings.Contains(e, "tailkeeper: reads are not being audited: ") {
		t.Fatalf("stderr = %q, want the warning that reads are not being audited, or the test does not exercise a warning", e)
	}
	lines, partial := s.stdout.all()
	if partial != "" {
		t.Errorf("standard output ends with %q, an unfinished line", partial)
	}
	if len(lines) < 2 {
		t.Fatalf("standard output holds %d lines, want the replies to initialize and to the call", len(lines))
	}
	for i, line := range lines {
		var m struct {
			JSONRPC string `json:"jsonrpc"`
		}
		if err := json.Unmarshal([]byte(line), &m); err != nil || m.JSONRPC != "2.0" {
			t.Errorf("standard output line %d is not a JSON-RPC message: %s", i+1, describe(line))
		}
	}
}

// credentialWrapper writes the exec provider's stand-in wrapper in dir, which appends a line to
// the file it returns each time it runs. With inject it supplies the read credential to the
// command it starts, as a secret manager's run command does; without, it starts the command
// as it is.
func credentialWrapper(t *testing.T, dir string, inject bool) (wrapper, marker string) {
	t.Helper()
	wrapper, marker = filepath.Join(dir, "wrapper.sh"), filepath.Join(dir, "runs")
	script := "#!/bin/sh\necho run >> " + strconv.Quote(marker) + "\n"
	if inject {
		script += "TAILKEEPER_READ_CLIENT_ID=e2e-client TAILKEEPER_READ_CLIENT_SECRET=e2e-value "
	}
	script += "exec \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return wrapper, marker
}

// runCLI runs the real binary for a command with an exec provider whose wrapper is wrapper, with
// a proxy that nothing listens on so that no request leaves the machine, and returns what it
// printed and how it ended.
func runCLI(t *testing.T, wrapper string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	env := isolated(t)
	writeConfig(t, env, `{"contexts": {"e2e": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "exec", "command": ["/bin/sh", `+
		strconv.Quote(wrapper)+`]}}}}}`)
	// A wrapper that loops forever must fail this test, not hang the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(env, "HTTPS_PROXY=http://127.0.0.1:1", "NO_PROXY=")
	var out, errs syncBuffer
	cmd.Stdout, cmd.Stderr = &out, &errs
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatalf("%v did not end within 30 s: a wrapper that is run again and again?", args)
	}
	return out.String(), errs.String(), code
}

// exitOf is the exit code of an error of the given code.
func exitOf(c tkerr.Code) int { return tkerr.ExitCode(tkerr.New(c, "x", "")) }

func runsOf(t *testing.T, marker string) int {
	t.Helper()
	b, err := os.ReadFile(marker)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "run\n")
}

// TestExecProviderReexecRunsACLICommand is TestExecProviderReexecKeepsStdio for a command of
// the CLI: with the credential missing, tailkeeper replaces itself with the wrapper, which
// supplies one and starts tailkeeper again with the same arguments, which then runs the command.
// The unreachable proxy shows that the second run held the credential: it fails reaching
// the network (upstream_unavailable), while one that never got it fails with
// credential_unavailable, and one that never re-executed fails there too.
func TestExecProviderReexecRunsACLICommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the exec provider re-executes with execve, which Windows lacks")
	}
	wrapper, marker := credentialWrapper(t, t.TempDir(), true)
	_, stderr, code := runCLI(t, wrapper, "dns", "get")
	if want := exitOf(tkerr.UpstreamUnavailable); !strings.Contains(stderr, "upstream_unavailable") || code != want {
		t.Errorf("dns get under a wrapper that supplies the credential: exit %d, stderr %q; want upstream_unavailable (exit %d) from the re-executed command", code, stderr, want)
	}
	if n := runsOf(t, marker); n != 1 {
		t.Errorf("the wrapper ran %d times, want once", n)
	}
}

// TestExecProviderLoopGuardStopsAWrapperThatSuppliesNothing: a wrapper that starts tailkeeper
// without a credential must not be run again and again. tailkeeper marks the second run
// (TAILKEEPER_REEXEC=1), which then fails and says no credential came with the wrapper.
func TestExecProviderLoopGuardStopsAWrapperThatSuppliesNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the exec provider re-executes with execve, which Windows lacks")
	}
	wrapper, marker := credentialWrapper(t, t.TempDir(), false)
	_, stderr, code := runCLI(t, wrapper, "dns", "get")
	want := exitOf(tkerr.CredentialUnavailable)
	if !strings.Contains(stderr, "credential_unavailable") || !strings.Contains(stderr, "TAILKEEPER_REEXEC=1 is set") || code != want {
		t.Errorf("dns get under a wrapper that supplies nothing: exit %d, stderr %q; want credential_unavailable (exit %d) naming TAILKEEPER_REEXEC=1", code, stderr, want)
	}
	if n := runsOf(t, marker); n != 1 {
		t.Errorf("the wrapper ran %d times, want once: the loop guard did not stop the second run", n)
	}
}
