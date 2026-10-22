package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/privacy"
)

// The binary is built once and run as a real process, so these tests exercise
// argument handling, exit codes and the stdio transport end to end.
var bin string

// coverDir is where go test collects coverage counters when it runs with -cover.
// The binary is then built with coverage too and writes there, so the end-to-end
// runs count toward coverage instead of only this package's in-process code.
var coverDir string

func TestMain(m *testing.M) {
	flag.Parse()
	dir, err := os.MkdirTemp("", "tailkeeper-bin")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "tailkeeper")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	args := []string{"build", "-o", bin}
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		coverDir = f.Value.String()
		args = append(args, "-cover", "-coverpkg=github.com/abm9111/tailkeeper/...")
	}
	if out, err := exec.Command("go", append(args, ".")...).CombinedOutput(); err != nil {
		panic("go build: " + err.Error() + "\n" + string(out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// isolated returns an environment with an empty home: no configuration, no
// credential, and the CLI search limited to the system candidates.
func isolated(t *testing.T) []string {
	t.Helper()
	// A system configuration always wins (spec §15) and no variable can redirect
	// it, so these tests cannot run on a machine that has one. They fail rather than
	// skip: a gate that passes without running them proves nothing.
	if _, err := os.Stat("/etc/tailkeeper/config.hujson"); err == nil {
		t.Fatal("/etc/tailkeeper/config.hujson exists and would replace the test configuration; run the end-to-end tests on a machine without one")
	}
	home := t.TempDir()
	env := []string{"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"XDG_STATE_HOME=" + filepath.Join(home, ".state"), "PATH=/usr/bin:/bin"}
	if runtime.GOOS == "windows" {
		// DefaultDirs reads these three (internal/config/load.go). ProgramData is
		// redirected too, so no system configuration on the runner can apply.
		// SystemRoot is needed to start any process; PATH holds only System32.
		root := os.Getenv("SystemRoot")
		env = []string{"USERPROFILE=" + home, "ProgramData=" + filepath.Join(home, "ProgramData"),
			"AppData=" + filepath.Join(home, "AppData", "Roaming"), "LocalAppData=" + filepath.Join(home, "AppData", "Local"),
			"SystemRoot=" + root, "PATH=" + filepath.Join(root, "System32")}
	}
	if coverDir != "" {
		env = append(env, "GOCOVERDIR="+coverDir)
	}
	return env
}

func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = isolated(t)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return stdout.String(), stderr.String(), code
}

func TestVersionAndHelp(t *testing.T) {
	if out, _, code := run(t, "version"); code != 0 || !strings.HasPrefix(out, "tailkeeper ") {
		t.Errorf("version: %d %q", code, out)
	}
	if out, _, code := run(t, "help"); code != 0 || !strings.Contains(out, "devices") {
		t.Errorf("help: %d %q", code, out)
	}
	if _, _, code := run(t); code != 2 {
		t.Errorf("no arguments: exit %d, want 2", code)
	}
}

func TestNoConfigurationExitCode(t *testing.T) {
	_, stderr, code := run(t, "devices", "list")
	if code != 6 || !strings.Contains(stderr, "config_missing") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

func TestStdioMCPServer(t *testing.T) {
	cmd := exec.Command(bin, "mcp")
	cmd.Env = isolated(t)
	ctx := context.Background()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	if got := cs.InitializeResult().ServerInfo.Name; got != "tailkeeper" {
		t.Errorf("server name = %q", got)
	}
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 43 {
		t.Errorf("reads profile lists %d tools, want 43", len(tools.Tools))
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "devices_list", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.HasPrefix(res.Content[0].(*mcp.TextContent).Text, "config_missing:") {
		t.Errorf("devices_list without configuration: %+v", res.Content)
	}
}

// TestExecProviderReexecKeepsStdio runs the MCP server under the exec provider.
// tailkeeper finds no credential, re-executes itself under the wrapper, and the
// wrapper injects one; the stdio session must survive the exec. An unreachable
// proxy keeps every request on this machine: a re-executed server reports
// upstream_unavailable, one that never got the credential reports
// credential_unavailable.
func TestExecProviderReexecKeepsStdio(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the exec provider re-executes with execve, which Windows lacks")
	}
	env := isolated(t)
	home := strings.TrimPrefix(env[0], "HOME=")
	cfgDir := filepath.Join(home, ".config", "tailkeeper")
	if runtime.GOOS == "darwin" {
		cfgDir = filepath.Join(home, "Library", "Application Support", "tailkeeper")
	}
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(home, "wrapper.sh")
	script := "#!/bin/sh\nTAILKEEPER_READ_CLIENT_ID=e2e-client TAILKEEPER_READ_CLIENT_SECRET=e2e-value exec \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := `{"contexts": {"e2e": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "exec", "command": ["/bin/sh", "` + wrapper + `"]}}}}}`
	if err := os.WriteFile(filepath.Join(cfgDir, "config.hujson"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "mcp")
	cmd.Env = append(env, "HTTPS_PROXY=http://127.0.0.1:1", "NO_PROXY=")
	ctx := context.Background()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "dns_get", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if !res.IsError || !strings.HasPrefix(text, "upstream_unavailable:") {
		t.Fatalf("want upstream_unavailable from a re-executed server, got %q", text)
	}
}

// TestInterruptEndsAHungCall sends Ctrl-C to an MCP server whose only call hangs on
// a network that never answers: the server must still exit promptly.
func TestInterruptEndsAHungCall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Interrupt cannot be sent to another process on Windows")
	}
	// A proxy that accepts connections and never replies.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	env := isolated(t)
	writeConfig(t, env, `{"contexts": {"e2e": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "env"}}}}}`)
	env = append(env, "HTTPS_PROXY=http://"+ln.Addr().String(), "NO_PROXY=",
		"TAILKEEPER_READ_CLIENT_ID=e2e-client", "TAILKEEPER_READ_CLIENT_SECRET=e2e-value")
	interruptDuring(t, env, "dns_get") // waits on the proxy for a token
}

// TestInterruptEndsAHungLocalCall is the same for a call waiting on a local
// tailscale CLI that never finishes.
func TestInterruptEndsAHungLocalCall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Interrupt cannot be sent to another process on Windows")
	}
	env := isolated(t)
	dir := t.TempDir()
	fake, pidFile := filepath.Join(dir, "tailscale"), filepath.Join(dir, "pid")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho $$ > "+strconv.Quote(pidFile)+"\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, env, `{"contexts": {"e2e": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "env"}}}},
		"local": {"tailscaleBinary": `+strconv.Quote(fake)+`}}`)
	interruptDuring(t, env, "local_status")
	// The hung CLI must not outlive the server.
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := os.FindProcess(pid)
	for deadline := time.Now().Add(3 * time.Second); p.Signal(syscall.Signal(0)) == nil; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			_ = p.Kill()
			t.Fatalf("the tailscale CLI (pid %d) outlived the server", pid)
		}
	}
}

// TestServeGivesInFlightCallsAGrace covers a call that ignores cancellation: the
// server returns shutdownGrace after the signal.
func TestServeGivesInFlightCallsAGrace(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "1"}, nil)
	release := make(chan struct{})
	mcp.AddTool(srv, &mcp.Tool{Name: "hang"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		<-release
		return &mcp.CallToolResult{}, nil, nil
	})
	st, ct := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- serve(ctx, srv, st) }()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "1"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Deferred calls run last first: the hung call is released before the client
	// closes, since closing waits for it.
	defer func() { _ = cs.Close() }()
	defer close(release)
	go func() {
		_, _ = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "hang", Arguments: map[string]any{}})
	}()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	cancel()
	select {
	case <-served:
	case <-time.After(shutdownGrace + 3*time.Second):
		t.Fatal("serve did not return after the grace")
	}
	if d := time.Since(start); d < shutdownGrace-100*time.Millisecond {
		t.Errorf("serve returned after %v, before the grace ended", d)
	}
}

// writeConfig writes the user configuration of the isolated environment env.
func writeConfig(t *testing.T, env []string, cfg string) {
	t.Helper()
	home := strings.TrimPrefix(env[0], "HOME=")
	cfgDir := filepath.Join(home, ".config", "tailkeeper")
	if runtime.GOOS == "darwin" {
		cfgDir = filepath.Join(home, "Library", "Application Support", "tailkeeper")
	}
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.hujson"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

// interruptDuring starts the MCP server, calls tool, sends Ctrl-C while the call
// hangs, and requires the server to exit promptly.
func interruptDuring(t *testing.T, env []string, tool string) {
	t.Helper()
	cmd := exec.Command(bin, "mcp")
	cmd.Env = env
	ctx := context.Background()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill() // a server that ignored the signal must not outlive the test
		_ = cs.Close()
	})
	go func() { _, _ = cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: map[string]any{}}) }()
	time.Sleep(time.Second) // the call is now hanging
	ended := make(chan struct{})
	go func() { _ = cs.Wait(); close(ended) }()
	start := time.Now()
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
	case <-time.After(15 * time.Second):
		t.Fatal("the server did not exit within 15s of Ctrl-C")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("the server took %v to exit after Ctrl-C", d)
	}
}

// readDoc reads a document of the repository with Unix line ends, whatever the
// checkout did to them.
func readDoc(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// hujsonBlocks returns the contents of the hujson code blocks of a document.
func hujsonBlocks(t *testing.T, doc string) []string {
	t.Helper()
	var blocks []string
	for i, rest := range strings.Split(doc, "```hujson\n")[1:] {
		block, _, closed := strings.Cut(rest, "```")
		if !closed {
			t.Errorf("hujson block %d is not closed", i+1)
			continue
		}
		blocks = append(blocks, block)
	}
	return blocks
}

// unixPath matches a JSON string that holds a Unix absolute path.
var unixPath = regexp.MustCompile(`"(/[^"]*)"`)

// parseExample parses a configuration written in a document. The examples write
// absolute paths the Unix way; on Windows they get a drive letter, because the
// configuration refuses a path that is not absolute there.
func parseExample(block string) (config.Config, error) {
	if runtime.GOOS == "windows" {
		block = unixPath.ReplaceAllString(block, `"C:$1"`)
	}
	return config.Parse([]byte(block))
}

// TestREADMEConfigurationParses keeps the README's example a valid configuration.
func TestREADMEConfigurationParses(t *testing.T) {
	blocks := hujsonBlocks(t, readDoc(t, "../../README.md"))
	if len(blocks) == 0 {
		t.Fatal("README has no hujson block")
	}
	cfg, err := parseExample(blocks[0])
	if err != nil {
		t.Fatalf("README example does not parse: %v", err)
	}
	if p := cfg.Contexts["home"].Credentials.Read; p.Provider != "exec" || !filepath.IsAbs(p.Command[0]) {
		t.Errorf("README example provider = %+v", p)
	}
}

// configKeys lists the dotted key of every setting that holds a value, from the
// types config.Parse decodes. The contexts are a map, so their keys start with
// contexts.<name>.
func configKeys(t reflect.Type, prefix string) []string {
	var keys []string
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		key, ft := prefix+name, t.Field(i).Type
		if ft.Kind() == reflect.Map {
			key, ft = key+".<name>", ft.Elem()
		}
		if ft.Kind() == reflect.Struct {
			keys = append(keys, configKeys(ft, key+".")...)
			continue
		}
		keys = append(keys, key)
	}
	return keys
}

// tableFirstCells returns the first cell of every row of every Markdown table
// outside a code block, without its backticks.
func tableFirstCells(doc string) map[string]bool {
	cells := map[string]bool{}
	fenced := false
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
			continue
		}
		if fenced || !strings.HasPrefix(line, "|") {
			continue
		}
		first, _, _ := strings.Cut(strings.TrimPrefix(line, "|"), "|")
		cells[strings.Trim(strings.TrimSpace(first), "`")] = true
	}
	return cells
}

// TestREADMEDocumentsWhatTheConfigurationAccepts keeps the README complete: a
// parsing example and a row for every provider, a row for every setting under
// its full dotted key, the flags of the commands that take them and the
// variables tailkeeper reads. A mention in running text does not count: a row is
// what a reader scanning for a setting finds.
func TestREADMEDocumentsWhatTheConfigurationAccepts(t *testing.T) {
	readme := readDoc(t, "../../README.md")
	var missing []string
	examples := map[string]bool{}
	for i, block := range hujsonBlocks(t, readme) {
		if !strings.Contains(block, `"contexts"`) {
			continue
		}
		cfg, err := parseExample(block)
		if err != nil {
			t.Errorf("hujson block %d does not parse: %v", i+1, err)
			continue
		}
		for _, c := range cfg.Contexts {
			examples[c.Credentials.Read.Provider] = true
		}
	}
	rows := tableFirstCells(readme)
	for _, p := range []string{"env", "file", "exec", "oidc"} {
		if !examples[p] {
			missing = append(missing, "an example of provider "+p)
		}
		if !rows[p] {
			missing = append(missing, "a row for provider "+p)
		}
	}
	for _, key := range configKeys(reflect.TypeFor[config.Config](), "") {
		if !rows[key] {
			missing = append(missing, "a row for "+key)
		}
	}
	for _, s := range []string{"--profile", "--enable-alpha", "--context", creds.EnvClientID, creds.EnvClientSecret,
		creds.EnvAPIKey, creds.EnvOIDCToken, privacy.EnvKey, "TAILKEEPER_CONTEXT"} {
		if !strings.Contains(readme, "`"+s) {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		t.Errorf("README.md lacks %d items: %s", len(missing), strings.Join(missing, ", "))
	}
}

// TestREADMERebuildsWithThePinnedGoReleaser keeps the rebuild instructions on the
// GoReleaser version the Makefile pins: another version is not the build the
// release workflow ran.
func TestREADMERebuildsWithThePinnedGoReleaser(t *testing.T) {
	pin := regexp.MustCompile(`(?m)^GORELEASER\s*:=\s*(\S+)$`).FindStringSubmatch(readDoc(t, "../../Makefile"))
	if pin == nil {
		t.Fatal("the Makefile has no GORELEASER pin")
	}
	if !strings.Contains(readDoc(t, "../../README.md"), pin[1]) {
		t.Errorf("README.md does not run %s, the GoReleaser the Makefile pins", pin[1])
	}
}

// TestRecipesAreValid keeps the credential recipes usable: each has a provider
// block that parses, runs an absolute wrapper and ends the wrapper's arguments
// with "--", and each environment file lists references, never values.
func TestRecipesAreValid(t *testing.T) {
	files, err := filepath.Glob("../../docs/recipes/*.md")
	if err != nil {
		t.Fatal(err)
	}
	reference := regexp.MustCompile(`^[a-z]+://\S+$`)
	assignment := regexp.MustCompile(`(?m)^\s*(TAILKEEPER_[A-Z_]+)=(.*)$`)
	recipes := 0
	for _, f := range files {
		if filepath.Base(f) == "README.md" {
			continue
		}
		recipes++
		doc := readDoc(t, f)
		blocks := hujsonBlocks(t, doc)
		if len(blocks) == 0 {
			t.Errorf("%s has no hujson block", f)
		}
		for _, block := range blocks {
			cfg, err := parseExample(`{"contexts": {"x": {"tailnetId": "T1234CNTRL", "credentials": {` + block + `}}}}`)
			if err != nil {
				t.Errorf("%s: a provider block does not parse: %v", f, err)
				continue
			}
			p := cfg.Contexts["x"].Credentials.Read
			if p.Provider != "exec" || !filepath.IsAbs(p.Command[0]) || p.Command[len(p.Command)-1] != "--" {
				t.Errorf("%s: provider block = %+v, want exec, an absolute wrapper and a last argument --", f, p)
			}
		}
		vars := assignment.FindAllStringSubmatch(doc, -1)
		if len(vars) < 2 {
			t.Errorf("%s lists %d environment variables, want the credential and the privacy key at least", f, len(vars))
		}
		for _, m := range vars {
			if !reference.MatchString(strings.TrimSpace(m[2])) {
				t.Errorf("%s: %s is not set to a reference", f, m[1])
			}
		}
	}
	if recipes < 2 {
		t.Errorf("found %d recipes in docs/recipes, want at least 2", recipes)
	}
}

// The README's checksum step must fail, and say so, when it checked nothing: the sha256sum that
// macOS ships prints nothing and exits 0 when the lines it is given hold no checksum, which is
// what an archive named otherwise than checksums.txt names it gives. The step (the lines
// between the cosign command and the first gh attestation line) is run as written, with each
// checksum tool this machine has, for a match, an archive checksums.txt does not name, a
// tampered archive and a missing one.
func TestReadmeChecksumStepFailsWhenItChecksNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the step is a shell script")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	doc := readDoc(t, "../../README.md")
	_, after, ok := strings.Cut(doc, "## Verify a release")
	if !ok {
		t.Fatal("README.md has no Verify a release section")
	}
	_, block, ok := strings.Cut(after, "```\n")
	if !ok {
		t.Fatal("the section has no code block")
	}
	block, _, _ = strings.Cut(block, "```")
	var step []string
	started := false
	for _, line := range strings.Split(block, "\n") {
		switch {
		case strings.HasPrefix(line, "gh attestation verify"):
			started = false
		case started:
			step = append(step, line)
		case strings.Contains(line, "--certificate-oidc-issuer"):
			started = true
		}
	}
	comment := regexp.MustCompile(`\s+#\s.*$`)
	tool := regexp.MustCompile(`(shasum -a 256|sha256sum) -c -`)
	for i, line := range step {
		step[i] = comment.ReplaceAllString(line, "")
	}
	script := strings.TrimSpace(strings.Join(step, "\n"))
	if !tool.MatchString(script) || !strings.Contains(script, "checksums.txt") || !strings.Contains(script, `"$ARCHIVE"`) {
		t.Fatalf("found no checksum step between the cosign command and gh attestation verify: %q", script)
	}
	tools := 0
	for _, name := range []string{"shasum -a 256 -c -", "sha256sum -c -"} {
		if _, err := exec.LookPath(strings.Fields(name)[0]); err != nil {
			continue
		}
		tools++
		run := func(t *testing.T, archive string, dir string) (string, int) {
			t.Helper()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, sh, "-c", tool.ReplaceAllString(script, name))
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "ARCHIVE="+archive)
			out, err := cmd.CombinedOutput()
			code := 0
			if ee := (&exec.ExitError{}); errors.As(err, &ee) {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			return string(out), code
		}
		dir := t.TempDir()
		const archive = "tailkeeper_0.5.0_darwin_arm64.tar.gz"
		write := func(name, content string) {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		write(archive, "archive bytes\n")
		write("tailkeeper_0.5.0_linux_amd64.tar.gz", "other bytes\n")
		sum := func(file string) string {
			out, err := exec.Command(strings.Fields(name)[0], append(strings.Fields(name)[1:len(strings.Fields(name))-2], file)...).Output()
			if err != nil {
				t.Fatal(err)
			}
			return strings.Fields(string(out))[0]
		}
		write("checksums.txt", sum(filepath.Join(dir, "tailkeeper_0.5.0_linux_amd64.tar.gz"))+"  tailkeeper_0.5.0_linux_amd64.tar.gz\n"+
			sum(filepath.Join(dir, archive))+"  "+archive+"\n")
		if out, code := run(t, archive, dir); code != 0 || !strings.Contains(out, archive+": OK") {
			t.Errorf("%s, a matching archive: exit %d, output %q: want exit 0 and %q", name, code, out, archive+": OK")
		}
		write("tailkeeper_0.5.0_renamed.tar.gz", "renamed\n")
		if out, code := run(t, "tailkeeper_0.5.0_renamed.tar.gz", dir); code == 0 || strings.TrimSpace(out) == "" {
			t.Errorf("%s, an archive checksums.txt does not name: exit %d, output %q: want a failure that says so", name, code, out)
		}
		write(archive, "archive bytes, tampered\n")
		if out, code := run(t, archive, dir); code == 0 || !strings.Contains(out, "FAILED") {
			t.Errorf("%s, a tampered archive: exit %d, output %q: want a failure that says FAILED", name, code, out)
		}
		if err := os.Remove(filepath.Join(dir, archive)); err != nil {
			t.Fatal(err)
		}
		if out, code := run(t, archive, dir); code == 0 || strings.TrimSpace(out) == "" {
			t.Errorf("%s, a missing archive: exit %d, output %q: want a failure that says so", name, code, out)
		}
	}
	if tools == 0 {
		t.Skip("neither shasum nor sha256sum is installed")
	}
}
