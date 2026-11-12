//go:build darwin

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/releasebundle"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mcpbVersion = "0.6.0-test"

var mcpbOnce sync.Once
var mcpbArchive string
var mcpbBuildErr error

func buildMCPB() {
	dir := filepath.Dir(bin)
	root, err := filepath.Abs("../..")
	if err != nil {
		mcpbBuildErr = err
		return
	}
	var slices []string
	for _, arch := range []string{"amd64", "arm64"} {
		path := filepath.Join(dir, "bundle-"+arch)
		cmd := exec.Command("go", "build", "-ldflags", "-X github.com/abm9111/tailkeeper/internal/version.Version="+mcpbVersion, "-o", path, ".")
		cmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH="+arch, "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			mcpbBuildErr = fmt.Errorf("build %s: %w: %s", arch, err, out)
			return
		}
		slices = append(slices, path)
	}
	universal := filepath.Join(dir, "bundle-universal")
	cmd := exec.Command("/usr/bin/lipo", "-create", slices[0], slices[1], "-output", universal)
	if out, err := cmd.CombinedOutput(); err != nil {
		mcpbBuildErr = fmt.Errorf("lipo: %w: %s", err, out)
		return
	}
	mcpbArchive = filepath.Join(dir, "bundle.mcpb")
	mcpbBuildErr = releasebundle.Build(releasebundle.BuildOptions{Version: mcpbVersion, UniversalPath: universal, RootDir: root, OutputPath: mcpbArchive})
}

type mcpbManifest struct {
	Server struct {
		MCPConfig struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcp_config"`
	} `json:"server"`
}

func extractedMCPB(t *testing.T) (string, []string) {
	t.Helper()
	mcpbOnce.Do(buildMCPB)
	if mcpbBuildErr != nil {
		t.Fatal(mcpbBuildErr)
	}
	return extractMCPB(t, mcpbArchive)
}

func extractMCPB(t *testing.T, archive string) (string, []string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "package with spaces")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	z, err := zip.OpenReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = z.Close() }()
	for _, f := range z.File {
		if !filepath.IsLocal(f.Name) {
			t.Fatalf("unsafe entry %q", f.Name)
		}
		path := filepath.Join(dir, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, f.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest mcpbManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	cfg := manifest.Server.MCPConfig
	if cfg.Command != "${__dirname}/server/tailkeeper" || len(cfg.Args) != 1 || cfg.Args[0] != "mcp" {
		t.Fatal("unexpected manifest command")
	}
	return strings.Replace(cfg.Command, "${__dirname}", dir, 1), cfg.Args
}

func mcpbEnv(t *testing.T) []string {
	t.Helper()
	if _, err := os.Lstat("/etc/tailkeeper/config.hujson"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("system config must be absent: %v", err)
	}
	home := filepath.Join(t.TempDir(), "home with spaces")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	return []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
}

func mcpbConfig(t *testing.T, env []string, provider string) {
	t.Helper()
	writeConfig(t, env, `{"contexts":{"fixture":{"tailnetId":"fixture","credentials":{"read":`+provider+`}}},"audit":{"reads":"none"}}`)
}

func mcpbWrapper(t *testing.T, unlocked bool, notify string) (string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "wrapper with spaces")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker, wrapper := filepath.Join(dir, "marker"), filepath.Join(dir, "wrapper")
	script := "#!/bin/sh\nprintf ran > " + strconv.Quote(marker) + "\n"
	if notify == "before" {
		notification := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"control","progress":1,"message":"` + apitest.AccessToken + `"}}`
		script += "printf '%s\\n' " + strconv.Quote(notification) + "\n"
	}
	if unlocked {
		script += "export " + creds.EnvAPIKey + "=" + strconv.Quote(apitest.AccessToken) + "\n"
		if notify == "after" {
			benign := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"control","progress":1,"message":"benign"}}`
			secret := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"control","progress":1,"message":"` + apitest.AccessToken + `"}}`
			script += "\"$@\"\nstatus=$?\nprintf '%s\\n' " + strconv.Quote(benign) + "\n/bin/sleep 0.1\nprintf '%s\\n' " + strconv.Quote(secret) + "\nexit \"$status\"\n"
		} else {
			script += "exec \"$@\"\n"
		}
	} else {
		script += "echo locked >&2\nexit 19\n"
	}
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return wrapper, marker
}

func mcpbMarker(t *testing.T, marker string, want bool) {
	t.Helper()
	_, err := os.Stat(marker)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if (err == nil) != want {
		t.Fatalf("wrapper marker presence = %t, want %t", err == nil, want)
	}
}

// mcpbDetector retains only the possible prefix of a match, so it has bounded
// memory and detects a canary even when the SDK reads it across buffer boundaries.
type mcpbDetector struct {
	mu     sync.Mutex
	tail   []byte
	canary string
	found  bool
}

func (d *mcpbDetector) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	combined := append(append([]byte(nil), d.tail...), p...)
	if bytes.Contains(combined, []byte(d.canary)) {
		d.found = true
	}
	keep := len(d.canary) - 1
	if len(combined) < keep {
		keep = len(combined)
	}
	d.tail = append(d.tail[:0], combined[len(combined)-keep:]...)
	return len(p), nil
}

func (d *mcpbDetector) leaked() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.found
}

func mcpbExchange(t *testing.T, path string, args, env []string, missing bool, canary string, notifications *atomic.Int32) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = env
	stdoutDetector := mcpbDetector{canary: canary}
	stderrDetector := mcpbDetector{canary: canary}
	cmd.Stderr = &stderrDetector
	stdout, childStdout, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = childStdout
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = stdout.Close()
		_ = childStdout.Close()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		_ = childStdout.Close()
		t.Fatal(err)
	}
	if err := childStdout.Close(); err != nil {
		_ = stdout.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	reader, forward := io.Pipe()
	drainDone := make(chan error, 1)
	go func() {
		defer func() { _ = forward.Close() }()
		buf := make([]byte, 4096)
		forwarding := true
		for {
			n, readErr := stdout.Read(buf)
			if n > 0 {
				_, _ = stdoutDetector.Write(buf[:n])
				if forwarding {
					if _, err := forward.Write(buf[:n]); err != nil {
						forwarding = false
					}
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					drainDone <- nil
				} else {
					drainDone <- readErr
				}
				return
			}
		}
	}()
	drained := false
	defer func() {
		_ = reader.Close()
		_ = stdout.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		if !drained {
			<-drainDone
		}
	}()
	// The dedicated reader always drains until process stdout EOF, even after
	// SDK shutdown closes its forwarding pipe. Its fixed-size buffer and the
	// detector's short suffix keep memory bounded without logging output.
	opts := &mcp.ClientOptions{ProgressNotificationHandler: func(context.Context, *mcp.ProgressNotificationClientRequest) {
		if notifications != nil {
			notifications.Add(1)
		}
	}}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "bundle-test", Version: "1"}, opts).Connect(ctx, &mcp.IOTransport{Reader: reader, Writer: stdin}, nil)
	if err != nil {
		t.Fatal("initialize failed")
	}
	if cs.InitializeResult().ServerInfo.Version != mcpbVersion {
		t.Fatal("wrong server version")
	}
	list, err := cs.ListTools(ctx, nil)
	if err != nil || len(list.Tools) == 0 {
		t.Fatal("list failed")
	}
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "tailkeeper_info", Arguments: struct{}{}})
	if err != nil || result.IsError {
		t.Fatal("info failed")
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		Version string `json:"version"`
		OS      string `json:"os"`
		Arch    string `json:"arch"`
	}
	if err := json.Unmarshal(data, &info); err != nil || info.Version != mcpbVersion || info.OS != "darwin" || info.Arch != runtime.GOARCH {
		t.Fatal("unexpected packaged identity")
	}
	if missing {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "devices_list", Arguments: struct{}{}})
		if err != nil || !res.IsError {
			t.Fatal("missing credential call failed")
		}
		body, err := json.Marshal(res)
		if err != nil || !strings.Contains(string(body), "credential_unavailable") {
			t.Fatal("missing credential was not visible")
		}
	}
	if err := cs.Close(); err != nil {
		t.Fatal("close failed")
	}
	select {
	case err := <-drainDone:
		drained = true
		if err != nil {
			t.Fatal("stdout drain failed")
		}
	case <-ctx.Done():
		t.Fatal("stdout drain timed out")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	return stdoutDetector.leaked() || stderrDetector.leaked()
}

// The private file is outside both the source root and extracted package.
// All archive entries and their extracted bytes are examined, including the
// binary; the distinct canary is present in the provider fixture itself.
func mcpbExternalFixture(t *testing.T) {
	t.Helper()
	env := mcpbEnv(t)
	external := filepath.Join(t.TempDir(), "private provider")
	if err := os.Mkdir(external, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(external, "read.env")
	canary := strings.Repeat("mcpb-external-fixture-", 4)
	if err := os.WriteFile(fixture, []byte(creds.EnvAPIKey+"="+canary+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mcpbConfig(t, env, `{"provider":"file","path":`+strconv.Quote(fixture)+`}`)
	// The external fixture and its reference exist before this new Build call.
	mcpbOnce.Do(buildMCPB)
	if mcpbBuildErr != nil {
		t.Fatal(mcpbBuildErr)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "fresh.mcpb")
	if err := releasebundle.Build(releasebundle.BuildOptions{Version: mcpbVersion, UniversalPath: filepath.Join(filepath.Dir(bin), "bundle-universal"), RootDir: root, OutputPath: archive}); err != nil {
		t.Fatal(err)
	}
	path, args := extractMCPB(t, archive)
	packageDir := filepath.Dir(filepath.Dir(path))
	if filepath.IsLocal(mustMCPBRelative(t, packageDir, fixture)) {
		t.Fatal("provider fixture is inside package")
	}
	cfg := filepath.Join(strings.TrimPrefix(env[0], "HOME="), "Library", "Application Support", "tailkeeper", "config.hujson")
	configBytes, err := os.ReadFile(cfg)
	if err != nil || !bytes.Contains(configBytes, []byte(fixture)) || bytes.Contains(configBytes, []byte(canary)) {
		t.Fatal("provider reference was not external")
	}
	fixtureBytes, err := os.ReadFile(fixture)
	if err != nil || !bytes.Contains(fixtureBytes, []byte(canary)) {
		t.Fatal("fixture canary was not present")
	}
	z, err := zip.OpenReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = z.Close() }()
	want := map[string]bool{"CHANGELOG.md": true, "LICENSE": true, "NOTICE": true, "README.md": true, "SECURITY.md": true, "THIRD_PARTY_LICENSES": true, "manifest.json": true, "server/tailkeeper": true}
	if len(z.File) != len(want) {
		t.Fatal("unexpected bundle entry count")
	}
	for _, entry := range z.File {
		if !want[entry.Name] {
			t.Fatal("unexpected or duplicate bundle entry")
		}
		delete(want, entry.Name)
		r, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		extracted, err := os.ReadFile(filepath.Join(packageDir, filepath.FromSlash(entry.Name)))
		if err != nil || !bytes.Equal(body, extracted) || bytes.Contains(body, []byte(canary)) {
			t.Fatal("bundle content differs or contains private fixture canary")
		}
	}
	if len(want) != 0 {
		t.Fatal("bundle entry missing")
	}
	if mcpbExchange(t, path, args, env, false, canary, nil) {
		t.Fatal("fixture credential appeared in output")
	}
}

func mustMCPBRelative(t *testing.T, base, target string) string {
	t.Helper()
	rel, err := filepath.Rel(base, target)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

func TestMCPBBundledServerInSpacedPathWithMinimalPATH(t *testing.T) {
	path, args := extractedMCPB(t)
	if mcpbExchange(t, path, args, mcpbEnv(t), false, apitest.AccessToken, nil) {
		t.Fatal("fixture credential appeared in output")
	}
}

func TestMCPBUnlockedExecWrapperKeepsStdio(t *testing.T) {
	path, args := extractedMCPB(t)
	env := mcpbEnv(t)
	wrapper, marker := mcpbWrapper(t, true, "")
	mcpbConfig(t, env, `{"provider":"exec","command":[`+strconv.Quote(wrapper)+`]}`)
	if mcpbExchange(t, path, args, env, false, apitest.AccessToken, nil) {
		t.Fatal("fixture credential appeared in output")
	}
	mcpbMarker(t, marker, true)
	t.Run("notification positive control", func(t *testing.T) {
		path, args := extractedMCPB(t)
		env := mcpbEnv(t)
		wrapper, marker := mcpbWrapper(t, true, "before")
		mcpbConfig(t, env, `{"provider":"exec","command":[`+strconv.Quote(wrapper)+`]}`)
		var received atomic.Int32
		if !mcpbExchange(t, path, args, env, false, apitest.AccessToken, &received) {
			t.Fatal("stdout detector missed notification canary")
		}
		if received.Load() == 0 {
			t.Fatal("SDK did not receive the notification")
		}
		mcpbMarker(t, marker, true)
	})
	t.Run("post-shutdown notification positive control", func(t *testing.T) {
		path, args := extractedMCPB(t)
		env := mcpbEnv(t)
		wrapper, marker := mcpbWrapper(t, true, "after")
		mcpbConfig(t, env, `{"provider":"exec","command":[`+strconv.Quote(wrapper)+`]}`)
		if !mcpbExchange(t, path, args, env, false, apitest.AccessToken, nil) {
			t.Fatal("stdout detector missed post-shutdown canary")
		}
		mcpbMarker(t, marker, true)
	})
	t.Run("external provider fixture", func(t *testing.T) {
		mcpbExternalFixture(t)
	})
}

func TestMCPBCompleteInheritedCredentialSkipsWrapper(t *testing.T) {
	path, args := extractedMCPB(t)
	env := mcpbEnv(t)
	wrapper, marker := mcpbWrapper(t, false, "")
	mcpbConfig(t, env, `{"provider":"exec","command":[`+strconv.Quote(wrapper)+`]}`)
	if mcpbExchange(t, path, args, append(env, creds.EnvAPIKey+"="+apitest.AccessToken), false, apitest.AccessToken, nil) {
		t.Fatal("fixture credential appeared in output")
	}
	mcpbMarker(t, marker, false)
	cmd := exec.Command(path, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 19 || !strings.Contains(string(out), "locked") {
		t.Fatalf("absent-credential control: %v", err)
	}
	mcpbMarker(t, marker, true)
}

func TestMCPBMissingEnvironmentIsVisible(t *testing.T) {
	path, args := extractedMCPB(t)
	env := mcpbEnv(t)
	mcpbConfig(t, env, `{"provider":"env"}`)
	if mcpbExchange(t, path, args, env, true, apitest.AccessToken, nil) {
		t.Fatal("fixture credential appeared in output")
	}
}

func TestMCPBLockedExecWrapperRefusesWithoutInheritedCredential(t *testing.T) {
	path, args := extractedMCPB(t)
	env := mcpbEnv(t)
	wrapper, marker := mcpbWrapper(t, false, "")
	mcpbConfig(t, env, `{"provider":"exec","command":[`+strconv.Quote(wrapper)+`]}`)
	cmd := exec.Command(path, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 19 || !strings.Contains(string(out), "locked") || strings.Contains(string(out), apitest.AccessToken) {
		t.Fatalf("locked wrapper refusal: %v", err)
	}
	mcpbMarker(t, marker, true)
}

func TestMCPBNonExecutableServerRefused(t *testing.T) {
	path, args := extractedMCPB(t)
	env := mcpbEnv(t)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil || !errors.Is(err, os.ErrPermission) || len(out) != 0 {
		t.Fatalf("non-executable server: %v", err)
	}
}
