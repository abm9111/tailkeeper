//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/securitypack"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestPackToolsAbsentFromBuiltMCP(t *testing.T) {
	if _, err := os.Stat("/etc/tailkeeper/config.hujson"); !os.IsNotExist(err) {
		t.Fatalf("cannot isolate the built MCP test from a system configuration: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dir := t.TempDir()
	binary := filepath.Join(dir, "tailkeeper")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/tailkeeper")
	build.Dir = filepath.Join("..", "..")
	build.Env = []string{"GOFLAGS=-mod=readonly", "GOPROXY=off", "TAILKEEPER_LIVE="}
	for _, name := range []string{"PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH", "GOTOOLCHAIN", "GOROOT"} {
		if value, ok := os.LookupEnv(name); ok {
			build.Env = append(build.Env, name+"="+value)
		}
	}
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, output)
	}
	command := exec.CommandContext(ctx, binary, "mcp")
	command.Env = []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + filepath.Join(dir, "config"), "XDG_STATE_HOME=" + filepath.Join(dir, "state"), "PATH=/usr/bin:/bin"}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "pack-test", Version: "1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	list, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"security_export", "security_replay", "security_redact", "security_verify"} {
		for _, tool := range list.Tools {
			if tool.Name == name {
				t.Fatalf("MCP listed %s", name)
			}
		}
		if _, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: struct{}{}}); err == nil {
			t.Fatalf("MCP accepted %s", name)
		}
	}
	// Exercise the production command parser with the same isolated environment.
	help := exec.CommandContext(ctx, binary, "security", "verify", "--help")
	help.Env = []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + filepath.Join(dir, "config"), "XDG_STATE_HOME=" + filepath.Join(dir, "state"), "PATH=/usr/bin:/bin"}
	output, err := help.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "-before") || !strings.Contains(string(output), "-correction") {
		t.Fatalf("built verify help: %v: %s", err, output)
	}
	correction := filepath.Join(dir, "correction.json")
	if err := os.WriteFile(correction, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	refusal := exec.CommandContext(ctx, binary, "security", "verify", "--before", filepath.Join(dir, "missing"), "--correction", correction, "--json")
	refusal.Env = help.Env
	output, err = refusal.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(output), "correction_invalid") {
		t.Fatalf("built verify preflight: %v: %s", err, output)
	}
}

func TestBuiltPackReplayRedactDoNotStartExecProvider(t *testing.T) {
	if _, err := os.Stat("/etc/tailkeeper/config.hujson"); !os.IsNotExist(err) {
		t.Fatalf("system config prevents isolation: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, nil)
	catalog, err := advisory.Shipped()
	if err != nil {
		t.Fatal(err)
	}
	h.app.Env.Now = func() time.Time { return catalog.IssuedAt.Add(time.Hour) }
	h.app.Env.Config = &config.Loaded{Dirs: config.Dirs{State: dir}}
	h.app.Env.RecordObservation = h.app.RecordObservation
	h.app.Env.RecordPack = h.app.RecordPack
	pack := filepath.Join(dir, "pack.json")
	if code := h.run("security", "export", "--scope", "local", "--out", pack, "--json"); code != 0 {
		t.Fatalf("fixture export %d: %s %s", code, h.out, h.err)
	}
	binary := filepath.Join(dir, "tailkeeper")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/tailkeeper")
	build.Dir = filepath.Join("..", "..")
	build.Env = []string{"GOFLAGS=-mod=readonly", "GOPROXY=off", "TAILKEEPER_LIVE="}
	for _, name := range []string{"PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH", "GOTOOLCHAIN", "GOROOT"} {
		if v, ok := os.LookupEnv(name); ok {
			build.Env = append(build.Env, name+"="+v)
		}
	}
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	marker, wrapper := filepath.Join(dir, "marker"), filepath.Join(dir, "wrapper.sh")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nprintf ran > "+strconv.Quote(marker)+"\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cfgdir := filepath.Join(dir, "config", "tailkeeper")
	if runtime.GOOS == "darwin" {
		cfgdir = filepath.Join(dir, "Library", "Application Support", "tailkeeper")
	}
	if err := os.MkdirAll(cfgdir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`{"contexts":{"synthetic":{"tailnetId":"T1234CNTRL","credentials":{"read":{"provider":"exec","command":["/bin/sh",%q]}}}}}`, wrapper)
	if err := os.WriteFile(filepath.Join(cfgdir, "config.hujson"), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + filepath.Join(dir, "config"), "XDG_STATE_HOME=" + filepath.Join(dir, "state"), "PATH=/usr/bin:/bin"}
	projection := filepath.Join(dir, "projection.json")
	for _, tc := range []struct {
		name string
		args []string
	}{{"replay", []string{"security", "replay", pack, "--json"}}, {"redact", []string{"security", "redact", pack, "--out", projection, "--json"}}} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(ctx, binary, tc.args...)
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("command: %v: %s", err, out)
			}
			if tc.name == "replay" && !strings.Contains(string(out), `"reproduced": true`) {
				t.Fatalf("not reproduced: %s", out)
			}
			if tc.name == "redact" {
				data, err := os.ReadFile(projection)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := securitypack.Decode(data, nil); !errors.Is(err, securitypack.ErrProjectionNotReplayable) {
					t.Fatalf("not a projection: %v", err)
				}
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("exec wrapper ran: %v", err)
			}
		})
	}
	// A missing synthetic file provider is an observable read sentinel: ordinary
	// credential loading reports a privacy-key error before either command runs.
	fileCfg := fmt.Sprintf(`{"contexts":{"synthetic":{"tailnetId":"T1234CNTRL","credentials":{"read":{"provider":"file","path":%q}}}}}`, filepath.Join(dir, "missing-credential"))
	if err := os.WriteFile(filepath.Join(cfgdir, "config.hujson"), []byte(fileCfg), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"replay", []string{"security", "replay", pack, "--json"}},
		{"redact", []string{"security", "redact", pack, "--out", filepath.Join(dir, "file-projection.json"), "--json"}},
	} {
		t.Run("file-provider-"+tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(ctx, binary, tc.args...)
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("offline command accessed missing provider: %v: %s", err, out)
			}
			if tc.name == "replay" && !strings.Contains(string(out), `"reproduced": true`) {
				t.Fatalf("not reproduced: %s", out)
			}
			if tc.name == "redact" {
				data, err := os.ReadFile(filepath.Join(dir, "file-projection.json"))
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := securitypack.Decode(data, nil); !errors.Is(err, securitypack.ErrProjectionNotReplayable) {
					t.Fatalf("not a projection: %v", err)
				}
			}
		})
	}

}
