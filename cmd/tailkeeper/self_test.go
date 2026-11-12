package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CLI and MCP must identify this exact process build without needing an API or
// local Tailscale. An assessment that has not shipped must not be advertised.
func TestSelfInfoCLIAndMCPNameTheSameBuild(t *testing.T) {
	stdout, stderr, code := run(t, "self", "info", "--json")
	if code != 0 {
		t.Fatalf("self info: exit %d, stderr %s, stdout %s", code, stderr, stdout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "mcp")
	cmd.Env = isolated(t)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "self-info-e2e", Version: "1"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "tailkeeper_info", Arguments: struct{}{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("self info error: %v", res.Content)
	}
	body, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var cliJSON, mcpJSON bytes.Buffer
	if err := json.Compact(&cliJSON, []byte(stdout)); err != nil {
		t.Fatal(err)
	}
	if err := json.Compact(&mcpJSON, body); err != nil {
		t.Fatal(err)
	}
	var left, right map[string]json.RawMessage
	if err := json.Unmarshal(cliJSON.Bytes(), &left); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mcpJSON.Bytes(), &right); err != nil {
		t.Fatal(err)
	}
	l, err := json.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	r, err := json.Marshal(right)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(l, r) {
		t.Fatalf("CLI/MCP differ: %s / %s", l, r)
	}
	if string(left["name"]) != `"tailkeeper"` || string(left["version"]) != `"dev"` || cs.InitializeResult().ServerInfo.Version != "dev" {
		t.Fatalf("wrong build identity: %s", l)
	}
}

func TestSelfInfoIgnoresUnsafeConfiguration(t *testing.T) {
	env := isolated(t)
	// Exercise the HOME fallback when XDG_CONFIG_HOME is empty.
	for i, entry := range env {
		if strings.HasPrefix(entry, "XDG_CONFIG_HOME=") {
			env[i] = "XDG_CONFIG_HOME="
		}
	}
	// An invalid configured provider would prevent normal App.Build. Self info
	// succeeds without reading it and never echoes the configuration contents.
	canary := strings.Repeat("private-fixture-", 8)
	writeConfig(t, env, `{"contexts":{"fixture":{"tailnetId":"fixture","credentials":{"read":{"provider":"file","path":"`+canary+`"}}}}}`)
	// The same child environment must find and reject the invalid configuration.
	control := exec.Command(bin, "doctor", "--json")
	control.Env = env
	controlOut, controlErr := control.CombinedOutput()
	if controlErr == nil || !strings.Contains(string(controlOut), "the file provider needs an absolute") {
		t.Fatalf("doctor did not find the invalid user configuration: %v, %s", controlErr, controlOut)
	}
	cmd := exec.Command(bin, "self", "info", "--json")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(out), canary) {
		t.Fatalf("self info touched provider: %v, %s", err, out)
	}
}

// The built binary prints all three lists of self info in the text form, none when empty, and
// takes no --context: a command that reads no configuration has no context to select, so the
// flag is refused as one it does not know. The global flag, given before the command, is
// accepted, as it is for every command.
func TestSelfInfoPrintsItsListsAndRefusesAContext(t *testing.T) {
	stdout, stderr, code := run(t, "self", "info")
	if code != 0 || stderr != "" {
		t.Fatalf("self info: exit %d, stderr %q", code, stderr)
	}
	for _, want := range []string{"name: tailkeeper\n", "reportSchemas: none\n", "catalogSchemas: none\n", "assessmentCapabilities: none\n"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("self info lacks %q:\n%s", want, stdout)
		}
	}
	if _, stderr, code = run(t, "self", "info", "--context", "work"); code != 2 || !strings.Contains(stderr, "usage") || !strings.Contains(stderr, "context") {
		t.Errorf("self info --context: exit %d, stderr %q, want exit 2 and a usage error", code, stderr)
	}
	if _, stderr, code = run(t, "--context", "work", "self", "info"); code != 0 || stderr != "" {
		t.Errorf("--context work self info: exit %d, stderr %q", code, stderr)
	}
}
