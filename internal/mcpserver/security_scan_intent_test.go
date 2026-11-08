package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
)

// Over MCP the scan's intent is the configured invariants file and nothing a model says. The
// choice of another file, and the switch that turns the intent off, are for the command line:
// they are not in the schema a model reads, and a call that passes them is refused before the
// configuration's own file is looked at.
func TestSecurityScanMCPStillHasOnlyScopeAndThreshold(t *testing.T) {
	// The configured file is missing: a call that went on to read it would be config_invalid,
	// not validation_failed, so the code of each refusal below shows the file was not read.
	f := apitest.New(t)
	a := newApp(t, f)
	a.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: filepath.Join(t.TempDir(), "gone.hujson")}}}
	a.Env.RecordObservation = a.RecordObservation
	cs := connect(t, a, Options{Profile: "reads"})
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var tool *mcp.Tool
	for _, tl := range list.Tools {
		if tl.Name == "security_scan" {
			tool = tl
		}
	}
	if tool == nil {
		t.Fatal("security_scan is not advertised")
	}
	raw, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties           map[string]struct{ Type string } `json:"properties"`
		AdditionalProperties any                              `json:"additionalProperties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	var names []string
	for k, p := range schema.Properties {
		names = append(names, k)
		if p.Type != "string" {
			t.Errorf("argument %s has type %q", k, p.Type)
		}
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "scope,threshold" || schema.AdditionalProperties != false {
		t.Errorf("the arguments are %v (additionalProperties %v), want exactly scope and threshold and no more", names, schema.AdditionalProperties)
	}

	for _, args := range []map[string]any{
		{"scope": "local", "invariants": "/etc/passwd"}, {"scope": "local", "Invariants": "x"}, {"scope": "local", "noInvariants": true},
		{"scope": "local", "no-invariants": true}, {"scope": "local", "invariantsFile": "x"}, {"scope": "local", "operator": true},
		{"scope": "local", "intent": map[string]any{"tests": []any{}}}, {"scope": "local", "tests": []any{map[string]any{"src": "x"}}},
		{"scope": "local", "env": "TAILKEEPER_INVARIANTS"}, {"scope": map[string]any{"invariants": "x"}},
		{"scope": "local", "threshold": map[string]any{"noInvariants": true}}, {"scope": "local", "acl": map[string]any{"invariantsFile": "x"}},
	} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "security_scan", Arguments: args})
		if err != nil {
			t.Fatalf("%v: protocol error %v", args, err)
		}
		m, _ := res.StructuredContent.(map[string]any)
		inner, _ := m["error"].(map[string]any)
		if !res.IsError || inner == nil || inner["code"] != "validation_failed" {
			t.Errorf("%v: %v (want validation_failed: refused before the configured file was looked at)", args, res.StructuredContent)
		}
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d API requests came of arguments that were refused", n)
	}

	// The same server with a readable file: a plain call uses it, and says so.
	const file = `{"tests": [{"src": "zq-canary-owner@example.com", "accept": ["tag:zq-canary-db:5432"]}]}`
	path := filepath.Join(t.TempDir(), "intent.hujson")
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	b := newApp(t, apitest.New(t))
	b.Env.Privacy = key
	b.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
	b.Env.RecordObservation = b.RecordObservation
	res, err := connect(t, b, Options{Profile: "reads"}).CallTool(context.Background(), &mcp.CallToolParams{Name: "security_scan", Arguments: map[string]any{"scope": "local"}})
	if err != nil || res.IsError {
		t.Fatalf("a plain call: %v %+v", err, res)
	}
	sum := sha256.Sum256([]byte(file))
	in, _ := res.StructuredContent.(map[string]any)["intent"].(map[string]any)
	// While personal data is masked the digest is the keyed one; the plain hash is nowhere.
	if in["source"] != "configured" || in["digest"] != key.Digest([]byte(file)) || in["expectations"] != float64(1) {
		t.Errorf("intent %v", in)
	}
	all, _ := json.Marshal(res)
	if strings.Contains(string(all), hex.EncodeToString(sum[:])) {
		t.Errorf("the result holds the plain SHA-256 of the file while personal data is masked: %s", all)
	}
	if strings.Contains(string(all), "zq-canary") || strings.Contains(string(all), ":5432") {
		t.Errorf("the result repeats the file: %s", all)
	}
}

// A configured intent file that the engine refuses for its size is config_invalid over MCP too,
// as every other way the configured file cannot be used is, and the words are fixed.
func TestSecurityScanMCPConfiguredIntentFilePastTheEngineIsConfigInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "intent.hujson")
	if err := os.WriteFile(path, []byte(`{"tests": [`+strings.Repeat("{},", acl.MaxNodes)+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f := apitest.New(t)
	a := newApp(t, f)
	a.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
	a.Env.RecordObservation = a.RecordObservation
	res, err := connect(t, a, Options{Profile: "reads"}).CallTool(context.Background(), &mcp.CallToolParams{Name: "security_scan", Arguments: map[string]any{"scope": "local"}})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := res.StructuredContent.(map[string]any)
	inner, _ := m["error"].(map[string]any)
	if !res.IsError || inner == nil || inner["code"] != "config_invalid" || inner["message"] != "the intent file is too large or too complex to read" {
		t.Errorf("%v", res.StructuredContent)
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d API requests", n)
	}
}
