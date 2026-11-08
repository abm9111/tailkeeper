package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/audit"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/mcpserver"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// The security scan through the command line and the MCP server, against the fake API and
// the shipped catalog read at a clock taken from its own dates. Everything is synthetic.

// scanAt is an instant inside the shipped catalog's window, taken from the catalog itself.
func scanAt(t *testing.T) time.Time {
	t.Helper()
	c, err := advisory.Shipped()
	if err != nil {
		t.Fatal(err)
	}
	return c.IssuedAt.Add(24 * time.Hour)
}

func scanDevice(at time.Time, id, version string, extra map[string]any) map[string]any {
	d := map[string]any{"nodeId": id, "clientVersion": version, "os": "linux", "lastSeen": at.Add(-time.Minute).Format(time.RFC3339), "connectedToControl": true}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

// scanHarness is a harness whose API lists devs, whose clock is at, and whose scans are
// recorded (each source) in its audit log, as the real App wires them. There is no
// tailscale command: the local sources fail with local_binary_missing, a gap like any other.
func scanHarness(t *testing.T, at time.Time, devs ...map[string]any) *harness {
	t.Helper()
	f := apitest.New(t)
	body, err := json.Marshal(map[string]any{"devices": devs})
	if err != nil {
		t.Fatal(err)
	}
	f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/devices", 200, string(body))
	h := newHarness(t, f)
	h.app.Env.Now = func() time.Time { return at }
	h.app.Env.RecordObservation = h.app.RecordObservation
	return h
}

// fleet is a fleet in which one device is affected (the shipped rule, connected, an old client)
// and one is not.
func fleet(at time.Time) []map[string]any {
	return []map[string]any{scanDevice(at, "nOLD01CNTRL", "1.28.2-t0123456ab", nil), scanDevice(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil)}
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	return m
}

func TestSecurityScanExitCodes(t *testing.T) {
	at := scanAt(t)
	t.Run("a finding at the threshold is 8, though the scan is partial", func(t *testing.T) {
		h := scanHarness(t, at, fleet(at)...)
		if code := h.run("--json", "security", "scan", "fleet"); code != 8 {
			t.Fatalf("exit %d, want 8: %s %s", code, h.out, h.err)
		}
		out := decode(t, h.out.Bytes())
		if out["status"] != "partial" || out["atThreshold"].(map[string]any)["affected"] != float64(1) {
			t.Errorf("status %v, at threshold %v", out["status"], out["atThreshold"])
		}
		if !strings.Contains(h.err.String(), "findings_present") {
			t.Errorf("stderr does not say why the exit is 8: %q", h.err)
		}
		if strings.Contains(h.err.String(), "--fail-on") {
			t.Errorf("stderr blames a --fail-on the command does not have: %q", h.err)
		}
	})
	t.Run("a threshold above the finding is 1, not 8", func(t *testing.T) {
		h := scanHarness(t, at, fleet(at)...)
		// The shipped rule's severity is low.
		if code := h.run("--json", "security", "scan", "fleet", "--threshold", "medium"); code != 1 {
			t.Fatalf("exit %d, want 1: %s %s", code, h.out, h.err)
		}
		if got := decode(t, h.out.Bytes())["atThreshold"].(map[string]any); got["affected"] != float64(0) || got["potentiallyAffected"] != float64(0) {
			t.Errorf("at threshold %v", got)
		}
	})
	t.Run("nothing found and not everything covered is 1", func(t *testing.T) {
		h := scanHarness(t, at, scanDevice(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil))
		if code := h.run("security", "scan", "fleet"); code != 1 {
			t.Fatalf("exit %d, want 1: %s %s", code, h.out, h.err)
		}
		// --quiet prints nothing only on success: an incomplete scan is not a success.
		h.out.Reset()
		if code := h.run("security", "scan", "fleet", "--quiet"); code != 1 || h.out.Len() == 0 {
			t.Errorf("--quiet: exit %d, %d bytes", code, h.out.Len())
		}
	})
	t.Run("the shipped catalog's pending rules keep a clean fleet from exiting 0", func(t *testing.T) {
		// Everything else is whole except what the stand-in lacks (the local sources fail):
		// the catalog row is partial by itself, because four rules are pending.
		h := scanHarness(t, at, scanDevice(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil))
		if code := h.run("--json", "security", "scan", "fleet"); code != 1 {
			t.Fatalf("exit %d: %s", code, h.out)
		}
		rows := decode(t, h.out.Bytes())["coverage"].([]any)
		for _, r := range rows {
			if m := r.(map[string]any); m["dimension"] == "catalog" && !strings.Contains(fmt.Sprint(m["explanation"]), "pending rules: 4") {
				t.Errorf("the catalog row does not name the pending rules: %v", m)
			}
		}
	})
}

func TestSecurityScanGlobalFailuresKeepTheirCodes(t *testing.T) {
	at := scanAt(t)
	// With --json an error is a JSON document on standard output.
	run := func(h *harness, args ...string) (int, map[string]any) {
		t.Helper()
		code := h.run(append([]string{"--json"}, args...)...)
		var e map[string]any
		if h.out.Len() > 0 {
			e = decode(t, h.out.Bytes())
		}
		return code, e
	}
	t.Run("an invalid configuration is 6", func(t *testing.T) {
		h := scanHarness(t, at, fleet(at)...)
		h.r.Build = func(context.Context, string) (*app.App, error) {
			return nil, tkerr.New(tkerr.ConfigInvalid, "synthetic: the configuration does not parse", "fix it")
		}
		if code, _ := run(h, "security", "scan", "fleet"); code != 6 {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("audit reads none refuses the scan, with 6, before any source is asked", func(t *testing.T) {
		h := scanHarness(t, at, fleet(at)...)
		h.app.AuditReads = "none"
		if code, e := run(h, "security", "scan", "fleet"); code != 6 || !strings.Contains(fmt.Sprint(e), "audit.reads") {
			t.Errorf("exit %d: %v", code, e)
		}
	})
	t.Run("an audit log that is not open is 7", func(t *testing.T) {
		h := scanHarness(t, at, fleet(at)...)
		h.app.Audit, h.app.AuditErr = nil, tkerr.New(tkerr.AuditUnavailable, "synthetic: no log", "")
		if code, _ := run(h, "security", "scan", "fleet"); code != 7 {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("a surface that keeps no per-source record refuses, with 7", func(t *testing.T) {
		h := scanHarness(t, at, fleet(at)...)
		h.app.Env.RecordObservation = nil
		if code, _ := run(h, "security", "scan", "fleet"); code != 7 {
			t.Errorf("exit %d", code)
		}
	})
	t.Run("a missing credential is a gap in a fleet scan, not a refusal", func(t *testing.T) {
		h := newHarness(t, nil)
		h.app.Env.RecordObservation = h.app.RecordObservation
		h.app.Env.Now = func() time.Time { return at }
		code := h.run("--json", "security", "scan", "fleet")
		if code != 1 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
		rows := decode(t, h.out.Bytes())["coverage"].([]any)
		found := false
		for _, r := range rows {
			if m := r.(map[string]any); m["dimension"] == "versions" && strings.Contains(fmt.Sprint(m["explanation"]), "credential_unavailable") {
				found = true
			}
		}
		if !found {
			t.Errorf("the missing credential is not in the coverage: %v", rows)
		}
	})
	t.Run("no scope, a scope outside the set and a threshold outside it are 2", func(t *testing.T) {
		for _, args := range [][]string{{"security", "scan"}, {"security", "scan", "all"}, {"security", "scan", "fleet", "--threshold", "urgent"}} {
			h := scanHarness(t, at, fleet(at)...)
			code, e := run(h, args...)
			if code != 2 {
				t.Errorf("%v: exit %d", args, code)
			}
			if inner, _ := e["error"].(map[string]any); inner == nil || inner["code"] == nil {
				t.Errorf("%v: output %q is not a JSON error", args, h.out)
			}
		}
	})
}

// The command offers --json, --format and --quiet, and nothing that would choose what is
// judged or by what: a flag it does not have is a usage error, in the shape --json asks for,
// and nothing is read. --json and a format other than json contradict each other.
func TestSecurityScanOutputFlagsAreRefusedAsUsageErrors(t *testing.T) {
	at := scanAt(t)
	for _, args := range [][]string{
		{"security", "scan", "fleet", "--json", "--format", "markdown"}, {"security", "scan", "fleet", "--json", "--format", "text"},
		{"--json", "security", "scan", "fleet", "--format", "github"}, {"security", "scan", "fleet", "--format", "sarif"},
		{"--json", "security", "scan", "fleet", "--format=sarif"}, {"security", "scan", "fleet", "--fail-on", "warnings"},
		{"security", "scan", "fleet", "--catalog", "x.json"}, {"security", "scan", "fleet", "--intent", "x.json"},
		{"security", "scan", "fleet", "--update"}, {"security", "scan", "fleet", "--url", "https://example.com"},
	} {
		h := scanHarness(t, at, fleet(at)...)
		code := h.run(args...)
		if code != 2 {
			t.Errorf("%v: exit %d (%s)", args, code, h.err)
		}
		// An error is a JSON document on standard output when JSON was asked for, else a
		// line on standard error; nothing else is printed.
		if jsonRequested(args) {
			if e := decode(t, h.out.Bytes()); e["error"] == nil || h.err.Len() != 0 {
				t.Errorf("%v: stdout %q stderr %q: not a JSON error alone", args, h.out, h.err)
			}
		} else if h.out.Len() != 0 || h.err.Len() == 0 {
			t.Errorf("%v: stdout %q stderr %q", args, h.out, h.err)
		}
	}
	// --format json is --json.
	h := scanHarness(t, at, fleet(at)...)
	if code := h.run("security", "scan", "fleet", "--format", "json"); code != 8 || decode(t, h.out.Bytes())["scope"] != "fleet" {
		t.Errorf("--format json: exit %d, %s", code, h.out)
	}
}

// The CLI in JSON and the MCP tool return one structured result.
func TestSecurityScanCLIJSONMCPParity(t *testing.T) {
	at := scanAt(t)
	devs := append(fleet(at), scanDevice(at, "nOFF01CNTRL", "1.28.2-t0123456ab", map[string]any{"connectedToControl": false}))
	h := scanHarness(t, at, devs...)
	if code := h.run("--json", "security", "scan", "fleet", "--threshold", "low"); code != 8 {
		t.Fatalf("exit %d: %s %s", code, h.out, h.err)
	}
	cliOut := decode(t, h.out.Bytes())

	srv, err := mcpserver.New(h.app, mcpserver.Options{Profile: "reads"})
	if err != nil {
		t.Fatal(err)
	}
	cs := connectMCP(t, srv)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "security_scan", Arguments: map[string]any{"scope": "fleet", "threshold": "low"}})
	if err != nil || res.IsError {
		t.Fatalf("mcp call: %v %+v", err, res)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	mcpOut := decode(t, raw)

	// The premise: the result is not trivially the same because it is empty.
	if f, _ := cliOut["findings"].([]any); len(f) < 3 || cliOut["status"] != "partial" || cliOut["atThreshold"].(map[string]any)["affected"] != float64(1) {
		t.Fatalf("the CLI result is too thin to compare: %v", cliOut)
	}
	if !reflect.DeepEqual(cliOut, mcpOut) {
		cb, _ := json.MarshalIndent(cliOut, "", " ")
		mb, _ := json.MarshalIndent(mcpOut, "", " ")
		t.Errorf("the CLI and MCP results differ:\nCLI\n%s\nMCP\n%s", cb, mb)
	}
	// The MCP text content carries the same document, for hosts that ignore structuredContent.
	var inText map[string]any
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok && strings.HasPrefix(tc.Text, "{") {
			inText = decode(t, []byte(tc.Text))
		}
	}
	if !reflect.DeepEqual(cliOut, inText) {
		t.Errorf("the MCP text content differs from the CLI result")
	}
}

func connectMCP(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })
	return cs
}

// The device is shown whole nowhere, in any format, and a hostile device ID reaches no
// layout: the CLI's text and JSON and the MCP result alike.
func TestSecurityScanSanitizerAndTripwireAcrossEveryFormat(t *testing.T) {
	at := scanAt(t)
	hostile := []string{
		"##vso[task.logissue]AAAAAAAA", "tskey-api-kABCDEFG1CNTRL-0123456789abcdefghij", "alice@example.com-device-0001",
		"nESC\x1b[31mRED\x1b[0m-CNTRL", "nBIDI\u202eEVILCNTRL", "::error file=x::injected-message-0001",
	}
	var devs []map[string]any
	for _, id := range hostile {
		devs = append(devs, scanDevice(at, id, "1.28.2-t0123456ab", nil))
	}
	devs = append(devs, scanDevice(at, "nOLD01CNTRL", "1.28.2-t0123456ab", nil))
	h := scanHarness(t, at, devs...)

	var outputs = map[string]string{}
	h.run("security", "scan", "fleet")
	outputs["cli text"] = h.out.String() + h.err.String()
	h.out.Reset()
	h.err.Reset()
	h.run("--json", "security", "scan", "fleet")
	outputs["cli json"] = h.out.String() + h.err.String()
	srv, err := mcpserver.New(h.app, mcpserver.Options{Profile: "reads"})
	if err != nil {
		t.Fatal(err)
	}
	cs := connectMCP(t, srv)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "security_scan", Arguments: map[string]any{"scope": "fleet"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	outputs["mcp"] = string(b)
	for name, text := range outputs {
		if text == "" {
			t.Errorf("%s: no output", name)
		}
		for _, bad := range []string{"tskey-", "alice@", "::error", "##vso[", "\x1b", "\u202e", "nOLD01CNTRL", "injected-message"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s holds %q", name, bad)
			}
		}
		if !strings.Contains(text, "nOLD…") {
			t.Errorf("%s does not show the one ordinary device by its start", name)
		}
	}
	// In the text layout no line starts a CI log command or a workflow command.
	for _, line := range strings.Split(outputs["cli text"], "\n") {
		if regexp.MustCompile(`^\s*(::|##)`).MatchString(line) {
			t.Errorf("a line of the text layout starts a command: %q", line)
		}
	}
}

// F10: the read line of a scan carries the call identifier its collect lines carry as their
// parent, from the command line and from MCP, and the log still verifies.
func TestSecurityScanReadLineJoinsToItsCollectLines(t *testing.T) {
	at := scanAt(t)
	lines := func(h *harness) []map[string]any {
		t.Helper()
		data, err := os.ReadFile(h.app.AuditPath)
		if err != nil {
			t.Fatal(err)
		}
		var out []map[string]any
		for _, l := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			var m map[string]any
			if err := json.Unmarshal(l, &m); err != nil {
				t.Fatal(err)
			}
			out = append(out, m)
		}
		return out
	}
	check := func(t *testing.T, h *harness, surface string) {
		t.Helper()
		var read map[string]any
		var parents = map[string]int{}
		for _, l := range lines(h) {
			switch {
			case l["event"] == "read" && l["tool"] == "security_scan":
				read = l
			case l["event"] == "collect":
				parents[fmt.Sprint(l["parent"])]++
			}
		}
		if read == nil {
			t.Fatal("no read line for the scan")
		}
		id, _ := read["call"].(string)
		if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(id) {
			t.Fatalf("the read line's call = %v", read["call"])
		}
		if parents[id] < 2 || len(parents) != 1 {
			t.Errorf("the collect lines' parents %v do not join to the read line %s", parents, id)
		}
		if r, _ := read["requester"].(map[string]any); r == nil || r["kind"] != surface {
			t.Errorf("requester %v, want %s", read["requester"], surface)
		}
		if _, err := audit.VerifyHistory(h.app.AuditPath); err != nil {
			t.Errorf("audit verify: %v", err)
		}
	}
	t.Run("cli", func(t *testing.T) {
		h := scanHarness(t, at, fleet(at)...)
		h.run("security", "scan", "fleet")
		check(t, h, "cli")
	})
	t.Run("mcp", func(t *testing.T) {
		h := scanHarness(t, at, fleet(at)...)
		srv, err := mcpserver.New(h.app, mcpserver.Options{Profile: "reads"})
		if err != nil {
			t.Fatal(err)
		}
		cs := connectMCP(t, srv)
		if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "security_scan", Arguments: map[string]any{"scope": "fleet"}}); err != nil {
			t.Fatal(err)
		}
		check(t, h, "mcp")
	})
}

// The scan's help names its arguments, its format and its intent flags, and offers nothing else.
func TestSecurityScanHelp(t *testing.T) {
	h := scanHarness(t, scanAt(t))
	if code := h.run("security", "scan", "--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	help := h.err.String() + h.out.String()
	for _, want := range []string{"tailkeeper security scan", "-scope", "-threshold", "-json", "-quiet", "-format", "-invariants", "-no-invariants", "MCP tool: security_scan"} {
		if !strings.Contains(help, want) {
			t.Errorf("help lacks %q:\n%s", want, help)
		}
	}
	for _, not := range []string{"-catalog", "-fail-on", "-url", "-path", "-update", "-intent"} {
		if strings.Contains(help, not) {
			t.Errorf("help offers %q", not)
		}
	}
}

// A fleet scan needs the credential, so a configuration that reads it through a wrapper
// re-executes under the wrapper; a local scan makes no API request and does not.
func TestSecurityScanLocalScopeStartsNoCredentialWrapper(t *testing.T) {
	at := scanAt(t)
	for scope, wantWrapper := range map[string]bool{"fleet": true, "local": false} {
		h := newHarness(t, nil)
		h.app.Env.APIErr = creds.ErrReexecRequired
		h.app.Env.RecordObservation = h.app.RecordObservation
		h.app.Env.Now = func() time.Time { return at }
		h.run("--json", "security", "scan", scope)
		if got := h.reexecProvider != nil; got != wantWrapper {
			t.Errorf("%s: the wrapper was started: %v, want %v (stdout %s)", scope, got, wantWrapper, h.out)
		}
		if scope == "local" {
			out := decode(t, h.out.Bytes())
			if out["scope"] != "local" || out["status"] != "partial" {
				t.Errorf("the local scan did not run: %v", out)
			}
		}
	}
}

// A device is shown by part of its ID whatever the ID's length, in the text layout, in JSON and
// over MCP: the IDs of 1, 4, 8, 9 and 128 characters, each with a different first letter.
func TestSecurityScanShowsOnlyPartOfEveryDeviceIDInEveryOutput(t *testing.T) {
	at := scanAt(t)
	ids := map[string]string{ // ID -> what is shown
		"Q": "…", "WXYZ": "WX…", "EDCVBNMK": "EDCV…", "RFVTGBYHN": "RFVT…", "T" + strings.Repeat("X", 127): "TXXX…",
	}
	var devs []map[string]any
	want := map[string]bool{}
	for id, shown := range ids {
		devs = append(devs, scanDevice(at, id, "1.28.2-t0123456ab", nil))
		want[shown] = true
	}
	h := scanHarness(t, at, devs...)

	outputs := map[string]string{}
	devicesIn := map[string]map[string]bool{}
	// The text layout: the second part of each finding line (rule, device, ...).
	h.run("security", "scan", "fleet")
	outputs["cli text"] = h.out.String()
	devicesIn["cli text"] = devicesOfLines(h.out.String(), "")
	// The JSON of the command line, and the structured result over MCP.
	h.out.Reset()
	h.run("--json", "security", "scan", "fleet")
	outputs["cli json"] = h.out.String()
	devicesIn["cli json"] = devicesOf(t, decode(t, h.out.Bytes()))
	srv, err := mcpserver.New(h.app, mcpserver.Options{Profile: "reads"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := connectMCP(t, srv).CallTool(context.Background(), &mcp.CallToolParams{Name: "security_scan", Arguments: map[string]any{"scope": "fleet"}})
	if err != nil || res.IsError {
		t.Fatalf("mcp: %v %+v", err, res)
	}
	raw, _ := json.Marshal(res)
	outputs["mcp"] = string(raw)
	sc, _ := json.Marshal(res.StructuredContent)
	devicesIn["mcp"] = devicesOf(t, decode(t, sc))

	for name, got := range devicesIn {
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: devices shown %v, want %v", name, got, want)
		}
		for id := range ids {
			if len(id) > 1 && strings.Contains(outputs[name], id) {
				t.Errorf("%s holds the whole ID of %d characters", name, len(id))
			}
		}
	}
}

// devicesOfLines reads the device of each finding line of a layout: the lines that start with
// a severity word (after prefix, a list marker) hold "rule · device · applicability · ...", and
// the device may be followed by its pseudonym.
func devicesOfLines(layout, prefix string) map[string]bool {
	got := map[string]bool{}
	for _, line := range strings.Split(layout, "\n") {
		for _, sev := range []string{"error: ", "warning: ", "notice: "} {
			if rest, ok := strings.CutPrefix(line, prefix+sev); ok {
				if parts := strings.Split(rest, " · "); len(parts) >= 4 {
					got[strings.Fields(parts[1])[0]] = true
				}
			}
		}
	}
	return got
}

func devicesOf(t *testing.T, out map[string]any) map[string]bool {
	t.Helper()
	got := map[string]bool{}
	for _, f := range out["findings"].([]any) {
		got[f.(map[string]any)["device"].(string)] = true
	}
	return got
}

// A scope or a threshold outside the closed sets is refused from the input alone, before the
// configuration is loaded (loading it can cost a secret-manager unlock).
func TestSecurityScanRefusesABadArgumentBeforeLoadingTheConfiguration(t *testing.T) {
	at := scanAt(t)
	for _, args := range [][]string{{"security", "scan", "all"}, {"security", "scan", "fleet", "--threshold", "urgent"}, {"security", "scan", ""}} {
		h := scanHarness(t, at, fleet(at)...)
		builds := 0
		build := h.r.Build
		h.r.Build = func(ctx context.Context, name string) (*app.App, error) {
			builds++
			return build(ctx, name)
		}
		if code := h.run(args...); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
		if builds != 0 {
			t.Errorf("%v: the configuration was loaded %d times before the argument was refused", args, builds)
		}
	}
	// And the same harness does load it for a good one, so the count above can fail.
	h := scanHarness(t, at, fleet(at)...)
	builds := 0
	build := h.r.Build
	h.r.Build = func(ctx context.Context, name string) (*app.App, error) { builds++; return build(ctx, name) }
	h.run("security", "scan", "fleet")
	if builds != 1 {
		t.Errorf("a good command loaded the configuration %d times, want 1", builds)
	}
}
