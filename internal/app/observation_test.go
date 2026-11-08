package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/audit"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

var (
	attempt = security.CollectionEvent{Scope: security.ScopeFleet, Source: security.SourceAPIDevices, Phase: security.PhaseAttempt}
	outcome = security.CollectionEvent{Scope: security.ScopeFleet, Source: security.SourceAPIDevices, Phase: security.PhaseOutcome,
		Outcome: security.OutcomeError, Code: "scope_missing", Observed: 3, Dropped: 1, Millis: 12}
)

// buildApp is an App whose audit log is in a temporary directory.
func buildApp(t *testing.T, cfg string) (*App, string) {
	t.Helper()
	d := dirs(t, cfg)
	a, err := Build(context.Background(), Options{Dirs: d, Stat: noCLI, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	return a, filepath.Join(d.Logs, "audit.jsonl")
}

func lines(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

// An event is written as a collect line whose tool, call and requester are the framework's:
// the tool that ran, the surface that named the caller, and the identifier Prepared.Run made.
// Nothing in the tool's input reaches the line.
func TestBuildWiresARequiredObservationRecord(t *testing.T) {
	a, path := buildApp(t, envConfig)
	if a.Env.RecordObservation == nil {
		t.Fatal("the Env has no observation record")
	}
	type hostile struct {
		Tool      string `json:"tool,omitempty"`
		Parent    string `json:"parent,omitempty"`
		Requester string `json:"requester,omitempty"`
	}
	var calls []registry.Call
	probe := registry.Define(registry.Meta{Name: "security_probe", Area: "security", Verb: "probe", Summary: "probe"},
		func(ctx context.Context, env *registry.Env, _ hostile) (struct{}, error) {
			calls = append(calls, registry.CallOf(ctx))
			for _, ev := range []security.CollectionEvent{attempt, outcome} {
				if err := env.RecordObservation(ctx, ev); err != nil {
					return struct{}{}, err
				}
			}
			return struct{}{}, nil
		})
	ctx := registry.WithCaller(context.Background(), registry.Caller{Kind: "mcp", Client: "some-client"})
	for i := 0; i < 2; i++ {
		if _, err := probe.Call(ctx, a.Env, json.RawMessage(`{"tool":"EVIL-TOOL","parent":"EVIL-PARENT","requester":"EVIL-WHO"}`)); err != nil {
			t.Fatal(err)
		}
	}
	got := lines(t, path)
	if len(got) != 4 {
		t.Fatalf("%d lines, want 4: %v", len(got), got)
	}
	for i, l := range got {
		call := calls[i/2]
		who, _ := l["requester"].(map[string]any)
		if l["event"] != "collect" || l["tool"] != "security_probe" || l["parent"] != call.ID || len(call.ID) != 16 ||
			who["kind"] != "mcp" || who["client"] != "some-client" || l["tailnet"] != "T1234CNTRL" || l["scope"] != "fleet" || l["source"] != "api_devices" {
			t.Fatalf("line %d: %v (call %+v)", i, l, call)
		}
	}
	if calls[0].ID == calls[1].ID {
		t.Error("two calls share an identifier")
	}
	if got[0]["phase"] != "attempt" || got[0]["outcome"] != nil || got[1]["phase"] != "outcome" || got[1]["outcome"] != "error" ||
		got[1]["code"] != "scope_missing" || got[1]["observed"] != float64(3) || got[1]["dropped"] != float64(1) || got[1]["ms"] != float64(12) {
		t.Fatalf("attempt %v, outcome %v", got[0], got[1])
	}
	data, _ := os.ReadFile(path)
	for _, bad := range []string{"EVIL-TOOL", "EVIL-PARENT", "EVIL-WHO"} {
		if strings.Contains(string(data), bad) {
			t.Errorf("the audit log holds %q from the tool's input", bad)
		}
	}
	// Outside a tool call there is nothing to correlate with, and the line says so by omission.
	if err := a.RecordObservation(context.Background(), attempt); err != nil {
		t.Fatal(err)
	}
	if last := lines(t, path)[4]; last["tool"] != nil || last["parent"] != nil || last["requester"] != nil {
		t.Errorf("a line outside a call carries a correlation: %v", last)
	}
}

// audit.reads "none" turns the per-source record off, and a collection without it is not
// allowed: the error names the setting and the value that fixes it, reads the same on the
// command line and over MCP (both print the code, the message and the hint), and nothing is
// written.
func TestObservationRefusesAuditReadsNone(t *testing.T) {
	cfg := `{"contexts": {"test": {"tailnetId": "T1234CNTRL", "credentials": {"read": {"provider": "env"}}}}, "audit": {"reads": "none"}}`
	a, path := buildApp(t, cfg)
	err := a.RecordObservation(context.Background(), attempt)
	fe := tkerr.From(err)
	if fe == nil || fe.Code != tkerr.ConfigInvalid || !strings.Contains(fe.Message, "audit.reads") || !strings.Contains(fe.Message, `"none"`) || !strings.Contains(fe.Hint, `"metadata"`) {
		t.Fatalf("error = %+v", fe)
	}
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Errorf("a refused record wrote: %s", data)
	}
}

// A record that is not written is an error, whatever the reason; there is no stripped line to
// stand in for it, as Record writes for a read.
func TestObservationIsNeverDroppedOrReplaced(t *testing.T) {
	a, path := buildApp(t, envConfig)
	// The tripwire refuses a line that holds a credential shape; it is assembled at run time.
	a.Tailnet = "tskey" + "-api-" + "kTEST1CNTRL-" + "notarealsecretvalue"
	if err := a.RecordObservation(context.Background(), attempt); err == nil {
		t.Error("a line the log refuses was reported as recorded")
	}
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Errorf("a stripped line stood in for the refused one: %s", data)
	}
	a.Tailnet, a.Audit, a.AuditErr = "T1234CNTRL", nil, nil
	if fe := tkerr.From(a.RecordObservation(context.Background(), attempt)); fe == nil || fe.Code != tkerr.AuditUnavailable {
		t.Errorf("no log: %+v", fe)
	}
	a.AuditErr = tkerr.New(tkerr.AuditUnavailable, "the log is gone", "")
	if err := a.RecordObservation(context.Background(), attempt); !errors.Is(err, a.AuditErr) {
		t.Errorf("a log that could not be opened: %v", err)
	}
	// An event that is not one of the closed forms is a bug in the producer, not a line.
	if fe := tkerr.From(a.RecordObservation(context.Background(), security.CollectionEvent{})); fe == nil || fe.Code != tkerr.Internal {
		t.Errorf("an invalid event: %+v", fe)
	}
}

// F10: a read line may carry the identifier of its call (16 hexadecimal digits), which is the
// parent of the call's collect lines, so the two can be joined. Anything else under that key
// is dropped, and the line still verifies.
func TestAReadLineCarriesTheCallIdentifierOnlyInItsOwnShape(t *testing.T) {
	a, path := buildApp(t, envConfig)
	for _, call := range []any{"0123456789abcdef", "0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0", "EVIL-CALL", 42, ""} {
		if err := a.Record(map[string]any{"tool": "devices_list", "call": call}); err != nil {
			t.Fatal(err)
		}
	}
	got := lines(t, path)
	if len(got) != 7 {
		t.Fatalf("%d lines", len(got))
	}
	for i, l := range got {
		want, kept := "0123456789abcdef", i == 0
		if v, ok := l["call"]; ok != kept || (kept && v != want) {
			t.Errorf("line %d: call = %v (present %v), want kept=%v", i, v, ok, kept)
		}
	}
	if _, err := audit.VerifyHistory(path); err != nil {
		t.Errorf("the log does not verify: %v", err)
	}
}

// The keys the owner's security explanation adds to a read line are shape-gated like "call": an
// intent is one of three words, a digest is twelve lowercase hexadecimal digits, and a count is a
// whole number that is not negative. A value of any other shape is dropped, so that no key can
// carry an email or tailnet text; the line still verifies.
func TestTheExplanationKeysOfAReadLineKeepOnlyTheirOwnShapes(t *testing.T) {
	a, path := buildApp(t, envConfig)
	hostile := []any{"alice@example.com", "example.ts.net", "Alice Example <alice@example.com>", "{\"acls\":[]}", "", true, false, nil, -1, 1.5, float64(1 << 40), []string{"a"}}
	keys := []string{"intent", "digest", "expectations", "met", "unmet", "unknown", "limited", "not_evaluated"}
	for _, k := range keys {
		for _, v := range hostile {
			if err := a.Record(map[string]any{"tool": "security_explain", k: v}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := a.Record(map[string]any{"tool": "security_explain", "intent": "configured", "digest": "0123456789ab",
		"expectations": 5, "met": int64(1), "unmet": float64(2), "unknown": 0, "limited": 1, "not_evaluated": 1}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"cli", "none"} {
		if err := a.Record(map[string]any{"tool": "security_explain", "intent": v}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"alice@example.com", "example.ts.net", "Alice Example", "acls"} {
		if strings.Contains(string(raw), text) {
			t.Errorf("the audit log holds %q", text)
		}
	}
	got := lines(t, path)
	last := got[len(got)-3]
	for k, want := range map[string]any{"intent": "configured", "digest": "0123456789ab", "expectations": float64(5), "met": float64(1), "unmet": float64(2), "unknown": float64(0), "limited": float64(1), "not_evaluated": float64(1)} {
		if last[k] != want {
			t.Errorf("a value of its own shape: %s = %v, want %v", k, last[k], want)
		}
	}
	for i, l := range got[:len(got)-3] {
		for _, k := range keys {
			if v, ok := l[k]; ok {
				t.Errorf("line %d keeps %s = %v of the wrong shape", i, k, v)
			}
		}
	}
	for i, want := range []string{"cli", "none"} {
		if got[len(got)-2+i]["intent"] != want {
			t.Errorf("intent %q was not kept", want)
		}
	}
	if _, err := audit.VerifyHistory(path); err != nil {
		t.Errorf("the log does not verify: %v", err)
	}
}
