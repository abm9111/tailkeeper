package mcpserver

import (
	"context"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// Over MCP the caller of a tool is the kind of request and the name the client declared,
// sanitized; the arguments of the call have no part in it.
func TestMCPNamesTheCallerOfATool(t *testing.T) {
	a := newApp(t, nil)
	var got registry.Call
	a.Registry.MustAdd(registry.Define(registry.Meta{Name: "probe_caller", Area: "probe", Verb: "caller", Summary: "A test tool.",
		Tier: registry.TierLocal, Stage: registry.StageGA, Credential: registry.CredNone},
		func(ctx context.Context, _ *registry.Env, in struct {
			Caller string `json:"caller,omitempty"`
		}) (struct{}, error) {
			got = registry.CallOf(ctx)
			return struct{}{}, nil
		}))
	cs := connectAs(t, a, Options{Profile: "reads"}, "some-client")
	if res := callTool(t, cs, "probe_caller", map[string]any{"caller": "EVIL"}); res.IsError {
		t.Fatalf("probe_caller: %s", text(res, 0))
	}
	if got.Tool != "probe_caller" || got.Caller != (registry.Caller{Kind: "mcp", Client: "some-client"}) || len(got.ID) != 16 {
		t.Errorf("call = %+v", got)
	}
}
