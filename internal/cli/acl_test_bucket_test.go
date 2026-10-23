package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/mcpserver"
)

// An empty validation bucket is validate_rate_limited for acl test on both surfaces.
// The text a person reads, and the text an MCP host shows the model, name the seconds.
func TestTheACLTestBucketIsExhaustedOnBothSurfaces(t *testing.T) {
	t.Run("cli", func(t *testing.T) {
		f := apitest.New(t)
		serveLiveFor(f, "{}\n")
		f.ServeValidate(apitest.TestsPass())
		h := limitedHarness(t, f, 1)
		args := []string{"acl", "test", "tag:ci", "--accept", "tag:web:22"}
		for i := 1; i <= 2; i++ {
			if code := h.run(args...); code != 0 {
				t.Fatalf("call %d: exit %d: %s", i, code, h.err)
			}
		}
		h.out.Reset()
		h.err.Reset()
		code := h.run(args...)
		line, _, _ := strings.Cut(h.err.String(), "\n")
		if code != 1 || !strings.HasPrefix(line, "tailkeeper: validate_rate_limited: ") || !strings.Contains(line, "try again in 60 s") {
			t.Errorf("text line: exit %d, stderr %q", code, h.err.String())
		}
	})
	t.Run("mcp", func(t *testing.T) {
		f := apitest.New(t)
		serveLiveFor(f, "{}\n")
		f.ServeValidate(apitest.TestsPass())
		h := newHarness(t, f)
		fixed := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
		c, err := api.New(context.Background(), apitest.Tailnet,
			creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret), Provider: "env"},
			api.Options{BaseURL: f.URL(), ValidatePerMinute: 1, Now: func() time.Time { return fixed }, Sleep: func(context.Context, time.Duration) error { return nil }})
		if err != nil {
			t.Fatal(err)
		}
		h.app.Env.API = c
		srv, err := mcpserver.New(h.app, mcpserver.Options{Profile: "reads"})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		st, ct := mcp.NewInMemoryTransports()
		ss, err := srv.Connect(ctx, st, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ss.Close() })
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "1"}, nil).Connect(ctx, ct, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cs.Close() })
		args := map[string]any{"src": "tag:ci", "accept": []string{"tag:web:22"}}
		for i := 1; i <= 2; i++ {
			res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "acl_test", Arguments: args})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError {
				t.Fatalf("call %d: %s", i, mcpText(res))
			}
		}
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "acl_test", Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		got := mcpText(res)
		if !res.IsError || !strings.HasPrefix(got, "validate_rate_limited: ") || !strings.Contains(got, "try again in 60 s") {
			t.Errorf("mcp text: isError %v, %q", res.IsError, got)
		}
	})
}

func mcpText(res *mcp.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}
