package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// `security explain` is the owner's command line: no tool, argument, resource or prompt of the MCP
// server reaches it, in any profile, with the alpha tools or without, and the tool list is
// the size it was.
func TestExplainIsNotReachableOverMCP(t *testing.T) {
	for _, o := range []Options{{Profile: "reads"}, {Profile: "core"}, {Profile: "full"}, {Profile: "full", EnableAlpha: true}} {
		f := apitest.New(t)
		a := newApp(t, f)
		cs := connect(t, a, o)
		ctx := context.Background()

		tools, err := cs.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, tl := range tools.Tools {
			raw, _ := json.Marshal(tl)
			if strings.Contains(strings.ToLower(string(raw)), "security_explain") || strings.Contains(strings.ToLower(string(raw)), "security explain") {
				t.Errorf("%+v: tool %s names the explanation: %s", o, tl.Name, raw)
			}
			if tl.Name == "security_explain" {
				t.Errorf("%+v: the explanation is advertised as a tool", o)
			}
		}
		// Calling it by name is an error of the protocol, not a result.
		for _, name := range []string{"security_explain", "security-explain", "explain", "SECURITY_EXPLAIN"} {
			if res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: map[string]any{}}); err == nil {
				t.Errorf("%+v: calling %s did not fail: %+v", o, name, res)
			}
		}
		// The security_scan tool does not take it either, whatever it is given.
		if res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "security_scan", Arguments: map[string]any{"scope": "local", "explain": true, "only": []string{"network-1"}}}); err == nil && !res.IsError {
			t.Errorf("%+v: security_scan took an argument that selects an explanation: %+v", o, res)
		}

		resources, err := cs.ListResources(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range resources.Resources {
			if strings.Contains(strings.ToLower(r.URI+r.Name+r.Description), "explain") {
				t.Errorf("%+v: resource %s names the explanation", o, r.URI)
			}
		}
		for _, uri := range []string{"tailnet://security/explain", "tailnet://explain", "tailkeeper://security/explain"} {
			if _, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri}); err == nil {
				t.Errorf("%+v: resource %s was read", o, uri)
			}
		}
		prompts, err := cs.ListPrompts(ctx, nil)
		if err == nil {
			for _, p := range prompts.Prompts {
				if strings.Contains(strings.ToLower(p.Name+p.Description), "explain") {
					t.Errorf("%+v: prompt %s names the explanation", o, p.Name)
				}
			}
			if _, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: "security_explain"}); err == nil {
				t.Errorf("%+v: a prompt of that name was served", o)
			}
		}
	}
}

// The budget of the tool list is the one it was before the command existed: the command adds no
// tool definition to it.
func TestExplainLeavesTheToolListBudgetAlone(t *testing.T) {
	if toolListBudget != 111528 {
		t.Errorf("toolListBudget = %d; it was 111528 before security explain, which adds no tool to the list", toolListBudget)
	}
	total, sizes := definitionSizes(t)
	if _, ok := sizes["security_explain"]; ok {
		t.Error("the sizes of the tool list include security_explain")
	}
	if p := budgetProblem(total, toolListBudget, sizes); p != "" {
		t.Error(p)
	}
}
