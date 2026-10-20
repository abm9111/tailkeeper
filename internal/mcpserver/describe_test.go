package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

type titledIn struct {
	Name string `json:"name"`
}

func titledTool(m registry.Meta) registry.Tool {
	return registry.Define(m, func(context.Context, *registry.Env, titledIn) (struct{}, error) { return struct{}{}, nil })
}

func TestDescribeCarriesTitleOpenWorldAndOptionalScopes(t *testing.T) {
	m := registry.Meta{Name: "doc_send", Area: "doc", Verb: "send", Summary: "Send a document.", Tier: registry.TierRead, Stage: registry.StageGA,
		Credential: registry.CredRead, Scopes: []string{"policy_file:read"}, Title: "Send a document to Tailscale", OpenWorld: true,
		OptionalScopes: []registry.OptionalScope{{Scope: "users:read", Reason: "resolve a pseudonym"}}}
	tool, err := Describe(titledTool(m))
	if err != nil {
		t.Fatal(err)
	}
	if tool.Title != m.Title {
		t.Errorf("Title = %q, want %q", tool.Title, m.Title)
	}
	if h := tool.Annotations.OpenWorldHint; h == nil || !*h {
		t.Errorf("OpenWorldHint = %v, want true", h)
	}
	for _, want := range []string{"OAuth scopes: policy_file:read.", "Optional OAuth scopes: users:read (resolve a pseudonym).", "The input you supply is sent to Tailscale."} {
		if !strings.Contains(tool.Description, want) {
			t.Errorf("description %q lacks %q", tool.Description, want)
		}
	}
	// A tool that sends nothing keeps the closed-world hint and none of the sentences.
	m.OpenWorld, m.Title, m.OptionalScopes = false, "", nil
	m.Name, m.Verb = "doc_read", "read"
	tool, err = Describe(titledTool(m))
	if err != nil {
		t.Fatal(err)
	}
	if h := tool.Annotations.OpenWorldHint; h == nil || *h || tool.Title != "" ||
		strings.Contains(tool.Description, "sent to Tailscale") || strings.Contains(tool.Description, "Optional OAuth scopes") {
		t.Errorf("closed tool: OpenWorldHint %v, title %q, description %q", h, tool.Title, tool.Description)
	}
}

// acl_test sends the test to Tailscale for evaluation (POST .../acl/validate), so
// it is the one open-world tool of 0.5.0's 43.
func TestOnlyACLTestIsOpenWorld(t *testing.T) {
	reg := registry.New()
	tools.Register(reg)
	var open []string
	for _, tl := range reg.All() {
		d, err := Describe(tl)
		if err != nil {
			t.Fatal(err)
		}
		if h := d.Annotations.OpenWorldHint; h == nil {
			t.Errorf("%s: OpenWorldHint is unset, and MCP reads an unset hint as true", tl.Meta.Name)
		} else if *h {
			open = append(open, tl.Meta.Name)
		}
	}
	if strings.Join(open, ",") != "acl_test" {
		t.Errorf("open-world tools = %v, want [acl_test]", open)
	}
}
