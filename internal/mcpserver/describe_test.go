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

// acl_test and acl_validate send what the caller gave them to Tailscale (POST
// .../acl/validate), so they are the open-world tools.
func TestOnlyACLTestAndACLValidateAreOpenWorld(t *testing.T) {
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
	if strings.Join(open, ",") != "acl_test,acl_validate" {
		t.Errorf("open-world tools = %v, want [acl_test acl_validate]", open)
	}
}

// acl_test's description says the text goes to Tailscale, and it no longer says that
// a masked value cannot be tested at all: a user is named by the pseudonym users_list
// shows, which is the same sentence the server instructions use.
func TestACLTestIsOpenWorldAndItsDescriptionAgreesWithTheInstructions(t *testing.T) {
	const sentence = "A user is named by the pseudonym from users_list; a masked value with no pseudonym cannot be tested."
	if !strings.Contains(Instructions, sentence) {
		t.Errorf("Instructions lack %q", sentence)
	}
	reg := registry.New()
	tools.Register(reg)
	tool, ok := reg.Get("acl_test")
	if !ok {
		t.Fatal("acl_test is not registered")
	}
	if !tool.Meta.OpenWorld || tool.Meta.Title == "" {
		t.Errorf("open-world %v, title %q", tool.Meta.OpenWorld, tool.Meta.Title)
	}
	if !strings.Contains(tool.Meta.Notes, sentence) {
		t.Errorf("notes lack %q: %s", sentence, tool.Meta.Notes)
	}
	d, err := Describe(tool)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Description, "sent to Tailscale") {
		t.Errorf("description does not say the text goes to Tailscale: %s", d.Description)
	}
	if strings.Contains(d.Description, "A masked value (one with …) cannot be tested") {
		t.Errorf("description still says a masked value cannot be tested: %s", d.Description)
	}
}
