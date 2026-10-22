package docsgen

import (
	"context"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/openapi"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

type oddIn struct {
	X string `json:"x" jsonschema:"one|two\\three\nfour"`
}

func TestCellsEscapeTableSyntax(t *testing.T) {
	reg := registry.New()
	reg.MustAdd(registry.Define(registry.Meta{Name: "odd_get", Area: "odd", Verb: "get", Summary: "s", Tier: registry.TierRead,
		Stage: registry.StageGA, Credential: registry.CredRead, Scopes: []string{"devices:core:read"}},
		func(context.Context, *registry.Env, oddIn) (struct{}, error) { return struct{}{}, nil }))
	if md := Markdown(reg); !strings.Contains(md, "| `x` | string | yes | one\\|two\\\\three four |\n") {
		t.Errorf("markdown:\n%s", md)
	}
}

func TestMarkdownCoversEveryTool(t *testing.T) {
	reg := registry.New()
	tools.Register(reg)
	md := Markdown(reg)
	for _, tool := range reg.All() {
		if !strings.Contains(md, "### `"+tool.Meta.Name+"`") {
			t.Errorf("%s missing", tool.Meta.Name)
		}
	}
	for _, want := range []string{
		"45 tools.",
		"- CLI: `tailkeeper devices list`",
		"| `staleDays` | integer |  | only devices not connected",
		"| `device` | string | yes |",
		"| `tags` | string[] |",
		"- Untrusted output fields: `devices[].advertisedRoutes`, `devices[].clientVersion`, `devices[].connectivity.preferredDerp`, `devices[].distro`",
		"- Masked whole unless `personalData` is `show`: `devices[].user`",
		"- Untrusted but never masked (configuration): `devices[].advertisedRoutes`, `devices[].enabledRoutes`",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	if Markdown(reg) != md {
		t.Error("output is not deterministic")
	}
}

func TestEveryRequiredOperationIsCalledOrSkipped(t *testing.T) {
	reg := registry.New()
	tools.Register(reg)
	rows, problems := Coverage(reg)
	for _, p := range problems {
		t.Error(p)
	}
	if len(rows) < 30 {
		t.Fatalf("only %d rows: the operation list did not load", len(rows))
	}
}

func TestCoverageReportsGaps(t *testing.T) {
	reg := registry.New()
	reg.MustAdd(registry.Define(registry.Meta{Name: "odd_get", Area: "odd", Verb: "get", Summary: "s", Tier: registry.TierRead,
		Stage: registry.StageGA, Credential: registry.CredRead, Scopes: []string{"devices:core:read"},
		Operations: []string{"GET /no/such/path"}},
		func(context.Context, *registry.Env, oddIn) (struct{}, error) { return struct{}{}, nil }))
	reg.MustAdd(registry.Define(registry.Meta{Name: "bare_get", Area: "bare", Verb: "get", Summary: "s", Tier: registry.TierRead,
		Stage: registry.StageGA, Credential: registry.CredRead, Scopes: []string{"devices:core:read"}},
		func(context.Context, *registry.Env, oddIn) (struct{}, error) { return struct{}{}, nil }))
	_, problems := Coverage(reg)
	all := strings.Join(problems, "\n")
	for _, want := range []string{"odd_get declares GET /no/such/path", "bare_get declares no operation",
		"GET /tailnet/{tailnet}/devices is neither called by a tool nor skipped"} {
		if !strings.Contains(all, want) {
			t.Errorf("problems lack %q:\n%s", want, all)
		}
	}
	if md := Markdown(reg); !strings.Contains(md, "## API coverage") || !strings.Contains(md, "**Problem:**") {
		t.Error("the docs must show the map and its problems")
	}
}

// An operation the map says no tool calls cannot also have a caller: declaring
// one is the other way the map goes wrong, and it is reported with the caller.
func TestCoverageReportsACalledOperationThatIsAlsoSkipped(t *testing.T) {
	const skipped = "GET /organizations/{organization}/tailnets"
	if openapi.Skipped[skipped] == "" || !openapi.Required(skipped) {
		t.Fatalf("%s is no longer a skipped, required operation: pick another for this test", skipped)
	}
	reg := registry.New()
	reg.MustAdd(registry.Define(registry.Meta{Name: "org_get", Area: "org", Verb: "get", Summary: "s", Tier: registry.TierRead,
		Stage: registry.StageGA, Credential: registry.CredRead, Scopes: []string{"devices:core:read"},
		Operations: []string{skipped}},
		func(context.Context, *registry.Env, oddIn) (struct{}, error) { return struct{}{}, nil }))
	rows, problems := Coverage(reg)
	if all := strings.Join(problems, "\n"); !strings.Contains(all, skipped+" is called by org_get and also skipped") {
		t.Errorf("problems lack the called-and-skipped report:\n%s", all)
	}
	for _, r := range rows {
		if r.Operation == skipped && (len(r.Tools) != 1 || r.Skip == "") {
			t.Errorf("row = %+v, want the caller and the skip reason both shown", r)
		}
	}
}
