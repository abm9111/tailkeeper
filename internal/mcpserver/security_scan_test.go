package mcpserver

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// What a model can choose in a security scan is its scope and its threshold, and nothing else:
// no catalog, no path, no file, no URL, no update or sync switch, no destination, no
// expectation text. The test reads the definition the server advertises, which is what a
// model sees, and then tries to pass each of them anyway.
func TestMCPHasNoCatalogUpdateOrDestinationArguments(t *testing.T) {
	f := apitest.New(t)
	a := newApp(t, f)
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
		t.Fatal("security_scan is not advertised in the reads profile")
	}
	raw, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	props, _ := schema["properties"].(map[string]any)
	var names []string
	for k := range props {
		names = append(names, k)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "scope,threshold" {
		t.Errorf("the arguments are %v, want scope and threshold", names)
	}
	if schema["additionalProperties"] != false {
		t.Errorf("additionalProperties = %v: other arguments are not refused by the schema", schema["additionalProperties"])
	}
	// Every property of every nested object, whatever it is called, is a string or absent: no
	// object or array a model could put a catalog, a path or an expectation in.
	for name, p := range props {
		ty, _ := p.(map[string]any)["type"].(string)
		if ty != "string" {
			t.Errorf("argument %s has type %q", name, ty)
		}
	}
	suspect := regexp.MustCompile(`(?i)catalog|path|file|url|uri|dest|update|sync|expect|intent|invariant|endpoint|host|command|sink|webhook`)
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			if p, ok := x["properties"].(map[string]any); ok {
				for k := range p {
					if suspect.MatchString(k) {
						t.Errorf("the input schema has a property %s.%s", path, k)
					}
				}
			}
			for k, child := range x {
				walk(path+"."+k, child)
			}
		case []any:
			for _, child := range x {
				walk(path+"[]", child)
			}
		}
	}
	walk("$", schema)

	for _, args := range []map[string]any{
		{"scope": "fleet", "catalog": "/tmp/catalog.json"}, {"scope": "fleet", "catalogPath": "x"}, {"scope": "fleet", "path": "x"},
		{"scope": "fleet", "file": "x"}, {"scope": "fleet", "url": "https://example.com/advisories.json"}, {"scope": "fleet", "update": true},
		{"scope": "fleet", "sync": true}, {"scope": "fleet", "destination": "https://example.com/hook"}, {"scope": "fleet", "expect": "no device runs 1.0"},
		{"scope": "fleet", "intent": map[string]any{"network": []any{}}}, {"scope": "fleet", "invariants": "x"},
		{"scope": map[string]any{"catalog": "x"}}, {"scope": "fleet", "threshold": map[string]any{"path": "x"}},
	} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "security_scan", Arguments: args})
		if err != nil {
			t.Fatalf("%v: protocol error %v", args, err)
		}
		if !res.IsError {
			t.Errorf("%v was accepted", args)
			continue
		}
		if m, _ := res.StructuredContent.(map[string]any); m == nil || m["error"].(map[string]any)["code"] != "validation_failed" {
			t.Errorf("%v: %v", args, res.StructuredContent)
		}
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d API requests came of arguments that were refused", n)
	}
}

// What a model reads about the scan says what `complete` and exit 0 are relative to: the rules
// built into this binary (counted in catalog.rules), not Tailscale's advisories, and not a
// statement that the fleet is safe. Both the description and the status text say it.
func TestSecurityScanTextSaysCompleteIsRelativeToTheShippedCatalog(t *testing.T) {
	cs := connect(t, newApp(t, apitest.New(t)), Options{Profile: "reads"})
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
	raw, err := json.Marshal(tool.OutputSchema)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Properties map[string]struct {
			Description string `json:"description"`
			Properties  map[string]struct {
				Description string `json:"description"`
			} `json:"properties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"the tool description":   tool.Description,
		"the status schema text": out.Properties["status"].Description,
		"the catalog.rules text": out.Properties["catalog"].Properties["rules"].Description,
	} {
		lower := strings.ToLower(text)
		if !strings.Contains(lower, "relative to") || !strings.Contains(lower, "catalog") {
			t.Errorf("%s does not say that complete is relative to the shipped catalog: %q", name, text)
		}
	}
	for name, text := range map[string]string{"the tool description": tool.Description, "the status schema text": out.Properties["status"].Description} {
		if !strings.Contains(strings.ToLower(text), "safe") {
			t.Errorf("%s does not say that complete is not a statement that the fleet is safe: %q", name, text)
		}
	}
	if !strings.Contains(tool.Description, "catalog.rules") {
		t.Errorf("the description does not point at catalog.rules, where the rules are counted: %q", tool.Description)
	}
}
