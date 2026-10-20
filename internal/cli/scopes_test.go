package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/docsgen"
)

// writeScopes prints an optional use after the tools that need the scope, with its
// reason, and the JSON gains optionalTools for that scope only.
func TestWriteScopesShowsOptionalUses(t *testing.T) {
	uses := []docsgen.ScopeUse{
		{Scope: "a:read", Tools: []string{"a_get"}},
		{Scope: "u:read", Tools: []string{}, OptionalTools: []docsgen.OptionalUse{{Tool: "a_get", Reason: "resolve a pseudonym"}}},
		{Scope: "v:read", Tools: []string{"v_get"}, PartialTools: []string{"w_get"}, OptionalTools: []docsgen.OptionalUse{{Tool: "x_get", Reason: "more"}}},
	}
	var text bytes.Buffer
	if err := writeScopes(&text, uses, false, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"a:read  a_get\n", "u:read  optionally: a_get (resolve a pseudonym)\n", "v:read  v_get; in part: w_get; optionally: x_get (more)\n"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, text.String())
		}
	}
	var js bytes.Buffer
	if err := writeScopes(&js, uses, false, true); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Scopes []map[string]any `json:"scopes"`
	}
	if err := json.Unmarshal(js.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Scopes[0]["optionalTools"]; ok {
		t.Errorf("a:read prints optionalTools: %v", got.Scopes[0])
	}
	opt, _ := got.Scopes[1]["optionalTools"].([]any)
	if len(opt) != 1 || opt[0].(map[string]any)["tool"] != "a_get" || opt[0].(map[string]any)["reason"] != "resolve a pseudonym" {
		t.Errorf("u:read optionalTools = %v", got.Scopes[1]["optionalTools"])
	}
}
