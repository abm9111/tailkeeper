package registry

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// The limits are inclusive and count characters, not bytes: a title of exactly
// 80 characters and a reason of exactly 200 are accepted, in any script.
func TestTitleAndReasonLimitsAreInclusiveAndCountCharacters(t *testing.T) {
	for name, title := range map[string]string{
		"80 ASCII characters":      strings.Repeat("t", 80),
		"80 two-byte characters":   strings.Repeat("\u00e9", 80),
		"80 three-byte characters": strings.Repeat("\u4e2d", 80),
	} {
		m := readMeta("echo_get", "echo", "get")
		m.Title = title
		if err := New().Add(echoTool(m)); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	over := readMeta("echo_get", "echo", "get")
	over.Title = strings.Repeat("\u00e9", 81)
	if err := New().Add(echoTool(over)); err == nil || !strings.Contains(err.Error(), "title is longer than 80") {
		t.Errorf("81 characters: %v", err)
	}
	for name, reason := range map[string]string{
		"200 ASCII characters":      strings.Repeat("r", 200),
		"200 three-byte characters": strings.Repeat("\u4e2d", 200),
	} {
		m := readMeta("echo_get", "echo", "get")
		m.OptionalScopes = []OptionalScope{{Scope: "users:read", Reason: reason}}
		if err := New().Add(echoTool(m)); err != nil {
			t.Errorf("a reason of %s was refused: %v", name, err)
		}
	}
	m := readMeta("echo_get", "echo", "get")
	m.OptionalScopes = []OptionalScope{{Scope: "users:read", Reason: strings.Repeat("\u4e2d", 201)}}
	if err := New().Add(echoTool(m)); err == nil || !strings.Contains(err.Error(), "reason is longer than 200") {
		t.Errorf("201 characters: %v", err)
	}
}

// A call with no arguments at all is a call with none: absent, empty, blank and
// null all decode to {}, and anything else that is not an object is refused.
func TestValidateReadsAbsentArgumentsAsNone(t *testing.T) {
	type noArgs struct{}
	tool := Define(readMeta("none_get", "none", "get"), func(context.Context, *Env, noArgs) (checkedOut, error) {
		return checkedOut{}, nil
	})
	for name, raw := range map[string]json.RawMessage{
		"nil":        nil,
		"empty":      json.RawMessage(``),
		"blank":      json.RawMessage(" \n\t "),
		"null":       json.RawMessage(`null`),
		"padded":     json.RawMessage(" null\n"),
		"empty obj":  json.RawMessage(`{}`),
		"spaced obj": json.RawMessage(` { } `),
	} {
		if p, err := tool.Validate(raw); err != nil || p == nil {
			t.Errorf("%s: Validate = %v, %v, want it accepted", name, p, err)
		}
	}
	for name, raw := range map[string]json.RawMessage{
		"a number":   json.RawMessage(`5`),
		"a digit":    json.RawMessage(`7`),
		"an array":   json.RawMessage(`[]`),
		"a string":   json.RawMessage(`"x"`),
		"true":       json.RawMessage(`true`),
		"one letter": json.RawMessage(`x`),
		"nulll":      json.RawMessage(`nulll`),
	} {
		p, err := tool.Validate(raw)
		if e, ok := tkerr.As(err); p != nil || !ok || e.Code != tkerr.ValidationFailed {
			t.Errorf("%s: Validate = %v, %v, want validation_failed", name, p, err)
		}
	}
}
