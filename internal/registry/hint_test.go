package registry

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// An error raised without a hint of its own carries the generic hint of its code,
// so every error a program receives says what to do about it. A hint written where
// the error is raised wins.
func TestAnErrorWithoutAHintGetsTheProgramHint(t *testing.T) {
	fail := func(hint string) *tkerr.Error {
		tool := Define(readMeta("echo_fail", "echo", "fail"), func(context.Context, *Env, echoIn) (echoOut, error) {
			return echoOut{}, tkerr.New(tkerr.APIError, "upstream failed", hint)
		})
		_, err := tool.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"x"}`))
		return tkerr.From(err)
	}
	if e := fail(""); e.Hint != tkerr.ProgramHint(tkerr.APIError) || e.Hint == "" {
		t.Errorf("no hint: hint = %q, want the program hint", e.Hint)
	}
	if e := fail("its own hint"); e.Hint != "its own hint" {
		t.Errorf("own hint: hint = %q", e.Hint)
	}
	tool := echoTool(readMeta("echo_get", "echo", "get"))
	_, err := tool.Validate(json.RawMessage(`{"count":1}`))
	if e := tkerr.From(err); e.Code != tkerr.ValidationFailed || e.Hint != tkerr.ProgramHint(tkerr.ValidationFailed) {
		t.Errorf("a Validate error: %+v", e)
	}
}
