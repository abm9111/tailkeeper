package registry

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"
)

// The framework names the call: the tool that runs, a new identifier for each run, and the
// caller the surface set on the context. The input of the tool has no part in it.
func TestRunNamesTheCallFromTheFramework(t *testing.T) {
	type in struct {
		Caller string `json:"caller,omitempty"`
	}
	var seen []Call
	tool := Define(Meta{Name: "probe_call", Area: "probe", Verb: "call", Summary: "probe"},
		func(ctx context.Context, _ *Env, _ in) (struct{}, error) {
			seen = append(seen, CallOf(ctx))
			return struct{}{}, nil
		})
	if CallOf(context.Background()) != (Call{}) {
		t.Fatal("a context outside a tool call has a call")
	}
	who := Caller{Kind: "cli", Client: "x"}
	for _, ctx := range []context.Context{WithCaller(context.Background(), who), context.Background()} {
		if _, err := tool.Call(ctx, &Env{}, json.RawMessage(`{"caller":"EVIL"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 2 || seen[0].Tool != "probe_call" || seen[0].Caller != who || seen[1].Caller != (Caller{}) {
		t.Fatalf("calls = %+v", seen)
	}
	id := regexp.MustCompile(`^[0-9a-f]{16}$`)
	if !id.MatchString(seen[0].ID) || !id.MatchString(seen[1].ID) || seen[0].ID == seen[1].ID {
		t.Errorf("identifiers = %q, %q", seen[0].ID, seen[1].ID)
	}
}

// The surface learns the identifier of the call it ran, to put it on the audit line of the
// read: CallWithID and Prepared.CallID give the one the tool itself saw, and a call that
// never ran (its arguments were refused) has none.
func TestTheSurfaceCanReadTheIdentifierOfTheCallItRan(t *testing.T) {
	var seen []string
	tool := Define(Meta{Name: "probe_id", Area: "probe", Verb: "id", Summary: "probe"},
		func(ctx context.Context, _ *Env, _ struct{}) (struct{}, error) {
			seen = append(seen, CallOf(ctx).ID)
			return struct{}{}, nil
		})
	p, err := tool.Validate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.CallID() != "" {
		t.Errorf("a call that has not run has the identifier %q", p.CallID())
	}
	if _, err := p.Run(context.Background(), &Env{}); err != nil {
		t.Fatal(err)
	}
	id := regexp.MustCompile(`^[0-9a-f]{16}$`)
	if !id.MatchString(p.CallID()) || len(seen) != 1 || p.CallID() != seen[0] {
		t.Errorf("Prepared.CallID() = %q, the tool saw %v", p.CallID(), seen)
	}
	_, got, err := tool.CallWithID(context.Background(), &Env{}, nil)
	if err != nil || !id.MatchString(got) || len(seen) != 2 || got != seen[1] || got == p.CallID() {
		t.Errorf("CallWithID = %q, %v; the tool saw %v", got, err, seen)
	}
	// Arguments the schema refuses never reach the tool: no call, no identifier.
	if _, got, err := tool.CallWithID(context.Background(), &Env{}, json.RawMessage(`{"extra":1}`)); err == nil || got != "" || len(seen) != 2 {
		t.Errorf("a refused call: id %q, error %v, tool saw %v", got, err, seen)
	}
}
