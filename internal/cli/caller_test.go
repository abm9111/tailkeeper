package cli

import (
	"context"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// The command line names itself as the caller of a tool it runs, for the records a tool's
// run makes against its call.
func TestTheCommandLineNamesItselfAsTheCaller(t *testing.T) {
	h := newHarness(t, nil)
	var got registry.Call
	reg := registry.New()
	reg.MustAdd(registry.Define(surfaceMeta("caller"), func(ctx context.Context, _ *registry.Env, _ surfaceIn) (plainOut, error) {
		got = registry.CallOf(ctx)
		return plainOut{Name: "c"}, nil
	}))
	h.r.Registry = func() *registry.Registry { return reg }
	if code := h.run("caller", "check", "--name", "EVIL"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.err)
	}
	if got.Tool != "caller_check" || got.Caller != (registry.Caller{Kind: "cli"}) || len(got.ID) != 16 {
		t.Errorf("call = %+v", got)
	}
}
