package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

type formatClash struct {
	Format string `json:"format,omitempty"`
}
type quietClash struct {
	Quiet bool `json:"quiet,omitempty"`
}
type failOnClash struct {
	FailOn string `json:"failOn,omitempty"`
}
type jsonClash struct {
	JSON bool `json:"json,omitempty"`
}
type contextClash struct {
	Context string `json:"context,omitempty"`
}
type sameFlagTwice struct {
	A string `json:"a-b,omitempty"`
	B string `json:"aB,omitempty"`
}

func defineClash[I, O any](area string, out O) registry.Tool {
	return registry.Define(surfaceMeta(area), func(context.Context, *registry.Env, I) (O, error) { return out, nil })
}

// An input field whose flag the command line registers itself (--json, --context,
// and --format, --quiet and --fail-on where the result offers them) is a defect of
// the tool, reported as an internal error that names the field and the flag; it
// does not panic, and it does not run the tool.
func TestAnInputFieldThatTakesAFlagTheCommandLineRegistersIsAnInternalError(t *testing.T) {
	for _, c := range []struct {
		flag, field string
		tool        registry.Tool
	}{
		{"format", "Format", defineClash[formatClash]("clash", reportedOnlyOut{Name: "r"})},
		{"quiet", "Quiet", defineClash[quietClash]("clash", codedOnlyOut{Name: "c"})},
		{"fail-on", "FailOn", defineClash[failOnClash]("clash", gatedOnlyOut{Name: "g"})},
		{"json", "JSON", defineClash[jsonClash]("clash", plainOut{Name: "p"})},
		{"context", "Context", defineClash[contextClash]("clash", plainOut{Name: "p"})},
		{"a-b", "B", defineClash[sameFlagTwice]("clash", plainOut{Name: "p"})},
	} {
		h := newHarness(t, nil)
		reg := registry.New()
		reg.MustAdd(c.tool)
		h.r.Registry = func() *registry.Registry { return reg }
		code := h.run("clash", "check")
		if want := tkerr.ExitCode(tkerr.New(tkerr.Internal, "", "")); code != want || h.out.Len() != 0 ||
			!strings.Contains(h.err.String(), "internal_error") ||
			!strings.Contains(h.err.String(), "input field "+c.field+": flag --"+c.flag+" is already taken") {
			t.Errorf("%s: exit %d (want %d), stdout %q, stderr %q", c.flag, code, want, h.out, h.err)
		}
	}
}

// A defect of the tool that the command line finds while it builds the flags is an
// error like any other: --json placed after the command shapes it as it does for a
// refusal later on.
func TestTheFlagClashErrorIsJSONWhereverTheSwitchIs(t *testing.T) {
	for _, args := range [][]string{{"--json", "clash", "check"}, {"clash", "check", "--json"}, {"clash", "check", "--format", "json"}, {"clash", "check", "--json=true"}} {
		h := newHarness(t, nil)
		reg := registry.New()
		reg.MustAdd(defineClash[formatClash]("clash", reportedOnlyOut{Name: "r"}))
		h.r.Registry = func() *registry.Registry { return reg }
		code := h.run(args...)
		var e struct {
			Error struct{ Code, Message string }
		}
		if want := tkerr.ExitCode(tkerr.New(tkerr.Internal, "", "")); code != want || h.err.Len() != 0 ||
			json.Unmarshal(h.out.Bytes(), &e) != nil || e.Error.Code != string(tkerr.Internal) ||
			!strings.Contains(e.Error.Message, "flag --format is already taken") {
			t.Errorf("%v: exit %d (want %d), stdout %q, stderr %q", args, code, want, h.out, h.err)
		}
	}
}
