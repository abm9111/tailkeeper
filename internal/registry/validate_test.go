package registry

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// checkedIn refuses a negative max from its own fields, the way an input type
// with a Check method does. Extra is not in the JSON: the CLI fills a field like
// it after Validate.
type checkedIn struct {
	Name  string `json:"name" jsonschema:"a name"`
	Max   int    `json:"max,omitempty"`
	Extra string `json:"-"`
}

func (c checkedIn) Check() error {
	if c.Max < 0 {
		return tkerr.New(tkerr.ValidationFailed, "max must not be negative, got "+c.Name, "")
	}
	return nil
}

type checkedOut struct {
	Name  string `json:"name" tk:"untrusted"`
	Extra string `json:"extra"`
}

// checkedTool counts its runs: a Validate that fails must leave the count at 0.
func checkedTool(m Meta, ran *int) Tool {
	return Define(m, func(_ context.Context, _ *Env, in checkedIn) (checkedOut, error) {
		*ran++
		return checkedOut{Name: in.Name, Extra: in.Extra}, nil
	})
}

func TestValidateRefusesBeforeAnythingRuns(t *testing.T) {
	ran := 0
	tool := checkedTool(readMeta("check_get", "check", "get"), &ran)
	for name, raw := range map[string]string{
		"not json":      `not json`,
		"missing name":  `{"max":1}`,
		"unknown field": `{"name":"x","extra":"y"}`,
		"wrong type":    `{"name":5}`,
		"a Check fails": `{"name":"x","max":-1}`,
	} {
		p, err := tool.Validate(json.RawMessage(raw))
		if e, ok := tkerr.As(err); p != nil || !ok || e.Code != tkerr.ValidationFailed {
			t.Errorf("%s: p = %v, err = %v, want validation_failed and no Prepared", name, p, err)
		}
	}
	if ran != 0 {
		t.Errorf("the tool ran %d times for input Validate refused", ran)
	}
}

// Validate has no Env: its errors are masked as if masking were on, since the
// owner's personalData setting is not loaded yet. An address the caller typed
// comes back cut.
func TestValidateErrorsAreMasked(t *testing.T) {
	tool := checkedTool(readMeta("check_get", "check", "get"), new(int))
	_, err := tool.Validate(json.RawMessage(`{"name":"amy@example.com","max":-1}`))
	e := tkerr.From(err)
	if e == nil || strings.Contains(e.Message, "amy@") || !strings.Contains(e.Message, "a…@example.com") {
		t.Errorf("err = %v, want the address masked", err)
	}
}

func TestPreparedRunsWhatValidateChecked(t *testing.T) {
	ran := 0
	tool := checkedTool(readMeta("check_get", "check", "get"), &ran)
	p, err := tool.Validate(json.RawMessage(`{"name":"a\nb","max":2}`))
	if err != nil {
		t.Fatal(err)
	}
	// The CLI sets the fields that are not in the JSON through Input.
	p.Input().(*checkedIn).Extra = "from a file"
	out, err := p.Run(context.Background(), &Env{})
	if err != nil {
		t.Fatal(err)
	}
	if got := out.(checkedOut); got.Name != `a\u{000A}b` || got.Extra != "from a file" || ran != 1 {
		t.Errorf("out = %+v after %d runs", got, ran)
	}
	// Call is Validate then Run: the same answer.
	again, err := tool.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"a\nb","max":2}`))
	if err != nil || again.(checkedOut).Name != `a\u{000A}b` || again.(checkedOut).Extra != "" || ran != 2 {
		t.Errorf("Call = %+v, %v after %d runs", again, err, ran)
	}
	if p.Tool().Meta.Name != "check_get" {
		t.Errorf("Tool().Meta.Name = %q", p.Tool().Meta.Name)
	}
}

type panickyIn struct {
	Name string `json:"name"`
}

func (panickyIn) Check() error { panic("check-payload-must-not-surface") }

func TestAPanickingCheckBecomesAnInternalError(t *testing.T) {
	tool := Define(readMeta("panic_get", "panic", "get"), func(context.Context, *Env, panickyIn) (checkedOut, error) {
		return checkedOut{}, nil
	})
	p, err := tool.Validate(json.RawMessage(`{"name":"x"}`))
	if e, ok := tkerr.As(err); p != nil || !ok || e.Code != tkerr.Internal || strings.Contains(err.Error(), "check-payload") {
		t.Errorf("p = %v, err = %v", p, err)
	}
	if _, err := tool.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"x"}`)); tkerr.From(err).Code != tkerr.Internal {
		t.Errorf("Call: err = %v, want internal_error", err)
	}
}

type offlineIn struct {
	Name string `json:"name"`
}

// RunsOffline reads the CLI sources the command line set: a file given for each
// side needs no credential.
func (offlineIn) RunsOffline(g Given) bool { return g["offline"] || g["from"] && g["against"] }

func TestNeedsCredential(t *testing.T) {
	run := func(context.Context, *Env, offlineIn) (checkedOut, error) { return checkedOut{}, nil }
	optional := readMeta("opt_get", "opt", "get")
	optional.Credential = CredOptional
	local := Meta{Name: "loc_get", Area: "loc", Verb: "get", Summary: "s", Tier: TierLocal, Stage: StageGA, Credential: CredNone}
	for _, c := range []struct {
		name string
		meta Meta
		g    Given
		want bool
	}{
		{"read tool", readMeta("rd_get", "rd", "get"), nil, true},
		{"read tool, offline flag", readMeta("rd_get", "rd", "get"), Given{"offline": true}, true},
		{"local tool", local, nil, false},
		{"optional, nothing given", optional, nil, true},
		{"optional, --offline", optional, Given{"offline": true}, false},
		{"optional, both sides files", optional, Given{"from": true, "against": true}, false},
		{"optional, one side a file", optional, Given{"from": true}, true},
	} {
		p, err := Define(c.meta, run).Validate(json.RawMessage(`{"name":"x"}`))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := p.NeedsCredential(c.g); got != c.want {
			t.Errorf("%s: NeedsCredential = %v, want %v", c.name, got, c.want)
		}
	}
	// An optional tool whose input cannot say it runs offline needs the credential.
	p, _ := Define(optional, func(context.Context, *Env, echoIn) (echoOut, error) { return echoOut{}, nil }).
		Validate(json.RawMessage(`{"name":"x"}`))
	if !p.NeedsCredential(Given{"offline": true}) {
		t.Error("an input without RunsOffline was taken to run offline")
	}
}

func TestAddChecksTheCredentialMode(t *testing.T) {
	optional := readMeta("opt_get", "opt", "get")
	optional.Credential = CredOptional
	if err := New().Add(echoTool(optional)); err != nil {
		t.Errorf("an optional-credential read tool with scopes was refused: %v", err)
	}
	noScopes := optional
	noScopes.Scopes = nil
	if err := New().Add(echoTool(noScopes)); err == nil || !strings.Contains(err.Error(), "declare scopes") {
		t.Errorf("optional credential without scopes: %v", err)
	}
	local := Meta{Name: "loc_get", Area: "loc", Verb: "get", Summary: "s", Tier: TierLocal, Stage: StageGA, Credential: CredOptional}
	if err := New().Add(echoTool(local)); err == nil || !strings.Contains(err.Error(), "no credential") {
		t.Errorf("optional credential on a local tool: %v", err)
	}
}
