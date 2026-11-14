package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

type cappedOut struct {
	Name      string   `json:"name" tk:"untrusted"`
	Tags      []string `json:"tags" tk:"untrusted"`
	Untrusted string   `json:"untrusted" tk:"untrusted,emails"`
	Plain     string   `json:"plain"`
}

// The cap on one untrusted string of a result is 1,024 bytes, end to end: through Call, which
// is what a client sees, and not only through the Display the cap is applied in. A string
// of exactly the cap is shown whole, one byte more is cut to the cap with the notice, and a
// string that no tag marks is escaped and never cut.
func TestAResultShowsAtMost1024BytesOfAnUntrustedString(t *testing.T) {
	if ResultStringMax != 1024 {
		t.Fatalf("ResultStringMax = %d, want the 1,024 bytes SECURITY.md promises", ResultStringMax)
	}
	const notice = "...[truncated]"
	exact := strings.Repeat("n", ResultStringMax)
	over := strings.Repeat("n", ResultStringMax+1)
	huge := strings.Repeat("h", 100<<10)
	tool := Define(readMeta("echo_capped", "echo", "capped"), func(context.Context, *Env, echoIn) (cappedOut, error) {
		return cappedOut{Name: over, Tags: []string{exact, huge}, Untrusted: huge, Plain: huge}, nil
	})
	out, err := tool.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	got := out.(cappedOut)
	capped := strings.Repeat("n", ResultStringMax-len(notice)) + notice
	if got.Name != capped {
		t.Errorf("a string one byte over the cap: %d bytes, %.60q...%q, want %d bytes ending in the notice", len(got.Name), got.Name, lastBytes(got.Name, 20), ResultStringMax)
	}
	if got.Tags[0] != exact {
		t.Errorf("a string of exactly the cap was changed: %d bytes", len(got.Tags[0]))
	}
	for name, s := range map[string]string{"a list element": got.Tags[1], "an emails field": got.Untrusted} {
		if len(s) > ResultStringMax || !strings.HasSuffix(s, notice) {
			t.Errorf("%s: %d bytes ending %q, want at most %d bytes ending in the notice", name, len(s), lastBytes(s, 20), ResultStringMax)
		}
	}
	if got.Plain != huge {
		t.Errorf("an untagged string was cut to %d bytes: the cap is for untrusted text", len(got.Plain))
	}
}

// An error is capped like an untrusted string: its message and its hint hold at most 1,024
// bytes each however much text a server put in them.
func TestAnErrorShowsAtMost1024BytesOfItsMessageAndHint(t *testing.T) {
	huge := strings.Repeat("m", 100<<10)
	tool := Define(readMeta("echo_cappederr", "echo", "cappederr"), func(context.Context, *Env, echoIn) (echoOut, error) {
		return echoOut{}, tkerr.New(tkerr.APIError, huge, huge)
	})
	_, err := tool.Call(context.Background(), &Env{}, json.RawMessage(`{"name":"x"}`))
	e := tkerr.From(err)
	if e == nil || e.Code != tkerr.APIError {
		t.Fatalf("err = %v, want the api_error back", err)
	}
	for name, s := range map[string]string{"message": e.Message, "hint": e.Hint} {
		if len(s) != ResultStringMax || !strings.HasSuffix(s, "...[truncated]") {
			t.Errorf("%s is %d bytes, want %d ending in the notice", name, len(s), ResultStringMax)
		}
	}
}

// Define refuses an output type that holds an interface, in a field, a slice, a pointer or a
// map, so that the walk over a result never meets a shape that UntrustedPaths has not
// checked: a value in an interface could hold text the walk would not escape. The refusal is
// a panic at registration, so a tool with such an output type cannot be built.
func TestDefinePanicsForAnOutputTypeThatHoldsAnInterface(t *testing.T) {
	type anyField struct {
		Name string `json:"name" tk:"untrusted"`
		V    any    `json:"v"`
	}
	type anySlice struct {
		Rows []any `json:"rows"`
	}
	type anyPointer struct {
		V *any `json:"v"`
	}
	type anyMap struct {
		M map[string]any `json:"m"`
	}
	type anyNested struct {
		Rows []struct {
			V any `json:"v"`
		} `json:"rows"`
	}
	m := readMeta("echo_any", "echo", "any")
	for name, define := range map[string]func(){
		"a field": func() { Define(m, func(context.Context, *Env, echoIn) (anyField, error) { return anyField{}, nil }) },
		"a slice": func() { Define(m, func(context.Context, *Env, echoIn) (anySlice, error) { return anySlice{}, nil }) },
		"a pointer": func() {
			Define(m, func(context.Context, *Env, echoIn) (anyPointer, error) { return anyPointer{}, nil })
		},
		"a map":           func() { Define(m, func(context.Context, *Env, echoIn) (anyMap, error) { return anyMap{}, nil }) },
		"a nested struct": func() { Define(m, func(context.Context, *Env, echoIn) (anyNested, error) { return anyNested{}, nil }) },
	} {
		func() {
			defer func() {
				p := recover()
				if p == nil {
					t.Errorf("Define accepted an output type with an interface in %s", name)
					return
				}
				if msg := fmt.Sprint(p); !strings.Contains(msg, "sanitize: output field") {
					t.Errorf("%s: Define panicked with %q, want the sanitizer's refusal of the shape", name, msg)
				}
			}()
			define()
		}()
	}
	// The control: a type of the same shape without the interface is accepted, so the panics
	// above are the interface's.
	type scalarField struct {
		Name string `json:"name" tk:"untrusted"`
		V    string `json:"v"`
	}
	if tool := Define(m, func(context.Context, *Env, echoIn) (scalarField, error) { return scalarField{}, nil }); tool.Meta.Name != "echo_any" {
		t.Errorf("Define built %q", tool.Meta.Name)
	}
}

// lastBytes is the end of s, at most n bytes, for a failure message: a failing string
// shorter than n must still print rather than panic.
func lastBytes(s string, n int) string { return s[max(len(s)-n, 0):] }
