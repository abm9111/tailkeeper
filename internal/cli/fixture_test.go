package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// fixtureIn is an input shaped like the policy tools' input: the proposal, a patch
// and the other side of a diff are text over MCP and files or standard input on the
// command line (the old and the new side also as the first and second argument), and
// the invariants, the offline switch and the operator mark exist on the command line
// only. It is the test tool through which the framework is tested; no real tool
// ships in this change.
type fixtureIn struct {
	Name         string `json:"name,omitempty" tk:"short" jsonschema:"a label echoed back"`
	Policy       string `json:"policy,omitempty" cli:"file:from,stdin,group=proposal,arg=2,as=NEW" jsonschema:"the proposed policy text"`
	Patch        string `json:"patch,omitempty" cli:"file:patch,stdin,group=proposal" jsonschema:"a JSON Patch against the live policy"`
	Against      string `json:"against,omitempty" cli:"file:against,stdin,live,arg=1,as=OLD" jsonschema:"the old side of a comparison; live when left out"`
	Invariants   string `json:"-" cli:"file:invariants" jsonschema:"invariants to check the proposal against"`
	NoInvariants bool   `json:"-" cli:"bool:no-invariants" jsonschema:"skip the configured invariants"`
	Offline      bool   `json:"-" cli:"bool:offline" jsonschema:"do not call the API"`
	Operator     bool   `json:"-" cli:"operator"`
}

// RunsOffline: --offline, or a file on each side of a comparison.
func (in fixtureIn) RunsOffline(g registry.Given) bool {
	return g["offline"] || g["from"] && g["against"]
}

// fixtureOut echoes what reached the tool, so a test can compare it with the file.
type fixtureOut struct {
	Name         string `json:"name" tk:"untrusted"`
	Policy       string `json:"policy" tk:"untrusted"`
	Patch        string `json:"patch" tk:"untrusted"`
	Against      string `json:"against" tk:"untrusted"`
	Invariants   string `json:"invariants" tk:"untrusted"`
	NoInvariants bool   `json:"noInvariants"`
	Offline      bool   `json:"offline"`
	Operator     bool   `json:"operator"`
}

// attrRule is one element of a list a JSON flag carries: the shape of an SSH test, a
// destination and the users it accepts.
type attrRule struct {
	Dst    []string `json:"dst"`
	Accept []string `json:"accept,omitempty"`
}

// attrIn is a map and a list of structs. MCP sends them as JSON properties; the command
// line sends the same JSON as the text of a flag. The tool reads no file, so the fields
// need no short tag. The flag name and the MCP name differ on purpose for the map.
type attrIn struct {
	Attrs map[string]any `json:"attrs,omitempty" cli:"json:device-attrs" jsonschema:"device attributes, key to value"`
	Rules []attrRule     `json:"rules,omitempty" cli:"json:rules" jsonschema:"rules echoed back"`
}

// attrOut echoes what reached the tool, and the Go type of each attribute, so a test can
// tell a number from a string.
type attrOut struct {
	Echo  string `json:"echo" tk:"untrusted"`
	Kinds string `json:"kinds" tk:"untrusted"`
}

// gateIn builds a typed result with the status and finding counts a test asks
// for: the shape acl_validate, acl_test and acl_diff results will have.
type gateIn struct {
	Status       string `json:"status" jsonschema:"pass, fail, invalid, unresolved or unknown"`
	NewWarnings  int    `json:"newWarnings,omitempty"`
	TestsReduced int    `json:"testsReduced,omitempty"`
	Defaults     int    `json:"defaults,omitempty"`
	Widenings    int    `json:"widenings,omitempty"`
	Changes      int    `json:"changes,omitempty"`
}

type gateOut struct {
	Status       string `json:"status"`
	NewWarnings  int    `json:"newWarnings"`
	TestsReduced int    `json:"testsReduced"`
	Defaults     int    `json:"defaults"`
	Widenings    int    `json:"widenings"`
	Changes      int    `json:"changes"`
}

// ExitCode comes from the verdict alone, never from message text: pass 0, unknown 1,
// invalid and unresolved 2, fail 9.
func (o gateOut) ExitCode() int {
	switch o.Status {
	case "fail":
		return 9
	case "invalid", "unresolved":
		return 2
	case "unknown":
		return 1
	}
	return 0
}

func (o gateOut) Findings() registry.Findings {
	return registry.Findings{NewWarnings: o.NewWarnings, TestsReduced: o.TestsReduced, Defaults: o.Defaults, Widenings: o.Widenings, Changes: o.Changes}
}

// partialOut is gateOut for a tool that computes four of the five kinds of finding:
// it never fills the count of new warnings, so a gate on warnings could never fire.
type partialOut gateOut

func (o partialOut) ExitCode() int { return gateOut(o).ExitCode() }
func (o partialOut) Findings() registry.Findings {
	f := gateOut(o).Findings()
	f.NewWarnings = 0
	return f
}

// FailOnKinds names the --fail-on tokens the tool computes.
func (partialOut) FailOnKinds() []string {
	return []string{"tests-reduced", "defaults", "widening", "change"}
}

// fixtureRegistry holds the test tools; ran counts the runs of fixture_check and attr_check.
func fixtureRegistry(ran *int) *registry.Registry {
	reg := registry.New()
	reg.MustAdd(registry.Define(registry.Meta{Name: "fixture_check", Area: "fixture", Verb: "check", Summary: "A test tool for the framework.",
		Tier: registry.TierRead, Stage: registry.StageGA, Credential: registry.CredOptional, Scopes: []string{"devices:core:read"}},
		func(_ context.Context, _ *registry.Env, in fixtureIn) (fixtureOut, error) {
			*ran++
			return fixtureOut(in), nil
		}))
	reg.MustAdd(registry.Define(registry.Meta{Name: "attr_check", Area: "attr", Verb: "check", Summary: "A test tool with a map and a list of structs as flags.",
		Tier: registry.TierRead, Stage: registry.StageGA, Credential: registry.CredOptional, Scopes: []string{"devices:core:read"}},
		func(_ context.Context, _ *registry.Env, in attrIn) (attrOut, error) {
			*ran++
			echo, err := json.Marshal(in)
			if err != nil {
				return attrOut{}, err
			}
			keys := make([]string, 0, len(in.Attrs))
			for k := range in.Attrs {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			kinds := make([]string, len(keys))
			for i, k := range keys {
				kinds[i] = fmt.Sprintf("%s=%T", k, in.Attrs[k])
			}
			return attrOut{Echo: string(echo), Kinds: strings.Join(kinds, ",")}, nil
		}))
	reg.MustAdd(registry.Define(registry.Meta{Name: "gate_check", Area: "gate", Verb: "check", Summary: "A test tool whose result can be gated.",
		Tier: registry.TierLocal, Stage: registry.StageGA, Credential: registry.CredNone},
		func(_ context.Context, _ *registry.Env, in gateIn) (gateOut, error) { return gateOut(in), nil }))
	reg.MustAdd(registry.Define(registry.Meta{Name: "partial_check", Area: "partial", Verb: "check", Summary: "A test tool whose result computes four of the five kinds.",
		Tier: registry.TierLocal, Stage: registry.StageGA, Credential: registry.CredNone},
		func(_ context.Context, _ *registry.Env, in gateIn) (partialOut, error) { return partialOut(in), nil }))
	return reg
}

// withFixture points a harness at the test registry.
func withFixture(t *testing.T, h *harness) *int {
	t.Helper()
	ran := new(int)
	reg := fixtureRegistry(ran)
	h.r.Registry = func() *registry.Registry { return reg }
	h.app.Registry = reg
	h.r.Now = func() time.Time { return time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC) }
	return ran
}

func reflectTypeOf(v any) reflect.Type { return reflect.TypeOf(v) }
