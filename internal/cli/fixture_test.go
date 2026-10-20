package cli

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// fixtureIn is an input shaped like the policy tools' input: the proposal, a patch
// and the other side of a diff are text over MCP and files or standard input on the
// command line, and the invariants and the offline switch exist on the command line
// only. It is the test tool through which the framework is tested; no real tool
// ships in this change.
type fixtureIn struct {
	Name         string `json:"name,omitempty" jsonschema:"a label echoed back"`
	Policy       string `json:"policy,omitempty" cli:"file:from,stdin,group=proposal" jsonschema:"the proposed policy text"`
	Patch        string `json:"patch,omitempty" cli:"file:patch,stdin,group=proposal" jsonschema:"a JSON Patch against the live policy"`
	Against      string `json:"against,omitempty" cli:"file:against,stdin,live" jsonschema:"the old side of a comparison; live when left out"`
	Invariants   string `json:"-" cli:"file:invariants" jsonschema:"invariants to check the proposal against"`
	NoInvariants bool   `json:"-" cli:"bool:no-invariants" jsonschema:"skip the configured invariants"`
	Offline      bool   `json:"-" cli:"bool:offline" jsonschema:"do not call the API"`
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

// fixtureRegistry holds the test tools; ran counts the runs of fixture_check.
func fixtureRegistry(ran *int) *registry.Registry {
	reg := registry.New()
	reg.MustAdd(registry.Define(registry.Meta{Name: "fixture_check", Area: "fixture", Verb: "check", Summary: "A test tool for the framework.",
		Tier: registry.TierRead, Stage: registry.StageGA, Credential: registry.CredOptional, Scopes: []string{"devices:core:read"}},
		func(_ context.Context, _ *registry.Env, in fixtureIn) (fixtureOut, error) {
			*ran++
			return fixtureOut(in), nil
		}))
	reg.MustAdd(registry.Define(registry.Meta{Name: "gate_check", Area: "gate", Verb: "check", Summary: "A test tool whose result can be gated.",
		Tier: registry.TierLocal, Stage: registry.StageGA, Credential: registry.CredNone},
		func(_ context.Context, _ *registry.Env, in gateIn) (gateOut, error) { return gateOut(in), nil }))
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
