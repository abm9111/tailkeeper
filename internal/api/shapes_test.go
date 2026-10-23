package api_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// readsAsAPass says whether ValidateTests, sent one test, takes the shape for a pass.
func readsAsAPass(t *testing.T, s apitest.Shape) bool {
	t.Helper()
	f := apitest.New(t)
	f.ServeValidate(s)
	c := f.Client(t)
	res, err := c.ValidateTests(context.Background(), []api.PolicyTest{{Src: "tag:p", Accept: []string{"tag:p:22"}}})
	return err == nil && res.Passed
}

// readsAsAPolicyPass says whether the policy-mode reader takes the shape for a pass.
func readsAsAPolicyPass(s apitest.Shape) bool {
	return api.ReadPolicyValidation(s.Status, []byte(s.Body)).Status == api.PolicyPass
}

// An Assumed shape is one nobody has seen the API send, so no reader may turn it into a
// pass: ValidateTests (tests mode) and ReadPolicyValidation (policy mode) both read every
// one of them, and so does the client's policy-mode send (policy_validate_test.go).
func TestAssumedValidateShapesNeverReadAsAPass(t *testing.T) {
	n := 0
	for _, s := range apitest.AllShapes() {
		if s.Endpoint != apitest.EndpointValidate || s.Prov.Kind != apitest.Assumed {
			continue
		}
		n++
		t.Run(s.Name, func(t *testing.T) {
			if readsAsAPass(t, s) {
				t.Errorf("%s (%s) was read as a pass in tests mode", s.Name, s.Prov)
			}
			if readsAsAPolicyPass(s) {
				t.Errorf("%s (%s) was read as a pass in policy mode", s.Name, s.Prov)
			}
		})
	}
	if n < 6 {
		t.Errorf("only %d Assumed validate shapes in the ledger: the loop is not walking it", n)
	}
}

// notAPassInTestsMode requires ValidateTests to refuse s as an unrecognised response.
func notAPassInTestsMode(t *testing.T, s apitest.Shape) {
	t.Helper()
	f := apitest.New(t)
	f.ServeValidate(s)
	c := f.Client(t)
	res, err := c.ValidateTests(context.Background(), []api.PolicyTest{{Src: "tag:p", Accept: []string{"tag:p:22"}}})
	e := tkerr.From(err)
	if err == nil || e.Code != tkerr.APIError || !strings.Contains(err.Error(), "unrecognised response") || res.Passed {
		t.Errorf("%s: got %+v, %v; want api_error and the unrecognised response text", s.Name, res, err)
	}
}

// An empty data list is not a pass. The tests-mode pass the probe saw was a blank body.
func TestAnEmptyDataListIsNotAPass(t *testing.T) {
	notAPassInTestsMode(t, apitest.TestsEmptyData())
}

// A null data field is not a pass. It is a data field with no entries.
func TestANullDataListIsNotAPass(t *testing.T) {
	notAPassInTestsMode(t, apitest.TestsNullData())
}

// An empty message and no entries is not a pass.
func TestAnEmptyMessageIsNotAPass(t *testing.T) {
	notAPassInTestsMode(t, apitest.TestsEmptyMessage())
}

// The two passes the probes saw stay passes in tests mode: a blank body (A-12) and {}
// (A-1). A reader tightened until nothing passed would keep every refusal green.
func TestTheTwoObservedPassesStillPass(t *testing.T) {
	for _, s := range []apitest.Shape{apitest.TestsPass(), apitest.TestsPassEmptyObject()} {
		if !readsAsAPass(t, s) {
			t.Errorf("%s was not read as a pass", s.Name)
		}
	}
}

// Warnings alone stay a pass in tests mode, and the entry is kept.
func TestWarningsAloneStillPassInTestsMode(t *testing.T) {
	s := apitest.TestsWarned(apitest.Entry{User: "group:p", Warnings: []string{"host alias unused"}})
	f := apitest.New(t)
	f.ServeValidate(s)
	c := f.Client(t)
	res, err := c.ValidateTests(context.Background(), []api.PolicyTest{{Src: "tag:p", Accept: []string{"tag:p:22"}}})
	if err != nil || !res.Passed || len(res.Results) != 1 || res.Results[0].User != "group:p" || len(res.Results[0].Errors) != 0 || len(res.Results[0].Warnings) != 1 || res.Results[0].Warnings[0] != "host alias unused" {
		t.Fatalf("%s: %+v, %v", s.Name, res, err)
	}
}

// observedNotPasses is every Observed validate shape that is not one of the two passes (the
// empty body of tests mode and the {} of policy mode: A-12, A-1), written out: a shape added
// to the ledger must be added here, so the loop below cannot walk fewer shapes than the
// ledger holds without a change a reviewer sees.
var observedNotPasses = []string{
	"BareMessage200", "CanaryFailed", "PolicyDuplicateKey", "PolicyKeyRejected", "PolicyServerError500",
	"PolicySyntaxError", "PolicyTagNotFound", "PolicyUnknownField", "Rejected400", "SSHTestFailed",
	"TestUnevaluable", "TestsFailed",
}

// The live API answers a rejection of a well-formed document with HTTP 200 and a bare
// message (A-3), the status a pass has, so an Observed shape that is not one of the two
// passes must never read as a pass either, in either mode. A failure (CanaryFailed,
// TestsFailed) is not a pass in policy mode and is not one in tests mode.
func TestObservedValidateShapesThatAreNotPassesNeverReadAsAPass(t *testing.T) {
	passes := map[string]bool{"TestsPass": true, "TestsPassEmptyObject": true}
	var visited []string
	for _, s := range apitest.AllShapes() {
		if s.Endpoint != apitest.EndpointValidate || s.Prov.Kind != apitest.Observed || passes[s.Name] {
			continue
		}
		visited = append(visited, s.Name)
		t.Run(s.Name, func(t *testing.T) {
			if readsAsAPass(t, s) {
				t.Errorf("%s (%s) was read as a pass in tests mode", s.Name, s.Prov)
			}
			if readsAsAPolicyPass(s) {
				t.Errorf("%s (%s) was read as a pass in policy mode", s.Name, s.Prov)
			}
		})
	}
	slices.Sort(visited)
	if !slices.Equal(visited, observedNotPasses) {
		t.Errorf("the loop walked %v, the table says %v: the ledger and observedNotPasses must agree", visited, observedNotPasses)
	}
}

// The loops above can see a pass: the Observed pass shapes (the empty body of tests mode and
// the {} of policy mode) are read as one in both modes, and so are warnings alone. Without
// this, a reader that never passed anything would satisfy the loops.
func TestObservedPassShapesReadAsAPass(t *testing.T) {
	for _, s := range []apitest.Shape{apitest.TestsPass(), apitest.TestsPassEmptyObject()} {
		f := apitest.New(t)
		f.ServeValidate(s)
		c := f.Client(t)
		res, err := c.ValidateTests(context.Background(), []api.PolicyTest{{Src: "tag:p", Accept: []string{"tag:p:22"}}})
		if err != nil || !res.Passed {
			t.Errorf("%s in tests mode: %+v, %v", s.Name, res, err)
		}
		if !readsAsAPolicyPass(s) {
			t.Errorf("%s was not read as a pass in policy mode", s.Name)
		}
	}
	warned := apitest.TestsWarned(apitest.Entry{User: "group:p", Warnings: []string{"w"}})
	if v := api.ReadPolicyValidation(warned.Status, []byte(warned.Body)); v.Status != api.PolicyPass || len(v.Results) != 1 {
		t.Errorf("%s in policy mode: %+v, want a pass that carries its warning", warned.Name, v)
	}
}
