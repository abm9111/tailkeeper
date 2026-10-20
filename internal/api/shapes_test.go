package api_test

import (
	"context"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
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

// An Assumed shape is one nobody has seen the API send, so the reader must never turn
// it into a pass. The only reader today is ValidateTests; strict readers
// for policy mode and details, when they exist, join this loop.
func TestAssumedValidateShapesNeverReadAsAPass(t *testing.T) {
	n := 0
	for _, s := range apitest.AllShapes() {
		if s.Endpoint != apitest.EndpointValidate || s.Prov.Kind != apitest.Assumed {
			continue
		}
		n++
		t.Run(s.Name, func(t *testing.T) {
			if readsAsAPass(t, s) {
				t.Errorf("%s (%s) was read as a pass", s.Name, s.Prov)
			}
		})
	}
	if n < 2 {
		t.Errorf("only %d Assumed validate shapes in the ledger: the loop is not walking it", n)
	}
}

// The live API answers a rejection of a well-formed document with HTTP 200 and a bare
// message (A-3), the status a pass has, so an Observed shape that is not one of the two
// passes (the empty body of tests mode and the {} of policy mode: A-12, A-1) must never
// read as a pass either. A strict reader for policy mode joins this loop too.
func TestObservedValidateShapesThatAreNotPassesNeverReadAsAPass(t *testing.T) {
	passes := map[string]bool{"TestsPass": true, "TestsPassEmptyObject": true}
	n := 0
	for _, s := range apitest.AllShapes() {
		if s.Endpoint != apitest.EndpointValidate || s.Prov.Kind != apitest.Observed || passes[s.Name] {
			continue
		}
		n++
		t.Run(s.Name, func(t *testing.T) {
			if readsAsAPass(t, s) {
				t.Errorf("%s (%s) was read as a pass", s.Name, s.Prov)
			}
		})
	}
	if n < 8 {
		t.Errorf("only %d Observed validate shapes that are not passes in the ledger: the loop is not walking it", n)
	}
}

// The loops above can see a pass: the Observed pass shapes (the empty body of tests mode and
// the {} of policy mode) are read as one. Without this, a reader that never passed
// anything would satisfy the loops.
func TestObservedPassShapesReadAsAPass(t *testing.T) {
	for _, s := range []apitest.Shape{apitest.TestsPass(), apitest.TestsPassEmptyObject()} {
		f := apitest.New(t)
		f.ServeValidate(s)
		c := f.Client(t)
		res, err := c.ValidateTests(context.Background(), []api.PolicyTest{{Src: "tag:p", Accept: []string{"tag:p:22"}}})
		if err != nil || !res.Passed {
			t.Errorf("%s: %+v, %v", s.Name, res, err)
		}
	}
}
