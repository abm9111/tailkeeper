package api_test

import (
	"context"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// A body is one JSON value. White space may follow it; anything else is an error, whether it
// is a second value, the start of one, or bytes that are not JSON. Without the check the
// decoder reads the first value and stops, and the rest is never seen.
func TestGetRefusesDataAfterTheJSONValue(t *testing.T) {
	const value = `{"devices":[]}`
	for _, c := range []struct {
		name string
		body string
		ok   bool
	}{
		{"the value alone", value, true},
		{"white space after it", value + " \n\t\r\n", true},
		{"a second value", value + ` {"devices":[]}`, false},
		{"the start of another", value + ` {"devices":[`, false},
		{"a stray bracket", value + `]`, false},
		{"bytes that are not JSON", value + `x`, false},
		{"a number", value + ` 1`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := apitest.New(t)
			f.JSON("GET", devicesPath, 200, c.body)
			cl := newClient(t, f, api.Options{})
			err := cl.Get(context.Background(), cl.TailnetPath("/devices"), nil, &devicesResp{})
			if c.ok && err != nil {
				t.Errorf("err = %v, want none", err)
			}
			if !c.ok && err == nil {
				t.Error("a body with data after its value was read as complete")
			}
		})
	}
}
