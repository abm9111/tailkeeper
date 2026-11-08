package tools_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tools"
)

// TestTheDevicesKeyIsMatchedAsEncodingJSONMatchesIt pins the reader to encoding/json's
// reading of the body's key: a spelling encoding/json takes for "devices" is the devices
// array, and a second one is the same ambiguity as a repeated "devices", never a second
// array the reader quietly passes over.
func TestTheDevicesKeyIsMatchedAsEncodingJSONMatchesIt(t *testing.T) {
	const a, b = `{"nodeId":"nA"}`, `{"nodeId":"nB"}`
	spellings := []string{"Devices", "DEVICES", "devices", `devicEs`, "deviceſ"}
	for _, key := range spellings {
		var list struct {
			Devices []struct {
				NodeID string `json:"nodeId"`
			} `json:"devices"`
		}
		alone := `{"` + key + `":[` + a + `]}`
		if err := json.Unmarshal([]byte(alone), &list); err != nil || len(list.Devices) != 1 {
			t.Fatalf("%q: encoding/json does not take it for devices (%v, %d rows); the case is wrong", key, err, len(list.Devices))
		}

		got, err := tools.ReadSecurityDeviceList([]byte(alone), 100)
		if err != nil {
			t.Errorf("%q alone: %v, want it read as the devices array", key, err)
		} else if !slices.Equal(got.Kept(), []string{"nA"}) {
			t.Errorf("%q alone: kept %v, want [nA]", key, got.Kept())
		}

		for _, body := range []string{
			`{"devices":[` + a + `],"` + key + `":[` + b + `]}`,
			`{"` + key + `":[` + a + `],"devices":[` + b + `]}`,
		} {
			if got, err := tools.ReadSecurityDeviceList([]byte(body), 100); err == nil {
				t.Errorf("%s: read with no error, kept %v; two devices arrays must be an error", body, got.Kept())
			}
		}
	}

	// Positive control: a key encoding/json does not take for devices leaves the list alone.
	got, err := tools.ReadSecurityDeviceList([]byte(`{"devices":[`+a+`],"devicesX":[`+b+`]}`), 100)
	if err != nil || !slices.Equal(got.Kept(), []string{"nA"}) {
		t.Fatalf("an unrelated key: %v, kept %v; want [nA] and no error", err, got.Kept())
	}
}
