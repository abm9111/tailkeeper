package tools_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

const devicesPath = "/api/v2/tailnet/T1234CNTRL/devices"

// deviceFixture holds two devices. The first carries fields tailkeeper must never
// return (keys, serial numbers, public endpoints); the second has a name with a
// terminal escape sequence and has been offline since September.
func deviceFixture() string {
	return `{"devices":[
{"addresses":["100.64.0.1"],"id":"1001","nodeId":"nAAA1CNTRL","user":"amy@example.com","name":"web-1.example.ts.net",
 "hostname":"web-1","os":"linux","connectedToControl":true,"lastSeen":"2026-10-10T11:59:00Z","authorized":true,
 "tags":["tag:web"],"machineKey":"mkey:CANARY-MACHINE","nodeKey":"nodekey:CANARY-NODE","tailnetLockKey":"tlpub:CANARY-TL",
 "postureIdentity":{"serialNumbers":["CANARY-SERIAL"]},
 "clientConnectivity":{"endpoints":["203.0.113.7:41641"],"mappingVariesByDestIP":true,
   "latency":{"fra":{"preferred":true,"latencyMs":12.5},"nyc":{"latencyMs":90}},"clientSupports":{"udp":true,"ipv6":false}},
 "enabledRoutes":["10.0.0.0/24"],"advertisedRoutes":["10.0.0.0/24"]},
{"addresses":["100.64.0.2"],"id":"1002","nodeId":"nBBB2CNTRL","user":"bob@example.com","name":` + jsonString("evil"+r(0x1B)+"[2Jbox") + `,
 "hostname":"old-box","os":"windows","connectedToControl":false,"lastSeen":"2026-09-01T00:00:00Z","authorized":true,
 "enabledRoutes":["10.0.0.0/24"]}
]}`
}

func TestDevicesListFiltersAndDropsUndeclaredFields(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", devicesPath, 200, deviceFixture())
	var out tools.DevicesListOutput
	s := mustCall(t, reg, env, "devices_list", `{"tags":["TAG:Web"],"os":"linux","nameContains":"WEB","allFields":true}`, &out)
	absent(t, s, "CANARY", "203.0.113.7")

	q := f.Requests()[0].Query
	if q.Get("fields") != "all" || !slices.Equal(q["tags"], []string{"tag:web"}) || q.Get("os") != "linux" {
		t.Errorf("query = %v", q)
	}
	if out.Count != 1 || out.Devices[0].NodeID != "nAAA1CNTRL" {
		t.Fatalf("devices = %+v", out.Devices)
	}
	if !slices.Equal(out.ServerFilters, []string{"os", "tags=tag:web"}) || !slices.Equal(out.ClientFilters, []string{"nameContains"}) {
		t.Errorf("filters = %v / %v", out.ServerFilters, out.ClientFilters)
	}
	c := out.Devices[0].Connectivity
	if c == nil || !c.HardNAT || c.PreferredDERP != "fra" || c.PreferredLatencyMs != 12.5 || c.Supports.UDP == nil || !*c.Supports.UDP {
		t.Errorf("connectivity = %+v", c)
	}
}

func TestDevicesListStaleAndSanitized(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", devicesPath, 200, deviceFixture())
	var out tools.DevicesListOutput
	mustCall(t, reg, env, "devices_list", `{"staleDays":30}`, &out)
	if out.Count != 1 || out.Devices[0].NodeID != "nBBB2CNTRL" {
		t.Fatalf("stale devices = %+v", out.Devices)
	}
	if want := `evil\u{001B}[2Jbox`; out.Devices[0].Name != want {
		t.Errorf("name = %q, want %q", out.Devices[0].Name, want)
	}
	if out.Fields != "default" || f.Requests()[0].Query.Get("fields") != "default" {
		t.Errorf("fields = %q", out.Fields)
	}
}

func TestDevicesListRejectsBadInput(t *testing.T) {
	_, reg, env := apiEnv(t)
	for _, args := range []string{`{"tags":["web"]}`, `{"staleDays":-1}`, `{"unknown":1}`, `{"tags":"tag:web"}`} {
		if _, err := call(t, reg, env, "devices_list", args); code(err) != tkerr.ValidationFailed {
			t.Errorf("%s: err = %v, want validation_failed", args, err)
		}
	}
}

func TestDeviceGetResolvesHostname(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", devicesPath, 200, deviceFixture())
	f.JSON("GET", "/api/v2/device/nAAA1CNTRL", 200, `{"nodeId":"nAAA1CNTRL","name":"web-1.example.ts.net","nodeKey":"nodekey:CANARY"}`)
	var d tools.Device
	s := mustCall(t, reg, env, "device_get", `{"device":"WEB-1"}`, &d)
	absent(t, s, "CANARY")
	reqs := f.Requests()
	if len(reqs) != 2 || reqs[1].Path != "/api/v2/device/nAAA1CNTRL" || reqs[1].Query.Get("fields") != "all" {
		t.Fatalf("requests = %+v", reqs)
	}
	if d.NodeID != "nAAA1CNTRL" || d.Fields != "all" {
		t.Errorf("device = %+v", d)
	}
}

func TestDeviceGetByIDSkipsLookup(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", "/api/v2/device/nAAA1CNTRL", 200, `{"nodeId":"nAAA1CNTRL"}`)
	mustCall(t, reg, env, "device_get", `{"device":"nAAA1CNTRL"}`, nil)
	if n := len(f.Requests()); n != 1 {
		t.Fatalf("%d requests, want 1", n)
	}
}

func TestDeviceGetAmbiguousAndMissing(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", devicesPath, 200, `{"devices":[{"nodeId":"nAAA1CNTRL","hostname":"box"},{"nodeId":"nBBB2CNTRL","hostname":"box"}]}`)
	if _, err := call(t, reg, env, "device_get", `{"device":"box"}`); code(err) != tkerr.ValidationFailed {
		t.Errorf("ambiguous: err = %v", err)
	}
	if _, err := call(t, reg, env, "device_get", `{"device":"nobody"}`); code(err) != tkerr.NotFound {
		t.Errorf("missing: err = %v", err)
	}
}

func TestDeviceRoutesPendingLatentAndHA(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", "/api/v2/device/nAAA1CNTRL/routes", 200,
		`{"advertisedRoutes":["10.0.0.0/24","0.0.0.0/0","::/0","10.0.1.7/24"],"enabledRoutes":["10.0.0.0/24","192.168.1.0/24"]}`)
	f.JSON("GET", devicesPath, 200, deviceFixture())
	var out tools.DeviceRoutesOutput
	mustCall(t, reg, env, "device_routes", `{"device":"nAAA1CNTRL","includeHa":true}`, &out)
	if !slices.Equal(out.Pending, []string{"0.0.0.0/0", "10.0.1.0/24", "::/0"}) {
		t.Errorf("pending = %v", out.Pending)
	}
	if !slices.Equal(out.Latent, []string{"192.168.1.0/24"}) {
		t.Errorf("latent = %v", out.Latent)
	}
	if !out.ExitNodeAdvertised || out.ExitNodeEnabled {
		t.Errorf("exit node advertised=%v enabled=%v", out.ExitNodeAdvertised, out.ExitNodeEnabled)
	}
	if len(out.HAPeers) != 1 || out.HAPeers[0].NodeID != "nBBB2CNTRL" || out.HAPeers[0].Prefix != "10.0.0.0/24" {
		t.Errorf("HA peers = %+v", out.HAPeers)
	}
}

func TestDevicePostureAttributesTyped(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", "/api/v2/device/nAAA1CNTRL/attributes", 200,
		`{"attributes":{"custom:tier":"prod","custom:score":42,"custom:ok":true,"node:os":"linux"},"expiries":{"custom:tier":"2026-11-01T00:00:00Z"}}`)
	var out tools.DevicePostureOutput
	mustCall(t, reg, env, "device_posture_attributes", `{"device":"nAAA1CNTRL"}`, &out)
	got := map[string]tools.PostureAttribute{}
	var keys []string
	for _, a := range out.Attributes {
		got[a.Attribute] = a
		keys = append(keys, a.Attribute)
	}
	if !slices.IsSorted(keys) || len(keys) != 4 {
		t.Fatalf("keys = %v", keys)
	}
	if a := got["custom:score"]; a.Type != "number" || a.Value != "42" {
		t.Errorf("score = %+v", a)
	}
	if a := got["custom:ok"]; a.Type != "boolean" || a.Value != "true" {
		t.Errorf("ok = %+v", a)
	}
	if a := got["custom:tier"]; a.Expiry != "2026-11-01T00:00:00Z" {
		t.Errorf("tier = %+v", a)
	}
}

func TestCredentialShapesInDeviceNamesAreRedactedNotWithheld(t *testing.T) {
	f, reg, env := apiEnv(t)
	shape := "tskey" + "-auth-" + strings.Repeat("B", 12) // assembled so no literal matches a scanner rule
	f.JSON("GET", devicesPath, 200, `{"devices":[{"nodeId":"nAAA1CNTRL","name":`+jsonString("box "+shape)+`},{"nodeId":"nBBB2CNTRL","name":"web-1"}]}`)
	var out tools.DevicesListOutput
	s := mustCall(t, reg, env, "devices_list", `{}`, &out)
	absent(t, s, "BBBB")
	if out.Count != 2 || !strings.Contains(s, tripwire.Redacted) {
		t.Fatalf("one hostile name must not hide the inventory: %+v", out.Devices)
	}
	// Outside tailnet text a credential shape still withholds the result.
	f.JSON("GET", devicesPath, 200, `{"devices":[{"nodeId":`+jsonString(shape)+`,"name":"web-1"}]}`)
	_, err := call(t, reg, env, "devices_list", `{}`)
	if code(err) != tkerr.OutputWithheld || strings.Contains(err.Error(), "BBBB") {
		t.Fatalf("err = %v, want output_withheld without the text", err)
	}
}

func TestNoCredentialIsReportedPerCall(t *testing.T) {
	reg := newRegistry(t)
	env := &registry.Env{APIErr: tkerr.New(tkerr.CredentialUnavailable, "no read credential", "")}
	if _, err := call(t, reg, env, "devices_list", `{}`); code(err) != tkerr.CredentialUnavailable {
		t.Errorf("err = %v", err)
	}
}

func TestDeviceRoutesHAByNumericIDSkipsSelfAndExitRoutes(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", "/api/v2/device/1001/routes", 200,
		`{"advertisedRoutes":["10.0.0.0/24","0.0.0.0/0"],"enabledRoutes":["10.0.0.0/24","0.0.0.0/0"]}`)
	f.JSON("GET", devicesPath, 200, `{"devices":[
{"id":"1001","nodeId":"nAAA1CNTRL","name":"web-1","enabledRoutes":["10.0.0.0/24","0.0.0.0/0"]},
{"id":"1002","nodeId":"nBBB2CNTRL","name":"web-2","enabledRoutes":["10.0.0.0/24"]},
{"id":"1003","nodeId":"nCCC3CNTRL","name":"exit-1","enabledRoutes":["0.0.0.0/0","::/0"]}
]}`)
	var out tools.DeviceRoutesOutput
	mustCall(t, reg, env, "device_routes", `{"device":"1001","includeHa":true}`, &out)
	if len(out.HAPeers) != 1 || out.HAPeers[0].NodeID != "nBBB2CNTRL" || out.HAPeers[0].Prefix != "10.0.0.0/24" {
		t.Errorf("HA peers = %+v", out.HAPeers)
	}
}

func TestDeviceRouteAndRegionTextIsSanitized(t *testing.T) {
	f, reg, env := apiEnv(t)
	esc := jsonString("evil" + r(0x1B) + "[2J")
	f.JSON("GET", "/api/v2/device/nAAA1CNTRL", 200, `{"id":"1001","nodeId":"nAAA1CNTRL","name":"web-1",
 "advertisedRoutes":[`+esc+`],"clientConnectivity":{"latency":{`+esc+`:{"preferred":true,"latencyMs":3}}}}`)
	f.JSON("GET", "/api/v2/device/nAAA1CNTRL/routes", 200, `{"advertisedRoutes":[`+esc+`],"enabledRoutes":[]}`)
	want := `evil\u{001B}[2J`
	var dev tools.Device
	mustCall(t, reg, env, "device_get", `{"device":"nAAA1CNTRL"}`, &dev)
	if dev.Connectivity == nil || dev.Connectivity.PreferredDERP != want || len(dev.AdvertisedRoutes) != 1 || dev.AdvertisedRoutes[0] != want {
		t.Errorf("device = %+v, connectivity = %+v", dev, dev.Connectivity)
	}
	var routes tools.DeviceRoutesOutput
	mustCall(t, reg, env, "device_routes", `{"device":"nAAA1CNTRL"}`, &routes)
	if len(routes.Pending) != 1 || routes.Pending[0] != want {
		t.Errorf("pending = %q", routes.Pending)
	}
}

func TestDevicesListOrderIsDeterministic(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", devicesPath, 200, `{"devices":[
{"id":"2","nodeId":"nZZZ9CNTRL","name":"dup"},
{"id":"1","nodeId":"nAAA9CNTRL","name":"dup"}
]}`)
	var out tools.DevicesListOutput
	mustCall(t, reg, env, "devices_list", `{}`, &out)
	if len(out.Devices) != 2 || out.Devices[0].NodeID != "nAAA9CNTRL" {
		t.Errorf("order = %+v", out.Devices)
	}
}

func TestDevicePostureShowsOtherValues(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", "/api/v2/device/nAAA1CNTRL/attributes", 200, `{"attributes":{"custom:list":["a","b"]}}`)
	var out tools.DevicePostureOutput
	mustCall(t, reg, env, "device_posture_attributes", `{"device":"nAAA1CNTRL"}`, &out)
	if len(out.Attributes) != 1 || out.Attributes[0].Type != "other" || out.Attributes[0].Value != `["a","b"]` {
		t.Errorf("attributes = %+v", out.Attributes)
	}
}

func TestDeviceNameFiltersAndLookupsReadTheDisplayedName(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", devicesPath, 200, `{"devices":[
	 {"id":"1","nodeId":"nAAA1CNTRL","name":"box1.example.ts.net","hostname":"amy@example.com"},
	 {"id":"2","nodeId":"nBBB2CNTRL","name":"box2.example.ts.net","hostname":"203.0.113.9"},
	 {"id":"3","nodeId":"nCCC3CNTRL","name":"box3.example.ts.net","hostname":"build-1"}]}`)
	f.JSON("GET", "/api/v2/device/nAAA1CNTRL", 200, `{"nodeId":"nAAA1CNTRL"}`)
	matches := func(e *registry.Env, needle string) int {
		var out tools.DevicesListOutput
		mustCall(t, reg, e, "devices_list", fmt.Sprintf(`{"nameContains":%q}`, needle), &out)
		return out.Count
	}
	for _, guess := range []string{"amy@example.com", "amy", "203.0.113.9"} {
		if n := matches(env, guess); n != 0 {
			t.Errorf("nameContains %q matched %d device(s) while masked: it confirms a guess at hidden text", guess, n)
		}
		if n := matches(show(env), guess); n != 1 {
			t.Errorf("nameContains %q with masking off matched %d, want 1", guess, n)
		}
	}
	for needle, want := range map[string]int{"203.0.113": 1, "@example.com": 1, "build": 1,
		"a\u2026@example.com": 1, "203.0.113.0/24": 1} { // the exact forms the result shows
		if n := matches(env, needle); n != want {
			t.Errorf("nameContains %q matched %d, want %d (it is in the displayed text)", needle, n, want)
		}
	}
	before := len(f.Requests())
	for _, guess := range []string{"amy@example.com", "203.0.113.9"} {
		if _, err := call(t, reg, env, "devices_list", fmt.Sprintf(`{"hostname":%q}`, guess)); code(err) != tkerr.FilterRefused {
			t.Errorf("hostname %q while masked: err = %v, want filter_refused", guess, err)
		}
	}
	if len(f.Requests()) != before {
		t.Error("a refused hostname filter reached the server")
	}
	if _, err := call(t, reg, env, "devices_list", `{"hostname":"build-1"}`); err != nil {
		t.Errorf("a plain hostname is still a filter: %v", err)
	}
	if _, err := call(t, reg, env, "device_get", `{"device":"amy@example.com"}`); code(err) != tkerr.NotFound {
		t.Errorf("device_get by a hostname the result masks: err = %v, want not_found", err)
	}
	if _, err := call(t, reg, show(env), "device_get", `{"device":"amy@example.com"}`); err != nil {
		t.Errorf("device_get by hostname with masking off: %v", err)
	}
}

// With a privacy key a masked hostname carries its pseudonym, and nameContains
// reads the shown text: the pseudonym finds the device, a guess at the address does not.
func TestDeviceNameContainsTakesThePseudonymWhenKeyed(t *testing.T) {
	f, reg, env := apiEnv(t)
	env, k := keyed(t, env)
	f.JSON("GET", devicesPath, 200, `{"devices":[
	 {"id":"1","nodeId":"nAAA1CNTRL","name":"box1.example.ts.net","hostname":"amy@example.com"},
	 {"id":"3","nodeId":"nCCC3CNTRL","name":"box3.example.ts.net","hostname":"build-1"}]}`)
	count := func(needle string) int {
		var out tools.DevicesListOutput
		mustCall(t, reg, env, "devices_list", fmt.Sprintf(`{"nameContains":%q}`, needle), &out)
		return out.Count
	}
	pseudonym := strings.Trim(privacy.Suffix(k.Pseudonym("amy@example.com")), " ")
	if n := count(pseudonym); n != 1 {
		t.Errorf("nameContains %q (the pseudonym the result shows) matched %d, want 1", pseudonym, n)
	}
	if n := count("[p:" + strings.Repeat("z", 10) + "]"); n != 0 {
		t.Errorf("nameContains with another pseudonym matched %d, want 0", n)
	}
	for _, guess := range []string{"amy@example.com", "amy"} {
		if n := count(guess); n != 0 {
			t.Errorf("nameContains %q matched %d device(s) while masked: it confirms a guess", guess, n)
		}
	}
}
