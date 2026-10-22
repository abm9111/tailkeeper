package tools_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// validAuditCursor is a cursor of the shape an audit_log page issues: base64 of
// its window, the time it stopped at, and how many entries at that time it returned.
var validAuditCursor = base64.RawURLEncoding.EncodeToString([]byte(
	`{"s":"2026-01-01T00:00:00Z","e":"2026-01-02T00:00:00Z","t":"2026-01-01T12:00:00Z","n":1,"f":""}`))

// Input that no API answer can make valid is refused by Validate, with no
// environment, so the CLI refuses it before it loads the configuration or unlocks
// a credential. Call, which the MCP server uses, is Validate then Run: the same
// input fails the same way there (TestARefusedCallSendsNoRequest shows that no
// request is sent).
func TestInputChecksNeedNoEnvironment(t *testing.T) {
	reg := newRegistry(t)
	for _, c := range []struct{ tool, args string }{
		{"acl_get", `{"fromLine":-1}`},
		{"acl_get", `{"maxBytes":10}`},
		{"acl_get", `{"maxBytes":99999999}`},
		{"acl_get", `{"view":"raw"}`},
		{"acl_get", `{"view":"summary","fromLine":2}`},
		{"acl_get", `{"view":"summary","maxBytes":2048}`},
		{"acl_test", `{"src":"tag:ci"}`},
		{"acl_test", `{"src":"tag:ci","accept":["tag:prod"]}`},
		{"acl_validate", `{"policy":"{}","patch":"[]"}`},
		{"acl_diff", `{"policy":"{}","patch":"[]"}`},
		{"acl_diff", `{"section":"nope"}`},
		{"devices_list", `{"staleDays":4000}`},
		{"devices_list", `{"staleDays":-1}`},
		{"devices_list", `{"tags":["prod"]}`},
		{"users_list", `{"type":"robot"}`},
		{"users_list", `{"role":"wizard"}`},
		{"audit_log", `{"limit":9999}`},
		{"audit_log", `{"limit":-1}`},
		{"audit_log", `{"cursor":"x","start":"2026-01-01T00:00:00Z"}`},
		{"audit_log", `{"cursor":"x","end":"2026-01-01T00:00:00Z"}`},
		{"network_flow_logs", `{"maxRecords":20000}`},
		{"network_flow_logs", `{"maxRecords":-1}`},
		{"log_streaming_get", `{"logType":"audit"}`},
		{"key_get", `{"id":"bad id"}`},
		{"user_get", `{"id":"bad id"}`},
		{"webhook_get", `{"id":"bad id"}`},
		{"posture_integration_get", `{"id":"bad id"}`},
		{"oauth_app_get", `{"id":"bad id"}`},
		{"service_get", `{"name":"bad name"}`},
		{"device_invite_get", `{"id":"bad id"}`},
		{"user_invite_get", `{"id":"bad id"}`},
		// The device reference: empty after trimming, or longer than a hostname.
		{"device_get", `{"device":"  "}`},
		{"device_routes", `{"device":"  "}`},
		{"device_posture_attributes", `{"device":"  "}`},
		{"device_invites_list", `{"device":"  "}`},
		{"device_get", `{"device":"` + strings.Repeat("a", 254) + `"}`},
		// The window of the two log tools: the part that needs no clock.
		{"audit_log", `{"start":"garbage"}`},
		{"audit_log", `{"end":"garbage"}`},
		// A cursor that no page issued is refused before anything is sent.
		{"audit_log", `{"cursor":"x"}`},
		{"audit_log", `{"cursor":"` + base64.RawURLEncoding.EncodeToString([]byte(`{"s":"2026-01-01T00:00:00Z","e":"2026-01-02T00:00:00Z","t":"2026-01-03T00:00:00Z","n":1}`)) + `"}`},
		{"audit_log", `{"start":"2026-01-02T00:00:00Z","end":"2026-01-01T00:00:00Z"}`},
		{"audit_log", `{"start":"2026-01-01T00:00:00Z","end":"2026-03-01T00:00:00Z"}`},
		{"network_flow_logs", `{"start":"garbage"}`},
		{"network_flow_logs", `{"end":"garbage"}`},
		{"network_flow_logs", `{"start":"2026-01-02T00:00:00Z","end":"2026-01-01T00:00:00Z"}`},
		{"network_flow_logs", `{"start":"2026-01-01T00:00:00Z","end":"2026-01-01T03:00:00Z"}`},
	} {
		tool, ok := reg.Get(c.tool)
		if !ok {
			t.Fatalf("no tool %s", c.tool)
		}
		p, err := tool.Validate(json.RawMessage(c.args))
		if e, isErr := tkerr.As(err); p != nil || !isErr || e.Code != tkerr.ValidationFailed {
			t.Errorf("%s %s: Validate = (prepared: %v), %v; want validation_failed and no Prepared", c.tool, c.args, p != nil, err)
		}
	}
	// And the inputs that are valid pass Validate with no environment too.
	for _, c := range []struct{ tool, args string }{
		{"acl_get", `{}`}, {"acl_get", `{"fromLine":3,"maxBytes":2048}`}, {"acl_get", `{"view":"summary"}`}, {"acl_get", `{"view":"text","fromLine":3}`},
		{"acl_test", `{"src":"tag:ci","accept":["tag:prod:22"]}`},
		{"acl_validate", `{}`}, {"acl_validate", `{"policy":"{}"}`}, {"acl_validate", `{"patch":"[]"}`},
		{"acl_diff", `{}`}, {"acl_diff", `{"against":"{}"}`}, {"acl_diff", `{"policy":"{}","section":"Groups"}`}, {"acl_diff", `{"patch":"[]","section":"unknown","ignoreTailscaleWritten":true}`},
		{"devices_list", `{"staleDays":30,"tags":["tag:a"]}`}, {"users_list", `{"type":"member","role":"admin"}`},
		{"audit_log", `{"limit":5000}`}, {"network_flow_logs", `{"maxRecords":10000}`}, {"log_streaming_get", `{"logType":"network"}`},
		{"key_get", `{"id":"kABC123CNTRL"}`}, {"service_get", `{"name":"svc:web"}`},
		{"device_get", `{"device":"nABC123CNTRL"}`}, {"device_get", `{"device":"12345"}`}, {"device_routes", `{"device":"host.example.com"}`},
		{"device_invites_list", `{"device":"host"}`}, {"device_posture_attributes", `{"device":"host"}`},
		{"audit_log", `{"start":"2026-01-01T00:00:00Z","end":"2026-01-02T00:00:00Z"}`},
		{"audit_log", `{"start":"2026-01-01T00:00:00Z"}`}, {"audit_log", `{"cursor":"` + validAuditCursor + `"}`},
		{"network_flow_logs", `{"start":"2026-01-01T00:00:00Z","end":"2026-01-01T00:30:00Z"}`},
	} {
		tool, _ := reg.Get(c.tool)
		if _, err := tool.Validate(json.RawMessage(c.args)); err != nil {
			t.Errorf("%s %s: Validate = %v, want it valid", c.tool, c.args, err)
		}
	}
}

// No device reference is longer than 253 bytes, whatever it looks like: a node ID
// or a numeric ID of any length used to pass and went into the request path.
func TestAnOverlongDeviceReferenceIsRefusedEvenWhenItLooksLikeAnID(t *testing.T) {
	reg := newRegistry(t)
	for name, c := range map[string]struct {
		device string
		valid  bool
	}{
		"a node ID of 300 characters":        {"n" + strings.Repeat("A", 294) + "CNTRL", false},
		"a numeric ID of 300 digits":         {strings.Repeat("1", 300), false},
		"a node ID of 254 characters":        {"n" + strings.Repeat("A", 248) + "CNTRL", false},
		"a node ID of 253 characters":        {"n" + strings.Repeat("A", 247) + "CNTRL", true},
		"a numeric ID of 253 digits":         {strings.Repeat("1", 253), true},
		"a node ID of the usual length":      {"nABC123CNTRL", true},
		"a numeric ID of the usual length":   {"12345", true},
		"a padded node ID of the usual size": {"  nABC123CNTRL  ", true},
	} {
		for _, toolName := range []string{"device_get", "device_routes"} {
			tool, ok := reg.Get(toolName)
			if !ok {
				t.Fatalf("no tool %s", toolName)
			}
			args, _ := json.Marshal(map[string]string{"device": c.device})
			_, err := tool.Validate(args)
			if c.valid && err != nil {
				t.Errorf("%s, %s: Validate = %v, want it valid", toolName, name, err)
			}
			if e, isErr := tkerr.As(err); !c.valid && (!isErr || e.Code != tkerr.ValidationFailed || !strings.Contains(e.Message, "device must be a node ID, numeric ID or hostname")) {
				t.Errorf("%s, %s: Validate = %v, want validation_failed with the device message", toolName, name, err)
			}
		}
	}
}

// A call the tool refuses fails with validation_failed before any request goes to
// the API, whichever kind of tool it is.
func TestARefusedCallSendsNoRequest(t *testing.T) {
	f, reg, env := apiEnv(t)
	for _, c := range []struct{ tool, args string }{
		{"acl_test", `{"src":"tag:ci"}`},
		{"acl_validate", `{"policy":"{}","patch":"[]"}`},
		{"acl_get", `{"maxBytes":10}`},
		{"acl_get", `{"view":"raw"}`},
		{"devices_list", `{"tags":["prod"]}`},
		{"device_get", `{"device":"  "}`},
		{"device_routes", `{"device":"` + strings.Repeat("a", 254) + `"}`},
		{"audit_log", `{"limit":9999}`},
		{"network_flow_logs", `{"maxRecords":20000}`},
		{"key_get", `{"id":"bad id"}`},
		{"service_get", `{"name":"bad name"}`},
	} {
		_, err := call(t, reg, env, c.tool, c.args)
		if e, isErr := tkerr.As(err); !isErr || e.Code != tkerr.ValidationFailed {
			t.Errorf("%s %s: error = %v, want validation_failed", c.tool, c.args, err)
		}
		if n := len(f.Requests()); n != 0 {
			t.Fatalf("%s %s: %d requests reached the API, want none", c.tool, c.args, n)
		}
	}
}
