package tools_test

import (
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/api/openapi"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
)

// operationCalls are, for every tool that calls the API, the arguments of calls
// that together reach each request it can make: a device given by hostname is
// resolved through the device list first, a route lookup with includeHa lists the
// devices again, and the log stream is read for both log types.
var operationCalls = map[string][]string{
	"acl_get":                   {`{}`, `{"view":"summary"}`},
	"acl_test":                  {`{"src":"tag:a","accept":["tag:b:22"]}`, `{"src":"p:abcdefghij","accept":["tag:b:22"]}`, `{"src":"tag:a","ssh":[{"dst":["tag:b"],"accept":["root"]}]}`},
	"acl_diff":                  {`{"against":"{}\n"}`, `{"patch":"[{\"op\":\"add\",\"path\":\"/groups/group:eng\",\"value\":[\"p:abcdefghij\"]}]"}`},
	"acl_validate":              {`{}`, `{"patch":"[{\"op\":\"add\",\"path\":\"/groups/group:eng\",\"value\":[\"p:abcdefghij\"]}]"}`},
	"contacts_get":              {`{}`},
	"device_get":                {`{"device":"nAAA1CNTRL"}`, `{"device":"host-a"}`},
	"devices_list":              {`{}`},
	"device_posture_attributes": {`{"device":"host-a"}`},
	"device_routes":             {`{"device":"nAAA1CNTRL"}`, `{"device":"host-a","includeHa":true}`},
	"dns_get":                   {`{}`},
	"device_invite_get":         {`{"id":"i1"}`},
	"device_invites_list":       {`{"device":"host-a"}`},
	"user_invite_get":           {`{"id":"i1"}`},
	"user_invites_list":         {`{}`},
	"key_get":                   {`{"id":"k1"}`},
	"keys_list":                 {`{}`},
	"audit_log":                 {`{}`, `{"includeValues":true,"limit":1}`},
	"network_flow_logs":         {`{}`},
	"log_streaming_get":         {`{"logType":"configuration"}`, `{"logType":"network"}`},
	"oauth_app_get":             {`{"id":"a1"}`},
	"oauth_apps_list":           {`{}`},
	"posture_integration_get":   {`{"id":"p1"}`},
	"posture_integrations_list": {`{}`},
	"service_get":               {`{"name":"svc:web"}`},
	"services_list":             {`{}`},
	"settings_get":              {`{}`},
	"user_get":                  {`{"id":"u1"}`},
	"users_list":                {`{}`},
	"webhook_get":               {`{"id":"w1"}`},
	"webhooks_list":             {`{}`},
}

// operationOf names the operation of the pinned document that method and escaped
// path are, preferring the template with the most literal segments, or says why
// there is none.
func operationOf(method, path string) (string, error) {
	segs := strings.Split(strings.Trim(strings.TrimPrefix(path, "/api/v2"), "/"), "/")
	best, bestLiterals, tied := "", -1, false
	for _, op := range openapi.Operations() {
		m, tmpl, _ := strings.Cut(op, " ")
		tsegs := strings.Split(strings.Trim(tmpl, "/"), "/")
		if m != method || len(tsegs) != len(segs) {
			continue
		}
		literals, ok := 0, true
		for i, ts := range tsegs {
			switch {
			case strings.HasPrefix(ts, "{"):
				ok = ok && segs[i] != ""
			case ts == segs[i]:
				literals++
			default:
				ok = false
			}
		}
		switch {
		case !ok:
		case literals > bestLiterals:
			best, bestLiterals, tied = op, literals, false
		case literals == bestLiterals:
			tied = true
		}
	}
	switch {
	case tied:
		return "", fmt.Errorf("%s %s matches several operations", method, path)
	case best == "":
		return "", fmt.Errorf("%s %s is no operation of the pinned document", method, path)
	}
	return best, nil
}

func TestOperationOfMapsPathsToTemplates(t *testing.T) {
	for _, c := range []struct{ method, path, want string }{
		{"GET", "/api/v2/tailnet/T1/devices", "GET /tailnet/{tailnet}/devices"},
		{"GET", "/api/v2/device/nAAA1CNTRL", "GET /device/{deviceId}"},
		{"GET", "/api/v2/device/nAAA1CNTRL/routes", "GET /device/{deviceId}/routes"},
		{"GET", "/api/v2/tailnet/T1/keys", "GET /tailnet/{tailnet}/keys"},
		{"GET", "/api/v2/tailnet/T1/keys/k1", "GET /tailnet/{tailnet}/keys/{keyId}"},
		{"GET", "/api/v2/tailnet/T1/logging/network", "GET /tailnet/{tailnet}/logging/network"},
		{"GET", "/api/v2/tailnet/T1/logging/configuration/stream", "GET /tailnet/{tailnet}/logging/{logType}/stream"},
		{"GET", "/api/v2/tailnet/T1/logging/network/stream/status", "GET /tailnet/{tailnet}/logging/{logType}/stream/status"},
		{"POST", "/api/v2/tailnet/T1/acl/validate", "POST /tailnet/{tailnet}/acl/validate"},
	} {
		if got, err := operationOf(c.method, c.path); err != nil || got != c.want {
			t.Errorf("%s %s = %q, %v; want %q", c.method, c.path, got, err, c.want)
		}
	}
	for _, c := range [][2]string{{"GET", "/api/v2/tailnet/T1/nothing"}, {"POST", "/api/v2/tailnet/T1/devices"}, {"GET", "/api/v2/tailnet/T1/devices/extra/segments/here"}} {
		if got, err := operationOf(c[0], c[1]); err == nil {
			t.Errorf("%s %s = %q, want an error", c[0], c[1], got)
		}
	}
}

// fallbackBody answers any request a tool makes with data it can read to the end:
// one device for the device list, a tailnet with flow logging on, the policy in the form
// acl_get reads (from the shape ledger, as a test may not write it by hand), an empty
// object for the rest.
func fallbackBody(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(r.URL.Path, "/acl"):
		apitest.DetailsOK("{}\n", `"e1"`, nil, nil).Write(w)
	case strings.HasSuffix(r.URL.Path, "/devices"):
		_, _ = w.Write([]byte(`{"devices":[{"id":"1001","nodeId":"nAAA1CNTRL","name":"host-a.example.ts.net","hostname":"host-a"}]}`))
	case strings.HasSuffix(r.URL.Path, "/settings"):
		_, _ = w.Write([]byte(`{"networkFlowLoggingOn":true}`))
	case strings.HasSuffix(r.URL.Path, "/acl/validate"):
		_, _ = w.Write([]byte(`{}`))
	default:
		_, _ = w.Write([]byte(`{}`))
	}
}

// What a tool declares it calls (Meta.Operations, which docs/tools.md and the
// coverage map are built from) is what it sends. Each tool runs against the fake
// API; every request it records is mapped to the operation of the pinned
// document it is, and the two sets are compared both ways, so a declaration that
// has gone stale, in either direction, fails here and not in the weekly drift
// check. Requests count over all the calls made for the tool.
func TestEveryToolSendsExactlyTheOperationsItDeclares(t *testing.T) {
	reg := newRegistry(t)
	seen := map[string]bool{}
	for _, tool := range reg.All() {
		declared := tool.Meta.Operations
		if len(declared) == 0 {
			continue
		}
		seen[tool.Meta.Name] = true
		calls, ok := operationCalls[tool.Meta.Name]
		if !ok {
			t.Errorf("%s declares operations but operationCalls has no calls for it", tool.Meta.Name)
			continue
		}
		f := apitest.New(t)
		f.Fallback(fallbackBody)
		// A privacy key, so that a call that names a user by pseudonym reaches the users.
		key, err := privacy.Parse(strings.Repeat("5a", 32))
		if err != nil {
			t.Fatal(err)
		}
		env := &registry.Env{API: f.Client(t), Privacy: key, Now: func() time.Time { return now }}
		for _, args := range calls {
			// A tool may fail, as one given no usable answer does; it must still
			// have sent the requests it declares.
			_, _ = call(t, reg, env, tool.Meta.Name, args)
		}
		sent := map[string]bool{}
		for _, r := range f.Requests() {
			op, err := operationOf(r.Method, r.Path)
			if err != nil {
				t.Errorf("%s: %v", tool.Meta.Name, err)
				continue
			}
			sent[op] = true
		}
		var got []string
		for op := range sent {
			got = append(got, op)
		}
		sort.Strings(got)
		want := slices.Clone(declared)
		sort.Strings(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s declares %v but sends %v", tool.Meta.Name, want, got)
		}
		for _, op := range got {
			if _, skipped := openapi.Skipped[op]; skipped {
				t.Errorf("%s sends %s, which the coverage map says no tool calls", tool.Meta.Name, op)
			}
		}
	}
	for name := range operationCalls {
		if !seen[name] {
			t.Errorf("operationCalls names %s, which is not a tool that declares operations", name)
		}
	}
}
