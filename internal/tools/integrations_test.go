package tools_test

import (
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

func TestWebhookURLReducedAndSecretOmitted(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/webhooks", 200, `{"webhooks":[{"endpointId":"w1","endpointUrl":"https://hooks.example.test/services/T0/B0/PATH-CANARY?token=QUERY-CANARY",
		"providerType":"slack","secret":"SECRET-CANARY","subscriptions":["nodeCreated"]}]}`)
	var out tools.WebhooksOutput
	s := mustCall(t, reg, env, "webhooks_list", `{}`, &out)
	absent(t, s, "CANARY")
	w := out.Webhooks[0]
	if w.EndpointHost != "https://hooks.example.test" || len(w.EndpointPathHash) != 64 {
		t.Errorf("webhook = %+v", w)
	}
}

// A webhook or log-stream URL with no scheme has no host to show, and its path and query can
// carry the token. It shows as a URL that could not be read, the text the audit log gives
// such a URL, and nothing of it: not as an empty host, which reads as no destination.
func TestAnUnreadableEndpointURLShowsAsOne(t *testing.T) {
	const unreadable = "(a URL that could not be read)"
	for name, raw := range map[string]string{
		"no scheme":             "hooks.example.test/services/T0/B0/PATH-CANARY?token=QUERY-CANARY",
		"a path alone":          "/services/T0/B0/PATH-CANARY",
		"no host":               "https:///services/PATH-CANARY",
		"an opaque URL":         "mailto:PATH-CANARY@example.test",
		"a scheme and no slash": "https:hooks.example.test/PATH-CANARY",
		"spaces":                " PATH-CANARY ",
	} {
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/webhooks", 200, `{"webhooks":[{"endpointId":"w1","endpointUrl":`+jsonString(raw)+`,"providerType":"slack","subscriptions":[]}]}`)
		var hooks tools.WebhooksOutput
		s := mustCall(t, reg, env, "webhooks_list", `{}`, &hooks)
		absent(t, s, "CANARY")
		if w := hooks.Webhooks[0]; w.EndpointHost != unreadable || w.EndpointPathHash != "" {
			t.Errorf("webhook with %s: host %q, hash %q", name, w.EndpointHost, w.EndpointPathHash)
		}
		f.JSON("GET", tailnetPath+"/logging/network/stream", 200, `{"destinationType":"sumo","url":`+jsonString(raw)+`}`)
		f.JSON("GET", tailnetPath+"/logging/network/stream/status", 403, `{"message":"forbidden"}`)
		var stream tools.LogStreamOutput
		s = mustCall(t, reg, env, "log_streaming_get", `{"logType":"network"}`, &stream)
		absent(t, s, "CANARY")
		if c := stream.Configuration; c.URL != unreadable || c.URLPathHash != "" {
			t.Errorf("log stream with %s: url %q, hash %q", name, c.URL, c.URLPathHash)
		}
	}
	// No URL is no destination, and says so.
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/webhooks", 200, `{"webhooks":[{"endpointId":"w1","providerType":"slack","subscriptions":[]}]}`)
	var hooks tools.WebhooksOutput
	mustCall(t, reg, env, "webhooks_list", `{}`, &hooks)
	if w := hooks.Webhooks[0]; w.EndpointHost != "" || w.EndpointPathHash != "" {
		t.Errorf("webhook with no URL: host %q, hash %q", w.EndpointHost, w.EndpointPathHash)
	}
}

func TestPostureAndOAuthAppsOmitSecrets(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/posture/integrations", 200,
		`{"integrations":[{"id":"p1","provider":"intune","clientId":"cid","clientSecret":"POSTURE-CANARY","status":{"matchedCount":3}}]}`)
	f.JSON("GET", tailnetPath+"/oauth-apps", 200,
		`{"oauthApps":[{"id":"a1","name":"app","clientSecret":"APP-CANARY","scopes":["devices:core:read"]}]}`)
	s1 := mustCall(t, reg, env, "posture_integrations_list", `{}`, nil)
	s2 := mustCall(t, reg, env, "oauth_apps_list", `{}`, nil)
	absent(t, s1+s2, "CANARY")
}

func TestServicesList(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/services", 200, `{"vipServices":[{"name":"svc:web","addrs":["100.100.1.1"],"ports":["tcp:443"]}]}`)
	var out tools.ServicesOutput
	mustCall(t, reg, env, "services_list", `{}`, &out)
	if out.Count != 1 || out.Services[0].Name != "svc:web" {
		t.Errorf("services = %+v", out)
	}
}

func TestIntegrationPathIDsAreValidated(t *testing.T) {
	_, reg, env := apiEnv(t)
	for name, args := range map[string]string{
		"webhook_get": `{"id":""}`, "service_get": `{"name":"svc web"}`, "posture_integration_get": `{"id":"a/b"}`,
		"oauth_app_get": `{"id":"../x"}`,
	} {
		if _, err := call(t, reg, env, name, args); code(err) != tkerr.ValidationFailed {
			t.Errorf("%s %s: err = %v, want validation_failed", name, args, err)
		}
	}
}

// Each get tool reads one object at its own path and keeps the redaction its
// list tool applies.
func TestIntegrationGetToolsReadOneObject(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", "/api/v2/webhooks/w1", 200, `{"endpointId":"w1","endpointUrl":"https://hooks.example.test/PATH-CANARY","secret":"SECRET-CANARY"}`)
	f.JSON("GET", "/api/v2/posture/integrations/p1", 200, `{"id":"p1","provider":"intune","clientSecret":"POSTURE-CANARY"}`)
	f.JSON("GET", tailnetPath+"/services/svc:web", 200, `{"name":"svc:web","ports":["tcp:443"]}`)
	f.JSON("GET", tailnetPath+"/oauth-apps/a1", 200, `{"id":"a1","name":"app","clientSecret":"APP-CANARY"}`)
	for name, c := range map[string]struct{ args, want string }{
		"webhook_get":             {`{"id":"w1"}`, `"endpointId":"w1"`},
		"posture_integration_get": {`{"id":"p1"}`, `"id":"p1"`},
		"service_get":             {`{"name":"svc:web"}`, `"name":"svc:web"`},
		"oauth_app_get":           {`{"id":"a1"}`, `"id":"a1"`},
	} {
		s := mustCall(t, reg, env, name, c.args, nil)
		absent(t, s, "CANARY")
		if !strings.Contains(s, c.want) {
			t.Errorf("%s = %s, want %s", name, s, c.want)
		}
	}
}

// An API error reaches the caller with its code from every list and get tool,
// not as an empty result.
func TestIntegrationToolsReturnAPIErrors(t *testing.T) {
	f, reg, env := apiEnv(t)
	for _, p := range []string{tailnetPath + "/webhooks", "/api/v2/webhooks/w1", tailnetPath + "/posture/integrations",
		"/api/v2/posture/integrations/p1", tailnetPath + "/services", tailnetPath + "/services/svc:web",
		tailnetPath + "/oauth-apps", tailnetPath + "/oauth-apps/a1", "/api/v2/device/nAAA1CNTRL/device-invites"} {
		f.JSON("GET", p, 404, `{"message":"not found"}`)
	}
	for name, args := range map[string]string{
		"webhooks_list": `{}`, "webhook_get": `{"id":"w1"}`, "posture_integrations_list": `{}`, "posture_integration_get": `{"id":"p1"}`,
		"services_list": `{}`, "service_get": `{"name":"svc:web"}`, "oauth_apps_list": `{}`, "oauth_app_get": `{"id":"a1"}`,
		"device_invites_list": `{"device":"nAAA1CNTRL"}`,
	} {
		if _, err := call(t, reg, env, name, args); code(err) != tkerr.NotFound {
			t.Errorf("%s: err = %v, want not_found", name, err)
		}
	}
}
