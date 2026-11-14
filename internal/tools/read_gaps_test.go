package tools_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// esc is text with a terminal escape sequence in it, and escaped is how a result shows it.
var (
	esc     = "evil" + r(0x1B) + "[2J"
	escaped = `evil\u{001B}[2J`
)

// hostile is text from the tailnet that begins with prefix, holds an escape sequence, and runs
// past what a result shows of one string. Every string is escaped; only a field tagged untrusted
// is also cut, so the cut is what tells a tagged field from one that lost its tag.
func hostile(prefix string) string {
	return prefix + esc + strings.Repeat("x", registry.ResultStringMax)
}

// shownHostile checks what a result shows of hostile(prefix): the escape written out, the text
// cut under the cap, and the cut marked.
func shownHostile(t *testing.T, where, prefix, got string) {
	t.Helper()
	if !strings.HasPrefix(got, prefix+escaped) || strings.ContainsRune(got, 0x1B) ||
		len(got) > registry.ResultStringMax || !strings.HasSuffix(got, "...[truncated]") {
		t.Errorf("%s = %.60q (%d bytes): want %q escaped, then cut to %d bytes and marked", where, got, len(got), prefix, registry.ResultStringMax)
	}
}

// A filter that only tailkeeper can apply must not go to the server, or the server's answer
// would confirm a guess at text the result masks, and a name filter would be read by the
// server as something it is not. Only the filters the API knows are sent, and they are
// exactly the ones the output lists as server-side.
func TestDevicesListSendsOnlyTheServerSideFilters(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", devicesPath, 200, deviceFixture())
	var out tools.DevicesListOutput
	mustCall(t, reg, env, "devices_list",
		`{"tags":["TAG:Web"],"os":"linux","nameContains":"WEB","staleDays":30,"allFields":true,"limit":1,"offset":0}`, &out)
	q := f.Requests()[0].Query
	var keys []string
	for k := range q {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"fields", "os", "tags"}) {
		t.Errorf("query keys = %v, want only fields, os and tags: nameContains, staleDays, limit and offset are applied here", keys)
	}
	for _, v := range []string{"WEB", "web-1", "30"} {
		for k, vs := range q {
			if slices.Contains(vs, v) {
				t.Errorf("query %s = %v carries the client-side value %q", k, vs, v)
			}
		}
	}
	if !slices.Equal(out.ClientFilters, []string{"nameContains", "staleDays=30"}) {
		t.Errorf("client filters = %v", out.ClientFilters)
	}
}

// A failed read fails the whole tool: settings_get, contacts_get and dns_get never return an
// answer built from nothing, which would read as a tailnet with nothing set.
func TestSettingsContactsAndDNSFailWholeOnAnAPIError(t *testing.T) {
	for _, c := range []struct {
		tool, path string
	}{
		{"settings_get", "/settings"},
		{"contacts_get", "/contacts"},
		{"dns_get", "/dns/configuration"},
	} {
		for status, want := range map[int]tkerr.Code{
			403: tkerr.ScopeMissing, 500: tkerr.UpstreamUnavailable, 502: tkerr.UpstreamUnavailable, 404: tkerr.NotFound,
		} {
			f, reg, env := apiEnv(t)
			f.JSON("GET", tailnetPath+c.path, status, `{"message":"no"}`)
			out, err := call(t, reg, env, c.tool, `{}`)
			if code(err) != want {
				t.Errorf("%s with HTTP %d: err = %v, out = %s, want %s", c.tool, status, err, out, want)
			}
		}
	}
}

// Text from the tailnet in the settings link, the contacts and the DNS strings is escaped and
// cut like the text of any untrusted field.
func TestSettingsContactsAndDNSTextIsEscapedAndCut(t *testing.T) {
	f, reg, env := apiEnv(t)
	shown := show(env)
	f.JSON("GET", tailnetPath+"/settings", 200, `{"aclsExternalLink":`+jsonString(hostile("https://git.example.test/"))+`}`)
	var s tools.SettingsOutput
	mustCall(t, reg, env, "settings_get", `{}`, &s)
	if s.Settings.ACLsExternalLink == nil {
		t.Fatal("aclsExternalLink is missing")
	}
	shownHostile(t, "aclsExternalLink", "https://git.example.test/", *s.Settings.ACLsExternalLink)

	f.JSON("GET", tailnetPath+"/contacts", 200, `{"account":{"email":`+jsonString(hostile("acc"))+`},
		"support":{"email":`+jsonString(hostile("sup"))+`},
		"security":{"email":`+jsonString(hostile("sec"))+`,"fallbackEmail":`+jsonString(hostile("fb"))+`,"needsVerification":false}}`)
	var c tools.ContactsOutput
	mustCall(t, reg, shown, "contacts_get", `{}`, &c)
	shownHostile(t, "account.email", "acc", c.Account.Email)
	shownHostile(t, "support.email", "sup", c.Support.Email)
	shownHostile(t, "security.email", "sec", c.Security.Email)
	shownHostile(t, "security.fallbackEmail", "fb", c.Security.FallbackEmail)
	// Masked, the address is masked as well, and no control character survives either way.
	mustCall(t, reg, env, "contacts_get", `{}`, &c)
	for name, got := range map[string]string{"account.email": c.Account.Email, "security.fallbackEmail": c.Security.FallbackEmail} {
		if strings.ContainsRune(got, 0x1B) || len(got) > registry.ResultStringMax {
			t.Errorf("masked %s = %.60q holds a raw control character or runs past the cap", name, got)
		}
	}

	f.JSON("GET", tailnetPath+"/dns/configuration", 200, `{"nameservers":[{"address":`+jsonString(hostile("ns"))+`}],
		"splitDNS":{`+jsonString(hostile("zone"))+`:[{"address":`+jsonString(hostile("res"))+`}]},
		"searchPaths":[`+jsonString(hostile("search"))+`],"preferences":{"magicDNS":true}}`)
	f.JSON("GET", tailnetPath+"/acl", 403, `{"message":"forbidden"}`)
	var d tools.DNSOutput
	mustCall(t, reg, env, "dns_get", `{}`, &d)
	if len(d.Nameservers) != 1 || len(d.SplitDNS) != 1 || len(d.SplitDNS[0].Resolvers) != 1 || len(d.SearchPaths) != 1 {
		t.Fatalf("dns = %+v", d)
	}
	shownHostile(t, "nameservers[].address", "ns", d.Nameservers[0].Address)
	shownHostile(t, "splitDns[].domain", "zone", d.SplitDNS[0].Domain)
	shownHostile(t, "splitDns[].resolvers[].address", "res", d.SplitDNS[0].Resolvers[0].Address)
	shownHostile(t, "searchPaths[]", "search", d.SearchPaths[0])
}

// preferences present and set to null is the same as absent: unknown, not false.
func TestDNSExplicitNullPreferencesAreUnknown(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/dns/configuration", 200,
		`{"nameservers":[{"address":"1.1.1.1"}],"preferences":{"magicDNS":null}}`)
	var out tools.DNSOutput
	s := mustCall(t, reg, env, "dns_get", `{}`, &out)
	if out.MagicDNS != nil || out.OverrideLocalDNS != nil {
		t.Errorf("magicDns = %v, overrideLocalDns = %v, want null for both", out.MagicDNS, out.OverrideLocalDNS)
	}
	if !strings.Contains(s, `"magicDns":null`) || !strings.Contains(s, `"overrideLocalDns":null`) {
		t.Errorf("the result must say null, not leave the field out or write false: %s", s)
	}
	// With the object present and one of the two set, the other stays unknown and the one set is kept.
	f2, reg2, env2 := apiEnv(t)
	f2.JSON("GET", tailnetPath+"/dns/configuration", 200, `{"nameservers":[],"preferences":{"magicDNS":null,"overrideLocalDNS":false}}`)
	mustCall(t, reg2, env2, "dns_get", `{}`, &out)
	if out.MagicDNS != nil || out.OverrideLocalDNS == nil || *out.OverrideLocalDNS {
		t.Errorf("magicDns = %v, overrideLocalDns = %v", out.MagicDNS, out.OverrideLocalDNS)
	}
}

// key_get returns one key's metadata and never its material.
func TestKeyGetReturnsMetadataAndNeverTheKey(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/keys/k1", 200, `{"id":"k1","key":"KEY-MATERIAL-CANARY","keyType":"auth","description":`+jsonString(hostile("ci "))+`,
		"created":"2026-10-01T00:00:00Z","expires":"2027-01-01T00:00:00Z","invalid":false,"userId":"u1","scopes":["devices:core"],"tags":["tag:ci"],
		"capabilities":{"devices":{"create":{"reusable":true,"ephemeral":true,"preauthorized":false,"tags":["tag:ci"]}}}}`)
	var k tools.Key
	s := mustCall(t, reg, env, "key_get", `{"id":"k1"}`, &k)
	absent(t, s, "KEY-MATERIAL-CANARY")
	if reqs := f.Requests(); len(reqs) != 1 || reqs[0].Path != tailnetPath+"/keys/k1" {
		t.Fatalf("requests = %+v", reqs)
	}
	shownHostile(t, "description", "ci ", k.Description)
	if k.ID != "k1" || k.KeyType != "auth" || k.Created != "2026-10-01T00:00:00Z" ||
		k.Expires != "2027-01-01T00:00:00Z" || k.Invalid || k.UserID != "u1" ||
		!slices.Equal(k.Scopes, []string{"devices:core"}) || !slices.Equal(k.Tags, []string{"tag:ci"}) {
		t.Errorf("key = %+v", k)
	}
	if c := k.AuthKeyCapabilities; c == nil || !c.Reusable || !c.Ephemeral || c.Preauthorized || !slices.Equal(c.Tags, []string{"tag:ci"}) {
		t.Errorf("capabilities = %+v", k.AuthKeyCapabilities)
	}
}

// Coverage follows the scope forms the API grants: the read form of each key type, the bare
// form (which also reads), and all or all:read.
func TestKeysListCoverageCountsEveryScopeForm(t *testing.T) {
	all := []string{"api", "auth", "client", "federated"}
	for _, c := range []struct {
		scope   string
		visible []string
	}{
		{"auth_keys", []string{"auth"}},
		{"oauth_keys", []string{"client"}},
		{"federated_keys", []string{"federated"}},
		{"api_access_tokens", []string{"api"}},
		{"oauth_keys:read federated_keys", []string{"client", "federated"}},
		{"all", all},
		{"all:read", all},
		{"devices:core:read", nil},
		{"auth_keys:write", nil},
	} {
		f, reg, env := apiEnv(t)
		f.Scope = c.scope
		f.JSON("GET", tailnetPath+"/keys", 200, `{"keys":[]}`)
		var out tools.KeysListOutput
		mustCall(t, reg, env, "keys_list", `{}`, &out)
		var visible []string
		for typ, v := range out.Coverage {
			if v == "visible" {
				visible = append(visible, typ)
			}
		}
		slices.Sort(visible)
		if !slices.Equal(visible, c.visible) {
			t.Errorf("scope %q: visible %v, want %v (coverage %v)", c.scope, visible, c.visible, out.Coverage)
		}
		if complete := len(c.visible) == len(all); out.Complete == nil || *out.Complete != complete {
			t.Errorf("scope %q: complete = %v, want %v", c.scope, out.Complete != nil && *out.Complete, complete)
		}
	}
}

// Posture status is read back whole, and the text of a posture integration, a webhook, a
// service and an OAuth app is escaped and cut like the text of any untrusted field.
func TestIntegrationTextIsEscapedAndPostureStatusIsReadBack(t *testing.T) {
	f, reg, env := apiEnv(t)
	shown := show(env)
	posture := `{"id":"p1","provider":"intune","cloudId":` + jsonString(hostile("cloud")) + `,"clientId":` + jsonString(hostile("client")) +
		`,"tenantId":` + jsonString(hostile("tenant")) + `,"configUpdated":"2026-10-01T00:00:00Z",
		"status":{"lastSync":"2026-10-10T10:00:00Z","error":` + jsonString(hostile("sync ")) + `,"providerHostCount":7,"matchedCount":3,"possibleMatchedCount":2}}`
	f.JSON("GET", tailnetPath+"/posture/integrations", 200, `{"integrations":[`+posture+`]}`)
	f.JSON("GET", "/api/v2/posture/integrations/p1", 200, posture)
	hook := `{"endpointId":"w1","endpointUrl":"https://hooks.example.test/x","providerType":"slack","creatorLoginName":` + jsonString(hostile("hooker")) + `,"subscriptions":["nodeCreated"]}`
	f.JSON("GET", tailnetPath+"/webhooks", 200, `{"webhooks":[`+hook+`]}`)
	f.JSON("GET", "/api/v2/webhooks/w1", 200, hook)
	service := `{"name":` + jsonString(hostile("svc:")) + `,"displayName":` + jsonString(hostile("disp")) + `,"comment":` + jsonString(hostile("note")) +
		`,"ports":[` + jsonString(hostile("tcp:")) + `],"tags":[` + jsonString(hostile("tag:")) + `],"addrs":["100.100.1.1"]}`
	f.JSON("GET", tailnetPath+"/services", 200, `{"vipServices":[`+service+`]}`)
	f.JSON("GET", tailnetPath+"/services/svc:web", 200, service)
	app := `{"id":"a1","name":` + jsonString(hostile("app")) + `,"description":` + jsonString(hostile("desc")) + `,"redirectURIs":[` + jsonString(hostile("https://app.example.test/")) +
		`],"allowedNodeAttributes":[` + jsonString(hostile("attr")) + `],"scopes":["devices:core:read"]}`
	f.JSON("GET", tailnetPath+"/oauth-apps", 200, `{"oauthApps":[`+app+`]}`)
	f.JSON("GET", tailnetPath+"/oauth-apps/a1", 200, app)

	wantPosture := func(where string, p tools.PostureIntegration) {
		t.Helper()
		shownHostile(t, where+" cloudId", "cloud", p.CloudID)
		shownHostile(t, where+" clientId", "client", p.ClientID)
		shownHostile(t, where+" tenantId", "tenant", p.TenantID)
		st := p.Status
		if st == nil || st.LastSync != "2026-10-10T10:00:00Z" || st.ProviderHostCount != 7 || st.MatchedCount != 3 || st.PossibleMatchedCount != 2 {
			t.Fatalf("%s: status = %+v, want it read back whole", where, st)
		}
		shownHostile(t, where+" status.error", "sync ", st.Error)
	}
	var pl tools.PostureIntegrationsOutput
	mustCall(t, reg, shown, "posture_integrations_list", `{}`, &pl)
	if len(pl.Integrations) != 1 {
		t.Fatalf("posture list = %+v", pl)
	}
	wantPosture("list", pl.Integrations[0])
	var pg tools.PostureIntegration
	mustCall(t, reg, shown, "posture_integration_get", `{"id":"p1"}`, &pg)
	wantPosture("get", pg)

	var wl tools.WebhooksOutput
	mustCall(t, reg, shown, "webhooks_list", `{}`, &wl)
	shownHostile(t, "webhooks_list creatorLoginName", "hooker", wl.Webhooks[0].CreatorLoginName)
	var wg tools.Webhook
	mustCall(t, reg, shown, "webhook_get", `{"id":"w1"}`, &wg)
	shownHostile(t, "webhook_get creatorLoginName", "hooker", wg.CreatorLoginName)

	wantService := func(where string, s tools.Service) {
		t.Helper()
		if len(s.Ports) != 1 || len(s.Tags) != 1 {
			t.Fatalf("%s: service = %+v", where, s)
		}
		shownHostile(t, where+" name", "svc:", s.Name)
		shownHostile(t, where+" displayName", "disp", s.DisplayName)
		shownHostile(t, where+" comment", "note", s.Comment)
		shownHostile(t, where+" ports[]", "tcp:", s.Ports[0])
		shownHostile(t, where+" tags[]", "tag:", s.Tags[0])
	}
	var sl tools.ServicesOutput
	mustCall(t, reg, env, "services_list", `{}`, &sl)
	wantService("list", sl.Services[0])
	var sg tools.Service
	mustCall(t, reg, env, "service_get", `{"name":"svc:web"}`, &sg)
	wantService("get", sg)

	wantApp := func(where string, a tools.OAuthApp) {
		t.Helper()
		if len(a.RedirectURIs) != 1 || len(a.AllowedNodeAttributes) != 1 {
			t.Fatalf("%s: app = %+v", where, a)
		}
		shownHostile(t, where+" name", "app", a.Name)
		shownHostile(t, where+" description", "desc", a.Description)
		shownHostile(t, where+" redirectURIs[]", "https://app.example.test/", a.RedirectURIs[0])
		shownHostile(t, where+" allowedNodeAttributes[]", "attr", a.AllowedNodeAttributes[0])
	}
	var al tools.OAuthAppsOutput
	mustCall(t, reg, env, "oauth_apps_list", `{}`, &al)
	wantApp("list", al.Apps[0])
	var ag tools.OAuthApp
	mustCall(t, reg, env, "oauth_app_get", `{"id":"a1"}`, &ag)
	wantApp("get", ag)

	// Masked, no raw control character survives in the personal field either.
	mustCall(t, reg, env, "webhooks_list", `{}`, &wl)
	if got := wl.Webhooks[0].CreatorLoginName; strings.ContainsRune(got, 0x1B) || len(got) > registry.ResultStringMax {
		t.Errorf("masked creatorLoginName = %.60q", got)
	}
}
