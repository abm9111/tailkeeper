package tools_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// show returns a copy of env whose owner opted in to unmasked personal data.
func show(env *registry.Env) *registry.Env {
	e := *env
	e.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
	return &e
}

// Every tool that returns a login name, display name or email address masks it
// unless the owner set "personalData": "show" (spec Appendix C).
func TestIdentifiersAreMaskedUnlessTheOwnerOptsIn(t *testing.T) {
	f, reg, env := apiEnv(t)
	const amy = `"amy@example.com"`
	f.JSON("GET", tailnetPath+"/devices", 200, `{"devices":[{"id":"1","nodeId":"nAAA1CNTRL","name":"a.example.ts.net","hostname":"a","user":`+amy+`}]}`)
	f.JSON("GET", tailnetPath+"/users", 200, `{"users":[{"id":"u1","loginName":`+amy+`,"displayName":"Amy Lee","tailnetId":"T1234CNTRL"}]}`)
	f.JSON("GET", "/api/v2/users/u1", 200, `{"id":"u1","loginName":`+amy+`,"displayName":"Amy Lee"}`)
	f.JSON("GET", tailnetPath+"/contacts", 200, `{"account":{"email":`+amy+`},"security":{"email":`+amy+`,"fallbackEmail":`+amy+`,"needsVerification":false}}`)
	f.JSON("GET", tailnetPath+"/user-invites", 200, `[{"id":"ui1","role":"member","email":`+amy+`}]`)
	f.JSON("GET", "/api/v2/user-invites/ui1", 200, `{"id":"ui1","role":"member","email":`+amy+`}`)
	f.JSON("GET", "/api/v2/device/nAAA1CNTRL/device-invites", 200, `[{"id":"di1","email":`+amy+`,"accepted":true,"acceptedBy":{"id":2,"loginName":`+amy+`}}]`)
	f.JSON("GET", "/api/v2/device-invites/di1", 200, `{"id":"di1","email":`+amy+`,"accepted":true,"acceptedBy":{"id":2,"loginName":`+amy+`}}`)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE",
		"action":"UPDATE","actor":{"id":"u1","loginName":`+amy+`,"displayName":"Amy Lee"},"target":{"name":"e1"}}]}`)
	f.JSON("GET", tailnetPath+"/logging/network/stream", 200, `{"destinationType":"elastic","url":"https://logs.example.com/x","user":`+amy+`}`)
	webhook := `{"endpointId":"w1","endpointUrl":"https://hooks.example.test/x","providerType":"slack","creatorLoginName":` + amy + `,"subscriptions":["nodeCreated"]}`
	f.JSON("GET", tailnetPath+"/webhooks", 200, `{"webhooks":[`+webhook+`]}`)
	f.JSON("GET", "/api/v2/webhooks/w1", 200, webhook)
	for _, c := range []struct {
		tool, args string
		n          int // identifiers in the result
	}{
		{"devices_list", `{}`, 1},
		{"users_list", `{}`, 2},
		{"user_get", `{"id":"u1"}`, 2},
		{"contacts_get", `{}`, 3},
		{"user_invites_list", `{}`, 1},
		{"user_invite_get", `{"id":"ui1"}`, 1},
		{"device_invites_list", `{"device":"nAAA1CNTRL"}`, 2},
		{"device_invite_get", `{"id":"di1"}`, 2},
		{"audit_log", `{}`, 2},
		{"log_streaming_get", `{"logType":"network"}`, 1},
		{"webhooks_list", `{}`, 1},
		{"webhook_get", `{"id":"w1"}`, 1},
	} {
		masked := mustCall(t, reg, env, c.tool, c.args, nil)
		absent(t, masked, "amy@", "Amy Lee")
		if got := strings.Count(masked, `"a…@example.com"`) + strings.Count(masked, `"A…"`); got != c.n {
			t.Errorf("%s: %d identifiers masked, want %d: %s", c.tool, got, c.n, masked)
		}
		shown := mustCall(t, reg, show(env), c.tool, c.args, nil)
		if got := strings.Count(shown, amy) + strings.Count(shown, `"Amy Lee"`); got != c.n {
			t.Errorf("%s with personalData show: %d identifiers whole, want %d: %s", c.tool, got, c.n, shown)
		}
	}
	// The tailnet ID is masked too: CLAUDE.md keeps it out of transcripts.
	if users := mustCall(t, reg, env, "users_list", `{}`, nil); strings.Contains(users, "T1234CNTRL") || !strings.Contains(users, `"tailnetId":"T…"`) {
		t.Errorf("users_list tailnetId: %s", users)
	}
	// Facts derived from a contact stay correct: they are computed before masking.
	var contacts tools.ContactsOutput
	mustCall(t, reg, env, "contacts_get", `{}`, &contacts)
	if !contacts.SecurityContactOK {
		t.Errorf("securityContactOk = false for a verified security contact")
	}
}

func TestLocalIdentitiesAndTailnetNameAreMasked(t *testing.T) {
	identity := `{"Node":{"ID":1,"StableID":"nSELFCNTRL","Name":"me.example.ts.net.","Addresses":["100.64.0.10/32"]},
		"UserProfile":{"ID":7,"LoginName":"amy@example.com","DisplayName":"Amy Lee"}}`
	cli := newFakeCLI(t)
	cli.on("whoami --json", 0, identity, "")
	cli.on("whois --json 100.64.0.10", 0, identity, "")
	cli.on("status --json --peers=false", 0, statusFixture(false), "")
	reg, env := newRegistry(t), cli.env()
	for _, tool := range [][2]string{{"local_whoami", `{}`}, {"local_whois", `{"address":"100.64.0.10"}`}, {"local_status", `{}`}} {
		masked := mustCall(t, reg, env, tool[0], tool[1], nil)
		absent(t, masked, "amy@", "Amy Lee")
		if !strings.Contains(masked, `"a…@example.com"`) {
			t.Errorf("%s: no masked login in %s", tool[0], masked)
		}
		if shown := mustCall(t, reg, show(env), tool[0], tool[1], nil); !strings.Contains(shown, `"amy@example.com"`) {
			t.Errorf("%s with personalData show: %s", tool[0], shown)
		}
	}
}

// Public addresses in health messages, DNS errors and flow endpoints are cut to
// their network unless the owner opts in; tailnet and private ones are kept.
func TestPublicAddressesAreCutUnlessTheOwnerOptsIn(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/settings", 200, `{"networkFlowLoggingOn":true}`)
	f.JSON("GET", tailnetPath+"/logging/network", 200, `{"logs":[{"nodeId":"nAAA1CNTRL","logged":"2026-10-10T11:59:00Z",
		"virtualTraffic":[{"proto":6,"src":"100.64.0.1:5000","dst":"100.64.0.2:443"}],
		"exitTraffic":[{"proto":6,"src":"100.64.0.1:5001","dst":"198.51.100.80:443"}],
		"physicalTraffic":[{"src":"100.64.0.1:0","dst":"203.0.113.9:41641"}]}]}`)
	var out tools.FlowLogsOutput
	mustCall(t, reg, env, "network_flow_logs", `{}`, &out)
	var got []string
	for _, fl := range out.Records[0].Flows {
		got = append(got, fl.Src+">"+fl.Dst)
	}
	want := []string{"100.64.0.1:5000>100.64.0.2:443", "100.64.0.1:5001>198.51.100.0/24:443", "100.64.0.1:0>203.0.113.0/24:41641"}
	if !slices.Equal(got, want) {
		t.Errorf("flows = %q, want %q", got, want)
	}
	if shown := mustCall(t, reg, show(env), "network_flow_logs", `{}`, nil); !strings.Contains(shown, "198.51.100.80:443") || !strings.Contains(shown, "203.0.113.9:41641") {
		t.Errorf("with personalData show: %s", shown)
	}

	cli := newFakeCLI(t)
	health := `"could not reach 203.0.113.9:3478 from 192.168.1.20"`
	cli.on("status --json --peers=false", 0, strings.Replace(statusFixture(false), `"Health":[`, `"Health":[`+health+`,`, 1), "")
	cli.on("dns status --json", 0, `{"TailscaleDNS":true,"SystemDNSError":"8.8.4.4:53 refused; 10.0.0.53 ok"}`, "")
	lreg, lenv := newRegistry(t), cli.env()
	var st tools.LocalStatusOutput
	mustCall(t, lreg, lenv, "local_status", `{}`, &st)
	if len(st.Health) == 0 || st.Health[0] != "could not reach 203.0.113.0/24:3478 from 192.168.1.20" {
		t.Errorf("health = %q", st.Health)
	}
	var dns tools.LocalDNSStatusOutput
	mustCall(t, lreg, lenv, "local_dns_status", `{}`, &dns)
	if dns.SystemDNSError != "8.8.4.0/24:53 refused; 10.0.0.53 ok" {
		t.Errorf("systemDnsError = %q", dns.SystemDNSError)
	}
}

// Untrusted free text is masked by default: an email or public address in any
// of it comes back cut, whatever the field is called.
func TestFreeTextIsMaskedByDefault(t *testing.T) {
	f, reg, env := apiEnv(t)
	text := `"Owen (owner@example.com) changed amy@example.com from 203.0.113.9"`
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE",
		"action":"UPDATE","target":{"id":"u1","name":"amy@example.com","type":"USER"},"actionDetails":`+text+`,"error":`+text+`,
		"old":{"acls":[{"src":["amy@example.com"],"dst":["203.0.113.9:22"]}]},"new":`+text+`}]}`)
	f.JSON("GET", tailnetPath+"/keys", 200, `{"keys":[{"id":"k1","keyType":"federated","description":`+text+`,
		"subject":"amy@example.com","customClaimRules":{"email":"amy@example.com"}}]}`)
	f.JSON("GET", tailnetPath+"/posture/integrations", 200, `{"integrations":[{"id":"p1","provider":"intune","status":{"error":`+text+`}}]}`)
	f.JSON("GET", tailnetPath+"/logging/network/stream", 200, `{"destinationType":"elastic","url":"https://logs.example.com"}`)
	f.JSON("GET", tailnetPath+"/logging/network/stream/status", 200, `{"lastError":`+text+`}`)
	for _, c := range [][2]string{
		{"audit_log", `{"includeValues":true}`}, {"keys_list", `{}`}, {"posture_integrations_list", `{}`},
		{"log_streaming_get", `{"logType":"network"}`},
	} {
		masked := mustCall(t, reg, env, c[0], c[1], nil)
		absent(t, masked, "amy@", "owner@", "203.0.113.9")
		if !strings.Contains(masked, "a…@example.com") || !strings.Contains(masked, "o…@example.com") && c[0] != "keys_list" && c[0] != "audit_log" {
			t.Errorf("%s: nothing masked in %s", c[0], masked)
		}
		if shown := mustCall(t, reg, show(env), c[0], c[1], nil); !strings.Contains(shown, "amy@example.com") {
			t.Errorf("%s with personalData show: %s", c[0], shown)
		}
	}
}

// Untrusted text tagged plain is configuration a diagnosis needs whole: DNS
// resolvers, routes, a webhook's host, local preferences.
func TestPlainConfigurationKeepsItsAddresses(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/dns/configuration", 200, `{"nameservers":[{"address":"8.8.8.8"}],"preferences":{"magicDNS":true}}`)
	f.JSON("GET", tailnetPath+"/webhooks", 200, `{"webhooks":[{"endpointId":"w1","endpointUrl":"https://198.51.100.7/hook","providerType":"generic"}]}`)
	f.JSON("GET", tailnetPath+"/devices", 200, `{"devices":[{"nodeId":"nAAA1CNTRL","name":"a.example.ts.net","advertisedRoutes":["198.51.100.7/32"],"enabledRoutes":["198.51.100.7/32"]}]}`)
	f.JSON("GET", "/api/v2/device/nAAA1CNTRL/routes", 200, `{"advertisedRoutes":["198.51.100.7/32","203.0.113.5/32"],"enabledRoutes":["198.51.100.7/32"]}`)
	f.JSON("GET", tailnetPath+"/settings", 200, `{"aclsExternalLink":"https://198.51.100.7:8443/policy"}`)
	for tool, want := range map[string]string{"dns_get": `"8.8.8.8"`, "webhooks_list": `"https://198.51.100.7"`, "devices_list": `"198.51.100.7/32"`,
		"device_routes": `"pending":["203.0.113.5/32"]`, "settings_get": `"https://198.51.100.7:8443/policy"`} {
		args := `{}`
		switch tool {
		case "devices_list":
			args = `{"allFields":true}`
		case "device_routes":
			args = `{"device":"nAAA1CNTRL"}`
		}
		if out := mustCall(t, reg, env, tool, args, nil); !strings.Contains(out, want) {
			t.Errorf("%s: %s lost %s", tool, out, want)
		}
	}
	cli := newFakeCLI(t)
	cli.on("get --json", 0, `{"advertise-routes":["198.51.100.7/32"],"operator":"amylee","nickname":"Amy","hostname":"amys-laptop"}`, "")
	cli.on("dns status --json", 0, `{"TailscaleDNS":true,"Resolvers":[{"Addr":"203.0.113.53"}],"SystemDNS":{"Nameservers":["198.51.100.1"]}}`, "")
	cli.on("status --json --peers=false", 0, statusFixture(false), "")
	cli.on("dns query --json www.corp.example A", 0, `{"Name":"www.corp.example.","QueryType":"A","ResponseCode":"RCodeSuccess",
		"Answers":[{"Name":"www.corp.example.","TTL":60,"Class":"ClassINET","Type":"TypeA","Body":"203.0.113.5"}]}`, "")
	lreg, lenv := newRegistry(t), cli.env()
	lenv.Config = &config.Loaded{Config: config.Config{Local: config.Local{DNSQueryAllowlist: []string{".corp.example"}}}}
	if answer := mustCall(t, lreg, lenv, "local_dns_query", `{"name":"www.corp.example"}`, nil); !strings.Contains(answer, `"203.0.113.5"`) {
		t.Errorf("local_dns_query = %s", answer)
	}
	var prefs tools.PrefsOutput
	mustCall(t, lreg, lenv, "local_prefs", `{}`, &prefs)
	got := map[string]string{}
	for _, p := range prefs.Prefs {
		got[p.Name] = p.Value
	}
	if got["advertise-routes"] != "198.51.100.7/32" || got["hostname"] != "amys-laptop" || got["operator"] != "a…" || got["nickname"] != "A…" {
		t.Errorf("prefs = %v", got)
	}
	var shownPrefs tools.PrefsOutput
	mustCall(t, lreg, show(lenv), "local_prefs", `{}`, &shownPrefs)
	for _, p := range shownPrefs.Prefs {
		if p.Name == "operator" && p.Value != "amylee" {
			t.Errorf("operator with personalData show = %q", p.Value)
		}
	}
	if dns := mustCall(t, lreg, lenv, "local_dns_status", `{}`, nil); !strings.Contains(dns, "203.0.113.53") || !strings.Contains(dns, "198.51.100.1") {
		t.Errorf("local_dns_status = %s", dns)
	}
}

// The class, not the instances: an output field named like a person's
// identifier must be tagged personal, or a new tool would return it whole.
func TestEveryIdentifierFieldIsTaggedPersonal(t *testing.T) {
	// A field is an identifier when its name contains one of these, ignoring case,
	// or is exactly user or tailnetId. (A tailnet's name is an organisation's domain,
	// or for a personal tailnet the owner's login, which free-text masking finds.)
	parts := []string{"login", "email", "displayname", "creator", "owner", "author", "nickname"}
	exact := map[string]bool{"user": true, "tailnetid": true}
	// Fields with such names that name no person.
	notPersonal := map[reflect.Type]map[string]bool{
		reflect.TypeFor[tools.ACLSummary]():   {"tagOwners": true},       // the tags a policy defines, which name no person
		reflect.TypeFor[tools.Service]():      {"displayName": true},     // a service's label
		reflect.TypeFor[tools.DeviceInvite](): {"lastEmailSentAt": true}, // a time
		reflect.TypeFor[tools.UserInvite]():   {"lastEmailSentAt": true},
	}
	identifier := func(name string) bool {
		n := strings.ToLower(name)
		if exact[n] {
			return true
		}
		for _, p := range parts {
			if strings.Contains(n, p) {
				return true
			}
		}
		return false
	}
	for _, tool := range newRegistry(t).All() {
		var walk func(typ reflect.Type, prefix string, seen map[reflect.Type]bool)
		walk = func(typ reflect.Type, prefix string, seen map[reflect.Type]bool) {
			for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
				if typ.Kind() != reflect.Pointer {
					prefix += "[]"
				}
				typ = typ.Elem()
			}
			if typ.Kind() != reflect.Struct || seen[typ] {
				return
			}
			seen[typ] = true
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				name := strings.Split(f.Tag.Get("json"), ",")[0]
				path := name
				if prefix != "" {
					path = prefix + "." + name
				}
				str := f.Type.Kind() == reflect.String || (f.Type.Kind() == reflect.Slice || f.Type.Kind() == reflect.Pointer) && f.Type.Elem().Kind() == reflect.String
				// A number cannot be masked, so a field named like the tailnet ID must not be one.
				if (str || exact[strings.ToLower(name)]) && identifier(name) && !notPersonal[typ][name] && !slices.Contains(tool.PersonalFields, path) {
					t.Errorf("%s: output field %s is not tagged personal", tool.Meta.Name, path)
				}
				walk(f.Type, path, seen)
			}
		}
		walk(tool.OutputType, "", map[reflect.Type]bool{})
	}
}

// A long health message is masked before any cap cuts it: an address cut short
// would no longer parse, and would show more of itself than its network.
func TestLongHealthMessagesAreMaskedBeforeTheyAreCut(t *testing.T) {
	health := strings.Repeat("x", 484) + " 2001:db8:1:2:3:4:5:6 " + strings.Repeat("y", 600)
	cli := newFakeCLI(t)
	cli.on("status --json --peers=false", 0, strings.Replace(statusFixture(false), `"Health":[`, `"Health":[`+jsonString(health)+`,`, 1), "")
	var st tools.LocalStatusOutput
	mustCall(t, newRegistry(t), cli.env(), "local_status", `{}`, &st)
	if len(st.Health) == 0 || strings.Contains(st.Health[0], "2001:db8:1:2") || !strings.Contains(st.Health[0], " 2001:db8:1::/48 ") {
		t.Errorf("health = %q", st.Health)
	}
}

// Errors are masked before any cap cuts them: the API client and the local runner
// cut long messages too, but past the registry's cap, never before it.
func TestLongErrorsAreMaskedBeforeTheyAreCut(t *testing.T) {
	long := strings.Repeat("x", 480) + " 2001:db8:1:2:3:4:5:6 " + strings.Repeat("y", 600)
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/devices", 400, `{"message":`+jsonString(long)+`}`)
	cli := newFakeCLI(t)
	cli.on("status --json --peers=false", 1, "", "ping failed: "+long[300:])
	for name, err := range map[string]error{
		"api":   func() error { _, err := call(t, reg, env, "devices_list", `{}`); return err }(),
		"local": func() error { _, err := call(t, newRegistry(t), cli.env(), "local_status", `{}`); return err }(),
	} {
		if err == nil || strings.Contains(err.Error(), "2001:db8:1:2") || !strings.Contains(err.Error(), "2001:db8:1::/48") {
			t.Errorf("%s error = %v", name, err)
		}
	}
}

// An organisation's tailnet name is a domain and stays whole; a personal
// tailnet's name is the owner's login and is masked as an email address.
func TestTailnetNameIsMaskedOnlyWhenItIsALogin(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("status --json --peers=false", 0, strings.Replace(statusFixture(false), `"Name":"amy@example.com"`, `"Name":"example.com"`, 1), "")
	var st tools.LocalStatusOutput
	mustCall(t, newRegistry(t), cli.env(), "local_status", `{}`, &st)
	if st.Tailnet != "example.com" {
		t.Errorf("tailnet = %q", st.Tailnet)
	}
}

// The tailnet ID is personal data (spec Appendix C; users_list masks it): the
// invite tools must not return it as a number either.
func TestInviteToolsDoNotReturnTheTailnetID(t *testing.T) {
	f, reg, env := apiEnv(t)
	const id = "1234567"
	f.JSON("GET", tailnetPath+"/user-invites", 200, `[{"id":"ui1","role":"member","tailnetId":`+id+`,"inviterId":77,"email":"amy@example.com"}]`)
	f.JSON("GET", "/api/v2/user-invites/ui1", 200, `{"id":"ui1","role":"member","tailnetId":`+id+`,"inviterId":77,"email":"amy@example.com"}`)
	f.JSON("GET", "/api/v2/device/nAAA1CNTRL/device-invites", 200, `[{"id":"di1","tailnetId":`+id+`,"deviceId":1001,"sharerId":77,"email":"amy@example.com"}]`)
	f.JSON("GET", "/api/v2/device-invites/di1", 200, `{"id":"di1","tailnetId":`+id+`,"deviceId":1001,"sharerId":77,"email":"amy@example.com"}`)
	for tool, args := range map[string]string{
		"user_invites_list": `{}`, "user_invite_get": `{"id":"ui1"}`,
		"device_invites_list": `{"device":"nAAA1CNTRL"}`, "device_invite_get": `{"id":"di1"}`,
	} {
		for mode, e := range map[string]*registry.Env{"masked": env, "shown": show(env)} {
			out := mustCall(t, reg, e, tool, args, nil)
			if strings.Contains(out, id) || strings.Contains(out, "tailnetId") {
				t.Errorf("%s (%s) returns the tailnet ID: %s", tool, mode, out)
			}
			// The control: the invite did reach the result, so the ID's absence is the tool's doing.
			if !strings.Contains(out, `"email":"`) {
				t.Errorf("%s (%s) returned no invite: %s", tool, mode, out)
			}
		}
	}
}

// Text from the tailnet reaches a result masked in the forms a URL and a control
// character give an address: nothing of amy shows.
func TestFreeTextMasksPercentEncodedAndControlCharacterAddresses(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE",
		"actor":{"id":"u1"},"target":{"id":"t1","name":"https://example.com/?u=amy%40example.com"},
		"actionDetails":"hint amy\u0001@example.com and ipv6:2001:db8:1::5","old":"mailto:amy%40example.com"}]}`)
	out := mustCall(t, reg, env, "audit_log", `{"includeValues":true}`, nil)
	absent(t, out, "amy", "2001:db8:1::5")
	// The control: with masking off the same entry shows all of it, so the text did
	// reach the result and it is the mask that removed it.
	shown := mustCall(t, reg, show(env), "audit_log", `{"includeValues":true}`, nil)
	for _, want := range []string{"amy%40example.com", "2001:db8:1::5", "amy"} {
		if !strings.Contains(shown, want) {
			t.Errorf("with masking off the result lacks %q: %s", want, shown)
		}
	}
}
