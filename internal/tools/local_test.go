package tools_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// The fixtures below follow the CLI's JSON shapes (tailscale.com v1.104 source,
// checked against a 1.102 client). Addresses are from documentation ranges;
// strings containing CANARY must never reach tool output.

func statusFixture(withPeers bool) string {
	peers := `null`
	if withPeers {
		peers = `{
 "nodekey:a":{"ID":"nP1CNTRL","HostName":"direct-peer","DNSName":"direct-peer.example.ts.net.","OS":"linux","TailscaleIPs":["100.64.0.11"],
  "Addrs":["203.0.113.9:41641"],"CurAddr":"203.0.113.9:41641","Relay":"fra","Online":true,"Active":true,"LastHandshake":"2026-10-10T11:59:00Z"},
 "nodekey:b":{"ID":"nP2CNTRL","HostName":"derp-peer","DNSName":"derp-peer.example.ts.net.","OS":"macOS","TailscaleIPs":["100.64.0.12"],
  "CurAddr":"","Relay":"nyc","Online":true,"Active":true,"LastHandshake":"0001-01-01T00:00:00Z"},
 "nodekey:c":{"ID":"nP3CNTRL","HostName":"relay-peer","DNSName":"relay-peer.example.ts.net.","OS":"linux","TailscaleIPs":["100.64.0.13"],
  "CurAddr":"","PeerRelay":"198.51.100.4:7777:12","Relay":"fra","Online":true,"Active":true},
 "nodekey:d":{"ID":"nP4CNTRL","HostName":"idle-peer","DNSName":"idle-peer.example.ts.net.","OS":"windows","TailscaleIPs":["100.64.0.14"],
  "Relay":"nyc","Online":false,"Active":false}}`
	}
	return `{"Version":"1.102.4-tTEST","BackendState":"Running","AuthURL":"","TailscaleIPs":["100.64.0.10"],
 "Self":{"ID":"nSELFCNTRL","HostName":"me","DNSName":"me.example.ts.net.","OS":"macOS","TailscaleIPs":["100.64.0.10"],
  "Addrs":["203.0.113.50:41641"],"CurAddr":"","Relay":"fra","Online":true},
 "Health":[` + jsonString("warning"+r(0x1B)+"[2J") + `],"MagicDNSSuffix":"example.ts.net",
 "CurrentTailnet":{"Name":"amy@example.com","MagicDNSSuffix":"example.ts.net","MagicDNSEnabled":true},
 "Peer":` + peers + `}`
}

func TestLocalStatusClassifiesPathsAndHidesEndpoints(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("status --json --peers=true", 0, statusFixture(true), "")
	reg, env := newRegistry(t), cli.env()
	var out tools.LocalStatusOutput
	s := mustCall(t, reg, env, "local_status", `{"peers":true}`, &out)
	absent(t, s, "203.0.113.", "198.51.100.4")
	paths := map[string]string{}
	for _, p := range out.Peers {
		paths[p.HostName] = p.Path
	}
	want := map[string]string{"direct-peer": "direct", "derp-peer": "derp", "relay-peer": "peer-relay", "idle-peer": "none"}
	for host, w := range want {
		if paths[host] != w {
			t.Errorf("%s path = %q, want %q", host, paths[host], w)
		}
	}
	if out.PeerCount != 4 || out.PeerScope != "network_map" || out.Self == nil || out.Self.Path != "" || !out.MagicDNSEnabled || out.NeedsLogin {
		t.Errorf("status = %+v", out)
	}
	if out.Health[0] != `warning\u{001B}[2J` {
		t.Errorf("health = %q", out.Health)
	}
	for _, p := range out.Peers {
		if p.HostName == "derp-peer" && p.LastHandshake != "" {
			t.Errorf("zero handshake time shown as %q", p.LastHandshake)
		}
	}
}

func TestLocalStatusNeedsLoginHidesAuthURL(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("status --json --peers=false", 0, `{"BackendState":"NeedsLogin","AuthURL":"https://login.example.test/a/LOGIN-CANARY"}`, "")
	var out tools.LocalStatusOutput
	s := mustCall(t, newRegistry(t), cli.env(), "local_status", `{}`, &out)
	absent(t, s, "CANARY")
	if !out.NeedsLogin {
		t.Error("needsLogin = false")
	}
}

func TestLocalDaemonUnreachable(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("status --json --peers=false", 1, "", "failed to connect to local tailscaled; it doesn't appear to be running")
	if _, err := call(t, newRegistry(t), cli.env(), "local_status", `{}`); code(err) != tkerr.LocalDaemonUnreachable {
		t.Errorf("err = %v", err)
	}
}

func TestLocalNetcheckRequiresDaemonAndDropsPublicIPs(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("status --json --peers=false", 0, statusFixture(false), "")
	cli.on("netcheck --format=json", 0, `{"UDP":true,"IPv4":true,"GlobalV4":"203.0.113.77:1234","GlobalV6":"[2001:db8::77]:1234",
		"GlobalV4Counters":{"203.0.113.77:1234":3},"MappingVariesByDestIP":false,"UPnP":null,"PMP":false,"PCP":true,
		"PreferredDERP":1,"RegionLatency":{"1":12000000,"2":95500000}}`, "")
	var out tools.NetcheckOutput
	s := mustCall(t, newRegistry(t), cli.env(), "local_netcheck", `{}`, &out)
	absent(t, s, "203.0.113.77", "2001:db8::77")
	if got := cli.calls(); !slices.Equal(got, []string{"status --json --peers=false", "netcheck --format=json"}) {
		t.Errorf("calls = %v", got)
	}
	if out.UPnP != nil || out.PMP == nil || *out.PMP || out.PCP == nil || !*out.PCP {
		t.Errorf("unknown must stay unknown: upnp=%v pmp=%v pcp=%v", out.UPnP, out.PMP, out.PCP)
	}
	if out.RegionLatencyMs["1"] != 12 || out.RegionLatencyMs["2"] != 95.5 {
		t.Errorf("latency = %v", out.RegionLatencyMs)
	}

	down := newFakeCLI(t)
	down.on("status --json --peers=false", 1, "", "failed to connect to local tailscaled")
	if _, err := call(t, newRegistry(t), down.env(), "local_netcheck", `{}`); code(err) != tkerr.LocalDaemonUnreachable {
		t.Errorf("err = %v", err)
	}
	if got := down.calls(); len(got) != 1 {
		t.Errorf("netcheck ran without a daemon: %v", got)
	}
}

func TestParsePing(t *testing.T) {
	out := `pong from peer (100.64.0.11) via DERP(fra) in 23ms
ping "100.64.0.11" timed out
pong from peer (100.64.0.11, 41234) via 192.0.2.10:41641 in 0s
pong from peer (100.64.0.11) via peer-relay(198.51.100.4:7777:12) in 1.2s
pong from peer (100.64.0.11) via TSMP in 4ms
something unexpected
`
	p := tools.ParsePing([]byte(out))
	if len(p.Replies) != 4 || p.Timeouts != 1 || !p.Direct || p.Unparsed != 1 {
		t.Fatalf("parsed = %+v", p)
	}
	want := []tools.PingReply{{Via: "derp", Region: "fra", LatencyMs: 23}, {Via: "direct", LatencyMs: 0},
		{Via: "peer-relay", LatencyMs: 1200}, {Via: "tsmp", LatencyMs: 4}}
	if !slices.Equal(p.Replies, want) {
		t.Errorf("replies = %+v", p.Replies)
	}
}

func TestLocalPingOutcomes(t *testing.T) {
	cli := newFakeCLI(t)
	args := "ping --c=3 --timeout=5s --until-direct=true 100.64.0.11"
	cli.on(args, 1, "pong from peer (100.64.0.11) via DERP(fra) in 23ms\n", "direct connection not established\n")
	var out tools.PingOutput
	s := mustCall(t, newRegistry(t), cli.env(), "local_ping", `{"target":"100.64.0.11"}`, &out)
	if !out.DirectNotEstablished || out.DirectEstablished || len(out.Replies) != 1 {
		t.Errorf("ping = %s", s)
	}

	unknown := newFakeCLI(t)
	unknown.on(args, 1, "", "no matching peer\n")
	if _, err := call(t, newRegistry(t), unknown.env(), "local_ping", `{"target":"100.64.0.11"}`); code(err) != tkerr.LocalCommandFailed {
		t.Errorf("unknown peer: err = %v", err)
	}
}

func TestLocalPingRefusesNonTailnetTargets(t *testing.T) {
	cli := newFakeCLI(t)
	reg := newRegistry(t)
	for _, args := range []string{`{"target":"8.8.8.8"}`, `{"target":"example.com"}`, `{"target":"-c"}`,
		`{"target":"100.64.0.11","count":11}`, `{"target":"100.64.0.11","mode":"udp"}`} {
		if _, err := call(t, reg, cli.env(), "local_ping", args); code(err) != tkerr.ValidationFailed {
			t.Errorf("%s: err = %v", args, err)
		}
	}
	if got := cli.calls(); len(got) != 0 {
		t.Errorf("the CLI ran for refused input: %v", got)
	}
}

func TestLocalDNSQueryAllowlist(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("status --json --peers=false", 0, statusFixture(false), "")
	cli.on("dns query --json web.example.ts.net A", 0, `{"Name":"web.example.ts.net.","QueryType":"A","ResponseCode":"RCodeSuccess",
		"Resolvers":[{"Addr":"100.100.100.100"}],"Answers":[{"Name":"web.example.ts.net.","TTL":600,"Class":"ClassINET","Type":"TypeA","Body":"100.64.0.20"}]}`, "")
	cli.on("dns query --json db.corp.example AAAA", 0, `{"Name":"db.corp.example.","QueryType":"AAAA","ResponseCode":"RCodeNameError"}`, "")
	reg, env := newRegistry(t), cli.env()
	env.Config = &config.Loaded{Config: config.Config{Local: config.Local{DNSQueryAllowlist: []string{".corp.example"}}}}

	var out tools.DNSQueryOutput
	mustCall(t, reg, env, "local_dns_query", `{"name":"WEB.example.ts.net."}`, &out)
	if len(out.Answers) != 1 || out.Answers[0].Type != "A" || out.Answers[0].Body != "100.64.0.20" {
		t.Errorf("answers = %+v", out.Answers)
	}
	mustCall(t, reg, env, "local_dns_query", `{"name":"db.corp.example","type":"aaaa"}`, nil)
	for _, args := range []string{`{"name":"example.com"}`, `{"name":"corp.example"}`, `{"name":"x.example.ts.net","type":"ANY"}`,
		`{"name":"bad name.example.ts.net"}`} {
		if _, err := call(t, reg, env, "local_dns_query", args); code(err) != tkerr.ValidationFailed {
			t.Errorf("%s: err = %v", args, err)
		}
	}
	for _, c := range cli.calls() {
		if strings.Contains(c, "example.com") || c == "dns query --json corp.example A" {
			t.Errorf("refused name reached the CLI: %s", c)
		}
	}
}

func TestLocalDNSQueryAllowlistBoundaries(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("status --json --peers=false", 0, statusFixture(false), "")
	cli.on("dns query --json example.ts.net A", 0, `{"Name":"example.ts.net.","QueryType":"A","ResponseCode":"RCodeSuccess"}`, "")
	cli.on("dns query --json exact.example A", 0, `{"Name":"exact.example.","QueryType":"A","ResponseCode":"RCodeSuccess"}`, "")
	reg, env := newRegistry(t), cli.env()
	env.Config = &config.Loaded{Config: config.Config{Local: config.Local{DNSQueryAllowlist: []string{".corp.example", "Exact.Example."}}}}
	for _, name := range []string{"example.ts.net", "exact.example"} {
		mustCall(t, reg, env, "local_dns_query", `{"name":"`+name+`"}`, nil)
	}
	// A shared string suffix is not a parent domain.
	for _, name := range []string{"xexample.ts.net", "ts.net", "evilcorp.example", "x.exact.example"} {
		if _, err := call(t, reg, env, "local_dns_query", `{"name":"`+name+`"}`); code(err) != tkerr.ValidationFailed {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// With MagicDNS off there is no suffix: only the allowlist counts.
	off := newFakeCLI(t)
	off.on("status --json --peers=false", 0, strings.ReplaceAll(statusFixture(false), `"MagicDNSSuffix":"example.ts.net"`, `"MagicDNSSuffix":""`), "")
	offEnv := off.env()
	offEnv.Config = env.Config
	if _, err := call(t, reg, offEnv, "local_dns_query", `{"name":"web.example.ts.net"}`); code(err) != tkerr.ValidationFailed {
		t.Errorf("MagicDNS off: err = %v", err)
	}
	for _, c := range append(cli.calls(), off.calls()...) {
		if strings.HasPrefix(c, "dns query") && c != "dns query --json example.ts.net A" && c != "dns query --json exact.example A" {
			t.Errorf("refused name reached the CLI: %s", c)
		}
	}
}

func TestLocalIPAndMetricsRefuseEmptyOutput(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("ip", 0, "", "")
	cli.on("metrics print", 0, "", "")
	reg, env := newRegistry(t), cli.env()
	for _, name := range []string{"local_ip", "local_metrics"} {
		if _, err := call(t, reg, env, name, `{}`); code(err) != tkerr.LocalOutputUnrecognized {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestLocalSyspolicyRedactsStrings(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("syspolicy list --json", 0, `{"Summary":{"Scope":"Device","Origin":{"Name":"MDM","Scope":"Device"}},"Settings":{
		"AuthKey":{"Value":"AUTHKEY-CANARY","Origin":{"Name":"MDM","Scope":"Device"}},
		"Tailnet":{"Value":"example.com","Origin":{"Name":"MDM"}},
		"EncryptState":{"Value":true},
		"KeyExpirationNotice":{"Value":["CANARY-LIST"]},
		"Broken":{"Error":"bad value"}}}`, "")
	var out tools.SyspolicyOutput
	s := mustCall(t, newRegistry(t), cli.env(), "local_syspolicy", `{}`, &out)
	absent(t, s, "CANARY")
	got := map[string]string{}
	for _, p := range out.Policies {
		got[p.Name] = p.Value
	}
	if got["AuthKey"] != "(redacted)" || got["Tailnet"] != "example.com" || got["EncryptState"] != "true" || got["KeyExpirationNotice"] != "(redacted)" {
		t.Errorf("policies = %v", got)
	}
}

func TestLocalServeStatusIncludesForegroundAndServices(t *testing.T) {
	cli := newFakeCLI(t)
	cfg := `{"TCP":{"443":{"HTTPS":true}},
		"Web":{"node.example.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:3000/TARGET-CANARY"},"/files":{"Path":"/Users/CANARY/files"}}}},
		"AllowFunnel":{"node.example.ts.net:443":true},
		"Foreground":{"session1":{"Web":{"node.example.ts.net:8443":{"Handlers":{"/":{"Text":"TEXT-CANARY"}}}},"AllowFunnel":{"node.example.ts.net:8443":true}}},
		"Services":{"svc:db":{"TCP":{"5432":{"TCPForward":"127.0.0.1:5432"}}}}}`
	cli.on("serve status --json", 0, cfg, "")
	cli.on("funnel status --json", 0, cfg, "")
	reg, env := newRegistry(t), cli.env()

	var serve tools.ServeOutput
	s := mustCall(t, reg, env, "local_serve_status", `{}`, &serve)
	absent(t, s, "CANARY", "127.0.0.1")
	var sources []string
	for _, e := range serve.Entries {
		sources = append(sources, e.Source+":"+e.Kind)
	}
	if want := []string{"background:web", "background:https", "foreground:web", "service:tcp-forward"}; !slices.Equal(sources, want) {
		t.Errorf("entries = %v, want %v", sources, want)
	}
	if !slices.Equal(serve.Entries[0].Handlers, []string{"path", "proxy"}) {
		t.Errorf("handlers = %v", serve.Entries[0].Handlers)
	}

	var funnel tools.ServeOutput
	mustCall(t, reg, env, "local_funnel_status", `{}`, &funnel)
	if funnel.Count != 3 {
		t.Errorf("funnel entries = %+v", funnel.Entries)
	}
	for _, e := range funnel.Entries {
		if !e.Funnel || e.Source == "service" {
			t.Errorf("non-funnel entry in funnel status: %+v", e)
		}
	}
}

func TestLocalLockStatusPinsSchema(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("lock status --json=1", 0, `{"SchemaVersion":"1","Enabled":true,"PublicKey":"tlpub:test","NodeKey":"nodekey:test",
		"NodeKeySigned":true,"TrustedKeys":[{},{}],"VisiblePeers":[{}],"FilteredPeers":[{},{},{}]}`, "")
	var out tools.LockStatusOutput
	mustCall(t, newRegistry(t), cli.env(), "local_lock_status", `{}`, &out)
	if !out.Enabled || out.NodeKeySigned == nil || !*out.NodeKeySigned || out.TrustedKeyCount != 2 || out.LockedOutPeers != 3 {
		t.Errorf("lock = %+v", out)
	}
}

func TestParseMetricsKeepsDocumentedNames(t *testing.T) {
	m := tools.ParseMetrics([]byte(`# HELP tailscaled_inbound_bytes_total x
# TYPE tailscaled_inbound_bytes_total counter
tailscaled_inbound_bytes_total{path="direct_ipv4"} 1024
tailscaled_inbound_bytes_total{path="derp"} 7
tailscaled_home_derp_region_id 1
tailscaled_secret_internal_gauge 5
`))
	if len(m.Metrics) != 3 || m.Dropped != 1 || m.Metrics[0].Name != "tailscaled_home_derp_region_id" || m.Metrics[1].Labels["path"] != "direct_ipv4" {
		t.Errorf("metrics = %+v", m)
	}
}

func TestLocalVersionSkew(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("version --json --daemon", 0, `{"majorMinorPatch":"1.102.5","long":"1.102.5-1-tTEST","daemonLong":"1.102.4-tTEST-gTEST","osVariant":"macos"}`,
		`Warning: client version "1.102.5-1-tTEST" != tailscaled server version "1.102.4-tTEST-gTEST"`+"\n")
	var out tools.VersionOutput
	mustCall(t, newRegistry(t), cli.env(), "local_version", `{}`, &out)
	if !out.Skew || len(out.Warnings) != 1 {
		t.Errorf("version = %+v", out)
	}
}

func TestLocalPrefsAllowlist(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("get --json", 0, `{"accept-routes":true,"hostname":"me","relay-server-port":"","relay-server-static-endpoints":"203.0.113.1:7777",
		"future-pref":"CANARY"}`, "")
	var out tools.PrefsOutput
	s := mustCall(t, newRegistry(t), cli.env(), "local_prefs", `{}`, &out)
	absent(t, s, "203.0.113.1", "CANARY")
	if len(out.Prefs) != 3 || out.Prefs[0].Name != "accept-routes" || out.Prefs[0].Value != "true" {
		t.Errorf("prefs = %+v", out.Prefs)
	}
}

func TestLocalWhoamiAndWhois(t *testing.T) {
	identity := `{"Node":{"ID":1,"StableID":"nSELFCNTRL","Name":"me.example.ts.net.","Key":"nodekey:CANARY","Addresses":["100.64.0.10/32"],
		"Endpoints":["203.0.113.50:41641"],"Hostinfo":{"Hostname":"CANARY-HOST"},"MachineAuthorized":true},
		"UserProfile":{"ID":7,"LoginName":"amy@example.com","DisplayName":"Amy"},"CapMap":{"example.com/cap/admin":[{"secret":"CAP-CANARY"}]}}`
	cli := newFakeCLI(t)
	cli.on("whoami --json", 0, identity, "")
	cli.on("whois --json --proto=tcp 100.64.0.10:22", 0, identity, "")
	reg, env := newRegistry(t), cli.env()
	var me tools.LocalIdentity
	s := mustCall(t, reg, env, "local_whoami", `{}`, &me)
	absent(t, s, "CANARY", "203.0.113.50")
	if me.NodeID != "nSELFCNTRL" || me.LoginName != "a…@example.com" || len(me.Capabilities) != 0 {
		t.Errorf("whoami = %+v", me)
	}
	var who tools.LocalIdentity
	s = mustCall(t, reg, env, "local_whois", `{"address":"100.64.0.10:22","proto":"tcp"}`, &who)
	absent(t, s, "CANARY")
	if !slices.Equal(who.Capabilities, []string{"example.com/cap/admin"}) {
		t.Errorf("capabilities = %v", who.Capabilities)
	}
	if _, err := call(t, reg, env, "local_whois", `{"address":"192.168.1.1"}`); code(err) != tkerr.ValidationFailed {
		t.Errorf("non-tailnet whois: err = %v", err)
	}
}

func TestLocalIPFamilyFlag(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("ip -4", 0, "100.64.0.10\n", "")
	var out tools.LocalIPOutput
	mustCall(t, newRegistry(t), cli.env(), "local_ip", `{"family":"4"}`, &out)
	if !slices.Equal(out.Addresses, []string{"100.64.0.10"}) {
		t.Errorf("addresses = %v", out.Addresses)
	}
}

func TestLocalDNSStatus(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("dns status --json", 0, `{"TailscaleDNS":true,"CurrentTailnet":{"MagicDNSEnabled":true,"MagicDNSSuffix":"example.ts.net","SelfDNSName":"me.example.ts.net."},
		"Resolvers":[{"Addr":"1.1.1.1"}],"SplitDNSRoutes":{"ts.net.":[{"Addr":"199.247.155.53"}],"corp.example.":[{"Addr":"10.0.0.53"}]},
		"SearchDomains":["example.ts.net."],"SystemDNS":{"Nameservers":["192.168.1.1"]}}`, "")
	var out tools.LocalDNSStatusOutput
	mustCall(t, newRegistry(t), cli.env(), "local_dns_status", `{}`, &out)
	if !out.TailscaleDNS || len(out.SplitDNS) != 2 || out.SplitDNS[0].Domain != "corp.example." || out.Resolvers[0] != "1.1.1.1" {
		t.Errorf("dns status = %+v", out)
	}
}

func TestNoCLIIsReportedPerCall(t *testing.T) {
	reg := newRegistry(t)
	env := newFakeCLI(t).env()
	env.Local = nil
	if _, err := call(t, reg, env, "local_status", `{}`); code(err) != tkerr.LocalBinaryMissing {
		t.Errorf("err = %v", err)
	}
}

func TestLocalNetcheckAndDNSQueryRequireRunning(t *testing.T) {
	for state, want := range map[string]tkerr.Code{
		"NeedsLogin":       tkerr.LocalNeedsLogin,
		"NeedsMachineAuth": tkerr.LocalNeedsMachineAuth,
		"Stopped":          tkerr.LocalStopped,
		"Starting":         tkerr.LocalCommandFailed,
		"":                 tkerr.LocalOutputUnrecognized,
	} {
		cli := newFakeCLI(t)
		cli.on("status --json --peers=false", 0, `{"BackendState":`+jsonString(state)+`}`, "")
		reg := newRegistry(t)
		if _, err := call(t, reg, cli.env(), "local_netcheck", `{}`); code(err) != want {
			t.Errorf("%q: netcheck err = %v, want %s", state, err, want)
		}
		if _, err := call(t, reg, cli.env(), "local_dns_query", `{"name":"me.example.ts.net"}`); code(err) != want {
			t.Errorf("%q: dns query err = %v, want %s", state, err, want)
		}
		for _, c := range cli.calls() {
			if c != "status --json --peers=false" {
				t.Errorf("%q: the CLI ran %q in a state that is not Running", state, c)
			}
		}
	}
}

func TestLocalUnrecognizedOutputIsAnError(t *testing.T) {
	for _, c := range []struct{ tool, args, cmd, stdout string }{
		{"local_status", `{}`, "status --json --peers=false", `{}`},
		{"local_status", `{}`, "status --json --peers=false", `null`},
		{"local_whoami", `{}`, "whoami --json", `{}`},
		{"local_whois", `{"address":"100.64.0.11"}`, "whois --json 100.64.0.11", `{}`},
		{"local_version", `{}`, "version --json --daemon", `{}`},
		{"local_dns_status", `{}`, "dns status --json", `{}`},
		{"local_lock_status", `{}`, "lock status --json=1", `{}`},
		{"local_prefs", `{}`, "get --json", `{"unexpected":1}`},
		{"local_syspolicy", `{}`, "syspolicy list --json", `{"x":1}`},
		{"local_syspolicy", `{}`, "syspolicy list --json", `null`},
		{"local_serve_status", `{}`, "serve status --json", `null`},
		{"local_funnel_status", `{}`, "funnel status --json", `null`},
		{"local_ip", `{}`, "ip", "garbage\n"},
		{"local_metrics", `{}`, "metrics print", "<html>not metrics</html>\n"},
		{"local_ping", `{"target":"100.64.0.11"}`, "ping --c=3 --timeout=5s --until-direct=true 100.64.0.11", "a new output format\n"},
	} {
		cli := newFakeCLI(t)
		cli.on(c.cmd, 0, c.stdout, "")
		if _, err := call(t, newRegistry(t), cli.env(), c.tool, c.args); code(err) != tkerr.LocalOutputUnrecognized {
			t.Errorf("%s with %q: err = %v, want local_output_unrecognized", c.tool, c.stdout, err)
		}
	}
}

func TestLocalSyspolicyRedactsErrors(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("syspolicy list --json", 0, `{"Settings":{"AuthKey":{"Value":"S3CRET-CANARY","Error":"cannot use S3CRET-CANARY"},
		"Tailnet":{"Value":"example.com","Error":"tailnet not reachable"}}}`, "")
	var out tools.SyspolicyOutput
	s := mustCall(t, newRegistry(t), cli.env(), "local_syspolicy", `{}`, &out)
	absent(t, s, "S3CRET-CANARY")
	if len(out.Policies) != 2 || out.Policies[0].Error != "(redacted)" || out.Policies[1].Error != "tailnet not reachable" {
		t.Errorf("policies = %+v", out.Policies)
	}
}

func TestLocalFlagShapedInputNeverReachesTheCLI(t *testing.T) {
	cli := newFakeCLI(t)
	reg := newRegistry(t)
	for _, c := range []struct{ tool, args string }{
		{"local_whois", `{"address":"-x"}`},
		{"local_whois", `{"address":"--socket=/tmp/x"}`},
		{"local_whois", `{"address":"::ffff:100.64.0.1%eth0"}`},
		{"local_ip", `{"peer":"-1"}`},
		{"local_ip", `{"family":"-socket=/tmp/x"}`},
		{"local_whois", `{"address":"100.64.0.11","proto":"--socket=/tmp/x"}`},
		{"local_ping", `{"target":"--socket=/tmp/x"}`},
		{"local_dns_query", `{"name":"-x.example.ts.net"}`},
		{"local_dns_query", `{"name":"--socket=/tmp/x"}`},
	} {
		if _, err := call(t, reg, cli.env(), c.tool, c.args); code(err) != tkerr.ValidationFailed {
			t.Errorf("%s %s: err = %v, want validation_failed", c.tool, c.args, err)
		}
	}
	if got := cli.calls(); len(got) != 0 {
		t.Errorf("the CLI ran for refused input: %v", got)
	}
}

func TestLocalPrefsShowRouteLists(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("get --json", 0, `{"advertise-routes":["10.0.0.0/24","10.1.0.0/24"]}`, "")
	var out tools.PrefsOutput
	mustCall(t, newRegistry(t), cli.env(), "local_prefs", `{}`, &out)
	if len(out.Prefs) != 1 || out.Prefs[0].Value != "10.0.0.0/24,10.1.0.0/24" {
		t.Errorf("prefs = %+v", out.Prefs)
	}
}

func TestParseMetricsDropsNonFiniteValues(t *testing.T) {
	m := tools.ParseMetrics([]byte("# TYPE tailscaled_home_derp_region_id gauge\ntailscaled_home_derp_region_id NaN\n"))
	if len(m.Metrics) != 0 || m.Dropped != 1 {
		t.Errorf("metrics = %+v", m)
	}
}

func TestLocalSyspolicyAcceptsNoPolicies(t *testing.T) {
	cli := newFakeCLI(t)
	// The CLI omits Settings when no policy is set.
	cli.on("syspolicy list --json", 0, "{}\n", "")
	var out tools.SyspolicyOutput
	mustCall(t, newRegistry(t), cli.env(), "local_syspolicy", `{}`, &out)
	if len(out.Policies) != 0 {
		t.Errorf("policies = %+v", out.Policies)
	}
}

func TestLocalSentinelsBehindTheStatusGate(t *testing.T) {
	cli := newFakeCLI(t)
	cli.on("status --json --peers=false", 0, statusFixture(false), "")
	cli.on("netcheck --format=json", 0, `{}`, "")
	cli.on("dns query --json web.example.ts.net A", 0, `{}`, "")
	reg := newRegistry(t)
	for tool, args := range map[string]string{"local_netcheck": `{}`, "local_dns_query": `{"name":"web.example.ts.net"}`} {
		if _, err := call(t, reg, cli.env(), tool, args); code(err) != tkerr.LocalOutputUnrecognized {
			t.Errorf("%s with {}: err = %v, want local_output_unrecognized", tool, err)
		}
	}
}
