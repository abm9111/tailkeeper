package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Shapes in this file follow the tailscale CLI's JSON output as defined in
// tailscale.com v1.104 (ipnstate, tsdnsjsonv0, tslockjsonv1, ipn.ServeConfig,
// netcheck.Report, setting.Snapshot) and were checked against a 1.102 client.
// Only declared fields are decoded; everything else is dropped.

const localTimeout = 30 * time.Second

func localMeta(name, verb, summary string) registry.Meta {
	return registry.Meta{Name: name, Area: "local", Verb: verb, Summary: summary,
		Tier: registry.TierLocal, Stage: registry.StageGA, Credential: registry.CredNone}
}

// withNotes adds a line to a tool's documentation.
func withNotes(m registry.Meta, notes string) registry.Meta {
	m.Notes = notes
	return m
}

func localTools() []registry.Tool {
	return []registry.Tool{
		registry.Define(localMeta("local_status", "status", "This node's backend state, identity, health and (optionally) peers. Public endpoints are never shown."), localStatus),
		registry.Define(localMeta("local_whoami", "whoami", "This node's machine and user identity."), localWhoami),
		registry.Define(localMeta("local_whois", "whois", "Which device and user own a tailnet address."), localWhois),
		registry.Define(localMeta("local_ip", "ip", "Tailscale addresses of this node or of a peer address."), localIP),
		registry.Define(localMeta("local_ping", "ping", "Ping a tailnet address from this node and report the path taken."), localPing),
		registry.Define(localMeta("local_netcheck", "netcheck", "This node's network conditions: UDP, NAT type, port mapping, nearest relay. Public IPs are never shown."), localNetcheck),
		registry.Define(localMeta("local_dns_status", "dns-status", "MagicDNS and resolver configuration as this node sees it."), localDNSStatus),
		registry.Define(localMeta("local_dns_query", "dns-query", "Resolve a tailnet name through this node's internal resolver."), localDNSQuery),
		registry.Define(withNotes(localMeta("local_prefs", "prefs", "This node's client preferences (accept-routes, shields-up, exit node, ...)."),
			"Values are never masked, except operator and nickname, which name a person: they are masked unless personalData is show."), localPrefs),
		registry.Define(localMeta("local_lock_status", "lock-status", "Tailnet Lock state as this node sees it (public keys only)."), localLockStatus),
		registry.Define(localMeta("local_metrics", "metrics", "This node's documented client metrics."), localMetrics),
		registry.Define(localMeta("local_version", "version", "CLI and daemon versions, and whether they differ."), localVersion),
		registry.Define(localMeta("local_serve_status", "serve-status", "What this node serves on the tailnet, including foreground sessions and Services (targets redacted)."), localServeStatus),
		registry.Define(localMeta("local_funnel_status", "funnel-status", "What this node exposes to the public internet through Funnel."), localFunnelStatus),
		registry.Define(localMeta("local_syspolicy", "syspolicy", "Effective MDM and system policies on this node (string values redacted unless known safe)."), localSyspolicy),
	}
}

// run runs the CLI and returns its stdout and warnings.
func run(ctx context.Context, env *registry.Env, timeout time.Duration, args ...string) ([]byte, []string, error) {
	r, err := env.RequireLocal()
	if err != nil {
		return nil, nil, err
	}
	res, err := r.Run(ctx, timeout, args...)
	if err != nil {
		return nil, nil, err
	}
	return res.Stdout, res.Warnings, nil
}

// runJSON runs the CLI and decodes its JSON output into out. The CLI's JSON format
// is documented as unstable, so the output must also carry each of keys at its top
// level: a renamed schema would otherwise decode to an empty, healthy-looking result.
func runJSON(ctx context.Context, env *registry.Env, out any, keys []string, args ...string) error {
	stdout, _, err := run(ctx, env, localTimeout, args...)
	if err != nil {
		return err
	}
	return decodeCLI(stdout, out, keys, args)
}

// decodeCLI is runJSON's decoding step.
func decodeCLI(stdout []byte, out any, keys, args []string) error {
	var top map[string]json.RawMessage
	err := json.Unmarshal(stdout, &top)
	if err == nil {
		err = json.Unmarshal(stdout, out)
	}
	if err != nil {
		return tkerr.Wrap(tkerr.LocalOutputUnrecognized, err, "`tailscale "+strings.Join(args, " ")+"` printed output tailkeeper cannot parse",
			unstableHint)
	}
	if top == nil {
		return unrecognized(args, "null")
	}
	for _, k := range keys {
		if _, ok := top[k]; !ok {
			return unrecognized(args, "JSON without "+k)
		}
	}
	return nil
}

const unstableHint = "the CLI's JSON format is documented as unstable; check `tailkeeper local version`"

// unrecognized reports CLI output that parsed but is not what tailkeeper expects.
func unrecognized(args []string, what string) error {
	return tkerr.New(tkerr.LocalOutputUnrecognized, "`tailscale "+strings.Join(args, " ")+"` printed "+what, unstableHint)
}

// runningStatus reads the daemon's state and refuses unless it is Running: in any
// other state netcheck fetches the public relay map and probes it from this host on
// its own, and DNS answers do not reflect the tailnet.
func runningStatus(ctx context.Context, env *registry.Env) (cliStatus, error) {
	args := []string{"status", "--json", "--peers=false"}
	var s cliStatus
	if err := runJSON(ctx, env, &s, []string{"BackendState"}, args...); err != nil {
		return s, err
	}
	switch s.BackendState {
	case "Running":
		return s, nil
	case "NeedsLogin":
		return s, tkerr.New(tkerr.LocalNeedsLogin, "this node is not logged in", "")
	case "NeedsMachineAuth":
		return s, tkerr.New(tkerr.LocalNeedsMachineAuth, "this node is waiting for device approval", "")
	case "Stopped":
		return s, tkerr.New(tkerr.LocalStopped, "Tailscale is stopped on this node", "")
	case "":
		return s, unrecognized(args, "an empty BackendState")
	}
	return s, tkerr.New(tkerr.LocalCommandFailed, "Tailscale on this node is "+strconv.Quote(sanitize.String(s.BackendState, 64))+", not Running", "")
}

// --- status -------------------------------------------------------------------

type cliPeer struct {
	ID             string   `json:"ID"`
	HostName       string   `json:"HostName"`
	DNSName        string   `json:"DNSName"`
	OS             string   `json:"OS"`
	TailscaleIPs   []string `json:"TailscaleIPs"`
	Tags           []string `json:"Tags"`
	CurAddr        string   `json:"CurAddr"`   // public endpoint: used for classification only
	Relay          string   `json:"Relay"`     // DERP region code
	PeerRelay      string   `json:"PeerRelay"` // ip:port:vni: used for classification only
	Online         bool     `json:"Online"`
	Active         bool     `json:"Active"`
	ExitNode       bool     `json:"ExitNode"`
	ExitNodeOption bool     `json:"ExitNodeOption"`
	LastHandshake  string   `json:"LastHandshake"`
	KeyExpiry      string   `json:"KeyExpiry"`
}

type cliTailnet struct {
	Name            string `json:"Name"`
	MagicDNSSuffix  string `json:"MagicDNSSuffix"`
	MagicDNSEnabled bool   `json:"MagicDNSEnabled"`
}

type cliStatus struct {
	Version        string             `json:"Version"`
	BackendState   string             `json:"BackendState"`
	AuthURL        string             `json:"AuthURL"` // a login link: only its presence is reported
	Self           *cliPeer           `json:"Self"`
	Health         []string           `json:"Health"`
	MagicDNSSuffix string             `json:"MagicDNSSuffix"`
	CurrentTailnet *cliTailnet        `json:"CurrentTailnet"`
	Peer           map[string]cliPeer `json:"Peer"`
}

// LocalPeer is a node as the local daemon sees it.
type LocalPeer struct {
	NodeID         string   `json:"nodeId" tk:"col"`
	HostName       string   `json:"hostName" tk:"untrusted,col"`
	DNSName        string   `json:"dnsName" tk:"untrusted"`
	OS             string   `json:"os,omitempty" tk:"untrusted,col"`
	TailscaleIPs   []string `json:"tailscaleIps"`
	Tags           []string `json:"tags,omitempty" tk:"untrusted"`
	Online         bool     `json:"online" tk:"col"`
	Active         bool     `json:"active"`
	Path           string   `json:"path,omitempty" tk:"col" jsonschema:"direct, peer-relay, derp or none (peers only)"`
	Relay          string   `json:"relay,omitempty" tk:"untrusted" jsonschema:"home DERP region code"`
	ExitNode       bool     `json:"exitNode"`
	ExitNodeOption bool     `json:"exitNodeOption"`
	LastHandshake  string   `json:"lastHandshake,omitempty"`
	KeyExpiry      string   `json:"keyExpiry,omitempty"`
}

// zeroTime is how Go encodes an unset time.Time.
const zeroTime = "0001-01-01T00:00:00Z"

func toLocalPeer(p cliPeer) LocalPeer {
	path := "none"
	switch {
	case p.CurAddr != "":
		path = "direct"
	case p.PeerRelay != "":
		path = "peer-relay"
	case p.Relay != "" && p.Active:
		path = "derp"
	}
	hs := p.LastHandshake
	if hs == zeroTime {
		hs = ""
	}
	return LocalPeer{NodeID: p.ID, HostName: p.HostName, DNSName: p.DNSName, OS: p.OS, TailscaleIPs: nonNil(p.TailscaleIPs),
		Tags: p.Tags, Online: p.Online, Active: p.Active, Path: path, Relay: p.Relay, ExitNode: p.ExitNode,
		ExitNodeOption: p.ExitNodeOption, LastHandshake: hs, KeyExpiry: p.KeyExpiry}
}

// LocalStatusInput selects what local_status includes.
type LocalStatusInput struct {
	Peers  bool `json:"peers,omitempty" jsonschema:"include peers"`
	Active bool `json:"active,omitempty" jsonschema:"include only peers with active sessions (implies peers)"`
}

// LocalStatusOutput is this node's status.
type LocalStatusOutput struct {
	BackendState    string      `json:"backendState"`
	NeedsLogin      bool        `json:"needsLogin"`
	Version         string      `json:"version" tk:"untrusted"`
	Self            *LocalPeer  `json:"self,omitempty"`
	Tailnet         string      `json:"tailnet,omitempty" tk:"untrusted" jsonschema:"the tailnet name: an organization's domain, or a person's login for a personal tailnet"`
	MagicDNSSuffix  string      `json:"magicDnsSuffix,omitempty" tk:"untrusted"`
	MagicDNSEnabled bool        `json:"magicDnsEnabled"`
	Health          []string    `json:"health" tk:"untrusted"`
	Peers           []LocalPeer `json:"peers,omitempty" tk:"rows"`
	PeerCount       int         `json:"peerCount"`
	PeerScope       string      `json:"peerScope,omitempty" jsonschema:"network_map: peers are those in this node's network map; devices it may not reach are absent"`
}

func localStatus(ctx context.Context, env *registry.Env, in LocalStatusInput) (LocalStatusOutput, error) {
	args := []string{"status", "--json", "--peers=" + strconv.FormatBool(in.Peers || in.Active)}
	if in.Active {
		args = append(args, "--active=true")
	}
	var s cliStatus
	if err := runJSON(ctx, env, &s, []string{"BackendState"}, args...); err != nil {
		return LocalStatusOutput{}, err
	}
	if s.BackendState == "" {
		return LocalStatusOutput{}, unrecognized(args, "an empty BackendState")
	}
	out := LocalStatusOutput{BackendState: s.BackendState, NeedsLogin: s.AuthURL != "" || s.BackendState == "NeedsLogin",
		Version: s.Version, MagicDNSSuffix: s.MagicDNSSuffix, Health: []string{}}
	// Whole: the registry masks addresses, then caps each string. A cap here would
	// cut an address before masking could parse it.
	out.Health = append(out.Health, s.Health...)
	if s.Self != nil {
		self := toLocalPeer(*s.Self)
		self.Path = ""
		out.Self = &self
	}
	if s.CurrentTailnet != nil {
		out.Tailnet, out.MagicDNSEnabled = s.CurrentTailnet.Name, s.CurrentTailnet.MagicDNSEnabled
		if out.MagicDNSSuffix == "" {
			out.MagicDNSSuffix = s.CurrentTailnet.MagicDNSSuffix
		}
	}
	for _, k := range sortedKeys(s.Peer) {
		out.Peers = append(out.Peers, toLocalPeer(s.Peer[k]))
	}
	sort.SliceStable(out.Peers, func(i, j int) bool { return out.Peers[i].DNSName < out.Peers[j].DNSName })
	out.PeerCount = len(out.Peers)
	if in.Peers || in.Active {
		out.PeerScope = "network_map"
	}
	return out, nil
}

// magicSuffix returns the tailnet's MagicDNS suffix from status, lower case and
// without dots at either end.
func magicSuffix(s cliStatus) string {
	suffix := s.MagicDNSSuffix
	if suffix == "" && s.CurrentTailnet != nil {
		suffix = s.CurrentTailnet.MagicDNSSuffix
	}
	return strings.Trim(strings.ToLower(suffix), ".")
}

// --- identity -----------------------------------------------------------------

type cliIdentity struct {
	Node struct {
		StableID          string   `json:"StableID"`
		Name              string   `json:"Name"`
		Addresses         []string `json:"Addresses"`
		Tags              []string `json:"Tags"`
		MachineAuthorized bool     `json:"MachineAuthorized"`
	} `json:"Node"`
	UserProfile struct {
		LoginName   string `json:"LoginName"`
		DisplayName string `json:"DisplayName"`
	} `json:"UserProfile"`
	CapMap map[string]json.RawMessage `json:"CapMap"`
}

// LocalIdentity is a node and its user.
type LocalIdentity struct {
	NodeID            string   `json:"nodeId"`
	Name              string   `json:"name" tk:"untrusted"`
	Addresses         []string `json:"addresses"`
	Tags              []string `json:"tags,omitempty" tk:"untrusted"`
	MachineAuthorized bool     `json:"machineAuthorized"`
	LoginName         string   `json:"loginName,omitempty" tk:"untrusted,personal"`
	DisplayName       string   `json:"displayName,omitempty" tk:"untrusted,personal"`
	Capabilities      []string `json:"capabilities,omitempty" tk:"untrusted" jsonschema:"names of application capabilities the peer is granted on this node (whois only; values are not shown)"`
}

func toIdentity(c cliIdentity) LocalIdentity {
	id := LocalIdentity{NodeID: c.Node.StableID, Name: c.Node.Name, Addresses: nonNil(c.Node.Addresses), Tags: c.Node.Tags,
		MachineAuthorized: c.Node.MachineAuthorized, LoginName: c.UserProfile.LoginName,
		DisplayName: c.UserProfile.DisplayName}
	if len(c.CapMap) > 0 {
		id.Capabilities = sortedKeys(c.CapMap)
	}
	return id
}

func localWhoami(ctx context.Context, env *registry.Env, _ NoInput) (LocalIdentity, error) {
	var c cliIdentity
	if err := runJSON(ctx, env, &c, []string{"Node"}, "whoami", "--json"); err != nil {
		return LocalIdentity{}, err
	}
	id := toIdentity(c)
	id.Capabilities = nil
	return id, nil
}

// WhoisInput names a tailnet address, optionally with a port.
type WhoisInput struct {
	Address string `json:"address" jsonschema:"tailnet IP, or IP:port"`
	Proto   string `json:"proto,omitempty" jsonschema:"tcp or udp (with a port); empty means both"`
}

func localWhois(ctx context.Context, env *registry.Env, in WhoisInput) (LocalIdentity, error) {
	if err := tailnetAddress(in.Address, true); err != nil {
		return LocalIdentity{}, err
	}
	args := []string{"whois", "--json"}
	switch in.Proto {
	case "":
	case "tcp", "udp":
		args = append(args, "--proto="+in.Proto)
	default:
		return LocalIdentity{}, validationf("proto must be tcp or udp")
	}
	var c cliIdentity
	if err := runJSON(ctx, env, &c, []string{"Node"}, append(args, in.Address)...); err != nil {
		return LocalIdentity{}, err
	}
	return toIdentity(c), nil
}

var (
	cgnat   = netip.MustParsePrefix("100.64.0.0/10")
	tsULA   = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	labelRE = regexp.MustCompile(`^[a-z0-9_]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// tailnetAddress accepts only literal tailnet addresses. Names are refused because
// the CLI would resolve them through the OS resolver, sending them to outside DNS.
func tailnetAddress(s string, allowPort bool) error {
	addr, err := netip.ParseAddr(s)
	if err != nil && allowPort {
		var ap netip.AddrPort
		if ap, err = netip.ParseAddrPort(s); err == nil {
			addr = ap.Addr()
		}
	}
	if err != nil {
		return validationf("address must be a literal tailnet IP (100.64.0.0/10 or fd7a:115c:a1e0::/48); find it with devices_list or local_status")
	}
	if addr.Zone() != "" {
		return validationf("address must not carry a zone")
	}
	if !cgnat.Contains(addr.Unmap()) && !tsULA.Contains(addr) {
		return validationf("address " + addr.String() + " is outside the tailnet ranges")
	}
	return nil
}

// LocalIPInput selects which addresses local_ip prints.
type LocalIPInput struct {
	Peer   string `json:"peer,omitempty" jsonschema:"a peer's tailnet IP (default: this node)"`
	Family string `json:"family,omitempty" jsonschema:"4, 6 or 1 (first address only); default all"`
}

// LocalIPOutput lists addresses.
type LocalIPOutput struct {
	Addresses []string `json:"addresses"`
}

func localIP(ctx context.Context, env *registry.Env, in LocalIPInput) (LocalIPOutput, error) {
	args := []string{"ip"}
	switch in.Family {
	case "":
	case "4", "6", "1":
		args = append(args, "-"+in.Family)
	default:
		return LocalIPOutput{}, validationf("family must be 4, 6 or 1")
	}
	if in.Peer != "" {
		if err := tailnetAddress(in.Peer, false); err != nil {
			return LocalIPOutput{}, err
		}
		args = append(args, in.Peer)
	}
	stdout, _, err := run(ctx, env, localTimeout, args...)
	if err != nil {
		return LocalIPOutput{}, err
	}
	out := LocalIPOutput{Addresses: []string{}}
	for _, line := range strings.Split(string(stdout), "\n") {
		if a, err := netip.ParseAddr(strings.TrimSpace(line)); err == nil {
			out.Addresses = append(out.Addresses, a.String())
		}
	}
	// The CLI exits non-zero when there is no address to print.
	if len(out.Addresses) == 0 {
		return LocalIPOutput{}, unrecognized(args, "no address")
	}
	return out, nil
}

// --- ping ---------------------------------------------------------------------

// PingInput configures local_ping.
type PingInput struct {
	Target         string `json:"target" jsonschema:"literal tailnet IP of the peer"`
	Count          int    `json:"count,omitempty" jsonschema:"1-10 (default 3)"`
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty" jsonschema:"per ping, 1-8 (default 5)"`
	Mode           string `json:"mode,omitempty" jsonschema:"disco (default), tsmp, icmp or peerapi"`
	AllPings       bool   `json:"allPings,omitempty" jsonschema:"send every ping; by default (like the CLI) disco pings stop at the first direct reply"`
}

// PingReply is one parsed reply line.
type PingReply struct {
	Via       string  `json:"via" tk:"col" jsonschema:"direct, derp, peer-relay, icmp, tsmp or peerapi"`
	Region    string  `json:"region,omitempty" tk:"untrusted,col" jsonschema:"DERP region code, for derp replies"`
	LatencyMs float64 `json:"latencyMs" tk:"col"`
}

// PingOutput summarises a ping run.
type PingOutput struct {
	Target               string      `json:"target"`
	Mode                 string      `json:"mode"`
	Replies              []PingReply `json:"replies" tk:"rows"`
	Timeouts             int         `json:"timeouts"`
	DirectEstablished    bool        `json:"directEstablished"`
	DirectNotEstablished bool        `json:"directNotEstablished" jsonschema:"the CLI gave up waiting for a direct path"`
	NoReply              bool        `json:"noReply" jsonschema:"no ping was answered"`
	UnparsedLines        int         `json:"unparsedLines"`
	Note                 string      `json:"note"`
}

var (
	pongRE    = regexp.MustCompile(`^pong from (.+?) \(([^,)]+)(?:, \d+)?\) via (.+) in (\S+)$`)
	peerapiRE = regexp.MustCompile(`^hit peerapi of \S+ \(.*\) at \S+ in (\S+)$`)
	timeoutRE = regexp.MustCompile(`^ping "[^"]*" timed out$`)
	derpRE    = regexp.MustCompile(`^DERP\(([^)]*)\)$`)
)

// PingResult is what ParsePing extracts from the CLI's stdout.
type PingResult struct {
	Replies  []PingReply
	Timeouts int
	Direct   bool
	Unparsed int
}

// ParsePing parses `tailscale ping` stdout. Formats are those printed by
// cmd/tailscale/cli/ping.go; latencies are Go durations ("0s", "12ms", "1.2s").
func ParsePing(out []byte) PingResult {
	var r PingResult
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
			continue
		case timeoutRE.MatchString(line):
			r.Timeouts++
			continue
		}
		if m := peerapiRE.FindStringSubmatch(line); m != nil {
			if d, err := time.ParseDuration(m[1]); err == nil {
				r.Replies = append(r.Replies, PingReply{Via: "peerapi", LatencyMs: ms(d)})
				continue
			}
		}
		m := pongRE.FindStringSubmatch(line)
		if m == nil {
			r.Unparsed++
			continue
		}
		d, err := time.ParseDuration(m[4])
		if err != nil {
			r.Unparsed++
			continue
		}
		reply := PingReply{LatencyMs: ms(d)}
		via := m[3]
		switch {
		case derpRE.MatchString(via):
			reply.Via, reply.Region = "derp", derpRE.FindStringSubmatch(via)[1]
		case strings.HasPrefix(via, "peer-relay("):
			reply.Via = "peer-relay"
		case via == "TSMP":
			reply.Via = "tsmp"
		case via == "ICMP":
			reply.Via = "icmp"
		default:
			if _, err := netip.ParseAddrPort(via); err != nil {
				r.Unparsed++
				continue
			}
			reply.Via, r.Direct = "direct", true
		}
		r.Replies = append(r.Replies, reply)
	}
	return r
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func localPing(ctx context.Context, env *registry.Env, in PingInput) (PingOutput, error) {
	if err := tailnetAddress(in.Target, false); err != nil {
		return PingOutput{}, err
	}
	count, timeout := in.Count, in.TimeoutSeconds
	if count == 0 {
		count = 3
	}
	if timeout == 0 {
		timeout = 5
	}
	if count < 1 || count > 10 || timeout < 1 || timeout > 8 {
		return PingOutput{}, validationf("count must be 1-10 and timeoutSeconds 1-8")
	}
	mode := in.Mode
	if mode == "" {
		mode = "disco"
	}
	args := []string{"ping", "--c=" + strconv.Itoa(count), "--timeout=" + strconv.Itoa(timeout) + "s",
		"--until-direct=" + strconv.FormatBool(!in.AllPings)}
	switch mode {
	case "disco":
	case "tsmp", "icmp", "peerapi":
		args = append(args, "--"+mode)
	default:
		return PingOutput{}, validationf("mode must be disco, tsmp, icmp or peerapi")
	}
	r, err := env.RequireLocal()
	if err != nil {
		return PingOutput{}, err
	}
	// The CLI sleeps one second between pings.
	res, runErr := r.Run(ctx, time.Duration(count*(timeout+1)+5)*time.Second, append(args, in.Target)...)
	if runErr != nil {
		if e, ok := tkerr.As(runErr); !ok || e.Code != tkerr.LocalCommandFailed {
			return PingOutput{}, runErr
		}
	}
	p := ParsePing(res.Stdout)
	stderr := strings.ToLower(res.Stderr)
	out := PingOutput{Target: in.Target, Mode: mode, Replies: nonNil(p.Replies), Timeouts: p.Timeouts,
		DirectEstablished: p.Direct, DirectNotEstablished: strings.Contains(stderr, "direct connection not established"),
		NoReply: strings.Contains(stderr, "no reply"), UnparsedLines: p.Unparsed,
		Note: "Measured from this node only; it says nothing about paths between two other devices."}
	// A non-zero exit is a result when it reports one of the two outcomes above;
	// anything else (an unknown peer, for example) is an error.
	if runErr != nil && !out.DirectNotEstablished && !out.NoReply {
		return PingOutput{}, runErr
	}
	// A clean exit with no reply, timeout or known outcome is a format tailkeeper
	// does not know, not "nothing happened".
	if runErr == nil && len(p.Replies) == 0 && p.Timeouts == 0 && !p.Direct && (p.Unparsed > 0 || len(bytes.TrimSpace(res.Stdout)) == 0) {
		return PingOutput{}, unrecognized(append(args, in.Target), "no reply, timeout or known outcome")
	}
	return out, nil
}

// --- netcheck -----------------------------------------------------------------

// NetcheckOutput is the local network report without public IP addresses.
type NetcheckOutput struct {
	UDP                   bool               `json:"udp"`
	IPv4                  bool               `json:"ipv4"`
	IPv6                  bool               `json:"ipv6"`
	IPv4CanSend           bool               `json:"ipv4CanSend"`
	IPv6CanSend           bool               `json:"ipv6CanSend"`
	OSHasIPv6             bool               `json:"osHasIpv6"`
	ICMPv4                bool               `json:"icmpv4"`
	MappingVariesByDestIP *bool              `json:"mappingVariesByDestIp,omitempty" jsonschema:"hard NAT when true; absent when unknown"`
	UPnP                  *bool              `json:"upnp,omitempty" jsonschema:"absent when unknown"`
	PMP                   *bool              `json:"pmp,omitempty" jsonschema:"absent when unknown"`
	PCP                   *bool              `json:"pcp,omitempty" jsonschema:"absent when unknown"`
	CaptivePortal         *bool              `json:"captivePortal,omitempty" jsonschema:"absent when unknown"`
	PreferredDERP         int                `json:"preferredDerp" jsonschema:"region ID; 0 when unknown"`
	RegionLatencyMs       map[string]float64 `json:"regionLatencyMs" jsonschema:"keyed by DERP region ID"`
}

func localNetcheck(ctx context.Context, env *registry.Env, _ NoInput) (NetcheckOutput, error) {
	if _, err := runningStatus(ctx, env); err != nil {
		return NetcheckOutput{}, err
	}
	// GlobalV4, GlobalV6 and their counters (this host's public addresses) are not
	// declared and so are dropped.
	var r struct {
		UDP                   bool             `json:"UDP"`
		IPv4                  bool             `json:"IPv4"`
		IPv6                  bool             `json:"IPv6"`
		IPv4CanSend           bool             `json:"IPv4CanSend"`
		IPv6CanSend           bool             `json:"IPv6CanSend"`
		OSHasIPv6             bool             `json:"OSHasIPv6"`
		ICMPv4                bool             `json:"ICMPv4"`
		MappingVariesByDestIP *bool            `json:"MappingVariesByDestIP"`
		UPnP                  *bool            `json:"UPnP"`
		PMP                   *bool            `json:"PMP"`
		PCP                   *bool            `json:"PCP"`
		CaptivePortal         *bool            `json:"CaptivePortal"`
		PreferredDERP         int              `json:"PreferredDERP"`
		RegionLatency         map[string]int64 `json:"RegionLatency"` // nanoseconds
	}
	if err := runJSON(ctx, env, &r, []string{"UDP"}, "netcheck", "--format=json"); err != nil {
		return NetcheckOutput{}, err
	}
	out := NetcheckOutput{UDP: r.UDP, IPv4: r.IPv4, IPv6: r.IPv6, IPv4CanSend: r.IPv4CanSend, IPv6CanSend: r.IPv6CanSend,
		OSHasIPv6: r.OSHasIPv6, ICMPv4: r.ICMPv4, MappingVariesByDestIP: r.MappingVariesByDestIP, UPnP: r.UPnP,
		PMP: r.PMP, PCP: r.PCP, CaptivePortal: r.CaptivePortal, PreferredDERP: r.PreferredDERP, RegionLatencyMs: map[string]float64{}}
	for region, ns := range r.RegionLatency {
		out.RegionLatencyMs[region] = ms(time.Duration(ns))
	}
	return out, nil
}

// --- dns ----------------------------------------------------------------------

// LocalDNSStatusOutput is the node's DNS view.
type LocalDNSStatusOutput struct {
	TailscaleDNS      bool          `json:"tailscaleDns" jsonschema:"the node accepts the tailnet DNS configuration (--accept-dns)"`
	MagicDNSEnabled   bool          `json:"magicDnsEnabled"`
	MagicDNSSuffix    string        `json:"magicDnsSuffix,omitempty" tk:"untrusted"`
	SelfDNSName       string        `json:"selfDnsName,omitempty" tk:"untrusted"`
	Resolvers         []string      `json:"resolvers" tk:"untrusted,plain" jsonschema:"the tailnet's resolvers in preference order; empty means system defaults"`
	SplitDNS          []SplitDomain `json:"splitDns"`
	SearchDomains     []string      `json:"searchDomains" tk:"untrusted"`
	SystemNameservers []string      `json:"systemNameservers" tk:"untrusted,plain"`
	SystemDNSError    string        `json:"systemDnsError,omitempty" tk:"untrusted"`
}

type cliResolver struct {
	Addr string `json:"Addr"`
}

func localDNSStatus(ctx context.Context, env *registry.Env, _ NoInput) (LocalDNSStatusOutput, error) {
	var r struct {
		TailscaleDNS   bool `json:"TailscaleDNS"`
		CurrentTailnet *struct {
			MagicDNSEnabled bool   `json:"MagicDNSEnabled"`
			MagicDNSSuffix  string `json:"MagicDNSSuffix"`
			SelfDNSName     string `json:"SelfDNSName"`
		} `json:"CurrentTailnet"`
		Resolvers      []cliResolver            `json:"Resolvers"`
		SplitDNSRoutes map[string][]cliResolver `json:"SplitDNSRoutes"`
		SearchDomains  []string                 `json:"SearchDomains"`
		SystemDNS      *struct {
			Nameservers []string `json:"Nameservers"`
		} `json:"SystemDNS"`
		SystemDNSError string `json:"SystemDNSError"`
	}
	if err := runJSON(ctx, env, &r, []string{"TailscaleDNS"}, "dns", "status", "--json"); err != nil {
		return LocalDNSStatusOutput{}, err
	}
	out := LocalDNSStatusOutput{TailscaleDNS: r.TailscaleDNS, Resolvers: []string{}, SplitDNS: []SplitDomain{},
		SearchDomains: nonNil(r.SearchDomains), SystemNameservers: []string{}, SystemDNSError: r.SystemDNSError}
	if t := r.CurrentTailnet; t != nil {
		out.MagicDNSEnabled, out.MagicDNSSuffix, out.SelfDNSName = t.MagicDNSEnabled, t.MagicDNSSuffix, t.SelfDNSName
	}
	if r.SystemDNS != nil {
		out.SystemNameservers = nonNil(r.SystemDNS.Nameservers)
	}
	for _, res := range r.Resolvers {
		out.Resolvers = append(out.Resolvers, res.Addr)
	}
	for _, d := range sortedKeys(r.SplitDNSRoutes) {
		sd := SplitDomain{Domain: d, Resolvers: []Resolver{}}
		for _, res := range r.SplitDNSRoutes[d] {
			sd.Resolvers = append(sd.Resolvers, Resolver{Address: res.Addr})
		}
		out.SplitDNS = append(out.SplitDNS, sd)
	}
	return out, nil
}

// DNSQueryInput is a name lookup.
type DNSQueryInput struct {
	Name string `json:"name" jsonschema:"a name under the tailnet's MagicDNS suffix, or allowed by local.dnsQueryAllowlist"`
	Type string `json:"type,omitempty" jsonschema:"A (default), AAAA, CNAME, MX, NS, PTR, SRV or TXT"`
}

// DNSAnswer is one answer record.
type DNSAnswer struct {
	Name string `json:"name" tk:"untrusted,col"`
	Type string `json:"type" tk:"col"`
	TTL  int    `json:"ttl" tk:"col"`
	Body string `json:"body" tk:"untrusted,col,plain"`
}

// DNSQueryOutput is the lookup result.
type DNSQueryOutput struct {
	Name         string      `json:"name" tk:"untrusted"`
	Type         string      `json:"type"`
	ResponseCode string      `json:"responseCode"`
	Resolvers    []string    `json:"resolvers" tk:"untrusted,plain"`
	Answers      []DNSAnswer `json:"answers" tk:"rows"`
}

var dnsTypes = []string{"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT"}

// queryAllowed reports whether name may be looked up: it is under the MagicDNS
// suffix, equals an allowlist entry, or is under an allowlist entry that starts
// with a dot.
func queryAllowed(name, suffix string, allowlist []string) bool {
	if suffix != "" && (name == suffix || strings.HasSuffix(name, "."+suffix)) {
		return true
	}
	for _, a := range allowlist {
		a = strings.TrimSuffix(strings.ToLower(a), ".")
		if strings.HasPrefix(a, ".") {
			if strings.HasSuffix(name, a) && len(name) > len(a) {
				return true
			}
		} else if name == a {
			return true
		}
	}
	return false
}

func localDNSQuery(ctx context.Context, env *registry.Env, in DNSQueryInput) (DNSQueryOutput, error) {
	typ := strings.ToUpper(in.Type)
	if typ == "" {
		typ = "A"
	}
	if !slices.Contains(dnsTypes, typ) {
		return DNSQueryOutput{}, validationf("type must be one of " + strings.Join(dnsTypes, ", "))
	}
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Name)), ".")
	if name == "" || len(name) > 253 {
		return DNSQueryOutput{}, validationf("name is not a valid DNS name")
	}
	for _, label := range strings.Split(name, ".") {
		if !labelRE.MatchString(label) {
			return DNSQueryOutput{}, validationf("name is not a valid DNS name")
		}
	}
	// The node forwards queries it cannot answer to the tailnet's upstream
	// resolvers, so only names the owner expects to look up are allowed.
	s, err := runningStatus(ctx, env)
	if err != nil {
		return DNSQueryOutput{}, err
	}
	var allowlist []string
	if env.Config != nil {
		allowlist = env.Config.Config.Local.DNSQueryAllowlist
	}
	if !queryAllowed(name, magicSuffix(s), allowlist) {
		return DNSQueryOutput{}, validationf("only names under the MagicDNS suffix or allowed by local.dnsQueryAllowlist may be queried")
	}
	var r struct {
		Name         string        `json:"Name"`
		QueryType    string        `json:"QueryType"`
		ResponseCode string        `json:"ResponseCode"`
		Resolvers    []cliResolver `json:"Resolvers"`
		Answers      []struct {
			Name string `json:"Name"`
			TTL  int    `json:"TTL"`
			Type string `json:"Type"`
			Body string `json:"Body"`
		} `json:"Answers"`
	}
	if err := runJSON(ctx, env, &r, []string{"ResponseCode"}, "dns", "query", "--json", name, typ); err != nil {
		return DNSQueryOutput{}, err
	}
	out := DNSQueryOutput{Name: r.Name, Type: r.QueryType, ResponseCode: r.ResponseCode, Resolvers: []string{}, Answers: []DNSAnswer{}}
	for _, res := range r.Resolvers {
		out.Resolvers = append(out.Resolvers, res.Addr)
	}
	for _, a := range r.Answers {
		out.Answers = append(out.Answers, DNSAnswer{Name: a.Name, Type: strings.TrimPrefix(a.Type, "Type"), TTL: a.TTL, Body: a.Body})
	}
	return out, nil
}

// --- prefs, lock, metrics, version --------------------------------------------

// prefKeys are the settings local_prefs reports (names from `tailscale get`).
// Anything else is dropped; relay-server-static-endpoints carries public addresses.
var prefKeys = []string{"accept-dns", "accept-routes", "advertise-connector", "advertise-exit-node", "advertise-routes",
	"auto-update", "exit-node", "exit-node-allow-lan-access", "hostname", "netfilter-mode", "nickname", "operator",
	"relay-server-port", "report-posture", "shields-up", "snat-subnet-routes", "ssh", "stateful-filtering",
	"unattended", "update-check", "webclient"}

// personalPrefs name a person: the operating-system user allowed to run tailscale,
// and the account's nickname.
var personalPrefs = map[string]bool{"operator": true, "nickname": true}

// Pref is one client preference.
type Pref struct {
	Name  string `json:"name" tk:"col"`
	Value string `json:"value" tk:"untrusted,col,plain"`
}

// PrefsOutput lists preferences.
type PrefsOutput struct {
	Prefs []Pref `json:"prefs" tk:"rows"`
}

func localPrefs(ctx context.Context, env *registry.Env, _ NoInput) (PrefsOutput, error) {
	var r map[string]any
	if err := runJSON(ctx, env, &r, nil, "get", "--json"); err != nil {
		return PrefsOutput{}, err
	}
	out := PrefsOutput{Prefs: []Pref{}}
	known := false
	for _, k := range prefKeys {
		if _, ok := r[k]; ok {
			known = true
		}
		switch x := r[k].(type) {
		case bool:
			out.Prefs = append(out.Prefs, Pref{Name: k, Value: strconv.FormatBool(x)})
		case string:
			out.Prefs = append(out.Prefs, Pref{Name: k, Value: x})
		case float64:
			out.Prefs = append(out.Prefs, Pref{Name: k, Value: strconv.FormatFloat(x, 'f', -1, 64)})
		case []any: // advertise-routes
			var parts []string
			for _, e := range x {
				if s, ok := e.(string); ok {
					parts = append(parts, s)
				}
			}
			out.Prefs = append(out.Prefs, Pref{Name: k, Value: strings.Join(parts, ",")})
		}
	}
	if !known {
		return PrefsOutput{}, unrecognized([]string{"get", "--json"}, "no known preference")
	}
	// Values are plain (routes and the exit node must stay exact); the two that
	// name a person are masked here instead.
	if !env.ShowPersonalData() {
		mk := env.Masker()
		for i, p := range out.Prefs {
			if personalPrefs[p.Name] {
				out.Prefs[i].Value = mk.Identifier(p.Value)
			}
		}
	}
	return out, nil
}

// LockStatusOutput is Tailnet Lock as this node sees it.
type LockStatusOutput struct {
	Enabled          bool   `json:"enabled"`
	PublicKey        string `json:"publicKey,omitempty" jsonschema:"this node's Tailnet Lock public key" tk:"untrusted"`
	NodeKey          string `json:"nodeKey,omitempty" jsonschema:"this node's public node key" tk:"untrusted"`
	NodeKeySigned    *bool  `json:"nodeKeySigned,omitempty" jsonschema:"absent when Tailnet Lock is off" tk:"absentok"`
	TrustedKeyCount  int    `json:"trustedKeyCount"`
	VisiblePeerCount int    `json:"visiblePeerCount"`
	LockedOutPeers   int    `json:"lockedOutPeers" jsonschema:"peers filtered out because their node key is not signed"`
}

func localLockStatus(ctx context.Context, env *registry.Env, _ NoInput) (LockStatusOutput, error) {
	var r struct {
		Enabled       bool              `json:"Enabled"`
		PublicKey     string            `json:"PublicKey"`
		NodeKey       string            `json:"NodeKey"`
		NodeKeySigned *bool             `json:"NodeKeySigned"`
		TrustedKeys   []json.RawMessage `json:"TrustedKeys"`
		VisiblePeers  []json.RawMessage `json:"VisiblePeers"`
		FilteredPeers []json.RawMessage `json:"FilteredPeers"`
	}
	// --json=1 pins the documented schema version.
	if err := runJSON(ctx, env, &r, []string{"Enabled"}, "lock", "status", "--json=1"); err != nil {
		return LockStatusOutput{}, err
	}
	return LockStatusOutput{Enabled: r.Enabled, PublicKey: r.PublicKey, NodeKey: r.NodeKey, NodeKeySigned: r.NodeKeySigned,
		TrustedKeyCount: len(r.TrustedKeys), VisiblePeerCount: len(r.VisiblePeers), LockedOutPeers: len(r.FilteredPeers)}, nil
}

// documentedMetrics are the client metrics Tailscale documents; others are dropped.
var documentedMetrics = map[string]bool{
	"tailscaled_advertised_routes": true, "tailscaled_approved_routes": true,
	"tailscaled_peer_relay_forwarded_packets_total": true, "tailscaled_peer_relay_forwarded_bytes_total": true,
	"tailscaled_peer_relay_endpoints": true, "tailscaled_health_messages": true, "tailscaled_home_derp_region_id": true,
	"tailscaled_serve_inbound_bytes_total": true, "tailscaled_serve_outbound_bytes_total": true,
	"tailscaled_inbound_packets_total": true, "tailscaled_inbound_bytes_total": true,
	"tailscaled_outbound_packets_total": true, "tailscaled_outbound_bytes_total": true,
	"tailscaled_inbound_dropped_packets_total": true, "tailscaled_outbound_dropped_packets_total": true,
}

// Metric is one sample.
type Metric struct {
	Name   string            `json:"name" tk:"col"`
	Labels map[string]string `json:"labels,omitempty" tk:"untrusted"`
	Value  float64           `json:"value" tk:"col"`
}

// MetricsOutput lists documented metrics.
type MetricsOutput struct {
	Metrics []Metric `json:"metrics" tk:"rows"`
	Dropped int      `json:"dropped" jsonschema:"samples with undocumented names, not shown"`
}

var (
	sampleRE    = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([^}]*)\})?\s+(\S+)`)
	labelPairRE = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"`)
)

// ParseMetrics parses Prometheus text, keeping documented metric names only.
func ParseMetrics(text []byte) MetricsOutput {
	out := MetricsOutput{Metrics: []Metric{}}
	sc := bufio.NewScanner(bytes.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := sampleRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if !documentedMetrics[m[1]] {
			out.Dropped++
			continue
		}
		v, err := strconv.ParseFloat(m[4], 64)
		if err != nil {
			continue
		}
		if math.IsNaN(v) || math.IsInf(v, 0) { // JSON cannot carry them
			out.Dropped++
			continue
		}
		metric := Metric{Name: m[1], Value: v}
		if m[3] != "" {
			metric.Labels = map[string]string{}
			for _, lp := range labelPairRE.FindAllStringSubmatch(m[3], -1) {
				metric.Labels[lp[1]] = lp[2]
			}
		}
		out.Metrics = append(out.Metrics, metric)
	}
	sort.SliceStable(out.Metrics, func(i, j int) bool { return out.Metrics[i].Name < out.Metrics[j].Name })
	return out
}

func localMetrics(ctx context.Context, env *registry.Env, _ NoInput) (MetricsOutput, error) {
	stdout, _, err := run(ctx, env, localTimeout, "metrics", "print")
	if err != nil {
		return MetricsOutput{}, err
	}
	if !bytes.Contains(stdout, []byte("# TYPE ")) {
		return MetricsOutput{}, unrecognized([]string{"metrics", "print"}, "no Prometheus metric types")
	}
	return ParseMetrics(stdout), nil
}

// VersionOutput reports CLI and daemon versions.
type VersionOutput struct {
	CLI       string   `json:"cli" tk:"untrusted"`
	Daemon    string   `json:"daemon,omitempty" tk:"untrusted"`
	OSVariant string   `json:"osVariant,omitempty" tk:"untrusted"`
	Skew      bool     `json:"skew" jsonschema:"CLI and daemon release versions differ"`
	Warnings  []string `json:"warnings" tk:"untrusted"`
}

func localVersion(ctx context.Context, env *registry.Env, _ NoInput) (VersionOutput, error) {
	stdout, warnings, err := run(ctx, env, localTimeout, "version", "--json", "--daemon")
	if err != nil {
		return VersionOutput{}, err
	}
	var v struct {
		Long       string `json:"long"`
		DaemonLong string `json:"daemonLong"`
		OSVariant  string `json:"osVariant"`
	}
	if err := decodeCLI(stdout, &v, []string{"long"}, []string{"version", "--json", "--daemon"}); err != nil {
		return VersionOutput{}, err
	}
	out := VersionOutput{CLI: v.Long, Daemon: v.DaemonLong, OSVariant: v.OSVariant, Warnings: nonNil(warnings)}
	out.Skew = v.DaemonLong != "" && release(v.Long) != release(v.DaemonLong)
	return out, nil
}

// release cuts a long version ("1.102.5-1-t5fb2a81b0") to its release ("1.102.5").
func release(v string) string {
	v, _, _ = strings.Cut(v, "-")
	return v
}

// --- serve, funnel ------------------------------------------------------------

// cliServe is ipn.ServeConfig. Foreground holds the configs of foreground
// `tailscale serve` sessions; Services holds ipn.ServiceConfig values, which use
// the TCP, Web and Tun fields.
type cliServe struct {
	TCP map[string]struct {
		HTTPS        bool   `json:"HTTPS"`
		HTTP         bool   `json:"HTTP"`
		TCPForward   string `json:"TCPForward"`
		TerminateTLS string `json:"TerminateTLS"`
	} `json:"TCP"`
	Web map[string]struct {
		Handlers map[string]struct {
			Proxy    string `json:"Proxy"`
			Path     string `json:"Path"`
			Text     string `json:"Text"`
			Redirect string `json:"Redirect"`
		} `json:"Handlers"`
	} `json:"Web"`
	Tun         bool                `json:"Tun"`
	AllowFunnel map[string]bool     `json:"AllowFunnel"`
	Services    map[string]cliServe `json:"Services"`
	Foreground  map[string]cliServe `json:"Foreground"`
}

// ServeEntry is one served endpoint. Targets (local ports, file paths, URLs, text)
// are reduced to their kind.
type ServeEntry struct {
	Source   string   `json:"source" tk:"col" jsonschema:"background, foreground or service"`
	Service  string   `json:"service,omitempty" tk:"untrusted,col" jsonschema:"Tailscale Service name, for source service"`
	Listener string   `json:"listener" tk:"untrusted,col" jsonschema:"host:port for web listeners, port for TCP"`
	Kind     string   `json:"kind" tk:"col" jsonschema:"web, https, http, tcp-forward or tun"`
	Paths    []string `json:"paths,omitempty" tk:"untrusted,col"`
	Handlers []string `json:"handlers,omitempty" tk:"col" jsonschema:"handler kinds: proxy, path, text or redirect"`
	Funnel   bool     `json:"funnel" tk:"col" jsonschema:"exposed to the public internet"`
}

// ServeOutput lists served endpoints.
type ServeOutput struct {
	Entries []ServeEntry `json:"entries" tk:"rows"`
	Count   int          `json:"count"`
}

func serveEntries(c cliServe, source, service string, funnel map[string]bool) []ServeEntry {
	var out []ServeEntry
	for _, hp := range sortedKeys(c.Web) {
		e := ServeEntry{Source: source, Service: service, Listener: hp, Kind: "web", Funnel: funnel[hp]}
		kinds := map[string]bool{}
		for _, path := range sortedKeys(c.Web[hp].Handlers) {
			h := c.Web[hp].Handlers[path]
			e.Paths = append(e.Paths, path)
			switch {
			case h.Proxy != "":
				kinds["proxy"] = true
			case h.Path != "":
				kinds["path"] = true
			case h.Text != "":
				kinds["text"] = true
			case h.Redirect != "":
				kinds["redirect"] = true
			}
		}
		e.Handlers = sortedKeys(kinds)
		out = append(out, e)
	}
	for _, port := range sortedKeys(c.TCP) {
		t := c.TCP[port]
		kind := "tcp-forward"
		switch {
		case t.HTTPS:
			kind = "https"
		case t.HTTP:
			kind = "http"
		}
		on := false
		for hp, allowed := range funnel {
			if allowed && strings.HasSuffix(hp, ":"+port) {
				on = true
			}
		}
		out = append(out, ServeEntry{Source: source, Service: service, Listener: port, Kind: kind, Funnel: on})
	}
	if c.Tun {
		out = append(out, ServeEntry{Source: source, Service: service, Listener: "*", Kind: "tun"})
	}
	return out
}

// ServeStatus flattens a serve config: background, then foreground sessions, then
// Services. Funnel applies to the node's own listeners, not to Services.
func ServeStatus(c cliServe, funnelOnly bool) ServeOutput {
	all := serveEntries(c, "background", "", c.AllowFunnel)
	for _, id := range sortedKeys(c.Foreground) {
		fg := c.Foreground[id]
		all = append(all, serveEntries(fg, "foreground", "", fg.AllowFunnel)...)
	}
	for _, name := range sortedKeys(c.Services) {
		all = append(all, serveEntries(c.Services[name], "service", name, nil)...)
	}
	out := ServeOutput{Entries: []ServeEntry{}}
	for _, e := range all {
		if !funnelOnly || e.Funnel {
			out.Entries = append(out.Entries, e)
		}
	}
	out.Count = len(out.Entries)
	return out
}

func localServeStatus(ctx context.Context, env *registry.Env, _ NoInput) (ServeOutput, error) {
	var c cliServe
	if err := runJSON(ctx, env, &c, nil, "serve", "status", "--json"); err != nil {
		return ServeOutput{}, err
	}
	return ServeStatus(c, false), nil
}

func localFunnelStatus(ctx context.Context, env *registry.Env, _ NoInput) (ServeOutput, error) {
	var c cliServe
	if err := runJSON(ctx, env, &c, nil, "funnel", "status", "--json"); err != nil {
		return ServeOutput{}, err
	}
	return ServeStatus(c, true), nil
}

// --- syspolicy ----------------------------------------------------------------

// safeStringPolicies may show their string values. Every other string is
// redacted: policies such as AuthKey carry secrets.
var safeStringPolicies = map[string]bool{"Tailnet": true, "ExitNodeID": true, "LoginURL": true, "ManagedByOrganizationName": true}

// Policy is one effective system policy.
type Policy struct {
	Name   string `json:"name" tk:"untrusted,col"`
	Value  string `json:"value" tk:"untrusted,col"`
	Origin string `json:"origin,omitempty" tk:"untrusted,col"`
	Error  string `json:"error,omitempty" tk:"untrusted"`
}

// SyspolicyOutput lists effective policies.
type SyspolicyOutput struct {
	Scope    string   `json:"scope,omitempty" tk:"untrusted"`
	Policies []Policy `json:"policies" tk:"rows"`
}

type cliOrigin struct {
	Name  string `json:"Name"`
	Scope string `json:"Scope"`
}

func localSyspolicy(ctx context.Context, env *registry.Env, _ NoInput) (SyspolicyOutput, error) {
	var r struct {
		Summary struct {
			Scope string `json:"Scope"`
		} `json:"Summary"`
		Settings map[string]struct {
			Value  any        `json:"Value"`
			Origin *cliOrigin `json:"Origin"`
			Error  string     `json:"Error"`
		} `json:"Settings"`
	}
	args := []string{"syspolicy", "list", "--json"}
	stdout, _, err := run(ctx, env, localTimeout, args...)
	if err != nil {
		return SyspolicyOutput{}, err
	}
	var top map[string]json.RawMessage
	if err := decodeCLI(stdout, &top, nil, args); err != nil {
		return SyspolicyOutput{}, err
	}
	// A node without policies prints {} (Settings is omitted when empty); any other
	// document must carry Settings or Summary.
	if len(top) > 0 && top["Settings"] == nil && top["Summary"] == nil {
		return SyspolicyOutput{}, unrecognized(args, "JSON without Settings or Summary")
	}
	if err := decodeCLI(stdout, &r, nil, args); err != nil {
		return SyspolicyOutput{}, err
	}
	out := SyspolicyOutput{Scope: r.Summary.Scope, Policies: []Policy{}}
	for _, name := range sortedKeys(r.Settings) {
		s := r.Settings[name]
		p := Policy{Name: name, Error: s.Error}
		if s.Error != "" && !safeStringPolicies[name] {
			p.Error = "(redacted)" // an error can quote the value it could not use
		}
		if s.Origin != nil {
			p.Origin = s.Origin.Name
		}
		switch v := s.Value.(type) {
		case nil:
		case bool:
			p.Value = strconv.FormatBool(v)
		case float64:
			p.Value = strconv.FormatFloat(v, 'f', -1, 64)
		case string:
			p.Value = "(redacted)"
			if safeStringPolicies[name] {
				p.Value = v
			}
		default:
			p.Value = "(redacted)"
		}
		out.Policies = append(out.Policies, p)
	}
	return out, nil
}
