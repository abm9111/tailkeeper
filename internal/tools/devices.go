package tools

import (
	"context"
	"encoding/json"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// apiDevice mirrors the API's Device schema. Fields tailkeeper never shows
// (machineKey, nodeKey, tailnetLockKey, postureIdentity serial numbers, client
// endpoints) are not declared, so they are dropped on decode.
type apiDevice struct {
	Addresses                 []string `json:"addresses"`
	ID                        string   `json:"id"`
	NodeID                    string   `json:"nodeId"`
	User                      string   `json:"user"`
	Name                      string   `json:"name"`
	Hostname                  string   `json:"hostname"`
	ClientVersion             string   `json:"clientVersion"`
	UpdateAvailable           bool     `json:"updateAvailable"`
	OS                        string   `json:"os"`
	Created                   string   `json:"created"`
	ConnectedToControl        bool     `json:"connectedToControl"`
	LastSeen                  string   `json:"lastSeen"`
	KeyExpiryDisabled         bool     `json:"keyExpiryDisabled"`
	Expires                   string   `json:"expires"`
	Authorized                bool     `json:"authorized"`
	IsExternal                bool     `json:"isExternal"`
	IsEphemeral               bool     `json:"isEphemeral"`
	BlocksIncomingConnections bool     `json:"blocksIncomingConnections"`
	Tags                      []string `json:"tags"`
	TailnetLockError          string   `json:"tailnetLockError"`
	// Only with fields=all:
	MultipleConnections *bool    `json:"multipleConnections"`
	SSHEnabled          *bool    `json:"sshEnabled"`
	EnabledRoutes       []string `json:"enabledRoutes"`
	AdvertisedRoutes    []string `json:"advertisedRoutes"`
	ClientConnectivity  *struct {
		MappingVariesByDestIP bool `json:"mappingVariesByDestIP"`
		Latency               map[string]struct {
			Preferred bool    `json:"preferred"`
			LatencyMs float64 `json:"latencyMs"`
		} `json:"latency"`
		ClientSupports Supports `json:"clientSupports"`
	} `json:"clientConnectivity"`
	Distro *Distro `json:"distro"`
}

// Supports reports NAT traversal features (nil = unknown).
type Supports struct {
	IPv6 *bool `json:"ipv6,omitempty"`
	PCP  *bool `json:"pcp,omitempty"`
	PMP  *bool `json:"pmp,omitempty"`
	UDP  *bool `json:"udp,omitempty"`
	UPnP *bool `json:"upnp,omitempty"`
}

// Distro is the reported OS distribution.
type Distro struct {
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	CodeName string `json:"codeName,omitempty"`
}

// Connectivity summarises clientConnectivity without public endpoints.
type Connectivity struct {
	HardNAT            bool     `json:"hardNat" jsonschema:"mappingVariesByDestIP: the NAT maps differently per destination"`
	Supports           Supports `json:"supports"`
	PreferredDERP      string   `json:"preferredDerp,omitempty" tk:"untrusted"`
	PreferredLatencyMs float64  `json:"preferredLatencyMs,omitempty"`
}

// Device is the device shape tailkeeper returns.
type Device struct {
	NodeID                    string        `json:"nodeId" tk:"col"`
	Name                      string        `json:"name" tk:"untrusted,col"`
	Hostname                  string        `json:"hostname" tk:"untrusted"`
	User                      string        `json:"user" tk:"untrusted,col,personal"`
	OS                        string        `json:"os" tk:"untrusted,col"`
	Tags                      []string      `json:"tags,omitempty" tk:"untrusted"`
	Addresses                 []string      `json:"addresses,omitempty"`
	ClientVersion             string        `json:"clientVersion,omitempty" tk:"untrusted"`
	UpdateAvailable           bool          `json:"updateAvailable"`
	Created                   string        `json:"created,omitempty"`
	Expires                   string        `json:"expires,omitempty"`
	LastSeen                  string        `json:"lastSeen,omitempty" tk:"col"`
	ConnectedToControl        bool          `json:"connectedToControl" tk:"col"`
	KeyExpiryDisabled         bool          `json:"keyExpiryDisabled"`
	Authorized                bool          `json:"authorized"`
	IsExternal                bool          `json:"isExternal"`
	IsEphemeral               bool          `json:"isEphemeral"`
	BlocksIncomingConnections bool          `json:"blocksIncomingConnections"`
	TailnetLockError          string        `json:"tailnetLockError,omitempty" tk:"untrusted"`
	MultipleConnections       *bool         `json:"multipleConnections,omitempty"`
	SSHEnabled                *bool         `json:"sshEnabled,omitempty"`
	AdvertisedRoutes          []string      `json:"advertisedRoutes,omitempty" tk:"untrusted,plain"`
	EnabledRoutes             []string      `json:"enabledRoutes,omitempty" tk:"untrusted,plain"`
	Connectivity              *Connectivity `json:"connectivity,omitempty"`
	Distro                    *Distro       `json:"distro,omitempty" tk:"untrusted"`
	Fields                    string        `json:"fields" jsonschema:"default or all: which API field set was requested; fields absent here are unknown, not false"`
}

func toDevice(a apiDevice, fields string) Device {
	d := Device{
		NodeID: a.NodeID, Name: a.Name, Hostname: a.Hostname, User: a.User, OS: a.OS, Tags: a.Tags,
		Addresses: a.Addresses, ClientVersion: a.ClientVersion, UpdateAvailable: a.UpdateAvailable,
		Created: a.Created, Expires: a.Expires, LastSeen: a.LastSeen, ConnectedToControl: a.ConnectedToControl,
		KeyExpiryDisabled: a.KeyExpiryDisabled, Authorized: a.Authorized, IsExternal: a.IsExternal,
		IsEphemeral: a.IsEphemeral, BlocksIncomingConnections: a.BlocksIncomingConnections,
		TailnetLockError: a.TailnetLockError, MultipleConnections: a.MultipleConnections, SSHEnabled: a.SSHEnabled,
		AdvertisedRoutes: a.AdvertisedRoutes, EnabledRoutes: a.EnabledRoutes, Distro: a.Distro, Fields: fields,
	}
	if cc := a.ClientConnectivity; cc != nil {
		c := &Connectivity{HardNAT: cc.MappingVariesByDestIP, Supports: cc.ClientSupports}
		for region, l := range cc.Latency {
			if l.Preferred {
				c.PreferredDERP, c.PreferredLatencyMs = region, l.LatencyMs
			}
		}
		d.Connectivity = c
	}
	return d
}

// DevicesListInput filters devices. Server-side filters are exact matches.
type DevicesListInput struct {
	Tags         []string `json:"tags,omitempty" jsonschema:"devices must carry all of these tags (server-side, exact)"`
	OS           string   `json:"os,omitempty" jsonschema:"exact OS name, for example linux, macOS, windows (server-side)"`
	Hostname     string   `json:"hostname,omitempty" jsonschema:"exact hostname (server-side); while personal data is masked, refused if it contains an email address or a public IP address"`
	User         string   `json:"user,omitempty" jsonschema:"exact owner login name (server-side); while personal data is masked, only a pseudonym (p:…) or a masked value carrying one, matched client-side, or tagged-devices (server-side)"`
	Ephemeral    *bool    `json:"ephemeral,omitempty" jsonschema:"filter on isEphemeral (server-side)"`
	Authorized   *bool    `json:"authorized,omitempty" jsonschema:"filter on authorized (server-side)"`
	Online       *bool    `json:"online,omitempty" jsonschema:"filter on connectedToControl (server-side)"`
	NameContains string   `json:"nameContains,omitempty" jsonschema:"case-insensitive substring of name or hostname as the result shows them, where an email or public address is masked while personal data is masked (client-side)"`
	StaleDays    int      `json:"staleDays,omitempty" jsonschema:"only devices not connected and last seen more than this many days ago (client-side)"`
	AllFields    bool     `json:"allFields,omitempty" jsonschema:"request fields=all: routes, connectivity, SSH, cloned-state flag"`
}

// DevicesListOutput lists devices.
type DevicesListOutput struct {
	Devices       []Device `json:"devices" tk:"rows"`
	Count         int      `json:"count"`
	Fields        string   `json:"fields"`
	ServerFilters []string `json:"serverFilters"`
	ClientFilters []string `json:"clientFilters"`
}

// DeviceRef names one device.
type DeviceRef struct {
	Device string `json:"device" jsonschema:"node ID (preferred), numeric ID, or exact hostname as the result shows it: while personal data is masked, an email or public address in it is masked, so use the node ID"`
}

// DeviceRoutesInput selects a device and optionally computes HA peers.
type DeviceRoutesInput struct {
	Device    string `json:"device" jsonschema:"node ID (preferred), numeric ID, or exact hostname as the result shows it: while personal data is masked, an email or public address in it is masked, so use the node ID"`
	IncludeHA bool   `json:"includeHa,omitempty" jsonschema:"also list other devices with identical enabled subnet routes (exit-node routes are not HA)"`
}

// RoutePeer is another device serving the same prefix.
type RoutePeer struct {
	Prefix string `json:"prefix" tk:"untrusted,plain"`
	NodeID string `json:"nodeId"`
	Name   string `json:"name" tk:"untrusted"`
}

// DeviceRoutesOutput shows route approval state.
type DeviceRoutesOutput struct {
	NodeID             string      `json:"nodeId"`
	Advertised         []string    `json:"advertised" tk:"untrusted,plain"`
	Enabled            []string    `json:"enabled" tk:"untrusted,plain"`
	Pending            []string    `json:"pending" jsonschema:"advertised but not approved" tk:"untrusted,plain"`
	Latent             []string    `json:"latent" jsonschema:"approved but not advertised: activates if this identity ever advertises it" tk:"untrusted,plain"`
	ExitNodeAdvertised bool        `json:"exitNodeAdvertised"`
	ExitNodeEnabled    bool        `json:"exitNodeEnabled"`
	HAPeers            []RoutePeer `json:"haPeers,omitempty"`
}

// PostureAttribute is one device posture attribute.
type PostureAttribute struct {
	Attribute string `json:"attribute" tk:"untrusted,col"`
	Value     string `json:"value" tk:"untrusted,col"`
	Type      string `json:"type" tk:"col"`
	Expiry    string `json:"expiry,omitempty" tk:"col"`
}

// DevicePostureOutput lists a device's posture attributes.
type DevicePostureOutput struct {
	NodeID     string             `json:"nodeId"`
	Attributes []PostureAttribute `json:"attributes" tk:"rows"`
}

func deviceTools() []registry.Tool {
	return []registry.Tool{
		registry.Define(withOps(readMeta("devices_list", "devices", "list", "List devices with server-side and client-side filters.", "devices:core:read"),
			"GET /tailnet/{tailnet}/devices"), devicesList),
		registry.Define(withOps(readMeta("device_get", "devices", "get", "Get one device with all fields.", "devices:core:read"),
			"GET /tailnet/{tailnet}/devices", "GET /device/{deviceId}"), deviceGet),
		registry.Define(withOps(readMeta("device_routes", "devices", "routes", "Show advertised, approved, pending and latent routes of a device.", "devices:routes:read", "devices:core:read"),
			"GET /tailnet/{tailnet}/devices", "GET /device/{deviceId}/routes"), deviceRoutes),
		registry.Define(withOps(readMeta("device_posture_attributes", "devices", "posture", "List a device's posture attributes and their expiries.", "devices:posture_attributes:read", "devices:core:read"),
			"GET /tailnet/{tailnet}/devices", "GET /device/{deviceId}/attributes"), devicePosture),
	}
}

func devicesList(ctx context.Context, env *registry.Env, in DevicesListInput) (DevicesListOutput, error) {
	if in.StaleDays < 0 || in.StaleDays > 3650 {
		return DevicesListOutput{}, validationf("staleDays must be between 0 and 3650")
	}
	fields := "default"
	if in.AllFields {
		fields = "all"
	}
	user, userRef := in.User, ""
	if p, ok := privacy.Ref(in.User); ok {
		if _, err := env.RequirePrivacy(); err != nil {
			return DevicesListOutput{}, err
		}
		user, userRef = "", p
	} else if in.User != "" && !env.ShowPersonalData() && !sanitize.IsTaggedDevices(in.User) {
		return DevicesListOutput{}, filterRefused(env, "user", false)
	}
	if in.Hostname != "" && !env.ShowPersonalData() && sanitize.MaskText(in.Hostname) != in.Hostname {
		// An exact match on text the result masks would confirm a guess at it.
		return DevicesListOutput{}, tkerr.New(tkerr.FilterRefused,
			"while personal data is masked, hostname cannot be an email address or a public IP address: a match would confirm a guess at text the result masks",
			"filter on a part of the name that is not an address, or the owner can set personalData to show")
	}
	q := url.Values{"fields": {fields}}
	var server, client []string
	for _, tag := range lower(in.Tags) {
		if !strings.HasPrefix(tag, "tag:") || len(tag) < 5 || strings.ContainsAny(tag, " \t,") {
			return DevicesListOutput{}, validationf("tags must look like tag:name")
		}
		q.Add("tags", tag)
		server = append(server, "tags="+tag)
	}
	for name, v := range map[string]string{"os": in.OS, "hostname": in.Hostname, "user": user} {
		if v != "" {
			q.Set(name, v)
			server = append(server, name)
		}
	}
	for name, v := range map[string]*bool{"isEphemeral": in.Ephemeral, "authorized": in.Authorized, "connectedToControl": in.Online} {
		if v != nil {
			q.Set(name, strconv.FormatBool(*v))
			server = append(server, name+"="+strconv.FormatBool(*v))
		}
	}
	path, err := tailnetPath(env, "/devices")
	if err != nil {
		return DevicesListOutput{}, err
	}
	var resp struct {
		Devices []apiDevice `json:"devices"`
	}
	if err := get(ctx, env, path, q, &resp); err != nil {
		return DevicesListOutput{}, err
	}
	needle := strings.ToLower(in.NameContains)
	if needle != "" {
		client = append(client, "nameContains")
	}
	if in.StaleDays > 0 {
		client = append(client, "staleDays="+strconv.Itoa(in.StaleDays))
	}
	if userRef != "" {
		client = append(client, "user (pseudonym)")
	}
	cutoff := env.Clock().Add(-time.Duration(in.StaleDays) * 24 * time.Hour)
	out := DevicesListOutput{Fields: fields, ServerFilters: sorted(server), ClientFilters: client, Devices: []Device{}}
	for _, a := range resp.Devices {
		name, hostname := shownNames(env, a)
		if needle != "" && !strings.Contains(strings.ToLower(name), needle) && !strings.Contains(strings.ToLower(hostname), needle) {
			continue
		}
		if in.StaleDays > 0 && !stale(a, cutoff) {
			continue
		}
		if userRef != "" && !slices.Contains(wholeRefs(env, a.User), userRef) {
			continue
		}
		out.Devices = append(out.Devices, toDevice(a, fields))
	}
	sort.Slice(out.Devices, func(i, j int) bool {
		if out.Devices[i].Name != out.Devices[j].Name {
			return out.Devices[i].Name < out.Devices[j].Name
		}
		return out.Devices[i].NodeID < out.Devices[j].NodeID
	})
	out.Count = len(out.Devices)
	return out, nil
}

// shownNames returns a device's name and hostname as a result shows them, masked
// unless the owner opted in. A filter or a lookup that read the raw text would
// confirm a guess at an address inside a name that the result hides.
func shownNames(env *registry.Env, a apiDevice) (name, hostname string) {
	t := struct {
		Name     string `tk:"untrusted"`
		Hostname string `tk:"untrusted"`
	}{a.Name, a.Hostname}
	env.Display(&t)
	return t.Name, t.Hostname
}

// stale: not connected now, and last seen before cutoff (or never seen).
func stale(a apiDevice, cutoff time.Time) bool {
	if a.ConnectedToControl {
		return false
	}
	if a.LastSeen == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339Nano, a.LastSeen)
	return err == nil && t.Before(cutoff)
}

func sorted(ss []string) []string {
	out := append([]string{}, ss...)
	sort.Strings(out)
	return out
}

// resolveDevice turns a node ID, numeric ID or exact hostname into an API device ID.
func resolveDevice(ctx context.Context, env *registry.Env, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if nodeIDRE.MatchString(ref) || legacyIDRE.MatchString(ref) {
		return ref, nil
	}
	if ref == "" || len(ref) > 253 {
		return "", validationf("device must be a node ID, numeric ID or hostname")
	}
	path, err := tailnetPath(env, "/devices")
	if err != nil {
		return "", err
	}
	var resp struct {
		Devices []apiDevice `json:"devices"`
	}
	if err := get(ctx, env, path, url.Values{"fields": {"default"}}, &resp); err != nil {
		return "", err
	}
	var matches []string
	for _, d := range resp.Devices {
		name, hostname := shownNames(env, d)
		short, _, _ := strings.Cut(name, ".")
		if strings.EqualFold(hostname, ref) || strings.EqualFold(short, ref) || strings.EqualFold(name, ref) {
			matches = append(matches, d.NodeID)
		}
	}
	switch len(matches) {
	case 0:
		return "", tkerr.New(tkerr.NotFound, "no device matches "+strconv.Quote(ref), "use devices_list to find the node ID")
	case 1:
		return matches[0], nil
	}
	return "", validationf(strconv.Itoa(len(matches)) + " devices match " + strconv.Quote(ref) + "; use the node ID")
}

func deviceGet(ctx context.Context, env *registry.Env, in DeviceRef) (Device, error) {
	id, err := resolveDevice(ctx, env, in.Device)
	if err != nil {
		return Device{}, err
	}
	var a apiDevice
	if err := get(ctx, env, api.Path("device/%s", id), url.Values{"fields": {"all"}}, &a); err != nil {
		return Device{}, err
	}
	return toDevice(a, "all"), nil
}

func deviceRoutes(ctx context.Context, env *registry.Env, in DeviceRoutesInput) (DeviceRoutesOutput, error) {
	id, err := resolveDevice(ctx, env, in.Device)
	if err != nil {
		return DeviceRoutesOutput{}, err
	}
	var r struct {
		Advertised []string `json:"advertisedRoutes"`
		Enabled    []string `json:"enabledRoutes"`
	}
	if err := get(ctx, env, api.Path("device/%s/routes", id), nil, &r); err != nil {
		return DeviceRoutesOutput{}, err
	}
	adv, en := normPrefixes(r.Advertised), normPrefixes(r.Enabled)
	out := DeviceRoutesOutput{
		NodeID: id, Advertised: adv, Enabled: en, Pending: minus(adv, en), Latent: minus(en, adv),
		ExitNodeAdvertised: isExit(adv), ExitNodeEnabled: isExit(en),
	}
	if in.IncludeHA && len(en) > 0 {
		path, err := tailnetPath(env, "/devices")
		if err != nil {
			return DeviceRoutesOutput{}, err
		}
		var resp struct {
			Devices []apiDevice `json:"devices"`
		}
		if err := get(ctx, env, path, url.Values{"fields": {"all"}}, &resp); err != nil {
			return DeviceRoutesOutput{}, err
		}
		mine := map[string]bool{}
		for _, p := range en {
			if !isExit([]string{p}) {
				mine[p] = true
			}
		}
		for _, d := range resp.Devices {
			if d.NodeID == id || d.ID == id {
				continue
			}
			for _, p := range normPrefixes(d.EnabledRoutes) {
				if mine[p] {
					out.HAPeers = append(out.HAPeers, RoutePeer{Prefix: p, NodeID: d.NodeID, Name: d.Name})
				}
			}
		}
	}
	return out, nil
}

func normPrefixes(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if p, err := netip.ParsePrefix(s); err == nil {
			s = p.Masked().String()
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func minus(a, b []string) []string {
	in := map[string]bool{}
	for _, s := range b {
		in[s] = true
	}
	out := []string{}
	for _, s := range a {
		if !in[s] {
			out = append(out, s)
		}
	}
	return out
}

func isExit(prefixes []string) bool {
	for _, p := range prefixes {
		if p == "0.0.0.0/0" || p == "::/0" {
			return true
		}
	}
	return false
}

func devicePosture(ctx context.Context, env *registry.Env, in DeviceRef) (DevicePostureOutput, error) {
	id, err := resolveDevice(ctx, env, in.Device)
	if err != nil {
		return DevicePostureOutput{}, err
	}
	var r struct {
		Attributes map[string]any    `json:"attributes"`
		Expiries   map[string]string `json:"expiries"`
	}
	if err := get(ctx, env, api.Path("device/%s/attributes", id), nil, &r); err != nil {
		return DevicePostureOutput{}, err
	}
	out := DevicePostureOutput{NodeID: id, Attributes: []PostureAttribute{}}
	for _, k := range sortedKeys(r.Attributes) {
		a := PostureAttribute{Attribute: k, Expiry: r.Expiries[k]}
		switch v := r.Attributes[k].(type) {
		case string:
			a.Type, a.Value = "string", v
		case bool:
			a.Type, a.Value = "boolean", strconv.FormatBool(v)
		case float64:
			a.Type, a.Value = "number", strconv.FormatFloat(v, 'f', -1, 64)
		default:
			a.Type = "other"
			if b, err := json.Marshal(v); err == nil {
				a.Value = string(b)
			}
		}
		out.Attributes = append(out.Attributes, a)
	}
	return out, nil
}
