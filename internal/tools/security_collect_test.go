package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/api/openapi"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// Everything here is synthetic. The collector is tested against the fake API and the
// stand-in CLI, with an audit callback that records what it was given and what the sources
// had been asked by then.

const selfID = "nSELF1CNTRL"

// observation is one event the audit callback accepted, with the state of the sources at the
// time.
type observation struct {
	ev       security.CollectionEvent
	call     registry.Call
	requests int  // API requests the fake had received
	cliCalls int  // CLI calls the stand-in had received
	live     bool // the context was not cancelled
}

// rig is a collection's world: a fake API, optionally a stand-in CLI, and an audit callback.
type rig struct {
	t      *testing.T
	f      *apitest.Fake
	cli    *fakeCLI
	env    *registry.Env
	mu     sync.Mutex
	got    []observation
	tried  int
	failAt int // the nth record fails (1 is the first); 0 never
	// forward, if set, is where each event goes after it is noted: a real App's record.
	forward func(context.Context, security.CollectionEvent) error
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, f: apitest.New(t)}
	r.env = &registry.Env{Now: func() time.Time { return now }, API: r.f.Client(t), RecordObservation: r.record}
	return r
}

// newCLIRig is a rig with a stand-in CLI as well.
func newCLIRig(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	r.cli = newFakeCLI(t)
	r.env.Local = r.cli.env().Local
	return r
}

func (r *rig) record(ctx context.Context, ev security.CollectionEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tried++
	if err := ev.Validate(); err != nil {
		r.t.Errorf("an invalid event reached the audit callback: %v", err)
	}
	if r.tried == r.failAt {
		return tkerr.New(tkerr.AuditUnavailable, "synthetic: the audit log cannot be written", "")
	}
	o := observation{ev: ev, call: registry.CallOf(ctx), requests: len(r.f.Requests()), live: ctx.Err() == nil}
	if r.cli != nil {
		o.cliCalls = len(r.cli.calls())
	}
	r.got = append(r.got, o)
	if r.forward != nil {
		return r.forward(ctx, ev)
	}
	return nil
}

// event is the recorded event of a source and phase.
func (r *rig) event(src security.CollectionSource, ph security.CollectionPhase) observation {
	r.t.Helper()
	for _, o := range r.got {
		if o.ev.Source == src && o.ev.Phase == ph {
			return o
		}
	}
	r.t.Fatalf("no %s event for %s in %+v", ph, src, r.got)
	return observation{}
}

func (r *rig) collect(scope security.Scope, required ...string) tools.SecurityCollection {
	r.t.Helper()
	c, err := tools.CollectSecurity(context.Background(), r.env, scope, required...)
	if err != nil {
		r.t.Fatalf("collection: %v", err)
	}
	requireValid(r.t, c)
	return c
}

// requireValid fails the test unless the snapshot passes the checks Match applies and the
// whole collection, as a report, passes ValidateReport.
func requireValid(t *testing.T, c tools.SecurityCollection) {
	t.Helper()
	if err := security.ValidateSnapshot(c.Snapshot, now); err != nil {
		t.Fatalf("the snapshot does not validate: %v", err)
	}
	rep := security.Report{SchemaVersion: security.SchemaVersion, Context: c.Snapshot.Context, GeneratedAt: now, Status: security.ReportPartial,
		Snapshot: c.Snapshot, Coverage: c.Coverage}
	if err := security.ValidateReport(rep); err != nil {
		t.Fatalf("the collection does not validate as a report: %v", err)
	}
}

func seenAgo(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }

// dev is an API device that runs a stable release, is connected and was seen a minute ago.
// A nil value in extra removes the field.
func dev(id string, extra map[string]any) map[string]any {
	d := map[string]any{"nodeId": id, "clientVersion": "1.102.5-t0123456ab", "os": "linux", "lastSeen": seenAgo(time.Minute), "connectedToControl": true}
	for k, v := range extra {
		if v == nil {
			delete(d, k)
		} else {
			d[k] = v
		}
	}
	return d
}

func (r *rig) devices(devs ...map[string]any) {
	r.t.Helper()
	if devs == nil {
		devs = []map[string]any{}
	}
	body, err := json.Marshal(map[string]any{"devices": devs})
	if err != nil {
		r.t.Fatal(err)
	}
	r.f.JSON("GET", tailnetPath+"/devices", 200, string(body))
}

// serveLocal answers the three local reads. ssh is the value of the ssh preference as JSON,
// or "" to leave the preference out.
func serveLocal(r *rig, ssh string) {
	r.t.Helper()
	r.cli.on("status --json --peers=false", 0, `{"BackendState":"Running","Self":{"ID":"`+selfID+`","OS":"linux"},`+
		`"Peer":{"nodekey:aa":{"ID":"nPEER1CNTRL","OS":"windows"}}}`, "")
	r.cli.on("version --json --daemon", 0, `{"long":"1.102.5-t0123456ab","daemonLong":"1.102.5-t0123456ab-gfedcba987"}`, "")
	prefs := `{"accept-dns":true}`
	if ssh != "" {
		prefs = `{"accept-dns":true,"ssh":` + ssh + `}`
	}
	r.cli.on("get --json", 0, prefs, "")
}

// feature finds the feature fact of a device by name.
func feature(s security.Snapshot, asset, name string) (security.FeatureFact, bool) {
	for _, f := range s.Features {
		if f.Evidence.Asset == asset && f.Name == name {
			return f, true
		}
	}
	return security.FeatureFact{}, false
}

func versionsOf(s security.Snapshot, asset string) []security.VersionFact {
	var out []security.VersionFact
	for _, v := range s.Versions {
		if v.Evidence.Asset == asset {
			out = append(out, v)
		}
	}
	return out
}

func assets(s security.Snapshot) []string {
	set := map[string]bool{}
	for _, v := range s.Versions {
		set[v.Evidence.Asset] = true
	}
	for _, p := range s.Platforms {
		set[p.Evidence.Asset] = true
	}
	for _, f := range s.Features {
		set[f.Evidence.Asset] = true
	}
	var out []string
	for a := range set {
		out = append(out, a)
	}
	slices.Sort(out)
	return out
}

func row(t *testing.T, c tools.SecurityCollection, dim security.CoverageDimension) security.Coverage {
	t.Helper()
	for _, r := range c.Coverage {
		if r.Target.Dimension == dim {
			return r
		}
	}
	t.Fatalf("no %s coverage row in %+v", dim, c.Coverage)
	return security.Coverage{}
}

// The producer contract: every fact names its device, keeps the raw strings and the presence
// of each decision field, gives the channel its release says, takes the device's own lastSeen
// as the time it was observed, and records where it came from (the API reports a version, the
// local daemon runs one).
func TestCollectionPreservesEveryDecisionFieldPresenceAndVersionOrigin(t *testing.T) {
	r := newCLIRig(t)
	serveLocal(r, "false")
	states := []struct {
		name string
		v    any
	}{{"absent", nil}, {"false", false}, {"true", true}}
	var devs []map[string]any
	for ci, c := range states {
		for si, s := range states {
			devs = append(devs, dev(fmt.Sprintf("nD%d%dCNTRL", ci, si), map[string]any{"connectedToControl": c.v, "sshEnabled": s.v}))
		}
	}
	devs = append(devs, dev("nUNST1CNTRL", map[string]any{"clientVersion": "1.103.1"}), dev("nODD1CNTRL", map[string]any{"clientVersion": "v1.2"}))
	// This node is one of the tailnet's devices (the local facts join only then); the API says
	// nothing about its version, system or SSH, so what it has of those is the daemon's.
	devs = append(devs, dev(selfID, map[string]any{"clientVersion": nil, "os": nil}))
	r.devices(devs...)
	snap := r.collect(security.ScopeFleet).Snapshot

	check := func(id, name, state string, want any) {
		t.Helper()
		f, found := feature(snap, id, name)
		switch {
		case want == nil && found:
			t.Errorf("%s: %s is absent from the API and has a fact: %+v", id, name, f)
		case want == nil:
		case !found || f.Value == nil || *f.Value != want.(bool):
			t.Errorf("%s: %s %s from the API, got %+v (found %v)", id, name, state, f, found)
		case f.Evidence.Origin != security.OriginAPI:
			t.Errorf("%s: %s has origin %s", id, name, f.Evidence.Origin)
		}
	}
	for ci, c := range states {
		for si, s := range states {
			id := fmt.Sprintf("nD%d%dCNTRL", ci, si)
			check(id, security.FeatureConnectedToControl, c.name, c.v)
			check(id, security.FeatureTailscaleSSH, s.name, s.v)
		}
	}
	// A version the API reports is the API's report, with the raw string and the device's own time.
	vs := versionsOf(snap, "nD11CNTRL")
	if len(vs) != 1 {
		t.Fatalf("versions of a device: %+v", vs)
	}
	v := vs[0]
	if v.Role != security.VersionAPIReported || v.Name != "client" || v.Channel != security.ChannelStable || v.Value == nil || *v.Value != "1.102.5-t0123456ab" ||
		v.Evidence.Origin != security.OriginAPI || v.Evidence.Scope != security.ScopeFleet || !v.Evidence.AcquiredAt.Equal(now) ||
		v.Evidence.ObservedAt == nil || !v.Evidence.ObservedAt.Equal(now.Add(-time.Minute)) || v.Evidence.Error != "" || v.Evidence.Freshness != security.FreshnessFresh {
		t.Errorf("api version fact: %+v", v)
	}
	if c := versionsOf(snap, "nUNST1CNTRL")[0].Channel; c != security.ChannelUnstable {
		t.Errorf("a release with an odd minor has channel %s", c)
	}
	if c := versionsOf(snap, "nODD1CNTRL")[0].Channel; c != security.ChannelUnknown {
		t.Errorf("an unparseable build has channel %s", c)
	}
	// This node: the daemon runs a version, the CLI reports one, the preference is off; the source gives no time.
	roles := map[security.VersionRole]string{}
	for _, v := range versionsOf(snap, selfID) {
		if v.Evidence.Origin != security.OriginLocal || v.Evidence.ObservedAt != nil || v.Value == nil {
			t.Errorf("local version fact: %+v", v)
		} else {
			roles[v.Role] = *v.Value
		}
	}
	if roles[security.VersionRunningDaemon] != "1.102.5-t0123456ab-gfedcba987" || roles[security.VersionLocalCLI] != "1.102.5-t0123456ab" || len(roles) != 2 {
		t.Errorf("local versions: %v", roles)
	}
	if f, ok := feature(snap, selfID, security.FeatureTailscaleSSH); !ok || f.Value == nil || *f.Value || f.Evidence.Origin != security.OriginLocal {
		t.Errorf("the local ssh preference: %+v", f)
	}
	for _, p := range snap.Platforms {
		if p.OS != "linux" || p.Evidence.Asset == "" {
			t.Errorf("platform fact: %+v", p)
		}
	}
	// Every fact names a device.
	for _, f := range snap.Features {
		if f.Evidence.Asset == "" {
			t.Errorf("a feature fact names no device: %+v", f)
		}
	}
}

// The local ssh preference is a fact only when the CLI gave it.
func TestAbsentLocalSSHPreferenceIsNoFact(t *testing.T) {
	r := newCLIRig(t)
	serveLocal(r, "")
	snap := r.collect(security.ScopeLocal).Snapshot
	if f, ok := feature(snap, selfID, security.FeatureTailscaleSSH); ok {
		t.Errorf("an absent preference has a fact: %+v", f)
	}
	serveLocal(r, "true")
	if f, ok := feature(r.collect(security.ScopeLocal).Snapshot, selfID, security.FeatureTailscaleSSH); !ok || f.Value == nil || !*f.Value {
		t.Errorf("a preference that is on: %+v", f)
	}
}

// The parsed device keeps absent, false and true apart for the decision fields no fact is
// made of yet, as for the two that are.
func TestObservedDevicesKeepThePresenceOfEveryDecisionField(t *testing.T) {
	body := `{"devices":[
	  {"nodeId":"n1"},
	  {"nodeId":"n2","connectedToControl":false,"authorized":false,"blocksIncomingConnections":false,"sshEnabled":false},
	  {"nodeId":"n3","connectedToControl":true,"authorized":true,"blocksIncomingConnections":true,"sshEnabled":true}]}`
	got, err := tools.DecodeSecurityDevices([]byte(body))
	if err != nil || len(got) != 3 {
		t.Fatalf("%v %v", got, err)
	}
	for i, want := range []*bool{nil, new(bool), ptr(true)} {
		for name, p := range map[string]*bool{"connectedToControl": got[i].Connected, "authorized": got[i].Authorized,
			"blocksIncomingConnections": got[i].BlocksIncomingConnections, "sshEnabled": got[i].SSHEnabled} {
			if (p == nil) != (want == nil) || (p != nil && *p != *want) {
				t.Errorf("device %d: %s = %v, want %v", i+1, name, p, want)
			}
		}
	}
}

func ptr(b bool) *bool { return &b }

// A local collection is about this node: it asks for no peers, makes no API request, and
// claims no fleet coverage, even when the CLI hands it a netmap.
func TestLocalNetmapDoesNotClaimFleetCoverage(t *testing.T) {
	r := newCLIRig(t)
	serveLocal(r, "true")
	c := r.collect(security.ScopeLocal)
	if got := assets(c.Snapshot); !slices.Equal(got, []string{selfID}) {
		t.Errorf("assets = %v, want only this node", got)
	}
	if c.Snapshot.Scope != security.ScopeLocal || len(r.f.Requests()) != 0 {
		t.Errorf("scope %s, %d API requests", c.Snapshot.Scope, len(r.f.Requests()))
	}
	if !slices.Contains(r.cli.calls(), "status --json --peers=false") {
		t.Errorf("peers were asked for: %v", r.cli.calls())
	}
	if len(c.Coverage) != 2 {
		t.Fatalf("coverage = %+v", c.Coverage)
	}
	for _, row := range c.Coverage {
		if row.Target.Scope != security.ScopeLocal || row.Status != security.ReportComplete || row.Target.Asset != "" {
			t.Errorf("row %+v", row)
		}
	}
	for _, o := range r.got {
		if o.ev.Source == security.SourceAPIDevices || o.ev.Scope != security.ScopeLocal {
			t.Errorf("event %+v", o.ev)
		}
	}
}

// A source is recorded before it is asked and after it ended, in order, and a collection asks
// no more than the four operations it declares: the API's device list with fields=all, and
// three CLI reads. The API operation is one of the pinned document's; every request is a GET.
func TestNoSourceIsAskedBeforeItsAttemptIsRecorded(t *testing.T) {
	r := newCLIRig(t)
	serveLocal(r, "false")
	r.devices(dev("nAAA1CNTRL", map[string]any{"sshEnabled": false}), dev(selfID, nil))
	c := r.collect(security.ScopeFleet)
	for _, rw := range c.Coverage {
		if rw.Status != security.ReportComplete {
			t.Errorf("row %+v", rw)
		}
	}
	type step struct {
		src            security.CollectionSource
		api, cliBefore int
	}
	// api requests and cli calls completed before the source is asked.
	order := []step{{security.SourceAPIDevices, 0, 0}, {security.SourceLocalStatus, 1, 0}, {security.SourceLocalVersion, 1, 1}, {security.SourceLocalPrefs, 1, 2}}
	if len(r.got) != 2*len(order) {
		t.Fatalf("%d events: %+v", len(r.got), r.got)
	}
	for i, s := range order {
		a, o := r.got[2*i], r.got[2*i+1]
		if a.ev.Source != s.src || a.ev.Phase != security.PhaseAttempt || o.ev.Source != s.src || o.ev.Phase != security.PhaseOutcome || o.ev.Outcome != security.OutcomeOK {
			t.Fatalf("events %d and %d: %+v %+v", 2*i, 2*i+1, a.ev, o.ev)
		}
		isAPI := s.src == security.SourceAPIDevices
		wantAfterAPI, wantAfterCLI := s.api, s.cliBefore
		if isAPI {
			wantAfterAPI = 1
		} else {
			wantAfterCLI++
		}
		if a.requests != s.api || a.cliCalls != s.cliBefore || o.requests != wantAfterAPI || o.cliCalls != wantAfterCLI {
			t.Errorf("%s: asked before its attempt was recorded, or not by its outcome: attempt saw %d/%d, outcome saw %d/%d requests/calls",
				s.src, a.requests, a.cliCalls, o.requests, o.cliCalls)
		}
	}
	// What was asked is what is declared.
	ops := tools.SecurityOperations()
	if len(ops) != 4 {
		t.Fatalf("operations = %v", ops)
	}
	reqs := r.f.Requests()
	if len(reqs) != 1 || reqs[0].Method != "GET" || reqs[0].Query.Get("fields") != "all" || len(reqs[0].Query) != 1 {
		t.Fatalf("requests = %+v", reqs)
	}
	op, err := operationOf(reqs[0].Method, reqs[0].Path)
	if err != nil || op != ops[0] || !slices.Contains(openapi.Operations(), ops[0]) {
		t.Errorf("the API request is %q (%v), declared %q", op, err, ops[0])
	}
	var wantCLI []string
	for _, o := range ops[1:] {
		wantCLI = append(wantCLI, strings.TrimPrefix(o, "tailscale "))
	}
	if got := r.cli.calls(); !slices.Equal(got, wantCLI) {
		t.Errorf("CLI calls = %q, declared %q", got, wantCLI)
	}
}

// The framework names the caller, the tool and the call; a tool's input cannot.
func TestTheCorrelationOfARecordIsTheFrameworks(t *testing.T) {
	r := newRig(t)
	r.devices(dev("nAAA1CNTRL", nil))
	type hostile struct {
		Caller string `json:"caller,omitempty"`
		Parent string `json:"parent,omitempty"`
	}
	probe := registry.Define(registry.Meta{Name: "security_probe", Area: "security", Verb: "probe", Summary: "probe"},
		func(ctx context.Context, env *registry.Env, _ hostile) (struct{}, error) {
			_, err := tools.CollectSecurity(ctx, env, security.ScopeFleet)
			return struct{}{}, err
		})
	ctx := registry.WithCaller(context.Background(), registry.Caller{Kind: "mcp", Client: "some-client"})
	if _, err := probe.Call(ctx, r.env, json.RawMessage(`{"caller":"EVIL-CALLER","parent":"EVIL-PARENT"}`)); err != nil {
		t.Fatal(err)
	}
	if len(r.got) == 0 {
		t.Fatal("no events")
	}
	id := r.got[0].call.ID
	for _, o := range r.got {
		if o.call.Tool != "security_probe" || o.call.Caller != (registry.Caller{Kind: "mcp", Client: "some-client"}) || o.call.ID != id || len(id) != 16 {
			t.Errorf("event %+v carries call %+v", o.ev, o.call)
		}
	}
}

// The scope is the only input, and it is closed; a surface with no audit path is refused.
func TestACollectionRefusesWhatItCannotRecord(t *testing.T) {
	r := newRig(t)
	if _, err := tools.CollectSecurity(context.Background(), r.env, security.Scope("everything")); code(err) != tkerr.ValidationFailed {
		t.Errorf("an unknown scope: %v", err)
	}
	r.env.RecordObservation = nil
	if _, err := tools.CollectSecurity(context.Background(), r.env, security.ScopeFleet); code(err) != tkerr.AuditUnavailable {
		t.Errorf("no audit path: %v", err)
	}
	if len(r.f.Requests()) != 0 || len(r.got) != 0 {
		t.Errorf("a refused collection asked %d requests and recorded %d events", len(r.f.Requests()), len(r.got))
	}
}
