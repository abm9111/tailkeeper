package tools_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// requireNoLocalFacts checks that nothing from this node's own sources is in the snapshot,
// that the status was read and refused, and that the two sources that ask about this node
// were not asked.
func requireNoLocalFacts(t *testing.T, r *rig, c tools.SecurityCollection) {
	t.Helper()
	if namesDevice(c.Snapshot, selfID) {
		t.Errorf("a fact names this node: %v", assets(c.Snapshot))
	}
	for _, v := range c.Snapshot.Versions {
		if v.Evidence.Origin == security.OriginLocal {
			t.Errorf("a local version fact: %+v", v)
		}
	}
	for _, f := range c.Snapshot.Features {
		if f.Evidence.Origin == security.OriginLocal {
			t.Errorf("a local feature fact: %+v", f)
		}
	}
	for _, p := range c.Snapshot.Platforms {
		if p.Evidence.Origin == security.OriginLocal {
			t.Errorf("a local platform fact: %+v", p)
		}
	}
	if ev := r.event(security.SourceLocalStatus, security.PhaseOutcome).ev; ev.Outcome != security.OutcomeError || ev.Code != string(tkerr.LocalTailnetMismatch) || ev.Observed != 0 {
		t.Errorf("status outcome %+v, want error with local_tailnet_mismatch and nothing observed", ev)
	}
	for _, src := range []security.CollectionSource{security.SourceLocalVersion, security.SourceLocalPrefs} {
		if ev := r.event(src, security.PhaseOutcome).ev; ev.Outcome != security.OutcomeSkipped || ev.Code != security.SkipIdentity {
			t.Errorf("%s: %+v, want skipped", src, ev)
		}
	}
	if calls := r.cli.calls(); !slices.Equal(calls, []string{"status --json --peers=false"}) {
		t.Errorf("CLI calls = %q: only the status may be asked", calls)
	}
	for _, dim := range []security.CoverageDimension{security.CoverageVersions, security.CoverageFeatures} {
		if rw := row(t, c, dim); rw.Status != security.ReportPartial || !strings.Contains(rw.Explanation, "local_tailnet_mismatch") {
			t.Errorf("%s row = %+v, want partial and naming local_tailnet_mismatch", dim, rw)
		}
	}
}

// In a fleet collection this node's own facts join the evidence only if its ID is one the API
// listed for the tailnet just read. A daemon that has been switched to another tailnet, or a
// list that could not be read, must not put its platform, versions and preferences on a
// device of the configured one: every local fact is left out, the two sources that ask about
// this node are not asked, and the coverage says local_tailnet_mismatch.
func TestLocalFactsJoinAFleetCollectionOnlyIfTheNodeIsInTheListedTailnet(t *testing.T) {
	r := newCLIRig(t)
	serveLocal(r, "true")

	// The control: the node is in the list, and its facts join.
	r.devices(dev("nPEER1CNTRL", nil), dev(selfID, map[string]any{"clientVersion": nil, "os": nil}))
	c := r.collect(security.ScopeFleet)
	roles := map[security.VersionRole]bool{}
	for _, v := range versionsOf(c.Snapshot, selfID) {
		roles[v.Role] = v.Evidence.Origin == security.OriginLocal
	}
	if f, ok := feature(c.Snapshot, selfID, security.FeatureTailscaleSSH); !ok || f.Evidence.Origin != security.OriginLocal || !roles[security.VersionRunningDaemon] {
		t.Fatalf("the node is listed, and its local facts are missing: ssh %+v, versions %v", f, roles)
	}

	// The node of another tailnet: its ID is not among the devices the API listed.
	r = newCLIRig(t)
	serveLocal(r, "true")
	r.devices(dev("nPEER1CNTRL", nil), dev("nPEER2CNTRL", nil))
	c = r.collect(security.ScopeFleet)
	requireNoLocalFacts(t, r, c)
	if got := assets(c.Snapshot); !slices.Equal(got, []string{"nPEER1CNTRL", "nPEER2CNTRL"}) {
		t.Errorf("the listed devices lost their facts: %v", got)
	}

	// The list could not be read: nothing shows the node is in the tailnet.
	for _, status := range []int{403, 500} {
		r = newCLIRig(t)
		serveLocal(r, "true")
		r.f.JSON("GET", tailnetPath+"/devices", status, `{"message":"synthetic"}`)
		c = r.collect(security.ScopeFleet)
		requireNoLocalFacts(t, r, c)
		requireGap(t, c, "API device list: error")
	}
}

// A node whose ID the list gives twice is in the list; the API's rows for it are not
// believed (the API names it only by a fact with no value that says why), and its own facts
// are the node's.
func TestALocalNodeTheListNamesTwiceIsStillInTheTailnet(t *testing.T) {
	r := newCLIRig(t)
	serveLocal(r, "true")
	r.devices(dev(selfID, nil), dev(selfID, map[string]any{"clientVersion": "1.1.1"}))
	c := r.collect(security.ScopeFleet)
	local := 0
	for _, v := range versionsOf(c.Snapshot, selfID) {
		switch {
		case v.Evidence.Origin == security.OriginLocal:
			local++
		case v.Value != nil || v.Evidence.Error == "":
			t.Errorf("a row of a repeated ID reached the snapshot: %+v", v)
		}
	}
	if local != 2 {
		t.Errorf("the node's own versions: %+v", versionsOf(c.Snapshot, selfID))
	}
	if ev := r.event(security.SourceLocalStatus, security.PhaseOutcome).ev; ev.Outcome != security.OutcomeOK {
		t.Errorf("status outcome %+v", ev)
	}
}

// A local collection asks no API and needs no list: this node's facts join whatever the API
// would say.
func TestALocalCollectionNeedsNoListToJoinTheNodesFacts(t *testing.T) {
	r := newCLIRig(t)
	serveLocal(r, "true")
	r.f.JSON("GET", tailnetPath+"/devices", 403, `{"message":"synthetic"}`)
	c := r.collect(security.ScopeLocal)
	if got := assets(c.Snapshot); !slices.Equal(got, []string{selfID}) || len(r.f.Requests()) != 0 {
		t.Errorf("assets %v, %d API requests", got, len(r.f.Requests()))
	}
	for _, rw := range c.Coverage {
		if rw.Status != security.ReportComplete {
			t.Errorf("row %+v", rw)
		}
	}
}
