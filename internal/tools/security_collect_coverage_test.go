package tools_test

import (
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

// A device the API names and gives no field the matcher reads is still a device: it reaches
// the matcher and gets an explicit unknown with a closed reason, never silence. The reason is
// the one the evidence earned (no version; or a lastSeen that is no good; or stale evidence).
// The control, a device with a version, is judged normally, so the check can fail.
func TestADeviceWithNoDecisionFieldIsAnExplicitUnknown(t *testing.T) {
	bare := func(extra map[string]any) map[string]any {
		m := map[string]any{"clientVersion": nil, "os": nil, "connectedToControl": nil}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	r := newRig(t)
	r.devices(
		dev("nFULL1CNTRL", map[string]any{"clientVersion": "1.104.5"}),
		dev("nEMPTY1CNTRL", bare(nil)),
		dev("nNOSEEN1CNTRL", bare(map[string]any{"lastSeen": nil})),
		dev("nSTALE1CNTRL", bare(map[string]any{"lastSeen": seenAgo(2 * time.Hour)})),
	)
	c := r.collect(security.ScopeFleet)
	// A pending rule does not change the reason: an unknown keeps the one it earned.
	for _, state := range []security.ReviewState{security.ReviewApproved, security.ReviewPending} {
		rule := daemonRule("1.104.4")
		rule.ReviewState = state
		got := matchRule(t, c, rule)
		if len(got) != 4 {
			t.Errorf("%s rule: %d devices judged, want 4: %v", state, len(got), got)
		}
		for id, want := range map[string]security.UnknownReason{"nEMPTY1CNTRL": security.ReasonNoVersion, "nNOSEEN1CNTRL": security.ReasonEvidenceError,
			"nSTALE1CNTRL": security.ReasonStaleEvidence} {
			if f, ok := got[id]; !ok || f.Applicability != security.ApplicabilityUnknown || f.Reason != want {
				t.Errorf("%s rule, %s: %+v (found %v), want unknown for %s", state, id, f, ok, want)
			}
		}
		if f := got["nFULL1CNTRL"]; state == security.ReviewApproved && f.Applicability != security.ApplicabilityNotAffected {
			t.Errorf("the device with a version: %+v", f)
		}
	}
	// It is counted as observed, and the versions row says that it has no version.
	if ev := r.apiOutcome(); ev.Outcome != security.OutcomeOK || ev.Observed != 4 {
		t.Errorf("outcome %+v", ev)
	}
	if rw := row(t, c, security.CoverageVersions); !strings.Contains(rw.Explanation, "3 of 4 devices have no running-daemon or API version") {
		t.Errorf("versions row = %+v", rw)
	}
}

// The versions row is complete only if every device in scope has a version of the running
// daemon or from the API. On a local collection that is the daemon's: a CLI version alone is
// not what runs.
func TestVersionsCoverageNeedsAVersionOfTheDaemonOrTheAPIForEveryDevice(t *testing.T) {
	r := newCLIRig(t)
	serveLocal(r, "false")
	c := r.collect(security.ScopeLocal)
	if rw := row(t, c, security.CoverageVersions); rw.Status != security.ReportComplete {
		t.Fatalf("the control (the daemon's version given): %+v", rw)
	}
	r.cli.on("version --json --daemon", 0, `{"long":"1.102.5-t0123456ab"}`, "")
	c = r.collect(security.ScopeLocal)
	for _, o := range r.got[len(r.got)-6:] {
		if o.ev.Phase == security.PhaseOutcome && o.ev.Outcome != security.OutcomeOK {
			t.Fatalf("every source should have ended ok: %+v", o.ev)
		}
	}
	if rw := row(t, c, security.CoverageVersions); rw.Status != security.ReportPartial || !strings.Contains(rw.Explanation, "1 of 1 devices have no running-daemon or API version") {
		t.Errorf("no daemon version: %+v", rw)
	}
	if rw := row(t, c, security.CoverageFeatures); rw.Status != security.ReportComplete {
		t.Errorf("nothing requires a feature, and the sources ended ok: %+v", rw)
	}
}

// In the fleet a device the API gave no version for keeps the row partial, though every
// source ended ok.
func TestVersionsCoverageNamesTheDevicesWithoutAVersion(t *testing.T) {
	r := newCLIRig(t)
	serveLocal(r, "false")
	r.devices(dev(selfID, nil), dev("nA1CNTRL", nil), dev("nB1CNTRL", map[string]any{"clientVersion": nil}), dev("nC1CNTRL", map[string]any{"clientVersion": "1.104.5"}))
	c := r.collect(security.ScopeFleet)
	if rw := row(t, c, security.CoverageVersions); rw.Status != security.ReportPartial || rw.Explanation != "1 of 4 devices have no running-daemon or API version" {
		t.Errorf("versions row = %+v", rw)
	}
	r.devices(dev(selfID, nil), dev("nA1CNTRL", nil), dev("nB1CNTRL", nil))
	if rw := row(t, r.collect(security.ScopeFleet), security.CoverageVersions); rw.Status != security.ReportComplete {
		t.Errorf("every device has a version: %+v", rw)
	}
}

// The features row is complete only if each feature a rule requires is one a source gives and
// every device has a value for it. The TS-2026 rules require four features and the collector
// gives one, so the row says partial and names the three; a feature a source does give but
// the API left out for a device is unknown, not off, and keeps the row partial too.
func TestFeaturesCoverageNamesWhatNoSourceGivesAndWhatADeviceLacks(t *testing.T) {
	ts2026 := []string{security.FeatureTailscaleSSH, security.FeatureSSHForwardingAllowed, security.FeatureServeUnixBackend, security.FeatureServeTLSMultiMount}
	r := newCLIRig(t)
	serveLocal(r, "false")
	r.devices(dev(selfID, map[string]any{"sshEnabled": false}), dev("nA1CNTRL", map[string]any{"sshEnabled": true}))

	if rw := row(t, r.collect(security.ScopeFleet, security.FeatureTailscaleSSH), security.CoverageFeatures); rw.Status != security.ReportComplete {
		t.Fatalf("the control (one feature, which a source gives for every device): %+v", rw)
	}
	rw := row(t, r.collect(security.ScopeFleet, ts2026...), security.CoverageFeatures)
	if rw.Status != security.ReportPartial || rw.Explanation != "no source gives the features serve_tls_multi_mount, serve_unix_backend, ssh_forwarding_allowed" {
		t.Errorf("the TS-2026 features: %+v", rw)
	}
	// A name the program does not know is counted and never shown.
	rw = row(t, r.collect(security.ScopeFleet, security.FeatureTailscaleSSH, "made_up_feature"), security.CoverageFeatures)
	if rw.Status != security.ReportPartial || rw.Explanation != "1 required features that this program does not know" {
		t.Errorf("an unknown feature: %+v", rw)
	}
	// The versions row does not depend on the features a rule requires.
	if rw := row(t, r.collect(security.ScopeFleet, ts2026...), security.CoverageVersions); rw.Status != security.ReportComplete {
		t.Errorf("versions row = %+v", rw)
	}

	// Four sources ended ok, and no source said whether Tailscale SSH is on: the row cannot
	// be complete for a rule that needs it.
	serveLocal(r, "")
	r.devices(dev(selfID, nil), dev("nA1CNTRL", nil))
	c := r.collect(security.ScopeFleet, security.FeatureTailscaleSSH)
	for _, src := range []security.CollectionSource{security.SourceAPIDevices, security.SourceLocalStatus, security.SourceLocalVersion, security.SourceLocalPrefs} {
		if ev := r.event(src, security.PhaseOutcome).ev; ev.Outcome != security.OutcomeOK {
			t.Fatalf("%s did not end ok: %+v", src, ev)
		}
	}
	if _, found := feature(c.Snapshot, "nA1CNTRL", security.FeatureTailscaleSSH); found {
		t.Fatal("the premise: no tailscale_ssh fact exists")
	}
	if rw := row(t, c, security.CoverageFeatures); rw.Status != security.ReportPartial || rw.Explanation != "tailscale_ssh: no value for 2 of 2 devices" {
		t.Errorf("no value from any source: %+v", rw)
	}
}

// A collection that observed no device claims nothing.
func TestCoverageIsNotCompleteWhenNoDeviceWasObserved(t *testing.T) {
	r := newRig(t)
	r.devices()
	c := r.collect(security.ScopeFleet)
	for _, dim := range []security.CoverageDimension{security.CoverageVersions, security.CoverageFeatures} {
		if rw := row(t, c, dim); rw.Status != security.ReportPartial || !strings.Contains(rw.Explanation, "no device was observed") {
			t.Errorf("%s row = %+v", dim, rw)
		}
	}
}
