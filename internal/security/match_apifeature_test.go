package security

import (
	"testing"
	"time"
)

// D5: for a running-daemon or local-CLI rule, a feature fact of origin api speaks while the
// device passes the guard of D1 (a usable connected_to_control = true fact of origin api and
// no usable false one) and the fact itself is usable. Everything else about features is as
// before. The cases build one device whose daemon runs 1.30.0 (in range) and a rule that
// requires the feature tailscale_ssh.

// sshOnly is a rule that requires tailscale_ssh, for a daemon the local source reports.
func sshOnly(w *world) {
	w.rec().RequiredFeatures = []string{FeatureTailscaleSSH}
	w.daemon("1.30.0")
}

// apiSSH adds tailscale_ssh as the API reports it.
func (w *world) apiSSH(value bool, edit ...evEdit) {
	w.feature(mAsset, OriginAPI, FeatureTailscaleSSH, value, edit...)
}

func apiFeatureCases() []matchCase {
	var cs []matchCase
	add := func(app Applicability, reason UnknownReason, evidence int, name string, build func(w *world)) {
		cs = append(cs, with(app, reason, evidence, name, build))
	}

	// The guard holds: the API's report decides.
	add(ApplicabilityNotAffected, "", 2, "connected, fresh, the api says ssh is off", func(w *world) { sshOnly(w); w.connected(true); w.apiSSH(false) })
	add(ApplicabilityAffected, "", 2, "connected, fresh, the api says ssh is on", func(w *world) { sshOnly(w); w.connected(true); w.apiSSH(true) })
	add(ApplicabilityNotAffected, "", 2, "the order of the facts does not matter", func(w *world) { sshOnly(w); w.apiSSH(false); w.connected(true) })
	add(ApplicabilityAffected, "", 3, "connected, the api feature at the age limit", func(w *world) {
		sshOnly(w)
		w.connected(true)
		w.apiSSH(true, w.ago(30*time.Minute))
	})
	add(ApplicabilityNotAffected, "", 3, "the api's version and feature, connected", func(w *world) {
		w.rec().RequiredFeatures = []string{FeatureTailscaleSSH}
		w.api("1.30.0", w.ago(2*time.Minute))
		w.connected(true)
		w.apiSSH(false)
	})

	// The guard does not hold: the API's feature fact is ignored, as before D5.
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "device disconnected, the api says ssh is off", func(w *world) { sshOnly(w); w.connected(false); w.apiSSH(false) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "device disconnected, the api says ssh is on", func(w *world) { sshOnly(w); w.connected(false); w.apiSSH(true) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "no connected fact", func(w *world) { sshOnly(w); w.apiSSH(false) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "connected fact stale by age", func(w *world) {
		sshOnly(w)
		w.connected(true, w.ago(31*time.Minute))
		w.apiSSH(false)
	})
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "connected fact observed long ago", func(w *world) {
		sshOnly(w)
		w.connected(true, w.observedAgo(31*time.Minute))
		w.apiSSH(false)
	})
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "connected fact with freshness stale", func(w *world) {
		sshOnly(w)
		w.connected(true, freshness(FreshnessStale))
		w.apiSSH(false)
	})
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "connected fact that carries an error", func(w *world) {
		sshOnly(w)
		w.connected(true, failed())
		w.apiSSH(false)
	})
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "connected fact without a value", func(w *world) {
		sshOnly(w)
		w.s.Features = append(w.s.Features, FeatureFact{Name: FeatureConnectedToControl, Evidence: w.ev(OriginAPI, mAsset)})
		w.apiSSH(false)
	})
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "the api contradicts itself about connected", func(w *world) {
		sshOnly(w)
		w.connected(true)
		w.connected(false)
		w.apiSSH(false)
	})
	for _, origin := range []Origin{OriginLocal, OriginCollector, OriginOperator, OriginVendor, OriginDerived} {
		add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "connected reported by the "+string(origin)+" is not the guard", func(w *world) {
			sshOnly(w)
			w.feature(mAsset, origin, FeatureConnectedToControl, true)
			w.apiSSH(false)
		})
	}

	// The guard holds, but the feature fact is not usable.
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "connected, the api feature stale by age", func(w *world) {
		sshOnly(w)
		w.connected(true)
		w.apiSSH(false, w.ago(31*time.Minute))
	})
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "connected, the api feature observed long ago", func(w *world) {
		sshOnly(w)
		w.connected(true)
		w.apiSSH(false, w.observedAgo(31*time.Minute))
	})
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "connected, the api feature with freshness stale", func(w *world) {
		sshOnly(w)
		w.connected(true)
		w.apiSSH(false, freshness(FreshnessStale))
	})
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "connected, the api feature carries an error", func(w *world) {
		sshOnly(w)
		w.connected(true)
		w.apiSSH(false, failed())
	})
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "connected, the api feature without a value", func(w *world) {
		sshOnly(w)
		w.connected(true)
		w.s.Features = append(w.s.Features, FeatureFact{Name: FeatureTailscaleSSH, Evidence: w.ev(OriginAPI, mAsset)})
	})

	// A local or collector fact and a guarded API fact on the same feature: when they agree
	// the answer is theirs, and when they disagree nothing is affected or cleared.
	add(ApplicabilityNotAffected, "", 3, "local and api agree: off", func(w *world) { sshOnly(w); w.connected(true); w.feat(FeatureTailscaleSSH, false); w.apiSSH(false) })
	add(ApplicabilityAffected, "", 3, "local and api agree: on", func(w *world) { sshOnly(w); w.connected(true); w.feat(FeatureTailscaleSSH, true); w.apiSSH(true) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 3, "local says on and the api says off", func(w *world) { sshOnly(w); w.connected(true); w.feat(FeatureTailscaleSSH, true); w.apiSSH(false) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 3, "local says off and the api says on", func(w *world) { sshOnly(w); w.connected(true); w.feat(FeatureTailscaleSSH, false); w.apiSSH(true) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 3, "the collector says on and the api says off", func(w *world) {
		sshOnly(w)
		w.connected(true)
		w.feature(mAsset, OriginCollector, FeatureTailscaleSSH, true)
		w.apiSSH(false)
	})
	add(ApplicabilityPotential, ReasonFeatureUnknown, 3, "the order of a disagreement does not matter", func(w *world) { sshOnly(w); w.apiSSH(false); w.feat(FeatureTailscaleSSH, true); w.connected(true) })
	// The api is not believed while disconnected, so there is no disagreement to speak of.
	add(ApplicabilityAffected, "", 2, "local on, device disconnected, the api's off is ignored", func(w *world) { sshOnly(w); w.connected(false); w.feat(FeatureTailscaleSSH, true); w.apiSSH(false) })
	// A stale local fact does not disagree with a believed one.
	add(ApplicabilityNotAffected, "", 2, "a stale local on beside a guarded api off", func(w *world) {
		sshOnly(w)
		w.connected(true)
		w.feat(FeatureTailscaleSSH, true, w.ago(40*time.Minute))
		w.apiSSH(false)
	})

	// connected_to_control is the guard and never a required feature: the API's report of it
	// still does not satisfy a daemon rule that requires it, guard or no guard.
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "a rule that requires connected_to_control is not satisfied by the api's report", func(w *world) {
		w.rec().RequiredFeatures = []string{FeatureConnectedToControl}
		w.daemon("1.30.0")
		w.connected(true)
	})
	add(ApplicabilityAffected, "", 2, "a rule that requires connected_to_control is satisfied by a local report", func(w *world) {
		w.rec().RequiredFeatures = []string{FeatureConnectedToControl}
		w.daemon("1.30.0")
		w.feat(FeatureConnectedToControl, true)
	})

	// Two features: the guarded api fact speaks for one of them like any other source.
	twoRule := func(w *world) { w.rec().RequiredFeatures = []string{FeatureTailscaleSSH, "funnel"}; w.daemon("1.30.0") }
	add(ApplicabilityAffected, "", 3, "two features, one local and one guarded api, both on", func(w *world) {
		twoRule(w)
		w.connected(true)
		w.apiSSH(true)
		w.feat("funnel", true)
	})
	add(ApplicabilityPotential, ReasonFeatureUnknown, 2, "two features, one guarded api on and one unknown", func(w *world) { twoRule(w); w.connected(true); w.apiSSH(true) })
	add(ApplicabilityNotAffected, "", 2, "two features, a guarded api off and one unknown", func(w *world) { twoRule(w); w.connected(true); w.apiSSH(false) })

	// An api rule always took the api's feature facts and still does, with or without the guard.
	apiRule := func(w *world) {
		w.rec().VersionRole = VersionAPIReported
		w.rec().RequiredFeatures = []string{FeatureTailscaleSSH}
		w.api("1.30.0")
	}
	add(ApplicabilityNotAffected, "", 2, "api rule, the api says ssh is off, no connected fact", func(w *world) { apiRule(w); w.apiSSH(false) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "api rule, the local daemon's ssh does not speak", func(w *world) { apiRule(w); w.feat(FeatureTailscaleSSH, false) })

	// A local-CLI rule takes the guarded api feature as well. A CLI version is a local one.
	cliRule := func(w *world) {
		w.rec().VersionRole = VersionLocalCLI
		w.rec().RequiredFeatures = []string{FeatureTailscaleSSH}
		w.cli("1.30.0")
	}
	add(ApplicabilityNotAffected, "", 2, "local-cli rule, connected, the api says ssh is off", func(w *world) { cliRule(w); w.connected(true); w.apiSSH(false) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "local-cli rule, not connected, the api says ssh is off", func(w *world) { cliRule(w); w.connected(false); w.apiSSH(false) })
	return cs
}

func TestMatchGuardedAPIFeatures(t *testing.T) { runMatchCases(t, apiFeatureCases()) }

// The guard is one test for versions and features: whatever state of the connected fact lets
// the API's version stand in for the daemon's lets the API's feature speak, and no other does.
func TestAPIVersionAndFeatureShareOneGuard(t *testing.T) {
	type guardState struct {
		name  string
		build func(w *world)
		open  bool
	}
	states := []guardState{
		{"connected", func(w *world) { w.connected(true) }, true},
		{"connected at the age limit", func(w *world) { w.connected(true, w.ago(30*time.Minute)) }, true},
		{"no connected fact", func(w *world) {}, false},
		{"disconnected", func(w *world) { w.connected(false) }, false},
		{"stale by age", func(w *world) { w.connected(true, w.ago(31*time.Minute)) }, false},
		{"observed long ago", func(w *world) { w.connected(true, w.observedAgo(31*time.Minute)) }, false},
		{"freshness stale", func(w *world) { w.connected(true, freshness(FreshnessStale)) }, false},
		{"failed", func(w *world) { w.connected(true, failed()) }, false},
		{"contradictory", func(w *world) { w.connected(true); w.connected(false) }, false},
		{"from the local source", func(w *world) { w.feature(mAsset, OriginLocal, FeatureConnectedToControl, true) }, false},
		{"another device's", func(w *world) { w.feature("other", OriginAPI, FeatureConnectedToControl, true) }, false},
	}
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			// Versions: the API's report of a release at the fix decides only through the guard.
			wv := newWorld(ScopeFleet)
			wv.api("1.32.3")
			st.build(wv)
			versionDecides := onlyFinding(t, wv).Applicability == ApplicabilityNotAffected

			// Features: the API's report that ssh is off clears only through the guard.
			wf := newWorld(ScopeFleet)
			sshOnly(wf)
			st.build(wf)
			wf.apiSSH(false)
			featureDecides := onlyFinding(t, wf).Applicability == ApplicabilityNotAffected

			if versionDecides != st.open || featureDecides != st.open {
				t.Fatalf("guard %q: the api's version decides %v and its feature %v, want both %v", st.name, versionDecides, featureDecides, st.open)
			}
		})
	}
}

func onlyFinding(t *testing.T, w *world) Finding {
	t.Helper()
	findings, _, err := w.match(WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	var out []Finding
	for _, f := range findings {
		if f.Asset == mAsset {
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("want one finding for the device, got %+v", out)
	}
	return out[0]
}

// A guarded fact cites the connected_to_control fact that opened the guard, once, whatever
// else the finding cites; an unguarded fact does not.
func TestGuardedAPIFeatureCitesTheGuard(t *testing.T) {
	w := newWorld(ScopeLocal)
	sshOnly(w)
	w.connected(true, w.ago(5*time.Minute))
	w.apiSSH(false, w.ago(2*time.Minute))
	f := onlyFinding(t, w)
	if f.Applicability != ApplicabilityNotAffected || len(f.Evidence) != 3 {
		t.Fatalf("got %s citing %d pieces of evidence: %+v", f.Applicability, len(f.Evidence), f.Evidence)
	}
	cited := 0
	for _, e := range f.Evidence {
		if e.Origin == OriginAPI && e.AcquiredAt.Equal(w.now.Add(-5*time.Minute)) {
			cited++
		}
	}
	if cited != 1 {
		t.Fatalf("the connected fact is cited %d times, want once: %+v", cited, f.Evidence)
	}

	// With the API's version also resting on the guard, the connected fact is cited once.
	w = newWorld(ScopeLocal)
	w.rec().RequiredFeatures = []string{FeatureTailscaleSSH}
	w.api("1.30.0", w.ago(2*time.Minute))
	w.connected(true, w.ago(5*time.Minute))
	w.apiSSH(true, w.ago(3*time.Minute))
	f = onlyFinding(t, w)
	if f.Applicability != ApplicabilityAffected || len(f.Evidence) != 3 {
		t.Fatalf("got %s citing %d pieces of evidence: %+v", f.Applicability, len(f.Evidence), f.Evidence)
	}
	findings, cov, err := w.match(WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	requireValidReport(t, w, findings, cov)
}
