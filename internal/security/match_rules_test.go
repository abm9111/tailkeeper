package security

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Table tests for every branch of the matcher (C6). A case builds a world with one device
// ("dev") and one rule, and says what the one finding must be. The runner checks the
// finding, its evidence state, whether it carries the mitigation, the coverage row and its
// counts, and that a report built from Match's output passes ValidateReport. Every case runs
// under both scopes.

type matchCase struct {
	name     string
	build    func(w *world)
	app      Applicability
	reason   UnknownReason
	evidence int  // pieces of evidence the finding cites; 0 means any number
	stale    bool // positive, but the catalog or the rule's review is not fresh: the row is partial
}

// specState is the evidence state the spec gives each result: observed for affected,
// not_affected and potentially_affected; stale for stale_evidence; absent for no_version;
// unknown for every other unknown.
func specState(a Applicability, r UnknownReason) EvidenceState {
	if a != ApplicabilityUnknown {
		return EvidenceObserved
	}
	switch r {
	case ReasonStaleEvidence:
		return EvidenceStale
	case ReasonNoVersion:
		return EvidenceAbsent
	}
	return EvidenceUnknown
}

func (tc matchCase) run(t *testing.T, scope Scope) {
	t.Helper()
	w := newWorld(scope)
	tc.build(w)
	findings, cov, err := w.match(WorkBudget{})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(findings) != 1 || len(cov) != 1 {
		t.Fatalf("got %d findings and %d coverage rows, want 1 and 1: %+v", len(findings), len(cov), findings)
	}
	f := findings[0]
	if f.Asset != mAsset || f.RuleID != "RULE-1" || f.ID != FindingID(mCtx, scope, mAsset, "RULE-1") {
		t.Fatalf("finding names %q %q %q", f.Asset, f.RuleID, f.ID)
	}
	if f.Context != mCtx || f.RuleRevision != w.rec().Revision || f.SourceSeverity != w.rec().Severity || f.Priority != PriorityUnknown {
		t.Fatalf("finding carries context %q, revision %q, severity %q, priority %q", f.Context, f.RuleRevision, f.SourceSeverity, f.Priority)
	}
	if f.Applicability != tc.app || f.Reason != tc.reason {
		t.Fatalf("got %s (%q), want %s (%q); explanation %q", f.Applicability, f.Reason, tc.app, tc.reason, f.Explanation)
	}
	if want := specState(tc.app, tc.reason); f.EvidenceState != want {
		t.Fatalf("evidence state %s, want %s", f.EvidenceState, want)
	}
	if tc.evidence > 0 && len(f.Evidence) != tc.evidence {
		t.Fatalf("%d pieces of evidence, want %d: %+v", len(f.Evidence), tc.evidence, f.Evidence)
	}
	wantMitigation := tc.app == ApplicabilityAffected || tc.app == ApplicabilityPotential
	if gotMitigation := len(f.Verification) > 0; gotMitigation != wantMitigation {
		t.Fatalf("mitigation present %v, want %v (%+v)", gotMitigation, wantMitigation, f.Verification)
	}
	if wantMitigation && (len(f.Verification) != 1 || f.Verification[0] != w.rec().Mitigation) {
		t.Fatalf("mitigation %+v", f.Verification)
	}
	if f.Explanation == "" {
		t.Fatal("empty explanation")
	}
	if wantConfidence := map[bool]Confidence{true: ConfidenceReported, false: ConfidenceUnknown}[len(f.Evidence) > 0]; f.Confidence != wantConfidence {
		t.Fatalf("confidence %s with %d pieces of evidence, want %s", f.Confidence, len(f.Evidence), wantConfidence)
	}
	positive := tc.app == ApplicabilityAffected || tc.app == ApplicabilityNotAffected
	checkRow(t, cov[0], scope, findings, !positive || tc.stale)
	if got := countsOf(cov[0]); got.Rules != 1 || got.Withdrawn != 0 || got.Assets != 1 {
		t.Fatalf("counts %+v", got)
	}
	requireValidReport(t, w, findings, cov)
}

// checkRow checks the shape of the catalog row of a Match run and that its counts say what
// the findings say. A partial row explains itself; a complete one does not need to.
func checkRow(t *testing.T, row Coverage, scope Scope, findings []Finding, partial bool) {
	t.Helper()
	if row.Target != (CoverageTarget{Dimension: CoverageCatalog, Scope: scope}) || row.Context != mCtx || row.Source != "advisory catalog" {
		t.Fatalf("row %+v", row)
	}
	if row.Counts == nil {
		t.Fatal("the row has no counts")
	}
	unknown, potential := 0, 0
	for _, f := range findings {
		switch f.Applicability {
		case ApplicabilityUnknown:
			unknown++
		case ApplicabilityPotential:
			potential++
		}
	}
	if row.Counts.Findings != len(findings) || row.Counts.Unknown != unknown || row.Counts.Potential != potential {
		t.Fatalf("counts %+v for %d findings (%d unknown, %d potential)", *row.Counts, len(findings), unknown, potential)
	}
	wantStatus := ReportComplete
	if partial {
		wantStatus = ReportPartial
	}
	if row.Status != wantStatus {
		t.Fatalf("row is %s, want %s: %q", row.Status, wantStatus, row.Explanation)
	}
	if partial != (row.Explanation != "") {
		t.Fatalf("explanation %q on a %s row", row.Explanation, row.Status)
	}
}

func runMatchCases(t *testing.T, cases []matchCase) {
	t.Helper()
	for _, scope := range []Scope{ScopeLocal, ScopeFleet} {
		for _, tc := range cases {
			t.Run(string(scope)+"/"+tc.name, func(t *testing.T) { tc.run(t, scope) })
		}
	}
}

func with(app Applicability, reason UnknownReason, evidence int, name string, build func(w *world)) matchCase {
	return matchCase{name: name, build: build, app: app, reason: reason, evidence: evidence}
}

// ---- releases, ranges and the channel -------------------------------------------------

func releaseCases() []matchCase {
	var cs []matchCase
	daemon := func(name, version string, app Applicability) {
		cs = append(cs, with(app, "", 1, name, func(w *world) { w.daemon(version) }))
	}
	unrecognised := func(version string) {
		cs = append(cs, with(ApplicabilityUnknown, ReasonUnrecognisedBuild, 1, fmt.Sprintf("unrecognised %q", version), func(w *world) { w.daemon(version) }))
	}
	daemon("below the fixed release", "1.30.0", ApplicabilityAffected)
	daemon("one patch below the fixed release", "1.32.2", ApplicabilityAffected)
	daemon("exactly the fixed release", "1.32.3", ApplicabilityNotAffected)
	daemon("one patch above the fixed release", "1.32.4", ApplicabilityNotAffected)
	daemon("a later minor", "1.34.0", ApplicabilityNotAffected)
	daemon("a later major", "2.0.0", ApplicabilityNotAffected)
	daemon("an earlier major with a larger minor and patch", "0.98.9", ApplicabilityAffected)
	daemon("build suffix below the fixed release", "1.32.2-t0123456ab", ApplicabilityAffected)
	daemon("build suffix and commit below the fixed release", "1.32.2-t0123456ab-gfedcba987", ApplicabilityAffected)
	daemon("build suffix at the fixed release", "1.32.3-t0123456ab", ApplicabilityNotAffected)
	daemon("build suffix and commit at the fixed release", "1.32.3-t0123456ab-gfedcba987", ApplicabilityNotAffected)
	daemon("nine-digit components", "999999999.998.999999999", ApplicabilityNotAffected)

	for _, v := range []string{
		"1.32.3-rc1", "v1.32.3", "1.32", "1.32.3.1", "01.32.3", " 1.32.3", "1.32.3 ", "1.32.3+dfsg-1", "1.32.3-g0123456ab",
		"1.32.3-t012345", "1.32.3-t0123456AB", "1.32.3-dev20261030", "1.32.3-ERR-BuildInfo", "1.32.3-0123456ab", "1234567890.32.3", "", "latest",
	} {
		unrecognised(v)
	}

	cs = append(cs,
		with(ApplicabilityUnknown, ReasonChannelUnknown, 1, "channel unknown", func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginLocal, ChannelUnknown, "1.30.0")
		}),
		with(ApplicabilityUnknown, ReasonChannelUnknown, 1, "channel unknown with an odd minor", func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginLocal, ChannelUnknown, "1.33.0")
		}),
		with(ApplicabilityUnknown, ReasonUnstableTrack, 1, "channel unstable below the fixed release", func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginLocal, ChannelUnstable, "1.30.0")
		}),
		with(ApplicabilityUnknown, ReasonUnstableTrack, 1, "channel unstable at an even minor", func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginLocal, ChannelUnstable, "1.34.0")
		}),
		with(ApplicabilityUnknown, ReasonUnstableTrack, 1, "the unstable release of the bulletin", func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginLocal, ChannelUnstable, "1.33.257")
		}),
		with(ApplicabilityUnknown, ReasonUnstableTrack, 1, "stable channel with an odd minor", func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginLocal, ChannelStable, "1.33.257")
		}),
		with(ApplicabilityUnknown, ReasonUnstableTrack, 1, "stable channel with the smallest odd minor", func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginLocal, ChannelStable, "1.1.0")
		}),
		with(ApplicabilityAffected, "", 1, "stable channel with minor zero", func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginLocal, ChannelStable, "1.0.0")
		}),
	)
	return cs
}

func TestMatchReleasesAndChannels(t *testing.T) { runMatchCases(t, releaseCases()) }

// Introduced is inclusive and fixed exclusive, whichever component differs, and any range
// of a rule may match.
func TestMatchRangeBoundaries(t *testing.T) {
	type bound = VersionRange
	cases := []struct {
		name    string
		ranges  []bound
		version string
		want    Applicability
	}{
		{"closed range, below introduced", []bound{{Introduced: "1.10.0", Fixed: "1.20.0"}}, "1.8.9", ApplicabilityNotAffected},
		{"closed range, exactly introduced", []bound{{Introduced: "1.10.0", Fixed: "1.20.0"}}, "1.10.0", ApplicabilityAffected},
		{"closed range, just above introduced", []bound{{Introduced: "1.10.0", Fixed: "1.20.0"}}, "1.10.1", ApplicabilityAffected},
		{"closed range, inside", []bound{{Introduced: "1.10.0", Fixed: "1.20.0"}}, "1.14.5", ApplicabilityAffected},
		{"closed range, just below fixed", []bound{{Introduced: "1.10.0", Fixed: "1.20.0"}}, "1.18.99", ApplicabilityAffected},
		{"closed range, exactly fixed", []bound{{Introduced: "1.10.0", Fixed: "1.20.0"}}, "1.20.0", ApplicabilityNotAffected},
		{"closed range, above fixed", []bound{{Introduced: "1.10.0", Fixed: "1.20.0"}}, "1.22.0", ApplicabilityNotAffected},
		{"closed range, an earlier major", []bound{{Introduced: "1.10.0", Fixed: "1.20.0"}}, "0.50.0", ApplicabilityNotAffected},
		{"closed range, a later major", []bound{{Introduced: "1.10.0", Fixed: "1.20.0"}}, "2.0.0", ApplicabilityNotAffected},
		{"closed range, introduced patch differs", []bound{{Introduced: "1.10.4", Fixed: "1.20.0"}}, "1.10.3", ApplicabilityNotAffected},
		{"closed range, introduced patch equal", []bound{{Introduced: "1.10.4", Fixed: "1.20.0"}}, "1.10.4", ApplicabilityAffected},
		{"introduced major differs", []bound{{Introduced: "2.0.0", Fixed: "2.4.0"}}, "1.98.99", ApplicabilityNotAffected},
		{"introduced major equal", []bound{{Introduced: "2.0.0", Fixed: "2.4.0"}}, "2.0.0", ApplicabilityAffected},
		{"fixed major differs", []bound{{Introduced: "1.0.0", Fixed: "2.0.0"}}, "1.98.0", ApplicabilityAffected},
		{"fixed major reached", []bound{{Introduced: "1.0.0", Fixed: "2.0.0"}}, "2.0.0", ApplicabilityNotAffected},
		{"open end, below introduced", []bound{{Introduced: "1.50.0"}}, "1.48.9", ApplicabilityNotAffected},
		{"open end, exactly introduced", []bound{{Introduced: "1.50.0"}}, "1.50.0", ApplicabilityAffected},
		{"open end, a later major", []bound{{Introduced: "1.50.0"}}, "2.0.0", ApplicabilityAffected},
		{"open end, an earlier major", []bound{{Introduced: "1.50.0"}}, "0.98.0", ApplicabilityNotAffected},
		{"two ranges, in the first", []bound{{Introduced: "1.10.0", Fixed: "1.12.0"}, {Introduced: "1.20.0", Fixed: "1.22.0"}}, "1.10.5", ApplicabilityAffected},
		{"two ranges, between", []bound{{Introduced: "1.10.0", Fixed: "1.12.0"}, {Introduced: "1.20.0", Fixed: "1.22.0"}}, "1.12.0", ApplicabilityNotAffected},
		{"two ranges, exactly the second introduced", []bound{{Introduced: "1.10.0", Fixed: "1.12.0"}, {Introduced: "1.20.0", Fixed: "1.22.0"}}, "1.20.0", ApplicabilityAffected},
		{"two ranges, after both", []bound{{Introduced: "1.10.0", Fixed: "1.12.0"}, {Introduced: "1.20.0", Fixed: "1.22.0"}}, "1.22.0", ApplicabilityNotAffected},
		{"two ranges that touch", []bound{{Introduced: "1.10.0", Fixed: "1.12.0"}, {Introduced: "1.12.0", Fixed: "1.14.0"}}, "1.12.0", ApplicabilityAffected},
		{"build suffix is dropped before comparing introduced", []bound{{Introduced: "1.10.0", Fixed: "1.20.0"}}, "1.10.0-t0123456ab-gfedcba987", ApplicabilityAffected},
	}
	var all []matchCase
	for _, tc := range cases {
		all = append(all, with(tc.want, "", 1, tc.name+" "+tc.version, func(w *world) {
			w.rec().Ranges = tc.ranges
			w.daemon(tc.version)
		}))
	}
	runMatchCases(t, all)
}

// ---- version evidence: absent, stale, failed, unreadable ------------------------------

func evidenceCases() []matchCase {
	other := func(w *world, name, value string) { // a fact about another component of the device
		v := value
		w.versionFact(name, mAsset, VersionRunningDaemon, OriginLocal, ChannelStable, &v)
	}
	return []matchCase{
		with(ApplicabilityUnknown, ReasonNoVersion, 0, "a device named only by a platform fact", func(w *world) { w.os("linux") }),
		with(ApplicabilityUnknown, ReasonNoVersion, 0, "a device named only by a feature fact", func(w *world) { w.feat("ssh", true) }),
		with(ApplicabilityUnknown, ReasonNoVersion, 0, "a version of another component only", func(w *world) { other(w, "other", "1.30.0") }),
		with(ApplicabilityUnknown, ReasonNoVersion, 0, "a usable fact without a value", func(w *world) {
			w.versionFact("client", mAsset, VersionRunningDaemon, OriginLocal, ChannelStable, nil)
		}),
		with(ApplicabilityUnknown, ReasonNoVersion, 0, "only a fact without a value beside another component", func(w *world) {
			other(w, "other", "1.30.0")
			w.versionFact("client", mAsset, VersionRunningDaemon, OriginLocal, ChannelStable, nil)
		}),
		with(ApplicabilityUnknown, ReasonStaleEvidence, 1, "acquired 31 minutes ago", func(w *world) { w.daemon("1.30.0", w.ago(31*time.Minute)) }),
		with(ApplicabilityUnknown, ReasonStaleEvidence, 1, "acquired a nanosecond over 30 minutes ago", func(w *world) {
			w.daemon("1.30.0", w.ago(30*time.Minute+time.Nanosecond))
		}),
		with(ApplicabilityAffected, "", 1, "acquired exactly 30 minutes ago", func(w *world) { w.daemon("1.30.0", w.ago(30*time.Minute)) }),
		with(ApplicabilityUnknown, ReasonStaleEvidence, 1, "recently acquired but observed 31 minutes ago", func(w *world) { w.daemon("1.30.0", w.observedAgo(31*time.Minute)) }),
		with(ApplicabilityAffected, "", 1, "recently acquired and observed 29 minutes ago", func(w *world) { w.daemon("1.30.0", w.observedAgo(29*time.Minute)) }),
		with(ApplicabilityUnknown, ReasonStaleEvidence, 1, "freshness stale", func(w *world) { w.daemon("1.30.0", freshness(FreshnessStale)) }),
		with(ApplicabilityUnknown, ReasonStaleEvidence, 1, "freshness unknown", func(w *world) { w.daemon("1.30.0", freshness(FreshnessUnknown)) }),
		with(ApplicabilityUnknown, ReasonEvidenceError, 1, "evidence that carries an error", func(w *world) { w.daemon("1.30.0", failed()) }),
		with(ApplicabilityUnknown, ReasonEvidenceError, 2, "an error beside a stale fact", func(w *world) {
			w.daemon("1.30.0", w.ago(40*time.Minute))
			w.daemon("1.30.0", failed())
		}),
		with(ApplicabilityUnknown, ReasonEvidenceError, 2, "an error and staleness on the other fact", func(w *world) {
			w.daemon("1.30.0", failed())
			w.daemon("1.30.0", w.ago(40*time.Minute))
		}),
		with(ApplicabilityUnknown, ReasonEvidenceError, 1, "an error that is also stale", func(w *world) { w.daemon("1.30.0", failed(), w.ago(2*time.Hour)) }),
		with(ApplicabilityUnknown, ReasonStaleEvidence, 2, "two stale facts", func(w *world) {
			w.daemon("1.30.0", w.ago(40*time.Minute))
			w.api("1.30.0", freshness(FreshnessStale))
		}),
		// A fact that cannot be used does not make the others unusable.
		with(ApplicabilityAffected, "", 1, "a stale fact beside a usable one", func(w *world) {
			w.daemon("1.32.3", w.ago(40*time.Minute))
			w.daemon("1.30.0")
		}),
		with(ApplicabilityAffected, "", 1, "a fact with an error beside a usable one", func(w *world) {
			w.daemon("1.32.3", failed())
			w.daemon("1.30.0")
		}),
		with(ApplicabilityAffected, "", 1, "a fact of another component beside a usable one", func(w *world) {
			other(w, "other", "1.32.3")
			w.daemon("1.30.0")
		}),
		with(ApplicabilityAffected, "", 1, "an unreadable value of another component", func(w *world) {
			other(w, "other", "garbage")
			w.daemon("1.30.0")
		}),
		with(ApplicabilityAffected, "", 1, "a fact without a value beside a usable one", func(w *world) {
			w.versionFact("client", mAsset, VersionRunningDaemon, OriginLocal, ChannelStable, nil)
			w.daemon("1.30.0")
		}),
		// A fact whose role or origin the rule cannot use is not a version of any kind it asks for.
		with(ApplicabilityUnknown, ReasonNoVersion, 0, "a running_daemon fact from the API", func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginAPI, ChannelStable, "1.30.0")
		}),
		with(ApplicabilityUnknown, ReasonNoVersion, 0, "a running_daemon fact from the operator", func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginOperator, ChannelStable, "1.30.0")
		}),
		with(ApplicabilityUnknown, ReasonNoVersion, 0, "a running_daemon fact from a vendor", func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginVendor, ChannelStable, "1.30.0")
		}),
		with(ApplicabilityUnknown, ReasonNoVersion, 0, "a running_daemon fact that was derived", func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginDerived, ChannelStable, "1.30.0")
		}),
		with(ApplicabilityAffected, "", 1, "a running_daemon fact from the collector", func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginCollector, ChannelStable, "1.30.0")
		}),
		// A CLI report from the operator is not a CLI report: the one usable CLI fact decides.
		with(ApplicabilityPotential, ReasonRuntimeUnobserved, 1, "a local_cli fact from the operator is no fallback", func(w *world) {
			w.cli("1.30.0")
			w.version(mAsset, VersionLocalCLI, OriginOperator, ChannelStable, "1.32.3")
		}),
	}
}

func TestMatchVersionEvidence(t *testing.T) { runMatchCases(t, evidenceCases()) }

// ---- running daemon, API-reported and CLI versions (R5, R9) ---------------------------

func versionSourceCases() []matchCase {
	var cs []matchCase
	add := func(app Applicability, reason UnknownReason, evidence int, name string, build func(w *world)) {
		cs = append(cs, with(app, reason, evidence, name, build))
	}

	// The API alone: a fallback (runtime_unobserved).
	add(ApplicabilityPotential, ReasonRuntimeUnobserved, 1, "api alone, in range", func(w *world) { w.api("1.30.0") })
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "api alone, at the fixed release", func(w *world) { w.api("1.32.3") })
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "api alone, a later major", func(w *world) { w.api("2.0.0") })
	add(ApplicabilityPotential, ReasonRuntimeUnobserved, 1, "api alone, build suffix, in range", func(w *world) { w.api("1.30.0-t0123456ab-gfedcba987") })
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "api alone, build suffix, fixed", func(w *world) { w.api("1.32.3-t0123456ab") })

	// R9: the API counts as the daemon while the device is connected to control.
	add(ApplicabilityAffected, "", 2, "api and connected, in range", func(w *world) { w.api("1.30.0"); w.connected(true) })
	add(ApplicabilityNotAffected, "", 2, "api and connected, at the fixed release", func(w *world) { w.api("1.32.3"); w.connected(true) })
	add(ApplicabilityNotAffected, "", 2, "api and connected, a later major", func(w *world) { w.api("2.0.0"); w.connected(true) })
	add(ApplicabilityAffected, "", 2, "api and connected, build suffix", func(w *world) { w.api("1.32.2-t0123456ab"); w.connected(true) })
	add(ApplicabilityNotAffected, "", 2, "connected, then api (fact order does not matter)", func(w *world) { w.connected(true); w.api("1.32.3") })
	add(ApplicabilityNotAffected, "", 2, "api and connected, at the age limit", func(w *world) {
		w.api("1.32.3", w.ago(30*time.Minute))
		w.connected(true, w.ago(30*time.Minute))
	})

	// R9 does not apply: connected is false, absent, stale, failed, empty or from the wrong source.
	add(ApplicabilityPotential, ReasonRuntimeUnobserved, 1, "connected false, in range", func(w *world) { w.api("1.30.0"); w.connected(false) })
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "connected false, fixed", func(w *world) { w.api("1.32.3"); w.connected(false) })
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "connected stale by age, fixed", func(w *world) {
		w.api("1.32.3")
		w.connected(true, w.ago(31*time.Minute))
	})
	add(ApplicabilityPotential, ReasonRuntimeUnobserved, 1, "connected stale by age, in range", func(w *world) {
		w.api("1.30.0")
		w.connected(true, w.ago(31*time.Minute))
	})
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "connected observed long ago", func(w *world) {
		w.api("1.32.3")
		w.connected(true, w.observedAgo(31*time.Minute))
	})
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "connected with freshness stale", func(w *world) {
		w.api("1.32.3")
		w.connected(true, freshness(FreshnessStale))
	})
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "connected that carries an error", func(w *world) {
		w.api("1.32.3")
		w.connected(true, failed())
	})
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "connected without a value", func(w *world) {
		w.api("1.32.3")
		w.s.Features = append(w.s.Features, FeatureFact{Name: FeatureConnectedToControl, Evidence: w.ev(OriginAPI, mAsset)})
	})
	for _, origin := range []Origin{OriginLocal, OriginCollector, OriginOperator, OriginVendor, OriginDerived} {
		add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "connected true from the "+string(origin), func(w *world) {
			w.api("1.32.3")
			w.feature(mAsset, origin, FeatureConnectedToControl, true)
		})
	}
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "another feature with the same value", func(w *world) {
		w.api("1.32.3")
		w.connected(true)
		w.s.Features[0].Name = "connected"
	})
	// Contradictory facts of the API leave the API as a fallback; an unusable one does not count.
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "connected both true and false", func(w *world) {
		w.api("1.32.3")
		w.connected(true)
		w.connected(false)
	})
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "connected both false and true", func(w *world) {
		w.api("1.32.3")
		w.connected(false)
		w.connected(true)
	})
	add(ApplicabilityNotAffected, "", 2, "connected true beside a stale false", func(w *world) {
		w.api("1.32.3")
		w.connected(true)
		w.connected(false, w.ago(40*time.Minute))
	})
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "a stale true beside a fresh false", func(w *world) {
		w.api("1.32.3")
		w.connected(true, w.ago(40*time.Minute))
		w.connected(false)
	})

	// The API version must itself be usable and readable.
	add(ApplicabilityUnknown, ReasonStaleEvidence, 1, "connected, but the api fact is stale", func(w *world) {
		w.api("1.32.3", w.ago(31*time.Minute))
		w.connected(true)
	})
	add(ApplicabilityUnknown, ReasonEvidenceError, 1, "connected, but the api fact carries an error", func(w *world) {
		w.api("1.32.3", failed())
		w.connected(true)
	})
	add(ApplicabilityUnknown, ReasonUnrecognisedBuild, 2, "connected, but the api version is unrecognised", func(w *world) {
		w.api("1.32.3-rc1")
		w.connected(true)
	})
	add(ApplicabilityUnknown, ReasonUnstableTrack, 2, "connected, but the api fact is on the unstable channel", func(w *world) {
		w.version(mAsset, VersionAPIReported, OriginAPI, ChannelUnstable, "1.32.3")
		w.connected(true)
	})
	add(ApplicabilityUnknown, ReasonChannelUnknown, 2, "connected, but the api fact has no known channel", func(w *world) {
		w.version(mAsset, VersionAPIReported, OriginAPI, ChannelUnknown, "1.32.3")
		w.connected(true)
	})
	add(ApplicabilityUnknown, ReasonUnstableTrack, 2, "connected, but the api release has an odd minor", func(w *world) {
		w.api("1.33.0")
		w.connected(true)
	})

	// Exact and connected facts must agree; a CLI report never conflicts with a daemon fact.
	add(ApplicabilityAffected, "", 3, "daemon, api and connected agree", func(w *world) { w.daemon("1.30.0"); w.api("1.30.0"); w.connected(true) })
	add(ApplicabilityNotAffected, "", 3, "daemon and api agree through different build suffixes", func(w *world) {
		w.daemon("1.32.3-t0123456ab-gfedcba987")
		w.api("1.32.3-t0abcdef01")
		w.connected(true)
	})
	add(ApplicabilityUnknown, ReasonVersionConflict, 3, "connected api newer than the daemon", func(w *world) { w.daemon("1.30.0"); w.api("1.32.3"); w.connected(true) })
	add(ApplicabilityUnknown, ReasonVersionConflict, 3, "connected api older than the daemon", func(w *world) { w.daemon("1.32.3"); w.api("1.30.0"); w.connected(true) })
	add(ApplicabilityUnknown, ReasonVersionConflict, 2, "api older than the daemon, not connected", func(w *world) { w.daemon("1.32.3"); w.api("1.30.0") })
	add(ApplicabilityUnknown, ReasonVersionConflict, 2, "api newer than the daemon, not connected", func(w *world) { w.daemon("1.30.0"); w.api("1.32.3") })
	add(ApplicabilityUnknown, ReasonVersionConflict, 2, "api differs from the daemon in the patch only", func(w *world) { w.daemon("1.32.3"); w.api("1.32.2") })
	add(ApplicabilityNotAffected, "", 2, "daemon and api agree, not connected", func(w *world) { w.daemon("1.32.3"); w.api("1.32.3") })
	add(ApplicabilityAffected, "", 2, "daemon and api agree and connected is false", func(w *world) { w.daemon("1.30.0"); w.api("1.30.0"); w.connected(false) })
	add(ApplicabilityNotAffected, "", 1, "a stale api fact beside the daemon is no conflict", func(w *world) {
		w.daemon("1.32.3")
		w.api("1.30.0", w.ago(40*time.Minute))
	})
	add(ApplicabilityNotAffected, "", 1, "an api fact with an error beside the daemon is no conflict", func(w *world) {
		w.daemon("1.32.3")
		w.api("1.30.0", failed())
	})
	add(ApplicabilityUnknown, ReasonUnrecognisedBuild, 2, "an api fact that cannot be read beside the daemon", func(w *world) {
		w.daemon("1.32.3")
		w.api("1.32.3-rc1")
	})
	add(ApplicabilityNotAffected, "", 1, "an api fact that is not from the API is no conflict", func(w *world) {
		w.daemon("1.32.3")
		w.version(mAsset, VersionAPIReported, OriginOperator, ChannelStable, "1.30.0")
	})
	add(ApplicabilityUnknown, ReasonVersionConflict, 2, "two daemon facts that differ", func(w *world) { w.daemon("1.30.0"); w.daemon("1.32.3") })
	add(ApplicabilityNotAffected, "", 2, "two daemon facts that agree", func(w *world) { w.daemon("1.32.3"); w.daemon("1.32.3-t0123456ab") })
	add(ApplicabilityUnknown, ReasonUnstableTrack, 2, "two daemon facts that agree but differ in channel", func(w *world) {
		w.daemon("1.32.3")
		w.version(mAsset, VersionRunningDaemon, OriginLocal, ChannelUnstable, "1.32.3")
	})
	add(ApplicabilityUnknown, ReasonChannelUnknown, 2, "two daemon facts that agree but one has no channel", func(w *world) {
		w.daemon("1.32.3")
		w.version(mAsset, VersionRunningDaemon, OriginLocal, ChannelUnknown, "1.32.3")
	})
	add(ApplicabilityUnknown, ReasonUnrecognisedBuild, 2, "one daemon fact unreadable beside a readable one", func(w *world) { w.daemon("1.32.3"); w.daemon("1.32.3-rc1") })

	add(ApplicabilityNotAffected, "", 1, "cli older than the daemon is ignored", func(w *world) { w.daemon("1.32.3"); w.cli("1.30.0") })
	add(ApplicabilityAffected, "", 1, "cli newer than the daemon is ignored", func(w *world) { w.daemon("1.30.0"); w.cli("1.32.3") })
	add(ApplicabilityNotAffected, "", 1, "an unreadable cli version is ignored beside the daemon", func(w *world) { w.daemon("1.32.3"); w.cli("not a version") })
	add(ApplicabilityNotAffected, "", 1, "a cli on another channel is ignored beside the daemon", func(w *world) {
		w.daemon("1.32.3")
		w.version(mAsset, VersionLocalCLI, OriginLocal, ChannelUnstable, "1.33.0")
	})
	add(ApplicabilityNotAffected, "", 2, "cli older than the connected api is ignored", func(w *world) { w.api("1.32.3"); w.connected(true); w.cli("1.30.0") })
	add(ApplicabilityNotAffected, "", 2, "cli and api disagree, api connected", func(w *world) { w.cli("1.30.0"); w.api("1.32.3"); w.connected(true) })
	add(ApplicabilityAffected, "", 2, "cli newer than the connected api is ignored", func(w *world) { w.api("1.30.0"); w.connected(true); w.cli("1.32.3") })

	// No exact fact: the API and CLI reports are a fallback, and must agree.
	add(ApplicabilityPotential, ReasonRuntimeUnobserved, 2, "api and cli agree, in range", func(w *world) { w.api("1.30.0"); w.cli("1.30.0") })
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 2, "api and cli agree, fixed", func(w *world) { w.api("1.32.3"); w.cli("1.32.3") })
	add(ApplicabilityUnknown, ReasonVersionConflict, 2, "api older than the cli", func(w *world) { w.api("1.30.0"); w.cli("1.32.3") })
	add(ApplicabilityUnknown, ReasonVersionConflict, 2, "api newer than the cli", func(w *world) { w.api("1.32.3"); w.cli("1.30.0") })
	add(ApplicabilityPotential, ReasonRuntimeUnobserved, 1, "cli alone, in range", func(w *world) { w.cli("1.30.0") })
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "cli alone, fixed", func(w *world) { w.cli("1.32.3") })
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "cli alone, a later major", func(w *world) { w.cli("2.0.0") })
	add(ApplicabilityPotential, ReasonRuntimeUnobserved, 1, "cli from the collector alone, in range", func(w *world) {
		w.version(mAsset, VersionLocalCLI, OriginCollector, ChannelStable, "1.30.0")
	})
	add(ApplicabilityUnknown, ReasonUnstableTrack, 1, "cli alone on the unstable channel", func(w *world) {
		w.version(mAsset, VersionLocalCLI, OriginLocal, ChannelUnstable, "1.30.0")
	})
	add(ApplicabilityUnknown, ReasonChannelUnknown, 1, "api alone with no known channel", func(w *world) {
		w.version(mAsset, VersionAPIReported, OriginAPI, ChannelUnknown, "1.30.0")
	})
	add(ApplicabilityUnknown, ReasonUnrecognisedBuild, 1, "api alone unreadable", func(w *world) { w.api("1.30.0-dev20261030") })
	add(ApplicabilityUnknown, ReasonUnrecognisedBuild, 2, "api readable and cli unreadable", func(w *world) { w.api("1.30.0"); w.cli("1.30.0+dfsg") })
	add(ApplicabilityUnknown, ReasonRuntimeUnobserved, 1, "a stale daemon fact does not make the cli exact", func(w *world) {
		w.daemon("1.30.0", w.ago(40*time.Minute))
		w.cli("1.32.3")
	})
	add(ApplicabilityPotential, ReasonRuntimeUnobserved, 1, "a failed daemon fact leaves the cli as a fallback", func(w *world) {
		w.daemon("1.32.3", failed())
		w.cli("1.30.0")
	})
	add(ApplicabilityNotAffected, "", 2, "a stale daemon fact beside a connected api", func(w *world) {
		w.daemon("1.30.0", w.ago(40*time.Minute))
		w.api("1.32.3")
		w.connected(true)
	})

	// A rule about the API's own report, or the CLI's: only its role counts (no R9, no fallback).
	asRole := func(role VersionRole) func(w *world) { return func(w *world) { w.rec().VersionRole = role } }
	add(ApplicabilityAffected, "", 1, "api rule, api in range", func(w *world) { asRole(VersionAPIReported)(w); w.api("1.30.0") })
	add(ApplicabilityNotAffected, "", 1, "api rule, api fixed", func(w *world) { asRole(VersionAPIReported)(w); w.api("1.32.3") })
	add(ApplicabilityUnknown, ReasonNoVersion, 0, "api rule, only the daemon reported", func(w *world) { asRole(VersionAPIReported)(w); w.daemon("1.30.0") })
	add(ApplicabilityUnknown, ReasonNoVersion, 0, "api rule, only the cli reported", func(w *world) { asRole(VersionAPIReported)(w); w.cli("1.30.0") })
	add(ApplicabilityAffected, "", 1, "api rule, other roles are ignored", func(w *world) { asRole(VersionAPIReported)(w); w.api("1.30.0"); w.daemon("1.32.3"); w.cli("1.32.3") })
	add(ApplicabilityUnknown, ReasonVersionConflict, 2, "api rule, two api reports differ", func(w *world) { asRole(VersionAPIReported)(w); w.api("1.30.0"); w.api("1.32.3") })
	add(ApplicabilityUnknown, ReasonNoVersion, 0, "api rule, an api report from a local origin", func(w *world) {
		asRole(VersionAPIReported)(w)
		w.version(mAsset, VersionAPIReported, OriginLocal, ChannelStable, "1.30.0")
	})
	add(ApplicabilityAffected, "", 1, "api rule, connected is not needed", func(w *world) { asRole(VersionAPIReported)(w); w.api("1.30.0"); w.connected(false) })
	add(ApplicabilityAffected, "", 1, "cli rule, cli in range", func(w *world) { asRole(VersionLocalCLI)(w); w.cli("1.30.0") })
	add(ApplicabilityNotAffected, "", 1, "cli rule, cli fixed", func(w *world) { asRole(VersionLocalCLI)(w); w.cli("1.32.3") })
	add(ApplicabilityUnknown, ReasonNoVersion, 0, "cli rule, only the api reported", func(w *world) { asRole(VersionLocalCLI)(w); w.api("1.30.0"); w.connected(true) })
	add(ApplicabilityUnknown, ReasonNoVersion, 0, "cli rule, only the daemon reported", func(w *world) { asRole(VersionLocalCLI)(w); w.daemon("1.30.0") })
	add(ApplicabilityAffected, "", 1, "cli rule from the collector", func(w *world) {
		asRole(VersionLocalCLI)(w)
		w.version(mAsset, VersionLocalCLI, OriginCollector, ChannelStable, "1.30.0")
	})
	return cs
}

func TestMatchVersionSources(t *testing.T) { runMatchCases(t, versionSourceCases()) }

// ---- the operating system and features a rule requires --------------------------------

func conditionCases() []matchCase {
	var cs []matchCase
	add := func(app Applicability, reason UnknownReason, evidence int, name string, build func(w *world)) {
		cs = append(cs, with(app, reason, evidence, name, build))
	}
	macRule := func(w *world) { w.rec().OS = "macos"; w.daemon("1.30.0") }
	sshRule := func(w *world) { w.rec().RequiredFeatures = []string{"ssh"}; w.daemon("1.30.0") }
	bothRule := func(w *world) {
		w.rec().OS = "macos"
		w.rec().RequiredFeatures = []string{"ssh"}
		w.daemon("1.30.0")
	}

	// The operating system, in the spellings sources use.
	for _, os := range []string{"macOS", "darwin"} {
		add(ApplicabilityAffected, "", 2, "macos rule, device reports "+os, func(w *world) { macRule(w); w.os(os) })
	}
	for _, os := range []string{"macos", "Darwin", "MacOS", "mac", "OSX", "macOS ", " macOS", "mac os", "zos", "Linux", "WINDOWS"} {
		add(ApplicabilityPotential, ReasonOSUnrecognised, 2, fmt.Sprintf("macos rule, device reports the unrecognised %q", os), func(w *world) { macRule(w); w.os(os) })
	}
	for _, os := range []string{"linux", "windows", "iOS", "ios", "tvOS", "android", "freebsd", "plan9", "js"} {
		add(ApplicabilityNotAffected, "", 2, "macos rule, device reports "+os, func(w *world) { macRule(w); w.os(os) })
	}
	add(ApplicabilityPotential, ReasonOSUnknown, 1, "macos rule, no platform fact", macRule)
	add(ApplicabilityPotential, ReasonOSUnknown, 1, "macos rule, a platform fact without an os", func(w *world) { macRule(w); w.os("") })
	add(ApplicabilityPotential, ReasonOSUnknown, 1, "macos rule, a stale platform fact", func(w *world) { macRule(w); w.os("linux", w.ago(31*time.Minute)) })
	add(ApplicabilityPotential, ReasonOSUnknown, 1, "macos rule, a platform fact with an error", func(w *world) { macRule(w); w.os("linux", failed()) })
	add(ApplicabilityPotential, ReasonOSUnknown, 1, "macos rule, a platform fact with freshness stale", func(w *world) { macRule(w); w.os("linux", freshness(FreshnessStale)) })
	add(ApplicabilityNotAffected, "", 2, "macos rule, a platform fact at the age limit", func(w *world) { macRule(w); w.os("linux", w.ago(30*time.Minute)) })
	for _, origin := range []Origin{OriginAPI, OriginOperator, OriginVendor, OriginDerived} {
		add(ApplicabilityPotential, ReasonOSUnknown, 1, "macos rule, linux reported by the "+string(origin), func(w *world) { macRule(w); w.platform(mAsset, origin, "linux") })
	}
	add(ApplicabilityNotAffected, "", 2, "macos rule, linux reported by the collector", func(w *world) { macRule(w); w.platform(mAsset, OriginCollector, "linux") })
	add(ApplicabilityAffected, "", 3, "macos rule, two spellings of macos agree", func(w *world) { macRule(w); w.os("macOS"); w.os("darwin") })
	add(ApplicabilityPotential, ReasonOSUnknown, 3, "macos rule, two platform facts disagree", func(w *world) { macRule(w); w.os("macOS"); w.os("linux") })
	add(ApplicabilityPotential, ReasonOSUnrecognised, 3, "macos rule, an unrecognised spelling beside a known one", func(w *world) { macRule(w); w.os("macOS"); w.os("MacOS") })
	add(ApplicabilityPotential, ReasonOSUnrecognised, 3, "macos rule, an unrecognised spelling beside a known mismatch", func(w *world) { macRule(w); w.os("linux"); w.os("Linux") })
	add(ApplicabilityAffected, "", 2, "macos rule, an untrusted platform fact beside a trusted one", func(w *world) {
		macRule(w)
		w.os("macOS")
		w.platform(mAsset, OriginOperator, "linux")
	})
	add(ApplicabilityAffected, "", 2, "macos rule, an empty platform fact beside a trusted one", func(w *world) { macRule(w); w.os("macOS"); w.os("") })
	add(ApplicabilityAffected, "", 2, "macos rule, a stale platform fact beside a trusted one", func(w *world) {
		macRule(w)
		w.os("macOS")
		w.os("linux", w.ago(40*time.Minute))
	})
	add(ApplicabilityAffected, "", 2, "the variant of a platform is ignored", func(w *world) {
		macRule(w)
		w.os("macOS")
		w.s.Platforms[0].Variant = "standalone"
	})
	add(ApplicabilityNotAffected, "", 2, "the variant of a platform does not rescue a mismatch", func(w *world) {
		macRule(w)
		w.os("linux")
		w.s.Platforms[0].Variant = "macOS"
	})
	add(ApplicabilityAffected, "", 2, "windows rule, device reports windows", func(w *world) {
		w.rec().OS = "windows"
		w.daemon("1.30.0")
		w.os("windows")
	})
	// Out of range, the operating system is not looked at.
	add(ApplicabilityNotAffected, "", 1, "out of range, no platform fact", func(w *world) { w.rec().OS = "macos"; w.daemon("1.32.3") })
	add(ApplicabilityNotAffected, "", 1, "out of range, an unrecognised platform", func(w *world) { w.rec().OS = "macos"; w.daemon("1.32.3"); w.os("MacOS") })
	add(ApplicabilityNotAffected, "", 1, "out of range, features missing", func(w *world) { w.rec().RequiredFeatures = []string{"ssh"}; w.daemon("1.32.3") })
	add(ApplicabilityNotAffected, "", 1, "out of range, both conditions unknown", func(w *world) { w.rec().OS = "macos"; w.rec().RequiredFeatures = []string{"ssh"}; w.daemon("1.34.0") })
	add(ApplicabilityNotAffected, "", 2, "out of range through the connected api, no platform", func(w *world) {
		w.rec().OS = "macos"
		w.api("1.32.3")
		w.connected(true)
	})

	// A rule for an API role takes its platform from the API.
	apiRule := func(w *world) { w.rec().VersionRole = VersionAPIReported; w.rec().OS = "linux"; w.api("1.30.0") }
	add(ApplicabilityNotAffected, "", 2, "api rule, windows reported by the api", func(w *world) { apiRule(w); w.platform(mAsset, OriginAPI, "windows") })
	add(ApplicabilityAffected, "", 2, "api rule, linux reported by the api", func(w *world) { apiRule(w); w.platform(mAsset, OriginAPI, "linux") })
	add(ApplicabilityPotential, ReasonOSUnknown, 1, "api rule, windows reported locally is not the api's", func(w *world) { apiRule(w); w.platform(mAsset, OriginLocal, "windows") })
	add(ApplicabilityPotential, ReasonOSUnknown, 1, "api rule, windows reported by the operator", func(w *world) { apiRule(w); w.platform(mAsset, OriginOperator, "windows") })

	// Features.
	add(ApplicabilityAffected, "", 2, "ssh required and on", func(w *world) { sshRule(w); w.feat("ssh", true) })
	add(ApplicabilityNotAffected, "", 2, "ssh required and off", func(w *world) { sshRule(w); w.feat("ssh", false) })
	add(ApplicabilityNotAffected, "", 2, "ssh required and off, from the collector", func(w *world) { sshRule(w); w.feature(mAsset, OriginCollector, "ssh", false) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "ssh required and not reported", sshRule)
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "ssh required, a different feature reported", func(w *world) { sshRule(w); w.feat("funnel", false) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "ssh required, a similar name reported", func(w *world) { sshRule(w); w.feat("SSH", false) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "ssh required, reported without a value", func(w *world) {
		sshRule(w)
		w.s.Features = append(w.s.Features, FeatureFact{Name: "ssh", Evidence: w.ev(OriginLocal, mAsset)})
	})
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "ssh required, off but stale", func(w *world) { sshRule(w); w.feat("ssh", false, w.ago(31*time.Minute)) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "ssh required, off but with an error", func(w *world) { sshRule(w); w.feat("ssh", false, failed()) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "ssh required, off but freshness stale", func(w *world) { sshRule(w); w.feat("ssh", false, freshness(FreshnessStale)) })
	for _, origin := range []Origin{OriginAPI, OriginOperator, OriginVendor, OriginDerived} {
		add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "ssh required, off as reported by the "+string(origin), func(w *world) { sshRule(w); w.feature(mAsset, origin, "ssh", false) })
	}
	add(ApplicabilityPotential, ReasonFeatureUnknown, 3, "ssh required, reported both on and off", func(w *world) { sshRule(w); w.feat("ssh", true); w.feat("ssh", false) })
	add(ApplicabilityNotAffected, "", 2, "ssh required, a stale on beside a fresh off", func(w *world) {
		sshRule(w)
		w.feat("ssh", true, w.ago(40*time.Minute))
		w.feat("ssh", false)
	})
	add(ApplicabilityAffected, "", 3, "ssh required, on twice", func(w *world) { sshRule(w); w.feat("ssh", true); w.feat("ssh", true) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "connected_to_control from the api does not satisfy a daemon rule that requires it", func(w *world) {
		w.rec().RequiredFeatures = []string{FeatureConnectedToControl}
		w.daemon("1.30.0")
		w.connected(true)
	})
	twoRule := func(w *world) { w.rec().RequiredFeatures = []string{"ssh", "funnel"}; w.daemon("1.30.0") }
	add(ApplicabilityAffected, "", 3, "two features, both on", func(w *world) { twoRule(w); w.feat("ssh", true); w.feat("funnel", true) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 2, "two features, one on and one unknown", func(w *world) { twoRule(w); w.feat("ssh", true) })
	add(ApplicabilityNotAffected, "", 3, "two features, one on and one off", func(w *world) { twoRule(w); w.feat("ssh", true); w.feat("funnel", false) })
	add(ApplicabilityNotAffected, "", 2, "two features, one off and one unknown", func(w *world) { twoRule(w); w.feat("funnel", false) })
	add(ApplicabilityNotAffected, "", 4, "two features, one off and one contradictory", func(w *world) {
		twoRule(w)
		w.feat("ssh", true)
		w.feat("ssh", false)
		w.feat("funnel", false)
	})
	add(ApplicabilityPotential, ReasonFeatureUnknown, 1, "two features, neither reported", twoRule)

	// Both conditions: a known false decides; otherwise all must be known to be true.
	add(ApplicabilityAffected, "", 3, "os and feature both hold", func(w *world) { bothRule(w); w.os("macOS"); w.feat("ssh", true) })
	add(ApplicabilityPotential, ReasonFeatureUnknown, 2, "os holds and the feature is unknown", func(w *world) { bothRule(w); w.os("macOS") })
	add(ApplicabilityPotential, ReasonOSUnknown, 2, "os unknown and the feature holds", func(w *world) { bothRule(w); w.feat("ssh", true) })
	add(ApplicabilityPotential, ReasonOSUnknown, 1, "os unknown and the feature unknown", bothRule)
	add(ApplicabilityPotential, ReasonOSUnrecognised, 2, "os unrecognised and the feature unknown", func(w *world) { bothRule(w); w.os("MacOS") })
	add(ApplicabilityPotential, ReasonOSUnrecognised, 3, "os unrecognised and the feature holds", func(w *world) { bothRule(w); w.os("MacOS"); w.feat("ssh", true) })
	add(ApplicabilityNotAffected, "", 2, "os unknown and the feature is off", func(w *world) { bothRule(w); w.feat("ssh", false) })
	add(ApplicabilityNotAffected, "", 2, "os is another and the feature is unknown", func(w *world) { bothRule(w); w.os("linux") })
	add(ApplicabilityNotAffected, "", 3, "os is another and the feature holds", func(w *world) { bothRule(w); w.os("linux"); w.feat("ssh", true) })
	add(ApplicabilityNotAffected, "", 3, "os holds and the feature is off", func(w *world) { bothRule(w); w.os("macOS"); w.feat("ssh", false) })
	add(ApplicabilityNotAffected, "", 3, "os unrecognised and the feature is off", func(w *world) { bothRule(w); w.os("MacOS"); w.feat("ssh", false) })
	return cs
}

func TestMatchOSAndFeatureConditions(t *testing.T) { runMatchCases(t, conditionCases()) }

// A rule names an operating system by its canonical name; a device reports it in the
// spelling its source uses. Every reported spelling meets its canonical name, and no other.
func TestMatchOSVocabularyEndToEnd(t *testing.T) {
	reported := []string{"linux", "windows", "macOS", "darwin", "iOS", "ios", "tvOS", "android", "freebsd", "openbsd", "illumos", "solaris", "plan9", "js", "aix", "dragonfly", "netbsd", "tamago", "wasip1"}
	var cs []matchCase
	for _, spelling := range reported {
		canonical, ok := NormaliseOS(spelling)
		if !ok {
			t.Fatalf("%q is in the table of reported spellings and is not recognised", spelling)
		}
		for _, rule := range []string{"linux", "windows", "macos", "ios", "tvos", "android", "freebsd", "openbsd", "illumos", "solaris", "plan9", "js", "aix", "dragonfly", "netbsd", "tamago", "wasip1"} {
			want := ApplicabilityNotAffected
			if rule == canonical {
				want = ApplicabilityAffected
			}
			cs = append(cs, with(want, "", 2, fmt.Sprintf("rule %s, device reports %s", rule, spelling), func(w *world) {
				w.rec().OS = rule
				w.daemon("1.30.0")
				w.os(spelling)
			}))
		}
	}
	runMatchCases(t, cs)
}

// ---- review, catalog freshness and pending rules --------------------------------------

func stateCases() []matchCase {
	var cs []matchCase
	add := func(app Applicability, reason UnknownReason, stale bool, name string, build func(w *world)) {
		cs = append(cs, matchCase{name: name, build: build, app: app, reason: reason, stale: stale})
	}
	expireCatalog := func(w *world) { w.c.ExpiresAt = w.now }
	futureCatalog := func(w *world) { w.c.IssuedAt = w.now.Add(time.Minute) }
	expireReview := func(w *world) { w.rec().ReviewExpiresAt = w.now }
	pending := func(w *world) { w.rec().ReviewState = ReviewPending }

	// Fresh, to a nanosecond.
	add(ApplicabilityNotAffected, "", false, "catalog and review fresh to the nanosecond", func(w *world) {
		w.daemon("1.32.3")
		w.c.ExpiresAt = w.now.Add(time.Nanosecond)
		w.rec().ReviewExpiresAt = w.now.Add(time.Nanosecond)
	})
	add(ApplicabilityNotAffected, "", false, "catalog issued at the evaluation time", func(w *world) {
		w.daemon("1.32.3")
		w.c.IssuedAt = w.now
		w.rec().ReviewedAt = w.now
	})

	// A catalog that is not fresh cannot clear a device; it keeps a positive warning.
	add(ApplicabilityUnknown, ReasonCatalogExpired, false, "expired catalog cannot clear", func(w *world) { w.daemon("1.32.3"); expireCatalog(w) })
	add(ApplicabilityUnknown, ReasonCatalogExpired, false, "a catalog not yet valid cannot clear", func(w *world) { w.daemon("1.32.3"); futureCatalog(w) })
	add(ApplicabilityAffected, "", true, "expired catalog keeps the affected warning", func(w *world) { w.daemon("1.30.0"); expireCatalog(w) })
	add(ApplicabilityAffected, "", true, "a catalog not yet valid keeps the affected warning", func(w *world) { w.daemon("1.30.0"); futureCatalog(w) })
	add(ApplicabilityPotential, ReasonRuntimeUnobserved, true, "expired catalog keeps the potential warning", func(w *world) { w.api("1.30.0"); expireCatalog(w) })
	add(ApplicabilityPotential, ReasonOSUnknown, true, "expired catalog keeps an unknown-os warning", func(w *world) { w.rec().OS = "macos"; w.daemon("1.30.0"); expireCatalog(w) })

	// A review that is not fresh likewise.
	add(ApplicabilityUnknown, ReasonReviewExpired, false, "expired review cannot clear", func(w *world) { w.daemon("1.32.3"); expireReview(w) })
	add(ApplicabilityAffected, "", true, "expired review keeps the affected warning", func(w *world) { w.daemon("1.30.0"); expireReview(w) })
	add(ApplicabilityPotential, ReasonRuntimeUnobserved, true, "expired review keeps the potential warning", func(w *world) { w.api("1.30.0"); expireReview(w) })
	add(ApplicabilityUnknown, ReasonCatalogExpired, false, "an expired catalog is named before an expired review", func(w *world) {
		w.daemon("1.32.3")
		expireCatalog(w)
		expireReview(w)
	})
	add(ApplicabilityAffected, "", true, "expired catalog and review keep the warning", func(w *world) { w.daemon("1.30.0"); expireCatalog(w); expireReview(w) })
	add(ApplicabilityUnknown, ReasonCatalogExpired, false, "out of range through the connected api, expired catalog", func(w *world) {
		w.api("1.32.3")
		w.connected(true)
		expireCatalog(w)
	})

	// An unknown keeps the reason it was given, whatever the state of the catalog or the rule.
	for _, state := range []struct {
		name  string
		apply func(w *world)
	}{{"expired catalog", expireCatalog}, {"expired review", expireReview}, {"pending rule", pending}, {"all three", func(w *world) { expireCatalog(w); expireReview(w); pending(w) }}} {
		add(ApplicabilityUnknown, ReasonUnstableTrack, false, "unstable track keeps its reason: "+state.name, func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginLocal, ChannelUnstable, "1.33.257")
			state.apply(w)
		})
		add(ApplicabilityUnknown, ReasonNoVersion, false, "no version keeps its reason: "+state.name, func(w *world) { w.os("linux"); state.apply(w) })
		add(ApplicabilityUnknown, ReasonStaleEvidence, false, "stale evidence keeps its reason: "+state.name, func(w *world) { w.daemon("1.30.0", w.ago(time.Hour)); state.apply(w) })
		add(ApplicabilityUnknown, ReasonEvidenceError, false, "an evidence error keeps its reason: "+state.name, func(w *world) { w.daemon("1.30.0", failed()); state.apply(w) })
		add(ApplicabilityUnknown, ReasonVersionConflict, false, "a conflict keeps its reason: "+state.name, func(w *world) { w.daemon("1.30.0"); w.daemon("1.32.3"); state.apply(w) })
		add(ApplicabilityUnknown, ReasonUnrecognisedBuild, false, "an unrecognised build keeps its reason: "+state.name, func(w *world) { w.daemon("1.30.0-rc1"); state.apply(w) })
		add(ApplicabilityUnknown, ReasonChannelUnknown, false, "an unknown channel keeps its reason: "+state.name, func(w *world) {
			w.version(mAsset, VersionRunningDaemon, OriginLocal, ChannelUnknown, "1.30.0")
			state.apply(w)
		})
		add(ApplicabilityUnknown, ReasonRuntimeUnobserved, false, "an unobserved daemon keeps its reason: "+state.name, func(w *world) { w.api("1.32.3"); state.apply(w) })
	}

	// A pending rule turns any result into unknown, and no mitigation is attached.
	add(ApplicabilityUnknown, ReasonReviewPending, false, "pending, affected", func(w *world) { w.daemon("1.30.0"); pending(w) })
	add(ApplicabilityUnknown, ReasonReviewPending, false, "pending, not affected", func(w *world) { w.daemon("1.32.3"); pending(w) })
	add(ApplicabilityUnknown, ReasonReviewPending, false, "pending, potentially affected", func(w *world) { w.api("1.30.0"); pending(w) })
	add(ApplicabilityUnknown, ReasonReviewPending, false, "pending without ranges", func(w *world) { w.daemon("1.30.0"); pending(w); w.rec().Ranges = nil })
	add(ApplicabilityUnknown, ReasonReviewPending, false, "pending without ranges, requiring a feature", func(w *world) {
		w.daemon("1.32.3")
		pending(w)
		w.rec().Ranges = nil
		w.rec().RequiredFeatures = []string{"ssh"}
	})
	add(ApplicabilityUnknown, ReasonReviewPending, false, "pending with a condition unknown", func(w *world) { w.rec().OS = "macos"; w.daemon("1.30.0"); pending(w) })
	add(ApplicabilityUnknown, ReasonReviewPending, false, "pending, with a mitigation text", func(w *world) { w.daemon("1.30.0"); pending(w); w.rec().Mitigation = "Do not show this." })
	add(ApplicabilityUnknown, ReasonCatalogExpired, false, "pending, not affected, expired catalog: the catalog is named first", func(w *world) {
		w.daemon("1.32.3")
		pending(w)
		expireCatalog(w)
	})
	add(ApplicabilityUnknown, ReasonReviewExpired, false, "pending, not affected, expired review: the review is named first", func(w *world) {
		w.daemon("1.32.3")
		pending(w)
		expireReview(w)
	})
	add(ApplicabilityUnknown, ReasonReviewPending, false, "pending, affected, expired catalog", func(w *world) { w.daemon("1.30.0"); pending(w); expireCatalog(w) })
	return cs
}

func TestMatchRuleAndCatalogState(t *testing.T) {
	runMatchCases(t, stateCases())
	// The runner derives "a mitigation is attached" from the result alone; a rule with no
	// mitigation text needs its own check.
	t.Run("a rule without mitigation text attaches none", func(t *testing.T) {
		w := newWorld(ScopeLocal)
		w.daemon("1.30.0")
		w.rec().Mitigation = ""
		findings, _, err := w.match(WorkBudget{})
		if err != nil || len(findings) != 1 || findings[0].Applicability != ApplicabilityAffected || len(findings[0].Verification) != 0 {
			t.Fatalf("%+v %v", findings, err)
		}
	})
}

// A stale review explains itself on a positive warning that is kept.
func TestMatchStaleReviewExplainsAKeptWarning(t *testing.T) {
	for name, stale := range map[string]func(w *world){
		"review":  func(w *world) { w.rec().ReviewExpiresAt = w.now },
		"catalog": func(w *world) { w.c.ExpiresAt = w.now },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(ScopeLocal)
			w.daemon("1.30.0")
			fresh, _, err := w.match(WorkBudget{})
			if err != nil || len(fresh) != 1 {
				t.Fatal(err)
			}
			stale(w)
			kept, _, err := w.match(WorkBudget{})
			if err != nil || len(kept) != 1 || kept[0].Applicability != ApplicabilityAffected {
				t.Fatalf("%+v %v", kept, err)
			}
			if kept[0].Explanation == fresh[0].Explanation || !strings.Contains(kept[0].Explanation, "stale") {
				t.Fatalf("the warning does not say that the review is stale: %q", kept[0].Explanation)
			}
		})
	}
}

// Every reason of the closed set is produced by some case of the tables above, so none is
// left without a path.
func TestMatchEveryReasonIsExercised(t *testing.T) {
	seen := map[UnknownReason]bool{}
	for _, group := range [][]matchCase{releaseCases(), evidenceCases(), versionSourceCases(), conditionCases(), stateCases()} {
		for _, tc := range group {
			if tc.reason != "" {
				seen[tc.reason] = true
			}
		}
	}
	for _, r := range unknownReasons {
		if !seen[r] {
			t.Errorf("no case produces the reason %q", r)
		}
	}
}
