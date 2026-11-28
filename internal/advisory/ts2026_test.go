package advisory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

// The bulletins TS-2026-014 to TS-2026-017 ship as approved rules, one file each: the owner
// confirmed the bulletin text on 2026-11-28 after a live re-check (data/advisories/README.md).
// The tests read the shipped files, so a rule cannot change without a test saying so, and
// match devices against them as shipped.

type ts2026Rule struct {
	id       string
	file     string
	features []string
}

var ts2026Rules = []ts2026Rule{
	{"TS-2026-014", "ts-2026-014.json", []string{security.FeatureTailscaleSSH, security.FeatureSSHForwardingAllowed}},
	{"TS-2026-015", "ts-2026-015.json", []string{security.FeatureTailscaleSSH}},
	{"TS-2026-016", "ts-2026-016.json", []string{security.FeatureServeUnixBackend}},
	{"TS-2026-017", "ts-2026-017.json", []string{security.FeatureServeTLSMultiMount}},
}

const (
	ts2026Context = "synthetic-context"
	ts2026Asset   = "synthetic-asset"

	// Synthetic hex only: none of these is a real commit. The forms are the ones Tailscale
	// appends to a release and parseRelease reads: -t<hex> and -t<hex>-g<hex>.
	ts2026SuffixT  = "-t0123456ab"
	ts2026SuffixTG = "-t0123456ab-gfedcba987"
)

// ts2026Now is after the catalogs were issued (2026-11-28T08:35:00Z) and long before they
// expire, so the catalog and the rules are fresh.
var ts2026Now = time.Date(2026, 11, 29, 12, 0, 0, 0, time.UTC)

func readTS2026(t *testing.T, rule ts2026Rule) security.Catalog {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "data", "advisories", rule.file))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := Decode(data)
	if err != nil {
		t.Fatalf("%s: %v", rule.file, err)
	}
	if len(catalog.Records) != 1 {
		t.Fatalf("%s: want one record, got %d", rule.file, len(catalog.Records))
	}
	return catalog
}

// ts2026Fact is one feature fact of a device and the origin that reported it.
type ts2026Fact struct {
	name   string
	value  bool
	origin security.Origin
}

// localFacts reports every feature in names with the value, from the local origin: the
// origin a running-daemon rule accepts.
func localFacts(names []string, value bool) []ts2026Fact {
	var out []ts2026Fact
	for _, n := range names {
		out = append(out, ts2026Fact{n, value, security.OriginLocal})
	}
	return out
}

// ts2026Snapshot is one device that runs the given release as its daemon, with the given
// feature facts.
func ts2026Snapshot(version string, facts []ts2026Fact) security.Snapshot {
	evidence := func(origin security.Origin) security.EvidenceRef {
		return security.EvidenceRef{Context: ts2026Context, Asset: ts2026Asset, Scope: security.ScopeLocal, Origin: origin, AcquiredAt: ts2026Now, Freshness: security.FreshnessFresh}
	}
	s := security.Snapshot{Context: ts2026Context, Scope: security.ScopeLocal, ObservedAt: ts2026Now,
		Versions: []security.VersionFact{{Name: "client", Role: security.VersionRunningDaemon, Channel: security.ChannelStable, Value: &version, Evidence: evidence(security.OriginLocal)}}}
	for _, f := range facts {
		value := f.value
		s.Features = append(s.Features, security.FeatureFact{Name: f.name, Value: &value, Evidence: evidence(f.origin)})
	}
	return s
}

func matchTS2026(t *testing.T, c security.Catalog, s security.Snapshot) []security.Finding {
	t.Helper()
	findings, _, err := security.Match(context.Background(), c, s, ts2026Now, security.WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

// ts2026Update is what three of the shipped rules say to do. The bulletin of TS-2026-014 also
// gives a way to disable forwarding without disabling Tailscale SSH, and that rule says it
// after the same sentence (ts2026Mitigation); the other three bulletins give none.
const ts2026Update = "Update Tailscale to 1.104.4 or later; the vendor bulletin lists that release as the fix."

var ts2026Mitigation = map[string]string{
	"TS-2026-014": ts2026Update + " Until then, setting TS_SSH_DISABLE_FORWARDING=1 in the tailscaled service environment and restarting it disables SSH forwarding without disabling Tailscale SSH.",
	"TS-2026-015": ts2026Update,
	"TS-2026-016": ts2026Update,
	"TS-2026-017": ts2026Update,
}

// The shipped files say what the bulletins say and no more: fixed in 1.104.4 with no lower
// bound and no backport, no CVE, approved by the owner, severity unknown because the
// bulletins gave none.
func TestShippedTS2026RulesAreAsReviewed(t *testing.T) {
	issued := time.Date(2026, 11, 28, 8, 35, 0, 0, time.UTC)
	expires := issued.AddDate(0, 0, 90)
	published := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	readme, err := os.ReadFile("../../data/advisories/README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range ts2026Rules {
		t.Run(rule.id, func(t *testing.T) {
			catalog := readTS2026(t, rule)
			rec := catalog.Records[0]
			if catalog.Revision != 3 || !catalog.IssuedAt.Equal(issued) || !catalog.ExpiresAt.Equal(expires) {
				t.Errorf("catalog revision %d, issued %s, expires %s: want 3, %s, %s", catalog.Revision, catalog.IssuedAt, catalog.ExpiresAt, issued, expires)
			}
			if rec.ID != rule.id || rec.Revision != "3" || strings.HasPrefix(rec.ID, "CVE-") {
				t.Errorf("id %q, revision %q: want %s, 3, and no CVE", rec.ID, rec.Revision, rule.id)
			}
			if rec.Component != "client" || rec.VersionRole != security.VersionRunningDaemon || rec.OS != "" {
				t.Errorf("component %q, role %q, os %q: want client, running_daemon and no os", rec.Component, rec.VersionRole, rec.OS)
			}
			if want := "https://tailscale.com/security-bulletins#" + strings.ToLower(rule.id); rec.Source != want {
				t.Errorf("source %q, want %q", rec.Source, want)
			}
			if rec.Severity != security.SeverityUnknown {
				t.Errorf("severity %q: the bulletins gave none, so it is unknown", rec.Severity)
			}
			if rec.ReviewState != security.ReviewApproved {
				t.Errorf("review state %q: the owner approved the rule on 2026-11-28", rec.ReviewState)
			}
			if rec.Mitigation != ts2026Mitigation[rule.id] {
				t.Errorf("mitigation %q, want %q", rec.Mitigation, ts2026Mitigation[rule.id])
			}
			// The only range is "fixed in 1.104.4": introduced stays open, and there is no 1.102.x fix.
			if want := []security.VersionRange{{Fixed: "1.104.4"}}; !slices.Equal(rec.Ranges, want) {
				t.Errorf("ranges %+v, want %+v", rec.Ranges, want)
			}
			if !slices.Equal(rec.RequiredFeatures, rule.features) {
				t.Errorf("required features %v, want %v", rec.RequiredFeatures, rule.features)
			}
			if rec.PublishedAt == nil || !rec.PublishedAt.Equal(published) || rec.UpdatedAt != nil {
				t.Errorf("published %v, updated %v: want %s and none", rec.PublishedAt, rec.UpdatedAt, published)
			}
			if !rec.ReviewedAt.Equal(issued) || rec.SourceCheckedAt == nil || !rec.SourceCheckedAt.Equal(issued) || !rec.ReviewExpiresAt.Equal(expires) {
				t.Errorf("reviewed %s, checked %v, review expires %s: want %s, %s, %s", rec.ReviewedAt, rec.SourceCheckedAt, rec.ReviewExpiresAt, issued, issued, expires)
			}
			for _, want := range []string{rule.id, issued.Format(time.RFC3339), expires.Format(time.RFC3339)} {
				if !strings.Contains(string(readme), want) {
					t.Errorf("data/advisories/README.md does not state %q", want)
				}
			}
		})
	}
	// The README says what the files say: the owner approved the rules, on that day, after that
	// check; and it no longer describes them as waiting for the owner.
	for _, want := range []string{"approved by the owner on 2026-11-28", "TS_SSH_DISABLE_FORWARDING=1"} {
		if !strings.Contains(string(readme), want) {
			t.Errorf("data/advisories/README.md does not state %q", want)
		}
	}
	for _, stale := range []string{"still pending", "stay `pending`", "Every rule is `pending`"} {
		if strings.Contains(string(readme), stale) {
			t.Errorf("data/advisories/README.md still says %q", stale)
		}
	}
}

// combinedTS2026 is the four shipped rules in one catalog, in the order of ts2026Rules, and
// every feature they require, each once.
func combinedTS2026(t *testing.T) (security.Catalog, []string) {
	t.Helper()
	var combined security.Catalog
	var allFeatures []string
	for i, rule := range ts2026Rules {
		catalog := readTS2026(t, rule)
		if i == 0 {
			combined = catalog
		} else {
			combined.Records = append(combined.Records, catalog.Records...)
		}
		for _, f := range rule.features {
			if !slices.Contains(allFeatures, f) {
				allFeatures = append(allFeatures, f)
			}
		}
	}
	if len(combined.Records) != len(ts2026Rules) {
		t.Fatalf("want %d records, got %d", len(ts2026Rules), len(combined.Records))
	}
	return combined, allFeatures
}

// The shipped rules are approved, so they give a verdict: a device whose daemon is below the
// fix is affected when every feature the rule requires is known on, potentially affected
// (feature_unknown) when one is not known, and not affected when one is known off or the
// daemon is at or past the fix. The collector observes only tailscale_ssh, so a real scan
// meets the third case for TS-2026-014, -016 and -017 whatever the device runs. The
// mitigation text goes to an affected or potentially affected finding and to no other, and
// only TS-2026-014 carries the way to disable SSH forwarding.
func TestShippedTS2026RulesGiveTheApprovedVerdicts(t *testing.T) {
	combined, allFeatures := combinedTS2026(t)
	const (
		aff  = security.ApplicabilityAffected
		pot  = security.ApplicabilityPotential
		not  = security.ApplicabilityNotAffected
		fu   = security.ReasonFeatureUnknown
		none = security.UnknownReason("")
	)
	type verdict struct {
		applicability security.Applicability
		reason        security.UnknownReason
	}
	// want is the verdict of each rule in the order of ts2026Rules: 014, 015, 016, 017.
	cases := []struct {
		name    string
		version string
		facts   []ts2026Fact
		want    [4]verdict
	}{
		{"1.104.2, every feature on", "1.104.2", localFacts(allFeatures, true), [4]verdict{{aff, none}, {aff, none}, {aff, none}, {aff, none}}},
		{"1.104.2, every feature unknown", "1.104.2", nil, [4]verdict{{pot, fu}, {pot, fu}, {pot, fu}, {pot, fu}}},
		{"1.104.2, every feature off", "1.104.2", localFacts(allFeatures, false), [4]verdict{{not, none}, {not, none}, {not, none}, {not, none}}},
		// tailscale_ssh alone: what the collector can give. It decides TS-2026-015 and leaves the
		// rest with a feature nobody observes.
		{"1.104.2, only tailscale_ssh on", "1.104.2", []ts2026Fact{{security.FeatureTailscaleSSH, true, security.OriginLocal}}, [4]verdict{{pot, fu}, {aff, none}, {pot, fu}, {pot, fu}}},
		{"1.104.2, only tailscale_ssh off", "1.104.2", []ts2026Fact{{security.FeatureTailscaleSSH, false, security.OriginLocal}}, [4]verdict{{not, none}, {not, none}, {pot, fu}, {pot, fu}}},
		{"1.104.2 with a build suffix, every feature on", "1.104.2" + ts2026SuffixTG, localFacts(allFeatures, true), [4]verdict{{aff, none}, {aff, none}, {aff, none}, {aff, none}}},
		{"1.104.4, every feature on", "1.104.4", localFacts(allFeatures, true), [4]verdict{{not, none}, {not, none}, {not, none}, {not, none}}},
		{"1.104.4, every feature unknown", "1.104.4", nil, [4]verdict{{not, none}, {not, none}, {not, none}, {not, none}}},
		{"1.106.0, every feature unknown", "1.106.0", nil, [4]verdict{{not, none}, {not, none}, {not, none}, {not, none}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := matchTS2026(t, combined, ts2026Snapshot(tc.version, tc.facts))
			if len(findings) != len(ts2026Rules) {
				t.Fatalf("want %d findings, got %d: %+v", len(ts2026Rules), len(findings), findings)
			}
			for i, f := range findings {
				rule := ts2026Rules[i]
				if f.RuleID != rule.id || f.Applicability != tc.want[i].applicability || f.Reason != tc.want[i].reason {
					t.Errorf("%s: %s with reason %q, want %s with reason %q", f.RuleID, f.Applicability, f.Reason, tc.want[i].applicability, tc.want[i].reason)
				}
				if f.SourceSeverity != security.SeverityUnknown {
					t.Errorf("%s: source severity %q, want unknown", f.RuleID, f.SourceSeverity)
				}
				speaks := f.Applicability == security.ApplicabilityAffected || f.Applicability == security.ApplicabilityPotential
				switch {
				case !speaks && (len(f.Verification) != 0 || len(f.Remediation) != 0):
					t.Errorf("%s: a %s finding carries mitigation text: %+v", f.RuleID, f.Applicability, f)
				case speaks && (len(f.Verification) != 1 || f.Verification[0] != ts2026Mitigation[rule.id] || len(f.Remediation) != 0):
					t.Errorf("%s: a %s finding carries %q, want %q", f.RuleID, f.Applicability, f.Verification, ts2026Mitigation[rule.id])
				}
				if speaks && strings.Contains(f.Verification[0], "TS_SSH_DISABLE_FORWARDING") != (rule.id == "TS-2026-014") {
					t.Errorf("%s: the SSH forwarding workaround is TS-2026-014's alone: %q", f.RuleID, f.Verification[0])
				}
			}
		})
	}

	// The verdicts are the approved state's doing: the same files with a rule pending give
	// unknown for every device, so the cases above cannot pass on a rule that is not read.
	t.Run("the same rules pending give unknown only", func(t *testing.T) {
		pending := combined
		pending.Records = slices.Clone(combined.Records)
		for i := range pending.Records {
			pending.Records[i].ReviewState = security.ReviewPending
		}
		for _, f := range matchTS2026(t, pending, ts2026Snapshot("1.104.2", localFacts(allFeatures, true))) {
			if f.Applicability != security.ApplicabilityUnknown || f.Reason != security.ReasonReviewPending || len(f.Verification) != 0 {
				t.Errorf("%s pending: %s with reason %q: the control cannot tell approved from pending", f.RuleID, f.Applicability, f.Reason)
			}
		}
	})
}

// Each shipped rule, on the stable releases and the suffix forms Tailscale builds carry, and
// on every state of its features.
func TestShippedTS2026RulesMatchEveryStateOfTheirFeatures(t *testing.T) {
	type tc struct {
		name    string
		version string
		facts   []ts2026Fact
		want    security.Applicability
		reason  security.UnknownReason
	}
	for _, rule := range ts2026Rules {
		t.Run(rule.id, func(t *testing.T) {
			catalog := readTS2026(t, rule)
			if catalog.Records[0].ReviewState != security.ReviewApproved {
				t.Fatal("the shipped rule is not approved")
			}
			on := localFacts(rule.features, true)
			var cases []tc
			add := func(c ...tc) { cases = append(cases, c...) }

			// The version decides first: a release at or past the fix is cleared whatever the features say.
			for _, v := range []struct{ name, version string }{
				{"1.104.4", "1.104.4"},
				{"1.104.4 with -t", "1.104.4" + ts2026SuffixT},
				{"1.104.4 with -t and -g", "1.104.4" + ts2026SuffixTG},
				{"1.104.5", "1.104.5"},
				{"1.106.0", "1.106.0"},
			} {
				add(tc{"not affected at " + v.name + ", features on", v.version, on, security.ApplicabilityNotAffected, ""},
					tc{"not affected at " + v.name + ", features unknown", v.version, nil, security.ApplicabilityNotAffected, ""})
			}
			// Below the fix, with every feature known on, the device is affected. The fix is
			// stated for 1.104.4 only, with no 1.102.x backport and no lower bound.
			for _, v := range []struct{ name, version string }{
				{"1.104.2", "1.104.2"},
				{"1.104.2 with -t", "1.104.2" + ts2026SuffixT},
				{"1.104.2 with -t and -g", "1.104.2" + ts2026SuffixTG},
				{"1.104.3", "1.104.3"},
				{"1.102.9 (no backport)", "1.102.9"},
				{"1.60.0 (no lower bound)", "1.60.0"},
			} {
				add(tc{"affected at " + v.name, v.version, on, security.ApplicabilityAffected, ""},
					tc{"potentially affected at " + v.name + ", features unknown", v.version, nil, security.ApplicabilityPotential, security.ReasonFeatureUnknown})
			}
			// A feature known off clears the device, with the others on or unknown.
			for i, name := range rule.features {
				off := localFacts(rule.features, true)
				off[i].value = false
				add(tc{name + " off, the others on", "1.104.2", off, security.ApplicabilityNotAffected, ""},
					tc{name + " off, the others unknown", "1.104.2", []ts2026Fact{{name, false, security.OriginLocal}}, security.ApplicabilityNotAffected, ""})
				if len(rule.features) > 1 {
					// A single feature known on is not enough: the rest are unknown.
					add(tc{name + " on, the others unknown", "1.104.2", []ts2026Fact{{name, true, security.OriginLocal}}, security.ApplicabilityPotential, security.ReasonFeatureUnknown})
				}
			}
			// A feature fact of origin api speaks to a running-daemon rule only while the device is
			// connected to control as the API reports it (decision D5); without that fact, with a
			// disconnected one, or with a fact of origin derived, it says nothing and the feature
			// stays unknown.
			connected := ts2026Fact{security.FeatureConnectedToControl, true, security.OriginAPI}
			disconnected := ts2026Fact{security.FeatureConnectedToControl, false, security.OriginAPI}
			for _, value := range []bool{false, true} {
				var facts []ts2026Fact
				for _, name := range rule.features {
					facts = append(facts, ts2026Fact{name, value, security.OriginAPI})
				}
				guarded := append([]ts2026Fact{connected}, facts...)
				want := security.ApplicabilityNotAffected
				if value {
					want = security.ApplicabilityAffected
				}
				add(tc{fmt.Sprintf("api-origin features %t, connected", value), "1.104.2", guarded, want, ""},
					tc{fmt.Sprintf("api-origin features %t, no connected fact", value), "1.104.2", facts, security.ApplicabilityPotential, security.ReasonFeatureUnknown},
					tc{fmt.Sprintf("api-origin features %t, disconnected", value), "1.104.2", append([]ts2026Fact{disconnected}, facts...), security.ApplicabilityPotential, security.ReasonFeatureUnknown})

				var derived []ts2026Fact
				for _, name := range rule.features {
					derived = append(derived, ts2026Fact{name, value, security.OriginDerived})
				}
				add(tc{fmt.Sprintf("derived-origin features %t, connected", value), "1.104.2", append([]ts2026Fact{connected}, derived...), security.ApplicabilityPotential, security.ReasonFeatureUnknown})
			}
			// A local fact and a guarded api fact that disagree decide nothing.
			for _, name := range rule.features {
				facts := append(localFacts(rule.features, true), connected, ts2026Fact{name, false, security.OriginAPI})
				add(tc{name + ": local on, api off, connected", "1.104.2", facts, security.ApplicabilityPotential, security.ReasonFeatureUnknown})
			}
			// The collector origin does speak for a running-daemon rule.
			collector := localFacts(rule.features, true)
			for i := range collector {
				collector[i].origin = security.OriginCollector
			}
			add(tc{"collector-origin features on", "1.104.2", collector, security.ApplicabilityAffected, ""})

			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					findings := matchTS2026(t, catalog, ts2026Snapshot(c.version, c.facts))
					if len(findings) != 1 {
						t.Fatalf("want one finding, got %+v", findings)
					}
					f := findings[0]
					if f.RuleID != rule.id || f.Applicability != c.want || f.Reason != c.reason {
						t.Fatalf("%s: %s with reason %q, want %s with reason %q", f.RuleID, f.Applicability, f.Reason, c.want, c.reason)
					}
				})
			}
		})
	}
}

// Three devices of a fleet meet all four shipped rules, as the API reports them: one at a
// release past the fix, one with no version at all and one behind it. The API's report is no
// observation of the running daemon (there is no connected_to_control fact here, so it cannot
// stand for it), so the device behind the fix is only potentially affected
// (runtime_unobserved), the ones at or past it are unknown for the same reason and not
// cleared, and the device with no version keeps no_version. Only a finding that warns carries
// the mitigation text.
func TestShippedTS2026RulesOnAPIReportedVersionsOnlyWarn(t *testing.T) {
	combined, _ := combinedTS2026(t)
	evidence := func(asset string) security.EvidenceRef {
		return security.EvidenceRef{Context: ts2026Context, Asset: asset, Scope: security.ScopeFleet, Origin: security.OriginAPI, AcquiredAt: ts2026Now, Freshness: security.FreshnessFresh}
	}
	reported := func(asset, release string) security.VersionFact {
		return security.VersionFact{Name: "client", Role: security.VersionAPIReported, Channel: security.ChannelStable, Value: &release, Evidence: evidence(asset)}
	}
	snapshot := security.Snapshot{Context: ts2026Context, Scope: security.ScopeFleet, ObservedAt: ts2026Now,
		Versions:  []security.VersionFact{reported("past", "1.104.5"), reported("atfix", "1.104.4"), reported("behind", "1.104.2")},
		Platforms: []security.PlatformFact{{OS: "linux", Evidence: evidence("noversion")}}}
	type verdict struct {
		applicability security.Applicability
		reason        security.UnknownReason
	}
	want := map[string]verdict{
		"past":      {security.ApplicabilityUnknown, security.ReasonRuntimeUnobserved},
		"atfix":     {security.ApplicabilityUnknown, security.ReasonRuntimeUnobserved},
		"behind":    {security.ApplicabilityPotential, security.ReasonRuntimeUnobserved},
		"noversion": {security.ApplicabilityUnknown, security.ReasonNoVersion},
	}
	findings := matchTS2026(t, combined, snapshot)
	if len(findings) != len(ts2026Rules)*len(want) {
		t.Fatalf("want %d findings, got %d", len(ts2026Rules)*len(want), len(findings))
	}
	for _, f := range findings {
		w := want[f.Asset]
		if f.Applicability != w.applicability || f.Reason != w.reason {
			t.Errorf("%s for %s: %s with reason %q, want %s with %q", f.RuleID, f.Asset, f.Applicability, f.Reason, w.applicability, w.reason)
		}
		if f.Applicability == security.ApplicabilityPotential {
			if len(f.Verification) != 1 || f.Verification[0] != ts2026Mitigation[f.RuleID] || len(f.Remediation) != 0 {
				t.Errorf("%s for %s: mitigation %q, want %q", f.RuleID, f.Asset, f.Verification, ts2026Mitigation[f.RuleID])
			}
		} else if len(f.Verification) != 0 || len(f.Remediation) != 0 {
			t.Errorf("%s for %s: an unknown finding carries mitigation text: %+v", f.RuleID, f.Asset, f)
		}
	}
}
