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

// The bulletins TS-2026-014 to TS-2026-017 ship as pending rules, one file each. The tests
// read the shipped files, so a rule cannot change without a test saying so. Matching is
// tried on a copy whose review state is approved: the shipped rules stay pending until the
// owner confirms the bulletin text, and a pending rule can only give unknown.

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

// ts2026Now is after the catalogs were issued (2026-10-30T00:00:00Z) and long before they
// expire, so the catalog and the rules are fresh.
var ts2026Now = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

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

// approvedCopy returns a copy of the catalog whose record is approved. The records are
// copied, so the catalog it was made from stays pending.
func approvedCopy(c security.Catalog) security.Catalog {
	out := c
	out.Records = append([]security.AdvisoryRecord(nil), c.Records...)
	out.Records[0].ReviewState = security.ReviewApproved
	return out
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

// The shipped files say what the bulletins say and no more: fixed in 1.104.4 with no lower
// bound and no backport, no CVE, pending, severity unknown because the bulletins gave none.
func TestShippedTS2026RulesAreAsReviewed(t *testing.T) {
	issued := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
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
			if catalog.Revision != 1 || !catalog.IssuedAt.Equal(issued) || !catalog.ExpiresAt.Equal(expires) {
				t.Errorf("catalog revision %d, issued %s, expires %s: want 1, %s, %s", catalog.Revision, catalog.IssuedAt, catalog.ExpiresAt, issued, expires)
			}
			if rec.ID != rule.id || rec.Revision != "1" || strings.HasPrefix(rec.ID, "CVE-") {
				t.Errorf("id %q, revision %q: want %s, 1, and no CVE", rec.ID, rec.Revision, rule.id)
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
			if rec.ReviewState != security.ReviewPending {
				t.Errorf("review state %q: the rule stays pending until the owner confirms the bulletin", rec.ReviewState)
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
	if !strings.Contains(string(readme), "pending") {
		t.Error("data/advisories/README.md does not say that the rules are pending")
	}
}

// A pending rule never leaks an unconfirmed advisory: whatever the device's version and
// features, the finding is unknown and carries no mitigation. Here every rule meets a
// device that runs 1.104.2 as its daemon (and, to show the rule is not read at all, a
// 1.104.4 one) with all, none and one of the four features known, so the evidence is
// enough to decide the device and the reason is review-pending. A device the evidence
// cannot judge keeps the reason it earned: see the test after this one.
func TestShippedTS2026RulesAreUnknownWhilePending(t *testing.T) {
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
	cases := []struct {
		name    string
		version string
		facts   []ts2026Fact
	}{
		{"1.104.2, every feature on", "1.104.2", localFacts(allFeatures, true)},
		{"1.104.2, every feature unknown", "1.104.2", nil},
		{"1.104.2, every feature off", "1.104.2", localFacts(allFeatures, false)},
		{"1.104.2, one feature on", "1.104.2", localFacts(allFeatures[:1], true)},
		{"1.104.2 with a build suffix, every feature on", "1.104.2" + ts2026SuffixTG, localFacts(allFeatures, true)},
		{"1.104.4, every feature on", "1.104.4", localFacts(allFeatures, true)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := matchTS2026(t, combined, ts2026Snapshot(tc.version, tc.facts))
			if len(findings) != len(ts2026Rules) {
				t.Fatalf("want %d findings, got %d: %+v", len(ts2026Rules), len(findings), findings)
			}
			for i, f := range findings {
				if f.RuleID != ts2026Rules[i].id || f.Applicability != security.ApplicabilityUnknown || f.Reason != security.ReasonReviewPending {
					t.Errorf("%s: %s with reason %q, want unknown with %q", f.RuleID, f.Applicability, f.Reason, security.ReasonReviewPending)
				}
				if len(f.Verification) != 0 || len(f.Remediation) != 0 {
					t.Errorf("%s: a pending rule carries mitigation text: %+v", f.RuleID, f)
				}
				if f.SourceSeverity != security.SeverityUnknown {
					t.Errorf("%s: source severity %q, want unknown", f.RuleID, f.SourceSeverity)
				}
			}
		})
	}
}

// Each approved copy, on the stable releases and the suffix forms Tailscale builds carry,
// and on every state of its features.
func TestApprovedTS2026RuleCopies(t *testing.T) {
	type tc struct {
		name    string
		version string
		facts   []ts2026Fact
		want    security.Applicability
		reason  security.UnknownReason
	}
	for _, rule := range ts2026Rules {
		t.Run(rule.id, func(t *testing.T) {
			catalog := approvedCopy(readTS2026(t, rule))
			if catalog.Records[0].ReviewState != security.ReviewApproved {
				t.Fatal("the copy is not approved")
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

// What a pending rule guarantees is that it never gives affected, potentially affected or
// not affected: every finding is unknown and carries no mitigation. The reason is
// review-pending only for a device the evidence could decide; an unknown keeps the reason it
// had earned already, and the documents say so. Three devices of a fleet meet all four
// shipped rules: one the API reports as fixed (the daemon is not observed), one with no
// version at all, and one the API reports as behind (which the rule would flag).
func TestAPendingShippedRuleKeepsTheReasonTheEvidenceEarned(t *testing.T) {
	var combined security.Catalog
	for i, rule := range ts2026Rules {
		catalog := readTS2026(t, rule)
		if i == 0 {
			combined = catalog
		} else {
			combined.Records = append(combined.Records, catalog.Records...)
		}
	}
	evidence := func(asset string) security.EvidenceRef {
		return security.EvidenceRef{Context: ts2026Context, Asset: asset, Scope: security.ScopeFleet, Origin: security.OriginAPI, AcquiredAt: ts2026Now, Freshness: security.FreshnessFresh}
	}
	reported := func(asset, release string) security.VersionFact {
		return security.VersionFact{Name: "client", Role: security.VersionAPIReported, Channel: security.ChannelStable, Value: &release, Evidence: evidence(asset)}
	}
	snapshot := security.Snapshot{Context: ts2026Context, Scope: security.ScopeFleet, ObservedAt: ts2026Now,
		Versions:  []security.VersionFact{reported("fixed", "1.104.5"), reported("behind", "1.104.2")},
		Platforms: []security.PlatformFact{{OS: "linux", Evidence: evidence("noversion")}}}
	want := map[string]security.UnknownReason{"fixed": security.ReasonRuntimeUnobserved, "noversion": security.ReasonNoVersion, "behind": security.ReasonReviewPending}
	findings := matchTS2026(t, combined, snapshot)
	if len(findings) != len(ts2026Rules)*len(want) {
		t.Fatalf("want %d findings, got %d", len(ts2026Rules)*len(want), len(findings))
	}
	for _, f := range findings {
		if f.Applicability != security.ApplicabilityUnknown || f.Reason != want[f.Asset] || len(f.Verification) != 0 || len(f.Remediation) != 0 {
			t.Errorf("%s for %s: %s with reason %q and %d lines of mitigation, want unknown with %q", f.RuleID, f.Asset, f.Applicability, f.Reason,
				len(f.Verification)+len(f.Remediation), want[f.Asset])
		}
	}
	// Approved, the same snapshot does speak: the reasons above are the pending state's doing.
	spoke := false
	for _, rule := range ts2026Rules {
		for _, f := range matchTS2026(t, approvedCopy(readTS2026(t, rule)), snapshot) {
			spoke = spoke || f.Applicability != security.ApplicabilityUnknown
		}
	}
	if !spoke {
		t.Error("the approved copies give only unknown for these devices, so the pending result proves nothing")
	}
}
