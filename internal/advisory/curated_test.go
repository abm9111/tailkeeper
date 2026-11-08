package advisory

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

func TestReviewedCVE202241925Controls(t *testing.T) {
	data, err := os.ReadFile("../../data/advisories/cve-2022-41925.json")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Records) != 1 || catalog.Records[0].ID != "CVE-2022-41925" || catalog.Records[0].Severity != security.SeverityLow {
		t.Fatal("reviewed rule identity or source severity changed")
	}
	now := time.Date(2026, 10, 30, 16, 13, 0, 0, time.UTC)
	cases := []struct {
		name    string
		version string
		role    security.VersionRole
		origin  security.Origin
		channel security.VersionChannel
		want    security.Applicability
	}{
		{"affected stable daemon", "1.32.2", security.VersionRunningDaemon, security.OriginLocal, security.ChannelStable, security.ApplicabilityAffected},
		{"fixed boundary daemon", "1.32.3", security.VersionRunningDaemon, security.OriginLocal, security.ChannelStable, security.ApplicabilityNotAffected},
		{"later stable daemon", "1.34.0", security.VersionRunningDaemon, security.OriginLocal, security.ChannelStable, security.ApplicabilityNotAffected},
		{"API reported old version", "1.32.2", security.VersionAPIReported, security.OriginAPI, security.ChannelStable, security.ApplicabilityPotential},
		{"API patched version lacks runtime proof", "1.32.3", security.VersionAPIReported, security.OriginAPI, security.ChannelStable, security.ApplicabilityUnknown},
		{"unstable fix outside supported grammar", "1.33.257", security.VersionRunningDaemon, security.OriginLocal, security.ChannelUnstable, security.ApplicabilityUnknown},
		{"downstream backport unproven", "1.32.2+vendor", security.VersionRunningDaemon, security.OriginLocal, security.ChannelStable, security.ApplicabilityUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			version := tc.version
			snapshot := security.Snapshot{Context: "synthetic-context", Scope: security.ScopeLocal, ObservedAt: now,
				Versions: []security.VersionFact{{Name: "client", Role: tc.role, Channel: tc.channel, Value: &version,
					Evidence: security.EvidenceRef{Context: "synthetic-context", Asset: "synthetic-asset", Scope: security.ScopeLocal, Origin: tc.origin, AcquiredAt: now, Freshness: security.FreshnessFresh}}}}
			findings, coverage, err := security.Match(context.Background(), catalog, snapshot, now, security.WorkBudget{})
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || findings[0].RuleID != "CVE-2022-41925" || findings[0].Applicability != tc.want {
				t.Fatalf("expected %s for reviewed rule, got %+v", tc.want, findings)
			}
			if len(coverage) == 0 {
				t.Fatal("missing coverage accounting")
			}
		})
	}
}

// The rule's dates, revisions and README provenance must agree with each other: one check
// time, a 90-day review, and a README that states the same dates and revisions. The values
// are read from the file, so a re-review edits the data and the README and not this test.
func TestReviewedCVE202241925DatesAndProvenanceAgree(t *testing.T) {
	data, err := os.ReadFile("../../data/advisories/cve-2022-41925.json")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.Records) != 1 {
		t.Fatalf("want one record, got %d", len(catalog.Records))
	}
	rec := catalog.Records[0]
	if rec.SourceCheckedAt == nil {
		t.Fatal("the rule carries no source_checked_at")
	}
	if !catalog.IssuedAt.Equal(rec.ReviewedAt) || !catalog.IssuedAt.Equal(*rec.SourceCheckedAt) {
		t.Fatalf("issued_at %s, reviewed_at %s and source_checked_at %s must be one check time", catalog.IssuedAt, rec.ReviewedAt, rec.SourceCheckedAt)
	}
	expires := catalog.IssuedAt.AddDate(0, 0, 90)
	if !catalog.ExpiresAt.Equal(expires) || !rec.ReviewExpiresAt.Equal(expires) {
		t.Fatalf("expires_at %s and review_expires_at %s must both be the check time plus 90 days (%s)", catalog.ExpiresAt, rec.ReviewExpiresAt, expires)
	}
	readme, err := os.ReadFile("../../data/advisories/README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		catalog.IssuedAt.UTC().Format(time.RFC3339),
		catalog.ExpiresAt.UTC().Format(time.RFC3339),
		fmt.Sprintf("The catalog `revision` is %d and the record `revision` is %q", catalog.Revision, rec.Revision),
		"The owner delegated it, and Claude (Opus 5.5) performed it",
	} {
		if !strings.Contains(string(readme), want) {
			t.Errorf("data/advisories/README.md does not state %q", want)
		}
	}
}
