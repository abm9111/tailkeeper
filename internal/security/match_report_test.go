package security

import (
	"context"
	"testing"
	"time"
)

// The matcher and the validator share FindingID: a report built from Match's own output
// validates, and its identities are the ones FindingID gives for the snapshot's scope.

// reportFromMatch wraps Match's output in a report that requests the catalog row it
// returned (reportOf). It fails the test if Match fails.
func reportFromMatch(t *testing.T, c Catalog, s Snapshot, now time.Time) Report {
	t.Helper()
	findings, coverage, err := Match(context.Background(), c, s, now, WorkBudget{})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	return reportOf(s, now, findings, coverage)
}

// scopedInputs is testInputs with the snapshot and its evidence in the given scope.
func scopedInputs(now time.Time, version string, scope Scope) (Catalog, Snapshot) {
	c, s := testInputs(now, version)
	s.Scope = scope
	s.Versions[0].Evidence.Scope = scope
	return c, s
}

func TestMatchEmitsTheSharedFindingID(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, scope := range []Scope{ScopeLocal, ScopeFleet} {
		t.Run(string(scope), func(t *testing.T) {
			c, s := scopedInputs(now, "1.30.0", scope)
			findings, _, err := Match(context.Background(), c, s, now, WorkBudget{})
			if err != nil || len(findings) != 1 {
				t.Fatalf("%v %v", findings, err)
			}
			if want := FindingID("test", scope, "asset", "TEST-1"); findings[0].ID != want {
				t.Fatalf("id %s, want %s", findings[0].ID, want)
			}
		})
	}
}

func TestMatchIdentityDiffersByScope(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ids := map[Scope]string{}
	for _, scope := range []Scope{ScopeLocal, ScopeFleet} {
		c, s := scopedInputs(now, "1.30.0", scope)
		findings, _, err := Match(context.Background(), c, s, now, WorkBudget{})
		if err != nil || len(findings) != 1 {
			t.Fatalf("%v %v", findings, err)
		}
		ids[scope] = findings[0].ID
	}
	if ids[ScopeLocal] == ids[ScopeFleet] {
		t.Fatal("the same device and rule have one identity under both scopes")
	}
}

func TestMatchOutputValidatesAsAReport(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		version string
		want    Applicability
	}{{"1.30.0", ApplicabilityAffected}, {"1.32.3", ApplicabilityNotAffected}} {
		for _, scope := range []Scope{ScopeLocal, ScopeFleet} {
			t.Run(tc.version+"/"+string(scope), func(t *testing.T) {
				c, s := scopedInputs(now, tc.version, scope)
				r := reportFromMatch(t, c, s, now)
				if len(r.Findings) != 1 || r.Findings[0].Applicability != tc.want || r.Status != ReportComplete {
					t.Fatalf("unexpected match output: %+v", r)
				}
				if err := ValidateReport(r); err != nil {
					t.Fatalf("a report built from Match's output is refused: %v", err)
				}
			})
		}
	}
}
