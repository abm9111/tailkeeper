package security

import (
	"testing"
	"time"
)

// The one definition of when a catalog and a rule's review are fresh. The matcher judges by it,
// and so does anything that reports on the catalog without scanning (the doctor row), so that
// the two cannot disagree.
func TestCatalogStateAndReviewFreshnessAtTheirEdges(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	c := Catalog{IssuedAt: t0, ExpiresAt: t0.Add(100 * time.Hour)}
	for name, tc := range map[string]struct {
		at   time.Time
		want CatalogState
	}{
		"long before":           {t0.Add(-1000 * time.Hour), CatalogNotYetValid},
		"just before issue":     {t0.Add(-time.Nanosecond), CatalogNotYetValid},
		"the instant of issue":  {t0, CatalogCurrent},
		"in the middle":         {t0.Add(50 * time.Hour), CatalogCurrent},
		"just before expiry":    {t0.Add(100*time.Hour - time.Nanosecond), CatalogCurrent},
		"the instant of expiry": {t0.Add(100 * time.Hour), CatalogExpired},
		"long after":            {t0.Add(1000 * time.Hour), CatalogExpired},
	} {
		if got := CatalogStateAt(c, tc.at); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}
	rule := func(state ReviewState) AdvisoryRecord {
		return AdvisoryRecord{ReviewState: state, ReviewedAt: t0, ReviewExpiresAt: t0.Add(10 * time.Hour)}
	}
	for name, tc := range map[string]struct {
		at           time.Time
		fresh, stale bool // for an approved rule
	}{
		"before the review":      {t0.Add(-time.Nanosecond), false, true},
		"the instant of review":  {t0, true, false},
		"just before it expires": {t0.Add(10*time.Hour - time.Nanosecond), true, false},
		"the instant it expires": {t0.Add(10 * time.Hour), false, true},
	} {
		r := rule(ReviewApproved)
		if got := ReviewFresh(r, tc.at); got != tc.fresh {
			t.Errorf("%s: fresh %v, want %v", name, got, tc.fresh)
		}
		if got := ReviewStale(r, tc.at); got != tc.stale {
			t.Errorf("%s: stale %v, want %v", name, got, tc.stale)
		}
		// A rule that is pending or withdrawn is not "stale": the first gives unknown for its
		// state and the second gives nothing, whatever its review says.
		for _, state := range []ReviewState{ReviewPending, ReviewWithdrawn} {
			if ReviewStale(rule(state), tc.at) {
				t.Errorf("%s: a %s rule is stale", name, state)
			}
		}
	}
}
