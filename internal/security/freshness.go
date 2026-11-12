package security

import "time"

// CatalogState says where a moment falls in a catalog's window.
type CatalogState string

const (
	// CatalogCurrent: issued, and not yet expired. The only state in which the catalog can clear
	// a device.
	CatalogCurrent CatalogState = "current"
	// CatalogNotYetValid: the moment is before the catalog's issue time.
	CatalogNotYetValid CatalogState = "not_yet_valid"
	// CatalogExpired: the moment is at or after the catalog's expiry.
	CatalogExpired CatalogState = "expired"
)

// CatalogStateAt is the state of c at now. It is the one definition of a fresh catalog: Match
// judges by it, and so does anything that reports on a catalog without scanning, so that the two
// cannot disagree.
func CatalogStateAt(c Catalog, now time.Time) CatalogState {
	switch {
	case now.Before(c.IssuedAt):
		return CatalogNotYetValid
	case !now.Before(c.ExpiresAt):
		return CatalogExpired
	}
	return CatalogCurrent
}

// ReviewFresh says whether the review of r covers now: it began, and has not expired.
func ReviewFresh(r AdvisoryRecord, now time.Time) bool {
	return !now.Before(r.ReviewedAt) && now.Before(r.ReviewExpiresAt)
}

// ReviewStale says whether a rule that is in force by its review has a review that is not
// fresh at now. A pending rule is judged by its state (it gives unknown findings only) and a
// withdrawn one gives none, so neither is stale whatever its dates say. Match counts these
// rules in the catalog row's "rules with a stale review".
func ReviewStale(r AdvisoryRecord, now time.Time) bool {
	return r.ReviewState != ReviewWithdrawn && r.ReviewState != ReviewPending && !ReviewFresh(r, now)
}
