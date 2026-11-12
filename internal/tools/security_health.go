package tools

import (
	"context"
	"time"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// This file is what `tailkeeper doctor` reads of the security assessment: the catalog built
// into the binary and the intent set the configuration names. Both are read by the code the
// scan uses (scanCatalog, catalogInfo and loadScanIntent), not by a second path to the same
// facts, so that doctor and a scan cannot disagree about which catalog or which file they
// speak of. Neither makes a request or records a source.

// CatalogSummary is the shipped catalog as doctor shows it.
type CatalogSummary struct {
	Revision  uint64
	Digest    string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Rules     int
	Approved  int
	Pending   int
	Withdrawn int
	// State and StaleReviews are the scan's own answers at the moment asked about: where the
	// moment falls in the catalog's window, and how many approved rules have a review that is not
	// fresh (the count the scan's catalog row gives as "rules with a stale review"). Both come
	// from the security package's predicates, the ones Match judges by.
	State        security.CatalogState
	StaleReviews int
}

// ScanCatalogSummary summarises the catalog a scan judges by, as the scan sees it at now. The
// error is a catalog that does not load, which is a bug of the build.
func ScanCatalogSummary(now time.Time) (CatalogSummary, error) {
	c, err := scanCatalog()
	if err != nil {
		return CatalogSummary{}, tkerr.Wrap(tkerr.Internal, err, "the advisory catalog built into this binary does not load", "this is a tailkeeper bug; report it with `tailkeeper version` output")
	}
	info := catalogInfo(c)
	sum := CatalogSummary{Revision: c.Revision, Digest: c.Digest, IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt,
		Rules: info.Rules, Approved: info.Approved, Pending: info.Pending, Withdrawn: info.Withdrawn,
		State: security.CatalogStateAt(c, now)}
	for _, r := range c.Records {
		if security.ReviewStale(r, now) {
			sum.StaleReviews++
		}
	}
	return sum, nil
}

// IntentSummary is the intent set the configuration names, as doctor shows it: whether there
// is one, how many expectations it holds and its digest. It holds none of the set's text, and
// not the file's path.
type IntentSummary struct {
	Configured   bool
	Digest       string
	Expectations int
}

// ConfiguredIntentSummary reads the intent set a scan with no flag would use, with the same
// rules: a path that is set and cannot be read, decoded or adapted is an error (config_invalid),
// never a summary of no intent.
func ConfiguredIntentSummary(ctx context.Context, env *registry.Env) (IntentSummary, error) {
	set, _, err := loadScanIntent(ctx, env, SecurityScanInput{})
	if err != nil || set == nil {
		return IntentSummary{}, err
	}
	return IntentSummary{Configured: true, Digest: set.Digest, Expectations: len(set.Network) + len(set.SSH)}, nil
}
