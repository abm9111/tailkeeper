package tools_test

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// What doctor shows of the catalog is the catalog a scan judges by, not a second reading of the
// same files: replace the scan's catalog and the summary follows it.
func TestCatalogSummaryIsTheCatalogTheScanUses(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at,
		scanRule(at, "R-APPROVED", "1.32.3", security.SeverityHigh, security.ReviewApproved),
		scanRule(at, "R-PENDING-1", "1.32.3", security.SeverityHigh, security.ReviewPending),
		scanRule(at, "R-PENDING-2", "1.32.3", security.SeverityHigh, security.ReviewPending),
		scanRule(at, "R-WITHDRAWN", "1.32.3", security.SeverityHigh, security.ReviewWithdrawn))
	sum, err := tools.ScanCatalogSummary(at)
	if err != nil {
		t.Fatal(err)
	}
	out := scanRig(t, at).scan(t, `{"scope":"local"}`)
	c := out.Catalog
	if sum.Revision != c.Revision || sum.Digest != c.Digest || sum.Rules != c.Rules || sum.Approved != c.Approved || sum.Pending != c.Pending || sum.Withdrawn != c.Withdrawn ||
		sum.IssuedAt.UTC().Format(time.RFC3339) != c.IssuedAt || sum.ExpiresAt.UTC().Format(time.RFC3339) != c.ExpiresAt {
		t.Errorf("the summary %+v and the scan's catalog %+v differ", sum, c)
	}
	if sum.Rules != 4 || sum.Approved != 1 || sum.Pending != 2 || sum.Withdrawn != 1 || sum.Digest != strings.Repeat("0", 64) {
		t.Errorf("the premise: the replaced catalog is what both read: %+v", sum)
	}
}

func TestCatalogSummaryOfACatalogThatDoesNotLoad(t *testing.T) {
	restore := tools.SetScanCatalog(func() (security.Catalog, error) { return security.Catalog{}, errors.New("synthetic: no catalog") })
	defer restore()
	_, err := tools.ScanCatalogSummary(time.Now())
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.Internal || strings.Contains(e.Message, "synthetic") {
		t.Errorf("err = %v, want internal_error that does not repeat the cause", err)
	}
}

// The intent summary reads what a scan with no flag reads, by the same rules, and keeps none of
// it: the digest and the count only.
func TestConfiguredIntentSummary(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	t.Run("none", func(t *testing.T) {
		got, err := tools.ConfiguredIntentSummary(context.Background(), &registry.Env{})
		if err != nil || got != (tools.IntentSummary{}) {
			t.Errorf("%+v, %v", got, err)
		}
	})
	t.Run("a file", func(t *testing.T) {
		r := scanRig(t, at)
		r.configure(intentPath(t, intentFile))
		r.show()
		got, err := tools.ConfiguredIntentSummary(context.Background(), r.env)
		want := tools.IntentSummary{Configured: true, Digest: digestOf(intentFile), Expectations: 3}
		if err != nil || got != want {
			t.Errorf("%+v, %v, want %+v", got, err, want)
		}
		// And the scan names the same set.
		if out, err := r.scanWith(t, "local", nil); err != nil || out.Intent.Digest != got.Digest || out.Intent.Expectations != got.Expectations {
			t.Errorf("the scan names %+v (%v)", out.Intent, err)
		}
	})
	t.Run("a file that cannot be used is an error, not none", func(t *testing.T) {
		for name, path := range map[string]string{
			"missing":  filepath.Join(t.TempDir(), "gone.hujson"),
			"a defect": intentPath(t, `{"zq-canary-key": []}`),
			"a field":  intentPath(t, `{"tests": [{"src": "zq-canary-a", "zz-unmapped": ["tag:zq-canary:1"]}]}`),
		} {
			env := &registry.Env{Config: &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}}
			got, err := tools.ConfiguredIntentSummary(context.Background(), env)
			if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ConfigInvalid || got != (tools.IntentSummary{}) {
				t.Errorf("%s: %+v, %v, want config_invalid", name, got, err)
			}
		}
	})
}

// What the summary says of the catalog's freshness and of the reviews is what the scan says of
// them, at every clock: the catalog row of the scan is partial for "catalog expired or not yet
// valid" and counts "rules with a stale review", and the summary has the same two answers. The
// catalog here has a window, an approved rule whose review ends early, another whose review began
// before the catalog was issued and ends later, one that covers the whole window, a pending rule
// and a withdrawn one whose reviews end early: only the approved count. (A review cannot begin
// after the catalog is issued: a catalog like that does not validate.)
func TestCatalogSummaryAgreesWithTheScanAboutFreshness(t *testing.T) {
	base := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	hours := func(h int) time.Time { return base.Add(time.Duration(h) * time.Hour) }
	rule := func(id string, state security.ReviewState, from, to int) security.AdvisoryRecord {
		r := scanRule(base, id, "1.32.3", security.SeverityHigh, state)
		r.ReviewedAt, r.ReviewExpiresAt = hours(from), hours(to)
		return r
	}
	c := security.Catalog{SchemaVersion: security.SchemaVersion, Revision: 1, IssuedAt: hours(0), ExpiresAt: hours(100), Digest: strings.Repeat("0", 64), Records: []security.AdvisoryRecord{
		rule("R-EARLY", security.ReviewApproved, 0, 40), rule("R-OLDER", security.ReviewApproved, -20, 70), rule("R-WHOLE", security.ReviewApproved, 0, 100),
		rule("R-PENDING", security.ReviewPending, 0, 10), rule("R-WITHDRAWN", security.ReviewWithdrawn, 0, 10),
	}}
	defer tools.SetScanCatalog(func() (security.Catalog, error) { return c, nil })()
	stale := regexp.MustCompile(`rules with a stale review: (\d+)`)
	seen := map[string]bool{}
	for _, h := range []int{-50, -21, -20, -1, 0, 1, 39, 40, 41, 69, 70, 71, 99, 100, 101, 300} {
		at := hours(h)
		sum, err := tools.ScanCatalogSummary(at)
		if err != nil {
			t.Fatal(err)
		}
		out := scanRig(t, at).scan(t, `{"scope":"local"}`)
		row, ok := coverageRow(out, "catalog")
		if !ok {
			t.Fatal("no catalog row")
		}
		scanNotFresh := strings.Contains(row.Explanation, "catalog expired or not yet valid")
		if scanNotFresh != (sum.State != security.CatalogCurrent) {
			t.Errorf("hour %d: the scan says the catalog is not fresh: %v; the summary says it is %s (%q)", h, scanNotFresh, sum.State, row.Explanation)
		}
		scanStale := 0
		if m := stale.FindStringSubmatch(row.Explanation); m != nil {
			scanStale, _ = strconv.Atoi(m[1])
		}
		if scanStale != sum.StaleReviews {
			t.Errorf("hour %d: the scan counts %d stale reviews; the summary counts %d (%q)", h, scanStale, sum.StaleReviews, row.Explanation)
		}
		seen[string(sum.State)+"/"+strconv.Itoa(sum.StaleReviews)] = true
	}
	// The premise: the clocks above met every state of the catalog and different counts.
	for _, want := range []string{"not_yet_valid/", "current/", "expired/"} {
		found := false
		for k := range seen {
			found = found || strings.HasPrefix(k, want)
		}
		if !found {
			t.Errorf("no clock met state %s: %v", want, seen)
		}
	}
	if len(seen) < 6 {
		t.Errorf("the clocks met only %d different (state, stale) pairs: %v", len(seen), seen)
	}
}
