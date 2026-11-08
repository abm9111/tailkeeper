package advisory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

// freshnessWindow is how long before an expiry a shipped rule must be re-reviewed. A catalog
// or record that expires within it, or has expired, fails the build, so a stale rule cannot
// reach a release unnoticed.
const freshnessWindow = 14 * 24 * time.Hour

// staleDates names every expiry in the catalog c (the catalog's own expires_at and each
// record's review_expires_at) that is past or no more than freshnessWindow after now. The
// file name is the path shown to the reader; the lines end with the re-review step.
func staleDates(file string, c security.Catalog, now time.Time) []string {
	var out []string
	check := func(what string, expires time.Time) {
		if expires.After(now.Add(freshnessWindow)) {
			return
		}
		state := fmt.Sprintf("expires %s, within %d days of now (%s)", expires.UTC().Format(time.RFC3339), int(freshnessWindow/(24*time.Hour)), now.UTC().Format(time.RFC3339))
		if !expires.After(now) {
			state = fmt.Sprintf("expired %s (now %s)", expires.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		}
		out = append(out, fmt.Sprintf("%s: %s %s: re-review the rule: re-check the official bulletin, then update the dates and revisions (reviewed_at, source_checked_at, review_expires_at, issued_at, expires_at, revision) here and in data/advisories/README.md", file, what, state))
	}
	check("catalog expires_at", c.ExpiresAt)
	for _, r := range c.Records {
		check("record "+r.ID+" review_expires_at", r.ReviewExpiresAt)
	}
	return out
}

// The shipped rules are read against the real clock, on every run and in CI, with no
// network: a rule whose review is about to lapse fails here until someone re-reads the
// bulletin. It never skips; a missing file set is itself a failure.
func TestShippedAdvisoriesAreNotNearExpiry(t *testing.T) {
	files, err := filepath.Glob("../../data/advisories/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no shipped advisory files found under data/advisories: the path or the glob is wrong")
	}
	now := time.Now()
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		catalog, err := Decode(data)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, line := range staleDates("data/advisories/"+filepath.Base(path), catalog, now) {
			t.Error(line)
		}
	}
}

// The detector is checked against a fixed clock so a clean real-clock run is believable:
// it flags a date inside the window, on its edge and in the past, in the catalog and in a
// record, and it passes a date one nanosecond beyond the edge.
func TestStaleDatesFlagsTheFourteenDayWindow(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		catalog time.Time
		record  time.Time
		want    int
	}{
		{"both far", now.Add(90 * 24 * time.Hour), now.Add(90 * 24 * time.Hour), 0},
		{"both just beyond the window", now.Add(freshnessWindow + time.Nanosecond), now.Add(freshnessWindow + time.Nanosecond), 0},
		{"catalog on the edge", now.Add(freshnessWindow), now.Add(90 * 24 * time.Hour), 1},
		{"record on the edge", now.Add(90 * 24 * time.Hour), now.Add(freshnessWindow), 1},
		{"catalog inside", now.Add(5 * 24 * time.Hour), now.Add(90 * 24 * time.Hour), 1},
		{"record inside", now.Add(90 * 24 * time.Hour), now.Add(time.Hour), 1},
		{"catalog expired", now.Add(-time.Second), now.Add(90 * 24 * time.Hour), 1},
		{"record expired", now.Add(90 * 24 * time.Hour), now, 1},
		{"both inside", now.Add(24 * time.Hour), now.Add(24 * time.Hour), 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := security.Catalog{ExpiresAt: tc.catalog, Records: []security.AdvisoryRecord{{ID: "CVE-0000-0000", ReviewExpiresAt: tc.record}}}
			got := staleDates("data/advisories/example.json", c, now)
			if len(got) != tc.want {
				t.Fatalf("want %d lines, got %d: %q", tc.want, len(got), got)
			}
		})
	}
}

func TestStaleDatesMessageNamesTheFileTheDateAndTheStep(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	expires := time.Date(2026, 11, 4, 20, 53, 0, 0, time.UTC)
	got := staleDates("data/advisories/example.json", security.Catalog{ExpiresAt: expires}, now)
	if len(got) != 1 {
		t.Fatalf("want one line, got %q", got)
	}
	for _, part := range []string{"data/advisories/example.json", "2026-11-04T20:53:00Z", "re-check the official bulletin", "update the dates and revisions"} {
		if !strings.Contains(got[0], part) {
			t.Fatalf("message lacks %q: %s", part, got[0])
		}
	}
}
