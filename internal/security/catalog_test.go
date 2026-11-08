package security

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Every catalog rule has a case here whose input is valid except for that one rule, and
// whose error text is asserted. A case cannot pass because another check fired: the
// fixture passes ValidateCatalog (TestCatalogFixtureIsValid), and the messages of different
// rules are different (TestCatalogRuleMessagesDiffer).

func catalogFixture() (Catalog, time.Time) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, _ := testInputs(now, "1.30.0")
	return c, now
}

func rangesOf(pairs ...string) []VersionRange {
	out := make([]VersionRange, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, VersionRange{Introduced: pairs[i], Fixed: pairs[i+1]})
	}
	return out
}

// evenRanges returns n adjacent ranges whose bounds all have even minors.
func evenRanges(n int) []VersionRange {
	out := make([]VersionRange, n)
	for i := range out {
		out[i] = VersionRange{Introduced: fmt.Sprintf("1.%d.0", 2*i), Fixed: fmt.Sprintf("1.%d.0", 2*i+2)}
	}
	return out
}

func manyRecords(c *Catalog, n int) {
	for len(c.Records) < n {
		r := c.Records[0]
		r.ID = fmt.Sprintf("TEST-%d", len(c.Records)+1)
		c.Records = append(c.Records, r)
	}
}

func TestCatalogFixtureIsValid(t *testing.T) {
	c, _ := catalogFixture()
	if err := ValidateCatalog(c); err != nil {
		t.Fatalf("the fixture every rule case starts from is not valid: %v", err)
	}
}

type catalogRule struct {
	rule   string // the rule under test; cases of one rule share a message
	name   string
	want   string
	mutate func(c *Catalog, now time.Time)
}

func catalogRules() []catalogRule {
	floor := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	before := floor.Add(-time.Nanosecond)
	longText := strings.Repeat("x", MaxTextBytes+1)
	record := func(f func(r *AdvisoryRecord)) func(c *Catalog, now time.Time) {
		return func(c *Catalog, _ time.Time) { f(&c.Records[0]) }
	}
	timeAt := func(t time.Time) *time.Time { return &t }
	return []catalogRule{
		{"schema version", "version 2", "unsupported catalog schema version", func(c *Catalog, _ time.Time) { c.SchemaVersion = 2 }},
		{"schema version", "version 0", "unsupported catalog schema version", func(c *Catalog, _ time.Time) { c.SchemaVersion = 0 }},
		{"revision 0", "revision 0", "catalog revision must be at least 1", func(c *Catalog, _ time.Time) { c.Revision = 0 }},
		{"catalog times missing", "no issue time", "catalog issue or expiry time is missing", func(c *Catalog, _ time.Time) { c.IssuedAt = time.Time{} }},
		{"catalog times missing", "no expiry time", "catalog issue or expiry time is missing", func(c *Catalog, _ time.Time) { c.ExpiresAt = time.Time{} }},
		{"expiry at or before issue", "expiry equals issue", "catalog expiry is not after issue", func(c *Catalog, _ time.Time) { c.ExpiresAt = c.IssuedAt }},
		{"expiry at or before issue", "expiry before issue", "catalog expiry is not after issue", func(c *Catalog, _ time.Time) { c.ExpiresAt = c.IssuedAt.Add(-time.Second) }},
		{"too many records", "1001 records", "too many records", func(c *Catalog, _ time.Time) { manyRecords(c, MaxCatalogRecords+1) }},
		{"too many ranges", "33 ranges", "too many ranges", record(func(r *AdvisoryRecord) { r.Ranges = evenRanges(MaxRanges + 1) })},
		{"too many required features", "33 features", "too many required features", record(func(r *AdvisoryRecord) {
			for i := 0; i <= MaxRanges; i++ {
				r.RequiredFeatures = append(r.RequiredFeatures, fmt.Sprintf("feature-%d", i))
			}
		})},
		{"empty id", "empty id", "empty advisory id", record(func(r *AdvisoryRecord) { r.ID = "" })},
		{"duplicate ids", "second record repeats the id", "duplicate advisory id", func(c *Catalog, _ time.Time) { c.Records = append(c.Records, c.Records[0]) }},
		{"empty record revision", "empty revision", "empty advisory revision", record(func(r *AdvisoryRecord) { r.Revision = "" })},
		{"empty component", "empty component", "empty advisory component", record(func(r *AdvisoryRecord) { r.Component = "" })},
		{"empty source", "empty source", "empty advisory source", record(func(r *AdvisoryRecord) { r.Source = "" })},
		{"invalid severity", "unknown word", "invalid advisory severity", record(func(r *AdvisoryRecord) { r.Severity = "urgent" })},
		{"invalid severity", "empty", "invalid advisory severity", record(func(r *AdvisoryRecord) { r.Severity = "" })},
		{"invalid version role", "unknown word", "invalid advisory version role", record(func(r *AdvisoryRecord) { r.VersionRole = "daemon" })},
		{"invalid version role", "empty", "invalid advisory version role", record(func(r *AdvisoryRecord) { r.VersionRole = "" })},
		{"review time missing", "no reviewed_at", "advisory review time is missing", record(func(r *AdvisoryRecord) { r.ReviewedAt = time.Time{} })},
		{"review time missing", "no review_expires_at", "advisory review time is missing", record(func(r *AdvisoryRecord) { r.ReviewExpiresAt = time.Time{} })},
		{"review time order", "review expiry equals review", "advisory review expiry is not after review", record(func(r *AdvisoryRecord) { r.ReviewExpiresAt = r.ReviewedAt })},
		{"review time order", "review expiry before review", "advisory review expiry is not after review", record(func(r *AdvisoryRecord) { r.ReviewExpiresAt = r.ReviewedAt.Add(-time.Second) })},
		{"reviewed after issue", "review one nanosecond after issue", "advisory reviewed after catalog issue", func(c *Catalog, _ time.Time) {
			c.Records[0].ReviewedAt = c.IssuedAt.Add(time.Nanosecond)
		}},
		{"invalid review state", "unknown word", "invalid advisory review state", record(func(r *AdvisoryRecord) { r.ReviewState = "imaginary" })},
		{"invalid review state", "empty", "invalid advisory review state", record(func(r *AdvisoryRecord) { r.ReviewState = "" })},
		{"os outside vocabulary", "capitalised linux", "unsupported advisory os", record(func(r *AdvisoryRecord) { r.OS = "Linux" })},
		{"os outside vocabulary", "reported macOS spelling", "unsupported advisory os", record(func(r *AdvisoryRecord) { r.OS = "macOS" })},
		{"os outside vocabulary", "raw darwin", "unsupported advisory os", record(func(r *AdvisoryRecord) { r.OS = "darwin" })},
		{"os outside vocabulary", "unknown word", "unsupported advisory os", record(func(r *AdvisoryRecord) { r.OS = "beos" })},
		{"os outside vocabulary", "trailing space", "unsupported advisory os", record(func(r *AdvisoryRecord) { r.OS = "linux " })},
		{"advisory time", "published after issue", "advisory time is zero or after catalog issue", func(c *Catalog, _ time.Time) { c.Records[0].PublishedAt = timeAt(c.IssuedAt.Add(time.Nanosecond)) }},
		{"advisory time", "updated after issue", "advisory time is zero or after catalog issue", func(c *Catalog, _ time.Time) { c.Records[0].UpdatedAt = timeAt(c.IssuedAt.Add(time.Nanosecond)) }},
		{"advisory time", "source checked after issue", "advisory time is zero or after catalog issue", func(c *Catalog, _ time.Time) {
			c.Records[0].SourceCheckedAt = timeAt(c.IssuedAt.Add(time.Nanosecond))
		}},
		{"advisory time", "published zero", "advisory time is zero or after catalog issue", record(func(r *AdvisoryRecord) { r.PublishedAt = timeAt(time.Time{}) })},
		{"advisory time", "updated zero", "advisory time is zero or after catalog issue", record(func(r *AdvisoryRecord) { r.UpdatedAt = timeAt(time.Time{}) })},
		{"advisory time", "source checked zero", "advisory time is zero or after catalog issue", record(func(r *AdvisoryRecord) { r.SourceCheckedAt = timeAt(time.Time{}) })},
		{"advisory time order", "updated before published", "advisory update precedes publication", func(c *Catalog, _ time.Time) {
			p := c.IssuedAt.Add(-time.Hour)
			u := p.Add(-time.Nanosecond)
			c.Records[0].PublishedAt, c.Records[0].UpdatedAt = &p, &u
		}},
		{"approved without range", "no ranges", "approved advisory has no range", record(func(r *AdvisoryRecord) { r.Ranges = nil })},
		{"empty required feature", "empty name", "empty required feature", record(func(r *AdvisoryRecord) { r.RequiredFeatures = []string{"ssh", ""} })},
		{"duplicate required feature", "repeated name", "duplicate required feature", record(func(r *AdvisoryRecord) { r.RequiredFeatures = []string{"ssh", "ssh"} })},
		{"empty range", "neither bound", "empty range", record(func(r *AdvisoryRecord) { r.Ranges = []VersionRange{{}} })},
		{"invalid introduced", "two components", "invalid introduced version", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("1.2", "1.4.0") })},
		{"invalid introduced", "build suffix", "invalid introduced version", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("1.2.0-t0123456ab", "1.4.0") })},
		{"invalid introduced", "leading zero", "invalid introduced version", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("01.2.0", "1.4.0") })},
		{"invalid fixed", "word", "invalid fixed version", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("1.2.0", "latest") })},
		{"invalid fixed", "build suffix", "invalid fixed version", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("1.2.0", "1.4.0-t0123456ab-g0123456ab") })},
		{"invalid fixed", "ten digit component", "invalid fixed version", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("1.2.0", "1.4.1234567890") })},
		{"odd minor bound", "odd introduced", "introduced version must have an even minor", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("1.3.0", "1.4.0") })},
		{"odd minor bound", "odd fixed alone", "fixed version must have an even minor", record(func(r *AdvisoryRecord) { r.Ranges = []VersionRange{{Fixed: "1.33.257"}} })},
		{"odd minor bound", "odd fixed after an even introduced", "fixed version must have an even minor", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("1.2.0", "1.5.0") })},
		{"introduced equals fixed", "equal bounds", "introduced equals fixed", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("1.2.0", "1.2.0") })},
		{"introduced after fixed", "reversed bounds", "introduced is after fixed", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("1.4.0", "1.2.0") })},
		{"range matches nothing", "fixed 0.0.0 alone", "range 0: fixed is 0.0.0 and nothing is introduced, so the range matches no release", record(func(r *AdvisoryRecord) { r.Ranges = []VersionRange{{Fixed: "0.0.0"}} })},
		{"range matches nothing", "fixed 0.0.0 after a valid range", "range 1: fixed is 0.0.0 and nothing is introduced, so the range matches no release", record(func(r *AdvisoryRecord) {
			r.Ranges = []VersionRange{{Introduced: "1.2.0", Fixed: "1.4.0"}, {Fixed: "0.0.0"}}
		})},
		{"overlap", "interleaved", "overlapping ranges", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("1.0.0", "1.4.0", "1.2.0", "1.6.0") })},
		{"overlap", "interleaved in the other order", "overlapping ranges", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("1.2.0", "1.6.0", "1.0.0", "1.4.0") })},
		{"overlap", "nested", "overlapping ranges", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("1.0.0", "1.8.0", "1.2.0", "1.4.0") })},
		{"overlap", "open end meets a later range", "overlapping ranges", record(func(r *AdvisoryRecord) {
			r.Ranges = []VersionRange{{Introduced: "1.0.0"}, {Introduced: "1.2.0", Fixed: "1.4.0"}}
		})},
		{"overlap", "two open starts", "overlapping ranges", record(func(r *AdvisoryRecord) { r.Ranges = []VersionRange{{Fixed: "1.2.0"}, {Fixed: "1.4.0"}} })},
		{"overlap", "identical", "overlapping ranges", record(func(r *AdvisoryRecord) { r.Ranges = rangesOf("1.2.0", "1.4.0", "1.2.0", "1.4.0") })},
		{"control character", "C0 in source", "control character", record(func(r *AdvisoryRecord) { r.Source = "https://example.invalid/\x00" })},
		{"control character", "newline in mitigation", "control character", record(func(r *AdvisoryRecord) { r.Mitigation = "line one\nline two" })},
		{"control character", "escape in id", "control character", record(func(r *AdvisoryRecord) { r.ID = "TEST\x1b[31m" })},
		{"control character", "DEL in component", "control character", record(func(r *AdvisoryRecord) { r.Component = "client\x7f" })},
		{"control character", "C1 in revision", "control character", record(func(r *AdvisoryRecord) { r.Revision = "1\u0085" })},
		{"control character", "C1 in a feature", "control character", record(func(r *AdvisoryRecord) { r.RequiredFeatures = []string{"ss\u009bh"} })},
		{"invisible character", "bidi override in source", "invisible or misleading character", record(func(r *AdvisoryRecord) { r.Source = "https://example.invalid/\u202e" })},
		{"invisible character", "zero-width space in id", "invisible or misleading character", record(func(r *AdvisoryRecord) { r.ID = "TEST\u200b" })},
		{"invisible character", "no-break space in mitigation", "invisible or misleading character", record(func(r *AdvisoryRecord) { r.Mitigation = "update\u00a0now" })},
		{"invisible character", "paragraph separator in mitigation", "invisible or misleading character", record(func(r *AdvisoryRecord) { r.Mitigation = "one\u2029two" })},
		{"invisible character", "tag character in component", "invisible or misleading character", record(func(r *AdvisoryRecord) { r.Component = "client\U000e0041" })},
		{"invisible character", "byte order mark in a feature", "invisible or misleading character", record(func(r *AdvisoryRecord) { r.RequiredFeatures = []string{"\ufeffssh"} })},
		{"invalid text", "oversized mitigation", "invalid or oversized text", record(func(r *AdvisoryRecord) { r.Mitigation = longText })},
		{"invalid text", "invalid UTF-8", "invalid or oversized text", record(func(r *AdvisoryRecord) { r.Source = "a" + string([]byte{0xff}) })},
		{"invalid text", "oversized digest", "invalid or oversized text", func(c *Catalog, _ time.Time) { c.Digest = longText }},
		{"time floor", "issued before the floor", "before 2019-01-01T00:00:00Z", func(c *Catalog, _ time.Time) {
			// every time moves into 2018 together, so only the floor is broken
			shift := -8 * 365 * 24 * time.Hour
			c.IssuedAt, c.ExpiresAt = c.IssuedAt.Add(shift), c.ExpiresAt.Add(shift)
			c.Records[0].ReviewedAt, c.Records[0].ReviewExpiresAt = c.Records[0].ReviewedAt.Add(shift), c.Records[0].ReviewExpiresAt.Add(shift)
		}},
		{"time floor", "reviewed before the floor", "before 2019-01-01T00:00:00Z", record(func(r *AdvisoryRecord) { r.ReviewedAt = before })},
		{"time floor", "published before the floor", "before 2019-01-01T00:00:00Z", record(func(r *AdvisoryRecord) { r.PublishedAt = &before })},
		{"time floor", "source checked before the floor", "before 2019-01-01T00:00:00Z", record(func(r *AdvisoryRecord) { r.SourceCheckedAt = &before })},
		{"time floor", "year 1901", "before 2019-01-01T00:00:00Z", record(func(r *AdvisoryRecord) { y := time.Date(1901, 1, 1, 0, 0, 0, 0, time.UTC); r.PublishedAt = &y })},
		{"time offset", "issued with an offset", "UTC offset", func(c *Catalog, _ time.Time) { c.IssuedAt = c.IssuedAt.In(time.FixedZone("plus one", 3600)) }},
		{"time offset", "reviewed with an offset", "UTC offset", record(func(r *AdvisoryRecord) { r.ReviewedAt = r.ReviewedAt.In(time.FixedZone("plus one", 3600)) })},
		{"time year", "expires in year 10000", "invalid timestamp", func(c *Catalog, _ time.Time) { c.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }},
	}
}

func TestCatalogRulesRejectOnlyTheirOwnViolation(t *testing.T) {
	for _, tc := range catalogRules() {
		t.Run(tc.rule+"/"+tc.name, func(t *testing.T) {
			c, now := catalogFixture()
			tc.mutate(&c, now)
			err := ValidateCatalog(c)
			if err == nil {
				t.Fatalf("accepted a catalog that breaks %q", tc.rule)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("rule %q: error %q does not say %q", tc.rule, err, tc.want)
			}
			// A rule about a record names the record, and a rule about a range names the range;
			// a rule about the catalog as a whole names neither.
			prefix := catalogErrorPrefix(tc)
			if !strings.HasPrefix(err.Error(), prefix) || (prefix == "" && strings.HasPrefix(err.Error(), "record ")) {
				t.Fatalf("rule %q: error %q should begin with %q", tc.rule, err, prefix)
			}
		})
	}
}

// catalogErrorPrefix is the position a catalog error carries: "" for a rule about the
// catalog, "record N: " for a rule about a record and "record N: range M: " for one about a
// range. Every case of the table breaks the rule in record 0, in range 0 (range 1 for an
// overlap), or in a second record where it repeats an id.
func catalogErrorPrefix(tc catalogRule) string {
	switch tc.rule {
	case "schema version", "revision 0", "catalog times missing", "expiry at or before issue", "too many records", "too many ranges", "too many required features", "time year":
		return ""
	case "empty range", "invalid introduced", "invalid fixed", "odd minor bound", "introduced equals fixed", "introduced after fixed":
		return "record 0: range 0: "
	case "overlap":
		return "record 0: range 1: "
	case "duplicate ids":
		return "record 1: "
	case "invalid text":
		if tc.name == "oversized digest" {
			return ""
		}
	case "time floor":
		if tc.name == "issued before the floor" {
			return ""
		}
	case "time offset":
		if tc.name == "issued with an offset" {
			return ""
		}
	}
	return "record 0: "
}

// Two different rules never share a message, and no message is part of another's, so a
// case cannot pass on the message of another rule.
func TestCatalogRuleMessagesDiffer(t *testing.T) {
	owner := map[string]string{} // message -> rule
	for _, tc := range catalogRules() {
		if other, ok := owner[tc.want]; ok && other != tc.rule {
			t.Errorf("rules %q and %q share the message %q", other, tc.rule, tc.want)
		}
		owner[tc.want] = tc.rule
	}
	for a, ruleA := range owner {
		for b, ruleB := range owner {
			if a != b && ruleA != ruleB && strings.Contains(b, a) {
				t.Errorf("the message %q of rule %q is part of the message %q of rule %q", a, ruleA, b, ruleB)
			}
		}
	}
}

// The spec lists these rules; each has a case above.
func TestCatalogEveryListedRuleHasACase(t *testing.T) {
	have := map[string]bool{}
	for _, tc := range catalogRules() {
		have[tc.rule] = true
	}
	for _, rule := range []string{
		"overlap", "introduced equals fixed", "duplicate ids", "review time order", "approved without range",
		"duplicate required feature", "advisory time order", "expiry at or before issue", "revision 0",
		"too many records", "empty source", "empty record revision", "invalid severity", "os outside vocabulary",
	} {
		if !have[rule] {
			t.Errorf("no isolating case for %q", rule)
		}
	}
}

// Values at the edge of each rule are accepted, so a rule cannot be tightened by one.
func TestCatalogBoundariesAreAccepted(t *testing.T) {
	floor := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		mutate func(c *Catalog)
	}{
		{"revision 1", func(c *Catalog) { c.Revision = 1 }},
		{"large revision", func(c *Catalog) { c.Revision = 1<<64 - 1 }},
		{"expiry one nanosecond after issue", func(c *Catalog) { c.ExpiresAt = c.IssuedAt.Add(time.Nanosecond) }},
		{"review expiry one nanosecond after review", func(c *Catalog) { c.Records[0].ReviewExpiresAt = c.Records[0].ReviewedAt.Add(time.Nanosecond) }},
		{"review at issue", func(c *Catalog) { c.Records[0].ReviewedAt = c.IssuedAt }},
		{"published at issue", func(c *Catalog) { t := c.IssuedAt; c.Records[0].PublishedAt = &t }},
		{"updated equals published", func(c *Catalog) {
			t := c.IssuedAt.Add(-time.Hour)
			c.Records[0].PublishedAt, c.Records[0].UpdatedAt = &t, &t
		}},
		{"source checked at issue", func(c *Catalog) { t := c.IssuedAt; c.Records[0].SourceCheckedAt = &t }},
		{"published without an update", func(c *Catalog) { t := c.IssuedAt.Add(-time.Hour); c.Records[0].PublishedAt = &t }},
		{"updated without a publication", func(c *Catalog) { t := c.IssuedAt.Add(-time.Hour); c.Records[0].UpdatedAt = &t }},
		{"updated after published", func(c *Catalog) {
			p, u := c.IssuedAt.Add(-2*time.Hour), c.IssuedAt.Add(-time.Hour)
			c.Records[0].PublishedAt, c.Records[0].UpdatedAt = &p, &u
		}},
		{"1000 records", func(c *Catalog) { manyRecords(c, MaxCatalogRecords) }},
		{"32 ranges", func(c *Catalog) { c.Records[0].Ranges = evenRanges(MaxRanges) }},
		{"32 required features", func(c *Catalog) {
			for i := 0; i < MaxRanges; i++ {
				c.Records[0].RequiredFeatures = append(c.Records[0].RequiredFeatures, fmt.Sprintf("feature-%d", i))
			}
		}},
		{"adjacent ranges", func(c *Catalog) { c.Records[0].Ranges = rangesOf("1.0.0", "1.2.0", "1.2.0", "1.4.0") }},
		{"adjacent ranges in the other order", func(c *Catalog) { c.Records[0].Ranges = rangesOf("1.2.0", "1.4.0", "1.0.0", "1.2.0") }},
		{"open start meets open end at a bound", func(c *Catalog) { c.Records[0].Ranges = []VersionRange{{Fixed: "1.2.0"}, {Introduced: "1.2.0"}} }},
		{"separated ranges", func(c *Catalog) { c.Records[0].Ranges = rangesOf("1.0.0", "1.2.0", "1.4.0", "1.6.0") }},
		{"introduced only", func(c *Catalog) { c.Records[0].Ranges = []VersionRange{{Introduced: "1.2.0"}} }},
		{"fixed only", func(c *Catalog) { c.Records[0].Ranges = []VersionRange{{Fixed: "1.2.0"}} }},
		{"minor zero bounds", func(c *Catalog) { c.Records[0].Ranges = rangesOf("0.0.0", "1.0.0") }},
		{"patch one apart", func(c *Catalog) { c.Records[0].Ranges = rangesOf("1.2.0", "1.2.1") }},
		{"major bounds", func(c *Catalog) { c.Records[0].Ranges = rangesOf("1.2.0", "2.0.0") }},
		{"pending without ranges", func(c *Catalog) { c.Records[0].ReviewState, c.Records[0].Ranges = ReviewPending, nil }},
		{"withdrawn without ranges", func(c *Catalog) { c.Records[0].ReviewState, c.Records[0].Ranges = ReviewWithdrawn, nil }},
		{"a range fixed at the first release above zero", func(c *Catalog) { c.Records[0].Ranges = []VersionRange{{Fixed: "0.2.0"}} }},
		{"a range introduced at 0.0.0", func(c *Catalog) { c.Records[0].Ranges = []VersionRange{{Introduced: "0.0.0", Fixed: "0.2.0"}} }},
		{"text of the largest size", func(c *Catalog) { c.Records[0].Mitigation = strings.Repeat("x", MaxTextBytes) }},
		{"text with accented letters and other scripts", func(c *Catalog) { c.Records[0].Mitigation = "Update now: café 日本" }},
		{"issued at the floor", func(c *Catalog) {
			shift := floor.Sub(c.IssuedAt)
			c.IssuedAt, c.ExpiresAt = c.IssuedAt.Add(shift), c.ExpiresAt.Add(shift)
			c.Records[0].ReviewedAt = floor
		}},
		{"reviewed at the floor", func(c *Catalog) { c.Records[0].ReviewedAt = floor }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := catalogFixture()
			tc.mutate(&c)
			if err := ValidateCatalog(c); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
	for _, os := range specCanonicalOS {
		c, _ := catalogFixture()
		c.Records[0].OS = os
		if err := ValidateCatalog(c); err != nil {
			t.Errorf("canonical os %q rejected: %v", os, err)
		}
	}
}

// A rule's os takes canonical values only. The reported spellings that differ from their
// canonical name (macOS, darwin, iOS, tvOS) are for facts: a rule that uses one is refused,
// so that two spellings of one operating system cannot be two different rules.
func TestCatalogRuleOSTakesCanonicalValuesOnly(t *testing.T) {
	for reported, canonical := range specOSTable {
		c, _ := catalogFixture()
		c.Records[0].OS = reported
		err := ValidateCatalog(c)
		if reported == canonical {
			if err != nil {
				t.Errorf("canonical os %q rejected: %v", reported, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "unsupported advisory os") {
			t.Errorf("reported spelling %q (canonical %q) in a rule: %v", reported, canonical, err)
		}
	}
}

func TestAdvisoryRecordHasNoVariant(t *testing.T) {
	if _, ok := reflect.TypeOf(AdvisoryRecord{}).FieldByName("Variant"); ok {
		t.Fatal("AdvisoryRecord.Variant must stay removed: a rule can name an OS but not a variant")
	}
	// Facts keep the variant as information; matching ignores it.
	if _, ok := reflect.TypeOf(PlatformFact{}).FieldByName("Variant"); !ok {
		t.Fatal("PlatformFact.Variant is information and stays")
	}
}
