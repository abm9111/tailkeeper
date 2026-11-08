package security

import (
	"strings"
	"testing"
	"time"
)

// A report or a record that breaks two rules is refused for the first of them in the order
// the checks run, which the doc comments of ValidateReport and validateRecord state. The
// checks are split into steps (identity, totals, limits; fields, review, times, features,
// ranges), so each case breaks the last rule of an earlier step and the first of a later one,
// and expects the earlier. TestReportRulesRejectOnlyTheirOwnViolation and its catalog twin
// break one rule at a time, so they cannot see the order of the steps.
func TestAReportThatBreaksTwoRulesIsRefusedForTheFirstInTheOrderOfTheSteps(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(r *Report)
		want   string
	}{
		{"identity before totals", func(r *Report) { r.Status = "other"; r.TotalFindings = 99 }, "invalid report status"},
		{"identity before limits", func(r *Report) { r.SchemaVersion = 2; r.Snapshot.Scope = "other" }, "unsupported report schema version"},
		{"totals before limits", func(r *Report) { r.TotalFindings = MaxFindings + 1; r.Snapshot.Scope = "other" }, "finding total differs from the findings of an untruncated report"},
		{"the key epoch before the limits", func(r *Report) { r.KeyEpoch = "other"; r.Snapshot.Scope = "other" }, "key epoch mismatch"},
		{"the findings limit before the scope", func(r *Report) {
			r.Findings = make([]Finding, MaxFindings+1)
			r.TotalFindings = MaxFindings + 1
			r.Snapshot.Scope = "other"
		}, "too many findings"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := rulesPartial()
			c.mutate(&r)
			err := ValidateReport(r)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want one that says %q", err, c.want)
			}
		})
	}
}

func TestARecordThatBreaksTwoRulesIsRefusedForTheFirstInTheOrderOfTheSteps(t *testing.T) {
	soon := func(d time.Duration, c Catalog) *time.Time { t := c.IssuedAt.Add(d); return &t }
	for _, c := range []struct {
		name   string
		mutate func(c *Catalog)
		want   string
	}{
		{"fields before review", func(c *Catalog) { c.Records[0].ID = ""; c.Records[0].ReviewedAt = time.Time{} }, "empty advisory id"},
		{"the role before review", func(c *Catalog) { c.Records[0].VersionRole = "other"; c.Records[0].ReviewState = "other" }, "invalid advisory version role"},
		{"review before the operating system", func(c *Catalog) { c.Records[0].ReviewState = "other"; c.Records[0].OS = "other" }, "invalid advisory review state"},
		{"review before times", func(c *Catalog) { c.Records[0].ReviewState = "other"; c.Records[0].PublishedAt = soon(time.Hour, *c) }, "invalid advisory review state"},
		{"times before the approved range", func(c *Catalog) {
			c.Records[0].ReviewState = ReviewApproved
			c.Records[0].Ranges = nil
			c.Records[0].SourceCheckedAt = soon(time.Hour, *c)
		}, "advisory time is zero or after catalog issue"},
		{"the approved range before the features", func(c *Catalog) {
			c.Records[0].ReviewState = ReviewApproved
			c.Records[0].Ranges = nil
			c.Records[0].RequiredFeatures = []string{""}
		}, "approved advisory has no range"},
		{"features before ranges", func(c *Catalog) {
			c.Records[0].RequiredFeatures = []string{"a", "a"}
			c.Records[0].Ranges = []VersionRange{{}}
		}, "duplicate required feature"},
		{"ranges before text", func(c *Catalog) {
			c.Records[0].Ranges = []VersionRange{{}}
			c.Records[0].Mitigation = "bad\x00text"
		}, "range 0: empty range"},
		{"an invalid bound before the order of the bounds", func(c *Catalog) {
			c.Records[0].Ranges = []VersionRange{{Introduced: "1.3.0", Fixed: "1.2.0"}}
		}, "introduced version must have an even minor"},
		{"the checks of a range before its overlap with an earlier one", func(c *Catalog) {
			c.Records[0].Ranges = []VersionRange{{Introduced: "1.0.0", Fixed: "1.4.0"}, {Introduced: "1.2.0", Fixed: "1.3.0"}}
		}, "range 1: fixed version must have an even minor"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cat, _ := catalogFixture()
			c.mutate(&cat)
			err := ValidateCatalog(cat)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want one that says %q", err, c.want)
			}
		})
	}
}
