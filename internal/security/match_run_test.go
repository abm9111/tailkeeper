package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Tests of a whole Match run: which devices it judges, how it counts, what it says when it
// cannot finish, what it refuses before it starts, and what it costs.

// richWorld has three rules and three devices that between them reach most branches of the
// matcher: an R9 device, a device with an operating-system condition, a withdrawn rule and a
// pending one. It takes a few hundred steps of work.
func richWorld(scope Scope) *world {
	w := newWorld(scope)
	w.rec().OS = "macos"
	w.rec().RequiredFeatures = []string{"ssh"}
	second := w.rule("RULE-2")
	second.Ranges = []VersionRange{{Introduced: "1.10.0", Fixed: "1.20.0"}}
	withdrawn := w.rule("RULE-3")
	withdrawn.ReviewState = ReviewWithdrawn
	pending := w.rule("RULE-4")
	pending.ReviewState = ReviewPending
	pending.Ranges = nil
	w.c.Records = append(w.c.Records, second, withdrawn, pending)
	w.version("d1", VersionRunningDaemon, OriginLocal, ChannelStable, "1.14.0")
	w.platform("d1", OriginLocal, "macOS")
	w.feature("d1", OriginLocal, "ssh", true)
	w.version("d2", VersionAPIReported, OriginAPI, ChannelStable, "1.30.0")
	w.feature("d2", OriginAPI, FeatureConnectedToControl, true)
	w.version("d3", VersionLocalCLI, OriginLocal, ChannelStable, "1.34.0")
	w.platform("d3", OriginLocal, "linux")
	return w
}

// countsOf is a row's counts, or the zero counts when it has none, so that a row without
// counts fails a comparison instead of a nil dereference.
func countsOf(c Coverage) CoverageCounts {
	if c.Counts == nil {
		return CoverageCounts{}
	}
	return *c.Counts
}

func TestMatchCountsEveryRuleAndDevice(t *testing.T) {
	for _, scope := range []Scope{ScopeLocal, ScopeFleet} {
		t.Run(string(scope), func(t *testing.T) {
			w := newWorld(scope)
			second := w.rule("RULE-2")
			second.Ranges = []VersionRange{{Fixed: "1.20.0"}}
			withdrawn := w.rule("RULE-3")
			withdrawn.ReviewState = ReviewWithdrawn
			pending := w.rule("RULE-4")
			pending.ReviewState = ReviewPending
			w.c.Records = append(w.c.Records, second, withdrawn, pending)
			w.version("d1", VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
			w.version("d2", VersionRunningDaemon, OriginLocal, ChannelStable, "1.34.0")
			w.platform("d3", OriginLocal, "linux") // named by a platform fact only
			findings, cov, err := w.match(WorkBudget{})
			if err != nil {
				t.Fatal(err)
			}
			type key struct{ rule, asset string }
			got := map[key]string{}
			var order []key
			for _, f := range findings {
				k := key{f.RuleID, f.Asset}
				if _, dup := got[k]; dup {
					t.Fatalf("two findings for %v", k)
				}
				got[k] = string(f.Applicability) + "/" + string(f.Reason)
				order = append(order, k)
			}
			want := map[key]string{
				{"RULE-1", "d1"}: "affected/", {"RULE-1", "d2"}: "not_affected/", {"RULE-1", "d3"}: "unknown/no_version",
				{"RULE-2", "d1"}: "not_affected/", {"RULE-2", "d2"}: "not_affected/", {"RULE-2", "d3"}: "unknown/no_version",
				{"RULE-4", "d1"}: "unknown/review_pending", {"RULE-4", "d2"}: "unknown/review_pending", {"RULE-4", "d3"}: "unknown/no_version",
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("findings\n got %v\nwant %v", got, want)
			}
			wantOrder := []key{{"RULE-1", "d1"}, {"RULE-1", "d2"}, {"RULE-1", "d3"}, {"RULE-2", "d1"}, {"RULE-2", "d2"}, {"RULE-2", "d3"}, {"RULE-4", "d1"}, {"RULE-4", "d2"}, {"RULE-4", "d3"}}
			if !reflect.DeepEqual(order, wantOrder) {
				t.Fatalf("order %v, want rule by rule and device by device in first-seen order: %v", order, wantOrder)
			}
			if len(cov) != 1 || cov[0].Counts == nil || countsOf(cov[0]) != (CoverageCounts{Rules: 3, Withdrawn: 1, Assets: 3, Findings: 9, Unknown: 5}) {
				t.Fatalf("coverage %+v", cov)
			}
			if cov[0].Status != ReportPartial {
				t.Fatal("a pending rule and unknown findings, yet the row is complete")
			}
			for _, f := range findings {
				if f.RuleID == "RULE-3" {
					t.Fatal("a withdrawn rule produced a finding")
				}
				if f.RuleID == "RULE-4" && len(f.Verification) != 0 {
					t.Fatal("a pending rule carries mitigation text")
				}
			}
			requireValidReport(t, w, findings, cov)
		})
	}
}

// A device is judged by every rule, whatever kind of fact named it, and in the order the
// facts were first seen: versions, then platforms, then features. A device whose only
// version evidence is stale is still a device (it used to be dropped without a word).
func TestMatchJudgesEveryDeviceTheFactsName(t *testing.T) {
	w := newWorld(ScopeLocal)
	w.version("c", VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
	w.version("e", VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0", w.ago(time.Hour))
	w.version("c", VersionAPIReported, OriginAPI, ChannelStable, "1.30.0")
	w.platform("b", OriginLocal, "linux")
	w.platform("c", OriginLocal, "linux")
	w.feature("a", OriginLocal, "ssh", true)
	w.feature("b", OriginLocal, "ssh", true)
	// A policy fact does not name a device.
	w.s.Policies = []PolicyFact{{Name: "acl", Evidence: w.ev(OriginAPI, "policy-only")}}
	findings, cov, err := w.match(WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range findings {
		got = append(got, fmt.Sprintf("%s:%s/%s", f.Asset, f.Applicability, f.Reason))
	}
	want := []string{"c:affected/", "e:unknown/stale_evidence", "b:unknown/no_version", "a:unknown/no_version"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if countsOf(cov[0]).Assets != 4 {
		t.Fatalf("counts %+v", countsOf(cov[0]))
	}
	requireValidReport(t, w, findings, cov)
}

// A fact of one device never speaks for another: R9 included.
func TestMatchKeepsDevicesApart(t *testing.T) {
	w := newWorld(ScopeLocal)
	w.version("a", VersionAPIReported, OriginAPI, ChannelStable, "1.32.3") // the API, not connected
	w.feature("b", OriginAPI, FeatureConnectedToControl, true)             // connected, with no version
	w.version("c", VersionAPIReported, OriginAPI, ChannelStable, "1.32.3")
	w.feature("c", OriginAPI, FeatureConnectedToControl, true) // the API, connected
	w.version("d", VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
	w.version("e", VersionRunningDaemon, OriginLocal, ChannelStable, "1.32.3")
	findings, cov, err := w.match(WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range findings {
		got[f.Asset] = string(f.Applicability) + "/" + string(f.Reason)
	}
	want := map[string]string{"a": "unknown/runtime_unobserved", "b": "unknown/no_version", "c": "not_affected/", "d": "affected/", "e": "not_affected/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, f := range findings {
		for _, e := range f.Evidence {
			if e.Asset != f.Asset {
				t.Fatalf("finding for %q cites evidence for %q", f.Asset, e.Asset)
			}
		}
	}
	requireValidReport(t, w, findings, cov)
}

func TestMatchWithdrawnRulesAreSkippedAndCounted(t *testing.T) {
	w := newWorld(ScopeLocal)
	w.daemon("1.30.0")
	w.rec().ReviewState = ReviewWithdrawn
	w.rec().Ranges = nil
	findings, cov, err := w.match(WorkBudget{})
	if err != nil || len(findings) != 0 {
		t.Fatalf("a withdrawn rule produced findings: %+v %v", findings, err)
	}
	if cov[0].Status != ReportPartial || countsOf(cov[0]) != (CoverageCounts{Withdrawn: 1, Assets: 1}) {
		t.Fatalf("a catalog of withdrawn rules is not a complete assessment: %+v", cov[0])
	}
	if !strings.Contains(cov[0].Explanation, "no rules evaluated") || !strings.Contains(cov[0].Explanation, "withdrawn rules skipped: 1") {
		t.Fatalf("explanation %q", cov[0].Explanation)
	}
	requireValidReport(t, w, findings, cov)

	// Beside a live rule, a withdrawn one costs the row nothing but a count.
	w.c.Records = append(w.c.Records, w.rule("RULE-2"))
	findings, cov, err = w.match(WorkBudget{})
	if err != nil || len(findings) != 1 || findings[0].RuleID != "RULE-2" || findings[0].Applicability != ApplicabilityAffected {
		t.Fatalf("%+v %v", findings, err)
	}
	if cov[0].Status != ReportComplete || countsOf(cov[0]) != (CoverageCounts{Rules: 1, Withdrawn: 1, Assets: 1, Findings: 1}) {
		t.Fatalf("coverage %+v", cov[0])
	}
	requireValidReport(t, w, findings, cov)
}

// An empty catalog, and a snapshot that names no device, are not complete assessments.
func TestMatchNothingToJudgeIsPartial(t *testing.T) {
	t.Run("no rules", func(t *testing.T) {
		w := newWorld(ScopeLocal)
		w.daemon("1.30.0")
		w.c.Records = nil
		findings, cov, err := w.match(WorkBudget{})
		if err != nil || len(findings) != 0 || cov[0].Status != ReportPartial || countsOf(cov[0]) != (CoverageCounts{Assets: 1}) || !strings.Contains(cov[0].Explanation, "no rules evaluated") {
			t.Fatalf("%+v %+v %v", findings, cov, err)
		}
		requireValidReport(t, w, findings, cov)
	})
	t.Run("no devices", func(t *testing.T) {
		w := newWorld(ScopeFleet)
		w.s.Policies = []PolicyFact{{Name: "acl", Evidence: w.ev(OriginAPI, "")}}
		findings, cov, err := w.match(WorkBudget{})
		if err != nil || len(findings) != 0 || cov[0].Status != ReportPartial || countsOf(cov[0]) != (CoverageCounts{Rules: 1}) || !strings.Contains(cov[0].Explanation, "no devices observed") {
			t.Fatalf("%+v %+v %v", findings, cov, err)
		}
		requireValidReport(t, w, findings, cov)
	})
	t.Run("an empty snapshot", func(t *testing.T) {
		w := newWorld(ScopeLocal)
		findings, cov, err := w.match(WorkBudget{})
		if err != nil || len(findings) != 0 || cov[0].Status != ReportPartial || countsOf(cov[0]) != (CoverageCounts{Rules: 1}) {
			t.Fatalf("%+v %+v %v", findings, cov, err)
		}
		requireValidReport(t, w, findings, cov)
	})
}

// The row says what made it partial, with the counts, and never claims more.
func TestMatchCoverageNamesItsCausesAndCounts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(w *world)
		has   []string
		hasNo []string
	}{
		{"complete", func(w *world) { w.daemon("1.30.0") }, nil, []string{"catalog", "rules", "review", "unknown", "devices"}},
		{"an expired catalog", func(w *world) { w.daemon("1.30.0"); w.c.ExpiresAt = w.now }, []string{"catalog expired or not yet valid"}, []string{"review", "findings"}},
		{"a catalog not yet valid", func(w *world) { w.daemon("1.30.0"); w.c.IssuedAt = w.now.Add(time.Second) }, []string{"catalog expired or not yet valid"}, nil},
		{"an expired review", func(w *world) { w.daemon("1.30.0"); w.rec().ReviewExpiresAt = w.now }, []string{"rules with a stale review: 1"}, []string{"catalog"}},
		{"a pending rule", func(w *world) { w.daemon("1.30.0"); w.rec().ReviewState = ReviewPending }, []string{"pending rules: 1", "unknown findings: 1 (review_pending 1)"}, []string{"stale review"}},
		{"an unknown finding", func(w *world) { w.api("1.32.3") }, []string{"unknown findings: 1 (runtime_unobserved 1)"}, []string{"potentially"}},
		{"a potential finding", func(w *world) { w.api("1.30.0") }, []string{"potentially affected findings: 1 (runtime_unobserved 1)"}, []string{"unknown findings"}},
		{"several reasons, in the order of the closed set", func(w *world) {
			w.daemon("1.30.0", w.ago(time.Hour))
			w.version("d2", VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0", failed())
			w.version("d3", VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0-rc1")
			w.os("linux")
			w.platform("d4", OriginLocal, "linux")
			w.version("d5", VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0", w.ago(time.Hour))
		}, []string{"unknown findings: 5 (no_version 1, evidence_error 1, stale_evidence 2, unrecognised_build 1)"}, nil},
		{"every cause at once", func(w *world) {
			w.c.ExpiresAt = w.now
			w.rec().ReviewState = ReviewPending
			second := w.rule("RULE-2")
			second.ReviewExpiresAt = w.now
			w.c.Records = append(w.c.Records, second)
			w.api("1.32.3")
			w.version("d2", VersionAPIReported, OriginAPI, ChannelStable, "1.30.0")
		}, []string{"catalog expired or not yet valid", "pending rules: 1", "rules with a stale review: 1", "unknown findings: 3", "potentially affected findings: 1 (runtime_unobserved 1)"}, []string{"no devices", "no rules"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(ScopeLocal)
			tc.build(w)
			findings, cov, err := w.match(WorkBudget{})
			if err != nil {
				t.Fatal(err)
			}
			text := cov[0].Explanation
			if (len(tc.has) == 0) != (cov[0].Status == ReportComplete) {
				t.Fatalf("status %s with explanation %q", cov[0].Status, text)
			}
			for _, want := range tc.has {
				if !strings.Contains(text, want) {
					t.Errorf("explanation %q does not say %q", text, want)
				}
			}
			for _, not := range tc.hasNo {
				if strings.Contains(text, not) {
					t.Errorf("explanation %q says %q", text, not)
				}
			}
			requireValidReport(t, w, findings, cov)
		})
	}
}

// ---- input that is refused before anything is judged ---------------------------------

func TestMatchRefusesInvalidInputWithoutACoverageRow(t *testing.T) {
	long := strings.Repeat("x", MaxTextBytes+1)
	zoned := time.FixedZone("plus4", 4*3600)
	// The message each refusal gives, in full: a case passes only if it is refused by its own
	// check and not by another that happens to catch the same input.
	says := map[string]string{
		"a budget below zero":                                      "invalid advisory work budget",
		"a budget of minus infinity":                               "invalid advisory work budget",
		"a budget above the maximum":                               "invalid advisory work budget",
		"a budget of the largest integer":                          "invalid advisory work budget",
		"no context":                                               "nil context",
		"no evaluation time":                                       "evaluation time is missing",
		"an empty context":                                         "snapshot context is empty",
		"no scope":                                                 "snapshot scope must be local or fleet",
		"a scope that is not one":                                  "snapshot scope must be local or fleet",
		"no observation time":                                      "snapshot observation time is missing",
		"observed after the evaluation time":                       "snapshot observed after the evaluation time",
		"observed before 2019":                                     "timestamp before 2019-01-01T00:00:00Z",
		"observed in another time zone":                            "timestamp must use UTC offset",
		"a version fact without a name":                            "version fact has no name",
		"a version fact with a role outside the vocabulary":        "invalid version role",
		"a version fact with a channel outside the vocabulary":     "invalid version channel",
		"a feature fact without a name":                            "feature fact has no name",
		"a policy fact without a name":                             "policy fact has no name",
		"evidence of another context":                              "evidence context does not match the report",
		"evidence of another scope":                                "version evidence scope differs from the snapshot scope",
		"evidence without a scope":                                 "version evidence scope differs from the snapshot scope",
		"a version fact that names no device":                      "version evidence names no device",
		"a platform fact that names no device":                     "platform evidence names no device",
		"a feature fact that names no device":                      "feature evidence names no device",
		"evidence acquired after the evaluation time":              "evidence acquisition time is missing or after the report was generated",
		"evidence observed after it was acquired":                  "evidence observation time is missing or after its acquisition",
		"evidence acquired in another time zone":                   "timestamp must use UTC offset",
		"evidence of an origin outside the vocabulary":             "invalid evidence origin",
		"evidence of a freshness outside the vocabulary":           "invalid evidence freshness",
		"evidence with a control character in its error":           "text contains a control character",
		"evidence with an oversize error":                          "invalid or oversized text",
		"a version value with a control character":                 "text contains a control character",
		"a platform with invalid UTF-8":                            "invalid or oversized text",
		"a revision zero catalog":                                  "catalog revision must be at least 1",
		"a catalog of another schema":                              "unsupported catalog schema version",
		"a rule without a source":                                  "record 0: empty advisory source",
		"a rule with an overlapping range":                         "record 0: range 1: overlapping ranges",
		"a rule with a control character in its mitigation":        "record 0: text contains a control character",
		"a rule naming an operating system by a reported spelling": "record 0: unsupported advisory os",
		"a duplicate rule":                                         "record 1: duplicate advisory id",
		"a withdrawn rule that is itself invalid":                  "record 1: empty advisory source",
		"more rules than a catalog may hold":                       "too many records",
		"more version facts than a snapshot may hold":              "too many snapshot observations",
		"more facts of all kinds than a snapshot may hold":         "too many snapshot observations",
	}
	type call func(w *world) ([]Finding, []Coverage, error)
	run := func(w *world) ([]Finding, []Coverage, error) { return w.match(WorkBudget{}) }
	for _, tc := range []struct {
		name   string
		mutate func(w *world)
		call   call
		is     error
	}{
		{"a budget below zero", nil, func(w *world) ([]Finding, []Coverage, error) { return w.match(WorkBudget{Candidates: -1}) }, ErrInvalidBudget},
		{"a budget of minus infinity", nil, func(w *world) ([]Finding, []Coverage, error) {
			return w.match(WorkBudget{Candidates: math.MinInt})
		}, ErrInvalidBudget},
		{"a budget above the maximum", nil, func(w *world) ([]Finding, []Coverage, error) {
			return w.match(WorkBudget{Candidates: MaxCandidates + 1})
		}, ErrInvalidBudget},
		{"a budget of the largest integer", nil, func(w *world) ([]Finding, []Coverage, error) {
			return w.match(WorkBudget{Candidates: math.MaxInt})
		}, ErrInvalidBudget},
		{"no context", nil, func(w *world) ([]Finding, []Coverage, error) {
			var none context.Context
			return Match(none, w.c, w.s, w.now, WorkBudget{})
		}, nil},
		{"no evaluation time", nil, func(w *world) ([]Finding, []Coverage, error) {
			return Match(context.Background(), w.c, w.s, time.Time{}, WorkBudget{})
		}, nil},
		{"an empty context", func(w *world) { w.s.Context = "" }, run, nil},
		{"no scope", func(w *world) { w.s.Scope = "" }, run, nil},
		{"a scope that is not one", func(w *world) { w.s.Scope = "all" }, run, nil},
		{"no observation time", func(w *world) { w.s.ObservedAt = time.Time{} }, run, nil},
		{"observed after the evaluation time", func(w *world) { w.s.ObservedAt = w.now.Add(time.Nanosecond) }, run, nil},
		{"observed before 2019", func(w *world) { w.s.ObservedAt = time.Date(2018, 12, 31, 23, 59, 59, 0, time.UTC) }, run, nil},
		{"observed in another time zone", func(w *world) { w.s.ObservedAt = w.s.ObservedAt.In(zoned) }, run, nil},
		{"a version fact without a name", func(w *world) { w.daemon("1.30.0"); w.s.Versions[0].Name = "" }, run, nil},
		{"a version fact with a role outside the vocabulary", func(w *world) { w.daemon("1.30.0"); w.s.Versions[0].Role = "primary" }, run, nil},
		{"a version fact with a channel outside the vocabulary", func(w *world) { w.daemon("1.30.0"); w.s.Versions[0].Channel = "beta" }, run, nil},
		{"a feature fact without a name", func(w *world) { w.feat("ssh", true); w.s.Features[0].Name = "" }, run, nil},
		{"a policy fact without a name", func(w *world) { w.s.Policies = []PolicyFact{{Evidence: w.ev(OriginAPI, "")}} }, run, nil},
		{"evidence of another context", func(w *world) { w.daemon("1.30.0"); w.s.Versions[0].Evidence.Context = "other" }, run, nil},
		{"evidence of another scope", func(w *world) {
			w.daemon("1.30.0")
			w.s.Versions[0].Evidence.Scope = map[Scope]Scope{ScopeLocal: ScopeFleet, ScopeFleet: ScopeLocal}[w.s.Scope]
		}, run, nil},
		{"evidence without a scope", func(w *world) { w.daemon("1.30.0"); w.s.Versions[0].Evidence.Scope = "" }, run, nil},
		{"a version fact that names no device", func(w *world) { w.daemon("1.30.0"); w.s.Versions[0].Evidence.Asset = "" }, run, nil},
		{"a platform fact that names no device", func(w *world) { w.daemon("1.30.0"); w.platform("", OriginLocal, "linux") }, run, nil},
		{"a feature fact that names no device", func(w *world) { w.daemon("1.30.0"); w.feature("", OriginLocal, "ssh", true) }, run, nil},
		{"evidence acquired after the evaluation time", func(w *world) { w.daemon("1.30.0", w.ago(-time.Nanosecond)) }, run, nil},
		{"evidence observed after it was acquired", func(w *world) {
			w.daemon("1.30.0", func(e *EvidenceRef) {
				t := e.AcquiredAt.Add(time.Nanosecond)
				e.ObservedAt = &t
			})
		}, run, nil},
		{"evidence acquired in another time zone", func(w *world) {
			w.daemon("1.30.0", func(e *EvidenceRef) { e.AcquiredAt = e.AcquiredAt.In(zoned) })
		}, run, nil},
		{"evidence of an origin outside the vocabulary", func(w *world) { w.daemon("1.30.0", func(e *EvidenceRef) { e.Origin = "rumour" }) }, run, nil},
		{"evidence of a freshness outside the vocabulary", func(w *world) { w.daemon("1.30.0", freshness("fresh-ish")) }, run, nil},
		{"evidence with a control character in its error", func(w *world) { w.daemon("1.30.0", func(e *EvidenceRef) { e.Error = "line\nbreak" }) }, run, nil},
		{"evidence with an oversize error", func(w *world) { w.daemon("1.30.0", func(e *EvidenceRef) { e.Error = long }) }, run, nil},
		{"a version value with a control character", func(w *world) { w.daemon("1.30.0\t") }, run, nil},
		{"a platform with invalid UTF-8", func(w *world) { w.daemon("1.30.0"); w.os("lin\xffux") }, run, nil},
		{"a revision zero catalog", func(w *world) { w.c.Revision = 0 }, run, nil},
		{"a catalog of another schema", func(w *world) { w.c.SchemaVersion = 2 }, run, nil},
		{"a rule without a source", func(w *world) { w.rec().Source = "" }, run, nil},
		{"a rule with an overlapping range", func(w *world) { w.rec().Ranges = []VersionRange{{Fixed: "1.32.3"}, {Fixed: "1.30.0"}} }, run, nil},
		{"a rule with a control character in its mitigation", func(w *world) { w.rec().Mitigation = "update\u0085now" }, run, nil},
		{"a rule naming an operating system by a reported spelling", func(w *world) { w.rec().OS = "macOS" }, run, nil},
		{"a duplicate rule", func(w *world) { w.c.Records = append(w.c.Records, w.c.Records[0]) }, run, nil},
		{"a withdrawn rule that is itself invalid", func(w *world) {
			r := w.rule("RULE-2")
			r.ReviewState, r.Source = ReviewWithdrawn, ""
			w.c.Records = append(w.c.Records, r)
		}, run, nil},
		{"more rules than a catalog may hold", func(w *world) {
			for i := 0; i <= MaxCatalogRecords; i++ {
				w.c.Records = append(w.c.Records, w.rule(fmt.Sprintf("RULE-X%d", i)))
			}
		}, run, nil},
		{"more version facts than a snapshot may hold", func(w *world) {
			for i := 0; i <= MaxObservations; i++ {
				w.version(fmt.Sprintf("d%d", i), VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
			}
		}, run, nil},
		{"more facts of all kinds than a snapshot may hold", func(w *world) {
			for i := 0; i <= MaxObservations/2; i++ {
				w.version(fmt.Sprintf("d%d", i), VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
				w.os("linux")
			}
		}, run, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(ScopeLocal)
			// The same input without the fault is accepted, so the fault is what is refused.
			if tc.mutate != nil {
				base := newWorld(ScopeLocal)
				if _, _, err := base.match(WorkBudget{}); err != nil {
					t.Fatalf("the baseline world is refused: %v", err)
				}
				tc.mutate(w)
			}
			findings, cov, err := tc.call(w)
			if err == nil {
				t.Fatal("accepted")
			}
			if findings != nil || cov != nil {
				t.Fatalf("findings %v and coverage %v with the error %v: invalid input has no coverage row", findings, cov, err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("error %v is not %v", err, tc.is)
			}
			if want, ok := says[tc.name]; !ok {
				t.Fatalf("no expected message for %q", tc.name)
			} else if err.Error() != want {
				t.Fatalf("refused with %q, want %q", err, want)
			}
			if errors.Is(err, ErrWorkBudget) && !errors.Is(err, ErrInvalidBudget) {
				t.Fatalf("input refused as a spent budget: %v", err)
			}
		})
	}
}

func TestMatchBudgetZeroIsTheMaximumAndTheMaximumIsAllowed(t *testing.T) {
	w := richWorld(ScopeLocal)
	want, _, err := w.match(WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := w.match(WorkBudget{Candidates: MaxCandidates})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", err)
	}
	if _, _, err := w.match(WorkBudget{Candidates: 1}); !errors.Is(err, ErrWorkBudget) {
		t.Fatalf("a budget of one: %v", err)
	}
}

// ---- stopping part-way ---------------------------------------------------------------

// requirePartialOutput checks what Match owes a caller when it stops after the start: the
// findings it has, a valid partial row that says so and counts them, and the error; and that
// the report built from them validates.
func requirePartialOutput(t *testing.T, w *world, full []Finding, findings []Finding, cov []Coverage, err error, why string) {
	t.Helper()
	if len(cov) != 1 || cov[0].Status != ReportPartial || cov[0].Counts == nil {
		t.Fatalf("an error after the start must leave one partial row with counts: %+v", cov)
	}
	if !strings.Contains(cov[0].Explanation, "evaluation stopped early: "+why) {
		t.Fatalf("explanation %q does not say that evaluation stopped early because of %s (%v)", cov[0].Explanation, why, err)
	}
	for _, claim := range []string{"no rules evaluated", "no devices observed"} {
		if strings.Contains(cov[0].Explanation, claim) {
			t.Fatalf("a run that stopped early says %q: %q", claim, cov[0].Explanation)
		}
	}
	if len(findings) > len(full) {
		t.Fatalf("%d findings so far, more than the %d of a complete run", len(findings), len(full))
	}
	for i := range findings {
		if !reflect.DeepEqual(findings[i], full[i]) {
			t.Fatalf("finding %d so far is not finding %d of a complete run", i, i)
		}
	}
	if countsOf(cov[0]).Findings != len(findings) {
		t.Fatalf("counts %+v for %d findings", countsOf(cov[0]), len(findings))
	}
	requireValidReport(t, w, findings, cov)
}

func TestMatchStoppedByTheBudgetLeavesAValidPartialRow(t *testing.T) {
	for _, scope := range []Scope{ScopeLocal, ScopeFleet} {
		w := richWorld(scope)
		full, fullCov, err := w.match(WorkBudget{})
		if err != nil || len(full) == 0 {
			t.Fatal(err)
		}
		requireValidReport(t, w, full, fullCov)
		sawPartial, previous := false, 0
		for budget := 1; ; budget++ {
			findings, cov, err := w.match(WorkBudget{Candidates: budget})
			if err == nil {
				if !reflect.DeepEqual(findings, full) || !reflect.DeepEqual(cov, fullCov) {
					t.Fatalf("budget %d finished with other results than the unlimited run", budget)
				}
				if !sawPartial || budget < 10 {
					t.Fatalf("finished with a budget of %d", budget)
				}
				break
			}
			if !errors.Is(err, ErrWorkBudget) {
				t.Fatalf("budget %d: %v", budget, err)
			}
			if len(findings) < previous {
				t.Fatalf("budget %d has fewer findings (%d) than a smaller budget (%d)", budget, len(findings), previous)
			}
			previous = len(findings)
			sawPartial = true
			requirePartialOutput(t, w, full, findings, cov, err, "work budget exhausted")
			// The rules are RULE-1, RULE-2, the withdrawn RULE-3 and the pending RULE-4: a run
			// that has started k rules is in the rule at position where[k] of 4.
			where := map[int]string{0: "before the first rule", 1: "at rule 1 of 4", 2: "at rule 2 of 4", 3: "at rule 4 of 4"}
			if rules := cov[0].Counts.Rules; !strings.Contains(cov[0].Explanation, where[rules]) {
				t.Fatalf("budget %d: %d rules started, explanation %q does not say %q", budget, rules, cov[0].Explanation, where[rules])
			}
			if budget > 5000 {
				t.Fatal("the run needs more than 5000 steps")
			}
		}
	}
}

// deadlineContext is a countingContext whose Err reports an expired deadline instead of a
// cancellation.
type deadlineContext struct {
	context.Context
	checks, stop int
}

func (c *deadlineContext) Err() error {
	c.checks++
	if c.checks >= c.stop {
		return context.DeadlineExceeded
	}
	return nil
}

// countingContext, defined with the earlier matcher tests, cancels after a number of Err
// calls: Match checks it at the start, in the catalog check and at every step. The same is
// done with a context that reports an expired deadline.
func TestMatchCancelledPartWayLeavesAValidPartialRow(t *testing.T) {
	w := richWorld(ScopeFleet)
	full, _, err := w.match(WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []struct {
		name string
		ctx  func(stop int) context.Context
		want error
		why  string
	}{
		{"cancelled", func(stop int) context.Context { return &countingContext{Context: context.Background(), stop: stop} }, context.Canceled, "cancelled"},
		{"deadline", func(stop int) context.Context { return &deadlineContext{Context: context.Background(), stop: stop} }, context.DeadlineExceeded, "deadline exceeded"},
	} {
		t.Run(kind.name, func(t *testing.T) {
			for stop := 1; ; stop++ {
				findings, cov, err := Match(kind.ctx(stop), w.c, w.s, w.now, WorkBudget{})
				if err == nil {
					if stop < 10 || !reflect.DeepEqual(findings, full) {
						t.Fatalf("stop %d finished", stop)
					}
					break
				}
				if !errors.Is(err, kind.want) {
					t.Fatalf("stop %d: %v", stop, err)
				}
				requirePartialOutput(t, w, full, findings, cov, err, kind.why)
				if stop > 5000 {
					t.Fatal("the run needs more than 5000 checks")
				}
			}
		})
	}
}

func TestMatchCancelledBeforeTheStart(t *testing.T) {
	w := richWorld(ScopeLocal)
	full, _, err := w.match(WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	findings, cov, err := Match(ctx, w.c, w.s, w.now, WorkBudget{})
	if !errors.Is(err, context.Canceled) || len(findings) != 0 {
		t.Fatalf("%v %v", findings, err)
	}
	requirePartialOutput(t, w, full, findings, cov, err, "cancelled")
	if countsOf(cov[0]) != (CoverageCounts{}) || !strings.Contains(cov[0].Explanation, "before the first rule") {
		t.Fatalf("%+v %q", countsOf(cov[0]), cov[0].Explanation)
	}
	// The catalog has not been looked at, so nothing is said about it.
	if strings.Contains(cov[0].Explanation, "catalog expired") {
		t.Fatalf("a run that stopped before it read the catalog judges it: %q", cov[0].Explanation)
	}

	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	_, cov, err = Match(deadline, w.c, w.s, w.now, WorkBudget{})
	if !errors.Is(err, context.DeadlineExceeded) || len(cov) != 1 || !strings.Contains(cov[0].Explanation, "deadline exceeded") {
		t.Fatalf("%v %+v", err, cov)
	}
}

// A cancelled context does not excuse invalid input: nothing was judged, and nothing is said.
func TestMatchCancelledAndInvalidInputIsInvalidInput(t *testing.T) {
	w := richWorld(ScopeLocal)
	w.s.Context = ""
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	findings, cov, err := Match(ctx, w.c, w.s, w.now, WorkBudget{})
	if err == nil || errors.Is(err, context.Canceled) || findings != nil || cov != nil {
		t.Fatalf("%v %v %v", findings, cov, err)
	}
}

// At the cap on findings, Match returns the 10,000 it has, a valid row and ErrWorkBudget.
func TestMatchStopsAtTheFindingsCap(t *testing.T) {
	w := newWorld(ScopeLocal)
	w.c.Records = append(w.c.Records, w.rule("RULE-2"))
	for i := 0; i <= MaxFindings/2; i++ { // 5,001 devices, two rules: 10,002 findings
		w.version(fmt.Sprintf("d%d", i), VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
	}
	findings, cov, err := w.match(WorkBudget{})
	if !errors.Is(err, ErrWorkBudget) || len(findings) != MaxFindings {
		t.Fatalf("%d findings and %v", len(findings), err)
	}
	if len(cov) != 1 || cov[0].Status != ReportPartial || countsOf(cov[0]).Findings != MaxFindings || !strings.Contains(cov[0].Explanation, "evaluation stopped early: findings limit reached") {
		t.Fatalf("%+v", cov)
	}
	requireValidReport(t, w, findings, cov)
}

// ---- cost ----------------------------------------------------------------------------

// One rule against 10,000 observations of 5,000 devices finishes inside the budget: the
// facts are indexed by device once, so the cost is the rules times the facts and not the
// rules times the devices times the facts. The limit below (eight steps an observation) is
// far under the 250,000 that the quadratic matcher spent at about 500 devices.
func TestMatchScalesToTheObservationCap(t *testing.T) {
	const devices = MaxObservations / 2
	for _, shape := range []struct {
		name  string
		build func(w *world, asset string)
	}{
		{"a version and a required feature per device", func(w *world, asset string) {
			w.version(asset, VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
			w.feature(asset, OriginLocal, "ssh", true)
		}},
		{"a version and a platform per device", func(w *world, asset string) {
			w.version(asset, VersionRunningDaemon, OriginLocal, ChannelStable, "1.32.3")
			w.platform(asset, OriginLocal, "macOS")
		}},
		{"two versions per device", func(w *world, asset string) {
			w.version(asset, VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
			w.version(asset, VersionAPIReported, OriginAPI, ChannelStable, "1.30.0")
		}},
		{"an api version and connected_to_control per device", func(w *world, asset string) {
			w.version(asset, VersionAPIReported, OriginAPI, ChannelStable, "1.32.3")
			w.feature(asset, OriginAPI, FeatureConnectedToControl, true)
		}},
	} {
		t.Run(shape.name, func(t *testing.T) {
			w := newWorld(ScopeFleet)
			w.rec().RequiredFeatures = []string{"ssh"}
			w.rec().OS = "macos"
			for i := 0; i < devices; i++ {
				shape.build(w, fmt.Sprintf("device-%d", i))
			}
			if n := len(w.s.Versions) + len(w.s.Platforms) + len(w.s.Features); n != MaxObservations {
				t.Fatalf("%d observations, want %d", n, MaxObservations)
			}
			findings, cov, err := w.match(WorkBudget{Candidates: 8 * MaxObservations})
			if err != nil {
				t.Fatalf("one rule against %d observations of %d devices: %v", MaxObservations, devices, err)
			}
			if len(findings) != devices || countsOf(cov[0]).Assets != devices {
				t.Fatalf("%d findings for %d devices", len(findings), devices)
			}
			requireValidReport(t, w, findings, cov)
		})
	}
}

// The cost of a run follows the rules times the facts: twenty rules over a thousand facts
// stay near twenty thousand steps and well inside the budget.
func TestMatchCostIsRulesTimesFacts(t *testing.T) {
	w := newWorld(ScopeLocal)
	for i := 1; i < 20; i++ {
		w.c.Records = append(w.c.Records, w.rule(fmt.Sprintf("RULE-%d", i+1)))
	}
	for i := 0; i < 500; i++ {
		asset := fmt.Sprintf("device-%d", i)
		w.version(asset, VersionRunningDaemon, OriginLocal, ChannelStable, "1.30.0")
		w.version(asset, VersionAPIReported, OriginAPI, ChannelStable, "1.30.0")
	}
	facts := len(w.s.Versions)
	findings, cov, err := w.match(WorkBudget{Candidates: 3*len(w.c.Records)*facts + facts})
	if err != nil || len(findings) != 20*500 {
		t.Fatalf("%d findings and %v", len(findings), err)
	}
	requireValidReport(t, w, findings, cov)
}

// ---- the report built from Match's output, as a property of every case ----------------

// TestMatchOutputAlwaysValidates is the property of the whole table: every case of every
// group above passes ValidateReport (the runner checks it), and so does one run with all the
// groups' facts as devices of one snapshot, in a single report.
func TestMatchOutputAlwaysValidates(t *testing.T) {
	for _, scope := range []Scope{ScopeLocal, ScopeFleet} {
		w := richWorld(scope)
		findings, cov, err := w.match(WorkBudget{})
		if err != nil {
			t.Fatal(err)
		}
		requireValidReport(t, w, findings, cov)
		seen := map[string]bool{}
		for _, f := range findings {
			if seen[f.ID] {
				t.Fatalf("two findings share the identity %s", f.ID)
			}
			seen[f.ID] = true
		}
	}
}

// The words a finding and a coverage row use are fixed in the program: one text for each
// reason, none shared, each fit to sit in a report (no control character, within the limit).
func TestMatchExplanationsAreFixedText(t *testing.T) {
	if len(reasonText) != len(unknownReasons) {
		t.Fatalf("%d texts for %d reasons", len(reasonText), len(unknownReasons))
	}
	seen := map[string]UnknownReason{}
	for _, r := range unknownReasons {
		text := reasonText[r]
		if text == "" {
			t.Errorf("no text for %q", r)
		}
		if err := validateString(text); err != nil {
			t.Errorf("text for %q: %v", r, err)
		}
		if other, dup := seen[text]; dup {
			t.Errorf("%q and %q share a text", r, other)
		}
		seen[text] = r
		if err := validateString(text + " " + staleExplanation); err != nil {
			t.Errorf("text for %q with the stale note: %v", r, err)
		}
	}
}

// A run is a function of its input: the same input gives the same findings and the same row,
// whatever order a map is walked in, and the output survives JSON as a report.
func TestMatchIsDeterministicAndSurvivesJSON(t *testing.T) {
	w := richWorld(ScopeFleet)
	first, firstCov, err := w.match(WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, againCov, err := w.match(WorkBudget{})
		if err != nil || !reflect.DeepEqual(first, again) || !reflect.DeepEqual(firstCov, againCov) {
			t.Fatalf("run %d differs from the first: %v", i, err)
		}
	}
	b, err := json.Marshal(reportOf(w.s, w.now, first, firstCov))
	if err != nil {
		t.Fatal(err)
	}
	var got Report
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReport(got); err != nil {
		t.Fatalf("a report from Match's output is refused after a JSON round trip: %v", err)
	}
	withReason := -1
	for i, f := range first {
		if f.Reason != "" {
			withReason = i
			break
		}
	}
	if withReason < 0 || got.Coverage[0].Counts == nil || *got.Coverage[0].Counts != *firstCov[0].Counts || got.Findings[withReason].Reason != first[withReason].Reason {
		t.Fatalf("the counts or the reason did not survive: %+v", got.Coverage)
	}
}

// A review dated after the evaluation time is not current either: the row says the catalog
// and the review are not current, and a positive warning is kept with the explanation.
func TestMatchReviewDatedAfterTheEvaluationIsStale(t *testing.T) {
	w := newWorld(ScopeLocal)
	w.daemon("1.30.0")
	w.c.IssuedAt = w.now.Add(time.Minute)
	w.rec().ReviewedAt = w.now.Add(time.Minute)
	findings, cov, err := w.match(WorkBudget{})
	if err != nil || len(findings) != 1 || findings[0].Applicability != ApplicabilityAffected || findings[0].Explanation != staleExplanation {
		t.Fatalf("%+v %v", findings, err)
	}
	for _, want := range []string{"catalog expired or not yet valid", "rules with a stale review: 1"} {
		if !strings.Contains(cov[0].Explanation, want) {
			t.Errorf("explanation %q does not say %q", cov[0].Explanation, want)
		}
	}
	requireValidReport(t, w, findings, cov)
}

// The stale-review note goes with a positive warning that is kept (affected, potentially
// affected) and with nothing else; the words of every other result are its reason's.
func TestMatchStaleNoteIsOnKeptWarningsOnly(t *testing.T) {
	stale := func(w *world) { w.rec().ReviewExpiresAt = w.now }
	for _, tc := range []struct {
		name  string
		build func(w *world)
		stale func(w *world)
		want  string
	}{
		{"affected, fresh", func(w *world) { w.daemon("1.30.0") }, nil, plainExplanation},
		{"affected, stale", func(w *world) { w.daemon("1.30.0") }, stale, staleExplanation},
		{"not affected, fresh", func(w *world) { w.daemon("1.32.3") }, nil, plainExplanation},
		{"potentially affected, fresh", func(w *world) { w.api("1.30.0") }, nil, reasonText[ReasonRuntimeUnobserved]},
		{"potentially affected, stale", func(w *world) { w.api("1.30.0") }, stale, reasonText[ReasonRuntimeUnobserved] + " " + staleExplanation},
		{"unknown, fresh", func(w *world) { w.api("1.32.3") }, nil, reasonText[ReasonRuntimeUnobserved]},
		{"unknown, stale", func(w *world) { w.api("1.32.3") }, stale, reasonText[ReasonRuntimeUnobserved]},
		{"cleared before, stale", func(w *world) { w.daemon("1.32.3") }, stale, reasonText[ReasonReviewExpired]},
		{"no version, stale", func(w *world) { w.os("linux") }, stale, reasonText[ReasonNoVersion]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(ScopeLocal)
			tc.build(w)
			if tc.stale != nil {
				tc.stale(w)
			}
			findings, _, err := w.match(WorkBudget{})
			if err != nil || len(findings) != 1 || findings[0].Explanation != tc.want {
				t.Fatalf("%+v %v, want %q", findings, err, tc.want)
			}
		})
	}
}

// A rule that asks nothing of the platform or the features does not read them: the cost of
// a run is the facts a rule needs and not all the facts there are.
func TestMatchDoesNotReadFactsARuleDoesNotAskFor(t *testing.T) {
	w := newWorld(ScopeLocal)
	w.daemon("1.30.0")
	for i := 0; i < 1000; i++ {
		w.os("linux")
		w.feat(fmt.Sprintf("feature-%d", i), true)
	}
	// Indexing the 2,001 facts, the pair, the version fact and the range: a few steps over 2,001.
	findings, cov, err := w.match(WorkBudget{Candidates: 2100})
	if err != nil || len(findings) != 1 || findings[0].Applicability != ApplicabilityAffected {
		t.Fatalf("%+v %v", findings, err)
	}
	requireValidReport(t, w, findings, cov)
}
