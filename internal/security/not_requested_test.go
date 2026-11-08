package security

import (
	"strings"
	"testing"
)

// A coverage row can say that a target was not requested. The status is valid only for a
// target the report did not request, needs an explanation and a source, carries no counts,
// and is never the status of a report.

var rulesIntentTarget = CoverageTarget{Dimension: CoverageIntent, Scope: ScopeLocal}

func notRequestedRow() Coverage {
	return Coverage{Target: rulesIntentTarget, Context: rulesCtx, Source: "intent evaluation", Status: CoverageNotRequested,
		Explanation: "intent not requested: no intent set is configured"}
}

// completeWithIntentNotRequested is a complete report whose requested target is complete and
// that names the intent as not requested.
func completeWithIntentNotRequested() Report {
	r := rulesComplete()
	r.Coverage = append(r.Coverage, notRequestedRow())
	return r
}

func TestAReportCanBeCompleteBesideARowForATargetItDidNotRequest(t *testing.T) {
	r := completeWithIntentNotRequested()
	if err := ValidateReport(r); err != nil {
		t.Fatalf("a complete report with a not_requested row for an unrequested target: %v", err)
	}
	// The same row beside a partial report is as valid.
	p := rulesPartial()
	p.Coverage = append(p.Coverage, notRequestedRow())
	if err := ValidateReport(p); err != nil {
		t.Errorf("a partial report: %v", err)
	}
}

func TestNotRequestedIsRefusedWhereItWouldHideARequestedTarget(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(r *Report)
		want string
	}{
		"the target is requested": {func(r *Report) { r.RequestedCoverage = append(r.RequestedCoverage, rulesIntentTarget) },
			"not-requested coverage names a requested target"},
		"the target is requested and the report is partial": {func(r *Report) {
			r.Status = ReportPartial
			r.RequestedCoverage = append(r.RequestedCoverage, rulesIntentTarget)
		}, "not-requested coverage names a requested target"},
		"no explanation":                     {func(r *Report) { r.Coverage[len(r.Coverage)-1].Explanation = "" }, "not-requested coverage has no explanation"},
		"no source":                          {func(r *Report) { r.Coverage[len(r.Coverage)-1].Source = "" }, "not-requested coverage has no source"},
		"counts":                             {func(r *Report) { r.Coverage[len(r.Coverage)-1].Counts = &CoverageCounts{} }, "not-requested coverage carries counts"},
		"another context":                    {func(r *Report) { r.Coverage[len(r.Coverage)-1].Context = "elsewhere" }, "coverage context does not match the report"},
		"a report whose status is the row's": {func(r *Report) { r.Status = CoverageNotRequested }, "invalid report status"},
	} {
		t.Run(name, func(t *testing.T) {
			r := completeWithIntentNotRequested()
			tc.edit(&r)
			err := ValidateReport(r)
			if err == nil || err.Error() != tc.want {
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}
}

// A requested target is answered by a complete row for a complete report: a not_requested row
// is not an answer, whatever it is called.
func TestANotRequestedRowDoesNotAnswerARequestedTarget(t *testing.T) {
	r := rulesComplete()
	r.RequestedCoverage = append(r.RequestedCoverage, rulesIntentTarget)
	r.Coverage = append(r.Coverage, notRequestedRow())
	if err := ValidateReport(r); err == nil {
		t.Fatal("a complete report whose requested target has only a not_requested row")
	}
	// And no other status is let in by the new one.
	r = completeWithIntentNotRequested()
	r.Coverage[len(r.Coverage)-1].Status = "skipped"
	if err := ValidateReport(r); err == nil || !strings.Contains(err.Error(), "invalid coverage status") {
		t.Errorf("an unknown status: %v", err)
	}
}
