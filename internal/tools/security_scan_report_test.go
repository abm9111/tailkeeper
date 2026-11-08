package tools_test

import (
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// The scan's Report is the one layout every --format renders. It says what the result says: the
// verdict has the status and the counts, a fact for each thing the result states, and a line for
// each listed finding, with a severity a layout can show.

func TestSecurityScanReportLevelFollowsTheExitCode(t *testing.T) {
	for name, c := range map[string]struct {
		out   tools.SecurityScanOutput
		level registry.Level
		exit  int
	}{
		"complete, nothing at the threshold": {tools.SecurityScanOutput{Status: "complete"}, registry.LevelOK, 0},
		"partial, nothing at the threshold":  {tools.SecurityScanOutput{Status: "partial"}, registry.LevelWarn, 1},
		"a finding, partial":                 {tools.SecurityScanOutput{Status: "partial", AtThreshold: tools.SecurityScanThreshold{Affected: 1}}, registry.LevelFail, 8},
		"a finding, complete":                {tools.SecurityScanOutput{Status: "complete", AtThreshold: tools.SecurityScanThreshold{PotentiallyAffected: 2}}, registry.LevelFail, 8},
		"no status":                          {tools.SecurityScanOutput{}, registry.LevelWarn, 1},
	} {
		if got := c.out.ExitCode(); got != c.exit {
			t.Errorf("%s: exit %d, want %d", name, got, c.exit)
		}
		if got := c.out.Report().Level; got != c.level {
			t.Errorf("%s: level %q, want %q", name, got, c.level)
		}
	}
}

func TestSecurityScanReportSeveritiesAndLines(t *testing.T) {
	findings := []tools.SecurityScanFinding{
		{Rule: "R-1", Device: "nAAA…", DeviceRef: "p:abcdefghij", Applicability: "affected", Severity: "high", Explanation: "It is affected.", Verification: []string{"Update.", "Restart."}},
		{Rule: "R-2", Device: "nBBB…", Applicability: "potentially_affected", Severity: "low", Reason: "device_offline", Explanation: "Maybe."},
		{Rule: "R-3", Device: "nCCC…", Applicability: "unknown", Severity: "unknown", Reason: "review_pending", Explanation: "Pending."},
		{Rule: "R-4", Device: "nDDD…", Applicability: "not_affected", Severity: "low", Explanation: "Cleared."},
		{Rule: "R-5", Device: "nEEE…", Applicability: "something new", Severity: "low", Explanation: "Not known to this version."},
	}
	rep := tools.SecurityScanOutput{Status: "partial", Findings: findings}.Report()
	wantSeverity := []string{"error", "warning", "notice", "notice", "notice"}
	wantLine := []string{
		"R-1 · nAAA… p:abcdefghij · affected · severity high · It is affected. · verify: Update.; Restart.",
		"R-2 · nBBB… · potentially_affected · severity low · reason device_offline · Maybe.",
		"R-3 · nCCC… · unknown · severity unknown · reason review_pending · Pending.",
		"R-4 · nDDD… · not_affected · severity low · Cleared.",
		"R-5 · nEEE… · something new · severity low · Not known to this version.",
	}
	if len(rep.Findings) != len(findings) {
		t.Fatalf("%d finding lines for %d findings", len(rep.Findings), len(findings))
	}
	for i, f := range rep.Findings {
		if f.Severity != wantSeverity[i] || f.Message != wantLine[i] || f.Untrusted || f.Source != "" || f.Pointer != "" {
			t.Errorf("finding %d: %+v, want severity %s and %q", i, f, wantSeverity[i], wantLine[i])
		}
	}
}

// The details and the report say the same: the verdict is the first line, and each fact is a
// line of its own, label then text.
func TestSecurityScanDetailsAreTheVerdictThenTheFacts(t *testing.T) {
	at := scanClock(t)
	r := scanRig(t, at)
	r.devices(scanDev(at, "nOLD01CNTRL", "1.28.2-t0123456ab", nil), scanDev(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil))
	out := r.scan(t, `{"scope":"fleet"}`)
	rep := out.Report()
	lines := out.Details()
	if len(lines) != len(rep.Facts)+1 || lines[0] != rep.Verdict {
		t.Fatalf("%d lines for a verdict and %d facts; first %q, verdict %q", len(lines), len(rep.Facts), lines[0], rep.Verdict)
	}
	for i, f := range rep.Facts {
		if lines[i+1] != f.Label+": "+f.Text {
			t.Errorf("line %d: %q, want %q", i+1, lines[i+1], f.Label+": "+f.Text)
		}
	}
	for _, want := range []string{"fleet scan: partial; 1 affected", "10 findings, 10 listed"} {
		if !strings.Contains(rep.Verdict, want) {
			t.Errorf("the verdict lacks %q: %q", want, rep.Verdict)
		}
	}
	if len(rep.Findings) != len(out.Findings) || len(rep.NotChecked)+len(rep.Classes) != 0 {
		t.Errorf("%d finding lines for %d findings; not checked %v, classes %v", len(rep.Findings), len(out.Findings), rep.NotChecked, rep.Classes)
	}
}
