package tools_test

import (
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// --fail-on change counts the entries that changed, not the sum of the classes: a widening is
// a finding about a rule that changed, listed beside it, so one widened rule is one change and
// not two. A count is never 0 while any class has one, so the gate cannot fall silent.
func TestFailOnChangeCountsChangedEntriesNotOverlappingClasses(t *testing.T) {
	out := twoFiles(t, `{"acls": [{"action": "accept", "src": ["tag:a"], "dst": ["tag:x:22"]}]}`, `{"acls": [{"action": "accept", "src": ["*"], "dst": ["tag:x:22"]}]}`)
	if c := out.Counts; c.Widening != 1 || c.Semantic != 1 {
		t.Fatalf("counts = %+v: the edit should be one widening finding beside one changed rule", c)
	}
	if got := out.Findings(); got.Changes != 1 || got.Widenings != 1 {
		t.Errorf("acl_diff findings = %+v, want one change and one widening", got)
	}
	f, _, env := apiEnv(t)
	serveLive(f, `{"acls": [{"action": "accept", "src": ["tag:a"], "dst": ["tag:x:22"]}]}`+"\n", nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	v, err := runValidate(t, env, func(in *tools.ACLValidateInput) {
		in.Policy = `{"acls": [{"action": "accept", "src": ["*"], "dst": ["tag:x:22"]}]}`
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Findings(); got.Changes != 1 || got.Widenings != 1 {
		t.Errorf("acl_validate findings = %+v, want one change and one widening", got)
	}
	for _, c := range []struct {
		counts  tools.ACLChangeCounts
		ignored bool
		want    int
	}{
		{tools.ACLChangeCounts{Widening: 1}, false, 1},
		{tools.ACLChangeCounts{Widening: 2, Semantic: 1}, false, 2},
		{tools.ACLChangeCounts{Widening: 1, Semantic: 3}, false, 3},
		{tools.ACLChangeCounts{Defaults: 1, TestsReduced: 1, Widening: 1, Semantic: 1, TailscaleWritten: 1}, false, 4},
		{tools.ACLChangeCounts{Defaults: 1, TailscaleWritten: 2}, true, 1},
		{tools.ACLChangeCounts{}, false, 0},
	} {
		if got := (tools.ACLDiffOutput{Counts: c.counts, TailscaleWrittenIgnored: c.ignored}).Findings().Changes; got != c.want {
			t.Errorf("%+v (written ignored %v): %d changes, want %d", c.counts, c.ignored, got, c.want)
		}
	}
}

// A new warning the lists do not show still counts for --fail-on warnings, and the first line
// says so whatever the status: a failed test, a rejection or an unknown answer does not hide
// that the text also adds warnings.
func TestTheVerdictNamesNewWarningsThatAreNotListedWhateverTheStatus(t *testing.T) {
	for _, status := range []string{"fail", "rejected", "unresolved", "invalid", "unknown"} {
		v := (tools.ACLValidateOutput{Status: status, NewWarningsOmitted: 3}).Report().Verdict
		if !strings.HasSuffix(v, " · 3 new warnings not listed") {
			t.Errorf("%s: verdict = %q", status, v)
		}
		if v := (tools.ACLValidateOutput{Status: status}).Report().Verdict; strings.Contains(v, "not listed") {
			t.Errorf("%s: verdict = %q names warnings when none was cut", status, v)
		}
	}
	// A pass counts them with the listed ones, as it did.
	pass := (tools.ACLValidateOutput{Status: "pass", ServerChecked: true, NewWarningsOmitted: 3}).Report().Verdict
	if !strings.HasPrefix(pass, "VALID · 3 new warnings (0 existing)") || strings.Contains(pass, "not listed") {
		t.Errorf("pass: verdict = %q", pass)
	}
}
