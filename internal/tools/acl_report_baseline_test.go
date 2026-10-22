package tools_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// The warnings the live policy already has are a baseline and not news: the report lists
// them as notices of the live policy, marked as existing, after the new warnings and the
// other notices, so that no layout shows them as a warning of the proposal's file, and a
// GitHub step does not spend its ten warning annotations on them.
func TestTheLivePolicysOwnWarningsAreNoticesInTheReport(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, []string{`old: host alias "old" is unused`}, nil)
	f.ServeValidate(apitest.TestsWarned(
		apitest.Entry{User: "old", Warnings: []string{`host alias "old" is unused`}},
		apitest.Entry{User: "newer", Warnings: []string{`host alias "newer" is unused`}},
	))
	out := validateOnline(t, env, `{"policy":`+jsonString(liveText+"// a comment\n")+`}`)
	if len(out.NewWarnings) != 1 || len(out.ExistingWarnings) != 1 {
		t.Fatalf("new %+v, existing %+v; want one of each", out.NewWarnings, out.ExistingWarnings)
	}
	var existing, fresh []registry.Finding
	for _, fi := range out.Report().Findings {
		switch {
		case strings.HasPrefix(fi.Message, "existing: "):
			existing = append(existing, fi)
		case fi.Severity == "warning":
			fresh = append(fresh, fi)
		}
	}
	if len(existing) != 1 || existing[0].Severity != "notice" || existing[0].Source != "live" || !existing[0].Untrusted ||
		existing[0].Message != `existing: old: host alias "old" is unused` {
		t.Errorf("the existing warning in the report: %+v", existing)
	}
	if len(fresh) != 1 || fresh[0].Source != "from" || fresh[0].Message != `newer: host alias "newer" is unused` {
		t.Errorf("the new warning in the report: %+v", fresh)
	}
	// The existing warnings come last of the findings that are problems, as the cap keeps them.
	fs := out.Report().Findings
	if !strings.HasPrefix(fs[len(fs)-1].Message, "existing: ") {
		t.Errorf("the findings end with %+v, want the existing warning", fs[len(fs)-1])
	}
}

// What the caps left out is said in the report, with the new warnings among it, which a
// gate counts: a list that was cut must not read as complete.
func TestTheReportSaysHowManyProblemsAreNotListed(t *testing.T) {
	var entries []apitest.Entry
	for i := range 70 {
		entries = append(entries, apitest.Entry{User: fmt.Sprintf("tag:w%02d", i), Warnings: []string{"tag owns nothing"}})
	}
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsWarned(entries...))
	out := validateOnline(t, env, `{"policy":`+jsonString(liveText+"// a comment\n")+`}`)
	if out.Omitted != 6 || out.NewWarningsOmitted != 6 {
		t.Fatalf("omitted %d, of them new warnings %d; want 6 and 6", out.Omitted, out.NewWarningsOmitted)
	}
	var said []string
	for _, fi := range out.Report().Findings {
		if strings.Contains(fi.Message, "not listed") {
			said = append(said, fi.Message)
		}
	}
	if len(said) != 1 || said[0] != "6 problems are not listed (6 of them new warnings, which --fail-on warnings counts)" {
		t.Errorf("the report says %q", said)
	}
	// One problem left out is said in the singular, and a count of new warnings is only there
	// when some of them were left out.
	if got := (tools.ACLValidateOutput{Omitted: 1}).Report().Findings; len(got) != 1 || got[0].Message != "1 problem is not listed" {
		t.Errorf("one problem left out: %+v", got)
	}
	// A result that left nothing out says nothing of the kind.
	f2, _, env2 := apiEnv(t)
	serveLive(f2, liveText, nil, nil)
	f2.ServeValidate(apitest.TestsPassEmptyObject())
	whole := validateOnline(t, env2, `{}`)
	for _, fi := range whole.Report().Findings {
		if strings.Contains(fi.Message, "not listed") {
			t.Errorf("a whole result says %q", fi.Message)
		}
	}
}
