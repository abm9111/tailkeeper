package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// The two policies of the class tests: moving from a to b changes the defaults (acls and
// nodeAttrs appear), reduces a test, widens two rules, adds the Funnel attribute that
// Tailscale writes itself, and changes groups.
const (
	diffA = `{"tests": [{"src": "a", "accept": ["x:1"]}], "groups": {"group:g": []}, "ssh": [{"action": "check", "src": ["g"], "dst": ["t"], "users": ["u"]}]}`
	diffB = `{"acls": [{"action": "accept", "src": ["*"], "dst": ["x:1"]}], "groups": {"group:g": ["m"]}, "nodeAttrs": [{"target": ["a"], "attr": ["funnel"]}], "ssh": [{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["u"]}]}`
)

// runDiff runs acl_diff on an input the test fills in. The switches that exist on the
// command line only (offline, the operator mark) cannot be sent as MCP arguments, so the
// test sets them on the prepared input, as the command line's binder does. The result is
// the tool's own, before the registry masks it.
func runDiff(t *testing.T, env *registry.Env, set func(*tools.ACLDiffInput)) (tools.ACLDiffOutput, error) {
	t.Helper()
	tool, ok := newRegistry(t).Get("acl_diff")
	if !ok {
		t.Fatal("acl_diff is not registered")
	}
	p, err := tool.Validate(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	set(p.Input().(*tools.ACLDiffInput))
	out, err := p.Run(context.Background(), env)
	if err != nil {
		return tools.ACLDiffOutput{}, err
	}
	return out.(tools.ACLDiffOutput), nil
}

// diffOnline calls acl_diff over MCP with the given arguments, through the registry.
func diffOnline(t *testing.T, env *registry.Env, args string) tools.ACLDiffOutput {
	t.Helper()
	var out tools.ACLDiffOutput
	mustCall(t, newRegistry(t), env, "acl_diff", args, &out)
	return out
}

// twoFiles compares two texts as an operator would with `acl diff OLD NEW`: no credential,
// no request.
func twoFiles(t *testing.T, a, b string, more ...func(*tools.ACLDiffInput)) tools.ACLDiffOutput {
	t.Helper()
	out, err := runDiff(t, &registry.Env{Now: func() time.Time { return now }}, func(in *tools.ACLDiffInput) {
		in.Against, in.Policy, in.Operator = a, b, true
		for _, m := range more {
			m(in)
		}
	})
	if err != nil {
		t.Fatalf("diff of two files: %v", err)
	}
	return out
}

func gets(f *apitest.Fake) (n int, others []string) {
	for _, r := range f.Requests() {
		if r.Method == "GET" {
			n++
		} else {
			others = append(others, r.Method+" "+r.Path)
		}
	}
	return n, others
}

// Two files need no credential and no request, and the result says where each side is from.
func TestDiffOfTwoFilesNeedsNoCredentialOrFetch(t *testing.T) {
	out := twoFiles(t, diffA, diffB)
	if out.Status != "changed" || out.ExitCode() != 0 || out.SemanticallyEqual || out.Old.Source != "file" || out.New.Source != "file" {
		t.Fatalf("result = %+v", out)
	}
	if out.ExternallyManaged != "" || out.Old.PolicyVersion != "" || out.New.PolicyVersion != "" || out.Old.PolicySHA256 == "" || out.New.PolicySHA256 == "" {
		t.Errorf("no side is live, so nothing is said of who manages it: %+v", out)
	}
	if out.CheckedAt == "" || out.TailscaleWrittenAsOf == "" || len(out.NotChecked) == 0 {
		t.Errorf("checkedAt %q, as of %q, notChecked %v", out.CheckedAt, out.TailscaleWrittenAsOf, out.NotChecked)
	}
	// The same call through MCP, with no credential at all, works the same for two texts.
	mcp := diffOnline(t, &registry.Env{Now: func() time.Time { return now }}, `{"against":`+jsonString(diffA)+`,"policy":`+jsonString(diffB)+`}`)
	if mcp.Status != "changed" || mcp.Old.Source != "text" || mcp.New.Source != "text" {
		t.Errorf("over MCP: %+v", mcp)
	}
}

// The classes are counted over every change and listed in order: defaults, tests reduced and
// widenings first, the Tailscale-written ones, then the rest.
func TestTheClassesAreCountedAndListedInOrder(t *testing.T) {
	out := twoFiles(t, diffA, diffB)
	c := out.Counts
	if c.Defaults != 1 || c.TestsReduced != 1 || c.Widening != 2 || c.TailscaleWritten != 1 || c.Semantic < 3 {
		t.Fatalf("counts = %+v", c)
	}
	order := map[string]int{"defaults": 0, "testsReduced": 1, "widening": 2, "tailscaleWritten": 3, "semantic": 4}
	last := -1
	for _, ch := range out.Changes {
		if order[ch.Class] < last {
			t.Errorf("class %s listed after a later class", ch.Class)
		}
		last = order[ch.Class]
	}
	if out.Matched != len(out.Changes) || out.Truncated || out.NextChange != "" {
		t.Errorf("matched %d, listed %d, truncated %v, next %q", out.Matched, len(out.Changes), out.Truncated, out.NextChange)
	}
	f := out.Findings()
	if f.TestsReduced != 1 || f.Defaults != 1 || f.Widenings != 2 || f.Changes != c.Defaults+c.TestsReduced+max(c.Widening, c.Semantic)+c.TailscaleWritten || f.NewWarnings != 0 {
		t.Errorf("findings = %+v", f)
	}
	// Ignoring the Tailscale-written changes leaves them out of the list and out of the gate,
	// and still counts them.
	ig := twoFiles(t, diffA, diffB, func(in *tools.ACLDiffInput) { in.IgnoreTailscaleWritten = true })
	if ig.Counts.TailscaleWritten != 1 || !ig.TailscaleWrittenIgnored || ig.Findings().Changes != f.Changes-1 {
		t.Errorf("ignoring: counts %+v, ignored %v, findings %+v", ig.Counts, ig.TailscaleWrittenIgnored, ig.Findings())
	}
	for _, ch := range ig.Changes {
		if ch.Class == "tailscaleWritten" {
			t.Errorf("a Tailscale-written change is listed: %+v", ch)
		}
	}
}

// A rewrite that means the same is equal; a comment and a layout are counts only; a
// Tailscale-written change alone is equal only when asked to be ignored.
func TestARewriteThatMeansTheSameIsEqual(t *testing.T) {
	a := `{"groups": {"group:g": ["m@example.com"]}, "acls": [{"action": "accept", "src": ["group:g"], "dst": ["tag:x:80"]}]}`
	b := "// the same\n{\n  \"acls\": [{\"action\": \"accept\", \"src\": [\"group:g\"], \"dst\": [\"tag:x:80\"]}],\n  \"groups\": {\"group:g\": [\"m@example.com\"]},\n}\n"
	out := twoFiles(t, a, b)
	if out.Status != "equal" || !out.SemanticallyEqual || out.ExitCode() != 0 || len(out.Changes) != 0 || out.Counts.CommentOnly+out.Counts.FormatOnly == 0 {
		t.Fatalf("result = %+v", out)
	}
	funnel := `{"nodeAttrs": [{"target": ["autogroup:member"], "attr": ["funnel"]}]}`
	if out := twoFiles(t, "{}", funnel); out.Status != "changed" || out.SemanticallyEqual || out.Counts.TailscaleWritten != 1 {
		t.Errorf("a Tailscale-written change: %+v", out)
	}
	ig := twoFiles(t, "{}", funnel, func(in *tools.ACLDiffInput) { in.IgnoreTailscaleWritten = true })
	if ig.Status != "equal" || ig.SemanticallyEqual || ig.Counts.TailscaleWritten != 1 || ig.Findings().Changes != 0 {
		t.Errorf("ignored: %+v", ig)
	}
}

// Both sides live is refused with no request; so is a policy together with a patch.
func TestBothSidesLiveIsRefused(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	_, err := runDiff(t, env, func(in *tools.ACLDiffInput) {})
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidationFailed || !strings.Contains(e.Message, "both sides would be the live policy") {
		t.Errorf("err = %v", err)
	}
	if len(f.Requests()) != 0 {
		t.Errorf("%d requests were made for a call with nothing to compare", len(f.Requests()))
	}
	// The same call over MCP.
	if _, err := call(t, newRegistry(t), env, "acl_diff", `{}`); err == nil || !strings.Contains(err.Error(), "both sides would be the live policy") {
		t.Errorf("over MCP: %v", err)
	}
	if _, err := call(t, newRegistry(t), env, "acl_diff", `{"policy":"{}","patch":"[]"}`); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("a policy and a patch: %v", err)
	}
}

// --offline compares two files and nothing else: a live side is refused, and so is a patch.
func TestOfflineRefusesALiveSide(t *testing.T) {
	env := &registry.Env{Now: func() time.Time { return now }}
	for name, set := range map[string]func(*tools.ACLDiffInput){
		"no old side":  func(in *tools.ACLDiffInput) { in.Policy = "{}" },
		"no new side":  func(in *tools.ACLDiffInput) { in.Against = "{}" },
		"a patch":      func(in *tools.ACLDiffInput) { in.Against, in.Patch = "{}", "[]" },
		"only a patch": func(in *tools.ACLDiffInput) { in.Patch = "[]" },
	} {
		_, err := runDiff(t, env, func(in *tools.ACLDiffInput) { set(in); in.Offline, in.Operator = true, true })
		if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidationFailed {
			t.Errorf("%s: err = %v, want validation_failed", name, err)
		}
	}
	if _, err := runDiff(t, env, func(in *tools.ACLDiffInput) { in.Against, in.Policy, in.Offline, in.Operator = "{}", "{}", true, true }); err != nil {
		t.Errorf("two files offline: %v", err)
	}
}

// With one side given, the other is the live policy, on the side that was left out.
func TestDiffAgainstLiveDirections(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	const without = `{"tagOwners": {"tag:ci": ["autogroup:admin"]}}`
	// --against FILE alone: the old side is the file, the live policy is new, so the rule the
	// live policy has is added.
	out, err := runDiff(t, env, func(in *tools.ACLDiffInput) { in.Against, in.Operator = without, true })
	if err != nil || out.Old.Source != "file" || out.New.Source != "live" || out.New.PolicyVersion != "" || out.New.PolicySHA256 == "" {
		t.Fatalf("against alone: %v, %+v", err, out)
	}
	if out.ExternallyManaged != "true" || out.ExternalLink != "https://git.example.com/policy" {
		t.Errorf("who manages the policy: %q %q", out.ExternallyManaged, out.ExternalLink)
	}
	if ops := changeOps(out); ops["added"] == 0 || ops["removed"] != 0 {
		t.Errorf("against alone: changes %v, want only additions", ops)
	}
	// --from FILE alone: the live policy is old, the rule is removed.
	out, err = runDiff(t, env, func(in *tools.ACLDiffInput) { in.Policy, in.Operator = without, true })
	if err != nil || out.Old.Source != "live" || out.New.Source != "file" {
		t.Fatalf("policy alone: %v, %+v", err, out)
	}
	if ops := changeOps(out); ops["removed"] == 0 || ops["added"] != 0 {
		t.Errorf("policy alone: changes %v, want only removals", ops)
	}
	// The live policy against itself, written out in full, is equal.
	out, err = runDiff(t, env, func(in *tools.ACLDiffInput) { in.Against, in.Operator = liveText, true })
	if err != nil || out.Status != "equal" || !out.SemanticallyEqual {
		t.Errorf("the live policy against itself: %v, %+v", err, out)
	}
}

func changeOps(o tools.ACLDiffOutput) map[string]int {
	ops := map[string]int{}
	for _, c := range o.Changes {
		ops[c.Op]++
	}
	return ops
}

// A patch is applied to the live policy: old is the live policy, new is the patched one; the
// patch side records the live version it was made from and never a line.
func TestAPatchIsComparedWithTheLivePolicy(t *testing.T) {
	f, _, env := apiEnv(t)
	kenv, _ := keyed(t, env)
	serveLive(f, liveText, nil, nil)
	out := diffOnline(t, kenv, `{"patch":`+jsonString(`[{"op":"add","path":"/hosts","value":{"edge":"192.0.2.9"}}]`)+`}`)
	if out.Status != "changed" || out.Old.Source != "live" || out.New.Source != "patch" || out.Old.PolicyVersion == "" || out.New.PolicyVersion != out.Old.PolicyVersion {
		t.Fatalf("result = %+v", out)
	}
	if out.New.PolicySHA256 == out.Old.PolicySHA256 || out.Counts.Semantic != 1 {
		t.Errorf("the patched side has the live policy's digest, or counts %+v", out.Counts)
	}
	for _, c := range out.Changes {
		if c.NewLine != 0 {
			t.Errorf("a change in the patched policy carries a line: %+v", c)
		}
	}
	// A patch that does not apply is an invalid new side, with its place, and nothing is compared.
	bad := diffOnline(t, kenv, `{"patch":`+jsonString(`[{"op":"remove","path":"/nothing"}]`)+`}`)
	if bad.Status != "invalid" || bad.ExitCode() != 2 || len(bad.New.Findings) != 1 || bad.New.Findings[0].Source != "patch" || len(bad.Changes) != 0 {
		t.Errorf("a patch that does not apply: %+v", bad)
	}
}

// acl_diff reads and never writes: every request of every call of the tests above is a GET.
func TestACLDiffNeverPosts(t *testing.T) {
	f, _, env := apiEnv(t)
	kenv, _ := keyed(t, env)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	for _, args := range []string{`{"against":"{}"}`, `{"policy":"{}"}`, `{"patch":"[]"}`, `{"against":"{}","policy":"{}"}`} {
		diffOnline(t, kenv, args)
	}
	if n, others := gets(f); n == 0 || len(others) != 0 {
		t.Errorf("%d GETs, and other requests %v", n, others)
	}
}

// A side that is not a policy is a typed invalid result: which side, the finding with its
// place, exit 2, and nothing is read from Tailscale or compared.
func TestAnInvalidSideIsATypedInvalidResult(t *testing.T) {
	out := twoFiles(t, "{\n  \"acls\": [\n    {,}\n  ]\n}", "{}")
	if out.Status != "invalid" || out.ExitCode() != 2 || len(out.Old.Findings) != 1 || len(out.New.Findings) != 0 || len(out.Changes) != 0 {
		t.Fatalf("result = %+v", out)
	}
	if p := out.Old.Findings[0]; p.Kind != "syntax" || p.Source != "against" || p.Line != 3 || p.Column == 0 || p.Severity != "error" {
		t.Errorf("finding = %+v", p)
	}
	out = twoFiles(t, "{}", "\xef\xbb\xbf{}")
	if out.Status != "invalid" || len(out.New.Findings) != 1 || out.New.Findings[0].Kind != "encoding" || out.New.Findings[0].Source != "from" {
		t.Errorf("a byte order mark in the new side: %+v", out)
	}
	out = twoFiles(t, `{"groups": {"group:a": [], "group:a": []}}`, "{}")
	if out.Status != "invalid" || out.Old.Findings[0].Kind != "duplicate_key" {
		t.Errorf("a key written twice: %+v", out)
	}
	// A live policy this version cannot read is an invalid side as well.
	f, _, lenv := apiEnv(t)
	serveLive(f, "[1]", nil, nil)
	live, err := runDiff(t, lenv, func(in *tools.ACLDiffInput) { in.Against, in.Operator = "{}", true })
	if err != nil || live.Status != "invalid" || len(live.New.Findings) != 1 || live.New.Findings[0].Source != "live" ||
		!strings.Contains(live.New.Findings[0].Message, "cannot read the live policy") {
		t.Errorf("an unreadable live policy: %v, %+v", err, live)
	}
}

// manyChanges is a pair of policies that differ by 121 changes: 120 groups added, and one
// host.
func manyChanges() (older, newer string) {
	var b strings.Builder
	b.WriteString(`{"groups": {`)
	for i := range 120 {
		sep := ","
		if i == 119 {
			sep = ""
		}
		fmt.Fprintf(&b, `"group:g%03d": ["m%03d@example.com"]%s`, i, i, sep)
	}
	b.WriteString(`}, "hosts": {"edge": "192.0.2.9"}}`)
	return `{"hosts": {}}`, b.String()
}

// 120 changes: the page holds 50, the cursor continues, the section filter narrows, and the
// counts and the gate cover every change whatever the page shows.
func TestSectionFilterAndCursorPaginateAndTheGateSeesEverything(t *testing.T) {
	a, b := manyChanges()
	first := twoFiles(t, a, b)
	if first.Counts.Semantic != 121 || first.Matched != 121 || !first.Truncated || first.NextChange == "" || len(first.Changes) != 50 {
		t.Fatalf("first page: counts %+v, matched %d, truncated %v, listed %d", first.Counts, first.Matched, first.Truncated, len(first.Changes))
	}
	if first.Findings().Changes != 121 {
		t.Errorf("the gate sees %d changes, want all 121", first.Findings().Changes)
	}
	next := twoFiles(t, a, b, func(in *tools.ACLDiffInput) { in.FromChange = first.NextChange })
	if len(next.Changes) != 50 || !next.Truncated || next.Findings().Changes != 121 || next.Changes[0].Entry == first.Changes[0].Entry {
		t.Errorf("second page: listed %d, truncated %v, findings %+v", len(next.Changes), next.Truncated, next.Findings())
	}
	last := twoFiles(t, a, b, func(in *tools.ACLDiffInput) { in.FromChange = next.NextChange })
	if len(last.Changes) != 21 || last.Truncated || last.NextChange != "" {
		t.Errorf("last page: listed %d, truncated %v, next %q", len(last.Changes), last.Truncated, last.NextChange)
	}
	only := twoFiles(t, a, b, func(in *tools.ACLDiffInput) { in.Section = "HOSTS" })
	if only.Matched != 1 || len(only.Changes) != 1 || only.Changes[0].Section != "hosts" || only.Counts.Semantic != 121 || only.Findings().Changes != 121 {
		t.Errorf("section hosts: matched %d, listed %d, counts %+v", only.Matched, len(only.Changes), only.Counts)
	}
	// A cursor of another pair of policies is refused, not read as a place in this one.
	env := &registry.Env{Now: func() time.Time { return now }}
	_, err := runDiff(t, env, func(in *tools.ACLDiffInput) {
		in.Against, in.Policy, in.Operator, in.FromChange = "{}", `{"hosts": {"a": "192.0.2.1"}}`, true, first.NextChange
	})
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidationFailed {
		t.Errorf("a cursor of another pair: %v", err)
	}
}

// The status is the engine's verdict on the whole normal forms and never a reading of the
// page: a section that selects nothing lists nothing, and so does a cursor that lands past the
// last change, and in both the two policies still differ. The status stays changed, the
// counts stay whole, and the layout says that the filter selected nothing, so that an empty
// list is not read as "no change".
func TestAnEmptyPageIsNotAnEqualDiff(t *testing.T) {
	a, b := manyChanges()
	none := twoFiles(t, a, b, func(in *tools.ACLDiffInput) { in.Section = "TagOwners" })
	if none.Status != "changed" || none.SemanticallyEqual || none.Matched != 0 || len(none.Changes) != 0 || none.Truncated || none.Section != "tagOwners" ||
		none.Counts.Semantic != 121 || none.Findings().Changes != 121 {
		t.Fatalf("a section that selects nothing: %+v", none)
	}
	selects := false
	for _, f := range none.Report().Findings {
		selects = selects || f.Severity == "notice" && strings.Contains(f.Message, `the section filter "tagOwners" selects none of the changes of this comparison`)
	}
	if !selects {
		t.Errorf("the layout does not say that the filter selected nothing: %+v", none.Report().Findings)
	}
	// A filter that selects some of the changes, or that sits on equal policies, says nothing.
	for name, out := range map[string]tools.ACLDiffOutput{
		"a section with a match": twoFiles(t, a, b, func(in *tools.ACLDiffInput) { in.Section = "hosts" }),
		"equal policies":         twoFiles(t, "{}", "{}", func(in *tools.ACLDiffInput) { in.Section = "groups" }),
	} {
		for _, f := range out.Report().Findings {
			if strings.Contains(f.Message, "selects none") {
				t.Errorf("%s: %q", name, f.Message)
			}
		}
	}
	// A cursor is "c1.<position>.<digest>", and the engine accepts a position up to the number
	// of changes selected: the cursor of the first page, moved to the end, lists nothing.
	first := twoFiles(t, a, b)
	parts := strings.SplitN(first.NextChange, ".", 3)
	if len(parts) != 3 || parts[0] != "c1" {
		t.Fatalf("the cursor %q has a shape this test does not know", first.NextChange)
	}
	parts[1] = "121"
	end := twoFiles(t, a, b, func(in *tools.ACLDiffInput) { in.FromChange = strings.Join(parts, ".") })
	if end.Status != "changed" || end.SemanticallyEqual || len(end.Changes) != 0 || end.Matched != 121 || end.Truncated || end.NextChange != "" || end.Counts.Semantic != 121 {
		t.Errorf("a cursor past the last change: %+v", end)
	}
}

// A side lists at most 64 findings and counts the rest in omitted, whichever way the findings
// come: a key written twice (the engine itself lists 100 of them) or a section this version
// does not know. A text may hold as many as the engine accepts, and the result is bounded by
// this cap and not by the size of the text.
func TestASideListsAtMostSixtyFourFindingsAndCountsTheRest(t *testing.T) {
	var dups strings.Builder
	dups.WriteString(`{"hosts": {`)
	for range 150 {
		dups.WriteString(`"a": "192.0.2.1", `)
	}
	dups.WriteString(`}}`)
	invalid := twoFiles(t, dups.String(), "{}")
	if invalid.Status != "invalid" || len(invalid.Old.Findings) != 64 || invalid.Old.Omitted != 149-64 || len(invalid.New.Findings) != 0 {
		t.Errorf("150 keys written twice: status %q, %d findings, omitted %d", invalid.Status, len(invalid.Old.Findings), invalid.Old.Omitted)
	}
	var unknown strings.Builder
	unknown.WriteString(`{`)
	for i := range 100 {
		fmt.Fprintf(&unknown, `"k%03d": 0, `, i)
	}
	unknown.WriteString(`}`)
	changed := twoFiles(t, "{}", unknown.String())
	if changed.Status != "changed" || len(changed.New.Findings) != 64 || changed.New.Omitted != 100-64 || len(changed.Old.Findings) != 0 {
		t.Errorf("100 unknown sections: status %q, %d findings, omitted %d", changed.Status, len(changed.New.Findings), changed.New.Omitted)
	}
	// The same on the old side, where the findings are labelled against, and the layout says
	// how many are left out of which side, in the singular for one.
	old := twoFiles(t, unknown.String(), "{}")
	if len(old.Old.Findings) != 64 || old.Old.Omitted != 100-64 {
		t.Errorf("100 unknown sections on the old side: %d findings, omitted %d", len(old.Old.Findings), old.Old.Omitted)
	}
	var said []string
	for _, f := range old.Report().Findings {
		if strings.Contains(f.Message, "not listed") {
			said = append(said, f.Message)
		}
	}
	if len(said) != 1 || said[0] != "36 findings are not listed (the old side)" {
		t.Errorf("the layout says %q of 36 findings left out of the old side", said)
	}
	sixtyFive := twoFiles(t, "{}", unknownKeys(65))
	said = nil
	for _, f := range sixtyFive.Report().Findings {
		if strings.Contains(f.Message, "not listed") {
			said = append(said, f.Message)
		}
	}
	if len(said) != 1 || said[0] != "1 finding is not listed (the new side)" {
		t.Errorf("the layout says %q of 1 finding left out of the new side", said)
	}
}

// A section that is no section is refused by Validate, with no environment.
func TestASectionThatIsNoSectionIsRefusedBeforeAnything(t *testing.T) {
	tool, _ := newRegistry(t).Get("acl_diff")
	for _, s := range []string{"nope", "tests]"} {
		if _, err := tool.Validate(json.RawMessage(`{"section":` + jsonString(s) + `}`)); err == nil {
			t.Errorf("section %q was accepted", s)
		}
	}
	for _, s := range []string{"groups", "TagOwners", "unknown", "Unknown"} {
		if _, err := tool.Validate(json.RawMessage(`{"section":` + jsonString(s) + `}`)); err != nil {
			t.Errorf("section %q: %v", s, err)
		}
	}
}

// Over MCP the texts follow the subject rule: a literal login is refused before any
// request, a pseudonym is replaced by the login it names (one read of the users for both
// sides), and the login is in nothing that comes back, but its masked form with the
// pseudonym the live side shows.
func TestDiffTextsOverMCPFollowTheSubjectRule(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.org"))
	kenv, _ := keyed(t, env)
	live := `{"groups": {"group:eng": ["amy@example.com"]}}`
	serveLive(f, live, nil, nil)
	ref := shownRef(t, reg, kenv, "u1")
	before := len(f.Requests())

	_, err := call(t, reg, kenv, "acl_diff", `{"policy":`+jsonString(`{"groups": {"group:eng": ["amy@example.com"]}}`)+`}`)
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.FilterRefused {
		t.Errorf("a literal login in the new side: %v", err)
	}
	_, err = call(t, reg, kenv, "acl_diff", `{"against":`+jsonString(`{"groups": {"group:eng": ["bob@example.org"]}}`)+`}`)
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.FilterRefused {
		t.Errorf("a literal login in the old side: %v", err)
	}
	if len(f.Requests()) != before {
		t.Errorf("a refused text cost %d requests", len(f.Requests())-before)
	}

	// The pseudonym names the same user as the live policy does, so the new side equals it.
	same := `{"groups": {"group:eng": ["` + ref + `"]}}`
	out := diffOnline(t, kenv, `{"policy":`+jsonString(same)+`}`)
	if out.Status != "equal" {
		t.Fatalf("a pseudonym for the live policy's user: %+v", out)
	}
	// A real change shows the removed member, masked, with the pseudonym.
	gone := diffOnline(t, kenv, `{"policy":`+jsonString(`{"groups": {"group:eng": []}}`)+`}`)
	text := mustJSON(t, gone)
	absent(t, text, "amy@example.com")
	if gone.Status != "changed" || !strings.Contains(text, "[p:") {
		t.Errorf("the removed member of the live side: %s", text)
	}
	// Both sides carry a pseudonym: the users are read once for the call.
	n := usersRequests(f)
	diffOnline(t, kenv, `{"against":`+jsonString(same)+`,"policy":`+jsonString(`{"groups": {"group:eng": ["`+ref+`"], "group:ops": ["`+ref+`"]}}`)+`}`)
	if got := usersRequests(f) - n; got != 1 {
		t.Errorf("two sides that name a pseudonym read the users %d times, want once", got)
	}
	// A text that holds a credential-shaped name is refused with no request, though nothing is sent.
	_, err = call(t, reg, kenv, "acl_diff", `{"policy":`+jsonString(`{"tagOwners": {"tag:tskey-api-x": []}}`)+`}`)
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidationFailed {
		t.Errorf("a credential shape: %v", err)
	}
}

// An operator's own texts show their logins masked and with no pseudonym; the live side is
// left to the registry, which gives it the pseudonym acl_get shows.
func TestAnOperatorsTextsAreShownWithoutPseudonyms(t *testing.T) {
	f, _, env := apiEnv(t)
	kenv, _ := keyed(t, env)
	serveLive(f, `{"groups": {"group:eng": ["amy@example.com"]}}`, nil, nil)
	out, err := runDiff(t, kenv, func(in *tools.ACLDiffInput) {
		in.Against, in.Operator = `{"groups": {"group:eng": ["bob@example.org"]}}`, true
	})
	if err != nil {
		t.Fatal(err)
	}
	text := mustJSON(t, out)
	absent(t, text, "bob@example.org", "amy@example.com", "b…@example.org [p:")
	if !strings.Contains(text, `b…@example.org\"`) {
		t.Errorf("the operator's login is not shown masked, with no pseudonym: %s", text)
	}
	// The live side, in the same result, carries the pseudonym acl_get shows for it.
	if !strings.Contains(text, "a…@example.com [p:") {
		t.Errorf("the live side lacks its pseudonym: %s", text)
	}
}

// A comparison sends nothing, so nothing is probed by the tests a text holds: acl_diff applies
// no cap on them in any combination, two texts or a text against the live policy, a policy or
// a patch.
func TestADiffIsNotCappedAtSixtyFourTestsInAnyCombination(t *testing.T) {
	var many strings.Builder
	many.WriteString(`{"tests": [`)
	for i := range 70 {
		fmt.Fprintf(&many, `{"src": "tag:t%02d", "accept": ["tag:ci:22"]},`, i)
	}
	many.WriteString(`]}`)
	text := many.String()
	patch := `[{"op":"add","path":"/tests","value":` + strings.TrimSuffix(strings.TrimPrefix(text, `{"tests": `), `}`) + `}]`
	for name, args := range map[string]string{
		"two texts":                          `{"against":"{}","policy":` + jsonString(text) + `}`,
		"the old text against live":          `{"against":` + jsonString(text) + `}`,
		"the new text against live":          `{"policy":` + jsonString(text) + `}`,
		"a patch against live":               `{"patch":` + jsonString(patch) + `}`,
		"70 tests in the old, no tests live": `{"against":` + jsonString(text) + `,"policy":` + jsonString(liveText) + `}`,
	} {
		f, _, env := apiEnv(t)
		serveLive(f, liveText, nil, nil)
		if _, err := call(t, newRegistry(t), env, "acl_diff", args); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if out := diffOnline(t, env, args); out.Status != "changed" {
			t.Errorf("%s: status %q", name, out.Status)
		}
		if n, others := gets(f); len(others) > 0 {
			t.Errorf("%s: %d GETs and the other requests %v: a diff sends nothing but reads", name, n, others)
		}
	}
}

// An element is cut at 1 KiB, whichever way it is long: the engine says so (Truncated) and
// the tool adds no length of its own.
func TestAnElementIsCappedAtOneKiB(t *testing.T) {
	var src strings.Builder
	for i := range 3000 {
		fmt.Fprintf(&src, `"group:member-with-a-long-name-%04d",`, i)
	}
	long := `{"acls": [{"action": "accept", "src": [` + strings.TrimSuffix(src.String(), ",") + `], "dst": ["tag:x:80"]}]}`
	out := twoFiles(t, `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}]}`, long)
	if len(out.Changes) == 0 {
		t.Fatal("no change listed")
	}
	widest := 0
	for _, c := range out.Changes {
		for _, s := range []string{c.Entry, c.Old, c.New} {
			widest = max(widest, len(s))
		}
		for _, d := range c.Fields {
			for _, s := range append(append([]string{}, d.Added...), d.Removed...) {
				widest = max(widest, len(s))
			}
		}
	}
	if widest > 1024 {
		t.Errorf("an element of %d bytes", widest)
	}
	cut := false
	for _, c := range out.Changes {
		cut = cut || c.Truncated
	}
	if !cut {
		t.Errorf("no change says it was cut: %+v", out.Changes)
	}
}

// The largest page: changes of long, angle-bracket-heavy elements (each costs six bytes as
// JSON), as many as the engine puts on a page (it stops at about 60,000 characters, counted as
// a host receives them). The page is bounded by the engine's cap and not by the frame: it stays
// under the characters the tool declares. What a host receives is that JSON as structured
// content and again as text (a JSON string), and the two copies together stay under the
// largest frame the SDK reads.
func TestTheLargestDiffResultStaysUnderTheFrameLimit(t *testing.T) {
	var a, b strings.Builder
	a.WriteString(`{"groups": {`)
	b.WriteString(`{"groups": {`)
	for i := range 60 {
		sep := ","
		if i == 59 {
			sep = ""
		}
		var oldM, newM []string
		for j := range 30 {
			oldM = append(oldM, fmt.Sprintf("%q", strings.Repeat("<", 60)+fmt.Sprintf("o%d-%d", i, j)))
			newM = append(newM, fmt.Sprintf("%q", strings.Repeat("<", 60)+fmt.Sprintf("n%d-%d", i, j)))
		}
		fmt.Fprintf(&a, `"group:%s%02d": [%s]%s`, strings.Repeat("<", 400), i, strings.Join(oldM, ","), sep)
		fmt.Fprintf(&b, `"group:%s%02d": [%s]%s`, strings.Repeat("<", 400), i, strings.Join(newM, ","), sep)
	}
	a.WriteString(`}}`)
	b.WriteString(`}}`)
	out := twoFiles(t, a.String(), b.String())
	if len(out.Changes) == 0 || !out.Truncated || out.Matched != 60 {
		t.Fatalf("listed %d changes of %d, truncated %v", len(out.Changes), out.Matched, out.Truncated)
	}
	once, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := json.Marshal(string(once))
	if err != nil {
		t.Fatal(err)
	}
	if len(once) < 50000 {
		t.Errorf("the page is %d bytes: the test does not reach a large result", len(once))
	}
	if declared := declaredChars(t, "acl_diff"); len(once) > declared {
		t.Errorf("the page is %d bytes as JSON, over the %d characters the tool declares: the engine's cap on a page no longer holds", len(once), declared)
	}
	if frame := len(once) + len(twice); frame >= mcp.DefaultMaxLineLength {
		t.Errorf("the two copies are %d bytes, over the %d of a frame", frame, mcp.DefaultMaxLineLength)
	}
}

// The registration: not open-world (it never sends a policy), a credential only when a side
// is live, the three operations, the optional scope, and a title.
func TestDiffRegistration(t *testing.T) {
	tool, ok := newRegistry(t).Get("acl_diff")
	if !ok {
		t.Fatal("acl_diff is not registered")
	}
	m := tool.Meta
	if m.OpenWorld || m.Credential != registry.CredOptional || m.Title != "Compare two policies" || m.Area != "acl" || m.Verb != "diff" {
		t.Errorf("meta = %+v", m)
	}
	if len(m.OptionalScopes) != 1 || m.OptionalScopes[0].Scope != "users:read" {
		t.Errorf("optional scopes = %+v", m.OptionalScopes)
	}
	want := map[string]bool{"GET /tailnet/{tailnet}/acl": true, "GET /tailnet/{tailnet}/users": true, "GET /tailnet/{tailnet}/settings": true}
	if len(m.Operations) != len(want) {
		t.Errorf("operations = %v", m.Operations)
	}
	for _, op := range m.Operations {
		if !want[op] {
			t.Errorf("operation %q", op)
		}
	}
}

// The report: a one-line verdict, the counts by class with the Tailscale-written ones
// marked expected, and the changes behind the side that holds what they name.
func TestTheDiffReport(t *testing.T) {
	rep := twoFiles(t, diffA, diffB).Report()
	if !strings.HasPrefix(rep.Verdict, "CHANGED · ") || rep.Level != registry.LevelWarn || len(rep.Classes) != 5 {
		t.Fatalf("verdict %q, level %v, classes %+v", rep.Verdict, rep.Level, rep.Classes)
	}
	labels := []string{"defaults", "tests reduced", "widening", "tailscale-written", "semantic"}
	for i, c := range rep.Classes {
		if c.Class != labels[i] || c.Expected != (labels[i] == "tailscale-written") {
			t.Errorf("class %d = %+v", i, c)
		}
	}
	var removed, added int
	for _, f := range rep.Findings {
		switch f.Source {
		case "against":
			removed++
		case "from":
			added++
		}
		if f.Message == "" {
			t.Errorf("finding = %+v", f)
		}
	}
	if removed == 0 || added == 0 {
		t.Errorf("findings by side: %d in the old, %d in the new", removed, added)
	}
	if v := twoFiles(t, "{}", "{}").Report().Verdict; !strings.HasPrefix(v, "EQUAL · ") {
		t.Errorf("verdict of equal policies: %q", v)
	}
	if rep := twoFiles(t, "{", "{}").Report(); !strings.HasPrefix(rep.Verdict, "INVALID · 1 problem found before anything was compared") || len(rep.Classes) != 0 {
		t.Errorf("verdict of an invalid side: %q, classes %v", rep.Verdict, rep.Classes)
	}
}

// What an agent would otherwise learn by being refused is said in the description of the two
// tools: a patch may not hold a test operation, a text with a credential shape is refused, and
// acl_validate takes at most 64 new tests in a call.
func TestTheDescriptionsNameTheRefusalsAnAgentWouldMeet(t *testing.T) {
	reg := newRegistry(t)
	for name, want := range map[string][]string{
		"acl_validate": {"test operation", "credential shape", "64 tests"},
		"acl_diff":     {"test operation", "credential shape"},
	} {
		tool, ok := reg.Get(name)
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		for _, w := range want {
			if !strings.Contains(tool.Meta.Notes, w) {
				t.Errorf("the description of %s does not say %q: %s", name, w, tool.Meta.Notes)
			}
		}
	}
}

// declaredChars is the result size the tool declares to a host (the hint of its registration).
func declaredChars(t *testing.T, name string) int {
	t.Helper()
	tool, ok := newRegistry(t).Get(name)
	if !ok {
		t.Fatalf("%s is not registered", name)
	}
	if tool.Meta.MaxResultChars <= 0 {
		t.Fatalf("%s declares no result size", name)
	}
	return tool.Meta.MaxResultChars
}

// The result a host receives from acl_diff stays under the characters the tool declares, in the
// worst cases there are: a page of changes whose every character is escaped to six, one change
// that gained and lost a hundred elements of that kind, and two sides with the most findings
// whose names are of that kind too. The result is measured as the registry returns it, masked,
// escaped and capped, and as JSON text.
func TestADiffResultStaysUnderTheCharactersItDeclares(t *testing.T) {
	declared := declaredChars(t, "acl_diff")
	angle := func(n int) string { return strings.Repeat("<", n) }
	cases := map[string][2]string{}
	// A change that gained and lost a hundred members of 1 KiB each.
	var oldM, newM []string
	for i := range 100 {
		oldM = append(oldM, fmt.Sprintf("%q", fmt.Sprintf("%s%03d", angle(1000), i)))
		newM = append(newM, fmt.Sprintf("%q", fmt.Sprintf("%sn%03d", angle(1000), i)))
	}
	cases["one change with a hundred elements of 1 KiB"] = [2]string{
		`{"groups": {"group:big": [` + strings.Join(oldM, ",") + `]}}`, `{"groups": {"group:big": [` + strings.Join(newM, ",") + `]}}`}
	// Control characters, which the registry shows as eight-character escapes.
	ctrl := strings.Repeat(`\u0001`, 200)
	var oldC, newC []string
	for i := range 100 {
		oldC = append(oldC, fmt.Sprintf(`"%so%03d"`, ctrl, i))
		newC = append(newC, fmt.Sprintf(`"%sn%03d"`, ctrl, i))
	}
	cases["one change with a hundred control-character elements"] = [2]string{
		`{"groups": {"group:big": [` + strings.Join(oldC, ",") + `]}}`, `{"groups": {"group:big": [` + strings.Join(newC, ",") + `]}}`}
	// Findings: a hundred and thirty unknown sections on each side, named with angle brackets.
	var oldS, newS []string
	for i := range 130 {
		oldS = append(oldS, fmt.Sprintf(`"%so%03d": 1`, angle(1000), i))
		newS = append(newS, fmt.Sprintf(`"%sn%03d": 1`, angle(1000), i))
	}
	cases["the most findings"] = [2]string{`{` + strings.Join(oldS, ",") + `}`, `{` + strings.Join(newS, ",") + `}`}
	// A full page of changes and the most findings on both sides together.
	var oldG, newG []string
	for i := range 60 {
		var oldMem, newMem []string
		for j := range 30 {
			oldMem = append(oldMem, fmt.Sprintf("%q", angle(60)+fmt.Sprintf("o%d-%d", i, j)))
			newMem = append(newMem, fmt.Sprintf("%q", angle(60)+fmt.Sprintf("n%d-%d", i, j)))
		}
		oldG = append(oldG, fmt.Sprintf(`"group:%s%02d": [%s]`, angle(400), i, strings.Join(oldMem, ",")))
		newG = append(newG, fmt.Sprintf(`"group:%s%02d": [%s]`, angle(400), i, strings.Join(newMem, ",")))
	}
	cases["a full page and the most findings"] = [2]string{
		`{"groups": {` + strings.Join(oldG, ",") + `}, ` + strings.Join(oldS, ",") + `}`, `{"groups": {` + strings.Join(newG, ",") + `}, ` + strings.Join(newS, ",") + `}`}
	for name, texts := range cases {
		_, reg, env := apiEnv(t)
		s, err := call(t, reg, env, "acl_diff", `{"against":`+jsonString(texts[0])+`,"policy":`+jsonString(texts[1])+`}`)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(s) > declared {
			t.Errorf("%s: the result is %d characters, over the %d the tool declares", name, len(s), declared)
		}
		if len(s) < 3000 {
			t.Errorf("%s: the result is %d characters, so the case does not reach a large result", name, len(s))
		}
		t.Logf("%s: %d characters of the %d declared", name, len(s), declared)
	}
}
