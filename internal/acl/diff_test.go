package acl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// ellipsis is what a cut text ends in (U+2026).
const ellipsis = "\xe2\x80\xa6"

func diff(t testing.TB, a, b string, opts ...DiffOptions) *DiffResult {
	t.Helper()
	var o DiffOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	r, err := Diff(context.Background(), mustParse(t, a), mustParse(t, b), o)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	return r
}

// classes lists the classes of the changes of a page, in order.
func classes(r *DiffResult) []Class {
	var out []Class
	for _, c := range r.Changes {
		out = append(out, c.Class)
	}
	return out
}

// find returns the change of a class whose key contains key.
func find(t testing.TB, r *DiffResult, class Class, key string) Change {
	t.Helper()
	for _, c := range r.Changes {
		if c.Class == class && strings.Contains(c.Key, key) {
			return c
		}
	}
	t.Fatalf("no %s change with %q in its key among %+v", class, key, r.Changes)
	return Change{}
}

func TestDiffOfAPolicyWithItselfIsEmpty(t *testing.T) {
	for _, name := range []string{"basic.hujson", "crlf.hujson", "duplicates.hujson"} {
		text := string(fixture(t, name))
		r := diff(t, text, text)
		if !r.SemanticallyEqual || !r.Equal || len(r.Changes) != 0 || r.Counts != (Counts{}) || r.Truncated || r.NextChange != "" || r.Matched != 0 {
			t.Errorf("%s: %+v", name, r)
		}
	}
	r := diff(t, string(fixture(t, "basic.hujson")), string(fixture(t, "crlf.hujson")))
	if !r.SemanticallyEqual || r.Counts.Semantic != 0 {
		t.Errorf("the CRLF copy: %+v", r.Counts)
	}
	if r.TestsBefore != 2 || r.TestsAfter != 2 || r.SSHTestsBefore != 1 || r.SSHTestsAfter != 1 {
		t.Errorf("test counts: %+v", r)
	}
	if r.TailscaleWrittenAsOf != TailscaleWrittenAsOf || len(r.NotChecked) != 6 || len(r.NormalFormLimits) != 0 {
		t.Errorf("qualifiers: %+v", r)
	}
	// The result owns its list: a caller that edits it does not change the next result.
	r.NotChecked[0] = "changed"
	if NotChecked[0] == "changed" {
		t.Error("the result shares the package's list")
	}
}

// A rewrite that means the same is no change; it is counted as comment or format only.
func TestRewritesAreCountedNotListed(t *testing.T) {
	base := `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}, {"action": "accept", "src": ["b"], "dst": ["y:2"]}], "groups": {"group:g": []}}`
	for name, c := range map[string]struct {
		text            string
		comment, format int
	}{
		"whitespace":          {"{\n  \"acls\": [{\"action\": \"accept\", \"src\": [\"a\"], \"dst\": [\"x:1\"]},\n {\"action\": \"accept\", \"src\": [\"b\"], \"dst\": [\"y:2\"]}],\n \"groups\": {\"group:g\": []}\n}", 0, 1},
		"a comment added":     {`{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}, {"action": "accept", "src": ["b"], "dst": ["y:2"]}], "groups": {"group:g": []}} // note` + "\n", 1, 0},
		"two comments":        {`/* a */ {"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}, {"action": "accept", "src": ["b"], "dst": ["y:2"]}], "groups": {"group:g": []}} // b` + "\n", 2, 0},
		"a trailing comma":    {`{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}, {"action": "accept", "src": ["b"], "dst": ["y:2"]},], "groups": {"group:g": []}}`, 0, 0},
		"rules reordered":     {`{"acls": [{"action": "accept", "src": ["b"], "dst": ["y:2"]}, {"action": "accept", "src": ["a"], "dst": ["x:1"]}], "groups": {"group:g": []}}`, 0, 2},
		"the section name":    {`{"ACLs": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}, {"action": "accept", "src": ["b"], "dst": ["y:2"]}], "groups": {"group:g": []}}`, 0, 2},
		"key order":           {`{"groups": {"group:g": []}, "acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}, {"action": "accept", "src": ["b"], "dst": ["y:2"]}]}`, 0, 1},
		"a string's escape":   {`{"acls": [{"action": "acc\u0065pt", "src": ["a"], "dst": ["x:1"]}, {"action": "accept", "src": ["b"], "dst": ["y:2"]}], "groups": {"group:g": []}}`, 0, 1},
		"the console rewrite": {`{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["1"]}, {"src": ["b"], "dst": ["y"], "ip": ["2"]}], "groups": {"group:g": []}}`, 0, 1},
		"null for absent":     {`{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}, {"action": "accept", "src": ["b"], "dst": ["y:2"]}], "groups": {"group:g": []}, "ssh": null, "nodeAttrs": null}`, 0, 1},
		"a CRLF line end":     {strings.ReplaceAll(`{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}, {"action": "accept", "src": ["b"], "dst": ["y:2"]}], "groups": {"group:g": []}}`, `}, {`, "},\r\n{") + " // c\r\n", 1, 1},
	} {
		r := diff(t, base, c.text)
		if !r.SemanticallyEqual || !r.Equal || len(r.Changes) != 0 {
			t.Errorf("%s: not equal: %+v", name, r.Changes)
			continue
		}
		if r.Counts.CommentOnly != c.comment || r.Counts.FormatOnly < c.format {
			t.Errorf("%s: comment-only %d (want %d), format-only %d (want at least %d)", name, r.Counts.CommentOnly, c.comment, r.Counts.FormatOnly, c.format)
		}
	}
	// A comment's text is never shown.
	r := diff(t, base, `{"acls": [], "groups": {}} // SECRET-COMMENT`+"\n")
	for _, c := range r.Changes {
		if strings.Contains(c.Old.Text+c.New.Text+c.Key, "SECRET") {
			t.Errorf("a comment is shown: %+v", c)
		}
	}
	// A comment inside a string is not one.
	if r := diff(t, `{"groups": {"g": ["// x"]}}`, `{"groups": {"g": ["// y"]}}`); r.Counts.CommentOnly != 0 || r.Counts.Semantic != 1 {
		t.Errorf("a string that looks like a comment: %+v", r.Counts)
	}
	// A line comment is the same whatever ends its line.
	if r := diff(t, `{} // a`+"\r\n", `{} // a`+"\n"); r.Counts.CommentOnly != 0 {
		t.Errorf("a comment with another line end: %+v", r.Counts)
	}
	// A comment that moved is not a change of the comment, and one whose text changed is
	// one removed and one added.
	if r := diff(t, `{} // a`+"\n", `// a`+"\n"+`{}`); r.Counts.CommentOnly != 0 {
		t.Errorf("a comment moved: %+v", r.Counts)
	}
	if r := diff(t, `{} // a`+"\n", `{} // b`+"\n"); r.Counts.CommentOnly != 2 {
		t.Errorf("a comment reworded: %+v", r.Counts)
	}
	// A section spelled null against one that is not in the text is a format difference.
	if r := diff(t, `{}`, `{"hosts": null}`); !r.SemanticallyEqual || r.Counts.FormatOnly == 0 {
		t.Errorf("null against absent: %+v", r)
	}
	if r := diff(t, `{"futureSection": null}`, `{}`); !r.SemanticallyEqual {
		t.Errorf("an unknown section spelled null is absent: %+v", r)
	}
}

func TestDefaultsAreTheirOwnClassAndCome(t *testing.T) {
	rule := `[{"action": "accept", "src": ["*"], "dst": ["*:*"]}]`
	for name, c := range map[string]struct {
		a, b       string
		old, new   string
		defaults   int
		wantStatus string
	}{
		"allow-all to deny-all":     {`{}`, `{"acls": []}`, "absent", "empty", 1, ""},
		"deny-all to allow-all":     {`{"acls": []}`, `{}`, "empty", "absent", 1, ""},
		"deny-all to a rule":        {`{"acls": []}`, `{"acls": ` + rule + `}`, "empty", "1", 1, ""},
		"allow-all to a rule":       {`{}`, `{"acls": ` + rule + `}`, "absent", "1", 1, ""},
		"null is absent":            {`{"acls": null}`, `{}`, "", "", 0, ""},
		"acls to grants":            {`{"acls": ` + rule + `}`, `{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}`, "", "", 0, ""},
		"a rule less, still a rule": {`{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}, {"action": "accept", "src": ["b"], "dst": ["y:2"]}]}`, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}]}`, "", "", 0, ""},
		"grants emptied":            {`{"grants": ` + `[{"src": ["a"], "dst": ["x"], "ip": ["1"]}]}`, `{"grants": []}`, "1", "empty", 1, ""},
	} {
		r := diff(t, c.a, c.b)
		if r.Counts.Defaults != c.defaults {
			t.Errorf("%s: defaults = %d, want %d (%+v)", name, r.Counts.Defaults, c.defaults, r.Changes)
			continue
		}
		if c.defaults == 1 {
			ch := r.Changes[0]
			if ch.Class != ClassDefaults || ch.Section != "acls+grants" || ch.Old.Text != c.old || ch.New.Text != c.new || ch.Note == "" {
				t.Errorf("%s: %+v", name, ch)
			}
		}
	}
	r := diff(t, `{"ssh": [{"action": "accept", "src": ["a"], "dst": ["b"], "users": ["u"]}]}`, `{}`)
	ch := find(t, r, ClassDefaults, "ssh")
	if ch.Old.Text != "1" || ch.New.Text != "absent" || !strings.Contains(ch.Note, "Tailscale SSH") {
		t.Errorf("ssh removed: %+v", ch)
	}
	if r := diff(t, `{"ssh": []}`, `{}`); r.Counts.Defaults != 1 {
		t.Errorf("an empty ssh is not an absent one: %+v", r.Counts)
	}
}

// acls and grants are one pool of atoms, but an absent acls section is the default allow-all
// and "acls": [] is deny-all, and whether grants alone cancels the default is not known. So a
// section written as [] where it was absent (or the other way round) is a defaults change on
// its own, whatever the other one holds, and the normal form tells the two apart.
func TestAnAclsOrGrantsSectionMovingBetweenAbsentAndEmptyIsADefaultsChange(t *testing.T) {
	g := `{"src": ["a@example.com"], "dst": ["tag:x"], "ip": ["*"]}`
	r1 := `{"action": "accept", "src": ["a@example.com"], "dst": ["tag:x:*"]}`
	for name, c := range map[string]struct {
		a, b     string
		sections []string
	}{
		"acls added empty beside grants": {`{"grants": [` + g + `]}`, `{"acls": [], "grants": [` + g + `]}`, []string{"acls"}},
		"grants added empty beside acls": {`{"acls": [` + r1 + `]}`, `{"acls": [` + r1 + `], "grants": []}`, []string{"grants"}},
		"deny-all by grants or by acls":  {`{"grants": []}`, `{"acls": []}`, []string{"acls", "grants"}},
		"acls beside empty grants":       {`{"acls": [], "grants": []}`, `{"grants": []}`, []string{"acls"}},
		"grants beside empty acls":       {`{"acls": [], "grants": []}`, `{"acls": []}`, []string{"grants"}},
		"null grants beside empty acls":  {`{"acls": [], "grants": null}`, `{"acls": [], "grants": []}`, []string{"grants"}},
	} {
		for dir, ab := range [][2]string{{c.a, c.b}, {c.b, c.a}} {
			r := diff(t, ab[0], ab[1])
			if r.SemanticallyEqual || r.Equal || r.Counts.Defaults != len(c.sections) {
				t.Errorf("%s (direction %d): equal=%v, %d defaults changes, want %d: %+v", name, dir, r.SemanticallyEqual, r.Counts.Defaults, len(c.sections), r.Changes)
				continue
			}
			for i, ch := range r.Changes {
				if ch.Class != ClassDefaults || ch.Section != c.sections[i] || ch.Key != c.sections[i] || ch.Note == "" || ch.Old.Text == ch.New.Text {
					t.Errorf("%s (direction %d): change %d is %+v, want a defaults change of %s", name, dir, i, ch, c.sections[i])
				}
			}
			na, nb := normalise(t, ab[0]), normalise(t, ab[1])
			if bytes.Equal(na.Bytes(), nb.Bytes()) {
				t.Errorf("%s (direction %d): the normal forms are equal", name, dir)
			}
		}
	}
	// A rule moved from acls to grants (or half of them) is the console's rewrite, not a change,
	// and neither is a section that is non-empty on both sides.
	for name, c := range map[string][2]string{
		"acls to grants":     {`{"acls": [` + r1 + `]}`, `{"grants": [{"src": ["a@example.com"], "dst": ["tag:x"], "ip": ["*"]}]}`},
		"grants to acls":     {`{"grants": [{"src": ["a@example.com"], "dst": ["tag:x"], "ip": ["*"]}]}`, `{"acls": [` + r1 + `]}`},
		"acls beside grants": {`{"acls": [` + r1 + `]}`, `{"acls": [` + r1 + `], "grants": [{"src": ["a@example.com"], "dst": ["tag:x"], "ip": ["*"]}]}`},
		"null beside a rule": {`{"acls": [` + r1 + `], "grants": null}`, `{"acls": [` + r1 + `]}`},
	} {
		if r := diff(t, c[0], c[1]); !r.SemanticallyEqual || r.Counts.Defaults != 0 {
			t.Errorf("%s: %+v", name, r.Counts)
		}
		if !bytes.Equal(normalise(t, c[0]).Bytes(), normalise(t, c[1]).Bytes()) {
			t.Errorf("%s: the normal forms differ", name)
		}
	}
}

func TestRemovedTestsAreAReductionAndAddedOnesAreNot(t *testing.T) {
	two := `{"tests": [{"src": "a", "accept": ["x:1", "x:2"], "deny": ["y:3"]}]}`
	r := diff(t, two, `{"tests": [{"src": "a", "accept": ["x:1"], "deny": ["y:3"]}]}`)
	if r.Counts.TestsReduced != 1 || r.Counts.Semantic != 0 || r.TestsBefore != 1 || r.TestsAfter != 1 {
		t.Fatalf("one assertion dropped from a test: %+v", r)
	}
	ch := r.Changes[0]
	if ch.Class != ClassTestsReduced || ch.Op != OpRemoved || ch.Section != "tests" || !strings.Contains(ch.Key, "accept x:2") || ch.OldLine != 1 || ch.OldPointer != "/tests/0" {
		t.Errorf("the reduction: %+v", ch)
	}
	r = diff(t, two, `{}`)
	if r.Counts.TestsReduced != 3 || r.TestsAfter != 0 {
		t.Errorf("all removed: %+v", r.Counts)
	}
	r = diff(t, `{"tests": [{"src": "a", "accept": ["x:1"]}]}`, two)
	if r.Counts.TestsReduced != 0 || r.Counts.Semantic != 2 {
		t.Errorf("tests added: %+v", r.Counts)
	}
	// A repeated test is counted: dropping one of two identical tests reduces them.
	r = diff(t, `{"tests": [{"src": "a", "accept": ["x:1"]}, {"src": "a", "accept": ["x:1"]}]}`, `{"tests": [{"src": "a", "accept": ["x:1"]}]}`)
	if r.Counts.TestsReduced != 1 || r.Changes[0].OldN != 2 || r.Changes[0].NewN != 1 {
		t.Errorf("a repeated test: %+v", r.Changes)
	}
	// SSH tests.
	r = diff(t, `{"sshTests": [{"src": "a", "dst": ["t"], "accept": ["u"], "deny": ["root"]}]}`, `{"sshTests": [{"src": "a", "dst": ["t"], "accept": ["u"]}]}`)
	if r.Counts.TestsReduced != 1 || r.Changes[0].Section != "sshTests" || !strings.Contains(r.Changes[0].Key, "deny root") {
		t.Errorf("sshTests: %+v", r)
	}
	// A test split in two is no reduction.
	r = diff(t, two, `{"tests": [{"src": "a", "accept": ["x:1"]}, {"src": "a", "accept": ["x:2"], "deny": ["y:3"]}]}`)
	if !r.SemanticallyEqual {
		t.Errorf("a split test: %+v", r.Changes)
	}
	// What a test is shown as holds no separator and no quote of the encoding.
	r = diff(t, `{"tests": [{"src": "a", "proto": "tcp", "accept": ["x:1"], "srcPostureAttrs": {"k": 1}}]}`, `{}`)
	if k := r.Changes[0].Key; strings.ContainsAny(k, "\x1f") || !strings.Contains(k, "tcp accept x:1") || !strings.Contains(k, `srcpostureattrs={"k":1}`) && !strings.Contains(k, `srcPostureAttrs={"k":1}`) {
		t.Errorf("the key of an assertion: %q", k)
	}
	// A test that is not an object is one opaque assertion, shown as itself.
	r = diff(t, `{"tests": [7]}`, `{}`)
	if r.Counts.TestsReduced != 1 || strings.ContainsAny(r.Changes[0].Key, "\x1f") || !strings.Contains(r.Changes[0].Key, "7") {
		t.Errorf("an opaque test: %+v", r.Changes)
	}
}

func TestWideningsAreStructuralAndCheap(t *testing.T) {
	base := `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}]}`
	for name, c := range map[string]struct {
		text  string
		field string
		item  string
	}{
		"* as a source":                  {`{"acls": [{"action": "accept", "src": ["group:a", "*"], "dst": ["tag:x:80"]}]}`, "src", "*"},
		"* as a destination":             {`{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80", "*:*"]}]}`, "dst", "*"},
		"autogroup:internet to a source": {`{"acls": [{"action": "accept", "src": ["autogroup:internet"], "dst": ["tag:x:80"]}]}`, "src", "autogroup:internet"},
		"autogroup:member in a grant":    {`{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}], "grants": [{"src": ["autogroup:member"], "dst": ["tag:x"], "ip": ["1"]}]}`, "src", "autogroup:member"},
		"legacy autogroup:members":       {`{"acls": [{"action": "accept", "src": ["autogroup:members"], "dst": ["tag:x:80"]}]}`, "src", "autogroup:member"},
		"autogroup:internet to a dst":    {`{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80", "autogroup:internet:*"]}]}`, "dst", "autogroup:internet"},
	} {
		r := diff(t, base, c.text)
		ch := find(t, r, ClassWidening, c.field+" "+c.item)
		if ch.Section != "acls+grants" || len(ch.Fields) != 1 || ch.Fields[0].Field != c.field || ch.Fields[0].Added[0] != c.item {
			t.Errorf("%s: %+v", name, ch)
		}
		if r.Counts.Widening != 1 {
			t.Errorf("%s: widening = %d", name, r.Counts.Widening)
		}
		// It points at an atom that is new, not at one the policies share.
		if ch.NewLine != 1 || ch.NewPointer == "" {
			t.Errorf("%s: no place: %+v", name, ch)
		}
	}
	// A second rule with * where one already has it still counts: the number of atoms grew.
	two := `{"acls": [{"action": "accept", "src": ["*"], "dst": ["tag:x:80"]}]}`
	three := `{"acls": [{"action": "accept", "src": ["*"], "dst": ["tag:x:80"]}, {"action": "accept", "src": ["*"], "dst": ["tag:y:80"]}]}`
	if r := diff(t, two, three); r.Counts.Widening != 1 {
		t.Errorf("a second wildcard rule: %+v", r.Counts)
	}
	// Narrowing is not widening, and neither is the same wildcard moved.
	if r := diff(t, `{"acls": [{"action": "accept", "src": ["*"], "dst": ["tag:x:80"]}]}`, base); r.Counts.Widening != 0 {
		t.Errorf("narrowing: %+v", r.Counts)
	}
	if r := diff(t, two, `{"grants": [{"src": ["*"], "dst": ["tag:x"], "ip": ["80"]}]}`); r.Counts.Widening != 0 || !r.SemanticallyEqual {
		t.Errorf("a rewrite: %+v", r.Counts)
	}

	// A source posture removed.
	withPosture := `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"], "srcPosture": ["posture:p"]}]}`
	r := diff(t, withPosture, base)
	if ch := find(t, r, ClassWidening, "srcPosture removed"); ch.Op != OpChanged || ch.Fields[0].Field != "srcPosture" || !strings.Contains(ch.Old.Text, "posture:p") || ch.NewLine != 1 || ch.OldLine != 1 {
		t.Errorf("posture removed: %+v", ch)
	}
	if r := diff(t, withPosture, strings.ReplaceAll(withPosture, "posture:p", "posture:q")); r.Counts.Widening != 0 {
		t.Errorf("posture replaced: %+v", r.Counts)
	}
	if r := diff(t, base, withPosture); r.Counts.Widening != 0 {
		t.Errorf("posture added: %+v", r.Counts)
	}
	// With the posture still required by another rule of the same access, nothing was lost.
	bothRules := `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"], "srcPosture": ["posture:p"]}, {"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}]}`
	if r := diff(t, bothRules, base); r.Counts.Widening != 0 {
		t.Errorf("an access that was open already: %+v", r.Counts)
	}
	// The default source posture removed.
	r = diff(t, `{"defaultSrcPosture": ["posture:p"]}`, `{}`)
	if ch := find(t, r, ClassWidening, "defaultSrcPosture"); !strings.Contains(ch.Fields[0].Removed[0], "posture:p") {
		t.Errorf("default posture removed: %+v", ch)
	}
	if r := diff(t, `{"defaultSrcPosture": ["posture:p"]}`, `{"defaultSrcPosture": ["posture:q"]}`); r.Counts.Widening != 0 {
		t.Errorf("default posture changed: %+v", r.Counts)
	}
	if r := diff(t, `{"defaultSrcPosture": "posture:p"}`, `{}`); r.Counts.Widening != 0 {
		t.Errorf("a wrong-typed default posture is not one: %+v", r.Counts)
	}

	// SSH: check to accept, and a rule that lets someone in as root.
	check := `{"ssh": [{"action": "check", "src": ["g"], "dst": ["t"], "users": ["alice"]}]}`
	accept := `{"ssh": [{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["alice"]}]}`
	r = diff(t, check, accept)
	if ch := find(t, r, ClassWidening, "ssh check to accept"); ch.Fields[0].Added[0] != "accept" || ch.Fields[0].Removed[0] != "check" || ch.NewLine != 1 {
		t.Errorf("check to accept: %+v", ch)
	}
	if r := diff(t, accept, check); r.Counts.Widening != 0 {
		t.Errorf("accept to check: %+v", r.Counts)
	}
	if r := diff(t, check, `{"ssh": [{"action": "check", "src": ["g"], "dst": ["t"], "users": ["alice"]}, {"action": "accept", "src": ["g"], "dst": ["t"], "users": ["alice"]}]}`); r.Counts.Widening != 0 {
		t.Errorf("check beside accept: check is evaluated first: %+v", r.Counts)
	}
	r = diff(t, accept, `{"ssh": [{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["alice", "root"]}]}`)
	find(t, r, ClassWidening, "ssh users root")
	// A root rule for a source that had none is a rule that lets someone in as root where the old
	// rules did not (fix round 1: it was not counted while the number of root rules stayed).
	if r := diff(t, `{"ssh": [{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["root"]}]}`, `{"ssh": [{"action": "accept", "src": ["h"], "dst": ["t"], "users": ["root"]}]}`); r.Counts.Widening != 1 {
		t.Errorf("a root rule replaced by another: %+v", r.Counts)
	}
}

func TestTailscaleWrittenChangesAreAClassOfTheirOwn(t *testing.T) {
	base := `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}]}`
	funnel := `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}], "nodeAttrs": [{"target": ["autogroup:member"], "attr": ["funnel"]}]}`
	logstream := `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}, {"action": "accept", "src": ["logstream@tailscale"], "dst": ["tag:logs:443"]}]}`
	preset := `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}], "nodeAttrs": [{"target": ["tag:c"], "app": {"tailscale.com/app-connectors": [{"name": "n", "presetAppID": "github"}]}}]}`
	for name, text := range map[string]string{"funnel": funnel, "log streaming": logstream, "an app connector preset": preset} {
		r := diff(t, base, text)
		if r.Counts.TailscaleWritten != 1 || r.Counts.Semantic != 0 || r.SemanticallyEqual || r.Equal {
			t.Errorf("%s: %+v", name, r.Counts)
			continue
		}
		// Ignored, the drift job sees nothing, though the policies still differ.
		r = diff(t, base, text, DiffOptions{IgnoreTailscaleWritten: true})
		if !r.Equal || r.SemanticallyEqual || len(r.Changes) != 0 || r.Counts.TailscaleWritten != 1 || r.Matched != 0 {
			t.Errorf("%s, ignored: %+v", name, r)
		}
		// The other direction (live lost it) is the same class.
		if r := diff(t, text, base); r.Counts.TailscaleWritten != 1 {
			t.Errorf("%s removed: %+v", name, r.Counts)
		}
	}
	// A rule that shares its destination with the log-stream rule is not it, and one whose
	// sources hold the log-stream source beside others is somebody's own rule: neither may
	// be ignored by a drift job.
	for name, src := range map[string]string{
		"a rule with other sources": `"group:b", "logstream@tailscale"`,
		"a rule of another source":  `"group:b"`,
	} {
		other := `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}, {"action": "accept", "src": [` + src + `], "dst": ["tag:logs:443"]}]}`
		r := diff(t, base, other, DiffOptions{IgnoreTailscaleWritten: true})
		if r.Equal || r.Counts.TailscaleWritten != 0 || r.Counts.Semantic != 1 {
			t.Errorf("%s: %+v", name, r.Counts)
		}
	}
	// A real change beside a Tailscale-written one is not ignored.
	mixed := strings.Replace(funnel, `"tag:x:80"`, `"tag:x:81"`, 1)
	r := diff(t, base, mixed, DiffOptions{IgnoreTailscaleWritten: true})
	if r.Equal || r.Counts.Semantic == 0 || r.Counts.TailscaleWritten != 1 {
		t.Errorf("a real change beside a written one: %+v", r.Counts)
	}
	// The funnel attribute written with a change to its targets is a change of a written entry.
	r = diff(t, funnel, strings.Replace(funnel, `["autogroup:member"]`, `["autogroup:member", "tag:c"]`, 1))
	if r.Counts.TailscaleWritten != 1 || r.Counts.Semantic != 0 {
		t.Errorf("funnel targets: %+v", r.Counts)
	}
	// A node attribute that is not written, and a rule changed beside it, are semantic.
	r = diff(t, `{"nodeAttrs": [{"target": ["a"], "attr": ["x"]}]}`, `{"nodeAttrs": [{"target": ["a"], "attr": ["funnel"]}]}`)
	if r.Counts.Semantic != 1 || r.Counts.TailscaleWritten != 1 {
		t.Errorf("an attribute swapped for the funnel one: %+v", r.Counts)
	}
}

func TestSemanticChangesNameWhatChanged(t *testing.T) {
	r := diff(t, `{"acls": [{"action": "accept", "src": ["a", "b"], "dst": ["x:80"]}]}`, `{"acls": [{"action": "accept", "src": ["a", "c"], "dst": ["x:80,443"]}]}`)
	if len(r.Changes) != 1 || r.Changes[0].Op != OpChanged || r.Changes[0].Class != ClassSemantic || r.Changes[0].Section != "acls" {
		t.Fatalf("changes: %+v", r.Changes)
	}
	ch := r.Changes[0]
	if len(ch.Fields) != 2 || ch.Fields[0].Field != "src" || fmt.Sprint(ch.Fields[0].Added) != "[c]" || fmt.Sprint(ch.Fields[0].Removed) != "[b]" ||
		ch.Fields[1].Field != "ports" || fmt.Sprint(ch.Fields[1].Added) != "[443]" || len(ch.Fields[1].Removed) != 0 {
		t.Errorf("fields: %+v", ch.Fields)
	}
	if ch.Key != "x" || ch.OldLine != 1 || ch.NewLine != 1 || ch.OldPointer != "/acls/0" || ch.NewPointer != "/acls/0" {
		t.Errorf("where: %+v", ch)
	}
	// Added and removed rules are listed one atom each.
	r = diff(t, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1", "y:2"]}]}`, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1", "z:3"]}]}`)
	if r.Counts.Semantic != 2 || r.Changes[0].Op != OpRemoved || r.Changes[1].Op != OpAdded || r.Changes[0].Key != "y" || r.Changes[1].Key != "z" {
		t.Errorf("one removed, one added: %+v", r.Changes)
	}
	if len(r.NormalFormLimits) != 1 || !strings.Contains(r.NormalFormLimits[0], "safe direction") {
		t.Errorf("limits: %v", r.NormalFormLimits)
	}
	// Within a section the removals come before the additions, whatever the keys.
	r = diff(t, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1", "z:3"]}]}`, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1", "y:2"]}]}`)
	if r.Counts.Semantic != 2 || r.Changes[0].Op != OpRemoved || r.Changes[0].Key != "z" || r.Changes[1].Op != OpAdded || r.Changes[1].Key != "y" {
		t.Errorf("removed before added: %+v", r.Changes)
	}
	// A key change in a keyed section, an unknown section, a node attribute's targets.
	r = diff(t, `{"groups": {"group:a": ["x"], "group:b": []}, "futureSection": {"a": 1}, "nodeAttrs": [{"target": ["tag:a"], "attr": ["x"]}]}`,
		`{"groups": {"group:a": ["y"], "group:c": []}, "futureSection": {"a": 2}, "otherSection": 1, "nodeAttrs": [{"target": ["tag:a", "tag:b"], "attr": ["x"]}]}`)
	got := map[string]string{}
	for _, c := range r.Changes {
		got[c.Section+"/"+c.Key] = string(c.Op)
	}
	want := map[string]string{
		"groups/group:a": "changed", "groups/group:b": "removed", "groups/group:c": "added",
		"futuresection/": "changed", "othersection/": "added",
		"nodeAttrs/" + `{"attr":"x"}`: "changed",
	}
	// unknown sections are listed by their name
	got2 := map[string]string{}
	for k, v := range got {
		got2[strings.ToLower(k)] = v
	}
	for k, v := range want {
		if got2[strings.ToLower(k)] != v {
			t.Errorf("%s: got %q, want %q (all: %v)", k, got2[strings.ToLower(k)], v, got2)
		}
	}
	for _, c := range r.Changes {
		if c.Section == "nodeAttrs" {
			if c.Fields[0].Field != "target" || fmt.Sprint(c.Fields[0].Added) != "[tag:b]" {
				t.Errorf("targets: %+v", c.Fields)
			}
		}
	}
	// tagOwners [] is not equated to autogroup:admin, and says so.
	r = diff(t, `{"tagOwners": {"tag:a": []}}`, `{"tagOwners": {"tag:a": ["autogroup:admin"]}}`)
	if r.Counts.Semantic != 1 || !strings.Contains(r.Changes[0].Note, "documented as equivalent") {
		t.Errorf("tagOwners: %+v", r.Changes)
	}
	// ipset operations are ordered: a reorder is a change, not a move.
	r = diff(t, `{"ipsets": {"ipset:s": ["add 192.0.2.1", "remove 192.0.2.1"]}}`, `{"ipsets": {"ipset:s": ["remove 192.0.2.1", "add 192.0.2.1"]}}`)
	if r.Counts.Semantic != 1 || r.SemanticallyEqual {
		t.Errorf("ipsets reordered: %+v", r.Counts)
	}
	// A repeated SSH rule removed is a change, with its counts.
	rule := `{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["u"]}`
	r = diff(t, `{"ssh": [`+rule+`, `+rule+`]}`, `{"ssh": [`+rule+`]}`)
	if r.Counts.Semantic != 1 || r.Changes[0].Op != OpRemoved || r.Changes[0].OldN != 2 || r.Changes[0].NewN != 1 {
		t.Errorf("ssh rule repeated: %+v", r.Changes)
	}
	if r = diff(t, `{"ssh": [`+rule+`]}`, `{"ssh": [`+rule+`, `+rule+`]}`); r.Changes[0].Op != OpAdded {
		t.Errorf("ssh rule repeated, other way: %+v", r.Changes)
	}
	// The fields of autoApprovers and derpMap are entries too, named by their pointer.
	r = diff(t, `{"autoApprovers": {"routes": {"192.0.2.0/24": ["a"]}, "exitNode": ["a"]}}`, `{"autoApprovers": {"routes": {"192.0.2.0/24": ["b"]}, "exitNode": ["a"]}}`)
	if len(r.Changes) != 1 || r.Changes[0].Key != "routes/192.0.2.0~124" || r.Changes[0].OldPointer != "/autoApprovers/routes/192.0.2.0~124" {
		t.Errorf("autoApprovers: %+v", r.Changes)
	}
	// A node attribute entry that is not an object is kept whole and shown as itself.
	r = diff(t, `{"nodeAttrs": [7]}`, `{"nodeAttrs": [8]}`)
	if r.Counts.Semantic != 2 || strings.ContainsAny(r.Changes[0].Key+r.Changes[0].Old.Text+r.Changes[1].New.Text, "\x1f") {
		t.Errorf("an opaque node attribute: %+v", r.Changes)
	}
}

func TestClassesAreListedInOrder(t *testing.T) {
	a := `{"tests": [{"src": "a", "accept": ["x:1"]}], "groups": {"group:g": []}, "ssh": [{"action": "check", "src": ["g"], "dst": ["t"], "users": ["u"]}]}`
	b := `{"acls": [{"action": "accept", "src": ["*"], "dst": ["x:1"]}], "groups": {"group:g": ["m"]}, "nodeAttrs": [{"target": ["a"], "attr": ["funnel"]}], "ssh": [{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["u"]}]}`
	r := diff(t, a, b)
	want := []Class{ClassDefaults, ClassTestsReduced, ClassWidening, ClassWidening, ClassTailscaleWritten}
	got := classes(r)
	for i, w := range want {
		if i >= len(got) || got[i] != w {
			t.Fatalf("classes: %v, want to start with %v", got, want)
		}
	}
	for _, c := range got[len(want):] {
		if c != ClassSemantic {
			t.Errorf("after the others only semantic changes: %v", got)
		}
	}
	if r.Counts.Defaults != 1 || r.Counts.TestsReduced != 1 || r.Counts.Widening != 2 || r.Counts.TailscaleWritten != 1 || r.Counts.Semantic < 3 {
		t.Errorf("counts: %+v", r.Counts)
	}
}

// A widening entry cannot hide past the cut of a long element: each element is cut at
// 1 KiB, the fields name the widening selector first, and the text carries its full length.
func TestAWideningCannotHidePastTheCut(t *testing.T) {
	var many strings.Builder
	for i := range 3000 {
		fmt.Fprintf(&many, `"!g%04d",`, i)
	}
	long := many.String()
	a := `{"acls": [{"action": "accept", "src": [` + long + `], "dst": ["tag:x:80"]}]}`
	b := `{"acls": [{"action": "accept", "src": [` + long + `"*"], "dst": ["tag:x:80"]}]}`
	r := diff(t, a, b)
	ch := find(t, r, ClassSemantic, "tag:x")
	if !ch.New.Truncated || len(ch.New.Text) > maxPointer+len(ellipsis) || ch.New.Len < 20000 || !ch.Old.Truncated {
		t.Errorf("texts: %d bytes shown of %d, truncated %v", len(ch.New.Text), ch.New.Len, ch.New.Truncated)
	}
	if strings.Contains(ch.New.Text, `"*"`) {
		t.Fatal("the test no longer puts the wildcard past the cut")
	}
	if ch.Fields[0].Field != "src" || fmt.Sprint(ch.Fields[0].Added) != "[*]" {
		t.Errorf("the delta must carry the wildcard: %+v", ch.Fields)
	}
	w := find(t, r, ClassWidening, "src *")
	if w.Fields[0].Added[0] != "*" {
		t.Errorf("widening: %+v", w)
	}
	// Many added sources: the wide ones come first and the rest are counted.
	var added strings.Builder
	for i := range 200 {
		fmt.Fprintf(&added, `"group:n%03d",`, i)
	}
	r = diff(t, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}]}`, `{"acls": [{"action": "accept", "src": [`+added.String()+`"autogroup:internet", "a"], "dst": ["x:1"]}]}`)
	f := find(t, r, ClassSemantic, "x").Fields[0]
	if len(f.Added) != maxDeltaItems || f.AddedMore != 201-maxDeltaItems || f.Added[0] != "autogroup:internet" {
		t.Errorf("delta: %d listed, %d more, first %q", len(f.Added), f.AddedMore, f.Added[0])
	}
	// An item of the delta is cut at 1 KiB too.
	huge := strings.Repeat("h", 5000)
	r = diff(t, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}]}`, `{"acls": [{"action": "accept", "src": ["a", "`+huge+`"], "dst": ["x:1"]}]}`)
	if it := find(t, r, ClassSemantic, "x").Fields[0].Added[0]; len(it) > maxPointer+len(ellipsis) || !strings.HasSuffix(it, ellipsis) {
		t.Errorf("an item of %d bytes was not cut: %d", len(huge), len(it))
	}
}

func TestPagesCursorsAndSectionFilter(t *testing.T) {
	var a, b strings.Builder
	a.WriteString(`{"groups": {`)
	b.WriteString(`{"groups": {`)
	for i := range 120 {
		fmt.Fprintf(&a, `"group:k%03d": ["old"],`, i)
		fmt.Fprintf(&b, `"group:k%03d": ["new"],`, i)
	}
	a.WriteString(`}, "hosts": {"h": "192.0.2.1"}}`)
	b.WriteString(`}, "hosts": {"h": "192.0.2.2"}, "futureSection": 1}`)
	r1 := diff(t, a.String(), b.String())
	if r1.Counts.Semantic != 122 || r1.Matched != 122 || len(r1.Changes) != DefaultPage || !r1.Truncated || r1.NextChange == "" {
		t.Fatalf("page 1: counts %+v, matched %d, listed %d, truncated %v", r1.Counts, r1.Matched, len(r1.Changes), r1.Truncated)
	}
	var keys []string
	for _, c := range r1.Changes {
		keys = append(keys, c.Section+"/"+c.Key)
	}
	cursor := r1.NextChange
	for pages := 1; cursor != ""; pages++ {
		r := diff(t, a.String(), b.String(), DiffOptions{Cursor: cursor})
		if r.Counts != r1.Counts || r.Matched != 122 {
			t.Fatalf("page %d: the counts must not depend on the page: %+v", pages+1, r.Counts)
		}
		for _, c := range r.Changes {
			keys = append(keys, c.Section+"/"+c.Key)
		}
		cursor = r.NextChange
		if pages > 5 {
			t.Fatal("too many pages")
		}
	}
	all := diff(t, a.String(), b.String(), DiffOptions{PageSize: MaxPage})
	if len(all.Changes) != 122 || all.Truncated {
		t.Fatalf("one page of everything: %d, truncated %v", len(all.Changes), all.Truncated)
	}
	for i, c := range all.Changes {
		if got := c.Section + "/" + c.Key; got != keys[i] {
			t.Fatalf("change %d: paging gave %s, one page gave %s", i, keys[i], got)
		}
	}
	if len(keys) != 122 {
		t.Errorf("pages hold %d changes", len(keys))
	}
	// A page size over the most is the most; one under 1 is the default; a smaller one is kept.
	if r := diff(t, a.String(), b.String(), DiffOptions{PageSize: 100000}); len(r.Changes) != 122 {
		t.Errorf("an enormous page size: %d listed", len(r.Changes))
	}
	if r := diff(t, a.String(), b.String(), DiffOptions{PageSize: -3}); len(r.Changes) != DefaultPage {
		t.Errorf("a negative page size: %d listed", len(r.Changes))
	}
	if r := diff(t, a.String(), b.String(), DiffOptions{PageSize: 7}); len(r.Changes) != 7 || r.NextChange == "" {
		t.Errorf("a page of 7: %d listed", len(r.Changes))
	}

	// The section filter lists one section; the counts stay whole.
	r := diff(t, a.String(), b.String(), DiffOptions{Section: "HOSTS"})
	if len(r.Changes) != 1 || r.Matched != 1 || r.Counts.Semantic != 122 || r.Changes[0].Section != "hosts" {
		t.Errorf("hosts: %+v", r)
	}
	r = diff(t, a.String(), b.String(), DiffOptions{Section: "unknown"})
	if len(r.Changes) != 1 || r.Changes[0].Section != "futuresection" && r.Changes[0].Section != "futureSection" {
		t.Errorf("unknown: %+v", r.Changes)
	}
	r = diff(t, `{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}]}`, `{"grants": [{"src": ["b"], "dst": ["x"], "ip": ["1"]}]}`, DiffOptions{Section: "grants"})
	if len(r.Changes) == 0 {
		t.Error("the access rules of both are listed under grants")
	}
	// An unknown section is not matched by a known name that appears inside its own.
	r = diff(t, `{"hosts+x": 1}`, `{"hosts+x": 2}`, DiffOptions{Section: "hosts"})
	if len(r.Changes) != 0 {
		t.Errorf("an unknown section named like two: %+v", r.Changes)
	}

	// A cursor is for one pair and one set of options.
	for name, o := range map[string]DiffOptions{
		"another section": {Cursor: r1.NextChange, Section: "groups"},
		"made up":         {Cursor: "c1.5.0000000000000000"},
		"garbage":         {Cursor: "nonsense"},
		"negative":        {Cursor: "c1.-1.0000000000000000"},
		"past the end":    {Cursor: "c1.99999.0000000000000000"},
		"no digest":       {Cursor: "c1.5"},
		"another ignore":  {Cursor: r1.NextChange, IgnoreTailscaleWritten: true},
	} {
		_, err := Diff(context.Background(), mustParse(t, a.String()), mustParse(t, b.String()), o)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A cursor from this pair does not work for another.
	_, err := Diff(context.Background(), mustParse(t, a.String()), mustParse(t, `{}`), DiffOptions{Cursor: r1.NextChange})
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("a cursor of another comparison: err = %v", err)
	}
	if _, err := Diff(context.Background(), mustParse(t, a.String()), mustParse(t, b.String()), DiffOptions{Section: "nodeAttr"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a section that is not one: err = %v", err)
	}
	// The same cursor works whatever the page size asked for, and the end of the list ends it.
	r = diff(t, a.String(), b.String(), DiffOptions{Cursor: r1.NextChange, PageSize: MaxPage})
	if len(r.Changes) != 122-DefaultPage || r.Truncated || r.NextChange != "" {
		t.Errorf("the rest in one page: %d listed, truncated %v", len(r.Changes), r.Truncated)
	}
}

// A page ends by its size in bytes as well as by its count: a change that carries a lot
// of text does not let 200 of them through.
func TestAPageIsAboutSixtyFourKilobytes(t *testing.T) {
	var a, b strings.Builder
	a.WriteString(`{"groups": {`)
	b.WriteString(`{"groups": {`)
	for i := range 150 {
		fmt.Fprintf(&a, `"group:k%03d": ["%s"],`, i, strings.Repeat("o", 900))
		fmt.Fprintf(&b, `"group:k%03d": ["%s"],`, i, strings.Repeat("n", 900))
	}
	a.WriteString(`}}`)
	b.WriteString(`}}`)
	r := diff(t, a.String(), b.String(), DiffOptions{PageSize: MaxPage})
	if !r.Truncated || r.NextChange == "" || len(r.Changes) < 20 || len(r.Changes) > 60 {
		t.Fatalf("a page of ~1.8 KB changes: %d listed, truncated %v", len(r.Changes), r.Truncated)
	}
	size := 0
	for _, c := range r.Changes {
		size += len(c.Old.Text) + len(c.New.Text) + len(c.Key)
	}
	if size > pageBytes+4096 {
		t.Errorf("the page holds %d bytes of text", size)
	}
}

func TestDiffSpendsABudgetAndHonoursTheContext(t *testing.T) {
	a := mustParse(t, string(fixture(t, "basic.hujson")))
	b := mustParse(t, `{}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Diff(ctx, a, b, DiffOptions{}); !errors.Is(err, context.Canceled) {
		t.Errorf("a context that is done: %v", err)
	}
	if _, err := Diff(context.Background(), nil, b, DiffOptions{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("no old policy: %v", err)
	}
	if _, err := Diff(context.Background(), a, nil, DiffOptions{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("no new policy: %v", err)
	}
	old := maxWork
	t.Cleanup(func() { maxWork = old })
	// One budget covers the two normal forms and the comparison.
	r, err := Diff(context.Background(), a, b, DiffOptions{})
	if err != nil || r.Ops < 100 {
		t.Fatalf("ops = %d, err = %v", r.Ops, err)
	}
	maxWork = r.Ops - 1
	if res, err := Diff(context.Background(), a, b, DiffOptions{}); !errors.Is(err, ErrTooComplex) || res != nil {
		t.Errorf("a budget one step short: %v, %v", res, err)
	}
	maxWork = r.Ops
	if _, err := Diff(context.Background(), a, b, DiffOptions{}); err != nil {
		t.Errorf("a budget of exactly what it needs: %v", err)
	}
	// The same holds when the result is a page of a longer list, whose cursor is paid for.
	maxWork = old
	var x, y strings.Builder
	x.WriteString(`{"groups": {`)
	y.WriteString(`{"groups": {`)
	for i := range 80 {
		fmt.Fprintf(&x, `"group:k%03d": ["old"],`, i)
		fmt.Fprintf(&y, `"group:k%03d": ["new"],`, i)
	}
	x.WriteString(`}}`)
	y.WriteString(`}}`)
	px, py := mustParse(t, x.String()), mustParse(t, y.String())
	r, err = Diff(context.Background(), px, py, DiffOptions{})
	if err != nil || !r.Truncated {
		t.Fatalf("a long list: %v %+v", err, r)
	}
	maxWork = r.Ops - 1
	if _, err := Diff(context.Background(), px, py, DiffOptions{}); !errors.Is(err, ErrTooComplex) {
		t.Errorf("a page with a cursor, one step short: %v", err)
	}
}

// Diff(a, b) and Diff(b, a) list the same changes with the sides swapped. Widening and
// the defaults are one-sided by nature, and a removed test is a reduction where an added
// one is a plain change, so those are left out of the comparison.
func TestDiffMirrors(t *testing.T) {
	a := string(fixture(t, "basic.hujson"))
	b := `{"acls": [{"action": "accept", "src": ["group:eng"], "dst": ["tag:web:80"], "proto": "tcp"}], "groups": {"group:eng": ["amy@example.com"]}, "tests": [{"src": "group:eng", "accept": ["tag:web:80"]}]}`
	ab, ba := diff(t, a, b, DiffOptions{PageSize: MaxPage}), diff(t, b, a, DiffOptions{PageSize: MaxPage})
	flip := map[Op]Op{OpAdded: OpRemoved, OpRemoved: OpAdded, OpChanged: OpChanged}
	type id struct{ section, key string }
	count := func(r *DiffResult, op Op) map[id]int {
		m := map[id]int{}
		for _, c := range r.Changes {
			if c.Op == op && (c.Class == ClassSemantic || c.Class == ClassTestsReduced || c.Class == ClassTailscaleWritten) {
				m[id{c.Section, c.Key}]++
			}
		}
		return m
	}
	total := 0
	for op := range flip {
		x, y := count(ab, op), count(ba, flip[op])
		total += len(x)
		if fmt.Sprint(x) != fmt.Sprint(y) {
			t.Errorf("%s one way is not %s the other:\n%v\n%v", op, flip[op], x, y)
		}
	}
	if total < 10 {
		t.Errorf("only %d changes compared", total)
	}
	if ab.SemanticallyEqual || ba.SemanticallyEqual {
		t.Error("the policies differ")
	}
}

// Each side of a change carries the line and the pointer in its own text.
func TestChangesCarryTheLineOfEachSide(t *testing.T) {
	old := "{\n\"acls\": [{\"action\":\"accept\",\"src\":[\"a\"],\"dst\":[\"x:80\"]}]}"
	new := "{\n\n\n\"acls\": [{\"action\":\"accept\",\"src\":[\"a\",\"b\"],\"dst\":[\"x:80\"]}]}"
	r := diff(t, old, new)
	if len(r.Changes) != 1 {
		t.Fatalf("changes: %+v", r.Changes)
	}
	if ch := r.Changes[0]; ch.OldLine != 2 || ch.NewLine != 4 || ch.OldPointer != "/acls/0" || ch.NewPointer != "/acls/0" {
		t.Errorf("a changed atom: old %s line %d, new %s line %d", ch.OldPointer, ch.OldLine, ch.NewPointer, ch.NewLine)
	}
	// A removed rule has a line on the old side only, an added one on the new side only.
	r = diff(t, old, "{\n\n\n}")
	if ch := r.Changes[len(r.Changes)-1]; ch.Op != OpRemoved || ch.OldLine != 2 || ch.NewLine != 0 || ch.NewPointer != "" {
		t.Errorf("removed: %+v", ch)
	}
	r = diff(t, "{\n}", new)
	if ch := r.Changes[len(r.Changes)-1]; ch.Op != OpAdded || ch.NewLine != 4 || ch.OldLine != 0 || ch.OldPointer != "" {
		t.Errorf("added: %+v", ch)
	}
	// Entries of a keyed section, in the old and the new text.
	r = diff(t, "{\n\"groups\": {\n\"group:a\": []}}", "{\n\n\n\"groups\": {\n\n\"group:a\": [\"x\"]}}")
	if ch := r.Changes[0]; ch.OldLine != 3 || ch.NewLine != 6 || ch.OldPointer != "/groups/group:a" || ch.NewPointer != "/groups/group:a" {
		t.Errorf("a keyed entry: %+v", ch)
	}
	// A section spelled in another case is pointed at as the text spells it.
	r = diff(t, "{\n\"GROUPS\": {\n\"group:a\": []}}", "{\n\"Groups\": {\n\"group:a\": [\"x\"]}}")
	if ch := r.Changes[0]; ch.OldPointer != "/GROUPS/group:a" || ch.NewPointer != "/Groups/group:a" {
		t.Errorf("another case: %+v", ch)
	}
}

// A section that holds a value of the wrong type is kept whole, under the key "" - the key
// a real entry can have too. Diff must never pair the one with the other, or a policy that
// the server reads one way would read as unchanged against one it reads another.
func TestAWrongTypedSectionIsNeverPairedWithAnEntryNamedNothing(t *testing.T) {
	pairs := [][2]string{
		{`{"groups":{"":["a"]}}`, `{"groups":["a"]}`},
		{`{"tagOwners":{"":["a"]}}`, `{"tagOwners":["a"]}`},
		{`{"hosts":{"":"192.0.2.1"}}`, `{"hosts":"192.0.2.1"}`},
		{`{"postures":{"":["a"]}}`, `{"postures":["a"]}`},
		{`{"ipsets":{"":["add 192.0.2.1"]}}`, `{"ipsets":["add 192.0.2.1"]}`},
		{`{"attrConfig":{"":{}}}`, `{"attrConfig":{}}`},
		{`{"externalTailnets":{"":["a"]}}`, `{"externalTailnets":["a"]}`},
		{`{"autoApprovers":{"":["a"]}}`, `{"autoApprovers":["a"]}`},
		{`{"derpMap":{"":1}}`, `{"derpMap":1}`},
		{`{"acls":[]}`, `{"acls":{}}`},
		{`{"grants":[]}`, `{"grants":{}}`},
		{`{"ssh":[]}`, `{"ssh":{}}`},
		{`{"ssh":[{"action":"accept"}]}`, `{"ssh":{"action":"accept"}}`},
		{`{"tests":[{"src":"a","accept":["x:1"]}]}`, `{"tests":{"src":"a","accept":["x:1"]}}`},
		{`{"sshTests":[]}`, `{"sshTests":{}}`},
		{`{"nodeAttrs":[]}`, `{"nodeAttrs":{}}`},
		{`{"extraDNSRecords":[]}`, `{"extraDNSRecords":{}}`},
		{`{"defaultSrcPosture":["a"]}`, `{"defaultSrcPosture":{}}`},
	}
	for _, p := range pairs {
		for _, ab := range [][2]string{{p[0], p[1]}, {p[1], p[0]}} {
			a, b := mustParse(t, ab[0]), mustParse(t, ab[1])
			na, err := Normalise(context.Background(), a)
			if err != nil {
				t.Fatal(err)
			}
			nb, err := Normalise(context.Background(), b)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(na.Bytes(), nb.Bytes()) {
				t.Errorf("%s and %s: the normal forms are equal", ab[0], ab[1])
			}
			r := diff(t, ab[0], ab[1])
			listed := r.Counts.Defaults + r.Counts.TestsReduced + r.Counts.Semantic
			if r.SemanticallyEqual || r.Equal || listed == 0 || len(r.Changes) == 0 {
				t.Errorf("%s against %s: unchanged or only reformatted: %+v", ab[0], ab[1], r.Counts)
			}
		}
	}
	// The pair the ruling names: both read as one entry named "" with the same value.
	r := diff(t, `{"groups":{"":["a"]}}`, `{"groups":["a"]}`)
	if r.SemanticallyEqual || r.Counts.Semantic != 1 || len(r.Changes) != 1 {
		t.Fatalf("a real entry named nothing against a wrong-typed section: %+v", r)
	}
	if ch := r.Changes[0]; ch.Section != "groups" || ch.Op != OpChanged || ch.Note == "" || ch.OldPointer != "/groups" || ch.NewPointer != "/groups" ||
		strings.Contains(ch.Old.Text+ch.New.Text, "\x1f") {
		t.Errorf("the change: %+v", ch)
	}
	// Two wrong-typed values are compared as values, in every section shape.
	for _, p := range [][2]string{
		{`{"groups":["a"]}`, `{"groups":["b"]}`},
		{`{"acls":{"a":1}}`, `{"acls":{"a":2}}`},
		{`{"ssh":{"a":1}}`, `{"ssh":{"a":2}}`},
		{`{"tests":{"a":1}}`, `{"tests":{"a":2}}`},
		{`{"sshTests":7}`, `{"sshTests":8}`},
		{`{"nodeAttrs":"a"}`, `{"nodeAttrs":"b"}`},
		{`{"derpMap":[1]}`, `{"derpMap":[2]}`},
		{`{"defaultSrcPosture":"a"}`, `{"defaultSrcPosture":"b"}`},
		{`{"extraDNSRecords":1}`, `{"extraDNSRecords":2}`},
		{`{"mystery":1}`, `{"mystery":2}`},
	} {
		if r := diff(t, p[0], p[1]); r.SemanticallyEqual || len(r.Changes) == 0 {
			t.Errorf("%s against %s: %+v", p[0], p[1], r.Counts)
		}
		if r := diff(t, p[0], p[0]); !r.SemanticallyEqual {
			t.Errorf("%s against itself: %+v", p[0], r.Counts)
		}
	}
	// A wrong-typed list of tests that replaces real ones is a reduction of them.
	r = diff(t, `{"tests":[{"src":"a","accept":["x:1"]}]}`, `{"tests":{"src":"a"}}`)
	if r.Counts.TestsReduced != 1 || r.TestsAfter != 0 {
		t.Errorf("tests replaced by an object: %+v", r)
	}
	r = diff(t, `{"tests":{"src":"a"}}`, `{"tests":[{"src":"a","accept":["x:1"]}]}`)
	if r.Counts.TestsReduced != 0 || r.Counts.Semantic != 1 || r.TestsBefore != 0 {
		t.Errorf("an object replaced by tests: %+v", r)
	}
	// Added or removed, a wrong-typed section is an entry of its own.
	r = diff(t, `{}`, `{"groups":["a"]}`)
	if len(r.Changes) != 1 || r.Changes[0].Op != OpAdded || r.Changes[0].Old.Text != "" {
		t.Errorf("a wrong-typed section added: %+v", r.Changes)
	}
	// An unknown section that is null is absent, and a known one is too.
	if r := diff(t, `{"mystery":null,"groups":{"a":[]}}`, `{"groups":{"a":[]}}`); !r.SemanticallyEqual {
		t.Errorf("null unknown section: %+v", r.Changes)
	}
}

// Diff says "equal" exactly when the normal forms are, in the dangerous direction above all:
// nothing the normal form keeps may be unreported. Every edit below changes what one section
// holds; each must be seen, and each rewrite must not be.
func TestDiffIsEqualExactlyWhenTheNormalFormsAre(t *testing.T) {
	base := string(fixture(t, "basic.hujson"))
	edits := [][2]string{
		{`"amy@example.com"`, `"zed@example.com"`},
		{`"tag:router": ["autogroup:admin"]`, `"tag:router": []`},
		{`"build-box": "192.0.2.10"`, `"build-box": "192.0.2.11"`},
		{`"remove 198.51.100.7"`, `"remove 198.51.100.8"`},
		{`"onFailure": "deny"`, `"onFailure": "allow"`},
		{`"defaultSrcPosture": ["posture:managed"]`, `"defaultSrcPosture": []`},
		{`"tag:web:80,443"`, `"tag:web:80,444"`},
		{`"proto": "tcp"`, `"proto": "udp"`},
		{`"group:eng", "group:ops"], "dst": ["tag:db:5432"]`, `"group:eng"], "dst": ["tag:db:5432"]`},
		{`"tcp:22", "udp:53"`, `"tcp:22", "udp:54"`},
		{`{"role": "admin"}`, `{"role": "user"}`},
		{`"checkPeriod": "12h"`, `"checkPeriod": "24h"`},
		{`"users": ["root"]`, `"users": ["nobody"]`},
		{`"attr": ["funnel"]`, `"attr": ["nofunnel"]`},
		{`"domains": ["example.com"]`, `"domains": ["example.org"]`},
		{`"exitNode": ["tag:router"]`, `"exitNode": ["tag:db"]`},
		{`"198.51.100.0/24": ["tag:router"]`, `"198.51.100.0/24": ["tag:db"]`},
		{`"Value": "192.0.2.10"`, `"Value": "192.0.2.11"`},
		{`"accept": ["tag:web:443"]`, `"accept": ["tag:web:444"]`},
		{`"deny": ["root"]`, `"deny": []`},
		{`"disableIPv4": false`, `"disableIPv4": true`},
		{`"randomizeClientPort": true`, `"randomizeClientPort": false`},
		{`"disableIPv4": false,`, `"disableIPv4": false, "newSection": 1,`},
		{`"disableIPv4": false,`, ``},
		{`"autoApprovers": {`, `"autoApprovers": {"services": {"svc:a": ["tag:db"]},`},
		{`"hosts": {`, `"hosts": {"": "192.0.2.99",`},
		{`"posture:latest": {`, `"posture:other": {"assertions": ["x"]}, "posture:latest": {`},
		{`"src": ["group:ops"], "dst": ["tag:router"]`, `"src": ["group:ops"], "dst": ["tag:router", "tag:db"]`},
		{`"ip": ["*"]`, `"ip": ["*"], "via": ["tag:router"]`},
		{`"action": "check"`, `"action": "accept"`},
		{`"dst": ["tag:web"], "accept": ["alice"]`, `"dst": ["tag:web"], "accept": ["bob"]`},
	}
	rewrites := [][2]string{
		{`"disableIPv4": false,`, `"disableIPv4": false ,   // a comment` + "\n"},
		{`["amy@example.com", "bo@example.com"]`, `["bo@example.com", "amy@example.com"]`},
		{`"acls": [`, `"ACLS": [`},
		{`"tag:ci":     [],`, `"tag:ci": [] , `},
		{`"remove 198.51.100.7"`, `"remove 198.51.100.7" /* c */`},
		{`"group:eng", "group:ops"], "dst": ["tag:db:5432"]`, `"group:ops", "group:eng", "group:ops"], "dst": ["tag:db:5432"]`},
		{`"hosts": {`, `"Hosts": {`},
	}
	nf := func(text string) []byte {
		n, err := Normalise(context.Background(), mustParse(t, text))
		if err != nil {
			t.Fatal(err)
		}
		return n.Bytes()
	}
	check := func(label, a, b string, wantEqual bool) {
		t.Helper()
		for _, ab := range [][2]string{{a, b}, {b, a}} {
			r := diff(t, ab[0], ab[1])
			same := bytes.Equal(nf(ab[0]), nf(ab[1]))
			if r.SemanticallyEqual != same {
				t.Errorf("%s: Diff says equal %v, the normal forms are equal %v (%+v)", label, r.SemanticallyEqual, same, r.Counts)
			}
			if same != wantEqual {
				t.Errorf("%s: the edit was meant to be equal=%v", label, wantEqual)
			}
		}
	}
	for _, e := range edits {
		check(e[0]+" -> "+e[1], base, replaceOnce(base, e[0], e[1]), false)
	}
	for _, e := range rewrites {
		check(e[0]+" -> "+e[1], base, replaceOnce(base, e[0], e[1]), true)
	}
}

// Everything a result builds is cut or counted before it is built: a value of megabytes in
// a change costs a page a kilobyte, and the figures it reports are the whole's.
func TestWhatAChangeShowsIsCutBeforeItIsBuilt(t *testing.T) {
	big := strings.Repeat("b", 300000)
	rule := func(ports string) string {
		return `{"action": "accept", "src": ["a", "` + big + `"], "dst": ["` + big + `:` + ports + `"], "srcPosture": ["` + big + `"], "app": {"k": ["` + big + `"]}}`
	}
	a := mustParse(t, `{"acls": [`+rule("80")+`]}`)
	b := mustParse(t, `{"acls": [`+rule("81")+`]}`)
	m := newMeter(context.Background())
	na, err := normaliseWith(m, a)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := normaliseWith(m, b)
	if err != nil {
		t.Fatal(err)
	}
	d := &comparer{m: m, oa: a, ob: b, na: na, nb: nb}
	var oracle []string
	var want []string
	for _, as := range [][]*atom{na.atoms, nb.atoms} {
		var parts []string
		for _, at := range as {
			parts = append(parts, oracleAtomJSON(at))
		}
		oracle = append(oracle, strings.Join(parts, "; "))
		want = append(want, capText(strings.Join(parts, "; ")))
	}
	for i, as := range [][]*atom{na.atoms, nb.atoms} {
		var tb textBuf
		before := heapAlloc()
		if err := d.atomsText(&tb, as); err != nil {
			t.Fatal(err)
		}
		alloc := heapAlloc() - before
		got := tb.text()
		if got.Len != len(oracle[i]) || got.Text != want[i] || !got.Truncated {
			t.Errorf("side %d: len %d (want %d), truncated %v, text equal %v", i, got.Len, len(oracle[i]), got.Truncated, got.Text == want[i])
		}
		if alloc > 64<<10 {
			t.Errorf("side %d: showing %d bytes of text allocated %d bytes", i, got.Len, alloc)
		}
	}
	// The whole path: a change whose texts are megabytes shows a kilobyte of each.
	r, err := Diff(context.Background(), a, b, DiffOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Changes) != 1 {
		t.Fatalf("changes: %d", len(r.Changes))
	}
	if ch := r.Changes[0]; len(ch.Old.Text) > maxPointer+len(ellipsis) || len(ch.New.Text) > maxPointer+len(ellipsis) || len(ch.Key) > maxPointer+len(ellipsis) ||
		ch.Old.Len < 4*len(big) || !ch.Old.Truncated {
		t.Errorf("a change of megabytes: old %d of %d, new %d, key %d", len(ch.Old.Text), ch.Old.Len, len(ch.New.Text), len(ch.Key))
	}

	// A pointer and a key built from a name of a megabyte are cut as they are built.
	name := strings.Repeat("n", 1<<20)
	ha := mustParse(t, `{"hosts": {"`+name+`": "192.0.2.1"}}`)
	hb := mustParse(t, `{"hosts": {"`+name+`": "192.0.2.2"}}`)
	before := heapAlloc()
	hr, err := Diff(context.Background(), ha, hb, DiffOptions{})
	if err != nil || len(hr.Changes) != 1 {
		t.Fatalf("a long key: %v %+v", err, hr)
	}
	ch := hr.Changes[0]
	for _, s := range []string{ch.Key, ch.OldPointer, ch.NewPointer} {
		if len(s) > maxPointer+len(ellipsis) {
			t.Errorf("a name of a megabyte shown as %d bytes", len(s))
		}
	}
	// A pointer reads a name only as far as the cut shows it.
	hn, err := Normalise(context.Background(), ha)
	if err != nil {
		t.Fatal(err)
	}
	at := hn.secs[sectionPos("hosts")].entries[0].ref
	before2 := heapAlloc()
	pointer := ha.pointerOf(at)
	if alloc := heapAlloc() - before2; alloc > 64<<10 || len(pointer) > maxPointer+len(ellipsis) || !strings.HasPrefix(pointer, "/hosts/nnnn") {
		t.Errorf("a pointer through a name of a megabyte: %d bytes allocated, %d shown", alloc, len(pointer))
	}
	// Normalising holds the name a few times; showing it adds nothing near a copy for each place.
	if alloc := heapAlloc() - before; alloc > 40<<20 {
		t.Errorf("a long key: %d bytes allocated", alloc)
	}

	// The fields of a node attribute entry: the targets are shown to the cut.
	var targets strings.Builder
	for i := range 20000 {
		fmt.Fprintf(&targets, `"tag:t%05d",`, i)
	}
	ta := mustParse(t, `{"nodeAttrs": [{"target": [`+targets.String()+`], "attr": ["x"]}]}`)
	tb2 := mustParse(t, `{"nodeAttrs": [{"target": [`+targets.String()+`"tag:more"], "attr": ["x"]}]}`)
	tr, err := Diff(context.Background(), ta, tb2, DiffOptions{})
	if err != nil || len(tr.Changes) != 1 {
		t.Fatalf("targets: %v %+v", err, tr)
	}
	if ch := tr.Changes[0]; !ch.Old.Truncated || ch.Old.Len < 200000 || len(ch.Old.Text) > maxPointer+len(ellipsis) || fmt.Sprint(ch.Fields[0].Added) != "[tag:more]" {
		t.Errorf("targets: old %d of %d, delta %v", len(ch.Old.Text), ch.Old.Len, ch.Fields)
	}
}

// oracleAtomJSON writes an atom the plain way, without any cut: what atomsText must equal.
func oracleAtomJSON(a *atom) string {
	var b strings.Builder
	b.WriteString(`{"dst":` + string(appendJSONString(nil, a.dst)))
	if a.proto != "" {
		b.WriteString(`,"proto":` + string(appendJSONString(nil, a.proto)))
	}
	if a.act != "" {
		b.WriteString(`,"action":` + string(appendJSONString(nil, a.act)))
	}
	b.WriteString(`,"ports":` + string(appendJSONString(nil, a.pkey)) + `,"src":[`)
	for i, it := range a.src.items {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(appendJSONString(nil, it))
	}
	b.WriteString("]")
	if a.posture != "" {
		b.WriteString(`,"srcPosture":[` + a.posture + `]`)
	}
	if a.via != "" {
		b.WriteString(`,"via":[` + a.via + `]`)
	}
	if a.app != "" {
		b.WriteString(`,"app":` + a.app)
	}
	if a.extra != "" {
		b.WriteString(`,"extra":` + a.extra)
	}
	b.WriteString("}")
	return b.String()
}

func heapAlloc() uint64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.TotalAlloc
}

func TestTheLengthOfAQuotedStringIsCountedWithoutBuildingIt(t *testing.T) {
	for _, s := range []string{
		"", "plain", `a"b\c`, "line\nfeed\rreturn\ttab", "\x00\x01\x1f\x7f", "caf\xc3\xa9 \xe2\x80\xa6 \xf0\x9f\x98\x80",
		"bad \xff\xfe bytes", "lone \xed\xa0\x80 surrogate", strings.Repeat("x\"y", 1000), "tail \xc3",
	} {
		if got, want := quotedLen(s), len(appendJSONString(nil, s)); got != want {
			t.Errorf("%q: counted %d, written %d", s, got, want)
		}
	}
	// A text builder holds the head and the length of everything written to it.
	var tb textBuf
	m := newMeter(context.Background())
	long := strings.Repeat("\xc3\xa9", 5000)
	if err := tb.quoted(m, long); err != nil {
		t.Fatal(err)
	}
	if err := tb.quoted(m, "after"); err != nil {
		t.Fatal(err)
	}
	got := tb.text()
	full := string(appendJSONString(nil, long)) + string(appendJSONString(nil, "after"))
	if got.Len != len(full) || got.Text != capText(full) || !got.Truncated {
		t.Errorf("len %d (want %d), text equal %v", got.Len, len(full), got.Text == capText(full))
	}
	if !strings.HasPrefix(got.Text, `"`+"\xc3\xa9") {
		t.Errorf("the head: %.20q", got.Text)
	}
}

// The cursor's digest reads both normal forms, and what it reads is paid for.
func TestTheCursorDigestIsMetered(t *testing.T) {
	a := mustParse(t, string(fixture(t, "basic.hujson")))
	b := mustParse(t, `{}`)
	m := newMeter(context.Background())
	na, _ := normaliseWith(m, a)
	nb, _ := normaliseWith(m, b)
	d := &comparer{m: m, oa: a, ob: b, na: na, nb: nb}
	before := m.used
	sum, err := d.digest(DiffOptions{}, "")
	if err != nil || len(sum) != 16 {
		t.Fatalf("digest: %q %v", sum, err)
	}
	if spent, need := m.used-before, int64(len(na.Bytes())+len(nb.Bytes())); spent < need {
		t.Errorf("the digest read %d bytes and was charged %d", need, spent)
	}
	// It is the same twice, and differs with the section and the ignore flag.
	again, _ := d.digest(DiffOptions{}, "")
	other, _ := d.digest(DiffOptions{}, "hosts")
	ignoring, _ := d.digest(DiffOptions{IgnoreTailscaleWritten: true}, "")
	if again != sum || other == sum || ignoring == sum {
		t.Errorf("digests: %s %s %s %s", sum, again, other, ignoring)
	}
}

// What Diff builds beyond the two normal forms is small whatever the shape of the input, and
// all of it is paid for out of the work budget.
func TestWhatADiffBuildsIsBoundedByTheWorkBudget(t *testing.T) {
	old := maxWork
	maxWork = 1 << 22
	t.Cleanup(func() { maxWork = old })
	item := strings.Repeat("i", 2000)
	var many, manyTo strings.Builder
	for i := range 100 {
		fmt.Fprintf(&many, `{"action": "accept", "src": ["s%03d", "%s"], "dst": ["d%03d:1"]},`, i, item, i)
		fmt.Fprintf(&manyTo, `{"action": "accept", "src": ["s%03d", "%s"], "dst": ["d%03d:2"]},`, i, item, i)
	}
	for name, c := range map[string][2]string{
		"changed rules that share a large source": {`{"acls": [` + many.String() + `]}`, `{"acls": [` + manyTo.String() + `]}`},
		"a large key": {`{"hosts": {"` + item + `": "192.0.2.1"}}`, `{"hosts": {"` + item + `": "192.0.2.2"}}`},
	} {
		a, b := mustParse(t, c[0]), mustParse(t, c[1])
		before := heapAlloc()
		_, errA := Normalise(context.Background(), a)
		_, errB := Normalise(context.Background(), b)
		normalising := heapAlloc() - before
		before = heapAlloc()
		r, err := Diff(context.Background(), a, b, DiffOptions{PageSize: MaxPage})
		diffing := heapAlloc() - before
		if errA != nil || errB != nil {
			t.Fatalf("%s: normalising gave %v and %v", name, errA, errB)
		}
		if err != nil {
			// Both normal forms and the comparison are one budget: refusing is right.
			if !errors.Is(err, ErrTooComplex) {
				t.Fatalf("%s: %v", name, err)
			}
			t.Logf("%s: refused", name)
			continue
		}
		t.Logf("%s: %d changes listed, %d bytes for the normal forms, %d for Diff", name, len(r.Changes), normalising, diffing)
		if extra := int64(diffing) - int64(normalising); extra > 4<<20 {
			t.Errorf("%s: Diff allocated %d bytes beyond the normal forms (%d)", name, extra, normalising)
		}
		for _, ch := range r.Changes {
			if len(ch.Old.Text) > maxPointer+len(ellipsis) || len(ch.New.Text) > maxPointer+len(ellipsis) {
				t.Errorf("%s: a text of %d bytes", name, len(ch.New.Text))
			}
		}
	}
}

// Every stage of a comparison pays for what it does and refuses, with nothing partial, when
// the budget runs out: a budget short by any amount gives too_complex, never a page that
// leaves a change out.
func TestEveryStageRefusesWhenTheBudgetRunsOut(t *testing.T) {
	var a, b strings.Builder
	a.WriteString(`{"groups": {`)
	b.WriteString(`{"groups": {`)
	for i := range 70 {
		fmt.Fprintf(&a, `"group:k%03d": ["old"],`, i)
		fmt.Fprintf(&b, `"group:k%03d": ["new"],`, i)
	}
	a.WriteString(`}, "tests": [{"src": "a", "accept": ["x:1", "x:2"]}], "ssh": [{"action": "check", "src": ["g"], "dst": ["t"], "users": ["u"]}],
		"acls": [{"action": "accept", "src": ["a", "b"], "dst": ["x:80"], "srcPosture": ["posture:p"]}, {"action": "accept", "src": ["a"], "dst": ["y:1"]}],
		"nodeAttrs": [{"target": ["tag:a"], "attr": ["x"]}], "defaultSrcPosture": ["posture:p"], "mystery": 1, "hosts": {"h": "192.0.2.1"}}`)
	b.WriteString(`}, "tests": [{"src": "a", "accept": ["x:1"]}], "ssh": [{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["u", "root"]}],
		"acls": [{"action": "accept", "src": ["*", "b"], "dst": ["x:80,81"]}, {"action": "accept", "src": ["logstream@tailscale"], "dst": ["z:443"]}],
		"nodeAttrs": [{"target": ["tag:a", "tag:b"], "attr": ["x"]}, {"target": ["tag:a"], "attr": ["funnel"]}], "other": 2, "hosts": {"h": "192.0.2.2"}}`)
	da, db := mustParse(t, a.String()), mustParse(t, b.String())
	old := maxWork
	t.Cleanup(func() { maxWork = old })
	r, err := Diff(context.Background(), da, db, DiffOptions{})
	if err != nil || !r.Truncated || r.Counts.Widening == 0 || r.Counts.TestsReduced == 0 {
		t.Fatalf("the pair no longer exercises every stage: %v %+v", err, r.Counts)
	}
	ops := r.Ops
	refused := 0
	for k := int64(0); k < ops; k += max(1, ops/600) {
		maxWork = k
		if res, err := Diff(context.Background(), da, db, DiffOptions{}); !errors.Is(err, ErrTooComplex) || res != nil {
			t.Fatalf("a budget of %d of %d: %v, %v", k, ops, res, err)
		}
		refused++
	}
	// The page after a cursor pays for the digest and for its own changes too.
	maxWork = old
	r2, err := Diff(context.Background(), da, db, DiffOptions{Cursor: r.NextChange})
	if err != nil {
		t.Fatal(err)
	}
	for k := int64(0); k < r2.Ops; k += max(1, r2.Ops/300) {
		maxWork = k
		if _, err := Diff(context.Background(), da, db, DiffOptions{Cursor: r.NextChange}); !errors.Is(err, ErrTooComplex) {
			t.Fatalf("a budget of %d of %d, with a cursor: %v", k, r2.Ops, err)
		}
	}
	if refused < 100 {
		t.Errorf("only %d budgets tried", refused)
	}
	// A context that is done part way is the context's error, never a partial answer.
	maxWork = old
	var rules strings.Builder
	for i := range 3000 {
		fmt.Fprintf(&rules, `{"action": "accept", "src": ["s%04d"], "dst": ["d%04d:1"]},`, i, i)
	}
	big := mustParse(t, `{"acls": [`+rules.String()+`]}`)
	canceled := 0
	for left := 0; left < 12; left++ {
		_, err := Diff(&countdownCtx{Context: context.Background(), left: left}, big, db, DiffOptions{})
		if errors.Is(err, context.Canceled) {
			canceled++
		} else if err != nil {
			t.Fatalf("left %d: %v", left, err)
		}
	}
	if canceled == 0 {
		t.Error("the context was never asked")
	}
}

// countdownCtx says it is done after it has been asked left times.
type countdownCtx struct {
	context.Context
	left int
}

func (c *countdownCtx) Err() error {
	if c.left <= 0 {
		return context.Canceled
	}
	c.left--
	return nil
}

func TestAChangedGroupOfSeveralAtomsNamesEverythingItGainedAndLost(t *testing.T) {
	r := diff(t, `{"acls": [
		{"action": "accept", "src": ["a"], "dst": ["x:80"], "proto": "tcp"},
		{"action": "accept", "src": ["b"], "dst": ["x:90"], "proto": "tcp"},
		{"action": "accept", "src": ["d"], "dst": ["x:95"], "proto": "tcp"}]}`,
		`{"acls": [
		{"action": "accept", "src": ["a"], "dst": ["x:80"], "proto": "tcp"},
		{"action": "accept", "src": ["c"], "dst": ["x:100"], "proto": "tcp"},
		{"action": "accept", "src": ["e"], "dst": ["x:110"], "proto": "tcp"}]}`)
	if len(r.Changes) != 1 {
		t.Fatalf("changes: %+v", r.Changes)
	}
	ch := r.Changes[0]
	if ch.Key != "x tcp" || len(ch.Fields) != 2 || fmt.Sprint(ch.Fields[0].Added) != "[c e]" || fmt.Sprint(ch.Fields[0].Removed) != "[b d]" ||
		fmt.Sprint(ch.Fields[1].Added) != "[100,110]" || fmt.Sprint(ch.Fields[1].Removed) != "[90,95]" {
		t.Errorf("fields: %+v", ch.Fields)
	}
	// Both atoms of a side are shown, in one text, and the place is the first of them in the text.
	if strings.Count(ch.Old.Text, `"dst":"x"`) != 2 || !strings.Contains(ch.Old.Text, "; ") || !strings.Contains(ch.Old.Text, `"proto":"tcp"`) || ch.OldLine != 3 || ch.NewLine != 3 {
		t.Errorf("texts: %q at %d", ch.Old.Text, ch.OldLine)
	}
	// A rule that is not an accept rule names its action.
	r = diff(t, `{"acls": [{"action": "reject", "src": ["a"], "dst": ["x:1"]}]}`, `{"acls": [{"action": "reject", "src": ["a"], "dst": ["x:2"]}]}`)
	if ch := r.Changes[0]; !strings.Contains(ch.Old.Text, `"action":"reject"`) {
		t.Errorf("the action: %q", ch.Old.Text)
	}
	// A rule that is not an object is shown as what it is, and the extra fields of one are kept.
	r = diff(t, `{"acls": [7, {"action": "accept", "src": ["a"], "dst": ["x:1"], "future": [1]}]}`, `{"acls": [8, {"action": "accept", "src": ["a"], "dst": ["x:1"], "future": [2]}]}`)
	if r.Counts.Semantic != 4 {
		t.Errorf("opaque rules and extra fields: %+v", r.Counts)
	}
	var texts string
	for _, c := range r.Changes {
		texts += c.Old.Text + c.New.Text
	}
	if !strings.Contains(texts, `"extra":{"future":[1]}`) || !strings.Contains(texts, `"extra":{"future":[2]}`) {
		t.Errorf("the extra fields are not shown: %q", texts)
	}
	// Posture, via and app are shown too.
	r = diff(t, `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["1"], "srcPosture": ["posture:p"], "via": ["tag:v"], "app": {"k": [1]}}]}`, `{}`)
	if ch := r.Changes[len(r.Changes)-1]; !strings.Contains(ch.Old.Text, `"srcPosture":["posture:p"]`) || !strings.Contains(ch.Old.Text, `"via":["tag:v"]`) || !strings.Contains(ch.Old.Text, `"app":{"k":[1]}`) {
		t.Errorf("qualifiers: %q", ch.Old.Text)
	}
}

func TestUnquotingTheHeadOfAnEncodedString(t *testing.T) {
	for _, s := range []string{"", "plain", `a"b\c`, "line\nfeed\rreturn\ttab", "\x01\x1f\x7f", "caf\xc3\xa9 \xe2\x80\xa6"} {
		if got := unquoteHead(string(appendJSONString(nil, s)), 1<<20); got != s {
			t.Errorf("%q came back as %q", s, got)
		}
	}
	if got := unquoteHead(string(appendJSONString(nil, strings.Repeat("ab", 100))), 10); len(got) < 10 || len(got) > 12 || !strings.HasPrefix(got, "abab") {
		t.Errorf("a cut head: %q", got)
	}
	// What the encoder never writes is read as itself and never panics.
	for _, q := range []string{`"`, `"x`, `"\`, `"` + "\\" + `u12"`, `"` + "\\" + `uzzzz"`, `"` + "\\" + `q"`} {
		_ = unquoteHead(q, 100)
	}
}

func TestAnAssertionIsShownDecodedAndCut(t *testing.T) {
	long := strings.Repeat("s", 3000)
	r := diff(t, `{"tests": [{"src": "`+long+`", "accept": ["x:1"]}], "sshTests": [{"src": "a\u0001b", "dst": ["t\n"], "accept": ["u"]}]}`, `{}`)
	for _, c := range r.Changes {
		if len(c.Key) > maxPointer+len(ellipsis) {
			t.Errorf("a key of %d bytes", len(c.Key))
		}
		if c.Section == "sshTests" && !strings.Contains(c.Key, "a\x01b -> t\n accept u") {
			t.Errorf("the key of an SSH test: %q", c.Key)
		}
	}
	if !strings.Contains(assertionKey("not an identity"), "not an identity") {
		t.Error("a key of another shape is shown as it is")
	}
}

func TestWhatIsLongInAnEntryIsCutAndCounted(t *testing.T) {
	var a, b strings.Builder
	for i := range 800 {
		fmt.Fprintf(&a, `"member-%04d@example.com",`, i)
		fmt.Fprintf(&b, `"member-%04d@example.org",`, i)
	}
	r := diff(t, `{"groups": {"group:big": [`+a.String()+`]}}`, `{"groups": {"group:big": [`+b.String()+`]}}`)
	ch := r.Changes[0]
	if !ch.Old.Truncated || !ch.New.Truncated || ch.Old.Len < 20000 || len(ch.Old.Text) > maxPointer+len(ellipsis) {
		t.Errorf("a group of 800 members: %d shown of %d", len(ch.Old.Text), ch.Old.Len)
	}
	if !strings.HasSuffix(ch.Old.Text, ellipsis) {
		t.Error("a cut text ends in an ellipsis")
	}
}

func TestUnknownSectionsAreMatchedWithoutRegardToCase(t *testing.T) {
	r := diff(t, `{"Mystery": 1}`, `{"mystery": 1}`)
	if !r.SemanticallyEqual || r.Counts.FormatOnly == 0 {
		t.Errorf("another spelling: %+v", r)
	}
	r = diff(t, `{"Mystery": 1, "zeta": 1}`, `{"mystery": 2, "alpha": 1}`)
	got := map[string]Op{}
	for _, c := range r.Changes {
		got[strings.ToLower(c.Section)] = c.Op
	}
	if got["mystery"] != OpChanged || got["zeta"] != OpRemoved || got["alpha"] != OpAdded || len(got) != 3 {
		t.Errorf("unknown sections: %v", got)
	}
	// Listed in a fixed order, whatever order the texts write them in.
	x := diff(t, `{}`, `{"b": 1, "a": 1, "c": 1}`, DiffOptions{Section: "unknown"})
	y := diff(t, `{}`, `{"c": 1, "b": 1, "a": 1}`, DiffOptions{Section: "unknown"})
	if fmt.Sprint(x.Changes) != fmt.Sprint(y.Changes) || len(x.Changes) != 3 {
		t.Errorf("order:\n%v\n%v", x.Changes, y.Changes)
	}
}

func TestADefaultPostureIsPointedAtAndTheLiveSideCanLoseOne(t *testing.T) {
	r := diff(t, `{"defaultSrcPosture": ["posture:p"]}`, `{}`)
	ch := find(t, r, ClassWidening, "defaultSrcPosture")
	if ch.Op != OpRemoved || ch.OldPointer != "/defaultSrcPosture" || ch.OldLine != 1 || ch.Section != "defaultSrcPosture" {
		t.Errorf("default posture: %+v", ch)
	}
	// Emptied is removed too.
	if r := diff(t, `{"defaultSrcPosture": ["posture:p"]}`, `{"defaultSrcPosture": []}`); r.Counts.Widening != 1 {
		t.Errorf("emptied: %+v", r.Counts)
	}
	// Section filters select the widening of their own section.
	r = diff(t, `{"defaultSrcPosture": ["posture:p"], "ssh": [{"action": "check", "src": ["g"], "dst": ["t"], "users": ["u"]}]}`, `{"ssh": [{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["u"]}]}`, DiffOptions{Section: "ssh"})
	if r.Counts.Widening != 2 || r.Matched == 0 || len(r.Changes) != r.Matched {
		t.Errorf("ssh: %+v", r)
	}
	for _, c := range r.Changes {
		if c.Section != "ssh" {
			t.Errorf("section %q under the ssh filter", c.Section)
		}
	}
}

// A generated pair is equal exactly when its normal forms are: the sections are drawn from
// pools that hold every shape, the wrong-typed values, nulls and repeats among them, and the
// two sides are drawn independently.
func TestGeneratedPairsAreEqualExactlyWhenTheirNormalFormsAre(t *testing.T) {
	pools := map[string][]string{
		"acls":              {``, `null`, `[]`, `{}`, `7`, `[{"action":"accept","src":["a"],"dst":["x:1"]}]`, `[{"action":"accept","src":["a","b"],"dst":["x:1","y:2"]}]`, `[{"action":"accept","src":["a"],"dst":["x:1"]},{"action":"accept","src":["b"],"dst":["x:1"]}]`, `[{"action":"accept","src":["a","b"],"dst":["x:1"]}]`, `[{"action":"accept","src":["a"],"dst":["x:1"],"srcPosture":["p"]}]`},
		"Grants":            {``, `[]`, `{}`, `[{"src":["a"],"dst":["x"],"ip":["1"]}]`, `[{"src":["a"],"dst":["x"],"ip":["tcp:1"]}]`},
		"groups":            {``, `null`, `{}`, `[]`, `{"":["a"]}`, `["a"]`, `{"g":["a"]}`, `{"g":["b","a"]}`, `{"g":["a","b"]}`, `{"g":["a"],"G":["a"]}`},
		"hosts":             {``, `{}`, `{"":"192.0.2.1"}`, `"192.0.2.1"`, `{"h":"192.0.2.1"}`},
		"ssh":               {``, `null`, `[]`, `{}`, `[{"action":"accept","src":["a"],"dst":["t"],"users":["u"]}]`, `[{"action":"check","src":["a"],"dst":["t"],"users":["u"]}]`, `[{"action":"accept","src":["a"],"dst":["t"],"users":["u"]},{"action":"accept","src":["a"],"dst":["t"],"users":["u"]}]`},
		"tests":             {``, `[]`, `{}`, `[{"src":"a","accept":["x:1"]}]`, `[{"src":"a","accept":["x:1","x:2"]}]`, `[{"src":"a","accept":["x:1"]},{"src":"a","accept":["x:2"]}]`, `[{"src":"a","deny":["x:1"]}]`, `[3]`},
		"sshTests":          {``, `[]`, `{}`, `[{"src":"a","dst":["t"],"accept":["u"]}]`},
		"nodeAttrs":         {``, `[]`, `{}`, `[{"target":["a"],"attr":["x"]}]`, `[{"target":["a","b"],"attr":["x"]}]`, `[{"target":["a"],"attr":["x"]},{"target":["b"],"attr":["x"]}]`, `[{"target":["a"],"attr":["funnel"]}]`, `[4]`},
		"tagOwners":         {``, `{}`, `{"tag:a":[]}`, `{"tag:a":["autogroup:admin"]}`, `{"":[]}`, `[]`},
		"autoApprovers":     {``, `{}`, `{"routes":{"192.0.2.0/24":["a"]}}`, `{"exitNode":["a"]}`, `{"":["a"]}`, `[]`},
		"derpMap":           {``, `{}`, `{"regions":{"1":{"regionID":1}}}`, `{"":1}`, `1`},
		"defaultSrcPosture": {``, `[]`, `["p"]`, `["q","p"]`, `"p"`},
		"disableIPv4":       {``, `true`, `false`, `null`},
		"extraDNSRecords":   {``, `[]`, `[{"Name":"a","Value":"b"}]`, `{}`},
		"mystery":           {``, `null`, `1`, `{"a":1}`, `[1]`},
		"ipsets":            {``, `{}`, `{"s":["add 1","remove 2"]}`, `{"s":["remove 2","add 1"]}`},
	}
	names := make([]string, 0, len(pools))
	for n := range pools {
		names = append(names, n)
	}
	slices.Sort(names)
	rng := rand.New(rand.NewPCG(7, 11))
	// A draw is one fragment of each pool; the other side of a pair keeps most of them, so
	// that the pairs fall on both sides of equal.
	draw := func(from []int) ([]int, string) {
		pick := make([]int, len(names))
		var b strings.Builder
		b.WriteString("{")
		for i, n := range names {
			pool := pools[n]
			pick[i] = rng.IntN(len(pool))
			if from != nil && rng.IntN(10) != 0 {
				pick[i] = from[i]
			}
			if v := pool[pick[i]]; v != "" {
				fmt.Fprintf(&b, "%q: %s,", n, v)
			}
		}
		b.WriteString("}")
		return pick, b.String()
	}
	nf := func(d *Doc) []byte {
		n, err := Normalise(context.Background(), d)
		if err != nil {
			t.Fatal(err)
		}
		return n.Bytes()
	}
	equal, unequal := 0, 0
	for range 3000 {
		pick, x := draw(nil)
		_, y := draw(pick)
		dx, dy := mustParse(t, x), mustParse(t, y)
		same := bytes.Equal(nf(dx), nf(dy))
		r, err := Diff(context.Background(), dx, dy, DiffOptions{PageSize: MaxPage})
		if err != nil {
			t.Fatal(err)
		}
		if r.SemanticallyEqual != same {
			t.Fatalf("Diff says equal %v, the normal forms are equal %v:\n%s\n%s\n%+v", r.SemanticallyEqual, same, x, y, r.Counts)
		}
		if same {
			equal++
		} else {
			unequal++
			if r.Counts.Defaults+r.Counts.TestsReduced+r.Counts.Widening+r.Counts.TailscaleWritten+r.Counts.Semantic != len(r.Changes) && !r.Truncated {
				t.Fatalf("the counts and the list disagree:\n%s\n%s\n%+v %d", x, y, r.Counts, len(r.Changes))
			}
		}
		// A comparison and its mirror agree on whether there is a difference.
		if rr := diff(t, y, x); rr.SemanticallyEqual != r.SemanticallyEqual {
			t.Fatalf("mirror:\n%s\n%s", x, y)
		}
	}
	if equal < 20 || unequal < 1000 {
		t.Errorf("the draw gave %d equal pairs and %d unequal ones", equal, unequal)
	}
}

// atomsText writes exactly what the plain writer would, cut at 1 KiB, and reports the length
// of the whole: the cut can fall in any field, in the middle of a set, or in a string.
func TestAtomsTextEqualsThePlainWriterWhereverTheCutFalls(t *testing.T) {
	var items strings.Builder
	for i := range 700 {
		fmt.Fprintf(&items, `"member-%04d-caf\u00e9\n\"q\"",`, i)
	}
	long := strings.Repeat("\u00e9", 4000)
	for name, rule := range map[string]string{
		"a short rule":                   `{"action": "accept", "src": ["a"], "dst": ["x:1"]}`,
		"a long source list":             `{"action": "accept", "src": [` + items.String() + `], "dst": ["x:1"]}`,
		"one long source":                `{"action": "accept", "src": ["a", "` + long + `"], "dst": ["x:1"]}`,
		"a long destination":             `{"action": "accept", "src": ["a"], "dst": ["` + long + `:1"]}`,
		"a protocol and an action":       `{"action": "other", "proto": "tcp", "src": ["a"], "dst": ["x:1"]}`,
		"long qualifiers":                `{"action": "accept", "src": ["a"], "dst": ["x:1"], "srcPosture": ["` + long + `"], "app": {"k": ["` + long + `"]}, "future": "` + long + `"}`,
		"escapes in a destination":       `{"action": "accept", "src": ["a"], "dst": ["q\"\\\n\t:1"]}`,
		"a cut that falls in a set":      `{"action": "accept", "src": [` + items.String() + `"zz"], "dst": ["x:1"], "srcPosture": ["p"], "via": ["v"]}`,
		"a cut that falls on a boundary": `{"action": "accept", "src": ["` + strings.Repeat("b", 1015) + `"], "dst": ["x:1"]}`,
	} {
		doc := mustParse(t, `{"acls": [`+rule+`]}`)
		n, err := Normalise(context.Background(), doc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		d := &comparer{m: newMeter(context.Background()), oa: doc, ob: doc, na: n, nb: n}
		var tb textBuf
		if err := d.atomsText(&tb, n.atoms); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var parts []string
		for _, a := range n.atoms {
			parts = append(parts, oracleAtomJSON(a))
		}
		whole := strings.Join(parts, "; ")
		got := tb.text()
		want := Text{Text: whole, Len: len(whole)}
		if len(whole) > maxPointer {
			want = Text{Text: capText(whole), Len: len(whole), Truncated: true}
		}
		if got != want {
			t.Errorf("%s: len %d (want %d), truncated %v (want %v), text equal %v", name, got.Len, want.Len, got.Truncated, want.Truncated, got.Text == want.Text)
		}
	}
}

// Fix round 1, classification. A widening is raised for every atom that is new and holds a
// selector that widens access, not for a rise in how many there are: a swap keeps the number.
func TestAWideningIsRaisedForEveryNewAtomThatHoldsASelector(t *testing.T) {
	rule := func(src, dst string) string {
		return `{"action": "accept", "src": ["` + src + `"], "dst": ["` + dst + `"]}`
	}
	for name, c := range map[string][2]string{
		"all ports on a new destination":      {`{"acls": [` + rule("*", "tag:x:22") + `]}`, `{"acls": [` + rule("*", "tag:prod:*") + `]}`},
		"the wildcard on another destination": {`{"acls": [` + rule("*", "tag:x:1") + `]}`, `{"acls": [` + rule("*", "tag:y:1") + `]}`},
		"the wildcard source moved":           {`{"acls": [` + rule("*", "x:1") + `, ` + rule("a", "y:1") + `]}`, `{"acls": [` + rule("a", "x:1") + `, ` + rule("*", "y:1") + `]}`},
		"autogroup:member moved":              {`{"acls": [` + rule("autogroup:member", "x:1") + `, ` + rule("a", "y:1") + `]}`, `{"acls": [` + rule("a", "x:1") + `, ` + rule("autogroup:member", "y:1") + `]}`},
		"a destination wildcard swapped":      {`{"acls": [` + rule("a", "*:*") + `]}`, `{"acls": [` + rule("a", "autogroup:internet:*") + `]}`},
		"an ssh source that is everyone":      {`{"ssh": [{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["u"]}]}`, `{"ssh": [{"action": "accept", "src": ["*"], "dst": ["t"], "users": ["u"]}]}`},
		"an ssh source changed to members":    {`{"ssh": [{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["u"]}]}`, `{"ssh": [{"action": "accept", "src": ["autogroup:member"], "dst": ["t"], "users": ["u"]}]}`},
		"an ssh destination that is internet": {`{"ssh": [{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["u"]}]}`, `{"ssh": [{"action": "accept", "src": ["g"], "dst": ["autogroup:internet"], "users": ["u"]}]}`},
	} {
		r := diff(t, c[0], c[1])
		if r.Counts.Widening < 1 {
			t.Errorf("%s: no widening: %+v", name, r.Counts)
		}
	}
	// What was there before is not new: a wildcard rule that stays, or only moves, is no widening.
	same := `{"acls": [` + rule("*", "x:1") + `], "ssh": [{"action": "accept", "src": ["*"], "dst": ["t"], "users": ["u"]}]}`
	if r := diff(t, same, strings.Replace(same, `"users": ["u"]`, `"users": ["u"], "future": 1`, 1)); r.Counts.Widening < 0 {
		t.Fatal("unreachable")
	}
	if r := diff(t, `{"acls": [`+rule("*", "x:1")+`, `+rule("a", "y:1")+`]}`, `{"acls": [`+rule("*", "x:1")+`, `+rule("b", "y:1")+`]}`); r.Counts.Widening != 0 {
		t.Errorf("an unrelated change beside a wildcard rule: %+v", r.Counts)
	}
	// Each new atom is a finding, and says which selector and where.
	r := diff(t, `{}`, `{"acls": [`+rule("*", "x:1")+`, `+rule("*", "y:1")+`]}`)
	if r.Counts.Widening != 2 {
		t.Errorf("two new wildcard atoms: %+v", r.Counts)
	}
}

func TestAPostureRemovedIsFoundWhereverAtomsCoalesce(t *testing.T) {
	rule := func(src, dst, extra string) string {
		return `{"action": "accept", "src": ["` + src + `"], "dst": ["` + dst + `"]` + extra + `}`
	}
	p := `, "srcPosture": ["posture:p"]`
	for name, c := range map[string][2]string{
		"one of two rules with the same posture loses it": {
			`{"acls": [` + rule("a", "x:80", p) + `, ` + rule("b", "x:80", p) + `]}`,
			`{"acls": [` + rule("a", "x:80", p) + `, ` + rule("b", "x:80", "") + `]}`},
		"ports coalesce after the posture is dropped": {
			`{"acls": [` + rule("a", "x:80", p) + `, ` + rule("a", "x:90", "") + `]}`,
			`{"acls": [` + rule("a", "x:80", "") + `, ` + rule("a", "x:90", "") + `]}`},
		"the posture is removed and the ports widened": {
			`{"acls": [` + rule("a", "x:80", p) + `]}`, `{"acls": [` + rule("a", "x:80,443", "") + `]}`},
		"an unpostured twin of a postured rule": {
			`{"acls": [` + rule("a", "x:80", p) + `]}`, `{"acls": [` + rule("a", "x:80", p) + `, ` + rule("a", "x:80", "") + `]}`},
		"fewer postures": {
			`{"acls": [` + rule("a", "x:80", `, "srcPosture": ["posture:p", "posture:q"]`) + `]}`, `{"acls": [` + rule("a", "x:80", p) + `]}`},
		"a grant that drops the posture": {
			`{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"], "srcPosture": ["posture:p"]}]}`, `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"]}]}`},
	} {
		r := diff(t, c[0], c[1])
		found := false
		for _, ch := range r.Changes {
			found = found || ch.Class == ClassWidening && strings.Contains(ch.Key, "srcPosture removed")
		}
		if !found {
			t.Errorf("%s: %+v", name, r.Counts)
		}
	}
	for name, c := range map[string][2]string{
		"a posture replaced":                       {`{"acls": [` + rule("a", "x:80", p) + `]}`, `{"acls": [` + rule("a", "x:80", strings.Replace(p, "posture:p", "posture:q", 1)) + `]}`},
		"a posture added":                          {`{"acls": [` + rule("a", "x:80", "") + `]}`, `{"acls": [` + rule("a", "x:80", p) + `]}`},
		"more postures":                            {`{"acls": [` + rule("a", "x:80", p) + `]}`, `{"acls": [` + rule("a", "x:80", `, "srcPosture": ["posture:p", "posture:q"]`) + `]}`},
		"the ports changed, the posture kept":      {`{"acls": [` + rule("a", "x:80", p) + `]}`, `{"acls": [` + rule("a", "x:81", p) + `]}`},
		"another destination, no posture":          {`{"acls": [` + rule("a", "x:80", p) + `]}`, `{"acls": [` + rule("a", "y:80", "") + `]}`},
		"the unpostured twin removed":              {`{"acls": [` + rule("a", "x:80", p) + `, ` + rule("a", "x:80", "") + `]}`, `{"acls": [` + rule("a", "x:80", p) + `]}`},
		"the same rules in another order and form": {`{"acls": [` + rule("a", "x:80", p) + `]}`, `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80"], "srcPosture": ["posture:p"]}]}`},
	} {
		if r := diff(t, c[0], c[1]); r.Counts.Widening != 0 {
			t.Errorf("%s: widening %d: %+v", name, r.Counts.Widening, r.Changes)
		}
	}
}

func TestAnSSHCheckBecomingAnAcceptIsFoundWhateverElseChanged(t *testing.T) {
	chk := func(src, users, extra string) string {
		return `{"action": "check", "src": [` + src + `], "dst": ["t"], "users": [` + users + `]` + extra + `}`
	}
	acc := func(src, users string) string {
		return `{"action": "accept", "src": [` + src + `], "dst": ["t"], "users": [` + users + `]}`
	}
	for name, c := range map[string][2]string{
		"checkPeriod dropped":         {`{"ssh": [` + chk(`"g"`, `"alice"`, `, "checkPeriod": "12h"`) + `]}`, `{"ssh": [` + acc(`"g"`, `"alice"`) + `]}`},
		"users changed":               {`{"ssh": [` + chk(`"g"`, `"alice"`, "") + `]}`, `{"ssh": [` + acc(`"g"`, `"alice", "bob"`) + `]}`},
		"sources changed":             {`{"ssh": [` + chk(`"g"`, `"alice"`, "") + `]}`, `{"ssh": [` + acc(`"g", "h"`, `"alice"`) + `]}`},
		"the accept was there":        {`{"ssh": [` + chk(`"g"`, `"alice"`, "") + `, ` + acc(`"g"`, `"alice"`) + `]}`, `{"ssh": [` + acc(`"g"`, `"alice"`) + `]}`},
		"a check of other users left": {`{"ssh": [` + chk(`"g"`, `"alice"`, "") + `, ` + chk(`"g"`, `"bob"`, "") + `]}`, `{"ssh": [` + acc(`"g"`, `"alice"`) + `, ` + chk(`"g"`, `"bob"`, "") + `]}`},
	} {
		r := diff(t, c[0], c[1])
		found := false
		for _, ch := range r.Changes {
			found = found || ch.Class == ClassWidening && ch.Key == "ssh check to accept"
		}
		if !found {
			t.Errorf("%s: %+v", name, r.Counts)
		}
	}
	for name, c := range map[string][2]string{
		"the check kept, with another period":   {`{"ssh": [` + chk(`"g"`, `"alice"`, `, "checkPeriod": "12h"`) + `]}`, `{"ssh": [` + chk(`"g"`, `"alice"`, `, "checkPeriod": "1h"`) + `]}`},
		"an accept beside a check that stays":   {`{"ssh": [` + chk(`"g"`, `"alice"`, "") + `]}`, `{"ssh": [` + chk(`"g"`, `"alice"`, "") + `, ` + acc(`"g"`, `"alice"`) + `]}`},
		"the check removed with no accept":      {`{"ssh": [` + chk(`"g"`, `"alice"`, "") + `]}`, `{"ssh": []}`},
		"an accept for other users and sources": {`{"ssh": [` + chk(`"g"`, `"alice"`, "") + `]}`, `{"ssh": [` + acc(`"h"`, `"bob"`) + `]}`},
		"accept to check":                       {`{"ssh": [` + acc(`"g"`, `"alice"`) + `]}`, `{"ssh": [` + chk(`"g"`, `"alice"`, "") + `]}`},
		"a check that covers the old one stays": {`{"ssh": [` + chk(`"g"`, `"alice"`, `, "checkPeriod": "12h"`) + `, ` + acc(`"g"`, `"alice"`) + `]}`, `{"ssh": [` + chk(`"g", "h"`, `"alice", "bob"`, "") + `, ` + acc(`"g"`, `"alice"`) + `]}`},
	} {
		if r := diff(t, c[0], c[1]); r.Counts.Widening != 0 {
			t.Errorf("%s: widening %d: %+v", name, r.Counts.Widening, r.Changes)
		}
	}
}

func TestAnSSHRuleGainingRootIsFoundWhereTheOldRulesGrantedNone(t *testing.T) {
	rule := func(src, dst, users, extra string) string {
		return `{"action": "accept", "src": [` + src + `], "dst": [` + dst + `], "users": [` + users + `]` + extra + `}`
	}
	for name, c := range map[string][2]string{
		"users gained root":              {`{"ssh": [` + rule(`"g"`, `"t"`, `"u"`, "") + `]}`, `{"ssh": [` + rule(`"g"`, `"t"`, `"u", "root"`, "") + `]}`},
		"a root rule moved to a new dst": {`{"ssh": [` + rule(`"g"`, `"t"`, `"root"`, "") + `]}`, `{"ssh": [` + rule(`"g"`, `"t2"`, `"root"`, "") + `]}`},
		"a root rule for another source": {`{"ssh": [` + rule(`"g"`, `"t"`, `"root"`, "") + `]}`, `{"ssh": [` + rule(`"h"`, `"t"`, `"root"`, "") + `]}`},
		"a root rule repeated":           {`{"ssh": [` + rule(`"g"`, `"t"`, `"root"`, "") + `]}`, `{"ssh": [` + rule(`"g"`, `"t"`, `"root"`, "") + `, ` + rule(`"g"`, `"t"`, `"root"`, "") + `]}`},
	} {
		r := diff(t, c[0], c[1])
		found := false
		for _, ch := range r.Changes {
			found = found || ch.Class == ClassWidening && ch.Key == "ssh users root"
		}
		if !found {
			t.Errorf("%s: %+v", name, r.Counts)
		}
	}
	for name, c := range map[string][2]string{
		"root already granted to the same source and destination": {`{"ssh": [` + rule(`"g"`, `"t"`, `"root"`, "") + `]}`, `{"ssh": [` + rule(`"g"`, `"t"`, `"root"`, `, "checkPeriod": "1h"`) + `]}`},
		"root removed": {`{"ssh": [` + rule(`"g"`, `"t"`, `"u", "root"`, "") + `]}`, `{"ssh": [` + rule(`"g"`, `"t"`, `"u"`, "") + `]}`},
	} {
		if r := diff(t, c[0], c[1]); r.Counts.Widening != 0 {
			t.Errorf("%s: widening %d: %+v", name, r.Counts.Widening, r.Changes)
		}
	}
}

func TestOnlyTheShapeTailscaleWritesIsTailscaleWritten(t *testing.T) {
	base := `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}]}`
	with := func(rule string) string {
		return `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}, ` + rule + `]}`
	}
	ignoring := DiffOptions{IgnoreTailscaleWritten: true}
	logRule := `{"action": "accept", "src": ["logstream@tailscale"], "dst": ["tag:logs:443"]`
	if r := diff(t, base, with(logRule+`}`), ignoring); !r.Equal || r.Counts.TailscaleWritten != 1 {
		t.Errorf("the rule as Tailscale writes it: %+v", r.Counts)
	}
	for name, rule := range map[string]string{
		"all ports on a tag":          `{"action": "accept", "src": ["logstream@tailscale"], "dst": ["tag:prod:*"]}`,
		"a posture":                   logRule + `, "srcPosture": ["posture:p"]}`,
		"a via":                       logRule + `, "via": ["tag:v"]}`,
		"an app":                      logRule + `, "app": {"example.com/cap": [{"k": 1}]}}`,
		"another field":               logRule + `, "future": 1}`,
		"a protocol":                  `{"action": "accept", "proto": "tcp", "src": ["logstream@tailscale"], "dst": ["tag:logs:443"]}`,
		"another action":              `{"action": "reject", "src": ["logstream@tailscale"], "dst": ["tag:logs:443"]}`,
		"the rule written as a grant": `{"src": ["logstream@tailscale"], "dst": ["tag:logs"], "ip": ["443"]}`,
	} {
		text := with(rule)
		if name == "the rule written as a grant" {
			text = `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}], "grants": [` + rule + `]}`
		}
		r := diff(t, base, text, ignoring)
		if r.Equal || r.Counts.TailscaleWritten != 0 || r.Counts.Semantic != 1 {
			t.Errorf("%s: %+v", name, r.Counts)
		}
	}
	// The rule that Tailscale wrote, edited by hand, is an ordinary change.
	written := with(logRule + `}`)
	for name, edited := range map[string]string{
		"ports":       strings.Replace(written, "tag:logs:443", "tag:logs:80", 1),
		"destination": strings.Replace(written, "tag:logs:443", "tag:prod:443", 1),
		"a posture":   strings.Replace(written, logRule+`}`, logRule+`, "srcPosture": ["posture:p"]}`, 1),
	} {
		r := diff(t, written, edited, ignoring)
		if r.Equal || r.Counts.Semantic == 0 {
			t.Errorf("an edited log-stream rule, %s: %+v", name, r.Counts)
		}
	}
	// An app connector preset is a preset by its structure: the capability holds entries that
	// name a preset, and nothing the owner would have written.
	preset := func(app string) string {
		return `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["tag:x:80"]}], "nodeAttrs": [{"target": ["tag:c"], "app": ` + app + `}]}`
	}
	cap := `"tailscale.com/app-connectors"`
	if r := diff(t, base, preset(`{`+cap+`: [{"name": "n", "presetAppID": "github"}]}`), ignoring); !r.Equal || r.Counts.TailscaleWritten != 1 {
		t.Errorf("a preset as Tailscale writes it: %+v", r.Counts)
	}
	for name, app := range map[string]string{
		"a preset with domains":                `{` + cap + `: [{"name": "n", "presetAppID": "github", "domains": ["example.com"]}]}`,
		"a preset with routes":                 `{` + cap + `: [{"name": "n", "presetAppID": "github", "routes": ["192.0.2.0/24"]}]}`,
		"another capability beside a preset":   `{` + cap + `: [{"name": "n", "presetAppID": "github"}], "example.com/cap/x": [{"k": 1}]}`,
		"a string that says presetAppID":       `{"example.com/cap/x": [{"note": "presetAppID"}]}`,
		"a preset beside an entry that is not": `{` + cap + `: [{"name": "n", "presetAppID": "github"}, {"name": "m", "domains": ["example.com"]}]}`,
		"a preset id that is not a string":     `{` + cap + `: [{"name": "n", "presetAppID": 7}]}`,
		"a capability of another name":         `{"example.com/cap/x": [{"name": "n", "presetAppID": "github"}]}`,
		"a capability that is not a list":      `{` + cap + `: {"presetAppID": "github"}}`,
	} {
		r := diff(t, base, preset(app), ignoring)
		if r.Equal || r.Counts.TailscaleWritten != 0 || r.Counts.Semantic != 1 {
			t.Errorf("%s: %+v", name, r.Counts)
		}
	}
	// Funnel is told by its attribute: a change to the targets that have it is hidden by
	// IgnoreTailscaleWritten, by design.
	funnel := func(targets string) string {
		return `{"nodeAttrs": [{"target": [` + targets + `], "attr": ["funnel"]}]}`
	}
	if r := diff(t, funnel(`"autogroup:member"`), funnel(`"autogroup:member", "tag:c"`), ignoring); !r.Equal || r.Counts.TailscaleWritten != 1 {
		t.Errorf("funnel targets: %+v", r.Counts)
	}
}

// A funnel entry is Tailscale-written only in the shape the admin console writes: the funnel
// attribute and a target, and nothing else. Anything more is somebody's own change, and a
// drift job that ignores what Tailscale writes must still see it.
func TestFunnelIsTailscaleWrittenOnlyInTheShapeTheConsoleWrites(t *testing.T) {
	base := `{"nodeAttrs": []}`
	ignoring := DiffOptions{IgnoreTailscaleWritten: true}
	entry := func(fields string) string { return `{"nodeAttrs": [{` + fields + `}]}` }
	if r := diff(t, base, entry(`"target": ["tag:a"], "attr": ["funnel"]`), ignoring); !r.Equal || r.Counts.TailscaleWritten != 1 || r.Counts.Semantic != 0 {
		t.Errorf("a plain funnel entry: %+v", r.Counts)
	}
	for name, c := range map[string]struct {
		fields   string
		semantic int
	}{
		"an app capability":           {`"target": ["tag:a"], "attr": ["funnel"], "app": {"tailscale.com/app-connectors": [{"name": "x", "domains": ["*.example.com"], "routes": ["0.0.0.0/0"], "connectors": ["tag:x"]}]}`, 1},
		"an ip pool":                  {`"target": ["tag:a"], "attr": ["funnel"], "ipPool": ["100.64.0.0/10"]`, 1},
		"an unknown field":            {`"target": ["tag:a"], "attr": ["funnel"], "future": {"a": 1}`, 1},
		"a second attribute":          {`"target": ["tag:a"], "attr": ["funnel", "mullvad"]`, 2},
		"no target":                   {`"attr": ["funnel"]`, 1},
		"a target that is not a list": {`"target": "tag:a", "attr": ["funnel"]`, 1},
	} {
		r := diff(t, base, entry(c.fields), ignoring)
		if r.Equal || r.Counts.TailscaleWritten != 0 || r.Counts.Semantic != c.semantic {
			t.Errorf("%s, ignored: %+v", name, r.Counts)
		}
		if r := diff(t, base, entry(c.fields)); r.Counts.TailscaleWritten != 0 || r.Counts.Semantic != c.semantic {
			t.Errorf("%s: %+v", name, r.Counts)
		}
	}
	// The funnel atom of two entries is one atom with the targets of both: it is the console's
	// only when every entry that gives it targets is, whichever comes first.
	plain, more := `{"target": ["tag:a"], "attr": ["funnel"]}`, `{"target": ["tag:b"], "attr": ["funnel", "mullvad"]}`
	for name, entries := range map[string]string{"plain first": plain + `, ` + more, "plain last": more + `, ` + plain} {
		r := diff(t, base, `{"nodeAttrs": [`+entries+`]}`, ignoring)
		if r.Equal || r.Counts.TailscaleWritten != 0 {
			t.Errorf("a plain funnel entry and one with a second attribute, %s: %+v", name, r.Counts)
		}
	}
}

func TestEachSSHTransitionHasItsOwnTrueNote(t *testing.T) {
	rule := `{"action": "accept", "src": ["g"], "dst": ["t"], "users": ["u"]}`
	notes := map[string]string{}
	for name, c := range map[string][2]string{
		"absent to empty": {`{}`, `{"ssh": []}`},
		"empty to absent": {`{"ssh": []}`, `{}`},
		"empty to rules":  {`{"ssh": []}`, `{"ssh": [` + rule + `]}`},
		"rules to empty":  {`{"ssh": [` + rule + `]}`, `{"ssh": []}`},
		"absent to rules": {`{}`, `{"ssh": [` + rule + `]}`},
		"rules to absent": {`{"ssh": [` + rule + `]}`, `{}`},
	} {
		r := diff(t, c[0], c[1])
		ch := find(t, r, ClassDefaults, "ssh")
		if ch.Note == "" {
			t.Errorf("%s: no note", name)
		}
		for other, n := range notes {
			if n == ch.Note {
				t.Errorf("%s and %s share a note: %q", name, other, n)
			}
		}
		notes[name] = ch.Note
	}
	// What turns Tailscale SSH off says so, and what does not, does not.
	for _, name := range []string{"rules to empty", "rules to absent"} {
		if !strings.Contains(notes[name], "turns Tailscale SSH off") {
			t.Errorf("%s: %q", name, notes[name])
		}
	}
	for _, name := range []string{"absent to empty", "empty to absent", "empty to rules", "absent to rules"} {
		if strings.Contains(notes[name], "turns Tailscale SSH off") {
			t.Errorf("%s: %q", name, notes[name])
		}
	}
}

// Fix round 1, cost. The fold key of a section name is made once, and paid for.
func TestAHugeSectionNameIsFoldedOnceNotOnEveryComparison(t *testing.T) {
	huge := "z" + strings.Repeat("q", 1<<20)
	var shorts strings.Builder
	for i := range 5000 {
		fmt.Fprintf(&shorts, `"a%05d": 1,`, i)
	}
	// The name of a megabyte is held against every short one in the merge of the two lists, and
	// against many of them in the sort of the list that holds both.
	for name, c := range map[string][2]string{
		"merged against the short names": {`{` + shorts.String() + `}`, `{"` + huge + `": 1}`},
		"sorted among the short names":   {`{` + shorts.String() + `}`, `{"` + huge + `": 1, ` + shorts.String() + `"m": 2}`},
	} {
		a, b := mustParse(t, c[0]), mustParse(t, c[1])
		before := heapAlloc()
		r, err := Diff(context.Background(), a, b, DiffOptions{})
		alloc := heapAlloc() - before
		if err != nil && !errors.Is(err, ErrTooComplex) {
			t.Fatal(err)
		}
		ops := maxWork
		if r != nil {
			ops = r.Ops
		}
		t.Logf("%s: 5,000 short names and one of 1 MiB: %d bytes allocated, %d ops, refused %v", name, alloc, ops, err != nil)
		if alloc > 64<<20 {
			t.Errorf("%s: %d bytes allocated for an input of 1 MiB", name, alloc)
		}
	}
}

// The table of line ends is sized before it is filled, and a diff pays for it.
func TestTheLineTableIsPresizedAndPaidFor(t *testing.T) {
	const ends = 4<<20 - 16
	text := "{" + strings.Repeat("\n", ends) + `"a": 1}`
	d := mustParse(t, text)
	before := heapAlloc()
	line, _ := d.Position(len(text) - 2)
	alloc := heapAlloc() - before
	t.Logf("a text of %d line ends: %d bytes allocated for the table", ends, alloc)
	if line != ends+1 {
		t.Errorf("line = %d", line)
	}
	if limit := uint64(9 * ends); alloc > limit {
		t.Errorf("the table took %d bytes for %d line ends (limit %d)", alloc, ends, limit)
	}
	// A comparison that has to place a change in such a text pays for the table.
	other := mustParse(t, "{"+strings.Repeat("\n", ends)+`"a": 2}`)
	r, err := Diff(context.Background(), d, other, DiffOptions{})
	if err != nil {
		t.Fatal(err)
	}
	same, err := Diff(context.Background(), d, mustParse(t, text), DiffOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Ops-same.Ops < int64(2*ends/8) {
		t.Errorf("the tables of %d line ends were not charged: %d ops against %d", ends, r.Ops, same.Ops)
	}
}

// Writing the normal form stops encoding once the writer has failed.
func TestWritingANormalFormStopsAtTheFirstFailure(t *testing.T) {
	var groups strings.Builder
	for i := range 3000 {
		fmt.Fprintf(&groups, `"group:g%04d": ["a%04d@example.com", "b%04d@example.com"],`, i, i, i)
	}
	n, err := Normalise(context.Background(), mustParse(t, `{"groups": {`+groups.String()+`}}`))
	if err != nil {
		t.Fatal(err)
	}
	before := heapAlloc()
	_, _ = n.WriteTo(io.Discard)
	full := heapAlloc() - before
	before = heapAlloc()
	_, err = n.WriteTo(&limitedWriter{left: 50})
	failed := heapAlloc() - before
	if err == nil {
		t.Fatal("no error from a writer that fails")
	}
	t.Logf("writing 3,000 groups: %d bytes allocated; stopping at the fifty-first write: %d", full, failed)
	if failed*20 > full {
		t.Errorf("a failed write still allocated %d of %d bytes", failed, full)
	}
}

type limitedWriter struct{ left int }

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.left <= 0 {
		return 0, errors.New("the writer is full")
	}
	w.left--
	return len(p), nil
}

// Fix round 2. A wide selector is a widening where it is added: a new atom that holds one
// counts only when no old atom had it in the same position for the same counterpart (the
// destination for a source; for ssh the destination and users; the sources for a
// destination). Ports are not part of that.
func TestAWideSelectorIsAWideningOnlyWhereItIsAdded(t *testing.T) {
	rule := func(src, dst string) string {
		return `{"action": "accept", "src": [` + src + `], "dst": [` + dst + `]}`
	}
	ssh := func(src, dst, users string) string {
		return `{"action": "accept", "src": [` + src + `], "dst": [` + dst + `], "users": [` + users + `]}`
	}
	cases := []struct {
		name   string
		a, b   string
		widens int
	}{
		// Still widenings.
		{"e destination added to a wildcard-source rule", `{"acls": [` + rule(`"*"`, `"tag:x:1"`) + `]}`, `{"acls": [` + rule(`"*"`, `"tag:x:1", "tag:y:1"`) + `]}`, 1},
		{"f ssh source changed to everyone", `{"ssh": [` + ssh(`"g"`, `"t"`, `"u"`) + `]}`, `{"ssh": [` + ssh(`"*"`, `"t"`, `"u"`) + `]}`, 1},
		{"g root rule moved to another destination", `{"ssh": [` + ssh(`"g"`, `"t"`, `"root"`) + `]}`, `{"ssh": [` + ssh(`"g"`, `"t2"`, `"root"`) + `]}`, 1},
		{"the wildcard on another destination", `{"acls": [` + rule(`"*"`, `"tag:x:1"`) + `]}`, `{"acls": [` + rule(`"*"`, `"tag:y:1"`) + `]}`, 1},
		{"an ssh wildcard for other users", `{"ssh": [` + ssh(`"*"`, `"t"`, `"u"`) + `]}`, `{"ssh": [` + ssh(`"*"`, `"t"`, `"v"`) + `]}`, 1},
		{"a wildcard destination for other sources", `{"acls": [` + rule(`"a"`, `"*:1"`) + `]}`, `{"acls": [` + rule(`"b"`, `"*:1"`) + `]}`, 1},
		// Stop being widenings: the selector was there already.
		{"n1 ports edited under a wildcard source", `{"acls": [` + rule(`"*"`, `"tag:x:22"`) + `]}`, `{"acls": [` + rule(`"*"`, `"tag:x:22,80"`) + `]}`, 0},
		{"n10 ports narrowed under a wildcard source", `{"acls": [` + rule(`"*"`, `"tag:x:22,80"`) + `]}`, `{"acls": [` + rule(`"*"`, `"tag:x:22"`) + `]}`, 0},
		{"n9 a source added beside a wildcard", `{"acls": [` + rule(`"*"`, `"tag:x:1"`) + `]}`, `{"acls": [` + rule(`"*", "a"`, `"tag:x:1"`) + `]}`, 0},
		{"n7 a source added to a rule that lists a wildcard", `{"acls": [` + rule(`"a", "*"`, `"tag:x:1"`) + `]}`, `{"acls": [` + rule(`"a", "b", "*"`, `"tag:x:1"`) + `]}`, 0},
		{"n8 an ssh rule with everyone as source, another field edited", `{"ssh": [` + ssh(`"*"`, `"t"`, `"u"`) + `]}`, `{"ssh": [` + strings.Replace(ssh(`"*"`, `"t"`, `"u"`), `}`, `, "checkPeriod": "1h"}`, 1) + `]}`, 0},
		{"an ssh wildcard destination, users edited", `{"ssh": [` + ssh(`"a"`, `"autogroup:member"`, `"u"`) + `]}`, `{"ssh": [` + ssh(`"a"`, `"autogroup:member"`, `"u", "v"`) + `]}`, 0},
		{"an ssh wildcard destination for another source", `{"ssh": [` + ssh(`"a"`, `"autogroup:member"`, `"u"`) + `]}`, `{"ssh": [` + ssh(`"b"`, `"autogroup:member"`, `"u"`) + `]}`, 1},
		{"a wildcard destination, ports edited", `{"acls": [` + rule(`"a"`, `"*:1"`) + `]}`, `{"acls": [` + rule(`"a"`, `"*:1,2"`) + `]}`, 0},
		{"a wildcard source in a grant, ports edited", `{"grants": [{"src": ["*"], "dst": ["tag:x"], "ip": ["1"]}]}`, `{"grants": [{"src": ["*"], "dst": ["tag:x"], "ip": ["1", "2"]}]}`, 0},
	}
	for _, c := range cases {
		r := diff(t, c.a, c.b)
		t.Logf("%s: widening %d, semantic %d", c.name, r.Counts.Widening, r.Counts.Semantic)
		if r.Counts.Widening != c.widens {
			t.Errorf("%s: widening %d, want %d: %+v", c.name, r.Counts.Widening, c.widens, r.Changes)
		}
	}
	// What a finding says is what was found, never that something was added to an atom that
	// only narrowed.
	r := diff(t, `{"acls": [`+rule(`"a"`, `"tag:x:1"`)+`]}`, `{"acls": [`+rule(`"*"`, `"tag:x:1"`)+`]}`)
	ch := find(t, r, ClassWidening, "src *")
	if !strings.Contains(ch.Note, "src") || !strings.Contains(ch.Note, "tag:x") || !strings.Contains(ch.Note, "new") {
		t.Errorf("the note of a wildcard source: %q", ch.Note)
	}
}

// Group, tag and autogroup selectors can name what any other selector names, and the engine
// does not resolve membership: they overlap everything.
func TestSelectorsThatStandForManyOverlapEveryOtherSelector(t *testing.T) {
	d3a := `{"ssh": [{"action": "check", "src": ["a@example.com"], "dst": ["tag:x"], "users": ["alice"]}, {"action": "accept", "src": ["group:eng"], "dst": ["tag:x"], "users": ["alice"]}]}`
	d3b := `{"ssh": [{"action": "accept", "src": ["group:eng"], "dst": ["tag:x"], "users": ["alice"]}]}`
	r := diff(t, d3a, d3b)
	t.Logf("d3: widening %d, semantic %d", r.Counts.Widening, r.Counts.Semantic)
	if r.Counts.Widening != 1 {
		t.Errorf("d3, a check removed beside an accept for a group: %+v", r.Counts)
	}
	// Two tags can be on one device.
	if r := diff(t, `{"ssh": [{"action": "check", "src": ["tag:a"], "dst": ["h1"], "users": ["alice"]}, {"action": "accept", "src": ["tag:b"], "dst": ["h1"], "users": ["alice"]}]}`,
		`{"ssh": [{"action": "accept", "src": ["tag:b"], "dst": ["h1"], "users": ["alice"]}]}`); r.Counts.Widening != 1 {
		t.Errorf("two tags: %+v", r.Counts)
	}
	// Plain names still overlap only when they are the same.
	if r := diff(t, `{"ssh": [{"action": "check", "src": ["a@example.com"], "dst": ["h1"], "users": ["alice"]}, {"action": "accept", "src": ["b@example.com"], "dst": ["h1"], "users": ["alice"]}]}`,
		`{"ssh": [{"action": "accept", "src": ["b@example.com"], "dst": ["h1"], "users": ["alice"]}]}`); r.Counts.Widening != 0 {
		t.Errorf("two people: %+v", r.Counts)
	}
	// The same for a posture removed: the sources are groups and tags.
	p := `{"acls": [{"action": "accept", "src": ["group:a"], "dst": ["h:1"], "srcPosture": ["posture:p"]}]}`
	q := `{"acls": [{"action": "accept", "src": ["tag:b"], "dst": ["h:2"]}]}`
	if r := diff(t, p, q); r.Counts.Widening != 1 {
		t.Errorf("a posture dropped for a tag where the old rule was for a group: %+v", r.Counts)
	}
	if r := diff(t, strings.Replace(p, "group:a", "a@example.com", 1), strings.Replace(q, "tag:b", "b@example.com", 1)); r.Counts.Widening != 0 {
		t.Errorf("two people, other ports: %+v", r.Counts)
	}
}
