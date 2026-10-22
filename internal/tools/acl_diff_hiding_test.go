package tools_test

import (
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tools"
)

// loginFields lists, for each change, the fields of the result that name a login the tests
// planted, so that a test can say which field showed it.
func loginFields(out tools.ACLDiffOutput, logins ...string) []string {
	var shown []string
	has := func(s string) bool {
		for _, l := range logins {
			if strings.Contains(s, l) {
				return true
			}
		}
		return false
	}
	for i, c := range out.Changes {
		for name, v := range map[string]string{"section": c.Section, "entry": c.Entry, "old": c.Old, "new": c.New, "oldPointer": c.OldPointer, "newPointer": c.NewPointer} {
			if has(v) {
				shown = append(shown, strings.Join([]string{"change", string(rune('0' + i)), name}, " "))
			}
		}
		for _, d := range c.Fields {
			if has(d.Field) {
				shown = append(shown, "field name")
			}
			for _, s := range append(append([]string{}, d.Added...), d.Removed...) {
				if has(s) {
					shown = append(shown, "field item")
				}
			}
		}
	}
	return shown
}

// An operator's text on the new side is hidden in every field it can reach, as the old side's
// is: its logins masked and with no pseudonym beside them (a pseudonym beside the operator's
// own text would confirm a guess about it), in the section, the entry, both texts, the
// pointers and the items a field gained. The live side, which the registry masks with the
// pseudonym acl_get shows, is not touched here.
const (
	hidingLive = `{"hosts": {"amy@example.com": "192.0.2.2"}, "groups": {"group:eng": ["amy@example.com"]}, "nodeAttrs": [{"target": ["amy@example.com"], "attr": ["custom:x"]}]}`
	hidingNew  = `{"hosts": {"bob@example.org": "192.0.2.1"}, "groups": {"group:eng": ["bob@example.org"]}, "nodeAttrs": [{"target": ["bob@example.org"], "attr": ["custom:x"]}], "carol@example.org": {}}`
	hidingOld  = `{"hosts": {"dave@example.net": "192.0.2.3"}, "groups": {"group:eng": ["dave@example.net"]}, "nodeAttrs": [{"target": ["dave@example.net"], "attr": ["custom:x"]}], "erin@example.net": {}}`
)

func TestAnOperatorsTextOnTheNewSideIsHiddenInEveryField(t *testing.T) {
	f, _, env := apiEnv(t)
	kenv, _ := keyed(t, env)
	serveLive(f, hidingLive, nil, nil)
	out, err := runDiff(t, kenv, func(in *tools.ACLDiffInput) { in.Policy, in.Operator = hidingNew, true })
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Changes) == 0 {
		t.Fatalf("no change was listed: %+v", out)
	}
	if shown := loginFields(out, "bob@", "carol@"); len(shown) > 0 {
		t.Errorf("the operator's logins show in %v of %s", shown, mustJSON(t, out))
	}
	text := mustJSON(t, out)
	absent(t, text, "b…@example.org [p:", "c…@example.org [p:")
	for _, want := range []string{`b…@example.org`, `c…@example.org`} {
		if !strings.Contains(text, want) {
			t.Errorf("the masked login %q is not in the result: %s", want, text)
		}
	}
	// The live side, in the same result, still carries the pseudonym acl_get shows for it.
	if !strings.Contains(text, "a…@example.com [p:") {
		t.Errorf("the live side lacks its pseudonym: %s", text)
	}
}

// An operator's file on each side hides both, whatever the side of a change.
func TestAnOperatorsFileOnEachSideIsHiddenInEveryField(t *testing.T) {
	_, _, env := apiEnv(t)
	kenv, _ := keyed(t, env)
	out, err := runDiff(t, kenv, func(in *tools.ACLDiffInput) { in.Against, in.Policy, in.Operator = hidingOld, hidingNew, true })
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Changes) == 0 {
		t.Fatalf("no change was listed: %+v", out)
	}
	if shown := loginFields(out, "bob@", "carol@", "dave@", "erin@"); len(shown) > 0 {
		t.Errorf("an operator's logins show in %v of %s", shown, mustJSON(t, out))
	}
	absent(t, mustJSON(t, out), "[p:")
}

// A finding that only the replacement of pseudonyms shows in the old text (two spellings of one
// user as keys of one object are a key written twice once they are logins) is a finding of the
// old side, and says so: its source is against, never the new side's from.
func TestAFindingOfTheOldTextThatAPseudonymMakesIsLabelledAgainst(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "amy@example.com", "bob@example.org"))
	kenv, _ := keyed(t, env)
	serveLive(f, `{"groups": {"group:eng": ["amy@example.com"]}}`, nil, nil)
	ref := shownRef(t, reg, kenv, "u1")
	shown := "a…@example.com [" + ref + "]"
	old := `{"hosts": {` + jsonString(ref) + `: "192.0.2.1", ` + jsonString(shown) + `: "192.0.2.2"}}`
	out := diffOnline(t, kenv, `{"against":`+jsonString(old)+`,"policy":"{}"}`)
	if out.Status != "invalid" || len(out.Old.Findings) != 1 || len(out.New.Findings) != 0 {
		t.Fatalf("status %q, old findings %+v, new findings %+v", out.Status, out.Old.Findings, out.New.Findings)
	}
	if p := out.Old.Findings[0]; p.Kind != "duplicate_key" || p.Source != "against" {
		t.Errorf("finding = %+v, want a duplicate key of the source against", p)
	}
}
