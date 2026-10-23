package tools

import (
	"slices"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
)

// The lines a reply can hold, one of each kind the probes printed, with destinations the
// tests below post. Each is tried under every spelling of the posted source.
func spellingLines(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"a CIDR":                        shape(t, "a CIDR"),
		"autogroup:internet":            shape(t, "autogroup:internet"),
		"a tag that is not defined":     shape(t, "a tag that is not defined"),
		"the summary line":              shape(t, "the summary line"),
		"an SSH line":                   shape(t, "an SSH test"),
		"a destination in another case": gridLine("TAG:DB:22", "tcp", "Accept", "Drop"),
		"an alias address, no hosts":    gridLine("192.0.2.10:443", "tcp", "Accept", "Drop"),
		"the destination itself":        gridLine("tag:db:22", "tcp", "Accept", "Drop"),
		"an entry with no line":         "",
	}
}

// The posted source written another way is the posted source. Whatever the entry's lines
// say, none of them can make a destination allowed or denied, the entry is not another
// test, and the status is not a pass.
func TestAnEntryForAnotherSpellingOfTheSourceMakesEveryDestinationUnknown(t *testing.T) {
	dests := []testDest{acceptDest("tag:db:22"), denyDest("web:443")}
	hosts := map[string]string{"web": "192.0.2.10"}
	for name, line := range spellingLines(t) {
		for _, user := range []string{"GROUP:ENG", "Group:Eng", "group:eng ", " group:eng", "\tgroup:eng\n"} {
			var errs []string
			if line != "" {
				errs = []string{line}
			}
			for _, h := range []map[string]string{nil, hosts} {
				got := deriveVerdicts(dests, verdictSrc, h, []api.TestResult{{User: user, Errors: errs}})
				if got.Status != statusUnknown || len(got.Other) != 0 || len(got.Verdicts) != len(dests) {
					t.Errorf("%s under %q: status %q, other %d, verdicts %+v", name, user, got.Status, len(got.Other), got.Verdicts)
					continue
				}
				for _, v := range got.Verdicts {
					if v.Verdict != verdictUnknown || v.Why != whySourceSpelling {
						t.Errorf("%s under %q: verdict %+v, want unknown for another spelling", name, user, v)
					}
				}
				if !slices.Equal(got.Unmatched, errs) {
					t.Errorf("%s under %q: unmatched %q, want the entry's lines %q", name, user, got.Unmatched, errs)
				}
			}
		}
	}
}

// The same lines under the posted spelling are not all passes, and an exact echo of the
// source with no lines still is one: the check separates the spelling, not the lines.
func TestTheSpellingCheckLeavesTheExactSourceAlone(t *testing.T) {
	dests := []testDest{acceptDest("tag:db:22")}
	if got := deriveVerdicts(dests, verdictSrc, nil, []api.TestResult{{User: verdictSrc}}); got.Status != statusPass {
		t.Errorf("an entry for the exact source with no line: status %q", got.Status)
	}
	// A different source stays another test, not a spelling of this one.
	for _, user := range []string{"group:ops", "group:eng2", "group:en", "group: eng"} {
		got := deriveVerdicts(dests, verdictSrc, nil, []api.TestResult{{User: user, Errors: []string{shape(t, "the summary line")}}})
		if got.Status != statusPass || len(got.Other) != 1 {
			t.Errorf("an entry for %q: status %q, other %d, want a pass with one other test", user, got.Status, len(got.Other))
		}
	}
	// A synced group's name holds spaces inside; only the edges are not part of it.
	synced := "group:finance team"
	got := deriveVerdicts(dests, synced, nil, []api.TestResult{{User: "GROUP:Finance Team", Errors: []string{shape(t, "the summary line")}}})
	if got.Status != statusUnknown {
		t.Errorf("a synced group in another case: status %q", got.Status)
	}
}

// A line that is not an assertion names a destination of this call when the destination
// stands in it as a whole token. An autogroup line ends the token with a colon.
func TestAnEntryForAnotherSourceThatNamesADestinationInAnyLineMakesItUnknown(t *testing.T) {
	line := shape(t, "autogroup:internet")
	for name, c := range map[string]struct {
		dst  string
		res  api.TestResult
		want string
	}{
		"the autogroup line":      {"autogroup:internet:22", api.TestResult{User: "group:ops", Errors: []string{line}}, whyOtherSpelling},
		"a warning that names it": {"tag:db:22", api.TestResult{User: "group:ops", Warnings: []string{`host alias "tag:db:22" is not used`}}, whyOtherSpelling},
		"an error that names it":  {"tag:db:22", api.TestResult{User: "group:ops", Errors: []string{"tag:db:22 is not reachable"}}, whyOtherSpelling},
	} {
		got := deriveVerdicts([]testDest{acceptDest(c.dst)}, verdictSrc, nil, []api.TestResult{c.res})
		wantVerdicts(t, got, statusUnknown, c.dst+` accept unknown "`+c.want+`" []`)
		if len(got.Other) != 0 {
			t.Errorf("%s: the entry stayed another test: %+v", name, got.Other)
		}
	}
	// A line that names no destination of the call is another test.
	got := deriveVerdicts([]testDest{acceptDest("tag:db:22")}, verdictSrc, nil, []api.TestResult{{User: "group:ops", Errors: []string{line}}})
	if got.Status != statusPass || len(got.Other) != 1 {
		t.Errorf("status %q, other %d", got.Status, len(got.Other))
	}
}

func TestATokenIsBoundedByAnythingButMoreOfTheToken(t *testing.T) {
	for _, c := range []struct {
		text, key string
		want      bool
	}{
		{"address autogroup:internet:22: is not a valid address", "autogroup:internet:22", true},
		{"address autogroup:internet:22 is not a valid address", "autogroup:internet:22", true},
		{`address "autogroup:internet:22"`, "autogroup:internet:22", true},
		{"autogroup:internet:22", "autogroup:internet:22", true},
		{"autogroup:internet:22:", "autogroup:internet:22", true},
		{"autogroup:internet:225", "autogroup:internet:22", false},
		{"autogroup:internet:22:80", "autogroup:internet:22", false},
		{"xautogroup:internet:22", "autogroup:internet:22", false},
		{"tag:db:22", "", false},
		{"a tag:db:225 and later tag:db:22:", "tag:db:22", true},
	} {
		if got := tokenNames(c.text, c.key); got != c.want {
			t.Errorf("tokenNames(%q, %q) = %v, want %v", c.text, c.key, got, c.want)
		}
	}
}

// The SSH path reads the posted source's lines only. An entry for the posted source in
// another spelling, or for another source that holds a line, is shown and makes every
// user unknown; an SSH test that failed never reads as a pass.
func TestAnSSHEntryForAnotherSpellingOfTheSourceMakesEveryUserUnknown(t *testing.T) {
	tests := []ACLSSHTestInput{{Dst: []string{"tag:db"}, Accept: []string{"root"}, Deny: []string{"guest"}}}
	sshLine := func(src string) string {
		return `[ssh test error]: src "` + src + `" at "100.64.0.1", dst "tag:db" at "100.64.0.2", ssh user "root": want: "accept" got: "deny"`
	}
	for name, errs := range map[string][]string{
		"an SSH failure":    {sshLine("TAG:DB")},
		"a CIDR line":       {shape(t, "a CIDR")},
		"the summary":       {shape(t, "the summary line")},
		"no line":           nil,
		"a line it quotes":  {sshLine("tag:db")},
		"two lines":         {sshLine("tag:db"), shape(t, "the summary line")},
		"a tests-form line": {gridLine("tag:db:22", "tcp", "Accept", "Drop")},
	} {
		for _, user := range []string{"TAG:DB", "tag:db ", " Tag:Db", "other:source"} {
			if user == "other:source" && len(errs) == 0 {
				continue
			}
			v, unmatched, status, _ := deriveSSHVerdicts("tag:db", tests, []api.TestResult{{User: user, Errors: errs}})
			if status != statusUnknown || len(v) != 2 {
				t.Errorf("%s under %q: status %q, verdicts %+v", name, user, status, v)
				continue
			}
			for _, one := range v {
				if one.Verdict != verdictUnknown || one.Why == "" {
					t.Errorf("%s under %q: verdict %+v, want unknown with a reason", name, user, one)
				}
			}
			if !slices.Equal(unmatched, errs) {
				t.Errorf("%s under %q: unmatched %q, want the entry's lines %q", name, user, unmatched, errs)
			}
		}
	}
	// The control: the exact source with no line is a pass for an accept user and a deny user.
	v, _, status, _ := deriveSSHVerdicts("tag:db", tests, []api.TestResult{{User: "tag:db"}})
	if status != statusPass || v[0].Verdict != verdictAllowed || v[1].Verdict != verdictDenied {
		t.Errorf("the exact source with no line: %q %+v", status, v)
	}
}
