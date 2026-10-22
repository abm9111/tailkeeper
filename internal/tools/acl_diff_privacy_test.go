package tools_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// What acl_diff shows of a policy is what a caller may see of it: every string of its result,
// and every cut and every number computed on those strings, comes from the masked text.

// loginInDst is a live policy whose rule has a login in its destination; a patch that makes the
// source everyone widens it, and the widening is about that destination.
const loginInDst = "{\n \"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"amy@example.com:22\"]}],\n \"tagOwners\": {\"tag:ci\": []}}\n"

const widenTheSource = `[{"op":"replace","path":"/acls/0/src","value":["*"]}]`

func TestANoteOfAChangeNeverQuotesThePolicy(t *testing.T) {
	for _, withKey := range []bool{false, true} {
		t.Run(fmt.Sprintf("key=%v", withKey), func(t *testing.T) {
			f, reg, env := apiEnv(t)
			if withKey {
				env, _ = keyed(t, env)
			}
			serveLive(f, loginInDst, nil, nil)
			s, err := call(t, reg, env, "acl_diff", patchCall(widenTheSource))
			if err != nil {
				t.Fatal(err)
			}
			absent(t, s, "amy@", "amy%40")
			var out tools.ACLDiffOutput
			if err := json.Unmarshal([]byte(s), &out); err != nil {
				t.Fatal(err)
			}
			closed := acl.ChangeNotes()
			var wide *tools.ACLChange
			for i := range out.Changes {
				c := &out.Changes[i]
				if c.Note != "" && !slices.Contains(closed, c.Note) {
					t.Errorf("the note %q is not one of the engine's sentences", c.Note)
				}
				if c.Class == "widening" {
					wide = c
				}
			}
			if wide == nil {
				t.Fatalf("no widening in %s", s)
			}
			// The destination the widening is about is in the fields, masked as every field is.
			found := false
			for _, d := range wide.Fields {
				if d.Field == "dst" && len(d.Added) == 1 && strings.HasPrefix(d.Added[0], "a…@example.com") {
					found = true
				}
			}
			if !found {
				t.Errorf("the destination is not in the fields of the widening: %+v", wide.Fields)
			}
			if withKey && !strings.Contains(s, "a…@example.com [p:") {
				t.Errorf("a keyed result names the live side's address: %s", s)
			}
		})
	}
}

// A destination shaped like a credential is redacted, and the result still comes back: a
// hostile live policy must not make acl_diff unusable.
func TestACredentialShapedDestinationIsRedactedAndTheResultStillReturns(t *testing.T) {
	f, reg, env := apiEnv(t)
	live := "{\n \"acls\": [{\"action\": \"accept\", \"src\": [\"tag:ci\"], \"dst\": [\"tag:tskey-api-x:80\"]}],\n \"tagOwners\": {\"tag:ci\": []}}\n"
	serveLive(f, live, nil, nil)
	s, err := call(t, reg, env, "acl_diff", patchCall(widenTheSource))
	if err != nil {
		t.Fatalf("the result was withheld: %v", err)
	}
	var out tools.ACLDiffOutput
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "changed" || out.Counts.Widening != 1 {
		t.Errorf("status %q, widening %d: %s", out.Status, out.Counts.Widening, s)
	}
	absent(t, s, "tskey-api-x")
	for _, c := range out.Changes {
		if c.Note != "" && !slices.Contains(acl.ChangeNotes(), c.Note) {
			t.Errorf("the note %q is not one of the engine's sentences", c.Note)
		}
	}
}

// A marker a policy spells itself is not the masker's: the live side of acl_diff sits beside
// the real ones, so every string of a change is rewritten as acl_get and acl_validate rewrite
// theirs.
func TestAForgedMarkerInAPolicyIsRewrittenInEveryStringOfADiff(t *testing.T) {
	f, reg, env := apiEnv(t)
	kenv, _ := keyed(t, env)
	live := "{\"groups\": {\"group:ops [p:aaaaaaaaaa]\": [\"tag:ci\", \"amy@example.com\"], \"group:b\": []},\n \"hosts\": {\"h [p:bbbbbbbbbb]\": \"192.0.2.1\"},\n \"tagOwners\": {\"tag:ci\": []}}\n"
	serveLive(f, live, nil, nil)
	newp := "{\"groups\": {\"group:b\": []},\n \"hosts\": {}, \"tagOwners\": {\"tag:ci\": []}}\n"
	s, err := call(t, reg, kenv, "acl_diff", `{"policy":`+jsonString(newp)+`}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"aaaaaaaaaa", "bbbbbbbbbb"} {
		if strings.Contains(s, "[p:"+m+"]") {
			t.Errorf("the forged marker [p:%s] survives: %s", m, s)
		}
	}
	// The real markers the masker appends are still there.
	if !strings.Contains(s, "a…@example.com [p:") {
		t.Errorf("the address of the live side lost its pseudonym: %s", s)
	}
	// A forged marker in a key shows as the rewritten spelling, in the entry and the pointer.
	var out tools.ACLDiffOutput
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatal(err)
	}
	for _, c := range out.Changes {
		if strings.Contains(c.Entry, "[p:") && c.Op == "removed" && !strings.Contains(c.Entry, "] ") {
			t.Errorf("entry %q holds a marker that was not appended", c.Entry)
		}
	}
}

// A login the resolver handed out and the address scan does not read whole (a slash in the
// local part) is hidden in a diff as in every other result, whichever text named it.
func TestALoginWithASlashIsHiddenInEveryTextADiffTakes(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "ops/amy@example.com", "bob@example.org"))
	kenv, _ := keyed(t, env)
	serveLive(f, "{\"groups\": {\"group:eng\": []}}\n", nil, nil)
	ref := shownRef(t, reg, kenv, "u1")
	member := "{\"groups\": {\"group:eng\": [\"" + ref + "\"]}}\n"
	for name, args := range map[string]string{
		"policy":  `{"policy":` + jsonString(member) + `}`,
		"against": `{"against":` + jsonString(member) + `}`,
		"patch":   `{"patch":` + jsonString(`[{"op":"add","path":"/groups/group:eng/-","value":"`+ref+`"}]`) + `}`,
	} {
		s, err := call(t, newRegistry(t), kenv, "acl_diff", args)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		absent(t, s, "ops/", "amy", "ops")
		var out tools.ACLDiffOutput
		if err := json.Unmarshal([]byte(s), &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Changes) == 0 {
			t.Fatalf("%s: no change was listed, so the test checked nothing: %s", name, s)
		}
		// The user is named by the pseudonym the caller holds.
		if !strings.Contains(s, "["+ref+"]") && !strings.Contains(s, ref) {
			t.Errorf("%s: the pseudonym %s is not in the result: %s", name, ref, s)
		}
	}
}

// membersOf is a live policy whose group holds n members, each a login of the given local-part
// length at one domain: masked, every one of them reads the same.
func membersOf(n, localLen int) string {
	var b strings.Builder
	b.WriteString("{\"groups\": {\"group:big\": [")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		local := fmt.Sprintf("a%0*d", localLen-1, i)
		fmt.Fprintf(&b, "%q", local+"@example.com")
	}
	b.WriteString("]}, \"tagOwners\": {\"tag:ci\": []}}\n")
	return b.String()
}

// What a result cuts of a text is cut after the text is masked: a group of two hundred members
// whose logins are padded by 2 or by 20 bytes reads alike, whatever patch is asked of it, and
// so does every number in the result (the page, the cursor, the counts).
func TestWhereADiffCutsATextTellsNothingOfTheLengthOfALogin(t *testing.T) {
	patch := `[{"op":"remove","path":"/groups/group:big"}]`
	results := map[int]string{}
	for _, local := range []int{9, 40} {
		f, reg, env := apiEnv(t)
		serveLive(f, membersOf(200, local), nil, nil)
		s, err := call(t, reg, env, "acl_diff", patchCall(patch))
		if err != nil {
			t.Fatal(err)
		}
		results[local] = s
	}
	// The logins are different texts of different lengths, and the result is the same bytes.
	if results[9] != results[40] {
		t.Errorf("the result tells the length of a login:\n%.600s\n%.600s", results[9], results[40])
	}
	// The test checks something: the change quotes the members.
	var out tools.ACLDiffOutput
	if err := json.Unmarshal([]byte(results[9]), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Changes) == 0 || !strings.Contains(results[9], "a…@example.com") {
		t.Fatalf("no change quotes the members: %s", results[9])
	}
}

// The same holds for a change of the members of a group, where the members are items of a
// field, and for an entry the engine cuts as a whole.
func TestTheItemsAndTheValuesOfAChangeAreCutAfterMasking(t *testing.T) {
	results := map[int][]string{}
	for _, local := range []int{9, 40} {
		f, reg, env := apiEnv(t)
		serveLive(f, membersOf(200, local), nil, nil)
		var got []string
		for _, newText := range []string{
			"{\"groups\": {\"group:big\": []}, \"tagOwners\": {\"tag:ci\": []}}\n",
			"{\"groups\": {}, \"tagOwners\": {\"tag:ci\": []}}\n",
			"{\"tagOwners\": {\"tag:ci\": []}}\n",
		} {
			s, err := call(t, reg, env, "acl_diff", `{"policy":`+jsonString(newText)+`}`)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, s)
		}
		results[local] = got
	}
	for i := range results[9] {
		if results[9][i] != results[40][i] {
			t.Errorf("case %d tells the length of a login:\n%.700s\n%.700s", i, results[9][i], results[40][i])
		}
		if !strings.Contains(results[9][i], "a…@example.com") {
			t.Errorf("case %d does not quote the members, so it checked nothing: %.400s", i, results[9][i])
		}
	}
}

// A text whose masked form is much shorter than itself is read as far as it takes to fill the
// cut, and no further: a grant whose capabilities name a hundred users with long logins gives
// one result whatever the length of a login, because the shown text is cut at the same place.
func TestWhatIsShownIsReadAsFarAsItTakesToFillTheCut(t *testing.T) {
	grant := func(local int) string {
		var users []string
		for i := range 120 {
			users = append(users, fmt.Sprintf("%q", fmt.Sprintf("u%0*d@example.com", local-1, i)))
		}
		return `{"grants": [{"src": ["tag:a"], "dst": ["tag:b"], "app": {"tailscale.com/cap/test": [{"users": [` + strings.Join(users, ",") + `]}]}}]}`
	}
	results := map[int]string{}
	for _, local := range []int{20, 100} {
		out := twoFiles(t, `{}`, grant(local))
		for _, c := range out.Changes {
			if c.Class == "semantic" {
				results[local] = c.New
			}
		}
	}
	if results[20] != results[100] {
		t.Errorf("the cut tells the length of a login:\n%.300s\n%.300s", results[20], results[100])
	}
	if len(results[20]) < 1000 {
		t.Errorf("the shown text is %d bytes, so the case does not reach the cut", len(results[20]))
	}
}

// With personalData show nothing is hidden, and the engine cuts the text as it is.
func TestWithPersonalDataShownADiffQuotesTheLoginAsItIs(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveLive(f, loginInDst, nil, nil)
	s, err := call(t, reg, show(env), "acl_diff", patchCall(widenTheSource))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "amy@example.com") || strings.Contains(s, "a…@") {
		t.Errorf("the login is masked, or missing, though the owner asked to see it: %s", s)
	}
}
