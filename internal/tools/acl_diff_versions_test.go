package tools_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/mcpserver"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// diffVersionID is a version id of the shape encodeVersionID writes: v1. plus
// base64url of the time, the event group, the ordinal and the side.
func diffVersionID(when, group, side string, n int) string {
	b, err := json.Marshal(struct {
		Time    string `json:"t"`
		Group   string `json:"g"`
		Ordinal int    `json:"n"`
		Side    string `json:"s"`
	}{when, group, n, side})
	if err != nil {
		panic(err)
	}
	return "v1." + base64.RawURLEncoding.EncodeToString(b)
}

// logPaths counts the log reads and the policy reads among the requests from index first on.
func logPaths(f *apitest.Fake, first int) (logReads, aclReads int) {
	for _, r := range f.Requests()[first:] {
		switch {
		case strings.HasSuffix(r.Path, "/logging/configuration"):
			logReads++
		case strings.HasSuffix(r.Path, "/acl"):
			aclReads++
		}
	}
	return logReads, aclReads
}

func TestDiffOfTwoVersionsReadsTheLogAndNotTheLivePolicy(t *testing.T) {
	f, reg, env := apiEnv(t)
	when := "2026-10-08T00:00:00Z"
	oldText := `{"tagOwners":{"tag:a":[]}}`
	newText := `{"tagOwners":{"tag:a":[]},"groups":{"group:eng":[]}}`
	serveHistory(f, historyLogs(historyLine(when, "g", "ADMIN_CONSOLE", "amy@example.com", oldText, newText)))
	var hist tools.ACLHistoryOutput
	mustCall(t, reg, env, "acl_history", `{}`, &hist)
	if len(hist.Versions) != 1 {
		t.Fatalf("versions: %+v", hist.Versions)
	}
	if hist.Versions[0].Version != diffVersionID(when, "g", "new", 0) || hist.Versions[0].Previous != diffVersionID(when, "g", "old", 0) {
		t.Fatalf("ids %s %s", hist.Versions[0].Version, hist.Versions[0].Previous)
	}
	before := len(f.Requests())
	args := fmt.Sprintf(`{"fromVersion":%q,"toVersion":%q}`, hist.Versions[0].Previous, hist.Versions[0].Version)
	var out tools.ACLDiffOutput
	raw := mustCall(t, reg, env, "acl_diff", args, &out)
	if out.Status != "changed" || out.Old.Source != "version" || out.New.Source != "version" || out.Old.Version != hist.Versions[0].Previous || out.New.Version != hist.Versions[0].Version {
		t.Fatalf("%+v", out)
	}
	if out.Old.PolicySHA256 == "" || out.New.PolicySHA256 == "" || out.Old.PolicySHA256 == out.New.PolicySHA256 {
		t.Fatalf("digests %s %s", out.Old.PolicySHA256, out.New.PolicySHA256)
	}
	logReads, aclReads := logPaths(f, before)
	if logReads != 2 || aclReads != 0 {
		t.Fatalf("log reads %d, acl reads %d, want 2 and 0", logReads, aclReads)
	}
	absent(t, raw, "amy@example.com")
	for _, c := range out.Changes {
		if c.Note != "" && !stringsContain(acl.ChangeNotes(), c.Note) {
			t.Errorf("note %q is not a fixed sentence", c.Note)
		}
	}
}

func stringsContain(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func TestAVersionAgainstLiveComparesTheHistoricalTextWithTheLivePolicy(t *testing.T) {
	f, reg, env := apiEnv(t)
	when := "2026-10-08T00:00:00Z"
	stored := `{"tagOwners":{"tag:a":["autogroup:admin"]},"acls":[{"action":"accept","src":["tag:a"],"dst":["tag:a:22"]}]}`
	live := `{"tagOwners":{"tag:a":["autogroup:admin"]},"acls":[{"action":"accept","src":["*"],"dst":["tag:a:22"]}]}`
	serveHistory(f, historyLogs(historyLine(when, "g", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, stored)))
	serveLive(f, live, nil, nil)
	id := diffVersionID(when, "g", "new", 0)
	var out tools.ACLDiffOutput
	mustCall(t, reg, env, "acl_diff", fmt.Sprintf(`{"fromVersion":%q}`, id), &out)
	if out.Status != "changed" || out.Counts.Widening != 1 || out.Old.Source != "version" || out.New.Source != "live" || out.Old.Version != id {
		t.Fatalf("%+v counts %+v", out, out.Counts)
	}
	logReads, aclReads := logPaths(f, 0)
	if logReads < 1 || aclReads != 1 {
		t.Fatalf("log reads %d, acl reads %d", logReads, aclReads)
	}
}

// A version that is no id from acl_history is refused whatever the other side holds, and the
// refusal does not repeat it: a text that is not a policy used to end the call as a result of
// status invalid with the version string in it, unmasked.
func TestAMalformedVersionIsRefusedWhateverTheOtherSideHoldsAndIsNeverEchoed(t *testing.T) {
	const secret = "amy@example.com secret-ish 203.0.113.9"
	valid := diffVersionID("2026-10-08T00:00:00Z", "g", "new", 0)
	for name, args := range map[string]string{
		"an old version and a text that is no policy": fmt.Sprintf(`{"fromVersion":%q,"policy":"not a policy {"}`, secret),
		"a new version and a file that is no policy":  fmt.Sprintf(`{"toVersion":%q,"against":"not a policy {"}`, secret),
		"both versions":                         fmt.Sprintf(`{"fromVersion":%q,"toVersion":%q}`, secret, secret),
		"an id of the right prefix and no body": `{"fromVersion":"v1.!!!","policy":"{}"}`,
		"an id over the length acl_diff reads":  fmt.Sprintf(`{"fromVersion":%q,"policy":"{}"}`, "v1."+strings.Repeat("A", 600)),
		"a valid id and a malformed one":        fmt.Sprintf(`{"fromVersion":%q,"toVersion":%q}`, valid, secret),
	} {
		t.Run(name, func(t *testing.T) {
			f, reg, env := apiEnv(t)
			serveHistory(f, historyLogs())
			raw, err := call(t, reg, env, "acl_diff", args)
			if code(err) != tkerr.ValidationFailed {
				t.Fatalf("got %v and %.200s, want validation_failed", err, raw)
			}
			absent(t, err.Error()+raw, "amy@", "203.0.113.9", "secret-ish")
			if len(f.Requests()) != 0 {
				t.Errorf("%d requests for a refused call", len(f.Requests()))
			}
		})
	}
}

func TestAVersionAgainstAFileOrAPatchIsRefusedWhereTheGroupsClash(t *testing.T) {
	_, reg, env := apiEnv(t)
	for _, args := range []string{
		`{"fromVersion":"v1.x","against":"{}"}`,
		`{"toVersion":"v1.x","policy":"{}"}`,
		`{"toVersion":"v1.x","patch":"[]"}`,
	} {
		_, err := call(t, reg, env, "acl_diff", args)
		if code(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), "not both") {
			t.Errorf("%s: %v, want validation_failed naming both", args, err)
		}
	}
}

func TestAVersionSideIsNotCallerTextSoALoginInItIsNotRefusedAndShowsWithAPseudonym(t *testing.T) {
	f, reg, env := apiEnv(t)
	kenv, _ := keyed(t, env)
	when := "2026-10-08T00:00:00Z"
	stored := "{\"groups\": {\"group:ops [p:aaaaaaaaaa]\": [\"amy@example.com\"], \"group:b\": []}}\n"
	other := "{\"groups\": {\"group:b\": []}}\n"
	serveHistory(f, historyLogs(historyLine(when, "g", "ADMIN_CONSOLE", "amy@example.com", other, stored)))
	id := diffVersionID(when, "g", "new", 0)
	raw, err := call(t, reg, kenv, "acl_diff", fmt.Sprintf(`{"fromVersion":%q,"policy":%s}`, id, jsonString(other)))
	if err != nil {
		t.Fatalf("a login in a stored policy was refused: %v", err)
	}
	if strings.Contains(raw, "amy@example.com") || strings.Contains(raw, "[p:aaaaaaaaaa]") {
		t.Fatalf("the login or the forged marker survives: %s", raw)
	}
	if !strings.Contains(raw, "a…@example.com [p:") {
		t.Fatalf("the stored address has no pseudonym: %s", raw)
	}
	var out tools.ACLDiffOutput
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	if out.Old.Source != "version" || out.Status != "changed" {
		t.Fatalf("%+v", out)
	}
	for _, c := range out.Changes {
		if c.Note != "" && !stringsContain(acl.ChangeNotes(), c.Note) {
			t.Errorf("note %q", c.Note)
		}
	}
}

func TestAResolvedLoginIsHiddenInAStoredVersion(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/users", 200, usersBody(t, "ops/amy@example.com"))
	kenv, _ := keyed(t, env)
	ref := shownRef(t, reg, kenv, "u1")
	when := "2026-10-08T00:00:00Z"
	stored := `{"groups":{"group:old":["ops/amy@example.com"]}}`
	caller := `{"groups":{"group:new":["` + ref + `"]}}`
	serveHistory(f, historyLogs(historyLine(when, "g", "ADMIN_CONSOLE", "amy@example.com", `{"groups":{}}`, stored)))
	raw, err := call(t, reg, kenv, "acl_diff", fmt.Sprintf(`{"fromVersion":%q,"policy":%s}`, diffVersionID(when, "g", "new", 0), jsonString(caller)))
	if err != nil {
		t.Fatal(err)
	}
	absent(t, raw, "ops/", "amy@", "ops/amy")
	if !strings.Contains(raw, ref) {
		t.Fatalf("the pseudonym %s is not in the result: %s", ref, raw)
	}
}

func TestAVersionThatTheLogNoLongerHoldsIsNotFoundWithAHint(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveHistory(f, `{"logs":[]}`)
	_, err := call(t, reg, env, "acl_diff", fmt.Sprintf(`{"fromVersion":%q,"policy":"{}"}`, diffVersionID("2026-10-08T00:00:00Z", "g", "new", 0)))
	if code(err) != tkerr.NotFound || !strings.Contains(err.Error(), "no longer holds") || !strings.Contains(err.Error(), "acl history") {
		t.Fatalf("%v, want not_found with the hint", err)
	}
}

func TestAMissingLogsScopeNamesTheOptionalScope(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 403, `{"message":"forbidden"}`)
	_, err := call(t, reg, env, "acl_diff", fmt.Sprintf(`{"fromVersion":%q,"policy":"{}"}`, diffVersionID("2026-10-08T00:00:00Z", "g", "new", 0)))
	if code(err) != tkerr.ScopeMissing || !strings.Contains(err.Error(), "logs:configuration:read") {
		t.Fatalf("%v, want scope_missing naming logs:configuration:read", err)
	}
	// A diff that names no version does not read the log, so the missing scope does not refuse it.
	var out tools.ACLDiffOutput
	mustCall(t, reg, env, "acl_diff", `{"against":"{}\n","policy":"{}\n"}`, &out)
	if out.Status != "equal" || out.Old.Source != "text" {
		t.Fatalf("a diff without a version: %+v", out)
	}
	if _, aclReads := logPaths(f, 0); aclReads != 0 {
		t.Fatalf("the text diff read the live policy")
	}
}

func TestAVersionTextOverTheCapIsRefusedWithItsSize(t *testing.T) {
	f, reg, env := apiEnv(t)
	over := strings.Repeat("a", guard.MaxPolicyBytes+1)
	when := "2026-10-08T00:00:00Z"
	serveHistory(f, historyLogs(historyLine(when, "g", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, over)))
	_, err := call(t, reg, env, "acl_diff", fmt.Sprintf(`{"fromVersion":%q,"policy":"{}"}`, diffVersionID(when, "g", "new", 0)))
	if code(err) != tkerr.ValidationFailed || strings.Contains(err.Error(), fmt.Sprintf("%d", len(over))) || !strings.Contains(err.Error(), fmt.Sprintf("over the cap of %d bytes", guard.MaxPolicyBytes)) {
		t.Fatalf("%v, want only the cap %d", err, guard.MaxPolicyBytes)
	}
	longer := strings.Repeat("a", guard.MaxPolicyBytes) + strings.Repeat("b", 40) + "@example.com"
	f, reg, env = apiEnv(t)
	serveHistory(f, historyLogs(historyLine(when, "g", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, longer)))
	_, err2 := call(t, reg, env, "acl_diff", fmt.Sprintf(`{"fromVersion":%q,"policy":"{}"}`, diffVersionID(when, "g", "new", 0)))
	if err2 == nil || err2.Error() != err.Error() {
		t.Fatalf("two over-cap texts:\n%v\n%v", err, err2)
	}
}

// Two stored policies whose logins differ in length and mask to one form give one result:
// the same bytes, including the page cursor, which is of the masked normal forms.
func TestAStoredVersionWithLoginsOfDifferentLengthsIsByteIdentical(t *testing.T) {
	other := `{"tagOwners":{"tag:ci":[]}}`
	results := map[int]string{}
	cursors := map[int]string{}
	for _, local := range []int{9, 40} {
		f, reg, env := apiEnv(t)
		when := "2026-10-08T00:00:00Z"
		stored := membersOf(200, local)
		serveHistory(f, historyLogs(historyLine(when, "g", "ADMIN_CONSOLE", "amy@example.com", other, stored)))
		raw := mustCall(t, reg, env, "acl_diff", fmt.Sprintf(`{"fromVersion":%q,"policy":%s}`, diffVersionID(when, "g", "new", 0), jsonString(other)), nil)
		results[local] = raw
		var out tools.ACLDiffOutput
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatal(err)
		}
		cursors[local] = out.NextChange
		for _, c := range out.Changes {
			if c.Note != "" && !stringsContain(acl.ChangeNotes(), c.Note) {
				t.Errorf("note %q", c.Note)
			}
		}
	}
	if results[9] != results[40] {
		t.Errorf("the result tells the length of a login:\n%.500s\n%.500s", results[9], results[40])
	}
	if !strings.Contains(results[9], "a…@example.com") {
		t.Fatalf("the result does not quote the members: %.400s", results[9])
	}
	if cursors[9] != cursors[40] {
		t.Fatalf("cursors %q %q, want one cursor of the masked forms", cursors[9], cursors[40])
	}
	// With a privacy key the cursor is keyed: it is not the unkeyed cursor of the same shown text.
	f, reg, env := apiEnv(t)
	kenv, _ := keyed(t, env)
	when := "2026-10-08T00:00:00Z"
	plain := `{"groups":{"group:x":["tag:ci"]}}`
	wide := wideGroups(60)
	serveHistory(f, historyLogs(historyLine(when, "g", "ADMIN_CONSOLE", "amy@example.com", plain, wide)))
	var keyedOut, plainOut tools.ACLDiffOutput
	args := fmt.Sprintf(`{"fromVersion":%q,"toVersion":%q}`, diffVersionID(when, "g", "old", 0), diffVersionID(when, "g", "new", 0))
	mustCall(t, reg, kenv, "acl_diff", args, &keyedOut)
	f2, reg2, env2 := apiEnv(t)
	serveHistory(f2, historyLogs(historyLine(when, "g", "ADMIN_CONSOLE", "amy@example.com", plain, wide)))
	mustCall(t, reg2, env2, "acl_diff", args, &plainOut)
	if !keyedOut.Truncated || !plainOut.Truncated || keyedOut.NextChange == "" || keyedOut.NextChange == plainOut.NextChange {
		t.Fatalf("keyed cursor %q, unkeyed %q", keyedOut.NextChange, plainOut.NextChange)
	}
}

// A finding in a stored policy is placed by its line only: a column counted on the text would
// say how long a login before it on the line is. Two stored policies whose logins differ in
// length, with a duplicate key behind the login on the same line, give one result.
func TestAFindingOnAStoredVersionHasNoColumnSoTwoLoginLengthsGiveOneResult(t *testing.T) {
	results := map[int]string{}
	for _, n := range []int{9, 40} {
		f, reg, env := apiEnv(t)
		when := "2026-10-08T00:00:00Z"
		login := strings.Repeat("q", n) + "@example.com"
		stored := `{"groups":{"group:a":["` + login + `"]},"tagOwners":{},"tagOwners":{}}`
		serveHistory(f, historyLogs(historyLine(when, "g", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, stored)))
		var out tools.ACLDiffOutput
		raw := mustCall(t, reg, env, "acl_diff", fmt.Sprintf(`{"fromVersion":%q,"policy":"{}"}`, diffVersionID(when, "g", "new", 0)), &out)
		located := 0
		for _, p := range out.Old.Findings {
			if p.Line > 0 {
				located++
			}
			if p.Column != 0 {
				t.Errorf("n=%d: a finding on a stored version has column %d: %+v", n, p.Column, p)
			}
		}
		if located == 0 {
			t.Fatalf("n=%d: no finding with a line on the stored side, so the test proves nothing: %.400s", n, raw)
		}
		results[n] = raw
	}
	if results[9] != results[40] {
		t.Errorf("the result tells the length of a login:\n%.600s\n%.600s", results[9], results[40])
	}
}

func TestOfflineRefusesAVersionOnEitherSide(t *testing.T) {
	env := &registry.Env{Now: func() time.Time { return now }}
	id := diffVersionID("2026-10-08T00:00:00Z", "g", "new", 0)
	for name, set := range map[string]func(*tools.ACLDiffInput){
		"an old version": func(in *tools.ACLDiffInput) { in.FromVersion, in.Policy = id, "{}" },
		"a new version":  func(in *tools.ACLDiffInput) { in.ToVersion, in.Against = id, "{}" },
	} {
		_, err := runDiff(t, env, func(in *tools.ACLDiffInput) { set(in); in.Offline, in.Operator = true, true })
		if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidationFailed || !strings.Contains(e.Message, "a version is read from the audit log") {
			t.Errorf("%s: err = %v, want the refusal that names the audit log", name, err)
		}
	}
}

// A change found between two stored policies is placed in the side that holds it, and the
// layout names that side a version: it replaces a file flag with the path the user typed.
func TestAChangeBetweenTwoVersionsIsLocatedInAVersionSide(t *testing.T) {
	f, reg, env := apiEnv(t)
	when := "2026-10-08T00:00:00Z"
	oldText := "{\n\t\"groups\": {\"group:a\": [], \"group:gone\": []}\n}\n"
	newText := "{\n\t\"groups\": {\"group:a\": [], \"group:new\": []}\n}\n"
	serveHistory(f, historyLogs(historyLine(when, "g", "ADMIN_CONSOLE", "amy@example.com", oldText, newText)))
	var out tools.ACLDiffOutput
	mustCall(t, reg, env, "acl_diff", fmt.Sprintf(`{"fromVersion":%q,"toVersion":%q}`, diffVersionID(when, "g", "old", 0), diffVersionID(when, "g", "new", 0)), &out)
	removed, added := 0, 0
	for _, c := range out.Changes {
		switch c.Op {
		case string(acl.OpRemoved):
			removed++
		case string(acl.OpAdded):
			added++
		}
	}
	if removed == 0 || added == 0 {
		t.Fatalf("the comparison found %d removals and %d additions: %+v", removed, added, out.Changes)
	}
	located := 0
	for _, f := range out.Report().Findings {
		if f.Line == 0 {
			continue
		}
		located++
		if f.Source != "version" {
			t.Errorf("a change located in a stored policy has source %q, want version: %+v", f.Source, f)
		}
	}
	if located == 0 {
		t.Fatalf("no change has a line: %+v", out.Report().Findings)
	}
}

func wideGroups(n int) string {
	var b strings.Builder
	b.WriteString(`{"groups":{`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"group:g%02d":[]`, i)
	}
	b.WriteString(`}}`)
	return b.String()
}

func TestInstructionsNameACLHistoryAndEveryNamedToolIsRegistered(t *testing.T) {
	reg := newRegistry(t)
	if !strings.Contains(mcpserver.Instructions, "acl_history") {
		t.Fatal("the instructions do not name acl_history")
	}
	names := regexp.MustCompile(`\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b`).FindAllString(mcpserver.Instructions, -1)
	for _, want := range []string{"acl_get", "users_list", "acl_test", "acl_validate", "acl_diff", "acl_history"} {
		if !stringsContain(names, want) {
			t.Errorf("the scan did not find %s among %v", want, names)
		}
	}
	for _, name := range names {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("the instructions name %s, which is not registered", name)
		}
	}
}
