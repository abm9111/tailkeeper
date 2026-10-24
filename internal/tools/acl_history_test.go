package tools_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

func serveHistory(f *apitest.Fake, body string) {
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, body)
}

func historyLine(when, group, origin, login, old, new string) string {
	line := struct {
		EventTime    string `json:"eventTime"`
		EventGroupID string `json:"eventGroupID"`
		Origin       string `json:"origin"`
		Action       string `json:"action"`
		Actor        struct {
			ID          string `json:"id"`
			Type        string `json:"type"`
			LoginName   string `json:"loginName"`
			DisplayName string `json:"displayName"`
		} `json:"actor"`
		Old string `json:"old"`
		New string `json:"new"`
	}{
		EventTime: when, EventGroupID: group, Origin: origin, Action: "UPDATE",
		Old: old, New: new,
	}
	line.Actor.ID, line.Actor.Type = "u1", "user"
	line.Actor.LoginName, line.Actor.DisplayName = login, "Amy"
	b, err := json.Marshal(line)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func historyLogs(lines ...string) string {
	return `{"logs":[` + strings.Join(lines, ",") + `]}`
}

func TestACLHistoryListsOneVersionPerACLUpdateWithSizeDigestActorAndOrigin(t *testing.T) {
	f, reg, env := apiEnv(t)
	body := apitest.AuditACLUpdates().Body
	onDisk, err := os.ReadFile("testdata/audit/acl-updates.json")
	text, hasNL := strings.CutSuffix(string(onDisk), "\n")
	if err != nil || !hasNL || strings.HasSuffix(text, "\n") || text != body {
		t.Fatalf("testdata/audit/acl-updates.json is not the H-1 shape's body: %v", err)
	}
	serveHistory(f, body)
	var out tools.ACLHistoryOutput
	raw := mustCall(t, reg, env, "acl_history", `{}`, &out)
	if out.Count != 2 || len(out.Versions) != 2 || out.Skipped != 0 {
		t.Fatalf("count %d, versions %d, skipped %d", out.Count, len(out.Versions), out.Skipped)
	}
	if out.Versions[0].EventTime != "2026-10-01T00:00:00Z" || out.Versions[1].EventTime != "2026-10-08T00:00:00Z" {
		t.Fatalf("order: %s then %s, want oldest first", out.Versions[0].EventTime, out.Versions[1].EventTime)
	}
	if out.Versions[0].Origin != "ADMIN_CONSOLE" || out.Versions[1].Origin != "CONFIG_API" {
		t.Fatalf("origins: %s %s", out.Versions[0].Origin, out.Versions[1].Origin)
	}
	if out.Versions[0].Bytes == 0 || out.Versions[0].PolicySHA256 == "" || out.Versions[0].Previous == "" || out.Note == "" {
		t.Fatalf("first version: %+v, note %q", out.Versions[0], out.Note)
	}
	if strings.Contains(raw, "amy@example.com") || strings.Contains(raw, "tagOwners") {
		t.Fatalf("the result holds a login or a policy text:\n%s", raw)
	}
	q := f.Requests()[0].Query
	if q.Get("event") != "TAILNET.UPDATE.ACL" || q.Get("start") != "2026-09-10T12:00:00Z" || q.Get("end") != "2026-10-10T12:00:00Z" {
		t.Fatalf("default window: %v", q)
	}
	if len(f.Requests()) != 1 {
		t.Fatalf("%d requests for a 30-day window, want 1", len(f.Requests()))
	}
}

func TestTheActorIsMaskedWithAPseudonymAndNoLoginWhileMasking(t *testing.T) {
	const (
		when  = "2026-10-09T00:00:00Z"
		short = "amy@example.com"
		long  = "alexander@example.com"
	)
	one := func(t *testing.T, login string, withKey bool) string {
		t.Helper()
		f, reg, env := apiEnv(t)
		if withKey {
			env, _ = keyed(t, env)
		}
		policy := `{"tagOwners":{"tag:a":["` + login + `"]}}`
		serveHistory(f, historyLogs(historyLine(when, "g1", "ADMIN_CONSOLE", login, `{"tagOwners":{}}`, policy)))
		raw := mustCall(t, reg, env, "acl_history", `{}`, nil)
		if strings.Contains(raw, login) || strings.Contains(raw, "alexander") || strings.Contains(raw, "amy@") {
			t.Fatalf("login %s still in the result:\n%s", login, raw)
		}
		return raw
	}
	shortRaw := one(t, short, false)
	longRaw := one(t, long, false)
	if shortRaw != longRaw {
		t.Fatalf("two logins that mask to one form differ:\n%s\n%s", shortRaw, longRaw)
	}
	keyedRaw := one(t, short, true)
	if !strings.Contains(keyedRaw, "[p:") {
		t.Fatalf("with a privacy key the actor has no pseudonym:\n%s", keyedRaw)
	}
	longKeyed := one(t, long, true)
	var a, b tools.ACLHistoryOutput
	if json.Unmarshal([]byte(keyedRaw), &a) != nil || json.Unmarshal([]byte(longKeyed), &b) != nil || a.Versions[0].Bytes != b.Versions[0].Bytes {
		t.Fatalf("bytes %d and %d, want one size for both logins", a.Versions[0].Bytes, b.Versions[0].Bytes)
	}
}

func TestTheDigestIsKeyedWhileMaskedSha256WithShowAndOmittedWithoutAKey(t *testing.T) {
	body := apitest.AuditACLUpdates().Body
	call := func(t *testing.T, env *registry.Env) tools.ACLHistoryOutput {
		t.Helper()
		f, reg, base := apiEnv(t)
		if env != nil {
			env.API, env.Now = base.API, base.Now
		} else {
			env = base
		}
		serveHistory(f, body)
		var out tools.ACLHistoryOutput
		mustCall(t, reg, env, "acl_history", `{}`, &out)
		return out
	}
	plain := call(t, nil)
	if plain.Versions[0].Digest != "" || plain.Versions[0].PolicyVersion != "" || plain.Versions[0].PolicySHA256 == "" {
		t.Fatalf("no key: digest %q version %q sha %q", plain.Versions[0].Digest, plain.Versions[0].PolicyVersion, plain.Versions[0].PolicySHA256)
	}
	_, _, base := apiEnv(t)
	kenv, key := keyed(t, base)
	keyedOut := call(t, kenv)
	if !strings.HasPrefix(keyedOut.Versions[0].Digest, "hmac-sha256:") || !strings.HasPrefix(keyedOut.Versions[0].PolicyVersion, "hmac-sha256:") {
		t.Fatalf("keyed: digest %q version %q", keyedOut.Versions[0].Digest, keyedOut.Versions[0].PolicyVersion)
	}
	if keyedOut.Versions[0].PolicyVersion != key.Digest([]byte(keyedOut.Versions[0].PolicySHA256)) {
		t.Fatalf("policyVersion %q is not the keyed digest of policySha256 %q", keyedOut.Versions[0].PolicyVersion, keyedOut.Versions[0].PolicySHA256)
	}
	shown := call(t, show(base))
	if !strings.HasPrefix(shown.Versions[0].Digest, "sha256:") || shown.Versions[0].PolicyVersion != shown.Versions[0].PolicySHA256 {
		t.Fatalf("show: digest %q version %q sha %q", shown.Versions[0].Digest, shown.Versions[0].PolicyVersion, shown.Versions[0].PolicySHA256)
	}
}

func TestAnEntryThatEverySliceOfALongWindowReturnsIsListedOnce(t *testing.T) {
	// The slices of a window share their end points, and a log entry on one is returned by
	// both requests; the fake returns the same two entries to all three.
	end := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	f, reg, env := apiEnv(t)
	serveHistory(f, historyLogs(
		historyLine("2026-09-20T00:00:00Z", "g1", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, `{"tagOwners":{"tag:a":[]}}`),
		historyLine("2026-09-20T00:00:00Z", "g2", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, `{"tagOwners":{"tag:b":[]}}`),
		historyLine("2026-10-08T00:00:00Z", "g3", "CONFIG_API", "amy@example.com", `{"tagOwners":{}}`, `{"tagOwners":{"tag:c":[]}}`),
	))
	args := fmt.Sprintf(`{"start":%q,"end":%q}`, end.Add(-90*24*time.Hour).Format(time.RFC3339Nano), end.Format(time.RFC3339Nano))
	var out tools.ACLHistoryOutput
	mustCall(t, reg, env, "acl_history", args, &out)
	if len(f.Requests()) != 3 {
		t.Fatalf("%d requests for 90 days, want 3", len(f.Requests()))
	}
	ids := map[string]bool{}
	for _, v := range out.Versions {
		ids[v.Version] = true
	}
	if out.Count != 3 || len(out.Versions) != 3 || len(ids) != 3 {
		t.Fatalf("count %d, %d versions, %d distinct ids: an entry came back from more than one slice", out.Count, len(out.Versions), len(ids))
	}
	if out.Versions[0].EventTime != "2026-09-20T00:00:00Z" || out.Versions[1].EventTime != "2026-09-20T00:00:00Z" || out.Versions[2].EventTime != "2026-10-08T00:00:00Z" {
		t.Fatalf("order: %v", out.Versions)
	}
}

func TestTheDigestVersionAndShaCoverTheTextAsShownNotTheTextAsItCame(t *testing.T) {
	// Two stored policies that differ only in a credential-shaped string: both show the same
	// replacement, so a digest of the raw text would tell one from the other.
	one := func(t *testing.T, tail string) tools.ACLVersion {
		t.Helper()
		f, reg, env := apiEnv(t)
		env, _ = keyed(t, env)
		policy := `{"tagOwners":{"tag:a":["tskey-api-` + tail + `"]}}`
		serveHistory(f, historyLogs(historyLine("2026-10-09T00:00:00Z", "g1", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, policy)))
		var out tools.ACLHistoryOutput
		raw := mustCall(t, reg, env, "acl_history", `{}`, &out)
		if strings.Contains(raw, tail) || len(out.Versions) != 1 {
			t.Fatalf("the result holds the credential-shaped text or no version: %s", raw)
		}
		return out.Versions[0]
	}
	a, b := one(t, "kAAAAAAAA"), one(t, "kBBBBBBBBBBBBBBBBBBBB")
	if a.Digest == "" || a.PolicyVersion == "" {
		t.Fatalf("a keyed result has no digest or version: %+v", a)
	}
	if a.Digest != b.Digest || a.PolicyVersion != b.PolicyVersion || a.PolicySHA256 != b.PolicySHA256 || a.Bytes != b.Bytes {
		t.Errorf("texts that show alike differ:\n%+v\n%+v", a, b)
	}
}

func TestAnEntryWhoseTextsAreNotStringsOrAreOverTheCapIsSkippedAndCounted(t *testing.T) {
	f, reg, env := apiEnv(t)
	over := strings.Repeat("a", guard.MaxPolicyBytes+1)
	good := historyLine("2026-10-09T00:00:00Z", "g", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, `{"tagOwners":{"tag:a":[]}}`)
	notString := `{"eventTime":"2026-10-08T00:00:00Z","eventGroupID":"g0","origin":"ADMIN_CONSOLE","old":{"tagOwners":{}},"new":"{\"tagOwners\":{}}"}`
	huge := historyLine("2026-10-07T00:00:00Z", "g2", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, over)
	serveHistory(f, historyLogs(notString, huge, good))
	var out tools.ACLHistoryOutput
	mustCall(t, reg, env, "acl_history", `{}`, &out)
	if out.Count != 1 || out.Skipped != 2 || out.Versions[0].EventTime != "2026-10-09T00:00:00Z" {
		t.Fatalf("count %d skipped %d versions %+v", out.Count, out.Skipped, out.Versions)
	}
}

func TestTheWindowIsAtMostNinetyDaysAndIsReadInRequestsOfAtMostThirtyOneDays(t *testing.T) {
	end := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	f, reg, env := apiEnv(t)
	serveHistory(f, `{"logs":[]}`)
	start := end.Add(-90 * 24 * time.Hour)
	args := fmt.Sprintf(`{"start":%q,"end":%q}`, start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano))
	var out tools.ACLHistoryOutput
	mustCall(t, reg, env, "acl_history", args, &out)
	reqs := f.Requests()
	if len(reqs) != 3 {
		t.Fatalf("%d requests for 90 days, want 3", len(reqs))
	}
	prev := start
	for i, r := range reqs {
		s, err1 := time.Parse(time.RFC3339Nano, r.Query.Get("start"))
		e, err2 := time.Parse(time.RFC3339Nano, r.Query.Get("end"))
		if err1 != nil || err2 != nil || e.Sub(s) > 31*24*time.Hour || r.Query.Get("event") != "TAILNET.UPDATE.ACL" {
			t.Fatalf("request %d: %v", i, r.Query)
		}
		if !s.Equal(prev) {
			t.Fatalf("request %d starts at %s, want %s", i, s, prev)
		}
		prev = e
	}
	if !prev.Equal(end) {
		t.Fatalf("last end %s, want %s", prev, end)
	}
	tooWide := fmt.Sprintf(`{"start":%q,"end":%q}`, end.Add(-91*24*time.Hour).Format(time.RFC3339Nano), end.Format(time.RFC3339Nano))
	if _, err := call(t, reg, env, "acl_history", tooWide); code(err) != tkerr.ValidationFailed {
		t.Fatalf("91 days: %v, want validation_failed", err)
	}
	if len(f.Requests()) != 3 {
		t.Fatalf("the refused window sent a request")
	}
}

func TestTheCursorPagesWithoutRepeatOrSkipAcrossEntriesWithTheSameTime(t *testing.T) {
	when := "2026-10-09T00:00:00Z"
	var lines []string
	for i, group := range []string{"g1", "g2", "g3"} {
		lines = append(lines, historyLine(when, group, "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, fmt.Sprintf(`{"tagOwners":{"tag:t%d":[]}}`, i)))
	}
	body := historyLogs(lines...)
	collect := func(t *testing.T, limit int) []string {
		t.Helper()
		f, reg, env := apiEnv(t)
		serveHistory(f, body)
		var ids []string
		args := fmt.Sprintf(`{"limit":%d}`, limit)
		for page := 0; ; page++ {
			if page >= 10 {
				t.Fatalf("limit %d: still paging after %d pages, collected %v", limit, page, ids)
			}
			var out tools.ACLHistoryOutput
			mustCall(t, reg, env, "acl_history", args, &out)
			for _, v := range out.Versions {
				ids = append(ids, v.Version)
			}
			if out.NextCursor == "" {
				break
			}
			args = fmt.Sprintf(`{"cursor":%q,"limit":%d}`, out.NextCursor, limit)
		}
		return ids
	}
	all := collect(t, 10)
	paged := collect(t, 1)
	if len(all) != 3 || strings.Join(all, ",") != strings.Join(paged, ",") {
		t.Fatalf("all %v\npaged %v", all, paged)
	}
}

func TestACursorOfAnotherToolOrFilterIsRefused(t *testing.T) {
	f, reg, env := apiEnv(t)
	body := historyLogs(
		historyLine("2026-10-08T00:00:00Z", "g1", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, `{"tagOwners":{"tag:a":[]}}`),
		historyLine("2026-10-09T00:00:00Z", "g2", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, `{"tagOwners":{"tag:b":[]}}`),
	)
	serveHistory(f, body)
	var audit tools.AuditLogOutput
	mustCall(t, reg, env, "audit_log", `{"limit":1}`, &audit)
	if audit.NextCursor == "" {
		t.Fatal("audit_log issued no cursor")
	}
	_, err := call(t, reg, env, "acl_history", fmt.Sprintf(`{"cursor":%q}`, audit.NextCursor))
	if code(err) != tkerr.ValidationFailed {
		t.Fatalf("audit_log cursor: %v, want validation_failed", err)
	}
}

func TestAHistoryCursorIsRefusedByAnotherPageSizeAndByAuditLog(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveHistory(f, historyLogs(
		historyLine("2026-10-08T00:00:00Z", "g1", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, `{"tagOwners":{"tag:a":[]}}`),
		historyLine("2026-10-09T00:00:00Z", "g2", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, `{"tagOwners":{"tag:b":[]}}`),
	))
	var page tools.ACLHistoryOutput
	mustCall(t, reg, env, "acl_history", `{"limit":1}`, &page)
	if page.NextCursor == "" {
		t.Fatal("acl_history issued no cursor")
	}
	if _, err := call(t, reg, env, "acl_history", fmt.Sprintf(`{"cursor":%q,"limit":2}`, page.NextCursor)); code(err) != tkerr.ValidationFailed {
		t.Errorf("a cursor with another page size: %v, want validation_failed", err)
	}
	if _, err := call(t, reg, env, "audit_log", fmt.Sprintf(`{"cursor":%q,"limit":1}`, page.NextCursor)); code(err) != tkerr.ValidationFailed {
		t.Errorf("a history cursor given to audit_log: %v, want validation_failed", err)
	}
	if _, err := call(t, reg, env, "acl_history", fmt.Sprintf(`{"cursor":%q,"limit":1}`, page.NextCursor)); err != nil {
		t.Errorf("the cursor with its own page size: %v", err)
	}
	keyedEnv, _ := keyed(t, env)
	if _, err := call(t, reg, keyedEnv, "acl_history", fmt.Sprintf(`{"cursor":%q,"limit":1}`, page.NextCursor)); code(err) != tkerr.ValidationFailed {
		t.Errorf("a cursor issued without a key, given with one: %v, want validation_failed", err)
	}
}

func TestAResponseOverTheBodyCapIsAnErrorThatSaysToNarrowTheWindow(t *testing.T) {
	f, reg, env := apiEnv(t)
	env.API = f.Client(t).WithMaxBody(64)
	serveHistory(f, historyLogs(historyLine("2026-10-09T00:00:00Z", "g", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, `{"tagOwners":{"tag:a":[]}}`)))
	_, err := call(t, reg, env, "acl_history", `{}`)
	if code(err) != tkerr.APIError || !strings.Contains(err.Error(), "narrow") {
		t.Fatalf("%v, want api_error that says to narrow the window", err)
	}
}

func TestAMissingLogsScopeIsScopeMissingNamingLogsConfigurationRead(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 403, `{"message":"forbidden"}`)
	_, err := call(t, reg, env, "acl_history", `{}`)
	if code(err) != tkerr.ScopeMissing || !strings.Contains(err.Error(), "logs:configuration:read") {
		t.Fatalf("%v, want scope_missing naming logs:configuration:read", err)
	}
}

const historyDepthChildEnv = "TAILKEEPER_HISTORY_DEPTH_CHILD"

func TestACLHistoryDepthChild(t *testing.T) {
	if os.Getenv(historyDepthChildEnv) == "" {
		return
	}
	f, reg, env := apiEnv(t)
	deep := strings.Repeat("[", 1<<20)
	body := historyLogs(
		historyLine("2026-10-07T00:00:00Z", "g1", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, `{"tagOwners":{"tag:a":[]}}`),
		historyLine("2026-10-08T00:00:00Z", "g2", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, deep),
		historyLine("2026-10-09T00:00:00Z", "g3", "ADMIN_CONSOLE", "amy@example.com", `{"tagOwners":{}}`, `{"tagOwners":{"tag:c":[]}}`),
	)
	serveHistory(f, body)
	var out tools.ACLHistoryOutput
	mustCall(t, reg, env, "acl_history", `{}`, &out)
	if out.Count != 3 || out.Skipped != 0 {
		t.Fatalf("count %d skipped %d", out.Count, out.Skipped)
	}
	fmt.Println("DEPTH-OK acl_history")
}

func TestAListingNeverParsesATextAndSurvivesAMillionLevelsOfNesting(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestACLHistoryDepthChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), historyDepthChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "DEPTH-OK acl_history") {
		t.Fatalf("the child did not finish cleanly: %v\n%s", err, string(out))
	}
}

func TestACLHistoryIsRegisteredReadOnlyWithOnlyTheLogRead(t *testing.T) {
	reg := newRegistry(t)
	tool, ok := reg.Get("acl_history")
	if !ok {
		t.Fatal("acl_history is not registered")
	}
	if tool.Meta.Tier != registry.TierRead || tool.Meta.OpenWorld || len(tool.Meta.Scopes) != 1 || tool.Meta.Scopes[0] != "logs:configuration:read" {
		t.Fatalf("meta: tier %v open %v scopes %v", tool.Meta.Tier, tool.Meta.OpenWorld, tool.Meta.Scopes)
	}
	if len(tool.Meta.Operations) != 1 || tool.Meta.Operations[0] != "GET /tailnet/{tailnet}/logging/configuration" {
		t.Fatalf("operations: %v", tool.Meta.Operations)
	}
	if tool.Meta.MaxResultChars == 0 {
		t.Fatal("MaxResultChars is not declared")
	}
}

func TestAuditLogIsUnchangedByTheCursorGeneralisation(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveHistory(f, apitest.AuditACLUpdates().Body)
	var first tools.AuditLogOutput
	mustCall(t, reg, env, "audit_log", `{"limit":1,"start":"2026-10-01T00:00:00Z","end":"2026-10-10T12:00:00Z"}`, &first)
	if first.Count != 1 || first.NextCursor == "" || first.Entries[0].EventTime != "2026-10-01T00:00:00Z" {
		t.Fatalf("first page: %+v", first)
	}
	var second tools.AuditLogOutput
	mustCall(t, reg, env, "audit_log", fmt.Sprintf(`{"cursor":%q,"limit":1}`, first.NextCursor), &second)
	if second.Count != 1 || second.Entries[0].EventTime != "2026-10-08T00:00:00Z" || second.NextCursor != "" {
		t.Fatalf("second page: %+v", second)
	}
}
