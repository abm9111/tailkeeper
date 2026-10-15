package tools_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// auditFixture has five entries out of order. Two share a timestamp, and one
// timestamp has fractional seconds, which sorts wrongly as plain text.
const auditFixture = `{"logs":[
{"eventTime":"2026-10-10T10:00:00.5Z","origin":"CONFIG_API","action":"UPDATE","target":{"name":"e3"}},
{"eventTime":"2026-10-10T09:00:00Z","origin":"ADMIN_CONSOLE","action":"CREATE","target":{"name":"e1"}},
{"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE","target":{"name":"e2a"}},
{"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE","target":{"name":"e2b"}},
{"eventTime":"2026-10-10T11:00:00Z","origin":"CONFIG_API","action":"DELETE","target":{"name":"e4"},
 "old":{"acls":[{"action":"accept"}]},"new":null}
]}`

func TestAuditLogPagesWithoutLossOrRepeats(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, auditFixture)
	var names []string
	cursor := ""
	for page := 0; page < 10; page++ {
		args := `{"limit":2}`
		if cursor != "" {
			args = `{"limit":2,"cursor":"` + cursor + `"}`
		}
		var out tools.AuditLogOutput
		mustCall(t, reg, env, "audit_log", args, &out)
		for _, e := range out.Entries {
			names = append(names, e.Target.Name)
		}
		if out.NextCursor == "" {
			break
		}
		cursor = out.NextCursor
	}
	if got := strings.Join(names, ","); got != "e1,e2a,e2b,e3,e4" {
		t.Fatalf("entries across pages = %s, want e1,e2a,e2b,e3,e4", got)
	}
	// Every page asks for the same window.
	reqs := f.Requests()
	for _, r := range reqs[1:] {
		if r.Query.Get("start") != reqs[0].Query.Get("start") || r.Query.Get("end") != reqs[0].Query.Get("end") {
			t.Fatalf("window moved between pages: %v vs %v", r.Query, reqs[0].Query)
		}
	}
}

func TestAuditLogDefaultsAndOldNewDigest(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, auditFixture)
	var out tools.AuditLogOutput
	mustCall(t, reg, env, "audit_log", `{"origin":["config_api"]}`, &out)
	q := f.Requests()[0].Query
	if q.Get("start") != "2026-10-09T12:00:00Z" || q.Get("end") != "2026-10-10T12:00:00Z" {
		t.Errorf("default window = %s .. %s", q.Get("start"), q.Get("end"))
	}
	if out.Count != 2 || out.Entries[1].Target.Name != "e4" {
		t.Fatalf("entries = %+v", out.Entries)
	}
	if e := out.Entries[1]; e.OldDigest != "" || e.NewDigest != "" || e.OldPreview != "" {
		t.Errorf("masked with no key, old/new = %q %q %q", e.OldDigest, e.NewDigest, e.OldPreview)
	}
	// Masking off gives the sha256 digest of the old value; null has none.
	var shown tools.AuditLogOutput
	mustCall(t, reg, show(env), "audit_log", `{"origin":["config_api"]}`, &shown)
	e := shown.Entries[1]
	if !strings.HasPrefix(e.OldDigest, "sha256:") || e.OldPreview != "" || e.NewDigest != "" {
		t.Errorf("old/new = %q %q %q", e.OldDigest, e.OldPreview, e.NewDigest)
	}
	// Previews can hold personal data, so they come only on request.
	var withValues tools.AuditLogOutput
	mustCall(t, reg, show(env), "audit_log", `{"origin":["config_api"],"includeValues":true}`, &withValues)
	if e := withValues.Entries[1]; e.OldPreview == "" || e.OldDigest != shown.Entries[1].OldDigest {
		t.Errorf("with includeValues: old = %q %q", e.OldDigest, e.OldPreview)
	}
}

// While masked with no key the digests are left out, so entries that differ only
// in old/new must still sort the same whatever order the API returns them in.
func TestAuditLogOrderDoesNotDependOnDigests(t *testing.T) {
	a := `{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE","target":{"name":"x"},"old":"one","new":"two"}`
	b := `{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE","target":{"name":"x"},"old":"three","new":"four"}`
	var seen []string
	for _, body := range []string{`{"logs":[` + a + `,` + b + `]}`, `{"logs":[` + b + `,` + a + `]}`} {
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/logging/configuration", 200, body)
		var out tools.AuditLogOutput
		mustCall(t, reg, env, "audit_log", `{"limit":1,"includeValues":true}`, &out)
		seen = append(seen, out.Entries[0].OldPreview)
	}
	if seen[0] != seen[1] {
		t.Errorf("first entry depends on API order: %q vs %q", seen[0], seen[1])
	}
}

// Entries that share a timestamp are ordered by a key over the entry as it is
// displayed, so under any configuration the order is the same whatever order the
// API sent them in, and a cursor is good only under the configuration that issued
// it: under another, the tied entries would sort differently and a page boundary
// inside them would repeat or skip.
func TestAuditLogTieOrderIsAFunctionOfTheDisplayedEntry(t *testing.T) {
	var logs []string
	for i := 0; i < 10; i++ {
		logs = append(logs, fmt.Sprintf(`{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE","actor":{"id":"u%d","loginName":"amy%d@example.com"},"target":{"id":"t%d"},"old":"o%d","new":"n%d"}`, i, i, i, i, i))
	}
	slices.Reverse(logs[:5])
	forward := `{"logs":[` + strings.Join(logs, ",") + `]}`
	slices.Reverse(logs)
	backward := `{"logs":[` + strings.Join(logs, ",") + `]}`
	other, err := privacy.Parse(strings.Repeat("a5", 32))
	if err != nil {
		t.Fatal(err)
	}
	configs := map[string]func(*registry.Env) *registry.Env{
		"masked, no key": func(e *registry.Env) *registry.Env { return e },
		"keyed":          func(e *registry.Env) *registry.Env { k, _ := keyed(t, e); return k },
		"other key": func(e *registry.Env) *registry.Env {
			c := *e
			c.Privacy = other
			return &c
		},
		"masking off": func(e *registry.Env) *registry.Env { return show(e) },
	}
	for name, mk := range configs {
		for _, args := range []string{`{}`, `{"includeValues":true}`} {
			var orders []string
			for _, body := range []string{forward, backward} {
				f, reg, env := apiEnv(t)
				f.JSON("GET", tailnetPath+"/logging/configuration", 200, body)
				var out tools.AuditLogOutput
				mustCall(t, reg, mk(env), "audit_log", args, &out)
				var ids []string
				for _, e := range out.Entries {
					ids = append(ids, e.Target.ID)
				}
				orders = append(orders, strings.Join(ids, ","))
			}
			if orders[0] != orders[1] || strings.Count(orders[0], ",") != 9 {
				t.Errorf("%s %s: tied entries come in %s or %s depending on the API's order", name, args, orders[0], orders[1])
			}
		}
	}
	// A cursor works under the configuration that issued it only.
	for from := range configs {
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/logging/configuration", 200, forward)
		var page tools.AuditLogOutput
		mustCall(t, reg, configs[from](env), "audit_log", `{"limit":3}`, &page)
		for to, mk := range configs {
			_, err := call(t, reg, mk(env), "audit_log", `{"limit":3,"cursor":"`+page.NextCursor+`"}`)
			if (to == from) != (err == nil) || (err != nil && code(err) != tkerr.ValidationFailed) {
				t.Errorf("a cursor from %q used under %q: err = %v", from, to, err)
			}
		}
	}
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, forward)
	var page tools.AuditLogOutput
	mustCall(t, reg, env, "audit_log", `{"limit":3}`, &page)
	if _, err := call(t, reg, env, "audit_log", `{"limit":3,"includeValues":true,"cursor":"`+page.NextCursor+`"}`); code(err) != tkerr.ValidationFailed {
		t.Errorf("a cursor issued without includeValues, used with it: %v", err)
	}
}

// No raw value feeds the tie-break key: entries that display alike sort alike,
// whatever the logins and the old and new values behind them were.
func TestAuditLogTieKeyHoldsNoRawValue(t *testing.T) {
	order := func(prefix string) string {
		var logs []string
		for i := 0; i < 12; i++ {
			logs = append(logs, fmt.Sprintf(`{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE","actor":{"id":"u%d","loginName":"%s%d@example.com","displayName":"%s%d"},"target":{"id":"t%d"},"old":"%s%d@example.com","new":"%s%d@example.org"}`,
				i, prefix, i, prefix, i, i, prefix, i, prefix, i))
		}
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[`+strings.Join(logs, ",")+`]}`)
		var out tools.AuditLogOutput
		mustCall(t, reg, env, "audit_log", `{"includeValues":true}`, &out)
		var ids []string
		for _, e := range out.Entries {
			ids = append(ids, e.Target.ID)
		}
		return strings.Join(ids, ",")
	}
	// Both display as "a…@example.com" and "a…", with no digest, and previews of
	// "a…@example.com" and "a…@example.org".
	if a, b := order("amy"), order("ann"); a != b {
		t.Errorf("entries that display alike came in %s and %s", a, b)
	}
}

// Entries that are identical once masked cannot be told apart by the caller, so
// their order is free; paging over them must still return each exactly once.
func TestAuditLogPagesOverEntriesIdenticalAfterMasking(t *testing.T) {
	f, reg, env := apiEnv(t)
	var logs []string
	for i := 0; i < 7; i++ {
		logs = append(logs, fmt.Sprintf(`{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE","actor":{"id":"u","loginName":"amy%d@example.com"},"target":{"id":"t"},"old":"o%d","new":"n%d"}`, i, i, i))
	}
	logs = append(logs, `{"eventTime":"2026-10-10T11:00:00Z","origin":"CONFIG_API","action":"UPDATE","target":{"id":"late"}}`)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[`+strings.Join(logs, ",")+`]}`)
	for _, limit := range []int{1, 2, 3, 7} {
		total, pages, cursor := 0, 0, ""
		var last string
		for ; pages < 20; pages++ {
			args := fmt.Sprintf(`{"limit":%d}`, limit)
			if cursor != "" {
				args = fmt.Sprintf(`{"limit":%d,"cursor":"%s"}`, limit, cursor)
			}
			var out tools.AuditLogOutput
			mustCall(t, reg, env, "audit_log", args, &out)
			total += len(out.Entries)
			if len(out.Entries) > 0 {
				last = out.Entries[len(out.Entries)-1].Target.ID
			}
			if out.NextCursor == "" {
				break
			}
			cursor = out.NextCursor
		}
		if total != 8 || last != "late" {
			t.Errorf("limit %d: %d entries over the pages, last %q, want 8 and late", limit, total, last)
		}
	}
}

// Where old and new are told apart by the key, a split of the same text between
// them is a different entry: ("ab", "c") and ("a", "bc") must not tie, and
// ("a", "b") and ("a", "c") differ in new alone. The entries are alike in all else,
// so only the digests and previews tell them apart (masking off shows both); the
// order of the five is the same whichever way the API sent them.
func TestAuditLogTieKeySeparatesOldFromNew(t *testing.T) {
	pairs := [][2]string{{"ab", "c"}, {"a", "bc"}, {"a", "b"}, {"a", "c"}, {"b", "a"}}
	var logs []string
	for _, p := range pairs {
		logs = append(logs, fmt.Sprintf(`{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE","target":{"id":"t"},"old":%q,"new":%q}`, p[0], p[1]))
	}
	var orders []string
	for n := 0; n < len(logs); n++ {
		rotated := append(slices.Clone(logs[n:]), logs[:n]...)
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[`+strings.Join(rotated, ",")+`]}`)
		var out tools.AuditLogOutput
		// The previews alone tell the pairs apart here, so the key must read them
		// as two fields.
		mustCall(t, reg, show(env), "audit_log", `{"includeValues":true}`, &out)
		var shown []string
		for _, e := range out.Entries {
			shown = append(shown, e.OldPreview+"|"+e.NewPreview)
		}
		orders = append(orders, strings.Join(shown, ","))
	}
	for _, o := range orders {
		if o != orders[0] || strings.Count(o, ",") != len(pairs)-1 {
			t.Fatalf("tied entries come in %v depending on the API's order", orders)
		}
	}
}

func TestAuditLogCursorRules(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, auditFixture)
	var out tools.AuditLogOutput
	mustCall(t, reg, env, "audit_log", `{"limit":1}`, &out)
	for _, args := range []string{
		`{"limit":1,"cursor":"` + out.NextCursor + `","start":"2026-10-10T00:00:00Z"}`, // window from the cursor only
		`{"limit":2,"cursor":"` + out.NextCursor + `"}`,                                // filters changed
		`{"cursor":"not-a-cursor"}`,
		`{"limit":1,"cursor":"` + forge(t, out.NextCursor, map[string]any{"s": "2000-01-01T00:00:00Z", "e": "2030-01-01T00:00:00Z"}) + `"}`, // a forged window past 31 days
		`{"limit":1,"cursor":"` + forge(t, out.NextCursor, map[string]any{"s": "2026-10-10T12:00:00Z", "e": "2026-10-09T12:00:00Z"}) + `"}`, // start after end
		`{"limit":1,"cursor":"` + forge(t, out.NextCursor, map[string]any{"t": "2020-01-01T00:00:00Z"}) + `"}`,                              // boundary outside the window
		`{"start":"2026-08-01T00:00:00Z","end":"2026-10-01T00:00:00Z"}`,                                                                     // more than 31 days
		`{"limit":5001}`,
	} {
		if _, err := call(t, reg, env, "audit_log", args); code(err) != tkerr.ValidationFailed {
			t.Errorf("%s: err = %v, want validation_failed", args, err)
		}
	}
}

func TestFlowLogsNotEnabledSkipsTheLogCall(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/settings", 200, `{"networkFlowLoggingOn":false}`)
	var out tools.FlowLogsOutput
	mustCall(t, reg, env, "network_flow_logs", `{}`, &out)
	if out.Status != "not_enabled" || out.LoggingEnabled != "false" || len(f.Requests()) != 1 {
		t.Errorf("out = %+v, requests = %d", out, len(f.Requests()))
	}
}

func TestFlowLogsUnknownWhenSettingsUnreadable(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/settings", 403, `{"message":"forbidden"}`)
	f.JSON("GET", tailnetPath+"/logging/network", 200, `{"logs":[{"nodeId":"nAAA1CNTRL","logged":"2026-10-10T11:59:00Z",
		"virtualTraffic":[{"proto":6,"src":"100.64.0.1:5000","dst":"100.64.0.2:443","txBytes":10}],
		"physicalTraffic":[{"src":"100.64.0.1:0","dst":"192.0.2.1:41641","rxBytes":7}]}]}`)
	var out tools.FlowLogsOutput
	mustCall(t, reg, env, "network_flow_logs", `{"maxRecords":5}`, &out)
	if out.Status != "ok" || out.LoggingEnabled != "unknown" || out.Count != 1 {
		t.Fatalf("out = %+v", out)
	}
	if fl := out.Records[0].Flows; len(fl) != 2 || fl[0].Kind != "virtual" || fl[0].Proto != "tcp" || fl[1].Kind != "physical" {
		t.Errorf("flows = %+v", fl)
	}
}

func TestFlowLogProtoAcceptsNumberOrName(t *testing.T) {
	// The docs and Tailscale's encoder use numbers; the OpenAPI document uses names.
	for body, want := range map[string]string{`6`: "tcp", `"udp"`: "udp", `250`: "250", `null`: ""} {
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/settings", 200, `{"networkFlowLoggingOn":true}`)
		f.JSON("GET", tailnetPath+"/logging/network", 200, `{"logs":[{"nodeId":"n1","virtualTraffic":[{"proto":`+body+`}]}]}`)
		var out tools.FlowLogsOutput
		mustCall(t, reg, env, "network_flow_logs", `{}`, &out)
		if got := out.Records[0].Flows[0].Proto; got != want {
			t.Errorf("proto %s decoded as %q, want %q", body, got, want)
		}
	}
}

func TestFlowLogsNotAvailableOn404(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/settings", 200, `{"networkFlowLoggingOn":true}`)
	var out tools.FlowLogsOutput
	mustCall(t, reg, env, "network_flow_logs", `{}`, &out)
	if out.Status != "not_available" || out.LoggingEnabled != "true" {
		t.Errorf("out = %+v", out)
	}
}

func TestLogStreamingOmitsSecrets(t *testing.T) {
	f, reg, env := apiEnv(t)
	// Assembled so that no literal in the repository is a URL with credentials in it.
	withUser := "https://user:" + "PASS-CANARY" + "@siem.example.test/collector?token=QUERY-CANARY"
	f.JSON("GET", tailnetPath+"/logging/configuration/stream", 200, `{"destinationType":"splunk",
		"url":`+jsonString(withUser)+`,"token":"TOKEN-CANARY",
		"s3SecretAccessKey":"S3-CANARY","gcsCredentials":"GCS-CANARY"}`)
	f.JSON("GET", tailnetPath+"/logging/configuration/stream/status", 403, `{"message":"forbidden"}`)
	var out tools.LogStreamOutput
	s := mustCall(t, reg, env, "log_streaming_get", `{"logType":"configuration"}`, &out)
	absent(t, s, "CANARY")
	sum := sha256.Sum256([]byte("/collector?token=QUERY-CANARY"))
	if out.Configuration.URL != "https://siem.example.test" || out.Configuration.URLPathHash != hex.EncodeToString(sum[:]) ||
		out.HealthError != string(tkerr.ScopeMissing) {
		t.Errorf("out = %+v", out)
	}
	// HTTP collectors (Sumo Logic style) carry their secret in the path.
	f.JSON("GET", tailnetPath+"/logging/network/stream", 200, `{"destinationType":"sumo","url":"https://collectors.example.test/receiver/v1/http/PATH-CANARY"}`)
	f.JSON("GET", tailnetPath+"/logging/network/stream/status", 403, `{"message":"forbidden"}`)
	s = mustCall(t, reg, env, "log_streaming_get", `{"logType":"network"}`, &out)
	absent(t, s, "CANARY")
	if out.Configuration.URL != "https://collectors.example.test" || out.Configuration.URLPathHash == "" {
		t.Errorf("out = %+v", out.Configuration)
	}
}

// forge rewrites fields of a cursor, as a caller could: cursors are not signed.
func forge(t *testing.T, cursor string, set map[string]any) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range set {
		m[k] = v
	}
	b, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestAuditLogPagingIgnoresTieOrder(t *testing.T) {
	f, reg, env := apiEnv(t)
	// Every call returns the four tied entries in a different order.
	var calls atomic.Int64
	f.Handle("GET", tailnetPath+"/logging/configuration", func(w http.ResponseWriter, _ *http.Request) {
		tied := []string{"t0", "t1", "t2", "t3"}
		n := int(calls.Add(1)-1) % len(tied)
		tied = append(tied[n:], tied[:n]...)
		var logs []string
		for _, name := range tied {
			logs = append(logs, `{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE","target":{"name":"`+name+`"}}`)
		}
		logs = append(logs, `{"eventTime":"2026-10-10T11:00:00Z","origin":"CONFIG_API","action":"UPDATE","target":{"name":"late"}}`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"logs":[` + strings.Join(logs, ",") + `]}`))
	})
	seen := map[string]int{}
	cursor := ""
	for page := 0; page < 10; page++ {
		args := `{"limit":2}`
		if cursor != "" {
			args = `{"limit":2,"cursor":"` + cursor + `"}`
		}
		var out tools.AuditLogOutput
		mustCall(t, reg, env, "audit_log", args, &out)
		for _, e := range out.Entries {
			seen[e.Target.Name]++
		}
		if out.NextCursor == "" {
			break
		}
		cursor = out.NextCursor
	}
	if len(seen) != 5 {
		t.Fatalf("entries seen = %v, want t0-t3 and late once each", seen)
	}
	for name, n := range seen {
		if n != 1 {
			t.Errorf("%s seen %d times", name, n)
		}
	}
}

func TestLogStreamingFlagsStaleActivity(t *testing.T) {
	for _, c := range []struct {
		last   string
		period int
		want   bool
	}{
		{"2026-10-10T11:30:00Z", 5, false},       // 30 minutes before now: within the hour floor
		{"2026-10-10T08:00:00Z", 5, true},        // 4 hours
		{"", 5, true},                            // nothing shows that delivery works
		{"2026-10-06T12:00:00Z", 50000000, true}, // 4 days: an absurd period is capped at a day
	} {
		last, want := c.last, c.want
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/logging/network/stream", 200, `{"destinationType":"s3","uploadPeriodMinutes":`+strconv.Itoa(c.period)+`,"s3RoleArn":`+jsonString("arn"+r(0x1B)+"[2J")+`}`)
		f.JSON("GET", tailnetPath+"/logging/network/stream/status", 200, `{"lastActivity":`+jsonString(last)+`,"numTotalRequests":10}`)
		var out tools.LogStreamOutput
		mustCall(t, reg, env, "log_streaming_get", `{"logType":"network"}`, &out)
		if got := slices.Contains(out.Findings, "stale_activity"); got != want {
			t.Errorf("lastActivity %q: findings %v", last, out.Findings)
		}
		if out.Configuration.S3RoleARN != `arn\u{001B}[2J` {
			t.Errorf("s3RoleArn = %q", out.Configuration.S3RoleARN)
		}
	}
}

// The server-side filters reach the API as repeated query parameters. A ~search
// actor is a literal name filter, so this runs with masking off.
func TestAuditLogSendsItsFilters(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[]}`)
	// With masking off a target literal is matched here, against the target as
	// shown, and never sent (TestAuditLogTargetFilterReadsTheTargetAsShownWhileUnmasked).
	mustCall(t, reg, show(env), "audit_log", `{"actor":["u1","~amy"],"target":["web"],"event":["TAILNET.UPDATE.ACL"]}`, nil)
	q := f.Requests()[0].Query
	if strings.Join(q["actor"], ",") != "u1,~amy" || q.Has("target") || q.Get("event") != "TAILNET.UPDATE.ACL" {
		t.Errorf("query = %v", q)
	}
	// Masked, a plain ID narrows at the server, then must match exactly here.
	mustCall(t, reg, env, "audit_log", `{"target":["web"]}`, nil)
	if q := f.Requests()[1].Query; q.Get("target") != "web" {
		t.Errorf("masked query = %v", q)
	}
}

func TestLogToolsReturnAPIErrorsAndCheckTheirInput(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 404, `{"message":"not found"}`)
	f.JSON("GET", tailnetPath+"/settings", 200, `{"networkFlowLoggingOn":true}`)
	f.JSON("GET", tailnetPath+"/logging/network", 500, `{"message":"boom"}`)
	if _, err := call(t, reg, env, "audit_log", `{}`); code(err) != tkerr.NotFound {
		t.Errorf("audit_log: err = %v, want not_found", err)
	}
	if _, err := call(t, reg, env, "network_flow_logs", `{}`); err == nil {
		t.Error("network_flow_logs: a failed log read must be an error, not an empty answer")
	}
	for _, args := range []string{`{"maxRecords":10001}`, `{"maxRecords":-1}`, `{"start":"yesterday"}`} {
		if _, err := call(t, reg, env, "network_flow_logs", args); code(err) != tkerr.ValidationFailed {
			t.Errorf("network_flow_logs %s: err = %v, want validation_failed", args, err)
		}
	}
}

func TestAuditLogNeverShowsAWebhookURLOrAToken(t *testing.T) {
	f, reg, env := apiEnv(t)
	token := strings.Repeat("Q", 24)
	hook := "https://hooks.example.test/services/T0/B0/" + token
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[
	 {"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE","action":"CREATE",
	  "target":{"id":"w1","name":"`+hook+`","type":"WEBHOOK_ENDPOINT"},"actionDetails":"created `+hook+`",
	  "new":{"endpointUrl":"`+hook+`","secret":"PLANTED-WEBHOOK-SECRET"}},
	 {"eventTime":"2026-10-10T10:05:00Z","origin":"CONFIG_API","action":"UPDATE",
	  "target":{"id":"s1","name":"logstream configuration","type":"LOGSTREAM_ENDPOINT"},
	  "old":{"url":"https://logs.example.test/collector","token":"PLANTED-STREAM-TOKEN"}}]}`)
	for _, e := range []*registry.Env{env, show(env)} {
		out := mustCall(t, reg, e, "audit_log", `{"includeValues":true}`, nil)
		for _, leak := range []string{token, "/services/", "/collector", "PLANTED"} {
			if strings.Contains(out, leak) {
				t.Errorf("audit_log shows %q: %s", leak, out)
			}
		}
		if !strings.Contains(out, "https://hooks.example.test") || !strings.Contains(out, "https://logs.example.test") {
			t.Errorf("the hosts should still show: %s", out)
		}
	}
}

// Every free-text field of an entry is cut, not only the ones that usually hold
// a name. The host is asserted in each, so a fixture key that decoded to nothing
// would fail here instead of passing for want of a URL.
func TestAuditLogCutsEveryFreeTextField(t *testing.T) {
	f, reg, env := apiEnv(t)
	token := strings.Repeat("Q", 24)
	hook := "https://hooks.example.test/services/T0/B0/" + token
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[
	 {"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE","action":"CREATE",
	  "target":{"id":"w1","name":"name `+hook+`","type":"WEBHOOK_ENDPOINT","property":"property `+hook+`"},
	  "actionDetails":"details `+hook+`","error":"error `+hook+`"}]}`)
	for name, e := range map[string]*registry.Env{"masked": env, "shown": show(env)} {
		var out tools.AuditLogOutput
		s := mustCall(t, reg, e, "audit_log", `{}`, &out)
		if len(out.Entries) != 1 {
			t.Fatalf("%s: %d entries", name, len(out.Entries))
		}
		en := out.Entries[0]
		for field, v := range map[string]string{"target.name": en.Target.Name, "target.property": en.Target.Property,
			"actionDetails": en.ActionDetails, "error": en.Error} {
			if !strings.Contains(v, "https://hooks.example.test/…[path sha256 ") {
				t.Errorf("%s: %s = %q, want the host and a path hash", name, field, v)
			}
		}
		absent(t, s, token, "/services/", "T0/B0")
	}
}

// A filter reads an entry as the result shows it. An address inside a URL path is
// cut away before anything filters, so its pseudonym matches only the entry that
// still shows the address.
func TestAuditLogFiltersReadTheCutName(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[
	 {"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE","action":"CREATE","target":{"id":"t1","name":"https://hooks.example.test/u/amy@example.com"}},
	 {"eventTime":"2026-10-10T10:01:00Z","origin":"ADMIN_CONSOLE","action":"CREATE","target":{"id":"t2","name":"mail amy@example.com"}}]}`)
	kenv, k := keyed(t, env)
	var all, got tools.AuditLogOutput
	mustCall(t, reg, kenv, "audit_log", `{}`, &all)
	if len(all.Entries) != 2 || !strings.HasPrefix(all.Entries[0].Target.Name, "https://hooks.example.test/…") || strings.Contains(all.Entries[0].Target.Name, "amy") ||
		!strings.Contains(all.Entries[1].Target.Name, "[p:") {
		t.Fatalf("entries = %+v", all.Entries)
	}
	mustCall(t, reg, kenv, "audit_log", `{"target":["`+k.Pseudonym("amy@example.com")+`"]}`, &got)
	if len(got.Entries) != 1 || got.Entries[0].Target.ID != "t2" {
		t.Errorf("the pseudonym of an address the display does not show matched: %+v", got.Entries)
	}
}

// While masking is off the target filter used to go to the server, which matches
// it against the raw target, and the entry came back whole: a caller could confirm
// a guess at a webhook's path one character at a time. A literal now matches only
// the target as shown, so what the cut hides cannot be confirmed.
func TestAuditLogTargetFilterReadsTheTargetAsShownWhileUnmasked(t *testing.T) {
	f, reg, env := apiEnv(t)
	token := strings.Repeat("Q", 24)
	hook := "https://hooks.example.test/services/T0/B0/" + token
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[
	 {"eventTime":"2026-10-10T10:00:00Z","origin":"ADMIN_CONSOLE","action":"CREATE",
	  "target":{"id":"w1","name":"`+hook+`","type":"WEBHOOK_ENDPOINT","property":"endpointUrl"}},
	 {"eventTime":"2026-10-10T10:01:00Z","origin":"ADMIN_CONSOLE","action":"CREATE","target":{"id":"x2","name":"other","type":"ACL"}}]}`)
	ids := func(e *registry.Env, args string) string {
		var out tools.AuditLogOutput
		mustCall(t, reg, e, "audit_log", args, &out)
		var s []string
		for _, en := range out.Entries {
			s = append(s, en.Target.ID)
		}
		return strings.Join(s, ",")
	}
	shown := show(env)
	if got := ids(shown, `{}`); got != "w1,x2" {
		t.Fatalf("unfiltered = %q, want both entries", got)
	}
	// Pieces of the path, singly and with the host before them: nothing.
	for _, guess := range []string{token, token[:4], "QQ", "services", "/services/T0", "T0/B0", "B0/" + token[:1], "hooks.example.test/services", "test/services"} {
		if got := ids(shown, `{"target":[`+jsonString(guess)+`]}`); got != "" {
			t.Errorf("a target filter for %q confirmed the hidden path: entries %q", guess, got)
		}
	}
	// What the result shows: the host, the type, the property, the ID, in any case.
	for guess, want := range map[string]string{"hooks.example": "w1", "HOOKS.EXAMPLE.TEST": "w1", "https://hooks.example.test": "w1",
		"webhook_endpoint": "w1", "ENDPOINTURL": "w1", "w1": "w1", "x2": "x2", "oth": "x2", "path sha256": "w1", "": "w1,x2"} {
		if got := ids(shown, `{"target":[`+jsonString(guess)+`]}`); got != want {
			t.Errorf("a target filter for %q returned %q, want %q", guess, got, want)
		}
	}
	// A list matches an entry if any literal does; a miss beside a hit confirms nothing.
	if got := ids(shown, `{"target":["`+token+`","hooks.example"]}`); got != "w1" {
		t.Errorf("a miss beside a hit: %q", got)
	}
	if got := ids(shown, `{"target":["`+token+`","nothing"]}`); got != "" {
		t.Errorf("two misses: %q", got)
	}
	if sent(f, "hooks") || sent(f, "QQ") || len(f.Requests()[0].Query["target"]) != 0 {
		t.Error("a target literal reached the server, which would match it against the raw target")
	}
	// Masked, a target takes exact IDs and pseudonyms only, as before.
	if got := ids(env, `{"target":["`+token[:4]+`"]}`); got != "" {
		t.Errorf("masked: a fragment returned %q", got)
	}
	if got := ids(env, `{"target":["w1"]}`); got != "w1" {
		t.Errorf("masked: an exact ID returned %q", got)
	}
}

// Entries that display alike sort alike: neither a URL's user info, which the cut
// drops, nor a credential the preview removes may feed the tie-break key.
func TestAuditLogTieOrderHoldsNothingTheCutOrTheRedactionRemoved(t *testing.T) {
	order := func(prefix string) string {
		var logs []string
		for i := 0; i < 12; i++ {
			name := fmt.Sprintf("https://%s%d:%s@hooks.example.test/services/T0", prefix, i, "x")
			logs = append(logs, fmt.Sprintf(`{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE","target":{"id":"t%d","name":%q},"old":{"token":"%s%d"},"new":{"secret":"%s%d"}}`,
				i, name, prefix, i, prefix, i))
		}
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[`+strings.Join(logs, ",")+`]}`)
		var out tools.AuditLogOutput
		mustCall(t, reg, env, "audit_log", `{"includeValues":true}`, &out)
		var ids []string
		for _, e := range out.Entries {
			if !strings.HasPrefix(e.Target.Name, "https://hooks.example.test/…") || !strings.Contains(e.OldPreview, "[removed]") {
				t.Fatalf("entry %+v is not cut and redacted", e)
			}
			ids = append(ids, e.Target.ID)
		}
		return strings.Join(ids, ",")
	}
	if a, b := order("amy"), order("ann"); a != b {
		t.Errorf("entries that display alike came in %s and %s", a, b)
	}
}

// A string that holds a JSON document is searched for credentials too, and the
// digest stays over the value as the API sent it.
func TestAuditLogPreviewRemovesCredentialsInsideAString(t *testing.T) {
	f, reg, env := apiEnv(t)
	old := `"{\"url\":\"https://logs.example.test/collector\",\"token\":\"PLANTED-IN-STRING\",\"n\":1}"`
	nw := `{"outer":"{\"secret\":\"PLANTED-NESTED\"}","note":"the word token in text"}`
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE",
		"target":{"id":"s1"},"old":`+old+`,"new":`+nw+`}]}`)
	for name, e := range map[string]*registry.Env{"masked": env, "shown": show(env)} {
		var out tools.AuditLogOutput
		s := mustCall(t, reg, e, "audit_log", `{"includeValues":true}`, &out)
		absent(t, s, "PLANTED", "/collector")
		en := out.Entries[0]
		if !strings.Contains(en.OldPreview, "https://logs.example.test/…") || !strings.Contains(en.OldPreview, `"n":1`) {
			t.Errorf("%s: old preview = %q", name, en.OldPreview)
		}
		if !strings.Contains(en.NewPreview, "the word token in text") {
			t.Errorf("%s: new preview = %q", name, en.NewPreview)
		}
	}
	var out tools.AuditLogOutput
	mustCall(t, reg, show(env), "audit_log", `{}`, &out)
	oldSum, newSum := sha256.Sum256([]byte(old)), sha256.Sum256([]byte(nw))
	if out.Entries[0].OldDigest != "sha256:"+hex.EncodeToString(oldSum[:]) || out.Entries[0].NewDigest != "sha256:"+hex.EncodeToString(newSum[:]) {
		t.Errorf("the digests are not over the raw values: %q %q", out.Entries[0].OldDigest, out.Entries[0].NewDigest)
	}
}

// The old and new values of a policy edit are the policy file as a string, and a policy
// file is HuJSON: a credential-named key in it is removed from the preview though the
// text is not strict JSON, and a policy with nothing to remove is shown as the API sent
// it, comments and commas included. Digests stay over the raw values.
func TestAuditLogPreviewRemovesCredentialsInsideAHuJSONPolicy(t *testing.T) {
	f, reg, env := apiEnv(t)
	old := "{\n  // owners\n  \"groups\": {\"group:a\": [\"x\"],},\n  \"token\": \"PLANTED-HU\", /* rotate */\n}\n"
	nw := `{ /* kept as written */ "groups": {"group:a": ["y"],}, "n": 1.50, }`
	oldJSON, nwJSON := jsonString(old), jsonString(nw)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE",
		"target":{"id":"p1"},"old":`+oldJSON+`,"new":`+nwJSON+`}]}`)
	for name, e := range map[string]*registry.Env{"masked": env, "shown": show(env)} {
		var out tools.AuditLogOutput
		s := mustCall(t, reg, e, "audit_log", `{"includeValues":true}`, &out)
		absent(t, s, "PLANTED", "rotate")
		en := out.Entries[0]
		if !strings.Contains(en.OldPreview, `"groups"`) || !strings.Contains(en.OldPreview, `[removed]`) {
			t.Errorf("%s: old preview = %q", name, en.OldPreview)
		}
		if en.NewPreview != nw {
			t.Errorf("%s: new preview = %q, want the API's text %q", name, en.NewPreview, nw)
		}
	}
	var out tools.AuditLogOutput
	mustCall(t, reg, show(env), "audit_log", `{}`, &out)
	oldSum, newSum := sha256.Sum256([]byte(oldJSON)), sha256.Sum256([]byte(nwJSON))
	if out.Entries[0].OldDigest != "sha256:"+hex.EncodeToString(oldSum[:]) || out.Entries[0].NewDigest != "sha256:"+hex.EncodeToString(newSum[:]) {
		t.Errorf("the digests are not over the raw values: %q %q", out.Entries[0].OldDigest, out.Entries[0].NewDigest)
	}
}

// The commonest policy file opens with a comment, and a file may open with a byte order
// mark: the credential-named value is removed all the same, and a policy with nothing to
// remove is the API's text.
func TestAuditLogPreviewRemovesCredentialsBehindALeadingCommentOrAByteOrderMark(t *testing.T) {
	for name, c := range map[string]struct{ lead, trail string }{
		"line comment":                {"// policy\n", ""},
		"block comment":               {"/* policy */ ", ""},
		"byte order mark":             {"\ufeff", ""},
		"byte order mark, comment":    {"\ufeff// policy\n", ""},
		"trailing line comment":       {"", "\n// end\n"},
		"trailing, no line feed":      {"", " // end"},
		"comments on both sides":      {"// policy\n", "\n/* end */\n"},
		"byte order mark, both sides": {"\ufeff/* policy */", " // end"},
	} {
		f, reg, env := apiEnv(t)
		old := c.lead + `{"groups": {"group:a": ["x"],}, "token": "PLANTED-HU",}` + c.trail
		nw := c.lead + `{"groups": {"group:a": ["y"],}, "n": 1.50,}` + c.trail
		oldJSON, nwJSON := jsonString(old), jsonString(nw)
		f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE",
			"target":{"id":"p1"},"old":`+oldJSON+`,"new":`+nwJSON+`}]}`)
		for mode, e := range map[string]*registry.Env{"masked": env, "shown": show(env)} {
			var out tools.AuditLogOutput
			s := mustCall(t, reg, e, "audit_log", `{"includeValues":true}`, &out)
			absent(t, s, "PLANTED")
			en := out.Entries[0]
			if !strings.Contains(en.OldPreview, `[removed]`) || !strings.Contains(en.OldPreview, `"groups"`) {
				t.Errorf("%s, %s: old preview = %q", name, mode, en.OldPreview)
			}
			// The display escapes a line feed and a byte order mark; nothing else changes.
			if want := strings.NewReplacer("\n", `\u{000A}`, "\ufeff", `\u{FEFF}`).Replace(nw); en.NewPreview != want {
				t.Errorf("%s, %s: new preview = %q, want the API's text %q (display-escaped)", name, mode, en.NewPreview, want)
			}
		}
	}
}

// A value that nests deeper than any document does must not end the process: the HuJSON
// reader recurses without a bound, and running out of stack is fatal. The preview is
// "[removed]", and the digest is still over the raw value.
func TestAuditLogPreviewSurvivesAValueNestedTooDeep(t *testing.T) {
	for name, raw := range map[string]string{
		"2,000,000 brackets":     jsonString(strings.Repeat("[", 2_000_000)),
		"1,000,000 objects":      jsonString(strings.Repeat(`{"a":`, 1_000_000)),
		"brackets, then as many": jsonString(strings.Repeat("[", 1_000_000) + strings.Repeat("]", 1_000_000)),
		"in an object":           `{"policy":` + jsonString(strings.Repeat("[", 1_500_000)) + `}`,
	} {
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE",
			"target":{"id":"p1"},"old":`+raw+`,"new":`+raw+`}]}`)
		for mode, e := range map[string]*registry.Env{"masked": env, "shown": show(env)} {
			var out tools.AuditLogOutput
			mustCall(t, reg, e, "audit_log", `{"includeValues":true}`, &out)
			if en := out.Entries[0]; !strings.Contains(en.OldPreview, "[removed]") || strings.Contains(en.OldPreview, "[[[") || !strings.Contains(en.NewPreview, "[removed]") {
				t.Errorf("%s, %s: previews = %.80q, %.80q", name, mode, en.OldPreview, en.NewPreview)
			}
		}
	}
}

// A preview is masked and then cut at 256 bytes, so a cut never leaves part of an address
// that masking would not have recognised, and never part of the pseudonym masking appended:
// whatever the cut lands in, the preview shows a pseudonym whole or not at all.
func TestAuditLogPreviewIsMaskedBeforeItIsCutAndNeverCutsAMarker(t *testing.T) {
	marker := regexp.MustCompile(`\[p:[a-z2-7]{10}\]`)
	const cutSuffix = "...[truncated]"
	var whole, markerDropped, beforeAddress int
	for pad := 150; pad <= 262; pad++ {
		value := jsonString(strings.Repeat("x", pad) + " amy.longname@example.com tail")
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE",
			"target":{"id":"p1"},"new":`+value+`}]}`)
		keyedEnv, _ := keyed(t, env)
		var out tools.AuditLogOutput
		mustCall(t, reg, keyedEnv, "audit_log", `{"includeValues":true}`, &out)
		p := out.Entries[0].NewPreview
		tailOf := func() string { return p[max(len(p)-40, 0):] }
		if strings.Contains(p, "amy") || strings.Contains(p, "longname") {
			t.Errorf("pad %d: part of the address shows: ...%q", pad, tailOf())
		}
		wholes := len(marker.FindAllString(p, -1))
		if opens := strings.Count(p, "[p:"); opens != wholes {
			t.Errorf("pad %d: a pseudonym is cut: ...%q", pad, tailOf())
		}
		if body := strings.TrimSuffix(p, cutSuffix); strings.HasSuffix(body, " [") || strings.HasSuffix(body, " [p") {
			t.Errorf("pad %d: the start of a pseudonym is left: ...%q", pad, tailOf())
		}
		if len(p) > 256 {
			t.Errorf("pad %d: the preview is %d bytes", pad, len(p))
		}
		switch cut := strings.HasSuffix(p, cutSuffix); {
		case wholes == 1:
			whole++
		case cut && strings.Contains(p, "@example.com"):
			markerDropped++ // the address is there and its pseudonym went with the cut
		case cut:
			beforeAddress++
		}
		// With masking off nothing is masked, so there is no pseudonym to cut.
		var shown tools.AuditLogOutput
		mustCall(t, reg, show(env), "audit_log", `{"includeValues":true}`, &shown)
		if sp := shown.Entries[0].NewPreview; strings.Contains(sp, "[p:") || len(sp) > 256 {
			t.Errorf("pad %d, masking off: %q", pad, sp[max(len(sp)-40, 0):])
		}
	}
	if whole < 20 || markerDropped < 5 || beforeAddress < 20 {
		t.Errorf("the cases do not reach every outcome: %d with a whole pseudonym, %d with it dropped, %d cut before the address", whole, markerDropped, beforeAddress)
	}
}

// With no credential to remove a preview is the API's own text, which may spell a
// URL with escaped slashes; the cut reads those spellings.
func TestAuditLogCutsAnEscapedURLInAPreview(t *testing.T) {
	f, reg, env := apiEnv(t)
	token := strings.Repeat("Q", 24)
	value := `{"endpointUrl":"https:\/\/hooks.example.test\/services\/T0\/` + token + `","other":"https:\u002f\u002fhooks.example.test\u002fservices\u002f` + token + `","n":1}`
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE",
		"target":{"id":"w1"},"new":`+value+`}]}`)
	for name, e := range map[string]*registry.Env{"masked": env, "shown": show(env)} {
		var out tools.AuditLogOutput
		s := mustCall(t, reg, e, "audit_log", `{"includeValues":true}`, &out)
		absent(t, s, token, "services")
		if p := out.Entries[0].NewPreview; strings.Count(p, "https://hooks.example.test/…[path sha256 ") != 2 || !strings.Contains(p, `"n":1`) {
			t.Errorf("%s: new preview = %q, want both URLs cut and the rest kept", name, p)
		}
	}
}

// A delivery error from a log stream quotes the collector's URL, which carries its
// token in the path.
func TestLogStreamingCutsURLsInItsLastError(t *testing.T) {
	f, reg, env := apiEnv(t)
	token := strings.Repeat("Q", 24)
	f.JSON("GET", tailnetPath+"/logging/network/stream", 200, `{"destinationType":"sumo","url":"https://collectors.example.test/receiver/v1/http/`+token+`"}`)
	f.JSON("GET", tailnetPath+"/logging/network/stream/status", 200, `{"lastActivity":"2026-10-10T11:00:00Z","numTotalRequests":1,
		"lastError":"Post \"https://collectors.example.test/receiver/v1/http/`+token+`\": dial tcp: connection refused"}`)
	var out tools.LogStreamOutput
	s := mustCall(t, reg, env, "log_streaming_get", `{"logType":"network"}`, &out)
	absent(t, s, token, "/receiver/")
	if out.Health == nil || !strings.HasPrefix(out.Health.LastError, `Post "https://collectors.example.test/…[path sha256 `) ||
		!strings.HasSuffix(out.Health.LastError, `]": dial tcp: connection refused`) || !slices.Contains(out.Findings, "last_error") {
		t.Errorf("health = %+v, findings = %v", out.Health, out.Findings)
	}
}

// A preview is made in a fixed order: values under credential-named keys come out,
// URLs are cut, addresses are masked, and the result is capped at 256 bytes. Each
// step reads what the one before left, so each case puts what a step hides across
// byte 242, where the cap cuts, and asserts the whole preview: a step moved after
// the cap sees a document cut in half, or a URL with its tail gone, and either
// keeps a piece of the token, or hashes a path that is not the URL's.
func TestAuditLogPreviewOrderIsRedactCutMaskCap(t *testing.T) {
	token := "ZJ9" + strings.Repeat("Q", 57)  // no capital Z anywhere else in a preview
	secret := "ZK8" + strings.Repeat("R", 57) // likewise
	pad := func(n int) string { return strings.Repeat("a", n) }
	pathHash := func(path string) string {
		sum := sha256.Sum256([]byte(path + "?"))
		return hex.EncodeToString(sum[:])[:12]
	}
	withSecret := `{"note":"` + pad(200) + `","name":"keep","token":"` + secret + `"}`
	redacted := `{"name":"keep","note":"` + pad(200) + `","token":"[removed]"}`
	cases := []struct {
		name, value, want string
		maskedOnly        bool
	}{
		{"a URL path across the cap",
			`{"note":"` + pad(150) + `","url":"https://hooks.example.test/services/T0/` + token + `"}`,
			`{"note":"` + pad(150) + `","url":"https://hooks.example.test/…[path sha256 ` + pathHash("/services/T0/"+token) + `]"}`, false},
		{"a credential-named value across the cap", withSecret, redacted, false},
		{"the same inside a string", jsonString(withSecret), redacted, false},
		{"an address in a path: cut before it is masked",
			`{"u":"https://hooks.example.test/u/amy@example.com/` + token + `"}`,
			`{"u":"https://hooks.example.test/…[path sha256 ` + pathHash("/u/amy@example.com/"+token) + `]"}`, false},
		{"an address across the cap: masked before it is capped",
			`{"note":"` + pad(218) + `","who":"amy@example.com","z":"` + strings.Repeat("z", 30) + `"}`,
			`{"note":"` + pad(218) + `","who":"a…@e...[truncated]`, true},
	}
	for _, c := range cases {
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[{"eventTime":"2026-10-10T10:00:00Z","origin":"CONFIG_API","action":"UPDATE",
			"target":{"id":"s1"},"new":`+c.value+`}]}`)
		for mode, e := range map[string]*registry.Env{"masked": env, "shown": show(env)} {
			if c.maskedOnly && mode == "shown" {
				continue
			}
			var out tools.AuditLogOutput
			mustCall(t, reg, e, "audit_log", `{"includeValues":true}`, &out)
			got := out.Entries[0].NewPreview
			if got != c.want {
				t.Errorf("%s, %s:\n got %q\nwant %q", c.name, mode, got, c.want)
			}
			if strings.Contains(got, "Z") || strings.Contains(got, "amy") {
				t.Errorf("%s, %s: a piece of what the preview hides survived: %q", c.name, mode, got)
			}
		}
	}
}

// A target's property is text the tailnet writes, like its name: it is capped, has
// credential shapes replaced (one in it would otherwise withhold the whole result),
// is masked, is named by a pseudonym that the target filter reads, and is flagged
// as untrusted in the tool's schema.
func TestAuditLogTargetPropertyIsUntrustedText(t *testing.T) {
	f, reg, env := apiEnv(t)
	tskey := "tskey" + "-auth-" + strings.Repeat("B", 12) // assembled so no literal matches a scanner rule
	var logs []string
	for i, prop := range []string{"owner amy@example.com", tskey, strings.Repeat("p", 2000), "plain"} {
		logs = append(logs, fmt.Sprintf(`{"eventTime":"2026-10-10T10:%02d:00Z","origin":"ADMIN_CONSOLE","action":"UPDATE","target":{"id":"t%d","property":%s}}`,
			i, i+1, jsonString(prop)))
	}
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[`+strings.Join(logs, ",")+`]}`)
	if tool, _ := reg.Get("audit_log"); !slices.Contains(tool.UntrustedFields, "entries[].target.property") {
		t.Errorf("target.property is not marked untrusted: %v", tool.UntrustedFields)
	}
	kenv, k := keyed(t, env)
	for name, e := range map[string]*registry.Env{"masked": kenv, "shown": show(kenv)} {
		var out tools.AuditLogOutput
		mustCall(t, reg, e, "audit_log", `{}`, &out)
		if len(out.Entries) != 4 {
			t.Fatalf("%s: %d entries", name, len(out.Entries))
		}
		p := func(i int) string { return out.Entries[i].Target.Property }
		if name == "masked" {
			if !strings.Contains(p(0), "a…@example.com [p:") || strings.Contains(p(0), "amy") {
				t.Errorf("masked: the address in a property is %q", p(0))
			}
		} else if p(0) != "owner amy@example.com" {
			t.Errorf("shown: property = %q", p(0))
		}
		if p(1) != "[credential-shaped text removed]" {
			t.Errorf("%s: a credential shape in a property is %q", name, p(1))
		}
		if len(p(2)) != 1024 || !strings.HasSuffix(p(2), "...[truncated]") {
			t.Errorf("%s: a long property is %d bytes ending %q", name, len(p(2)), p(2)[len(p(2))-14:])
		}
		if p(3) != "plain" {
			t.Errorf("%s: property = %q", name, p(3))
		}
	}
	// The pseudonym the display shows in a property matches the entry that shows it.
	var got tools.AuditLogOutput
	mustCall(t, reg, kenv, "audit_log", `{"target":["`+k.Pseudonym("amy@example.com")+`"]}`, &got)
	if len(got.Entries) != 1 || got.Entries[0].Target.ID != "t1" {
		t.Errorf("a pseudonym shown in a property matched %+v", got.Entries)
	}
}
