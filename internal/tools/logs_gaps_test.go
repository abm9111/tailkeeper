package tools_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// flowRecord is one flow-log record of node, with one flow, as the API sends it.
func flowRecord(node string) string {
	return `{"nodeId":"` + node + `","logged":"2026-10-10T11:59:00Z","virtualTraffic":[{"proto":6,"src":"100.64.0.1:5000","dst":"100.64.0.2:443","txBytes":10}]}`
}

// The record cap cuts the list and says so, and the node filter is applied before the cap, so
// records of other nodes never take a slot.
func TestFlowLogsCapTruncatesAndTheNodeFilterNarrows(t *testing.T) {
	body := `{"logs":[` + strings.Join([]string{flowRecord("nA"), flowRecord("nB"), flowRecord("nA"), flowRecord("nA")}, ",") + `]}`
	for _, c := range []struct {
		name, args string
		nodes      []string
		truncated  bool
	}{
		{"cap below the count", `{"maxRecords":2}`, []string{"nA", "nB"}, true},
		{"cap at the count", `{"maxRecords":4}`, []string{"nA", "nB", "nA", "nA"}, false},
		{"cap one below the count", `{"maxRecords":3}`, []string{"nA", "nB", "nA"}, true},
		{"a cap of one", `{"maxRecords":1}`, []string{"nA"}, true},
		{"node, cap below its records", `{"node":"nA","maxRecords":2}`, []string{"nA", "nA"}, true},
		{"node, cap at its records", `{"node":"nA","maxRecords":3}`, []string{"nA", "nA", "nA"}, false},
		{"node, other nodes take no slot", `{"node":"nB","maxRecords":1}`, []string{"nB"}, false},
		{"a node with no records", `{"node":"nZ"}`, nil, false},
		{"no filter, the default cap", `{}`, []string{"nA", "nB", "nA", "nA"}, false},
	} {
		f, reg, env := apiEnv(t)
		f.JSON("GET", tailnetPath+"/settings", 200, `{"networkFlowLoggingOn":true}`)
		f.JSON("GET", tailnetPath+"/logging/network", 200, body)
		var out tools.FlowLogsOutput
		mustCall(t, reg, env, "network_flow_logs", c.args, &out)
		var nodes []string
		for _, r := range out.Records {
			nodes = append(nodes, r.NodeID)
		}
		if !slices.Equal(nodes, c.nodes) || out.Count != len(c.nodes) || out.Truncated != c.truncated || out.Status != "ok" {
			t.Errorf("%s: nodes %v count %d truncated %v status %q, want %v and truncated %v", c.name, nodes, out.Count, out.Truncated, out.Status, c.nodes, c.truncated)
		}
		// Neither the cap nor the node is the API's to apply: the window is all it is sent.
		for _, r := range f.Requests() {
			if r.Path == tailnetPath+"/logging/network" && (r.Query.Has("node") || r.Query.Has("maxRecords") || r.Query.Has("nodeId")) {
				t.Errorf("%s: the cap or the node reached the API: %v", c.name, r.Query)
			}
		}
	}
}

// A cursor that fixes a window that starts when it ends, or a boundary past the window's end, is
// refused like one whose boundary is out of range at the start. (A request whose start equals
// its end, for both log tools, is covered by TestInputChecksAtTheirEdges.)
func TestAuditLogCursorRejectsAnEmptyWindowAndABoundaryPastTheEnd(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, auditFixture)
	var page tools.AuditLogOutput
	mustCall(t, reg, env, "audit_log", `{"limit":1}`, &page)
	end, err := time.Parse(time.RFC3339Nano, page.WindowEnd)
	if err != nil {
		t.Fatal(err)
	}
	for name, set := range map[string]map[string]any{
		// The boundary sits on the end, so only the empty window can be what is refused.
		"a cursor whose window starts when it ends": {"s": page.WindowEnd, "t": page.WindowEnd},
		"a boundary after the window's end":         {"t": end.Add(time.Hour).Format(time.RFC3339Nano)},
		"a boundary a nanosecond after the end":     {"t": end.Add(time.Nanosecond).Format(time.RFC3339Nano)},
	} {
		args := `{"limit":1,"cursor":"` + forge(t, page.NextCursor, set) + `"}`
		if _, err := call(t, reg, env, "audit_log", args); code(err) != tkerr.ValidationFailed {
			t.Errorf("%s: err = %v, want validation_failed", name, err)
		}
	}
	// The control: a boundary inside the window is the cursor's own and is accepted.
	if _, err := call(t, reg, env, "audit_log", `{"limit":1,"cursor":"`+page.NextCursor+`"}`); err != nil {
		t.Errorf("the issued cursor: %v", err)
	}
}

// Every field of a log stream's destination and delivery health that comes from the tailnet is
// escaped and cut like the text of any untrusted field.
func TestLogStreamTextIsEscapedAndCut(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/network/stream", 200, `{"destinationType":"s3","uploadPeriodMinutes":5,
		"user":`+jsonString(hostile("user"))+`,
		"s3Bucket":`+jsonString(hostile("bucket"))+`,"s3Region":`+jsonString(hostile("region"))+`,"s3KeyPrefix":`+jsonString(hostile("prefix"))+`,
		"s3AccessKeyId":`+jsonString(hostile("akid"))+`,"s3RoleArn":`+jsonString(hostile("arn"))+`,"s3ExternalId":`+jsonString(hostile("extid"))+`,
		"gcsBucket":`+jsonString(hostile("gbucket"))+`,"gcsKeyPrefix":`+jsonString(hostile("gprefix"))+`,"gcsScopes":[`+jsonString(hostile("gscope"))+`]}`)
	f.JSON("GET", tailnetPath+"/logging/network/stream/status", 200,
		`{"lastActivity":"2026-10-10T11:59:00Z","lastError":`+jsonString(hostile("err "))+`,"numTotalRequests":10}`)
	var out tools.LogStreamOutput
	// With masking off, so that the whole of the user is shown and cut.
	mustCall(t, reg, show(env), "log_streaming_get", `{"logType":"network"}`, &out)
	c, h := out.Configuration, out.Health
	if c == nil || h == nil || len(c.GCSScopes) != 1 {
		t.Fatalf("out = %+v", out)
	}
	for name, v := range map[string][2]string{
		"user": {"user", c.User}, "s3Bucket": {"bucket", c.S3Bucket}, "s3Region": {"region", c.S3Region},
		"s3KeyPrefix": {"prefix", c.S3KeyPrefix}, "s3AccessKeyId": {"akid", c.S3AccessKeyID}, "s3RoleArn": {"arn", c.S3RoleARN},
		"s3ExternalId": {"extid", c.S3ExternalID}, "gcsBucket": {"gbucket", c.GCSBucket}, "gcsKeyPrefix": {"gprefix", c.GCSKeyPrefix},
		"gcsScopes[]": {"gscope", c.GCSScopes[0]}, "lastError": {"err ", h.LastError},
	} {
		shownHostile(t, name, v[0], v[1])
	}
	// Masked, the user is masked whole and nothing holds a raw control character.
	mustCall(t, reg, env, "log_streaming_get", `{"logType":"network"}`, &out)
	if strings.ContainsRune(out.Configuration.User, 0x1B) || strings.Contains(out.Configuration.User, "user") {
		t.Errorf("masked user = %.60q", out.Configuration.User)
	}
}

// The pseudonym filters of audit_log need the privacy key, whether personal data is masked or
// shown, and refuse before anything is sent.
func TestAuditLogPseudonymFiltersNeedAKey(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, auditTwo)
	_, k := keyed(t, env)
	p := k.Pseudonym("amy@example.com")
	for mode, e := range map[string]*registry.Env{"masked": env, "shown": show(env)} {
		for _, args := range []string{
			`{"actor":["` + p + `"]}`, `{"target":["` + p + `"]}`,
			`{"actor":["u1","` + p + `"]}`, `{"target":["t1","` + p + `"]}`,
		} {
			if _, err := call(t, reg, e, "audit_log", args); code(err) != tkerr.PrivacyKeyUnavailable {
				t.Errorf("%s, no key, %s: err = %v, want privacy_key_unavailable", mode, args, err)
			}
		}
	}
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d requests were sent before the missing key was found", n)
	}
	// The control: with the key the same filter runs.
	kenv, _ := keyed(t, env)
	if _, err := call(t, reg, kenv, "audit_log", `{"actor":["`+p+`"]}`); err != nil {
		t.Errorf("with the key: %v", err)
	}
}

// auditIDsOut is the part of an audit_log result that names who did what to which target.
type auditIDsOut struct {
	Entries []struct {
		Actor  struct{ ID string } `json:"actor"`
		Target struct{ ID string } `json:"target"`
	} `json:"entries"`
}

// auditIDs lists "actor>target" of the entries of an audit_log result.
func auditIDs(out auditIDsOut) string {
	var s []string
	for _, e := range out.Entries {
		s = append(s, e.Actor.ID+">"+e.Target.ID)
	}
	return strings.Join(s, ",")
}

// While personal data is shown a pseudonym still names a value, and the filter returns what it
// names and only that.
func TestAuditLogPseudonymFilterWorksWhileMaskingIsOff(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, auditTwo)
	kenv, k := keyed(t, env)
	shown := show(kenv)
	var out auditIDsOut
	for args, want := range map[string]string{
		`{"actor":["` + k.Pseudonym("amy@example.com") + `"]}`:      "u1>t1",
		`{"actor":["` + k.Pseudonym("bob@example.com") + `"]}`:      "u2>t10",
		`{"actor":["` + k.Pseudonym("nobody@example.com") + `"]}`:   "",
		`{"target":["` + k.Pseudonym("amy@example.com") + `"]}`:     "u2>t10",
		`{"target":["` + k.Pseudonym("bob@example.com") + `"]}`:     "u1>t1",
		`{"target":["` + k.Pseudonym("nobody@example.com") + `"]}`:  "",
		`{"actor":["` + k.Pseudonym("amy@example.com") + `","u2"]}`: "u1>t1,u2>t10",
	} {
		mustCall(t, reg, shown, "audit_log", args, &out)
		if got := auditIDs(out); got != want {
			t.Errorf("%s: entries %q, want %q", args, got, want)
		}
	}
	// Narrowed here, not at the server: the pseudonym is no name the server knows.
	for _, r := range f.Requests() {
		if r.Query.Has("actor") && strings.Contains(strings.Join(r.Query["actor"], ","), "p:") {
			t.Errorf("a pseudonym reached the server: %v", r.Query)
		}
	}
}

// A list that mixes exact IDs with a pseudonym is matched here whole: the literal of the list
// is not sent to the server, which would narrow the answer to the literal and drop what the
// pseudonym names.
func TestAuditLogMixedListLiteralIsNotSentToTheServer(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, auditTwo)
	kenv, k := keyed(t, env)
	var out auditIDsOut
	bob, amy := k.Pseudonym("bob@example.com"), k.Pseudonym("amy@example.com")
	for _, c := range []struct {
		name, args string
		env        *registry.Env
		want       string
	}{
		{"masked actor", `{"actor":["u1","` + bob + `"]}`, kenv, "u1>t1,u2>t10"},
		{"shown actor", `{"actor":["u1","` + bob + `"]}`, show(kenv), "u1>t1,u2>t10"},
		{"masked target", `{"target":["t1","` + amy + `"]}`, kenv, "u1>t1,u2>t10"},
		{"masked target, the literal alone matches", `{"target":["t1","` + k.Pseudonym("nobody@example.com") + `"]}`, kenv, "u1>t1"},
	} {
		before := len(f.Requests())
		mustCall(t, reg, c.env, "audit_log", c.args, &out)
		if got := auditIDs(out); got != c.want {
			t.Errorf("%s: entries %q, want %q", c.name, got, c.want)
		}
		reqs := f.Requests()[before:]
		if len(reqs) != 1 {
			t.Fatalf("%s: %d requests", c.name, len(reqs))
		}
		if q := reqs[0].Query; q.Has("actor") || q.Has("target") {
			t.Errorf("%s: the list went to the server: %v", c.name, q)
		}
	}
}
