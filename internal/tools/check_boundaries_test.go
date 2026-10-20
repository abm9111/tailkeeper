package tools_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// The edges of every numeric and length limit an input check enforces: the last
// value allowed passes and the first one past it is refused, with no environment.
func TestInputChecksAtTheirEdges(t *testing.T) {
	reg := newRegistry(t)
	day := func(d int) string {
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, d).Format(time.RFC3339)
	}
	for _, c := range []struct {
		tool, args string
		valid      bool
	}{
		{"acl_get", `{"maxBytes":1023}`, false}, {"acl_get", `{"maxBytes":1024}`, true},
		{"acl_get", `{"maxBytes":4194304}`, true}, {"acl_get", `{"maxBytes":4194305}`, false},
		{"acl_get", `{"fromLine":1}`, true}, {"acl_get", `{"fromLine":0}`, true},
		{"devices_list", `{"staleDays":0}`, true}, {"devices_list", `{"staleDays":3650}`, true}, {"devices_list", `{"staleDays":3651}`, false},
		{"devices_list", `{"tags":["tag:"]}`, false}, {"devices_list", `{"tags":["tag:a"]}`, true},
		{"devices_list", `{"tags":["prodx"]}`, false}, {"devices_list", `{"tags":["tag:a b"]}`, false},
		{"devices_list", `{"tags":["tag:a,b"]}`, false}, {"devices_list", `{"tags":["tag:a\tb"]}`, false},
		{"devices_list", `{"tags":["TAG:A"]}`, true}, {"devices_list", `{"tags":["tag:a","bad"]}`, false},
		{"audit_log", `{"limit":1}`, true}, {"audit_log", `{"limit":5000}`, true}, {"audit_log", `{"limit":5001}`, false},
		{"network_flow_logs", `{"maxRecords":1}`, true}, {"network_flow_logs", `{"maxRecords":10000}`, true},
		{"network_flow_logs", `{"maxRecords":10001}`, false},
		{"device_get", `{"device":"` + strings.Repeat("a", 253) + `"}`, true}, {"device_get", `{"device":"` + strings.Repeat("a", 254) + `"}`, false},
		{"device_get", `{"device":" host "}`, true},
		// Windows are inclusive at their longest: 31 days of audit log, one hour of flow log.
		{"audit_log", `{"start":"` + day(0) + `","end":"` + day(31) + `"}`, true},
		{"audit_log", `{"start":"` + day(0) + `","end":"2026-02-01T00:00:01Z"}`, false},
		{"audit_log", `{"start":"` + day(0) + `","end":"` + day(0) + `"}`, false},
		{"network_flow_logs", `{"start":"2026-01-01T00:00:00Z","end":"2026-01-01T01:00:00Z"}`, true},
		{"network_flow_logs", `{"start":"2026-01-01T00:00:00Z","end":"2026-01-01T01:00:01Z"}`, false},
		{"network_flow_logs", `{"start":"2026-01-01T00:00:00Z","end":"2026-01-01T00:00:00Z"}`, false},
		// Either end alone is not a window to measure; a bad one alone is still refused.
		{"network_flow_logs", `{"start":"2026-01-01T00:00:00Z"}`, true}, {"network_flow_logs", `{"end":"2026-01-01T00:00:00Z"}`, true},
		{"network_flow_logs", `{"start":"nonsense"}`, false}, {"network_flow_logs", `{"end":"nonsense"}`, false},
	} {
		tool, ok := reg.Get(c.tool)
		if !ok {
			t.Fatalf("no tool %s", c.tool)
		}
		p, err := tool.Validate(json.RawMessage(c.args))
		if c.valid && err != nil {
			t.Errorf("%s %s: Validate = %v, want it valid", c.tool, c.args, err)
		}
		if e, isErr := tkerr.As(err); !c.valid && (p != nil || !isErr || e.Code != tkerr.ValidationFailed) {
			t.Errorf("%s %s: Validate = %v, want validation_failed", c.tool, c.args, err)
		}
	}
}

// Without a start, the flow log reads the 15 minutes before its end.
func TestFlowLogsDefaultToTheLastFifteenMinutes(t *testing.T) {
	f, reg, env := apiEnv(t)
	f.JSON("GET", tailnetPath+"/settings", 200, `{"networkFlowLoggingOn":true}`)
	f.JSON("GET", tailnetPath+"/logging/network", 200, `{"logs":[]}`)
	if _, err := call(t, reg, env, "network_flow_logs", `{}`); err != nil {
		t.Fatal(err)
	}
	var q map[string][]string
	for _, r := range f.Requests() {
		if strings.HasSuffix(r.Path, "/logging/network") {
			q = r.Query
		}
	}
	if len(q["start"]) != 1 || len(q["end"]) != 1 || q["start"][0] != "2026-10-10T11:45:00Z" || q["end"][0] != "2026-10-10T12:00:00Z" {
		t.Errorf("window = %v, want 11:45 to 12:00", q)
	}
}
