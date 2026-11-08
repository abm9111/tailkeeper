package tools_test

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// newAppRig is a rig whose records go to a real App and its audit log, in a temporary
// directory: the path a credential-shaped string or an oversize count would take to a line on
// disk. It returns the rig and the path of the log. The API is the fake; withCLI adds the
// stand-in CLI.
func newAppRig(t *testing.T) (*rig, string) {
	t.Helper()
	root := t.TempDir()
	d := &config.Dirs{System: filepath.Join(root, "etc"), User: filepath.Join(root, "user"), State: filepath.Join(root, "state"), Logs: filepath.Join(root, "logs")}
	if err := os.MkdirAll(d.User, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := `{"contexts": {"test": {"tailnetId": "` + apitest.Tailnet + `", "credentials": {"read": {"provider": "env"}}}}}`
	if err := os.WriteFile(filepath.Join(d.User, config.FileName), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := app.Build(context.Background(), app.Options{Dirs: d, Getenv: func(string) string { return "" },
		Stat: func(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist }})
	if err != nil {
		t.Fatal(err)
	}
	if a.Audit == nil {
		t.Fatalf("the audit log is not open: %v", a.AuditErr)
	}
	r := &rig{t: t, f: apitest.New(t), forward: a.RecordObservation}
	a.Env.API, a.Env.APIErr = r.f.Client(t), nil
	a.Env.Now = func() time.Time { return now }
	r.env = a.Env
	r.env.RecordObservation = r.record
	return r, a.AuditPath
}

// withCLI gives the rig the stand-in CLI. A test that calls it skips on Windows.
func withCLI(r *rig) *rig {
	r.t.Helper()
	r.cli = newFakeCLI(r.t)
	r.env.Local, r.env.LocalErr = r.cli.env().Local, nil
	return r
}

// auditLines reads the audit log: the raw text of each line and its fields.
func auditLines(t *testing.T, path string) (raw []string, parsed []map[string]any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("an audit line that is not JSON: %v: %s", err, l)
		}
		raw, parsed = append(raw, l), append(parsed, m)
	}
	return raw, parsed
}

// A device list with more entries than an event can count ends no run as a bug of the program.
// The count in the record stops at the bound the event takes, still says that items were left
// out (the outcome is truncated), and the coverage keeps the real number. This runs through a
// real App and its audit log, the way a run does: the event validator was not the only check.
func TestAListLongerThanAnEventCanCountIsSaturatedAndStillAGap(t *testing.T) {
	r, path := newAppRig(t)
	const empty = 1_100_000
	body := `{"devices":[` + strings.Repeat("{},", empty) + `{"nodeId":"nONLY1CNTRL","clientVersion":"1.104.5","lastSeen":"` + seenAgo(time.Minute) + `","connectedToControl":true}]}`
	r.f.JSON("GET", tailnetPath+"/devices", 200, body)
	c, err := tools.CollectSecurity(context.Background(), r.env, security.ScopeFleet)
	if err != nil {
		t.Fatalf("a long list ended the run: %v", err)
	}
	requireValid(t, c)
	bound := security.SaturateCount(1 << 30)
	if empty <= bound {
		t.Fatalf("the premise: %d entries must be more than an event counts (%d)", empty, bound)
	}
	ev := r.apiOutcome()
	if ev.Outcome != security.OutcomeTruncated || ev.Observed != 1 || ev.Dropped != bound {
		t.Errorf("outcome %+v, want truncated, 1 observed and %d dropped", ev, bound)
	}
	if rw := row(t, c, security.CoverageVersions); rw.Status != security.ReportPartial || !strings.Contains(rw.Explanation, "1100000 of 1100001 items not observed") {
		t.Errorf("versions row = %+v", rw)
	}
	_, lines := auditLines(t, path)
	found := false
	for _, l := range lines {
		if l["source"] == "api_devices" && l["phase"] == "outcome" {
			found = true
			if l["outcome"] != "truncated" || l["dropped"] != float64(bound) || l["observed"] != float64(1) {
				t.Errorf("audit line %v", l)
			}
		}
	}
	if !found {
		t.Error("no outcome line for the device list in the audit log")
	}
}
