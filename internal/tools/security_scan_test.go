package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// Everything here is synthetic: the fake API, the stand-in CLI, and either the shipped
// catalog read at a clock taken from its own dates, or a catalog built in the test.

const scanDaemon = "1.30.0-t0123456ab-gfedcba987" // a stable release below the shipped rule's 1.32.3

// scanClock is an instant inside the shipped catalog's window, taken from the catalog itself
// so that a refresh of its dates does not break the tests.
func scanClock(t *testing.T) time.Time {
	t.Helper()
	c, err := advisory.Shipped()
	if err != nil {
		t.Fatal(err)
	}
	return c.IssuedAt.Add(24 * time.Hour)
}

// scanRig is a rig whose clock is at. It has no stand-in CLI (a test that needs one adds it
// with withCLI), so that a test that needs none runs on Windows too: with no CLI the local
// sources fail with local_binary_missing, which is a gap like any other.
func scanRig(t *testing.T, at time.Time) *rig {
	t.Helper()
	r := newRig(t)
	r.env.Now = func() time.Time { return at }
	return r
}

// scanDev is an API device seen a minute before at.
func scanDev(at time.Time, id, version string, extra map[string]any) map[string]any {
	d := map[string]any{"nodeId": id, "clientVersion": version, "os": "linux", "lastSeen": at.Add(-time.Minute).Format(time.RFC3339), "connectedToControl": true}
	for k, v := range extra {
		if v == nil {
			delete(d, k)
		} else {
			d[k] = v
		}
	}
	return d
}

func serveScanLocal(r *rig, long, daemon string) {
	r.t.Helper()
	r.cli.on("status --json --peers=false", 0, `{"BackendState":"Running","Self":{"ID":"`+selfID+`","OS":"linux"}}`, "")
	r.cli.on("version --json --daemon", 0, `{"long":"`+long+`","daemonLong":"`+daemon+`"}`, "")
	r.cli.on("get --json", 0, `{"accept-dns":true,"ssh":false}`, "")
}

func scanTool(t *testing.T) registry.Tool {
	t.Helper()
	reg := registry.New()
	tools.Register(reg)
	tl, ok := reg.Get("security_scan")
	if !ok {
		t.Fatal("security_scan is not registered")
	}
	return tl
}

func (r *rig) scan(t *testing.T, args string) tools.SecurityScanOutput {
	t.Helper()
	out, err := scanTool(t).Call(registry.WithCaller(context.Background(), registry.Caller{Kind: "test"}), r.env, json.RawMessage(args))
	if err != nil {
		t.Fatalf("security_scan %s: %v", args, err)
	}
	return out.(tools.SecurityScanOutput)
}

func findingsOf(o tools.SecurityScanOutput, applicability string) []tools.SecurityScanFinding {
	var out []tools.SecurityScanFinding
	for _, f := range o.Findings {
		if f.Applicability == applicability {
			out = append(out, f)
		}
	}
	return out
}

func coverageRow(o tools.SecurityScanOutput, dimension string) (tools.SecurityScanCoverage, bool) {
	for _, c := range o.Coverage {
		if c.Dimension == dimension {
			return c, true
		}
	}
	return tools.SecurityScanCoverage{}, false
}

// A rule of the synthetic catalogs: approved unless said, reviewed and fresh at the clock.
func scanRule(at time.Time, id, fixed string, severity security.Severity, state security.ReviewState, features ...string) security.AdvisoryRecord {
	return security.AdvisoryRecord{ID: id, Revision: "1", Component: "client", VersionRole: security.VersionRunningDaemon,
		Ranges: []security.VersionRange{{Fixed: fixed}}, RequiredFeatures: features, Source: "synthetic", Severity: severity,
		ReviewedAt: at.Add(-72 * time.Hour), ReviewExpiresAt: at.Add(72 * time.Hour), ReviewState: state, Mitigation: "Synthetic mitigation."}
}

// useCatalog makes the tool judge by these rules for one test.
func useCatalog(t *testing.T, at time.Time, rules ...security.AdvisoryRecord) {
	t.Helper()
	c := security.Catalog{SchemaVersion: security.SchemaVersion, Revision: 1, IssuedAt: at.Add(-48 * time.Hour), ExpiresAt: at.Add(48 * time.Hour),
		Digest: strings.Repeat("0", 64), Records: rules}
	t.Cleanup(tools.SetScanCatalog(func() (security.Catalog, error) { return c, nil }))
}

// The shipped rule against a fleet: devices that are affected by the local daemon and by the
// API, a device that is not, and the devices that can never be cleared (offline, or not
// observed). N9: no device the API reports as offline is ever not_affected.
func TestAffectedLocalAndAPIFleetKnownPositive(t *testing.T) {
	at := scanClock(t)
	r := withCLI(scanRig(t, at))
	serveScanLocal(r, "1.30.0-t0123456ab", scanDaemon)
	r.devices(
		scanDev(at, selfID, "1.30.0-t0123456ab", nil), // this node: the daemon says 1.30.0
		scanDev(at, "nOLD01CNTRL", "1.28.2-t0123456ab", nil),
		scanDev(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil),
		scanDev(at, "nOFF01CNTRL", "1.28.2-t0123456ab", map[string]any{"connectedToControl": false}),
		scanDev(at, "nOFF02CNTRL", "1.102.5-t0123456ab", map[string]any{"connectedToControl": false}),
	)
	out := r.scan(t, `{"scope":"fleet"}`)

	counts := out.Counts
	if counts.Affected != 2 || counts.PotentiallyAffected != 1 || counts.NotAffected != 1 || counts.Unknown != 21 || out.TotalFindings != 25 {
		t.Errorf("counts %+v total %d, want 2 affected, 1 potentially affected, 1 not affected, 21 unknown of 25", counts, out.TotalFindings)
	}
	if out.AtThreshold.Affected != 2 || out.AtThreshold.PotentiallyAffected != 1 {
		t.Errorf("at threshold: %+v", out.AtThreshold)
	}
	if out.ExitCode() != 8 {
		t.Errorf("exit code %d, want 8", out.ExitCode())
	}
	aff := findingsOf(out, "affected")
	if len(aff) != 2 || aff[0].Rule != "CVE-2022-41925" || len(aff[0].Verification) == 0 {
		t.Fatalf("affected findings: %+v", aff)
	}
	devices := map[string]bool{}
	for _, f := range aff {
		devices[f.Device] = true
	}
	if !devices["nSEL…"] || !devices["nOLD…"] {
		t.Errorf("affected devices %v, want this node and the old one", devices)
	}
	// Order: affected, then potentially affected, then unknown, then not affected.
	rank := map[string]int{"affected": 0, "potentially_affected": 1, "unknown": 2, "not_affected": 3}
	for i := 1; i < len(out.Findings); i++ {
		if rank[out.Findings[i-1].Applicability] > rank[out.Findings[i].Applicability] {
			t.Fatalf("finding %d (%s) after %d (%s)", i, out.Findings[i].Applicability, i-1, out.Findings[i-1].Applicability)
		}
	}
	// N9: an offline device is never cleared, whatever its version says.
	for _, f := range findingsOf(out, "not_affected") {
		if f.Device != "nNEW…" {
			t.Errorf("%s is not_affected: only the connected current device may be", f.Device)
		}
	}
	// A pending rule never speaks: every finding of the four TS-2026 rules is unknown.
	for _, f := range out.Findings {
		if strings.HasPrefix(f.Rule, "TS-2026-") && f.Applicability != "unknown" {
			t.Errorf("pending rule %s gave %s", f.Rule, f.Applicability)
		}
	}
	// The report says it is partial and why: the pending rules, the unevaluated intent.
	if out.Status != "partial" {
		t.Errorf("status %s", out.Status)
	}
	if c, ok := coverageRow(out, "catalog"); !ok || c.Status != "partial" || !strings.Contains(c.Explanation, "pending rules: 4") {
		t.Errorf("catalog row: %+v", c)
	}
	// Intent is not requested (no intent set is configured): the row says so and blocks nothing,
	// so what keeps this report partial is the pending rules and nothing about intent.
	if c, ok := coverageRow(out, "intent"); !ok || c.Status != "not_requested" || !strings.Contains(c.Explanation, "not requested") {
		t.Errorf("intent row: %+v", c)
	}
}

// A fleet in which nothing is found is not a clean fleet when something was not seen. And a
// collection with every source whole is complete, and passes, once nothing is pending: intent
// that is not configured is not requested and blocks nothing.
func TestNoFindingsWithMissingCoverageIsIncomplete(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at, scanRule(at, "RULE-OK", "1.32.3", security.SeverityHigh, security.ReviewApproved))

	t.Run("a source failed", func(t *testing.T) {
		r := withCLI(scanRig(t, at))
		// The local status says nothing the scan can use; the API lists a current device.
		r.cli.on("status --json --peers=false", 1, "", "Tailscale is stopped.")
		r.devices(scanDev(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil))
		out := r.scan(t, `{"scope":"fleet"}`)
		if out.Counts.Affected+out.Counts.PotentiallyAffected != 0 || out.AtThreshold.Affected != 0 {
			t.Fatalf("the premise: nothing is found: %+v", out.Counts)
		}
		if out.Status != "partial" || out.ExitCode() != 1 {
			t.Errorf("status %s exit %d, want partial and 1", out.Status, out.ExitCode())
		}
		v, _ := coverageRow(out, "versions")
		if v.Status != "partial" || !strings.Contains(v.Explanation, "local status") {
			t.Errorf("versions row: %+v", v)
		}
	})
	t.Run("every source whole, intent not requested: complete and 0", func(t *testing.T) {
		r := withCLI(scanRig(t, at))
		serveScanLocal(r, "1.102.5-t0123456ab", "1.102.5-t0123456ab-gfedcba987")
		// The rule requires no feature; the features row is whole when the sources are.
		r.devices(scanDev(at, selfID, "1.102.5-t0123456ab", nil), scanDev(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil))
		out := r.scan(t, `{"scope":"fleet"}`)
		for _, d := range []string{"versions", "features", "catalog"} {
			if c, ok := coverageRow(out, d); !ok || c.Status != "complete" {
				t.Errorf("%s row: %+v (the premise: everything requested is whole)", d, c)
			}
		}
		if out.Counts.NotAffected != 2 || out.TotalFindings != 2 {
			t.Fatalf("the premise: two cleared devices: %+v", out.Counts)
		}
		if c, _ := coverageRow(out, "intent"); c.Status != "not_requested" || c.Explanation == "" {
			t.Errorf("intent row: %+v", c)
		}
		if out.Status != "complete" || out.ExitCode() != 0 {
			t.Errorf("status %s exit %d, want complete and 0", out.Status, out.ExitCode())
		}
	})
	t.Run("a rule still pending", func(t *testing.T) {
		useCatalog(t, at, scanRule(at, "RULE-OK", "1.32.3", security.SeverityHigh, security.ReviewApproved),
			scanRule(at, "RULE-PENDING", "1.32.3", security.SeverityHigh, security.ReviewPending))
		r := withCLI(scanRig(t, at))
		serveScanLocal(r, "1.102.5-t0123456ab", "1.102.5-t0123456ab-gfedcba987")
		r.devices(scanDev(at, selfID, "1.102.5-t0123456ab", nil), scanDev(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil))
		out := r.scan(t, `{"scope":"fleet"}`)
		if c, _ := coverageRow(out, "catalog"); c.Status != "partial" || !strings.Contains(c.Explanation, "pending rules: 1") {
			t.Fatalf("the premise: the pending rule keeps the catalog row partial: %+v", c)
		}
		if out.Status != "partial" || out.ExitCode() != 1 {
			t.Errorf("status %s exit %d, want partial and 1", out.Status, out.ExitCode())
		}
	})
}

func TestSecurityScanExitCodeIsDecidedByTheFindingsThenTheStatus(t *testing.T) {
	complete := tools.SecurityScanOutput{Status: "complete"}
	partial := tools.SecurityScanOutput{Status: "partial"}
	hitA, hitP := partial, complete
	hitA.AtThreshold.Affected = 1
	hitP.AtThreshold.PotentiallyAffected = 1
	for name, tc := range map[string]struct {
		out  tools.SecurityScanOutput
		want int
	}{
		"complete, nothing at the threshold":             {complete, 0},
		"partial, nothing at the threshold":              {partial, 1},
		"partial, an affected finding at the threshold":  {hitA, 8},
		"complete, a potential finding at the threshold": {hitP, 8},
		"unknown status is never a pass":                 {tools.SecurityScanOutput{}, 1},
		"a status that is not complete is not a pass":    {tools.SecurityScanOutput{Status: "truncated"}, 1},
	} {
		if got := tc.out.ExitCode(); got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
}

// The threshold decides which findings count, over every finding and not over the 100 the
// output lists: a result cannot be moved by the cut.
func TestSecurityScanThresholdCountsEveryFindingNotTheListedOnes(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at,
		scanRule(at, "RULE-LOW", "1.32.3", security.SeverityLow, security.ReviewApproved),
		scanRule(at, "RULE-MED", "1.32.3", security.SeverityMedium, security.ReviewApproved),
		scanRule(at, "RULE-HIGH", "1.32.3", security.SeverityHigh, security.ReviewApproved),
		scanRule(at, "RULE-CRIT", "1.32.3", security.SeverityCritical, security.ReviewApproved),
		scanRule(at, "RULE-UNK", "1.32.3", security.SeverityUnknown, security.ReviewApproved))
	r := scanRig(t, at)
	var devs []map[string]any
	for i := 0; i < 40; i++ { // 40 devices x 5 rules = 200 affected findings
		devs = append(devs, scanDev(at, fmt.Sprintf("nDEV%02dCNTRL", i), "1.30.0-t0123456ab", nil))
	}
	r.devices(devs...)
	for _, tc := range []struct {
		threshold string
		want      int
	}{{"", 200}, {"low", 200}, {"medium", 160}, {"high", 120}, {"critical", 80}} {
		args := `{"scope":"fleet"}`
		if tc.threshold != "" {
			args = `{"scope":"fleet","threshold":"` + tc.threshold + `"}`
		}
		out := r.scan(t, args)
		// The severity of an unknown rule is above every threshold, so it counts in each.
		wantThreshold := tc.threshold
		if wantThreshold == "" {
			wantThreshold = "low"
		}
		if out.Threshold != wantThreshold {
			t.Errorf("threshold %q reported as %q", tc.threshold, out.Threshold)
		}
		if out.AtThreshold.Affected != tc.want {
			t.Errorf("threshold %q: %d affected at it, want %d of %d", tc.threshold, out.AtThreshold.Affected, tc.want, out.TotalFindings)
		}
		if len(out.Findings) != 100 || out.TotalFindings != 200 || !out.Truncated || out.Status != "partial" {
			t.Errorf("threshold %q: %d listed of %d, truncated %v, status %s", tc.threshold, len(out.Findings), out.TotalFindings, out.Truncated, out.Status)
		}
		if out.Counts.Affected != 200 {
			t.Errorf("counts over the whole report: %+v", out.Counts)
		}
		if out.ExitCode() != 8 {
			t.Errorf("exit %d", out.ExitCode())
		}
	}
	if _, err := scanTool(t).Call(context.Background(), r.env, json.RawMessage(`{"scope":"fleet","threshold":"urgent"}`)); err == nil {
		t.Error("a threshold outside low, medium, high and critical was accepted")
	}
}

// The output lists at most 100 findings, says how many there are and that it cut, and offers
// no way to ask for the rest.
func TestInitialScanDoesNotAdvertiseUnavailablePaging(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	var rules []security.AdvisoryRecord
	for i := 0; i < 5; i++ {
		rules = append(rules, scanRule(at, fmt.Sprintf("RULE-%d", i), "1.32.3", security.SeverityHigh, security.ReviewApproved))
	}
	useCatalog(t, at, rules...)
	r := scanRig(t, at)
	var devs []map[string]any
	for i := 0; i < 30; i++ {
		devs = append(devs, scanDev(at, fmt.Sprintf("nDEV%02dCNTRL", i), "1.102.5-t0123456ab", nil))
	}
	r.devices(devs...)
	out := r.scan(t, `{"scope":"fleet"}`)
	if len(out.Findings) != 100 || out.TotalFindings != 150 || !out.Truncated {
		t.Fatalf("%d listed of %d, truncated %v", len(out.Findings), out.TotalFindings, out.Truncated)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	paging := regexp.MustCompile(`(?i)cursor|next|page|offset|continu|token`)
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if paging.MatchString(k) {
					t.Errorf("the result has %s.%s: paging that does not exist", path, k)
				}
				walk(path+"."+k, child)
			}
		case []any:
			for _, child := range x {
				walk(path+"[]", child)
			}
		}
	}
	walk("$", generic)
	tl := scanTool(t)
	for name, schema := range map[string]any{"input": tl.InputSchema, "output": tl.OutputSchema} {
		sb, err := json.Marshal(schema)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		var gather func(v any)
		gather = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				if props, ok := x["properties"].(map[string]any); ok {
					for k := range props {
						names = append(names, k)
					}
				}
				for _, child := range x {
					gather(child)
				}
			case []any:
				for _, child := range x {
					gather(child)
				}
			}
		}
		var g any
		if err := json.Unmarshal(sb, &g); err != nil {
			t.Fatal(err)
		}
		gather(g)
		for _, n := range names {
			if paging.MatchString(n) {
				t.Errorf("the %s schema has a property %q", name, n)
			}
		}
	}
}

// The scan reads what the caller gave it and nothing else: scope and threshold, no catalog,
// no path, no URL, no expectation.
func TestSecurityScanTakesScopeAndThresholdOnly(t *testing.T) {
	tl := scanTool(t)
	b, err := json.Marshal(tl.InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
		AdditionalProperties json.RawMessage            `json:"additionalProperties"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	var names []string
	for k := range s.Properties {
		names = append(names, k)
	}
	if len(names) != 2 || s.Properties["scope"] == nil || s.Properties["threshold"] == nil {
		t.Errorf("properties %v, want scope and threshold", names)
	}
	if strings.TrimSpace(string(s.AdditionalProperties)) != "false" {
		t.Errorf("additionalProperties = %s", s.AdditionalProperties)
	}
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at, scanRule(at, "RULE-1", "1.32.3", security.SeverityHigh, security.ReviewApproved))
	r := scanRig(t, at)
	r.devices(scanDev(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil))
	for _, args := range []string{
		`{"scope":"fleet","catalog":"/tmp/x.json"}`, `{"scope":"fleet","path":"x"}`, `{"scope":"fleet","url":"https://example.com/c.json"}`,
		`{"scope":"fleet","intent":{"network":[]}}`, `{"scope":"fleet","expect":"nothing"}`, `{"scope":"fleet","destination":"x"}`,
		`{"scope":"fleet","update":true}`, `{"scope":"fleet","threshold":"high","extra":{"nested":{"catalog":"x"}}}`,
		`{"scope":"all"}`, `{"scope":""}`, `{}`, `{"scope":"fleet","threshold":"HIGH"}`, `{"scope":["fleet"]}`,
	} {
		_, err := tl.Call(context.Background(), r.env, json.RawMessage(args))
		e, ok := tkerr.As(err)
		if err == nil || !ok || e.Code != tkerr.ValidationFailed {
			t.Errorf("%s: %v", args, err)
		}
	}
	if n := len(r.f.Requests()); n != 0 {
		t.Errorf("%d API requests came of arguments that were refused", n)
	}
}

// The scan is bound to its own call: results of two scans at the same time are each their
// own, whatever the order they finish in.
func TestConcurrentReportsOwnTheirData(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at, scanRule(at, "RULE-1", "1.32.3", security.SeverityHigh, security.ReviewApproved))
	const n = 6
	var wg sync.WaitGroup
	outs := make([]tools.SecurityScanOutput, n)
	errs := make([]error, n)
	tl := scanTool(t)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := scanRig(t, at)
			// World i has i+1 devices that are affected and one that is not.
			var devs []map[string]any
			for k := 0; k <= i; k++ {
				devs = append(devs, scanDev(at, fmt.Sprintf("nW%dD%dCNTRL", i, k), "1.30.0-t0123456ab", nil))
			}
			devs = append(devs, scanDev(at, fmt.Sprintf("nW%dOKCNTRL", i), "1.102.5-t0123456ab", nil))
			r.devices(devs...)
			out, err := tl.Call(registry.WithCaller(context.Background(), registry.Caller{Kind: "test"}), r.env, json.RawMessage(`{"scope":"fleet"}`))
			if err == nil {
				outs[i] = out.(tools.SecurityScanOutput)
			}
			errs[i] = err
		}()
	}
	wg.Wait()
	for i, o := range outs {
		if errs[i] != nil {
			t.Fatalf("scan %d: %v", i, errs[i])
		}
		if o.Counts.Affected != i+1 || o.Counts.NotAffected != 1 || o.TotalFindings != i+2 {
			t.Errorf("scan %d holds another's data: %+v of %d", i, o.Counts, o.TotalFindings)
		}
		for _, f := range o.Findings {
			if !strings.HasPrefix(f.Device, "nW"+fmt.Sprint(i)) {
				t.Errorf("scan %d lists the device %s of another", i, f.Device)
			}
		}
	}
}

// The output carries no unkeyed identifier and no raw device reference: not the finding's
// identity hash, not the context, not a node ID whole.
func TestSecurityScanOutputHoldsNoUnkeyedIdentifierOrRawDeviceReference(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at, scanRule(at, "RULE-1", "1.32.3", security.SeverityHigh, security.ReviewApproved))
	hexRun := regexp.MustCompile(`[0-9a-f]{32,}`)
	for _, keyed := range []bool{false, true} {
		t.Run(fmt.Sprint("privacy key ", keyed), func(t *testing.T) {
			r := withCLI(scanRig(t, at))
			if keyed {
				k, err := privacy.Parse(strings.Repeat("ab", 32))
				if err != nil {
					t.Fatal(err)
				}
				r.env.Privacy = k
			}
			serveScanLocal(r, "1.30.0-t0123456ab", scanDaemon)
			r.devices(scanDev(at, selfID, "1.30.0-t0123456ab", nil), scanDev(at, "nOLD01CNTRL", "1.28.2-t0123456ab", nil))
			out := r.scan(t, `{"scope":"fleet"}`)
			b, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			// The digest of the shipped files is public data, not an identifier of the tailnet.
			text := strings.ReplaceAll(string(b), out.Catalog.Digest, "<catalog digest>")
			for _, secret := range []string{selfID, "nOLD01CNTRL", "ctx-", apitest.Tailnet} {
				if strings.Contains(text, secret) {
					t.Errorf("the output holds %q", secret)
				}
			}
			if m := hexRun.FindString(text); m != "" {
				t.Errorf("the output holds a long hexadecimal string %q (an unkeyed identifier?)", m)
			}
			for _, f := range out.Findings {
				switch {
				case keyed && !strings.HasPrefix(f.DeviceRef, "p:"):
					t.Errorf("with a privacy key a device has the reference %q", f.DeviceRef)
				case !keyed && f.DeviceRef != "":
					t.Errorf("without a privacy key a device has the reference %q", f.DeviceRef)
				}
			}
		})
	}
}

// Local scope reads this node only and asks the API nothing; without an API client it still
// runs, and its context is not bound to a tailnet.
func TestLocalScopeAsksTheAPINothing(t *testing.T) {
	at := scanClock(t)
	r := withCLI(scanRig(t, at))
	r.env.API = nil
	serveScanLocal(r, "1.30.0-t0123456ab", scanDaemon)
	out := r.scan(t, `{"scope":"local"}`)
	if out.Counts.Affected != 1 || out.AtThreshold.Affected != 1 || out.ExitCode() != 8 {
		t.Errorf("counts %+v at threshold %+v exit %d", out.Counts, out.AtThreshold, out.ExitCode())
	}
	if out.Scope != "local" {
		t.Errorf("scope %q", out.Scope)
	}
	for _, c := range out.Coverage {
		if strings.Contains(c.Explanation, "API device list") {
			t.Errorf("a local scan speaks of the API: %+v", c)
		}
	}
}

// A shipped catalog that is not valid refuses the scan; there is no scan by a partial one.
func TestAScanRefusesACatalogThatDoesNotLoad(t *testing.T) {
	t.Cleanup(tools.SetScanCatalog(func() (security.Catalog, error) { return security.Catalog{}, fmt.Errorf("synthetic: corrupt file") }))
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	r := scanRig(t, at)
	r.devices(scanDev(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil))
	_, err := scanTool(t).Call(context.Background(), r.env, json.RawMessage(`{"scope":"fleet"}`))
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.Internal {
		t.Fatalf("error %v", err)
	}
	if n := len(r.f.Requests()); n != 0 {
		t.Errorf("%d API requests were made with no catalog to judge by", n)
	}
}

// The tool is cancelled with the call.
func TestAScanCancelledByTheCallerIsAnError(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at, scanRule(at, "RULE-1", "1.32.3", security.SeverityHigh, security.ReviewApproved))
	r := scanRig(t, at)
	r.devices(scanDev(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := scanTool(t).Call(registry.WithCaller(ctx, registry.Caller{Kind: "test"}), r.env, json.RawMessage(`{"scope":"fleet"}`))
	if e, ok := tkerr.As(err); !ok || e.Code == tkerr.Internal {
		t.Errorf("error %v: a cancelled call is not an internal error", err)
	}
	if err == nil {
		t.Error("a cancelled call returned a result")
	}
}

// The text layout names the status, the counts, the threshold, each coverage row and the cut.
func TestSecurityScanDetailsSayWhatTheReportCouldNotCover(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	var rules []security.AdvisoryRecord
	for i := 0; i < 4; i++ {
		rules = append(rules, scanRule(at, fmt.Sprintf("RULE-%d", i), "1.32.3", security.SeverityHigh, security.ReviewApproved))
	}
	useCatalog(t, at, rules...)
	r := scanRig(t, at)
	var devs []map[string]any
	for i := 0; i < 30; i++ {
		devs = append(devs, scanDev(at, fmt.Sprintf("nDEV%02dCNTRL", i), "1.30.0-t0123456ab", nil))
	}
	r.devices(devs...)
	out := r.scan(t, `{"scope":"fleet","threshold":"high"}`)
	text := strings.Join(out.Details(), "\n")
	for _, want := range []string{"fleet scan: partial", "120 affected", "threshold high: 120 affected", "coverage intent: not_requested", "intent not requested",
		"showing 100 of 120 findings", "no way to page", "start of its node ID, at most four characters",
		"4 rules built into this binary", "complete and exit 0 are relative to these rules and do not mean the fleet is safe"} {
		if !strings.Contains(text, want) {
			t.Errorf("the details lack %q:\n%s", want, text)
		}
	}
}

// Whatever the output holds is read by the tripwire before it leaves the tool, whichever
// format the surface then lays it out in: a credential-shaped value in the text of a rule is
// withheld, never repeated, and the error carries none of it. (The catalog is the binary's,
// not a caller's; this is the last line if a rule ever carried one.)
func TestSecurityScanWithholdsACredentialShapedRuleText(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	shape := "tskey" + "-api-" + strings.Repeat("A", 12)
	rule := scanRule(at, "RULE-1", "1.32.3", security.SeverityHigh, security.ReviewApproved)
	rule.Mitigation = "Update, and see " + shape + " for details."
	useCatalog(t, at, rule)
	r := scanRig(t, at)
	r.devices(scanDev(at, "nOLD01CNTRL", "1.28.2-t0123456ab", nil))
	out, err := scanTool(t).Call(registry.WithCaller(context.Background(), registry.Caller{Kind: "test"}), r.env, json.RawMessage(`{"scope":"fleet"}`))
	e, ok := tkerr.As(err)
	if err == nil || !ok || e.Code != tkerr.OutputWithheld {
		t.Fatalf("result %v, error %v: a credential-shaped value was not withheld", out, err)
	}
	for _, text := range []string{e.Message, e.Hint, err.Error()} {
		if strings.Contains(text, shape) || strings.Contains(text, strings.Repeat("A", 12)) {
			t.Errorf("the error repeats the value: %q", text)
		}
	}
}

// The text a rule's source, mitigation and explanation carry is trusted, but the rest of the
// output is held to the rules of every result: a control character in a catalog text cannot be
// there (the catalog refuses it), and one a device could put in an ID is cut with the rest of
// the ID.
func TestSecurityScanDeviceIDsAreCutBeforeTheyReachTheOutput(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at, scanRule(at, "RULE-1", "1.32.3", security.SeverityHigh, security.ReviewApproved))
	r := scanRig(t, at)
	hostile := []string{"##vso[task.logissue]AAAAAAAAAA", "tskey" + "-api-" + strings.Repeat("A", 12), "x@example.com-device-0001", "<script>alert(1)</script>"}
	var devs []map[string]any
	for _, id := range hostile {
		devs = append(devs, scanDev(at, id, "1.28.2-t0123456ab", nil))
	}
	r.devices(devs...)
	out := r.scan(t, `{"scope":"fleet"}`)
	b, _ := json.Marshal(out)
	for _, id := range hostile {
		if strings.Contains(string(b), id) {
			t.Errorf("the output holds the device ID %q", id)
		}
	}
	if len(out.Findings) != len(hostile) {
		t.Fatalf("%d findings for %d devices", len(out.Findings), len(hostile))
	}
	for _, f := range out.Findings {
		// Four characters and an ellipsis, or, for an ID that reads as an address, that cut
		// masked by the rules every result is held to.
		if n := len([]rune(f.Device)); n > 8 || !strings.Contains(f.Device, "…") {
			t.Errorf("device %q is not a cut of the ID", f.Device)
		}
	}
}

// The IDs of devices of every length the scan can be given, and what each is shown as: a
// short ID is cut too, because the scan never shows a whole device ID (sanitize.MaskID keeps
// an ID of eight characters or fewer whole, which is right for a tailnet or a client ID and
// wrong here). The first letters differ so that each device can be told by its own.
var deviceIDShown = map[string]string{
	"Q":                            "…",     // 1: nothing is shown
	"WXYZ":                         "WX…",   // 4: half
	"EDCVBNMK":                     "EDCV…", // 8: four
	"RFVTGBYHN":                    "RFVT…", // 9: four
	"T" + strings.Repeat("X", 127): "TXXX…", // 128: four
}

func TestMaskDeviceIDWithholdsPartOfAnIDOfAnyLength(t *testing.T) {
	for id, want := range deviceIDShown {
		if got := tools.MaskDeviceID(id); got != want {
			t.Errorf("%d characters: %q, want %q", len([]rune(id)), got, want)
		}
	}
	// Whatever the length, something is withheld and what is shown is the start of the ID.
	for n := 0; n <= 20; n++ {
		id := strings.Repeat("ab", 10)[:n]
		got := tools.MaskDeviceID(id)
		shown := strings.TrimSuffix(got, "…")
		if n > 0 && (len([]rune(shown)) >= n || !strings.HasPrefix(id, shown) || !strings.HasSuffix(got, "…")) {
			t.Errorf("%d characters: %q shows too much or not the start of %q", n, got, id)
		}
	}
	// Multibyte characters are cut by character, not by byte.
	if got := tools.MaskDeviceID("ŽščđŽščđ"); got != "Žščđ…" {
		t.Errorf("multibyte: %q", got)
	}
}

func TestSecurityScanShowsOnlyPartOfEveryDeviceID(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at, scanRule(at, "RULE-1", "1.32.3", security.SeverityHigh, security.ReviewApproved))
	r := scanRig(t, at)
	var devs []map[string]any
	for id := range deviceIDShown {
		devs = append(devs, scanDev(at, id, "1.28.2-t0123456ab", nil))
	}
	r.devices(devs...)
	out := r.scan(t, `{"scope":"fleet"}`)
	got := map[string]bool{}
	for _, f := range out.Findings {
		got[f.Device] = true
	}
	want := map[string]bool{}
	for _, shown := range deviceIDShown {
		want[shown] = true
	}
	if len(out.Findings) != len(deviceIDShown) || !reflect.DeepEqual(got, want) {
		t.Errorf("devices shown %v, want %v", got, want)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for id := range deviceIDShown {
		if len(id) > 1 && strings.Contains(string(b), id) {
			t.Errorf("the output holds the whole ID of %d characters", len(id))
		}
	}
}

// ---- controls that keep the scan honest or bounded, each pinned so that losing it fails a test ----

// The collection is told which features the rules in use require, so that its features row
// cannot be complete for a feature no source gives. With the argument dropped the row says
// complete. The device here is out of range of the rule, so the catalog row is complete too,
// and the features row is the only thing that keeps the scan from being complete.
func TestAScanTellsTheCollectionWhichFeaturesTheCatalogRequires(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at, scanRule(at, "RULE-FEATURE", "1.32.3", security.SeverityHigh, security.ReviewApproved, security.FeatureServeTLSMultiMount))
	// A subtest, so that the test as a whole runs where the stand-in CLI cannot (Windows).
	t.Run("every source whole", func(t *testing.T) {
		r := withCLI(scanRig(t, at))
		serveScanLocal(r, "1.102.5-t0123456ab", "1.102.5-t0123456ab-gfedcba987")
		r.devices(scanDev(at, selfID, "1.102.5-t0123456ab", nil), scanDev(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil))
		out := r.scan(t, `{"scope":"fleet"}`)
		if c, _ := coverageRow(out, "catalog"); c.Status != "complete" || out.Counts.NotAffected != 2 {
			t.Fatalf("the premise: the rule clears both devices and the catalog row is complete: %+v %+v", c, out.Counts)
		}
		f, _ := coverageRow(out, "features")
		if f.Status != "partial" || !strings.Contains(f.Explanation, "no source gives the features serve_tls_multi_mount") {
			t.Errorf("features row: %+v", f)
		}
		if out.Status != "partial" || out.ExitCode() != 1 {
			t.Errorf("status %s exit %d: a feature nothing observes must keep the scan from passing", out.Status, out.ExitCode())
		}
	})
	// And with no stand-in at all the row still names the feature, which is the argument itself.
	t.Run("the explanation names the feature", func(t *testing.T) {
		r := scanRig(t, at)
		r.devices(scanDev(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil))
		out := r.scan(t, `{"scope":"fleet"}`)
		if f, _ := coverageRow(out, "features"); !strings.Contains(f.Explanation, "no source gives the features serve_tls_multi_mount") {
			t.Errorf("features row: %+v", f)
		}
	})
}

// A device list is read up to 32 MiB: the client's own limit is 64 MiB, and the scan takes the
// lower. A list of exactly 32 MiB is read; one byte more is response_too_large, and nothing of
// it is kept. (The padding is white space after the JSON value, which costs the reader its
// bytes and nothing else.)
func TestAScanReadsAtMost32MiBOfDeviceList(t *testing.T) {
	const limit = 32 << 20
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at, scanRule(at, "RULE-1", "1.32.3", security.SeverityHigh, security.ReviewApproved))
	body := func(size int) string {
		list, err := json.Marshal(map[string]any{"devices": []map[string]any{scanDev(at, "nOLD01CNTRL", "1.28.2-t0123456ab", nil)}})
		if err != nil {
			t.Fatal(err)
		}
		return string(list) + strings.Repeat(" ", size-len(list))
	}
	devices := func(r *rig, size int) {
		r.f.JSON("GET", tailnetPath+"/devices", 200, body(size))
	}
	t.Run("exactly 32 MiB is read", func(t *testing.T) {
		r := scanRig(t, at)
		devices(r, limit)
		out := r.scan(t, `{"scope":"fleet"}`)
		if out.Counts.Affected != 1 || out.TotalFindings != 1 {
			t.Errorf("the list was not read: %+v", out.Counts)
		}
		if v, _ := coverageRow(out, "versions"); strings.Contains(v.Explanation, "API device list") {
			t.Errorf("the API source did not end whole: %q", v.Explanation)
		}
	})
	t.Run("one byte more is refused with its own code", func(t *testing.T) {
		r := scanRig(t, at)
		devices(r, limit+1)
		out := r.scan(t, `{"scope":"fleet"}`)
		v, _ := coverageRow(out, "versions")
		if !strings.Contains(v.Explanation, "API device list: error (response_too_large)") {
			t.Errorf("versions row: %q", v.Explanation)
		}
		if out.TotalFindings != 0 || out.Counts.Affected != 0 {
			t.Errorf("findings came of a list that was refused: %+v", out.Counts)
		}
		if out.Status != "partial" || out.ExitCode() != 1 {
			t.Errorf("status %s exit %d", out.Status, out.ExitCode())
		}
	})
}

// The pseudonym of a device is made from the whole node ID, not from the four characters the
// result shows: two devices that read alike are told apart by it, which is what it is for.
func TestTwoDevicesThatReadAlikeHaveDifferentPseudonyms(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at, scanRule(at, "RULE-1", "1.32.3", security.SeverityHigh, security.ReviewApproved))
	key, err := privacy.Parse(strings.Repeat("cd", 32))
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"nSHARE1CNTRL", "nSHARE2CNTRL"}
	r := scanRig(t, at)
	r.env.Privacy = key
	r.devices(scanDev(at, ids[0], "1.28.2-t0123456ab", nil), scanDev(at, ids[1], "1.28.2-t0123456ab", nil))
	out := r.scan(t, `{"scope":"fleet"}`)
	if len(out.Findings) != 2 {
		t.Fatalf("%d findings", len(out.Findings))
	}
	if out.Findings[0].Device != out.Findings[1].Device {
		t.Fatalf("the premise: the two devices read alike: %q %q", out.Findings[0].Device, out.Findings[1].Device)
	}
	got := map[string]bool{out.Findings[0].DeviceRef: true, out.Findings[1].DeviceRef: true}
	want := map[string]bool{key.APIPseudonym(ids[0]): true, key.APIPseudonym(ids[1]): true}
	if len(got) != 2 || !reflect.DeepEqual(got, want) {
		t.Errorf("pseudonyms %v, want those of the whole node IDs %v", got, want)
	}
}

// A wall clock that steps back after the sources were read does not fail the scan: the time of
// the evaluation is never earlier than the snapshot's (Evaluate refuses a snapshot observed
// after the time it is judged at), so the scan judges at the time it observed.
func TestAScanSurvivesAClockThatStepsBackAfterTheSourcesWereRead(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at, scanRule(at, "RULE-1", "1.32.3", security.SeverityHigh, security.ReviewApproved))
	r := scanRig(t, at)
	var stepped atomic.Bool
	r.env.Now = func() time.Time {
		if stepped.Load() {
			return at.Add(-10 * time.Minute)
		}
		return at
	}
	record := r.env.RecordObservation
	r.env.RecordObservation = func(ctx context.Context, ev security.CollectionEvent) error {
		err := record(ctx, ev)
		if ev.Phase == security.PhaseOutcome {
			stepped.Store(true) // the clock steps back as soon as a source has been read
		}
		return err
	}
	r.devices(scanDev(at, "nOLD01CNTRL", "1.28.2-t0123456ab", nil))
	out := r.scan(t, `{"scope":"fleet"}`)
	if !stepped.Load() {
		t.Fatal("the premise: the clock never stepped back")
	}
	if out.GeneratedAt != out.ObservedAt || out.ObservedAt != at.Format(time.RFC3339) {
		t.Errorf("observed %s, generated %s: want both at the time the sources were read, %s", out.ObservedAt, out.GeneratedAt, at.Format(time.RFC3339))
	}
	if out.Counts.Affected != 1 {
		t.Errorf("counts %+v", out.Counts)
	}
}
