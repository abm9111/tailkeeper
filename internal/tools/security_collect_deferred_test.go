package tools_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// The deferred items of the Task 5 reviews that Task 6a closes in the collector.

// F9: with no API client there is no tailnet to name, and every tailnet used to get the same
// reference, which looked like one bound to a tailnet. It is now marked as local-only, and no
// digest of a tailnet is made from nothing.
func TestAContextReferenceWithNoAPIIsMarkedLocalOnly(t *testing.T) {
	bound := newRig(t)
	got := bound.collect(security.ScopeLocal).Snapshot.Context
	if got != security.ContextLocalOnly {
		t.Errorf("local scope with an API client: %q", got)
	}

	local := newRig(t)
	local.env.API = nil
	c := local.collect(security.ScopeLocal)
	if c.Snapshot.Context != "ctx-local-only" {
		t.Errorf("with no API client the reference is %q, want ctx-local-only", c.Snapshot.Context)
	}
	// Everything the collection holds carries it, so no row claims a tailnet. (No local source
	// answers here: the stand-in CLI is not used, so these tests run on every platform.)
	for _, r := range c.Coverage {
		if r.Context != "ctx-local-only" {
			t.Errorf("a coverage row carries %q", r.Context)
		}
	}
}

// F8: a device list over the body cap fails the API source and nothing else, with a code of
// its own (not the API's generic error), and the effective limit is the one the client
// enforces, which is lower than securityBodyMax over MCP.
func TestADeviceListOverTheBodyCapIsAGapWithItsOwnCode(t *testing.T) {
	r := newRig(t)
	const limit = 512
	r.env.API = r.env.API.WithMaxBody(limit)
	var devs []map[string]any
	for _, id := range []string{selfID, "nBIG01CNTRL", "nBIG02CNTRL", "nBIG03CNTRL", "nBIG04CNTRL", "nBIG05CNTRL", "nBIG06CNTRL", "nBIG07CNTRL"} {
		devs = append(devs, dev(id, nil))
	}
	r.devices(devs...)
	if size := len(mustJSON(t, map[string]any{"devices": devs})); size <= limit {
		t.Fatalf("the premise: the list is %d bytes and must be over %d", size, limit)
	}
	c, err := tools.CollectSecurity(context.Background(), r.env, security.ScopeFleet)
	if err != nil {
		t.Fatalf("a list over the cap ended the run: %v", err)
	}
	requireValid(t, c)
	ev := r.apiOutcome()
	if ev.Outcome != security.OutcomeError || ev.Code != string(tkerr.ResponseTooLarge) || ev.Observed != 0 {
		t.Errorf("outcome %+v, want an error coded %s", ev, tkerr.ResponseTooLarge)
	}
	for _, d := range []security.CoverageDimension{security.CoverageVersions, security.CoverageFeatures} {
		rw := row(t, c, d)
		if rw.Status != security.ReportPartial || !strings.Contains(rw.Explanation, "API device list: error (response_too_large)") {
			t.Errorf("%s row: %+v", d, rw)
		}
	}
	// Nothing of the list is in the snapshot: it fails closed. (This node's facts do not join
	// a fleet collection whose list was not read.)
	for _, v := range c.Snapshot.Versions {
		if strings.HasPrefix(v.Evidence.Asset, "nBIG") {
			t.Errorf("a fact of a device from the oversize list: %+v", v)
		}
	}
	// The error says the limit that applied and where the other one is, and no text of the body.
	e := tools.TooLargeError(limit)
	if e.Code != tkerr.ResponseTooLarge || !strings.Contains(e.Message, "512") || !strings.Contains(e.Hint, "MCP") || !strings.Contains(e.Hint, "32 MiB") {
		t.Errorf("error: %+v", e)
	}
}

// C-report question 2: a list longer than the snapshot holds is cut where the API's order says,
// and the coverage text says so, so that nobody reads the cut as a sort.
func TestACutDeviceListSaysItFollowsTheAPIsOrder(t *testing.T) {
	r := newRig(t)
	// 10,001 devices of one fact each: past what a snapshot holds.
	var b strings.Builder
	b.WriteString(`{"devices":[`)
	for i := 0; i < 10001; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"nodeId":"nCUT%05dCNTRL","os":"linux","lastSeen":%q}`, i, seenAgo(time.Minute))
	}
	b.WriteString(`]}`)
	r.f.JSON("GET", tailnetPath+"/devices", 200, b.String())
	c, err := tools.CollectSecurity(context.Background(), r.env, security.ScopeFleet)
	if err != nil {
		t.Fatal(err)
	}
	requireValid(t, c)
	ev := r.apiOutcome()
	if ev.Outcome != security.OutcomeTruncated || ev.Dropped == 0 {
		t.Fatalf("the premise: the list was not cut: %+v", ev)
	}
	for _, d := range []security.CoverageDimension{security.CoverageVersions, security.CoverageFeatures} {
		rw := row(t, c, d)
		if rw.Status != security.ReportPartial || !strings.Contains(rw.Explanation, "items not observed") ||
			!strings.Contains(rw.Explanation, "the first the API listed") || !strings.Contains(rw.Explanation, "not sorted") {
			t.Errorf("%s row: %q", d, rw.Explanation)
		}
	}
}

// C-report question 4 (decision D5). At fleet scope this node counts as having a version
// through its API row even when the local daemon gave none, and that must clear nothing: an
// API fact stands in for the running daemon only while the device is connected to control and
// the fact is under 30 minutes old. The control case shows the rule can clear a device, so the
// others are not cleared for want of a rule that could.
func TestThisNodesAPIRowWithNoDaemonVersionClearsNoRunningDaemonRuleUnlessGuarded(t *testing.T) {
	rule := security.AdvisoryRecord{ID: "RULE-D5", Revision: "1", Component: "client", VersionRole: security.VersionRunningDaemon,
		Ranges: []security.VersionRange{{Fixed: "1.100.0"}}, Source: "synthetic", Severity: security.SeverityHigh,
		ReviewedAt: now.Add(-72 * time.Hour), ReviewExpiresAt: now.Add(72 * time.Hour), ReviewState: security.ReviewApproved}
	catalog := security.Catalog{SchemaVersion: security.SchemaVersion, Revision: 1, IssuedAt: now.Add(-48 * time.Hour),
		ExpiresAt: now.Add(48 * time.Hour), Records: []security.AdvisoryRecord{rule}}
	for _, tc := range []struct {
		name  string
		extra map[string]any
		want  security.Applicability
		why   security.UnknownReason
	}{
		{"connected and fresh: the API speaks for the daemon", nil, security.ApplicabilityNotAffected, ""},
		{"disconnected", map[string]any{"connectedToControl": false}, security.ApplicabilityUnknown, security.ReasonRuntimeUnobserved},
		{"connection not reported", map[string]any{"connectedToControl": nil}, security.ApplicabilityUnknown, security.ReasonRuntimeUnobserved},
		{"connected, last seen 31 minutes ago", map[string]any{"lastSeen": seenAgo(31 * time.Minute)}, security.ApplicabilityUnknown, security.ReasonRuntimeUnobserved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newCLIRig(t)
			// The local daemon gave a CLI version and no daemon version.
			r.cli.on("status --json --peers=false", 0, `{"BackendState":"Running","Self":{"ID":"`+selfID+`","OS":"linux"}}`, "")
			r.cli.on("version --json --daemon", 0, `{"long":"1.102.5-t0123456ab"}`, "")
			r.cli.on("get --json", 0, `{"accept-dns":true,"ssh":false}`, "")
			r.devices(dev(selfID, tc.extra))
			c := r.collect(security.ScopeFleet)
			if v := row(t, c, security.CoverageVersions); v.Status != security.ReportComplete {
				t.Fatalf("the premise: the API row gives this node a version, so the versions row is %s: %s", v.Status, v.Explanation)
			}
			for _, f := range c.Snapshot.Versions {
				if f.Role == security.VersionRunningDaemon {
					t.Fatalf("the premise: there is a daemon version fact: %+v", f)
				}
			}
			findings, _, err := security.Match(context.Background(), catalog, c.Snapshot, now, security.WorkBudget{})
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || findings[0].Asset != selfID {
				t.Fatalf("findings: %+v", findings)
			}
			f := findings[0]
			if f.Applicability != tc.want || f.Reason != tc.why {
				t.Errorf("the finding is %s (%q), want %s (%q)", f.Applicability, f.Reason, tc.want, tc.why)
			}
		})
	}
}
