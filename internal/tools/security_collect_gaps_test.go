package tools_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// The failure modes of a collection. A source that fails is a gap in the coverage and never
// an empty answer; the run goes on with the sources that remain. Without a stand-in CLI the
// local sources fail with local_binary_missing, which these tests leave alone.

// apiOutcome is how the API source ended, as recorded.
func (r *rig) apiOutcome() security.CollectionEvent {
	r.t.Helper()
	return r.event(security.SourceAPIDevices, security.PhaseOutcome).ev
}

// requireGap checks that the coverage of both dimensions is partial and names the API source.
func requireGap(t *testing.T, c tools.SecurityCollection, want string) {
	t.Helper()
	for _, dim := range []security.CoverageDimension{security.CoverageVersions, security.CoverageFeatures} {
		rw := row(t, c, dim)
		if rw.Status != security.ReportPartial || !strings.Contains(rw.Explanation, "API device list") || !strings.Contains(rw.Explanation, want) {
			t.Errorf("%s row = %+v, want a gap naming the API source and %q", dim, rw, want)
		}
	}
}

// A missing scope and a plan that does not allow the read are gaps, with the program's own
// error code. The run goes on: the local sources are asked, and without a CLI they fail on
// their own.
func TestCollectionScopeAndBillingFailuresAreGaps(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   tkerr.Code
	}{{403, tkerr.ScopeMissing}, {402, tkerr.PaymentRequired}, {401, tkerr.TokenRejected}, {500, tkerr.UpstreamUnavailable}} {
		t.Run(string(tc.code), func(t *testing.T) {
			r := newRig(t)
			r.f.JSON("GET", tailnetPath+"/devices", tc.status, `{"message":"synthetic"}`)
			c := r.collect(security.ScopeFleet)
			if ev := r.apiOutcome(); ev.Outcome != security.OutcomeError || ev.Code != string(tc.code) || ev.Observed != 0 {
				t.Errorf("outcome %+v", ev)
			}
			if ev := r.event(security.SourceLocalStatus, security.PhaseOutcome).ev; ev.Outcome != security.OutcomeError || ev.Code != string(tkerr.LocalBinaryMissing) {
				t.Errorf("the run did not go on to the local sources: %+v", ev)
			}
			requireGap(t, c, string(tc.code))
			if len(assets(c.Snapshot)) != 0 {
				t.Errorf("facts from sources that failed: %v", assets(c.Snapshot))
			}
		})
	}
}

// A token endpoint that refuses the client, and a credential provider that could not be
// unlocked, are gaps too.
func TestATokenRejectionAndALockedProviderAreGaps(t *testing.T) {
	r := newRig(t)
	bad, err := api.New(context.Background(), apitest.Tailnet, creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID,
		ClientSecret: creds.NewSecret("not-the-secret"), Provider: "env"},
		api.Options{BaseURL: r.f.URL(), Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	r.env.API = bad
	r.devices(dev("nAAA1CNTRL", nil))
	c := r.collect(security.ScopeFleet)
	if ev := r.apiOutcome(); ev.Outcome != security.OutcomeError || ev.Code != string(tkerr.TokenRejected) {
		t.Errorf("token rejection: %+v", ev)
	}
	requireGap(t, c, string(tkerr.TokenRejected))

	r = newRig(t)
	r.env.API, r.env.APIErr = nil, tkerr.New(tkerr.CredentialUnavailable, "the credential provider is locked", "unlock it")
	c = r.collect(security.ScopeFleet)
	if ev := r.apiOutcome(); ev.Outcome != security.OutcomeError || ev.Code != string(tkerr.CredentialUnavailable) {
		t.Errorf("locked provider: %+v", ev)
	}
	requireGap(t, c, string(tkerr.CredentialUnavailable))
	if len(r.f.Requests()) != 0 {
		t.Error("a request was sent with no credential")
	}
}

// A body that is not the shape of the device list is an error of the source, never a tailnet
// with no devices.
func TestAChangedAPIShapeIsAGapAndNotAnEmptyTailnet(t *testing.T) {
	for name, body := range map[string]string{
		"no devices key": `{}`, "null": `{"devices":null}`, "an object": `{"devices":{"a":1}}`, "an array": `[]`,
		"a string": `"devices"`, "a node ID of the wrong type": `{"devices":[{"nodeId":5}]}`, "not JSON": `<html>`,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.f.JSON("GET", tailnetPath+"/devices", 200, body)
			c := r.collect(security.ScopeFleet)
			if ev := r.apiOutcome(); ev.Outcome != security.OutcomeError || ev.Code != string(tkerr.APIError) {
				t.Errorf("outcome %+v", ev)
			}
			requireGap(t, c, string(tkerr.APIError))
			if len(assets(c.Snapshot)) != 0 {
				t.Errorf("facts from a body that is not a device list: %v", assets(c.Snapshot))
			}
		})
	}
	// An empty list is a list; the matcher says that no device was observed.
	r := newRig(t)
	r.devices()
	if ev := func() security.CollectionEvent { r.collect(security.ScopeFleet); return r.apiOutcome() }(); ev.Outcome != security.OutcomeOK || ev.Observed != 0 {
		t.Errorf("an empty device list: %+v", ev)
	}
}

// The caller's cancellation ends the source it interrupts as cancelled, skips the rest, and
// is still recorded: the record is not cancelled with the call. The collection so far comes
// back with the context's error, and its coverage says it is not whole.
func TestCancelledSourceIsRecordedIncomplete(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.f.Handle("GET", tailnetPath+"/devices", func(_ http.ResponseWriter, req *http.Request) {
		cancel()
		<-req.Context().Done()
	})
	c, err := tools.CollectSecurity(ctx, r.env, security.ScopeFleet)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cancellation", err)
	}
	requireValid(t, c)
	o := r.event(security.SourceAPIDevices, security.PhaseOutcome)
	if o.ev.Outcome != security.OutcomeCancelled || !o.live {
		t.Errorf("the cancelled source: %+v, record made with a live context %v", o.ev, o.live)
	}
	for _, src := range []security.CollectionSource{security.SourceLocalStatus, security.SourceLocalVersion, security.SourceLocalPrefs} {
		if ev := r.event(src, security.PhaseOutcome).ev; ev.Outcome != security.OutcomeSkipped || ev.Code != security.SkipCancel {
			t.Errorf("%s: %+v", src, ev)
		}
	}
	requireGap(t, c, "cancelled")
}

// The collection's own time budget ends a source that is slow as a timeout, which is not the
// caller's cancellation, and leaves the other sources unasked.
func TestTheTimeBudgetEndsASlowSourceAsATimeout(t *testing.T) {
	r := newRig(t)
	r.f.Handle("GET", tailnetPath+"/devices", func(_ http.ResponseWriter, req *http.Request) { <-req.Context().Done() })
	c, err := tools.CollectSecurityWithin(context.Background(), r.env, security.ScopeFleet, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("err = %v: the budget is not an error", err)
	}
	requireValid(t, c)
	if ev := r.apiOutcome(); ev.Outcome != security.OutcomeTimeout {
		t.Errorf("outcome %+v", ev)
	}
	for _, src := range []security.CollectionSource{security.SourceLocalStatus, security.SourceLocalVersion, security.SourceLocalPrefs} {
		if ev := r.event(src, security.PhaseOutcome).ev; ev.Outcome != security.OutcomeSkipped || ev.Code != security.SkipBudget {
			t.Errorf("%s: %+v", src, ev)
		}
	}
	requireGap(t, c, "timeout")
}

// A record that cannot be written ends the run, whichever record it is, and the run returns
// no collection: it cannot pass for a complete one. When the first attempt fails, nothing has
// been asked.
func TestAuditFailureCannotReturnComplete(t *testing.T) {
	probe := newRig(t)
	probe.devices(dev("nAAA1CNTRL", nil))
	probe.collect(security.ScopeFleet)
	total := len(probe.got)
	if total < 6 {
		t.Fatalf("a fleet collection recorded %d events", total)
	}
	for failAt := 1; failAt <= total; failAt++ {
		t.Run(fmt.Sprintf("record %d of %d", failAt, total), func(t *testing.T) {
			r := newRig(t)
			r.devices(dev("nAAA1CNTRL", nil))
			r.failAt = failAt
			c, err := tools.CollectSecurity(context.Background(), r.env, security.ScopeFleet)
			if code(err) != tkerr.AuditUnavailable {
				t.Fatalf("err = %v, want audit_unavailable", err)
			}
			if len(c.Coverage) != 0 || len(c.Snapshot.Versions)+len(c.Snapshot.Platforms)+len(c.Snapshot.Features) != 0 {
				t.Errorf("a run whose record failed returned %+v", c)
			}
			if failAt == 1 && len(r.f.Requests()) != 0 {
				t.Error("a source was asked before its attempt was recorded")
			}
		})
	}
}

// More devices than a snapshot holds are cut at a fixed bound, in node ID order, counted and
// reported, and what remains is valid. The room for this node's facts is kept.
func TestMoreDevicesThanASnapshotHoldsAreCountedAndTheRestIsValid(t *testing.T) {
	r := newRig(t)
	devs := make([]map[string]any, 10001)
	for i := range devs {
		devs[i] = dev(fmt.Sprintf("nT%06dCNTRL", i), map[string]any{"sshEnabled": true})
	}
	r.devices(devs...)
	c := r.collect(security.ScopeFleet)
	facts := len(c.Snapshot.Versions) + len(c.Snapshot.Platforms) + len(c.Snapshot.Features)
	ev := r.apiOutcome()
	if facts > security.MaxObservations-8 || ev.Outcome != security.OutcomeTruncated || ev.Observed+ev.Dropped != 10001 || ev.Dropped == 0 || ev.Observed*4 != facts {
		t.Fatalf("%d facts; outcome %+v", facts, ev)
	}
	requireGap(t, c, fmt.Sprintf("%d of 10001", ev.Dropped))
	if got := assets(c.Snapshot); got[0] != "nT000000CNTRL" || len(got) != ev.Observed {
		t.Errorf("the devices kept are not the first by node ID: %d, first %s", len(got), got[0])
	}
}

// Strings and times a source gave that a report cannot hold do not make the snapshot invalid:
// the fact stays, with no value and an error, so it is unusable; a device that cannot be named
// is dropped and counted (a device named twice is in security_collect_dups_test.go).
func TestHostileSourceValuesNeverInvalidateTheSnapshot(t *testing.T) {
	r := newRig(t)
	r.devices(
		dev("nGOOD1CNTRL", nil),
		dev("nCTRL1CNTRL", map[string]any{"os": "linux\x00", "clientVersion": "1.102.5\u202e"}),
		dev("nLONG1CNTRL", map[string]any{"clientVersion": strings.Repeat("9", 5000)}),
		dev("nNEVER1CNTRL", map[string]any{"lastSeen": "0001-01-01T00:00:00Z"}),
		dev("nJUNK1CNTRL", map[string]any{"lastSeen": "yesterday"}),
		dev("nNONE1CNTRL", map[string]any{"lastSeen": nil}),
		dev("n\nBAD1", nil), dev("", nil),
	)
	c := r.collect(security.ScopeFleet)
	ev := r.apiOutcome()
	if ev.Outcome != security.OutcomeTruncated || ev.Observed != 6 || ev.Dropped != 2 {
		t.Errorf("outcome %+v", ev)
	}
	for _, v := range c.Snapshot.Versions {
		bad := v.Evidence.Asset != "nGOOD1CNTRL"
		if bad != (v.Evidence.Error != "") {
			t.Errorf("version fact of %s: error %q", v.Evidence.Asset, v.Evidence.Error)
		}
		if v.Evidence.Asset == "nCTRL1CNTRL" && v.Value != nil {
			t.Errorf("a value with a control character was kept: %q", *v.Value)
		}
	}
	if got := versionsOf(c.Snapshot, "nGOOD1CNTRL"); len(got) != 1 || got[0].Value == nil {
		t.Errorf("the good device: %+v", got)
	}
}

// matchCollected judges a collection with one approved rule: the running daemon is fixed in
// 1.104.4.
func matchCollected(t *testing.T, c tools.SecurityCollection) map[string]security.Finding {
	t.Helper()
	cat := security.Catalog{SchemaVersion: security.SchemaVersion, Revision: 1, IssuedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(48 * time.Hour),
		Records: []security.AdvisoryRecord{{ID: "RULE-1", Revision: "1", Component: "client", VersionRole: security.VersionRunningDaemon,
			Ranges: []security.VersionRange{{Fixed: "1.104.4"}}, Source: "synthetic", Severity: security.SeverityHigh,
			ReviewedAt: now.Add(-72 * time.Hour), ReviewExpiresAt: now.Add(24 * time.Hour), ReviewState: security.ReviewApproved}}}
	findings, _, err := security.Match(context.Background(), cat, c.Snapshot, now, security.WorkBudget{})
	if err != nil {
		t.Fatalf("the matcher refused the collected snapshot: %v", err)
	}
	out := map[string]security.Finding{}
	for _, f := range findings {
		out[f.Asset] = f
	}
	return out
}

// One device whose clock runs ahead is clamped and made unusable; the others in the same
// snapshot are still judged.
func TestOneSkewedDeviceDoesNotAbortTheMatchOfTheRest(t *testing.T) {
	r := newRig(t)
	fixed := "1.104.5-t0123456ab"
	r.devices(
		dev("nFAST1CNTRL", map[string]any{"clientVersion": fixed, "lastSeen": now.Add(time.Hour).Format(time.RFC3339)}),
		dev("nOK1CNTRL", map[string]any{"clientVersion": fixed}),
		dev("nOK2CNTRL", map[string]any{"clientVersion": "1.104.2"}),
	)
	c := r.collect(security.ScopeFleet)
	for _, v := range versionsOf(c.Snapshot, "nFAST1CNTRL") {
		e := v.Evidence
		if e.ObservedAt == nil || !e.ObservedAt.Equal(e.AcquiredAt) || !strings.Contains(e.Error, "clock skew") {
			t.Errorf("the skewed fact: %+v", e)
		}
	}
	got := matchCollected(t, c)
	if len(got) != 3 || got["nOK1CNTRL"].Applicability != security.ApplicabilityNotAffected || got["nOK2CNTRL"].Applicability != security.ApplicabilityAffected ||
		got["nFAST1CNTRL"].Applicability != security.ApplicabilityUnknown || got["nFAST1CNTRL"].Reason != security.ReasonEvidenceError {
		t.Errorf("findings: %+v", got)
	}
}

// A device that is offline, or has not been seen within the freshness window, is never
// cleared. The control (connected and seen a minute ago) is cleared, so the check can fail.
func TestAnOfflineDeviceIsNeverClearedByTheMatcher(t *testing.T) {
	r := newRig(t)
	fixed := map[string]any{"clientVersion": "1.104.5-t0123456ab"}
	with := func(id string, extra map[string]any) map[string]any {
		d := map[string]any{}
		for k, v := range fixed {
			d[k] = v
		}
		for k, v := range extra {
			d[k] = v
		}
		return dev(id, d)
	}
	r.devices(
		with("nCTRL1CNTRL", nil),
		with("nEDGE1CNTRL", map[string]any{"lastSeen": seenAgo(29 * time.Minute)}),
		with("nOFF1CNTRL", map[string]any{"connectedToControl": false}),
		with("nGONE1CNTRL", map[string]any{"connectedToControl": nil}),
		with("nOLD1CNTRL", map[string]any{"lastSeen": seenAgo(31 * time.Minute)}),
		with("nOLD2CNTRL", map[string]any{"lastSeen": seenAgo(48 * time.Hour)}),
		with("nNEVER1CNTRL", map[string]any{"lastSeen": "0001-01-01T00:00:00Z"}),
		with("nNOSEEN1CNTRL", map[string]any{"lastSeen": nil}),
	)
	got := matchCollected(t, r.collect(security.ScopeFleet))
	for id, f := range got {
		cleared := f.Applicability == security.ApplicabilityNotAffected
		if want := id == "nCTRL1CNTRL" || id == "nEDGE1CNTRL"; cleared != want {
			t.Errorf("%s: %s (%s), cleared %v, want %v", id, f.Applicability, f.Reason, cleared, want)
		}
	}
	if len(got) != 8 {
		t.Errorf("%d findings, want 8", len(got))
	}
}
