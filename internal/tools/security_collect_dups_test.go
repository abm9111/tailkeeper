package tools_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// daemonRule is an approved rule for the running daemon, fixed in the release it names, that
// requires the features it names.
func daemonRule(fixed string, features ...string) security.AdvisoryRecord {
	return security.AdvisoryRecord{ID: "RULE-1", Revision: "1", Component: "client", VersionRole: security.VersionRunningDaemon,
		Ranges: []security.VersionRange{{Fixed: fixed}}, RequiredFeatures: features, Source: "synthetic", Severity: security.SeverityHigh,
		ReviewedAt: now.Add(-72 * time.Hour), ReviewExpiresAt: now.Add(24 * time.Hour), ReviewState: security.ReviewApproved}
}

// matchRule judges a collection with one rule and returns the findings by device.
func matchRule(t *testing.T, c tools.SecurityCollection, rec security.AdvisoryRecord) map[string]security.Finding {
	t.Helper()
	cat := security.Catalog{SchemaVersion: security.SchemaVersion, Revision: 1, IssuedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(48 * time.Hour),
		Records: []security.AdvisoryRecord{rec}}
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

// namesDevice says whether any fact of the snapshot names the device.
func namesDevice(s security.Snapshot, id string) bool {
	for _, a := range assets(s) {
		if a == id {
			return true
		}
	}
	return false
}

// believed says whether any fact of the snapshot that carries a value, and no error, names the
// device: a fact the matcher could judge it by.
func believed(s security.Snapshot, id string) bool {
	for _, v := range s.Versions {
		if v.Evidence.Asset == id && (v.Value != nil || v.Evidence.Error == "") {
			return true
		}
	}
	for _, p := range s.Platforms {
		if p.Evidence.Asset == id {
			return true
		}
	}
	for _, f := range s.Features {
		if f.Evidence.Asset == id {
			return true
		}
	}
	return false
}

// unjudged says that the finding for the device is an explicit unknown for evidence_error: the
// device listed twice is in the findings, judged neither way (ruling Q1).
func unjudged(t *testing.T, got map[string]security.Finding, id string) {
	t.Helper()
	if f, ok := got[id]; !ok || f.Applicability != security.ApplicabilityUnknown || f.Reason != security.ReasonEvidenceError {
		t.Errorf("finding for %s = %+v (present %v), want unknown for evidence_error", id, f, ok)
	}
}

// A node ID the API lists twice is not believed on either row. Whichever row comes first, and
// whatever the second says, no fact the matcher could judge it by names the device: it cannot
// be cleared by the row that says it is fixed and connected, nor flagged by the one that says
// it is not. It is still in the findings, as an explicit unknown. The two rows are counted as
// not observed, so the coverage is partial and the result is the same in every order. The
// control (a device listed once) is judged as before, so the check can fail.
func TestADeviceListedTwiceGivesNoFactFromEitherRow(t *testing.T) {
	fixed := map[string]any{"clientVersion": "1.32.3", "connectedToControl": true}
	behind := map[string]any{"clientVersion": "1.32.2", "connectedToControl": false}
	once := dev("nONCE1CNTRL", fixed)
	orders := map[string][]map[string]any{
		"fixed row first":  {dev("nTWIN1CNTRL", fixed), dev("nTWIN1CNTRL", behind), once},
		"behind row first": {dev("nTWIN1CNTRL", behind), dev("nTWIN1CNTRL", fixed), once},
		"rows apart":       {dev("nTWIN1CNTRL", fixed), once, dev("nTWIN1CNTRL", behind)},
		"control first":    {once, dev("nTWIN1CNTRL", behind), dev("nTWIN1CNTRL", fixed)},
	}
	var first tools.SecurityCollection
	for name, devs := range orders {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.devices(devs...)
			c := r.collect(security.ScopeFleet)
			if believed(c.Snapshot, "nTWIN1CNTRL") {
				t.Errorf("a usable fact names the device listed twice: %+v", c.Snapshot)
			}
			if ev := r.apiOutcome(); ev.Outcome != security.OutcomeTruncated || ev.Observed != 1 || ev.Dropped != 2 {
				t.Errorf("outcome %+v, want the two rows counted as not observed", ev)
			}
			requireGap(t, c, "2 of 3 items not observed")
			got := matchRule(t, c, daemonRule("1.32.3"))
			unjudged(t, got, "nTWIN1CNTRL")
			if len(got) != 2 || got["nONCE1CNTRL"].Applicability != security.ApplicabilityNotAffected {
				t.Errorf("findings: %+v", got)
			}
			// The same snapshot, whatever the order of the rows.
			if first.Snapshot.Context == "" {
				first = c
			} else if !reflect.DeepEqual(first, c) {
				t.Errorf("the collection depends on the order of the rows (assets %v and %v)", assets(first.Snapshot), assets(c.Snapshot))
			}
		})
	}
}

// The same holds for a feature: one row says Tailscale SSH is off and the other says it is on,
// and the rule that needs it would clear the device on one and flag it on the other.
func TestADeviceListedTwiceWithAContradictoryFeatureIsNeitherClearedNorFlagged(t *testing.T) {
	off := dev("nTWIN1CNTRL", map[string]any{"clientVersion": "1.102.5", "sshEnabled": false})
	on := dev("nTWIN1CNTRL", map[string]any{"clientVersion": "1.102.5", "sshEnabled": true})
	rule := daemonRule("1.104.4", security.FeatureTailscaleSSH)
	for name, devs := range map[string][]map[string]any{"off then on": {off, on}, "on then off": {on, off}} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.devices(append(devs, dev("nONCE1CNTRL", map[string]any{"clientVersion": "1.102.5", "sshEnabled": true}))...)
			c := r.collect(security.ScopeFleet)
			if f, ok := feature(c.Snapshot, "nTWIN1CNTRL", security.FeatureTailscaleSSH); ok {
				t.Errorf("a feature fact for the device listed twice: %+v", f)
			}
			got := matchRule(t, c, rule)
			unjudged(t, got, "nTWIN1CNTRL")
			if got["nONCE1CNTRL"].Applicability != security.ApplicabilityAffected {
				t.Errorf("findings: %+v", got)
			}
			requireGap(t, c, "2 of 3 items not observed")
		})
	}
}

// A node ID listed three times, or twice among rows with no usable ID, is still not believed
// (it is named only by the fact that says why), and every row is counted once.
func TestEveryRowOfARepeatedNodeIDIsCounted(t *testing.T) {
	r := newRig(t)
	r.devices(dev("nTHRICE1CNTRL", nil), dev("", nil), dev("nTHRICE1CNTRL", nil), dev("nONCE1CNTRL", nil), dev("nTHRICE1CNTRL", nil), dev("", nil))
	c := r.collect(security.ScopeFleet)
	if ev := r.apiOutcome(); ev.Outcome != security.OutcomeTruncated || ev.Observed != 1 || ev.Dropped != 5 {
		t.Errorf("outcome %+v", ev)
	}
	if got := assets(c.Snapshot); !reflect.DeepEqual(got, []string{"nONCE1CNTRL", "nTHRICE1CNTRL"}) {
		t.Errorf("assets = %v", got)
	}
	if believed(c.Snapshot, "nTHRICE1CNTRL") {
		t.Errorf("a usable fact names the device listed three times: %+v", c.Snapshot)
	}
}

// A row that gives a decision field twice says two things of one device, and encoding/json
// would keep whichever comes last. The device is named, and judged neither way, whatever the
// order of the keys and however the key is written: in another case, or with an escape, both
// of which encoding/json matches to the same field. A field it does not read, and a key of the
// same name in a nested object, are not decision fields given twice: that control is judged,
// so the check can fail.
func TestARowThatGivesADecisionFieldTwiceIsJudgedNeitherWay(t *testing.T) {
	seen := `"lastSeen":"` + seenAgo(time.Minute) + `","connectedToControl":true`
	once := `{"nodeId":"nONCE1CNTRL","clientVersion":"1.104.5",` + seen + `,"name":"a","name":"b","tags":{"os":1,"os":2}}`
	rule := daemonRule("1.104.4")
	for name, row := range map[string]string{
		"fixed version last":    `{"nodeId":"nTWO1CNTRL","clientVersion":"1.102.5","clientVersion":"1.104.5",` + seen + `}`,
		"fixed version first":   `{"nodeId":"nTWO1CNTRL","clientVersion":"1.104.5","clientVersion":"1.102.5",` + seen + `}`,
		"another case":          `{"nodeId":"nTWO1CNTRL","clientVersion":"1.102.5","ClientVersion":"1.104.5",` + seen + `}`,
		"an escaped key":        `{"nodeId":"nTWO1CNTRL","clientVersion":"1.102.5","clientVer\u0073ion":"1.104.5",` + seen + `}`,
		"a feature given twice": `{"nodeId":"nTWO1CNTRL","clientVersion":"1.104.5","sshEnabled":false,"sshEnabled":true,` + seen + `}`,
		"connected given twice": `{"nodeId":"nTWO1CNTRL","clientVersion":"1.104.5","lastSeen":"` + seenAgo(time.Minute) + `","connectedToControl":false,"connectedToControl":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.f.JSON("GET", tailnetPath+"/devices", 200, `{"devices":[`+row+`,`+once+`]}`)
			c := r.collect(security.ScopeFleet)
			if believed(c.Snapshot, "nTWO1CNTRL") {
				t.Errorf("a usable fact names the device whose row gave a field twice: %+v", c.Snapshot)
			}
			got := matchRule(t, c, rule)
			unjudged(t, got, "nTWO1CNTRL")
			if got["nONCE1CNTRL"].Applicability != security.ApplicabilityNotAffected {
				t.Errorf("the control: %+v", got["nONCE1CNTRL"])
			}
			if ev := r.apiOutcome(); ev.Outcome != security.OutcomeTruncated || ev.Observed != 1 || ev.Dropped != 1 {
				t.Errorf("outcome %+v, want the row counted as not observed", ev)
			}
		})
	}
}

// A row that gives its node ID twice names no one device: neither ID is named by it, and the
// row is counted as not observed.
func TestARowThatGivesItsNodeIDTwiceNamesNoDevice(t *testing.T) {
	seen := `"lastSeen":"` + seenAgo(time.Minute) + `","connectedToControl":true`
	r := newRig(t)
	r.f.JSON("GET", tailnetPath+"/devices", 200, `{"devices":[{"nodeId":"nB1CNTRL","NodeID":"nC1CNTRL","clientVersion":"1.104.5",`+seen+`},{"nodeId":"nONCE1CNTRL","clientVersion":"1.104.5",`+seen+`}]}`)
	c := r.collect(security.ScopeFleet)
	if got := assets(c.Snapshot); !reflect.DeepEqual(got, []string{"nONCE1CNTRL"}) {
		t.Errorf("assets = %v", got)
	}
	if ev := r.apiOutcome(); ev.Outcome != security.OutcomeTruncated || ev.Observed != 1 || ev.Dropped != 1 {
		t.Errorf("outcome %+v", ev)
	}
}
