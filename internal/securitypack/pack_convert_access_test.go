package securitypack

import (
	"errors"
	"testing"

	"github.com/abm9111/tailkeeper/internal/security"
)

func sameIntentFixture() security.IntentSet {
	return security.IntentSet{
		SchemaVersion: 1, Revision: "rev-1", Digest: "sha256:digest",
		Network: []security.NetworkExpectation{{ID: "network-1", Source: "group", Protocol: "tcp", Accept: []string{"service:443"}, Deny: []string{"other:22"}, SourcePostureAttributes: security.PostureAttributes{"os": {Kind: security.ScalarString, String: "linux"}}}},
		SSH:     []security.SSHExpectation{{ID: "ssh-1", Source: "group", Destinations: []string{"service"}, Accept: []string{"user"}, Check: []string{"root"}, Deny: []string{"guest"}}},
	}
}

// Each mutation changes exactly one field; the comparison must notice every one of them.
func TestSameIntentComparesEveryField(t *testing.T) {
	if !sameIntent(sameIntentFixture(), sameIntentFixture()) {
		t.Fatal("identical intent sets differ")
	}
	cases := []struct {
		name   string
		change func(*security.IntentSet)
	}{
		{"schema version", func(i *security.IntentSet) { i.SchemaVersion = 2 }},
		{"revision", func(i *security.IntentSet) { i.Revision = "rev-2" }},
		{"digest", func(i *security.IntentSet) { i.Digest = "sha256:other" }},
		{"network id", func(i *security.IntentSet) { i.Network[0].ID = "network-2" }},
		{"network count", func(i *security.IntentSet) { i.Network = nil }},
		{"network protocol", func(i *security.IntentSet) { i.Network[0].Protocol = "udp" }},
		{"network accept", func(i *security.IntentSet) { i.Network[0].Accept = []string{"service:80"} }},
		{"network deny", func(i *security.IntentSet) { i.Network[0].Deny = nil }},
		{"posture value", func(i *security.IntentSet) {
			i.Network[0].SourcePostureAttributes = security.PostureAttributes{"os": {Kind: security.ScalarString, String: "macos"}}
		}},
		{"posture name", func(i *security.IntentSet) {
			i.Network[0].SourcePostureAttributes = security.PostureAttributes{"arch": {Kind: security.ScalarString, String: "linux"}}
		}},
		{"posture count", func(i *security.IntentSet) { i.Network[0].SourcePostureAttributes = nil }},
		{"ssh id", func(i *security.IntentSet) { i.SSH[0].ID = "ssh-2" }},
		{"ssh count", func(i *security.IntentSet) { i.SSH = nil }},
		{"ssh destinations", func(i *security.IntentSet) { i.SSH[0].Destinations = []string{"elsewhere"} }},
		{"ssh check", func(i *security.IntentSet) { i.SSH[0].Check = nil }},
		{"ssh deny", func(i *security.IntentSet) { i.SSH[0].Deny = []string{"other"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := sameIntentFixture()
			tc.change(&changed)
			if sameIntent(sameIntentFixture(), changed) || sameIntent(changed, sameIntentFixture()) {
				t.Fatal("a changed intent set compared equal")
			}
		})
	}
}

func TestNormalizedOmittedRefusesOutOfRangeCounts(t *testing.T) {
	const limit = 1 << 31
	if got, err := normalizedOmitted(2, 5, 3); err != nil || got != 4 {
		t.Fatalf("valid count: %d %v", got, err)
	}
	if got, err := normalizedOmitted(limit-2, 5, 3); err != nil || got != limit {
		t.Fatalf("inclusive bound: %d %v", got, err)
	}
	if got, err := normalizedOmitted(limit, 3, 3); err != nil || got != limit {
		t.Fatalf("an omission at the bound itself: %d %v", got, err)
	}
	for _, tc := range []struct {
		name                 string
		omitted, count, keep int
	}{
		{"negative", -1, 3, 3},
		{"past the bound", limit + 1, 3, 3},
		{"sum past the bound", limit - 1, 5, 3},
	} {
		if got, err := normalizedOmitted(tc.omitted, tc.count, tc.keep); !errors.Is(err, ErrInvalidPack) || got != 0 {
			t.Errorf("%s: %d %v", tc.name, got, err)
		}
	}
	if _, err := candidatesToPack(map[string]security.AccessCandidates{"network-1": {Omitted: -1}}); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("negative candidate omission: %v", err)
	}
}

func accessConversionFixture() (*security.IntentSet, *accessInput) {
	full := &security.IntentSet{SchemaVersion: 1, Network: []security.NetworkExpectation{
		{ID: "network-1", Source: "group", Accept: []string{"service:443"}},
		{ID: "network-2", Source: "group", Accept: []string{"service:80"}},
	}}
	selected := security.IntentSet{SchemaVersion: 1, Network: append([]security.NetworkExpectation(nil), full.Network...)}
	return full, &accessInput{Context: "ctx-0123456789abcdef", Selected: []string{"network-1", "network-2"}, Input: security.AccessInput{Intent: selected}}
}

func TestAccessToPackRefusesInconsistentInput(t *testing.T) {
	full, value := accessConversionFixture()
	if packed, err := accessToPack(value, full); err != nil || packed == nil || len(packed.Selected) != 2 {
		t.Fatalf("control: %+v %v", packed, err)
	}
	value.Input.PolicyVersion = `"` + "x" + `"`
	value.PolicyVersionForm = "plain"
	if packed, err := accessToPack(value, full); err != nil || packed.PolicyVersion == nil || packed.PolicyVersion.Form != "plain" {
		t.Fatalf("policy control: %+v %v", packed, err)
	}
	// A recorded policy form without the policy version it describes is not a pack.
	value.Input.PolicyVersion = ""
	if _, err := accessToPack(value, full); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("form without version: %v", err)
	}
	value.PolicyVersionForm = ""
	value.Input.Candidates = map[string]security.AccessCandidates{"network-1": {Omitted: -1}}
	if _, err := accessToPack(value, full); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("negative omission: %v", err)
	}
}

func TestAccessFromPackRefusesUnorderedAndUnselected(t *testing.T) {
	full, value := accessConversionFixture()
	value.Input.Candidates = map[string]security.AccessCandidates{"network-1": {}, "network-2": {}}
	value.Input.Limits = map[string][]security.AccessLimit{"network-1": {security.LimitRules}, "network-2": {security.LimitPosture}}
	packed, err := accessToPack(value, full)
	if err != nil {
		t.Fatal(err)
	}
	back, err := accessFromPack(packed, full)
	if err != nil || len(back.Input.Candidates) != 2 || len(back.Input.Limits) != 2 || back.Selected[1] != "network-2" {
		t.Fatalf("control: %+v %v", back, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*packAccess)
	}{
		{"unselected expectation", func(p *packAccess) { p.Selected = []string{"network-1", "missing"} }},
		{"candidates out of order", func(p *packAccess) { p.Candidates[0], p.Candidates[1] = p.Candidates[1], p.Candidates[0] }},
		{"duplicate candidates", func(p *packAccess) { p.Candidates[1].Expectation = p.Candidates[0].Expectation }},
		{"limits out of order", func(p *packAccess) { p.Limits[0], p.Limits[1] = p.Limits[1], p.Limits[0] }},
		{"duplicate limits", func(p *packAccess) { p.Limits[1].Expectation = p.Limits[0].Expectation }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clone := *packed
			clone.Selected = append([]string(nil), packed.Selected...)
			clone.Candidates = append([]packCandidate(nil), packed.Candidates...)
			clone.Limits = append([]packLimits(nil), packed.Limits...)
			tc.change(&clone)
			if got, err := accessFromPack(&clone, full); !errors.Is(err, ErrInvalidPack) || got != nil {
				t.Fatalf("got %+v %v", got, err)
			}
		})
	}
}
