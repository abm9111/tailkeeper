package securitypack

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/security"
)

// countdownContext reports context.Canceled from the first call to Err after its free calls.
// Counting calls instead of waiting on a timer puts a cancellation at an exact check.
type countdownContext struct {
	context.Context
	free  int64
	calls atomic.Int64
}

func newCountdown(free int64) *countdownContext {
	return &countdownContext{Context: context.Background(), free: free}
}

func (c *countdownContext) Err() error {
	if c.calls.Add(1) > c.free {
		return context.Canceled
	}
	return nil
}

func TestPreflightTimesUsesTheLatestInstantOfEveryKind(t *testing.T) {
	base := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	older := base.Add(-time.Hour)
	evidence := func(acquired time.Time, observed *time.Time) security.EvidenceRef {
		return security.EvidenceRef{Context: "ctx-local-only", Scope: security.ScopeLocal, Asset: "synthetic", Origin: security.OriginLocal, AcquiredAt: acquired, ObservedAt: observed, Freshness: security.FreshnessFresh}
	}
	// Every instant starts an hour before base; each case raises exactly one of them to base.
	build := func(raise string) packInput {
		pi := packInput{EvaluationAt: older, Snapshot: security.Snapshot{ObservedAt: older}}
		at := func(name string) time.Time {
			if name == raise {
				return base
			}
			return older
		}
		versionObserved, platformObserved := at("version observed"), at("platform observed")
		pi.EvaluationAt = at("evaluation")
		pi.Snapshot.ObservedAt = at("snapshot")
		pi.Snapshot.Versions = []security.VersionFact{{Evidence: evidence(at("version acquired"), &versionObserved)}}
		pi.Snapshot.Platforms = []security.PlatformFact{{Evidence: evidence(older, &platformObserved)}}
		pi.Snapshot.Features = []security.FeatureFact{{Evidence: evidence(at("feature acquired"), nil)}}
		pi.Snapshot.Policies = []security.PolicyFact{{Evidence: evidence(at("policy acquired"), nil)}}
		pi.Access = &accessInput{Input: security.AccessInput{EvaluatedAt: at("access")}}
		return pi
	}
	for _, raise := range []string{"evaluation", "snapshot", "version acquired", "version observed", "platform observed", "feature acquired", "policy acquired", "access"} {
		t.Run(raise, func(t *testing.T) {
			pi := build(raise)
			if err := preflightTimes(pi, security.CorrectionIntent{ActionAt: base}); !errors.Is(err, ErrActionNotAfterObservation) {
				t.Fatalf("an action at the %s instant: %v", raise, err)
			}
			if err := preflightTimes(pi, security.CorrectionIntent{ActionAt: base.Add(time.Nanosecond)}); err != nil {
				t.Fatalf("an action after every instant: %v", err)
			}
		})
	}
	pi := build("")
	pi.Access = nil
	if err := preflightTimes(pi, security.CorrectionIntent{ActionAt: older.Add(time.Nanosecond)}); err != nil {
		t.Fatalf("no access input: %v", err)
	}
}

func TestVisitEvidenceAndAssetsCoverEveryFactKind(t *testing.T) {
	snapshot := factsFixture()
	snapshot.Versions[0].Evidence.Asset = "version-asset"
	snapshot.Platforms[0].Evidence.Asset = "platform-asset"
	snapshot.Features[0].Evidence.Asset = "feature-asset"
	snapshot.Policies[0].Evidence.Asset = "policy-asset"
	seen := map[string]bool{}
	visitEvidence(snapshot, func(e security.EvidenceRef) { seen[e.Asset] = true })
	for _, asset := range []string{"version-asset", "platform-asset", "feature-asset", "policy-asset"} {
		if !seen[asset] || !hasAsset(snapshot, asset) {
			t.Errorf("%s was not visited", asset)
		}
	}
	if hasAsset(snapshot, "other-asset") {
		t.Fatal("an unrelated asset was found")
	}
}

func TestGuardOutcomeNamesAMissingJudgement(t *testing.T) {
	got := guardOutcome(security.AccessJudgement{Status: security.AccessMet}, security.AccessJudgement{Status: "never judged"})
	if got != "access_judgement_missing" {
		t.Fatalf("got %q", got)
	}
}

func TestPreflightFactsSurfacesJudgeErrors(t *testing.T) {
	p, c, _ := fleetVerifyFixture(t)
	pi, err := packInputOf(p)
	if err != nil {
		t.Fatal(err)
	}
	c.Findings = nil
	c.Versions = []security.ExpectedVersion{{Asset: "synthetic", Name: "client", AtLeast: "9.8.9"}}
	c.Features = []security.ExpectedFeature{{Asset: "synthetic", Name: "tailscale_ssh", Value: false}}
	if err := preflightFacts(context.Background(), pi, c, security.WorkBudget{}); err != nil {
		t.Fatalf("control: %v", err)
	}
	badVersion := c
	badVersion.Versions = []security.ExpectedVersion{{Asset: "synthetic", Name: "client", AtLeast: "not a release"}}
	err = preflightFacts(context.Background(), pi, badVersion, security.WorkBudget{})
	if err == nil || errors.Is(err, ErrTargetNotOpen) || errors.Is(err, ErrDeviceNotInPack) {
		t.Fatalf("unparseable minimum release: %v", err)
	}
	badFeature := c
	badFeature.Features = []security.ExpectedFeature{{Asset: "synthetic", Name: security.FeatureConnectedToControl, Value: true}}
	err = preflightFacts(context.Background(), pi, badFeature, security.WorkBudget{})
	if err == nil || errors.Is(err, ErrTargetNotOpen) || errors.Is(err, ErrDeviceNotInPack) {
		t.Fatalf("connection guard as an expected feature: %v", err)
	}
}

func TestAppendRowsSurfaceJudgeErrorsFromEitherSide(t *testing.T) {
	p, c, a := fleetVerifyFixture(t)
	prepared := PreparedCorrection{}
	r, err := Replay(context.Background(), p, security.WorkBudget{})
	if err != nil {
		t.Fatal(err)
	}
	prepared.replay = r
	c.Findings = nil
	c.Versions = []security.ExpectedVersion{{Asset: "synthetic", Name: "client", AtLeast: "9.8.9"}}
	c.Features = []security.ExpectedFeature{{Asset: "synthetic", Name: "tailscale_ssh", Value: false}}
	var out VerificationReport
	if err := appendVersionRows(context.Background(), &out, prepared, c, a, security.WorkBudget{}); err != nil || len(out.Targets) != 1 {
		t.Fatalf("version control: %v %+v", err, out)
	}
	brokenAfter := a
	brokenAfter.Now = time.Time{}
	out = VerificationReport{}
	if err := appendVersionRows(context.Background(), &out, prepared, c, brokenAfter, security.WorkBudget{}); err == nil || len(out.Targets) != 0 {
		t.Fatalf("after-side version error: %v %+v", err, out)
	}
	badVersion := c
	badVersion.Versions = []security.ExpectedVersion{{Asset: "synthetic", Name: "client", AtLeast: "not a release"}}
	if err := appendVersionRows(context.Background(), &out, prepared, badVersion, a, security.WorkBudget{}); err == nil || len(out.Targets) != 0 {
		t.Fatalf("before-side version error: %v %+v", err, out)
	}
	badFeature := c
	badFeature.Features = []security.ExpectedFeature{{Asset: "synthetic", Name: security.FeatureConnectedToControl, Value: true}}
	if err := appendFeatureRows(context.Background(), &out, prepared, badFeature, a, security.WorkBudget{}); err == nil || len(out.Targets) != 0 {
		t.Fatalf("before-side feature error: %v %+v", err, out)
	}
	if err := appendFeatureRows(context.Background(), &out, prepared, c, brokenAfter, security.WorkBudget{}); err == nil || len(out.Targets) != 0 {
		t.Fatalf("after-side feature error: %v %+v", err, out)
	}
}

func TestVerifyRefusesTooManyCatalogSources(t *testing.T) {
	p, c, a := fleetVerifyFixture(t)
	a.CatalogSources = make([]advisory.Source, maxCatalogSources+1)
	if _, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("one source too many: %v", err)
	}
	a.CatalogSources = make([]advisory.Source, maxCatalogSources)
	if _, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{}); errors.Is(err, ErrTooLarge) {
		t.Fatalf("the source count limit is inclusive: %v", err)
	}
}

func TestSameCatalogComparesEveryHeaderField(t *testing.T) {
	_, _, a := fleetVerifyFixture(t)
	clone := func() security.Catalog {
		c := a.Catalog
		c.Records = append([]security.AdvisoryRecord(nil), a.Catalog.Records...)
		return c
	}
	if !sameCatalog(a.Catalog, clone()) {
		t.Fatal("identical catalogs differ")
	}
	later := a.Catalog.IssuedAt.Add(time.Hour)
	for name, change := range map[string]func(*security.Catalog){
		"schema version": func(c *security.Catalog) { c.SchemaVersion++ },
		"revision":       func(c *security.Catalog) { c.Revision++ },
		"issued at":      func(c *security.Catalog) { c.IssuedAt = later },
		"expires at":     func(c *security.Catalog) { c.ExpiresAt = later },
		"digest":         func(c *security.Catalog) { c.Digest = strings.Repeat("0", len(c.Digest)) },
		"record count":   func(c *security.Catalog) { c.Records = nil },
	} {
		changed := clone()
		change(&changed)
		if sameCatalog(a.Catalog, changed) || sameCatalog(changed, a.Catalog) {
			t.Errorf("%s: a changed catalog compared equal", name)
		}
	}
}

func TestOtherRulesChangedReportsRemovedAndRewrittenRules(t *testing.T) {
	_, _, a := fleetVerifyFixture(t)
	rule := a.Catalog.Records[0]
	renamed := rule
	renamed.ID = "SYNTHETIC-OTHER"
	before := security.Catalog{Records: []security.AdvisoryRecord{rule, renamed}}
	targeted := map[string]bool{rule.ID: true}
	if otherRulesChanged(before, security.Catalog{Records: []security.AdvisoryRecord{rule, renamed}}, targeted) {
		t.Fatal("an unchanged catalog reported a change")
	}
	if !otherRulesChanged(before, security.Catalog{Records: []security.AdvisoryRecord{rule}}, targeted) {
		t.Fatal("a removed rule was not reported")
	}
	rewritten := renamed
	rewritten.Mitigation = "Rewritten guidance."
	if !otherRulesChanged(before, security.Catalog{Records: []security.AdvisoryRecord{rule, rewritten}}, targeted) {
		t.Fatal("a rewritten rule was not reported")
	}
	if otherRulesChanged(before, security.Catalog{Records: []security.AdvisoryRecord{renamed}}, targeted) {
		t.Fatal("a change to the targeted rule alone was reported as another rule")
	}
	if !otherRulesChanged(security.Catalog{Records: []security.AdvisoryRecord{rule}}, security.Catalog{Records: []security.AdvisoryRecord{rule, renamed}}, targeted) {
		t.Fatal("an added rule was not reported")
	}
}

func TestVerifyCountsNewFindingsFromOtherRules(t *testing.T) {
	p, c, a := fleetVerifyFixture(t)
	// The other rule keeps the device affected after the targeted rule is satisfied.
	other := strings.Replace(strings.Replace(replayCatalog, "SYNTHETIC-ONLY", "SYNTHETIC-OTHER", 1), `"fixed":"9.8.9"`, `"fixed":"9.10.0"`, 1)
	a.CatalogSources = append(a.CatalogSources, advisory.Source{Name: "other.json", Data: []byte(other)})
	var err error
	a.Catalog, err = advisory.Merge(a.CatalogSources)
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyCorrection(context.Background(), p, c, a, security.WorkBudget{})
	if err != nil || r.Outcome != "fixed" || !r.CatalogChangedOtherRules || r.NewOtherFindings != 1 {
		t.Fatalf("got %+v %v", r, err)
	}
}

func TestIntentIndexAndEntryRefuseAmbiguousIDs(t *testing.T) {
	network := security.NetworkExpectation{ID: "network-1", Source: "group", Accept: []string{"service"}}
	twin := security.IntentSet{SchemaVersion: 1, Network: []security.NetworkExpectation{network, network}}
	if _, ok := intentIndex(context.Background(), twin); ok {
		t.Fatal("two network expectations with one id were indexed")
	}
	single := security.IntentSet{SchemaVersion: 1, Network: []security.NetworkExpectation{network}}
	if entry, ok := intentEntry(single, "network-1"); !ok || len(entry) == 0 {
		t.Fatalf("control: %q %v", entry, ok)
	}
	for name, in := range map[string]security.IntentSet{"absent": single, "ambiguous": twin} {
		id := "network-1"
		if name == "absent" {
			id = "network-9"
		}
		if entry, ok := intentEntry(in, id); ok || entry != nil {
			t.Errorf("%s: %q %v", name, entry, ok)
		}
	}
}

func TestIntentAndAccessBoundsRefuseEachKindOfExcess(t *testing.T) {
	long := strings.Repeat("x", security.MaxTextBytes+1)
	network := security.NetworkExpectation{ID: "network-1", Source: "group", Accept: []string{"service"}, SourcePostureAttributes: security.PostureAttributes{"os": {Kind: security.ScalarString, String: "linux"}}}
	intent := security.IntentSet{SchemaVersion: 1, Network: []security.NetworkExpectation{network}}
	if !intentWithinBounds(context.Background(), intent) {
		t.Fatal("control intent refused")
	}
	var missing context.Context
	if intentWithinBounds(missing, intent) {
		t.Fatal("nil context accepted")
	}
	if intentWithinBounds(context.Background(), security.IntentSet{Network: make([]security.NetworkExpectation, security.MaxObservations+1)}) {
		t.Fatal("too many network expectations accepted")
	}
	tooMany := security.IntentSet{Network: make([]security.NetworkExpectation, 1), SSH: make([]security.SSHExpectation, security.MaxObservations)}
	if intentWithinBounds(context.Background(), tooMany) {
		t.Fatal("expectations past the shared limit accepted")
	}
	longPosture := intent
	longPosture.Network = []security.NetworkExpectation{network}
	longPosture.Network[0].SourcePostureAttributes = security.PostureAttributes{"os": {Kind: security.ScalarString, String: long}}
	if intentWithinBounds(context.Background(), longPosture) {
		t.Fatal("overlong posture attribute accepted")
	}

	_, _, a := accessVerifyFixture(t)
	input := a.Access.Input
	if !accessWithinBounds(context.Background(), input) {
		t.Fatal("control access input refused")
	}
	if accessWithinBounds(missing, input) {
		t.Fatal("nil context accepted")
	}
	bad := input
	bad.PolicyVersion = long
	if accessWithinBounds(context.Background(), bad) {
		t.Fatal("overlong policy version accepted")
	}
	bad = input
	bad.Candidates = map[string]security.AccessCandidates{"network-1": {Rules: []security.RuleRef{{Section: "acls", Index: 1, Destination: long}}}}
	if accessWithinBounds(context.Background(), bad) {
		t.Fatal("overlong candidate rule accepted")
	}
	bad = input
	bad.Limits = map[string][]security.AccessLimit{"network-1": {security.AccessLimit(long)}}
	if accessWithinBounds(context.Background(), bad) {
		t.Fatal("overlong limit accepted")
	}
}

func TestSelectCompatibleStopsAtEachCheck(t *testing.T) {
	current := &security.IntentSet{
		Network: []security.NetworkExpectation{{ID: "network-1", Source: "group", Accept: []string{"a"}}},
		SSH: []security.SSHExpectation{
			{ID: "ssh-1", Source: "group", Destinations: []string{"b"}, Accept: []string{"u"}},
			{ID: "ssh-2", Source: "group", Destinations: []string{"c"}, Accept: []string{"u"}},
		},
	}
	selected := []string{"network-1", "ssh-1", "ssh-2"}
	run := func(free int64, changed []string) (security.IntentSet, int64) {
		var result security.IntentSet
		ctx := newCountdown(free)
		selectCompatible(ctx, &result, current, selected, changed)
		return result, ctx.calls.Load()
	}
	if r, _ := run(1<<30, nil); len(r.Network) != 1 || len(r.SSH) != 2 {
		t.Fatalf("control: %+v", r)
	}
	if r, _ := run(1<<30, []string{"ssh-1"}); len(r.Network) != 1 || len(r.SSH) != 1 || r.SSH[0].ID != "ssh-2" {
		t.Fatalf("a changed expectation must not be carried over: %+v", r)
	}
	// The checks run once per changed id, once per selected id, then once per network and per SSH entry.
	// A canceled check must end the work at once: no check runs after the one that reported it.
	for _, tc := range []struct {
		name         string
		free         int64
		changed      []string
		network, ssh int
	}{
		{"while reading the changed ids", 0, []string{"ssh-1"}, 0, 0},
		{"while reading the selected ids", 0, nil, 0, 0},
		{"before the network entries", int64(len(selected)), nil, 0, 0},
		{"before the SSH entries", int64(len(selected)) + 1, nil, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, calls := run(tc.free, tc.changed)
			if len(r.Network) != tc.network || len(r.SSH) != tc.ssh {
				t.Fatalf("kept work after cancellation: %+v", r)
			}
			if calls != tc.free+1 {
				t.Fatalf("%d checks ran; the canceled one is check %d", calls, tc.free+1)
			}
		})
	}
}
