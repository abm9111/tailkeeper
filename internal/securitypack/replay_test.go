package securitypack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/security"
)

const replayCatalog = `{"schema_version":1,"revision":1,"issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","records":[{"id":"SYNTHETIC-ONLY","revision":"1","component":"client","version_role":"running_daemon","ranges":[{"fixed":"9.8.9"}],"source":"synthetic source","severity":"high","reviewed_at":"2025-12-01T00:00:00Z","review_expires_at":"2027-01-01T00:00:00Z","review_state":"approved","mitigation":"Synthetic guidance."}]}`

func replayFixture(t *testing.T) BuildInput {
	t.Helper()
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	src := []advisory.Source{{Name: "synthetic.json", Data: []byte(replayCatalog)}}
	catalog, err := advisory.Merge(src)
	if err != nil {
		t.Fatal(err)
	}
	v := "1.30.0"
	snap := security.Snapshot{Context: "ctx-local-only", Scope: security.ScopeLocal, ObservedAt: at.Add(-time.Minute), Versions: []security.VersionFact{{Name: "client", Role: security.VersionRunningDaemon, Channel: security.ChannelStable, Value: &v, Evidence: security.EvidenceRef{Context: "ctx-local-only", Scope: security.ScopeLocal, Asset: "synthetic", Origin: security.OriginLocal, AcquiredAt: at.Add(-time.Minute), Freshness: security.FreshnessFresh}}}}
	in := security.Input{Catalog: catalog, Snapshot: snap, Now: at, Budget: security.WorkBudget{Candidates: 100}}
	report, err := security.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return BuildInput{Input: in, Report: report, Sources: src}
}
func replaySeal(b []byte) string {
	sum := sha256.Sum256(append([]byte("synthetic-test-key"), b...))
	return fmt.Sprintf("hmac-sha256:%x", sum)
}
func built(t *testing.T, in BuildInput, seal Sealer) ([]byte, EvidencePack, Replayed) {
	t.Helper()
	data, r, err := Build(context.Background(), in, seal)
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := Decode(data, seal)
	if err != nil {
		t.Fatal(err)
	}
	return data, p, r
}
func TestBuildReplayEmbeddedCatalogAndDeterminism(t *testing.T) {
	in := replayFixture(t)
	a, p, r := built(t, in, nil)
	b, _, _ := built(t, in, nil)
	if !bytes.Equal(a, b) {
		t.Fatal("same frozen inputs changed bytes")
	}
	if r.Reproduction.Status != "reproduced" || r.ScopeSentence != ScopeSentence || len(r.Report.Findings) != 1 || r.Report.Findings[0].RuleID != "SYNTHETIC-ONLY" {
		t.Fatalf("unexpected replay: %+v", r.Reproduction)
	}
	if _, err := Replay(context.Background(), p, security.WorkBudget{Candidates: 99}); !errors.Is(err, ErrBudgetTooSmall) {
		t.Fatalf("ceiling: %v", err)
	}
	again, err := Replay(context.Background(), p, security.WorkBudget{Candidates: 100})
	if err != nil || again.Reproduction.Status != "reproduced" {
		t.Fatalf("replay: %v %+v", err, again.Reproduction)
	}
}
func TestBuildRejectsMismatchedReport(t *testing.T) {
	in := replayFixture(t)
	in.Report.Coverage[0].Explanation = "synthetic altered explanation"
	data, _, err := Build(context.Background(), in, nil)
	if !errors.Is(err, ErrNotReproduced) || data != nil {
		t.Fatalf("bad report: %v", err)
	}
	in = replayFixture(t)
	in.Report.Snapshot.Versions = append([]security.VersionFact(nil), in.Report.Snapshot.Versions...)
	in.Report.Snapshot.Versions[0].Name = "other"
	data, _, err = Build(context.Background(), in, nil)
	if !errors.Is(err, ErrInvalidPack) || data != nil {
		t.Fatalf("bad snapshot: %v", err)
	}
}
func TestReplayDifferencesAndVersionRefusals(t *testing.T) {
	_, p, _ := built(t, replayFixture(t), nil)
	pi, err := packInputOf(p)
	if err != nil {
		t.Fatal(err)
	}
	pi.Expected.Report.SHA256 = strings.Repeat("a", 64)
	p, err = newPack(pi, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Replay(context.Background(), p, security.WorkBudget{})
	if err != nil || r.Reproduction.Status != "not_reproduced" || len(r.Reproduction.Differences) != 1 || r.Reproduction.Differences[0] != "report.sha256" {
		t.Fatalf("difference: %+v %v", r.Reproduction, err)
	}
	cases := []struct {
		name   string
		change func(*EvidencePack)
		want   error
	}{
		{"pack", func(p *EvidencePack) { p.envelope.Body.PackSchemaVersion++ }, ErrUnsupportedPackSchema},
		{"evaluator", func(p *EvidencePack) { p.envelope.Body.EvaluatorVersion++ }, ErrUnsupportedEvaluator},
		{"report", func(p *EvidencePack) { p.envelope.Body.ReportSchemaVersion++ }, ErrUnsupportedReportSchema},
		{"catalog", func(p *EvidencePack) { p.envelope.Body.CatalogSchemaVersion++ }, ErrUnsupportedCatalogSchema},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := p
			tc.change(&q)
			_, err := Replay(context.Background(), q, security.WorkBudget{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if _, err := Replay(context.Background(), EvidencePack{}, security.WorkBudget{}); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("zero pack: %v", err)
	}
}
func TestReferenceAndSealStates(t *testing.T) {
	data, p, r := built(t, replayFixture(t), replaySeal)
	if r.Reading.Seal != SealValid {
		t.Fatal(r.Reading.Seal)
	}
	plain, err := Reference(p, nil, true)
	if err != nil || len(plain) != 12 {
		t.Fatalf("plain %q %v", plain, err)
	}
	body, err := encodePackBody(p.envelope.Body)
	if err != nil {
		t.Fatal(err)
	}
	material := append([]byte("tailkeeper-evidence-pack/1\n"), body...)
	digest := sha256.Sum256(material)
	full := fmt.Sprintf("%x", digest)
	if plain != full[:12] || !bytes.Contains(data, []byte(full)) || strings.Contains(plain, full) {
		t.Fatal("reference failed its digest and privacy checks")
	}
	keyed, err := Reference(p, replaySeal, false)
	if err != nil || len(keyed) != 12 || keyed == plain {
		t.Fatalf("keyed %q %v", keyed, err)
	}
	keyedFull := replaySeal(material)
	if keyed != keyedFull[len("hmac-sha256:"):len("hmac-sha256:")+12] || strings.Contains(keyed, keyedFull) {
		t.Fatal("incorrect keyed reference")
	}
	empty, err := Reference(p, nil, false)
	if err != nil || empty != "" {
		t.Fatal("masked without key")
	}
	if _, err := Reference(p, func([]byte) string { return "invalid" }, false); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("invalid sealer: %v", err)
	}
	q, reading, err := Decode(data, nil)
	if err != nil || reading.Seal != SealNotChecked {
		t.Fatalf("unchecked: %v %v", reading, err)
	}
	rr, err := Replay(context.Background(), q, security.WorkBudget{})
	if err != nil || rr.Reading.Seal != SealNotChecked {
		t.Fatalf("reading not carried: %v", err)
	}
	data, _, _ = built(t, replayFixture(t), nil)
	_, reading, err = Decode(data, replaySeal)
	if err != nil || reading.Seal != SealAbsentKeyLoaded {
		t.Fatalf("absent with key: %v %v", reading, err)
	}
}
func TestReplayFreshnessHistorical(t *testing.T) {
	in := replayFixture(t)
	_, p, _ := built(t, in, nil)
	f := ReplayFreshness(p, in.Input.Now.Add(370*24*time.Hour))
	if !f.Valid || f.ClockUncertain || f.CatalogState != security.CatalogExpired || f.StaleReviews != 1 {
		t.Fatalf("freshness: %+v", f)
	}
	f = ReplayFreshness(p, in.Input.Now.Add(-6*time.Minute))
	if !f.ClockUncertain || f.Age != -6*time.Minute {
		t.Fatalf("skew: %+v", f)
	}
	if ReplayFreshness(EvidencePack{}, in.Input.Now).Valid {
		t.Fatal("zero pack")
	}
}

func TestBuildAccessNormalizationAndTokenForms(t *testing.T) {
	in := replayFixture(t)
	intent := security.IntentSet{SchemaVersion: security.SchemaVersion, Network: []security.NetworkExpectation{{ID: "network-1", Source: "synthetic", Accept: []string{"tag:service:443"}}, {ID: "network-2", Source: "synthetic-two", Deny: []string{"tag:service:22"}}}}
	in.Input.Intent = &intent
	var err error
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	access := security.AccessInput{Intent: intent, EvaluatedAt: in.Input.Now, Candidates: map[string]security.AccessCandidates{"network-1": {}, "network-2": {}}, Limits: map[string][]security.AccessLimit{"network-1": {security.LimitVia, security.LimitApp, security.LimitVia}, "network-2": {security.LimitSource}}}
	in.Access = &AccessEvidence{Context: "ctx-0123456789abcdef", Selected: []string{"network-1", "network-2"}, Input: access}
	a, _, ra := built(t, in, nil)
	in.Access.Input.Limits = map[string][]security.AccessLimit{"network-2": {security.LimitSource}, "network-1": {security.LimitApp, security.LimitVia}}
	in.Access.Input.Candidates = map[string]security.AccessCandidates{"network-2": {}, "network-1": {}}
	b, _, rb := built(t, in, nil)
	if !bytes.Equal(a, b) || ra.AccessReport == nil || rb.AccessReport == nil || len(ra.AccessJudgements) != 2 {
		t.Fatal("access decisions or bytes diverged")
	}
	for _, value := range []string{"sha256:bad", "hmac-sha256:" + strings.Repeat("A", 64), "opaque"} {
		in.Input.Intent.Digest = value
		if data, _, err := Build(context.Background(), in, nil); err == nil || data != nil {
			t.Fatalf("accepted malformed digest")
		}
	}
	for _, value := range []string{"opaque", strings.Repeat("a", 64), "\"" + strings.Repeat("A", 64) + "\""} {
		if _, err := policyForm(value); err == nil {
			t.Fatal("accepted malformed policy token")
		}
	}
}

func TestBudgetAndTokenHelpers(t *testing.T) {
	for _, tc := range []struct {
		recorded, ceiling int
		want              bool
	}{{0, 0, true}, {0, 100, false}, {100, 0, true}, {100, 99, false}, {-1, 0, false}, {100, -1, false}, {security.MaxCandidates + 1, 0, false}} {
		if got := budgetAllows(security.WorkBudget{Candidates: tc.recorded}, security.WorkBudget{Candidates: tc.ceiling}); got != tc.want {
			t.Fatalf("budget %d,%d: %v", tc.recorded, tc.ceiling, got)
		}
	}
	for _, tc := range []struct {
		token string
		want  tokenForm
	}{{"", ""}, {"\"" + strings.Repeat("a", 64) + "\"", "plain"}, {"hmac-sha256:" + strings.Repeat("a", 64), "keyed"}} {
		got, err := policyForm(tc.token)
		if err != nil || got != tc.want {
			t.Fatalf("policy form: %q %v", got, err)
		}
	}
}

func TestReportHashStopsAmplification(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	refs := make([]security.EvidenceRef, 1000)
	for i := range refs {
		refs[i] = security.EvidenceRef{Context: "ctx-local-only", Scope: security.ScopeLocal, Asset: "synthetic", Origin: security.OriginLocal, AcquiredAt: at, Freshness: security.FreshnessFresh, Error: strings.Repeat("x", 256)}
	}
	findings := make([]security.Finding, 240)
	for i := range findings {
		findings[i].Evidence = refs
	}
	_, err := expectedReport(security.Snapshot{}, security.Report{GeneratedAt: at, Findings: findings})
	if !errors.Is(err, ErrReportTooLarge) {
		t.Fatalf("amplified report: %v", err)
	}
}

func TestBuildRejectsStoppedEarly(t *testing.T) {
	in := replayFixture(t)
	second := in.Input.Snapshot.Versions[0]
	second.Evidence.Asset = "other-synthetic"
	in.Input.Snapshot.Versions = append(in.Input.Snapshot.Versions, second)
	in.Input.Budget.Candidates = 1
	report, err := security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	if !security.StoppedEarly(report) {
		t.Fatal("test did not exhaust recorded work budget")
	}
	in.Report = report
	data, _, err := Build(context.Background(), in, nil)
	if !errors.Is(err, ErrStoppedEarly) || data != nil {
		t.Fatalf("stopped report: %v", err)
	}
}

func TestReplayRejectsCatalogAndMissingFacts(t *testing.T) {
	_, p, _ := built(t, replayFixture(t), nil)
	badCatalog := p
	badCatalog.envelope.Body.Catalog.Digest = strings.Repeat("0", 64)
	if _, err := Replay(context.Background(), badCatalog, security.WorkBudget{}); !errors.Is(err, ErrCatalogMismatch) {
		t.Fatalf("catalog: %v", err)
	}
	missing := p
	missing.envelope.Body.Expected.Counts.Versions++
	if _, err := Replay(context.Background(), missing, security.WorkBudget{}); !errors.Is(err, ErrMissingFacts) {
		t.Fatalf("missing facts: %v", err)
	}
}

func TestSnapshotBindingCoversEveryFact(t *testing.T) {
	in := replayFixture(t)
	a := in.Input.Snapshot
	e := a.Versions[0].Evidence
	yes := true
	value := "synthetic"
	a.Platforms = []security.PlatformFact{{Evidence: e, OS: "linux"}}
	a.Features = []security.FeatureFact{{Evidence: e, Name: "test", Value: &yes}}
	a.Policies = []security.PolicyFact{{Evidence: e, Name: "test", Value: &value}}
	if !sameSnapshot(a, a) {
		t.Fatal("equal snapshot was rejected")
	}
	cases := []struct {
		name   string
		change func(*security.Snapshot)
	}{
		{"platform", func(s *security.Snapshot) {
			s.Platforms = append([]security.PlatformFact(nil), s.Platforms...)
			s.Platforms[0].OS = "macos"
		}},
		{"feature", func(s *security.Snapshot) {
			s.Features = append([]security.FeatureFact(nil), s.Features...)
			no := false
			s.Features[0].Value = &no
		}},
		{"policy", func(s *security.Snapshot) {
			s.Policies = append([]security.PolicyFact(nil), s.Policies...)
			s.Policies[0].Value = nil
		}},
		{"evidence time", func(s *security.Snapshot) {
			s.Versions = append([]security.VersionFact(nil), s.Versions...)
			s.Versions[0].Evidence.AcquiredAt = s.Versions[0].Evidence.AcquiredAt.Add(time.Second)
		}},
		{"snapshot time", func(s *security.Snapshot) { s.ObservedAt = s.ObservedAt.Add(time.Second) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := a
			tc.change(&b)
			if sameSnapshot(a, b) {
				t.Fatal("different snapshot accepted")
			}
		})
	}
}

func TestReplayStoppedEarlyDoesNotClaimReproduction(t *testing.T) {
	in := replayFixture(t)
	second := in.Input.Snapshot.Versions[0]
	second.Evidence.Asset = "other-synthetic"
	in.Input.Snapshot.Versions = append(in.Input.Snapshot.Versions, second)
	var err error
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	_, p, _ := built(t, in, nil)
	pi, err := packInputOf(p)
	if err != nil {
		t.Fatal(err)
	}
	pi.WorkBudget.Candidates = 1
	p, err = newPack(pi, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Replay(context.Background(), p, security.WorkBudget{})
	if err != nil || r.Reproduction.Status != "not_reproduced" || r.Reproduction.Cause != "stopped_early" {
		t.Fatalf("stopped replay: %+v %v", r.Reproduction, err)
	}
}

func TestCatalogSummaryUsesRecordedCatalog(t *testing.T) {
	in := replayFixture(t)
	data := `{"schema_version":1,"revision":2,"issued_at":"2026-02-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z","records":[{"id":"PENDING-CUSTOM","revision":"1","component":"client","version_role":"running_daemon","source":"private synthetic source","severity":"unknown","reviewed_at":"2026-01-01T00:00:00Z","review_expires_at":"2026-11-01T00:00:00Z","review_state":"pending","mitigation":"private synthetic mitigation"},{"id":"WITHDRAWN-CUSTOM","revision":"1","component":"client","version_role":"running_daemon","source":"private synthetic source","severity":"unknown","reviewed_at":"2026-01-01T00:00:00Z","review_expires_at":"2026-11-01T00:00:00Z","review_state":"withdrawn"}]}`
	in.Sources = append(in.Sources, advisory.Source{Name: "second.json", Data: []byte(data)})
	catalog, err := advisory.Merge(in.Sources)
	if err != nil {
		t.Fatal(err)
	}
	in.Input.Catalog = catalog
	in.Report, err = security.Evaluate(context.Background(), in.Input)
	if err != nil {
		t.Fatal(err)
	}
	_, _, replayed := built(t, in, nil)
	got := replayed.CatalogSummary()
	if got.Revision != 2 || !got.IssuedAt.Equal(catalog.IssuedAt) || !got.ExpiresAt.Equal(catalog.ExpiresAt) || got.Digest != catalog.Digest || got.Rules != 3 || got.Approved != 1 || got.Pending != 1 || got.Withdrawn != 1 {
		t.Fatalf("wrong catalog metadata: %+v", got)
	}
	text := fmt.Sprint(got)
	if strings.Contains(text, "private synthetic") || strings.Contains(text, "PENDING-CUSTOM") {
		t.Fatal("catalog text appeared in summary")
	}
	// The result is a value; changing it cannot affect a later summary.
	got.Rules = 99
	if replayed.CatalogSummary().Rules != 3 {
		t.Fatal("summary changed replayed catalog")
	}
}

func TestReplayPreservesInterruption(t *testing.T) {
	_, p, _ := built(t, replayFixture(t), nil)
	for _, tc := range []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
		want    error
	}{
		{"canceled", func() (context.Context, context.CancelFunc) {
			c, cancel := context.WithCancel(context.Background())
			cancel()
			return c, cancel
		}, context.Canceled},
		{"deadline", func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		}, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := tc.context()
			defer cancel()
			_, err := Replay(ctx, p, security.WorkBudget{})
			if !errors.Is(err, tc.want) || errors.Is(err, ErrInvalidPack) {
				t.Fatalf("interruption lost: %v", err)
			}
		})
	}
}
