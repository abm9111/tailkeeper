//go:build !windows

package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/securitypack"
)

// The embedded catalog is attacker-controlled on replay. A rule ID can contain
// an email, so verify must shape it under the current privacy setting.
func TestSecurityVerifyMasksEmbeddedRuleAfterReload(t *testing.T) {
	const catalogText = `{"schema_version":1,"revision":1,"issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","records":[{"id":"zqrule@example.com","revision":"1","component":"client","version_role":"running_daemon","ranges":[{"fixed":"9.8.9"}],"source":"synthetic","severity":"high","reviewed_at":"2025-12-01T00:00:00Z","review_expires_at":"2027-01-01T00:00:00Z","review_state":"approved","mitigation":"Synthetic guidance."}]}`
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	sources := []advisory.Source{{Name: "synthetic.json", Data: []byte(catalogText)}}
	catalog, err := advisory.Merge(sources)
	if err != nil {
		t.Fatal(err)
	}
	old := "1.30.0"
	snapshot := security.Snapshot{Context: security.ContextLocalOnly, Scope: security.ScopeLocal, ObservedAt: at.Add(-time.Minute), Versions: []security.VersionFact{{Name: "client", Role: security.VersionRunningDaemon, Channel: security.ChannelStable, Value: &old, Evidence: security.EvidenceRef{Context: security.ContextLocalOnly, Scope: security.ScopeLocal, Asset: "synthetic", Origin: security.OriginLocal, AcquiredAt: at.Add(-time.Minute), Freshness: security.FreshnessFresh}}}}
	input := security.Input{Catalog: catalog, Snapshot: snapshot, Now: at, Budget: security.WorkBudget{Candidates: 100}}
	report, err := security.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	data, _, err := securitypack.Build(context.Background(), securitypack.BuildInput{Input: input, Report: report, Sources: sources}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := privatePackDir(t)
	before := filepath.Join(dir, "before.json")
	if err := os.WriteFile(before, data, 0600); err != nil {
		t.Fatal(err)
	}
	correction := filepath.Join(dir, "correction.json")
	if err := os.WriteFile(correction, []byte(`{"schema_version":1,"action_at":"2026-03-04T05:07:07Z","findings":[{"rule":"zqrule@example.com","device":"synthetic"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	args, err := json.Marshal(struct {
		Before     string `json:"before"`
		Correction string `json:"correction"`
	}{before, correction})
	if err != nil {
		t.Fatal(err)
	}
	env := packTestEnv(t)
	env.Now = func() time.Time { return at.Add(2 * time.Minute) }
	reg := registry.New()
	RegisterOwnerOnly(reg)
	tool, ok := reg.Get("security_verify")
	if !ok {
		t.Fatal("security verify is not registered")
	}
	for _, mode := range []string{config.PersonalDataMask, config.PersonalDataShow} {
		env.Config.Config.PersonalData = mode
		out, err := tool.Call(context.Background(), env, args)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		wire, err := json.Marshal(out)
		if err != nil {
			t.Fatal(err)
		}
		if visible := strings.Contains(string(wire), "zqrule@example.com"); visible != (mode == config.PersonalDataShow) {
			t.Fatalf("%s: embedded rule visibility %v", mode, visible)
		}
	}
}
