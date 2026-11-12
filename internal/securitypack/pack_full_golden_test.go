package securitypack

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

// This fixture starts with security model values and asserts the full wire
// literal independently of all production conversion and writer helpers.
func TestPackFullMappingGolden(t *testing.T) {
	in := validPackInput()
	at := in.EvaluationAt
	observed := at.Add(-2 * time.Hour)
	in.Snapshot.ObservedAt = at.Add(-3 * time.Hour)
	feature := false
	policy := ""
	version := "1.2.3"
	evidence := security.EvidenceRef{Context: "ctx-local-only", Asset: "asset", Scope: security.ScopeLocal, Origin: security.OriginLocal, AcquiredAt: at.Add(-time.Hour), ObservedAt: &observed, Freshness: security.FreshnessFresh, Error: "note"}
	in.Snapshot.KeyEpoch = "epoch"
	in.Snapshot.Versions = []security.VersionFact{{Role: security.VersionRunningDaemon, Channel: security.ChannelStable, Name: "client", Value: &version, Evidence: evidence}}
	in.Snapshot.Platforms = []security.PlatformFact{{OS: "linux", Variant: "server", Evidence: evidence}}
	in.Snapshot.Features = []security.FeatureFact{{Name: "feature", Value: &feature, Evidence: evidence}}
	in.Snapshot.Policies = []security.PolicyFact{{Name: "policy", Value: &policy, Evidence: evidence}}
	in.Collected = []security.Coverage{{Context: "ctx-local-only", Target: security.CoverageTarget{Asset: "asset", Dimension: security.CoverageVersions, Scope: security.ScopeLocal}, Source: "collector", Status: security.ReportPartial, Explanation: "explanation", Counts: &security.CoverageCounts{Assets: 1, Findings: 2, Potential: 3, Rules: 4, Unknown: 5, Withdrawn: 6}}}
	in.WorkBudget = security.WorkBudget{Candidates: 123}
	in.Expected = packExpected{Counts: packExpectedCounts{Devices: 1, Features: 1, Platforms: 1, Policies: 1, Versions: 1}, Report: packExpectedReport{Affected: 1, NotAffected: 2, PotentiallyAffected: 3, SHA256: strings.Repeat("b", 64), Status: "partial", TotalFindings: 10, Unknown: 4}, Access: &packExpectedAccess{Met: 1, MetWithLimits: 2, NotEvaluated: 3, SHA256: strings.Repeat("c", 64), Status: "incomplete", Total: 15, Unknown: 4, Unmet: 5}}
	digest := strings.Repeat("d", 64)
	intent := security.IntentSet{SchemaVersion: 1, Digest: "sha256:" + digest, Revision: digest[:12], Network: []security.NetworkExpectation{{ID: "network-1", Source: "group", Protocol: "tcp", Accept: []string{"target"}, Deny: []string{"other"}, SourcePostureAttributes: security.PostureAttributes{"a": {Kind: security.ScalarBool, Bool: false}, "b": {Kind: security.ScalarNumber, Number: "1.50"}, "c": {Kind: security.ScalarString, String: "text"}}}}, SSH: []security.SSHExpectation{{ID: "ssh-1", Source: "group", Destinations: []string{"target"}, Accept: []string{"user"}, Check: []string{"check-user"}, Deny: []string{"deny-user"}}}}
	in.Intent = &intent
	in.IntentDigestForm = "plain"
	in.Access = &accessInput{Context: "ctx-0123456789abcdef", Selected: []string{"ssh-1", "network-1"}, PolicyVersionForm: "plain", Input: security.AccessInput{Intent: intent, Limit: 7, EvaluatedAt: at.Add(time.Hour), RulesPartial: true, PolicyVersion: `"` + digest + `"`, Candidates: map[string]security.AccessCandidates{"network-1": {Omitted: 1, Rules: []security.RuleRef{{Section: "acls", Index: 1, Line: 2, Column: 3, Source: "group", Destination: "*", Broad: true, Qualified: true, AllTraffic: true}, {Section: "grants", Index: 2, Source: "group", Destination: "target", Ports: "22", Traffic: "tcp"}}}}, Limits: map[string][]security.AccessLimit{"network-1": {security.LimitRules, security.LimitPosture}}, Owners: []security.AccessOwner{{Source: "group", Tags: []string{"tag-a", "tag-b"}, Omitted: 2}}, Witnesses: []security.AccessWitness{{Expectation: "network-1", Cell: security.AccessCell{Expect: "accept", Destination: "target"}, Observed: security.ObservedUnknown, Reason: security.ReasonCanary, Proof: security.AccessProof{Canary: true, LiveUnchanged: false}}, {Expectation: "ssh-1", Cell: security.AccessCell{Expect: "accept", Destination: "target", User: "user"}, Observed: security.ObservedAllowed, Proof: security.AccessProof{Canary: false, LiveUnchanged: true}}}}}
	sealValue := "hmac-sha256:" + strings.Repeat("e", 64)
	pack, err := newPack(in, func([]byte) string { return sealValue })
	if err != nil {
		t.Fatalf("new pack: %v", err)
	}
	got, err := Encode(pack)
	if err != nil {
		t.Fatal(err)
	}

	source := syntheticSource("ordinary").Data
	sourceDigest := sha256.Sum256(source)
	source64 := base64.StdEncoding.EncodeToString(source)
	evidenceJSON := `{"acquired_at":"2026-02-28T23:00:00Z","asset":"asset","context":"ctx-local-only","error":"note","freshness":"fresh","observed_at":"2026-02-28T22:00:00Z","origin":"local","scope":"local"}`
	body := `{"access":{"candidates":[{"expectation":"network-1","omitted":1,"rules":[{"all_traffic":true,"broad":true,"column":3,"destination":"*","index":1,"line":2,"qualified":true,"section":"acls","source":"group"},{"destination":"target","index":2,"ports":"22","section":"grants","source":"group","traffic":"tcp"}]}],"context":"ctx-0123456789abcdef","evaluated_at":"2026-03-01T01:00:00Z","limit":7,"limits":[{"expectation":"network-1","limits":["posture","rules"]}],"owners":[{"omitted":2,"source":"group","tags":["tag-a","tag-b"]}],"policy_version":{"form":"plain","value":"\"` + digest + `\""},"rules_partial":true,"selected":["ssh-1","network-1"],"witnesses":[{"cell":{"destination":"target","expect":"accept"},"expectation":"network-1","observed":"unknown","proof":{"canary":true,"live_unchanged":false},"reason":"canary"},{"cell":{"destination":"target","expect":"accept","user":"user"},"expectation":"ssh-1","observed":"allowed","proof":{"canary":false,"live_unchanged":true}}]},"catalog":{"digest":"` + strings.Repeat("a", 64) + `","sources":[{"data":"` + source64 + `","name":"synthetic","sha256":"` + fmt.Sprintf("%x", sourceDigest) + `"}]},"catalog_schema_version":1,"collected":[{"context":"ctx-local-only","counts":{"assets":1,"findings":2,"potential":3,"rules":4,"unknown":5,"withdrawn":6},"explanation":"explanation","source":"collector","status":"partial","target":{"asset":"asset","dimension":"versions","scope":"local"}}],"evaluation":{"at":"2026-03-01T00:00:00Z","work_budget":123},"evaluator_version":1,"expected":{"access":{"met":1,"met_with_limits":2,"not_evaluated":3,"sha256":"` + strings.Repeat("c", 64) + `","status":"incomplete","total":15,"unknown":4,"unmet":5},"counts":{"devices":1,"features":1,"platforms":1,"policies":1,"versions":1},"report":{"affected":1,"not_affected":2,"potentially_affected":3,"sha256":"` + strings.Repeat("b", 64) + `","status":"partial","total_findings":10,"unknown":4}},"format":"tailkeeper-evidence-pack","intent":{"digest":{"form":"plain","value":"sha256:` + digest + `"},"network":[{"accept":["target"],"deny":["other"],"id":"network-1","proto":"tcp","src":"group","src_posture_attrs":[{"bool":false,"name":"a"},{"name":"b","number":"1.50"},{"name":"c","string":"text"}]}],"revision":"` + digest[:12] + `","schema_version":1,"ssh":[{"accept":["user"],"check":["check-user"],"deny":["deny-user"],"dst":["target"],"id":"ssh-1","src":"group"}]},"pack_schema_version":1,"report_schema_version":1,"snapshot":{"context":"ctx-local-only","features":[{"evidence":` + evidenceJSON + `,"name":"feature","value":false}],"key_epoch":"epoch","observed_at":"2026-02-28T21:00:00Z","platforms":[{"evidence":` + evidenceJSON + `,"os":"linux","variant":"server"}],"policies":[{"evidence":` + evidenceJSON + `,"name":"policy","value":""}],"scope":"local","versions":[{"channel":"stable","evidence":` + evidenceJSON + `,"name":"client","role":"running_daemon","value":"1.2.3"}]}}`
	bodyHash := sha256.Sum256(append([]byte("tailkeeper-evidence-pack/1\n"), []byte(body)...))
	want := []byte(fmt.Sprintf("{\"body\":%s,\"integrity\":\"sha256:%x\",\"seal\":\"%s\"}\n", body, bodyHash, sealValue))
	if !bytes.Equal(got, want) {
		t.Fatal("full model-to-wire literal did not match")
	}
	decoded, reading, err := Decode(want, func([]byte) string { return sealValue })
	if err != nil || !decoded.valid || reading.Seal != SealValid {
		t.Fatalf("full literal did not decode: %v", err)
	}
}

func TestPackCoverageSymmetricConversion(t *testing.T) {
	input := []security.Coverage{{Counts: &security.CoverageCounts{Assets: 1, Findings: 2, Potential: 3, Rules: 4, Unknown: 5, Withdrawn: 6}}}
	output := coverageFromPack(coverageToPack(input))
	if !reflect.DeepEqual(input, output) {
		t.Fatal("coverage round trip changed fields")
	}
}
