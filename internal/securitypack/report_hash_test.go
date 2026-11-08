package securitypack

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

var hashFieldDecisions = map[reflect.Type]string{
	reflect.TypeOf(security.Report{}):           "SchemaVersion Context KeyEpoch GeneratedAt Status TotalFindings Truncated Snapshot Findings RequestedCoverage Coverage IntentDigest IntentRevision",
	reflect.TypeOf(security.Finding{}):          "ID Context Asset RuleID RuleRevision EvidenceState Applicability Reason Confidence Requirements Verification Remediation SourceSeverity Priority Explanation Evidence",
	reflect.TypeOf(security.EvidenceRef{}):      "Context Asset Scope Origin AcquiredAt ObservedAt Freshness Error",
	reflect.TypeOf(security.CoverageTarget{}):   "Dimension Scope Asset",
	reflect.TypeOf(security.CoverageCounts{}):   "Rules Withdrawn Assets Findings Unknown Potential",
	reflect.TypeOf(security.Coverage{}):         "Target Context Source Status Explanation Counts",
	reflect.TypeOf(security.AccessReport{}):     "SchemaVersion Status NoIntent IntentDigest IntentRevision PolicyVersion EvaluatedAt Counts Proof PairsJudged PairsPastCap Expectations Omitted Blast Notes",
	reflect.TypeOf(security.AccessCounts{}):     "Total Met MetWithLimits Unmet Unknown NotEvaluated",
	reflect.TypeOf(security.AccessProof{}):      "Canary LiveUnchanged",
	reflect.TypeOf(security.AccessResult{}):     "ID Kind Source Status Cells PastCap Candidates CandidatesOmitted Limits",
	reflect.TypeOf(security.AccessCellResult{}): "AccessCell Verdict Observed Reason Proof",
	reflect.TypeOf(security.AccessCell{}):       "Expect Destination User",
	reflect.TypeOf(security.RuleRef{}):          "Section Index Line Column Source Destination Ports Broad Qualified AllTraffic Traffic",
	reflect.TypeOf(security.AccessBlast{}):      "Source Heading Reaches Broad Tags TagsOmitted",
	reflect.TypeOf(security.AccessReach{}):      "Kind Destination User Expectation",
}

var fixtureTime = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
var timeType = reflect.TypeOf(time.Time{})

func populateHashFixture(v reflect.Value) {
	if v.Type() == timeType {
		v.Set(reflect.ValueOf(fixtureTime))
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type() == reflect.TypeOf(security.Report{}) && v.Type().Field(i).Name == "Snapshot" {
				continue
			}
			populateHashFixture(v.Field(i))
		}
	case reflect.Ptr:
		v.Set(reflect.New(v.Type().Elem()))
		populateHashFixture(v.Elem())
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		populateHashFixture(v.Index(0))
	case reflect.String:
		v.SetString("example")
	case reflect.Int:
		v.SetInt(1)
	case reflect.Bool:
		v.SetBool(true)
	default:
		panic("unhandled fixture field: " + v.Type().String())
	}
}

func TestReportHashExhaustive(t *testing.T) {
	for typ, names := range hashFieldDecisions {
		expected := make(map[string]bool)
		for _, name := range strings.Fields(names) {
			expected[name] = true
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.IsExported() && !expected[f.Name] {
				t.Errorf("%s.%s has no hash decision", typ, f.Name)
			}
			delete(expected, f.Name)
		}
		for name := range expected {
			t.Errorf("%s.%s is no longer present", typ, name)
		}
	}
}

// changeLeaves tests each leaf independently, including the flattened AccessCell.
// Every optional field is populated so its presence and value enter the digest.
func changeLeaves(t *testing.T, v reflect.Value, path string, hash func() (string, error), baseline string) {
	t.Helper()
	if v.Type() == timeType {
		old := v.Interface()
		v.Set(reflect.ValueOf(fixtureTime.Add(time.Second)))
		changed, err := hash()
		if err != nil || changed == baseline {
			t.Errorf("%s: digest unchanged or error: %v", path, err)
		}
		v.Set(reflect.ValueOf(old))
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if v.Type() == reflect.TypeOf(security.Report{}) && f.Name == "Snapshot" {
				continue
			}
			changeLeaves(t, v.Field(i), path+"."+f.Name, hash, baseline)
		}
	case reflect.Ptr:
		changeLeaves(t, v.Elem(), path, hash, baseline)
	case reflect.Slice:
		changeLeaves(t, v.Index(0), path+"[0]", hash, baseline)
	case reflect.String, reflect.Int, reflect.Bool:
		old := reflect.New(v.Type()).Elem()
		old.Set(v)
		switch v.Kind() {
		case reflect.String:
			v.SetString("changed")
		case reflect.Int:
			v.SetInt(2)
		case reflect.Bool:
			v.SetBool(!v.Bool())
		}
		changed, err := hash()
		if err != nil || changed == baseline {
			t.Errorf("%s: digest unchanged or error: %v", path, err)
		}
		v.Set(old)
	default:
		t.Fatalf("unhandled %s", path)
	}
}

func TestReportHashEveryLeaf(t *testing.T) {
	var report security.Report
	populateHashFixture(reflect.ValueOf(&report).Elem())
	hash := func() (string, error) { return hashReport(report) }
	baseline, err := hash()
	if err != nil {
		t.Fatal(err)
	}
	changeLeaves(t, reflect.ValueOf(&report).Elem(), "Report", hash, baseline)
	report.Snapshot.Context = "changed"
	if got, err := hash(); err != nil || got != baseline {
		t.Fatalf("Snapshot must be excluded: %s %v", got, err)
	}
	var access security.AccessReport
	populateHashFixture(reflect.ValueOf(&access).Elem())
	accessHash := func() (string, error) { return hashAccessReport(access) }
	baseline, err = accessHash()
	if err != nil {
		t.Fatal(err)
	}
	changeLeaves(t, reflect.ValueOf(&access).Elem(), "AccessReport", accessHash, baseline)
}

func TestReportHashGolden(t *testing.T) {
	report := security.Report{SchemaVersion: 1, Context: "ctx-local-only", GeneratedAt: fixtureTime, Status: "complete", RequestedCoverage: []security.CoverageTarget{}}
	const canonical = "{\"context\":\"ctx-local-only\",\"generated_at\":\"2024-01-02T03:04:05Z\",\"requested_coverage\":[],\"schema_version\":1,\"status\":\"complete\",\"total_findings\":0,\"truncated\":false}\n"
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(canonical)))
	got, err := hashReport(report)
	if err != nil || got != want {
		t.Fatalf("got %q (%v), want %s", got, err, want)
	}
	access := security.AccessReport{SchemaVersion: 1, Status: "complete", EvaluatedAt: fixtureTime}
	const accessCanonical = "{\"counts\":{\"met\":0,\"met_with_limits\":0,\"not_evaluated\":0,\"total\":0,\"unknown\":0,\"unmet\":0},\"evaluated_at\":\"2024-01-02T03:04:05Z\",\"pairs_judged\":0,\"pairs_past_cap\":0,\"proof\":{\"canary\":false,\"live_unchanged\":false},\"schema_version\":1,\"status\":\"complete\"}\n"
	want = fmt.Sprintf("%x", sha256.Sum256([]byte(accessCanonical)))
	got, err = hashAccessReport(access)
	if err != nil || got != want {
		t.Fatalf("access got %q (%v), want %s", got, err, want)
	}
}

func amplifiedReport(facts, findings, errorBytes int) security.Report {
	refs := make([]security.EvidenceRef, facts)
	for i := range refs {
		refs[i] = security.EvidenceRef{Context: "ctx-local-only", Asset: "device-synthetic", Origin: "synthetic", AcquiredAt: fixtureTime, Freshness: "unknown", Error: strings.Repeat("x", errorBytes)}
	}
	rows := make([]security.Finding, findings)
	for i := range rows {
		rows[i] = security.Finding{Context: "ctx-local-only", ID: "synthetic", RuleID: "rule", RuleRevision: "one", Evidence: refs}
	}
	return security.Report{Context: "ctx-local-only", GeneratedAt: fixtureTime, Findings: rows}
}

func TestReportHashLimit(t *testing.T) {
	report := amplifiedReport(1990, 120, 256)
	if _, err := hashReport(report); !errors.Is(err, errCanonTooLarge) {
		t.Fatalf("expected byte budget error, got %v", err)
	}
}

func hashAllocatedBytes(report security.Report, marshal bool) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 3; i++ {
		if marshal {
			_, _ = json.Marshal(report)
		} else {
			_, _ = hashReport(report)
		}
	}
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestReportHashAllocationGrowth(t *testing.T) {
	// The race detector itself allocates in proportion to every instrumented
	// memory access. Run this byte-growth guard in the ordinary test binary.
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "-race" && setting.Value == "true" {
				t.Skip("race instrumentation changes allocation accounting")
			}
		}
	}
	small, large := amplifiedReport(10, 1, 256), amplifiedReport(2000, 1, 256)
	smallBytes, largeBytes := hashAllocatedBytes(small, false), hashAllocatedBytes(large, false)
	// The full-marshal mutant is a positive control for this very guard.
	mutantBytes := hashAllocatedBytes(large, true)
	const maxGrowth = 1 << 20
	t.Logf("three hashes: small=%d large=%d; marshal mutant=%d bytes", smallBytes, largeBytes, mutantBytes)
	if largeBytes > smallBytes+maxGrowth {
		t.Fatalf("hash allocation grew by %d bytes", largeBytes-smallBytes)
	}
	if mutantBytes <= smallBytes+maxGrowth {
		t.Fatal("allocation guard failed to detect full marshal mutant")
	}
}
