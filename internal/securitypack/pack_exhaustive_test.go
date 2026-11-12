package securitypack

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

// walkTextFields uses reflection only in tests to put a positive-control shape
// into each reachable string field, including strings nested in lists.
func walkTextFields(t *testing.T, v reflect.Value, path string, check func() error, count *int) {
	t.Helper()
	if v.Type() == reflect.TypeOf(time.Time{}) {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		walkTextFields(t, v.Elem(), path, check, count)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			walkTextFields(t, v.Field(i), path+"."+v.Type().Field(i).Name, check, count)
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		walkTextFields(t, v.Index(0), path+"[]", check, count)
	case reflect.String:
		v.SetString("ts" + "key-" + "api-")
		if err := check(); !errors.Is(err, ErrSecretShaped) {
			t.Errorf("text leaf %s escaped scan: %v", path, err)
		}
		v.SetString("")
		*count++
	}
}

func TestPackExhaustiveWireTextScan(t *testing.T) {
	var envelope packEnvelope
	count := 0
	walkTextFields(t, reflect.ValueOf(&envelope).Elem(), "envelope", func() error { return checkPackTextLeaves(envelope) }, &count)
	if count < 60 {
		t.Fatalf("unexpectedly few wire string leaves: %d", count)
	}
}

func TestPackExhaustiveCatalogRecordScan(t *testing.T) {
	var record security.AdvisoryRecord
	count := 0
	walkTextFields(t, reflect.ValueOf(&record).Elem(), "record", func() error { return checkCatalogRecord(record) }, &count)
	if count != 12 {
		t.Fatalf("unexpected catalog string leaves: %d", count)
	}
}

func TestPackInternalFieldManifest(t *testing.T) {
	manifests := []struct {
		value  reflect.Type
		fields string
	}{
		{reflect.TypeOf(security.Snapshot{}), "Context KeyEpoch Scope ObservedAt Versions Platforms Features Policies"},
		{reflect.TypeOf(security.VersionFact{}), "Role Channel Name Value Evidence"},
		{reflect.TypeOf(security.PlatformFact{}), "OS Variant Evidence"},
		{reflect.TypeOf(security.FeatureFact{}), "Name Value Evidence"},
		{reflect.TypeOf(security.PolicyFact{}), "Name Value Evidence"},
		{reflect.TypeOf(security.EvidenceRef{}), "Context Asset Scope Origin AcquiredAt ObservedAt Freshness Error"},
		{reflect.TypeOf(security.Coverage{}), "Target Context Source Status Explanation Counts"},
		{reflect.TypeOf(security.CoverageTarget{}), "Dimension Scope Asset"},
		{reflect.TypeOf(security.CoverageCounts{}), "Rules Withdrawn Assets Findings Unknown Potential"},
		{reflect.TypeOf(security.IntentSet{}), "SchemaVersion Revision Digest Network SSH"},
		{reflect.TypeOf(security.NetworkExpectation{}), "ID Source Protocol SourcePostureAttributes Accept Deny"},
		{reflect.TypeOf(security.SSHExpectation{}), "ID Source Destinations Accept Deny Check"},
		{reflect.TypeOf(security.Scalar{}), "Kind String Number Bool"},
		{reflect.TypeOf(security.AccessInput{}), "NoIntent Intent Limit Witnesses Candidates Limits Owners RulesPartial PolicyVersion EvaluatedAt"},
		{reflect.TypeOf(security.AccessWitness{}), "Expectation Cell Observed Reason Proof"},
		{reflect.TypeOf(security.AccessCell{}), "Expect Destination User"},
		{reflect.TypeOf(security.AccessProof{}), "Canary LiveUnchanged"},
		{reflect.TypeOf(security.RuleRef{}), "Section Index Line Column Source Destination Ports Broad Qualified AllTraffic Traffic"},
		{reflect.TypeOf(security.AccessCandidates{}), "Rules Omitted"},
		{reflect.TypeOf(security.AccessOwner{}), "Source Tags Omitted"},
		{reflect.TypeOf(security.Catalog{}), "SchemaVersion Revision IssuedAt ExpiresAt Digest Records"},
		{reflect.TypeOf(security.AdvisoryRecord{}), "ID Revision Component VersionRole OS Ranges RequiredFeatures Source Severity PublishedAt UpdatedAt ReviewedAt ReviewExpiresAt SourceCheckedAt ReviewState Mitigation"},
		{reflect.TypeOf(security.VersionRange{}), "Introduced Fixed"},
	}
	for _, manifest := range manifests {
		typ := manifest.value
		want := strings.Fields(manifest.fields)
		var got []string
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).IsExported() {
				got = append(got, typ.Field(i).Name)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s fields changed: %v", typ, got)
		}
	}
}
