package securitypack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/tripwire"
)

var (
	fxAcquired   = time.Date(2019, 1, 2, 3, 4, 5, 123456789, time.UTC)
	fxEvaluated  = time.Date(2019, 2, 3, 4, 5, 6, 0, time.UTC)
	fxObserved   = time.Date(2019, 3, 4, 5, 6, 7, 500000000, time.UTC)
	fxSnapshotAt = time.Date(2019, 4, 5, 6, 7, 8, 1, time.UTC)
)

const fixtureSpecial = "q\"u\\o<&>/é"

func ptrString(value string) *string { return &value }
func ptrBool(value bool) *bool       { return &value }

func fixtureEvidence() packEvidence {
	return packEvidence{
		AcquiredAt: fxAcquired,
		Context:    "ev-ctx",
		Freshness:  "fresh",
		Origin:     "origin",
		Scope:      "ev-scope",
	}
}

func fixtureEvidenceFull() packEvidence {
	observed := fxObserved
	return packEvidence{
		AcquiredAt: fxAcquired,
		Asset:      "asset<&>/é",
		Context:    "ev-ctx",
		Error:      "ev-err",
		Freshness:  "fresh",
		ObservedAt: &observed,
		Origin:     "origin",
		Scope:      "ev-scope",
	}
}

// codecFixture returns a complete neutral valid envelope. Stage B package
// tests reuse it without changing its shape.
func codecFixture() packEnvelope {
	base := fixtureEvidence()
	return packEnvelope{
		Body: packBody{
			Access: &packAccess{
				Candidates: []packCandidate{
					{
						Expectation: "allow",
						Rules: []packRule{{
							Destination: "",
							Index:       0,
							Section:     "",
							Source:      "",
						}},
					},
					{
						Expectation: "deny",
						Omitted:     2,
						Rules: []packRule{{
							AllTraffic:  true,
							Broad:       true,
							Column:      3,
							Destination: fixtureSpecial,
							Index:       7,
							Line:        9,
							Ports:       "22",
							Qualified:   true,
							Section:     "in",
							Source:      "src",
							Traffic:     "tcp",
						}},
					},
				},
				Context:     "access-context",
				EvaluatedAt: fxAcquired,
				Limit:       0,
				Limits:      []packLimits{{Expectation: "allow", Limits: []string{"a", "b"}}},
				Owners:      []packOwner{{Omitted: 3, Source: "owner-source", Tags: []string{"t1", "t2"}}, {Source: "other-owner"}},
				PolicyVersion: &packToken{
					Form:  "seq",
					Value: "1",
				},
				RulesPartial: false,
				Selected:     []string{"allow"},
				Witnesses: []packWitness{{
					Cell: packCell{
						Destination: "dest",
						Expect:      "allow",
						User:        "alice",
					},
					Expectation: "allow",
					Observed:    "observed",
					Proof:       packProof{Canary: false, LiveUnchanged: true},
					Reason:      "reason",
				}},
			},
			Catalog: packCatalog{
				Digest: "catalog-digest",
				Sources: []packSource{
					{Data: []byte("alpha"), Name: "a", SHA256: "hash-a"},
					{Data: []byte{0x00, 0x01, 0xff}, Name: "b", SHA256: "hash-b"},
				},
			},
			CatalogSchemaVersion: 2,
			Collected: []packCoverage{{
				Context:     "cov-context",
				Counts:      &packCoverageCounts{Assets: 1, Findings: 2, Potential: 3, Rules: 4, Unknown: 5, Withdrawn: 6},
				Explanation: "cov\"ex<&>/é",
				Source:      "cov-source",
				Status:      "ok",
				Target: packCoverageTarget{
					Asset:     "cov-asset",
					Dimension: "dim",
					Scope:     "cov-scope",
				},
			}},
			Evaluation:       packEvaluation{At: fxEvaluated, WorkBudget: 5000},
			EvaluatorVersion: 3,
			Expected: packExpected{
				Access: &packExpectedAccess{
					Met:           1,
					MetWithLimits: 2,
					NotEvaluated:  3,
					SHA256:        "acc-hash",
					Status:        "pass",
					Total:         6,
					Unknown:       4,
					Unmet:         1,
				},
				Counts: packExpectedCounts{Devices: 1, Features: 2, Platforms: 3, Policies: 4, Versions: 5},
				Report: packExpectedReport{
					Affected:            1,
					NotAffected:         2,
					PotentiallyAffected: 3,
					SHA256:              "rep-hash",
					Status:              "ok",
					TotalFindings:       6,
					Unknown:             5,
				},
			},
			Format: "pack-format",
			Intent: &packIntent{
				Digest: &packToken{Form: "digest", Value: "v1"},
				Network: []packNetwork{
					{
						Accept: []string{"net-allowed"},
						Deny:   []string{"net-denied"},
						ID:     "net1",
						Proto:  "tcp",
						Src:    "any",
						SrcPostureAttrs: []packAttribute{
							{Bool: ptrBool(true), Name: "a"},
							{Name: "b", Number: ptrString("1.50")},
							{Name: "c", String: ptrString("str")},
						},
					},
					{ID: "net2", Src: "net-source"},
				},
				Revision:      "rev1",
				SchemaVersion: 4,
				SSH: []packSSH{{
					Accept: []string{"u1"},
					Check:  []string{"host"},
					Deny:   []string{"bad"},
					Dst:    []string{},
					ID:     "ssh1",
					Src:    "src1",
				}},
			},
			PackSchemaVersion:   1,
			ReportSchemaVersion: 2,
			Snapshot: packSnapshot{
				Context:    "snap\"ctx<&>/é",
				Features:   []packFeature{{Evidence: fixtureEvidenceFull(), Name: "feat-a", Value: ptrBool(false)}, {Evidence: base, Name: "feat-b"}},
				KeyEpoch:   "epoch1",
				ObservedAt: fxSnapshotAt,
				Platforms: []packPlatform{
					{Evidence: base, OS: "linux", Variant: "v1"},
					{Evidence: base},
				},
				Policies: []packPolicy{
					{Evidence: base, Name: "pol-a", Value: ptrString("")},
					{Evidence: base, Name: "pol-b"},
				},
				Scope: "snap-scope",
				Versions: []packVersion{
					{Channel: "stable", Evidence: base, Name: "go", Role: "runtime", Value: ptrString("1.22")},
					{Channel: "beta", Evidence: base, Name: "x", Role: "tool"},
				},
			},
		},
		Integrity: "integrity-fixed",
		Seal:      ptrString(""),
	}
}

func minimalPackBody(at time.Time) packBody {
	return packBody{
		Catalog:              packCatalog{Digest: "d", Sources: []packSource{}},
		CatalogSchemaVersion: 1,
		Evaluation:           packEvaluation{At: at},
		EvaluatorVersion:     1,
		Expected: packExpected{
			Counts: packExpectedCounts{},
			Report: packExpectedReport{},
		},
		Format:              "f",
		PackSchemaVersion:   1,
		ReportSchemaVersion: 1,
		Snapshot:            packSnapshot{Context: "c", ObservedAt: at, Scope: "s"},
	}
}

const fixtureEvidenceBaseJSON = `{"acquired_at":"2019-01-02T03:04:05.123456789Z","context":"ev-ctx","freshness":"fresh","origin":"origin","scope":"ev-scope"}`

const fixtureEvidenceFullJSON = `{"acquired_at":"2019-01-02T03:04:05.123456789Z","asset":"asset<&>/é","context":"ev-ctx","error":"ev-err","freshness":"fresh","observed_at":"2019-03-04T05:06:07.5Z","origin":"origin","scope":"ev-scope"}`

const packBodyGolden = `{"access":{"candidates":[{"expectation":"allow","rules":[{"destination":"","index":0,"section":"","source":""}]},{"expectation":"deny","omitted":2,"rules":[{"all_traffic":true,"broad":true,"column":3,"destination":"q\"u\\o<&>/é","index":7,"line":9,"ports":"22","qualified":true,"section":"in","source":"src","traffic":"tcp"}]}],"context":"access-context","evaluated_at":"2019-01-02T03:04:05.123456789Z","limit":0,"limits":[{"expectation":"allow","limits":["a","b"]}],"owners":[{"omitted":3,"source":"owner-source","tags":["t1","t2"]},{"source":"other-owner","tags":[]}],"policy_version":{"form":"seq","value":"1"},"rules_partial":false,"selected":["allow"],"witnesses":[{"cell":{"destination":"dest","expect":"allow","user":"alice"},"expectation":"allow","observed":"observed","proof":{"canary":false,"live_unchanged":true},"reason":"reason"}]},"catalog":{"digest":"catalog-digest","sources":[{"data":"YWxwaGE=","name":"a","sha256":"hash-a"},{"data":"AAH/","name":"b","sha256":"hash-b"}]},"catalog_schema_version":2,"collected":[{"context":"cov-context","counts":{"assets":1,"findings":2,"potential":3,"rules":4,"unknown":5,"withdrawn":6},"explanation":"cov\"ex<&>/é","source":"cov-source","status":"ok","target":{"asset":"cov-asset","dimension":"dim","scope":"cov-scope"}}],"evaluation":{"at":"2019-02-03T04:05:06Z","work_budget":5000},"evaluator_version":3,"expected":{"access":{"met":1,"met_with_limits":2,"not_evaluated":3,"sha256":"acc-hash","status":"pass","total":6,"unknown":4,"unmet":1},"counts":{"devices":1,"features":2,"platforms":3,"policies":4,"versions":5},"report":{"affected":1,"not_affected":2,"potentially_affected":3,"sha256":"rep-hash","status":"ok","total_findings":6,"unknown":5}},"format":"pack-format","intent":{"digest":{"form":"digest","value":"v1"},"network":[{"accept":["net-allowed"],"deny":["net-denied"],"id":"net1","proto":"tcp","src":"any","src_posture_attrs":[{"bool":true,"name":"a"},{"name":"b","number":"1.50"},{"name":"c","string":"str"}]},{"id":"net2","src":"net-source"}],"revision":"rev1","schema_version":4,"ssh":[{"accept":["u1"],"check":["host"],"deny":["bad"],"dst":[],"id":"ssh1","src":"src1"}]},"pack_schema_version":1,"report_schema_version":2,"snapshot":{"context":"snap\"ctx<&>/é","features":[{"evidence":` + fixtureEvidenceFullJSON + `,"name":"feat-a","value":false},{"evidence":` + fixtureEvidenceBaseJSON + `,"name":"feat-b"}],"key_epoch":"epoch1","observed_at":"2019-04-05T06:07:08.000000001Z","platforms":[{"evidence":` + fixtureEvidenceBaseJSON + `,"os":"linux","variant":"v1"},{"evidence":` + fixtureEvidenceBaseJSON + `}],"policies":[{"evidence":` + fixtureEvidenceBaseJSON + `,"name":"pol-a","value":""},{"evidence":` + fixtureEvidenceBaseJSON + `,"name":"pol-b"}],"scope":"snap-scope","versions":[{"channel":"stable","evidence":` + fixtureEvidenceBaseJSON + `,"name":"go","role":"runtime","value":"1.22"},{"channel":"beta","evidence":` + fixtureEvidenceBaseJSON + `,"name":"x","role":"tool"}]}}`

const packEnvelopeGolden = `{"body":` + packBodyGolden + `,"integrity":"integrity-fixed","seal":""}` + "\n"

const minimalPackBodyGolden = `{"catalog":{"digest":"d","sources":[]},"catalog_schema_version":1,"evaluation":{"at":"2019-01-02T03:04:05.123456789Z","work_budget":0},"evaluator_version":1,"expected":{"counts":{"devices":0,"features":0,"platforms":0,"policies":0,"versions":0},"report":{"affected":0,"not_affected":0,"potentially_affected":0,"sha256":"","status":"","total_findings":0,"unknown":0}},"format":"f","pack_schema_version":1,"report_schema_version":1,"snapshot":{"context":"c","observed_at":"2019-01-02T03:04:05.123456789Z","scope":"s"}}`

func TestPackBodyGolden(t *testing.T) {
	got, err := encodePackBody(codecFixture().Body)
	if err != nil {
		t.Fatalf("encodePackBody: %v", err)
	}
	if string(got) != packBodyGolden {
		t.Fatalf("body mismatch:\n got: %s\nwant: %s", got, packBodyGolden)
	}
	if bytes.Contains(got, []byte("\n")) {
		t.Fatalf("body must not contain a newline")
	}
	if !bytes.Contains(got, []byte("value\":false")) || !bytes.Contains(got, []byte("value\":\"\"")) {
		t.Fatalf("pointer false/empty values were not emitted")
	}
}

func TestPackEnvelopeGolden(t *testing.T) {
	got, err := encodePackEnvelope(codecFixture())
	if err != nil {
		t.Fatalf("encodePackEnvelope: %v", err)
	}
	if string(got) != packEnvelopeGolden {
		t.Fatalf("envelope mismatch:\n got: %s\nwant: %s", got, packEnvelopeGolden)
	}
	if bytes.Count(got, []byte("\n")) != 1 || got[len(got)-1] != '\n' {
		t.Fatalf("envelope must end with exactly one LF")
	}
	if !bytes.Contains(got, []byte(`"body":{"access":`)) {
		t.Fatalf("body was not written as a nested object")
	}
}

func TestPackOmissionGrammar(t *testing.T) {
	body := minimalPackBody(fxAcquired)
	got, err := encodePackBody(body)
	if err != nil {
		t.Fatalf("minimal encode: %v", err)
	}
	if string(got) != minimalPackBodyGolden {
		t.Fatalf("minimal body mismatch:\n got: %s\nwant: %s", got, minimalPackBodyGolden)
	}
	for _, absent := range []string{`"access"`, `"collected"`, `"intent"`, `"features":[`, `"key_epoch"`, `"platforms":[`, `"policies":[`, `"versions":[`} {
		if bytes.Contains(got, []byte(absent)) {
			t.Fatalf("optional field %s was not omitted: %s", absent, got)
		}
	}
	for _, required := range []string{`"sources":[]`, `"work_budget":0`, `"devices":0`, `"unknown":0`} {
		if !bytes.Contains(got, []byte(required)) {
			t.Fatalf("required value %s missing: %s", required, got)
		}
	}

	withIntent := minimalPackBody(fxAcquired)
	withIntent.Intent = &packIntent{SchemaVersion: 4}
	got, err = encodePackBody(withIntent)
	if err != nil {
		t.Fatalf("intent encode: %v", err)
	}
	if !bytes.Contains(got, []byte(`"intent":{"schema_version":4}`)) {
		t.Fatalf("empty optional intent members were not omitted: %s", got)
	}

	withAccess := minimalPackBody(fxAcquired)
	withAccess.Access = &packAccess{
		Candidates:  []packCandidate{},
		Context:     "a",
		EvaluatedAt: fxAcquired,
		Limits:      []packLimits{},
		Owners:      []packOwner{},
		Selected:    []string{"x"},
		Witnesses:   []packWitness{},
	}
	got, err = encodePackBody(withAccess)
	if err != nil {
		t.Fatalf("access encode: %v", err)
	}
	wantAccess := `"access":{"candidates":[],"context":"a","evaluated_at":"2019-01-02T03:04:05.123456789Z","limit":0,"limits":[],"owners":[],"rules_partial":false,"selected":["x"],"witnesses":[]}`
	if !bytes.Contains(got, []byte(wantAccess)) {
		t.Fatalf("required empty arrays or false/zero missing:\n got: %s\nwant: %s", got, wantAccess)
	}

	withCoverage := minimalPackBody(fxAcquired)
	withCoverage.Collected = []packCoverage{{
		Context: "c",
		Source:  "s",
		Target:  packCoverageTarget{Dimension: "d", Scope: "s"},
	}}
	got, err = encodePackBody(withCoverage)
	if err != nil {
		t.Fatalf("coverage encode: %v", err)
	}
	wantCoverage := `"collected":[{"context":"c","source":"s","status":"","target":{"dimension":"d","scope":"s"}}]`
	if !bytes.Contains(got, []byte(wantCoverage)) {
		t.Fatalf("optional coverage members were not omitted:\n got: %s\nwant: %s", got, wantCoverage)
	}

	fixture := codecFixture()
	fixtureBody, err := encodePackBody(fixture.Body)
	if err != nil {
		t.Fatalf("fixture encode: %v", err)
	}
	if !bytes.Contains(fixtureBody, []byte(`"name":"feat-a","value":false`)) {
		t.Fatalf("pointer bool false was omitted")
	}
	if !bytes.Contains(fixtureBody, []byte(`"name":"pol-a","value":""`)) {
		t.Fatalf("pointer string empty was omitted")
	}
	fixtureEnvelope, err := encodePackEnvelope(fixture)
	if err != nil {
		t.Fatalf("fixture envelope encode: %v", err)
	}
	if !bytes.HasSuffix(fixtureEnvelope, []byte(`,"seal":""}`+"\n")) {
		t.Fatalf("pointer seal empty was omitted")
	}
}

func assertOrder(t *testing.T, output []byte, first, second string) {
	t.Helper()
	firstAt := bytes.Index(output, []byte(first))
	secondAt := bytes.Index(output, []byte(second))
	if firstAt < 0 || secondAt < 0 {
		t.Fatalf("order marker missing: %q or %q", first, second)
	}
	if firstAt >= secondAt {
		t.Fatalf("order changed: %q must precede %q", first, second)
	}
}

func TestPackTypedOrdering(t *testing.T) {
	base := func() packBody { return minimalPackBody(fxAcquired) }

	if _, err := encodePackBody(base()); err != nil {
		t.Fatalf("empty sources array must be accepted: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*packBody)
	}{
		{"duplicate sources", func(body *packBody) {
			body.Catalog.Sources = []packSource{{Name: "a"}, {Name: "a"}}
		}},
		{"unsorted sources", func(body *packBody) {
			body.Catalog.Sources = []packSource{{Name: "b"}, {Name: "a"}}
		}},
		{"duplicate attributes", func(body *packBody) {
			body.Intent = &packIntent{Network: []packNetwork{{ID: "n", Src: "s", SrcPostureAttrs: []packAttribute{{Bool: ptrBool(true), Name: "a"}, {Bool: ptrBool(false), Name: "a"}}}}}
		}},
		{"unsorted attributes", func(body *packBody) {
			body.Intent = &packIntent{Network: []packNetwork{{ID: "n", Src: "s", SrcPostureAttrs: []packAttribute{{Bool: ptrBool(true), Name: "b"}, {Bool: ptrBool(false), Name: "a"}}}}}
		}},
		{"duplicate candidates", func(body *packBody) {
			body.Access = &packAccess{Selected: []string{"x"}, Candidates: []packCandidate{{Expectation: "a"}, {Expectation: "a"}}}
		}},
		{"unsorted candidates", func(body *packBody) {
			body.Access = &packAccess{Selected: []string{"x"}, Candidates: []packCandidate{{Expectation: "b"}, {Expectation: "a"}}}
		}},
		{"duplicate limits entries", func(body *packBody) {
			body.Access = &packAccess{Selected: []string{"x"}, Limits: []packLimits{{Expectation: "a"}, {Expectation: "a"}}}
		}},
		{"unsorted limits entries", func(body *packBody) {
			body.Access = &packAccess{Selected: []string{"x"}, Limits: []packLimits{{Expectation: "b"}, {Expectation: "a"}}}
		}},
		{"duplicate limit strings", func(body *packBody) {
			body.Access = &packAccess{Selected: []string{"x"}, Limits: []packLimits{{Expectation: "a", Limits: []string{"x", "x"}}}}
		}},
		{"unsorted limit strings", func(body *packBody) {
			body.Access = &packAccess{Selected: []string{"x"}, Limits: []packLimits{{Expectation: "a", Limits: []string{"b", "a"}}}}
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			body := base()
			testCase.mutate(&body)
			output, err := encodePackBody(body)
			if !errors.Is(err, errCanonInvalid) {
				t.Fatalf("want errCanonInvalid, got %v", err)
			}
			if output != nil {
				t.Fatalf("want nil bytes on error, got %d", len(output))
			}
		})
	}

	body := base()
	body.Access = &packAccess{
		Candidates: []packCandidate{{Expectation: "e1", Rules: []packRule{{Destination: "rule-second"}, {Destination: "rule-first"}}}},
		Context:    "ctx", EvaluatedAt: fxAcquired,
		Owners:   []packOwner{{Source: "owner-second"}, {Source: "owner-first"}},
		Selected: []string{"sel-second", "sel-first"},
		Witnesses: []packWitness{
			{Expectation: "wit-second"},
			{Expectation: "wit-first"},
		},
	}
	body.Intent = &packIntent{
		Network:       []packNetwork{{ID: "net-second", Src: "s"}, {ID: "net-first", Src: "s"}},
		SchemaVersion: 1,
		SSH:           []packSSH{{ID: "ssh-second", Src: "s", Dst: []string{}}, {ID: "ssh-first", Src: "s", Dst: []string{}}},
	}
	body.Snapshot.Features = []packFeature{{Evidence: fixtureEvidence(), Name: "feat-second"}, {Evidence: fixtureEvidence(), Name: "feat-first"}}
	body.Snapshot.Platforms = []packPlatform{{Evidence: fixtureEvidence(), OS: "plat-second"}, {Evidence: fixtureEvidence(), OS: "plat-first"}}
	body.Snapshot.Policies = []packPolicy{{Evidence: fixtureEvidence(), Name: "pol-second"}, {Evidence: fixtureEvidence(), Name: "pol-first"}}
	body.Snapshot.Versions = []packVersion{{Evidence: fixtureEvidence(), Name: "ver-second"}, {Evidence: fixtureEvidence(), Name: "ver-first"}}

	output, err := encodePackBody(body)
	if err != nil {
		t.Fatalf("order fixture encode: %v", err)
	}
	pairs := [][2]string{
		{"owner-second", "owner-first"},
		{"sel-second", "sel-first"},
		{"wit-second", "wit-first"},
		{"rule-second", "rule-first"},
		{"net-second", "net-first"},
		{"ssh-second", "ssh-first"},
		{"feat-second", "feat-first"},
		{"plat-second", "plat-first"},
		{"pol-second", "pol-first"},
		{"ver-second", "ver-first"},
	}
	for _, pair := range pairs {
		assertOrder(t, output, pair[0], pair[1])
	}
}

func sourcesWithNames(count int, dataSize int) []packSource {
	sources := make([]packSource, count)
	data := bytes.Repeat([]byte{0x01}, dataSize)
	for i := range sources {
		sources[i] = packSource{Data: data, Name: fmt.Sprintf("s%04d", i)}
	}
	return sources
}

func TestPackWriterBounds(t *testing.T) {
	if MaxPackBytes != 16<<20 || MaxPackNodes != 600000 || PackSchemaVersion != 1 {
		t.Fatalf("pack constants changed")
	}

	catalogBody := func(sources []packSource) packBody {
		body := minimalPackBody(fxAcquired)
		body.Catalog.Sources = sources
		return body
	}

	accepted := []struct {
		name string
		body packBody
	}{
		{"sources 64", catalogBody(sourcesWithNames(64, 1))},
		{"cumulative exactly 4MiB", catalogBody([]packSource{
			{Name: "a", Data: bytes.Repeat([]byte{0x01}, 2<<20)},
			{Name: "b", Data: bytes.Repeat([]byte{0x02}, 2<<20)},
		})},
		{"data over 4096", catalogBody([]packSource{{Name: "a", Data: bytes.Repeat([]byte{0x03}, 8192)}})},
	}
	for _, testCase := range accepted {
		t.Run(testCase.name, func(t *testing.T) {
			output, err := encodePackBody(testCase.body)
			if err != nil {
				t.Fatalf("want accepted: %v", err)
			}
			if output == nil {
				t.Fatalf("want bytes")
			}
		})
	}

	refused := []struct {
		name string
		body packBody
	}{
		{"sources 65", catalogBody(sourcesWithNames(65, 1))},
		{"cumulative over 4MiB", catalogBody([]packSource{
			{Name: "a", Data: bytes.Repeat([]byte{0x01}, 2<<20)},
			{Name: "b", Data: bytes.Repeat([]byte{0x02}, 2<<20+1)},
		})},
	}
	for _, testCase := range refused {
		t.Run(testCase.name, func(t *testing.T) {
			output, err := encodePackBody(testCase.body)
			if !errors.Is(err, errCanonInvalid) || output != nil {
				t.Fatalf("want errCanonInvalid and nil bytes, got %v with %d bytes", err, len(output))
			}
		})
	}

	factBody := func(count int) packBody {
		body := minimalPackBody(fxAcquired)
		body.Snapshot.Versions = make([]packVersion, count)
		for i := range body.Snapshot.Versions {
			body.Snapshot.Versions[i] = packVersion{Evidence: fixtureEvidence(), Name: fmt.Sprintf("v%05d", i)}
		}
		return body
	}
	if _, err := encodePackBody(factBody(10000)); err != nil {
		t.Fatalf("10000 facts must be accepted: %v", err)
	}
	if output, err := encodePackBody(factBody(10001)); !errors.Is(err, errCanonInvalid) || output != nil {
		t.Fatalf("10001 facts must be refused, got %v", err)
	}

	attributeBody := minimalPackBody(fxAcquired)
	attributes := make([]packAttribute, 10001)
	for i := range attributes {
		attributes[i] = packAttribute{Bool: ptrBool(true), Name: fmt.Sprintf("a%05d", i)}
	}
	attributeBody.Intent = &packIntent{Network: []packNetwork{{ID: "n", Src: "s", SrcPostureAttrs: attributes}}}
	if _, err := encodePackBody(attributeBody); err != nil {
		t.Fatalf("over 10000 sorted attributes must be accepted: %v", err)
	}

	accessBody := func(access *packAccess) packBody {
		body := minimalPackBody(fxAcquired)
		body.Access = access
		access.EvaluatedAt = fxAcquired
		return body
	}
	tags := make([]string, 8)
	for i := range tags {
		tags[i] = fmt.Sprintf("t%d", i)
	}
	if _, err := encodePackBody(accessBody(&packAccess{Selected: []string{"x"}, Owners: []packOwner{{Source: "o", Tags: tags}}})); err != nil {
		t.Fatalf("8 owner tags must be accepted: %v", err)
	}
	if output, err := encodePackBody(accessBody(&packAccess{Selected: []string{"x"}, Owners: []packOwner{{Source: "o", Tags: append(tags, "t8")}}})); !errors.Is(err, errCanonInvalid) || output != nil {
		t.Fatalf("9 owner tags must be refused, got %v", err)
	}

	rules := make([]packRule, 8)
	if _, err := encodePackBody(accessBody(&packAccess{Selected: []string{"x"}, Candidates: []packCandidate{{Expectation: "e", Rules: rules}}})); err != nil {
		t.Fatalf("8 candidate rules must be accepted: %v", err)
	}
	if output, err := encodePackBody(accessBody(&packAccess{Selected: []string{"x"}, Candidates: []packCandidate{{Expectation: "e", Rules: make([]packRule, 9)}}})); !errors.Is(err, errCanonInvalid) || output != nil {
		t.Fatalf("9 candidate rules must be refused, got %v", err)
	}

	if output, err := encodePackBody(accessBody(&packAccess{Candidates: []packCandidate{}, Selected: []string{}})); !errors.Is(err, errCanonInvalid) || output != nil {
		t.Fatalf("empty selected must be refused, got %v", err)
	}

	goldenLen := int64(len(packBodyGolden))
	var exact bytes.Buffer
	exactEncoder := newCanonEncoder(&exact, goldenLen)
	if err := writePackBody(exactEncoder, codecFixture().Body); err != nil {
		t.Fatalf("exact meter write: %v", err)
	}
	if err := exactEncoder.finish(false); err != nil {
		t.Fatalf("exact meter finish: %v", err)
	}
	if int64(exact.Len()) != goldenLen {
		t.Fatalf("exact meter wrote %d bytes, want %d", exact.Len(), goldenLen)
	}

	var short bytes.Buffer
	shortEncoder := newCanonEncoder(&short, goldenLen-1)
	shortErr := writePackBody(shortEncoder, codecFixture().Body)
	if shortErr == nil {
		shortErr = shortEncoder.finish(false)
	}
	if !errors.Is(shortErr, errCanonTooLarge) {
		t.Fatalf("one-short meter must refuse, got %v", shortErr)
	}
}

func TestPackInstantNormalization(t *testing.T) {
	zone := time.FixedZone("plus-one", 3600)
	utcInstant := time.Date(2020, 5, 6, 7, 8, 9, 500000000, time.UTC)
	zonedInstant := time.Date(2020, 5, 6, 8, 8, 9, 500000000, zone)

	utcBody := minimalPackBody(utcInstant)
	zonedBody := minimalPackBody(zonedInstant)
	utcOutput, err := encodePackBody(utcBody)
	if err != nil {
		t.Fatalf("utc encode: %v", err)
	}
	zonedOutput, err := encodePackBody(zonedBody)
	if err != nil {
		t.Fatalf("zoned encode: %v", err)
	}
	if !bytes.Equal(utcOutput, zonedOutput) {
		t.Fatalf("equivalent producer instants wrote different bytes")
	}
	if !bytes.Contains(utcOutput, []byte(`"at":"2020-05-06T07:08:09.5Z"`)) {
		t.Fatalf("instant was not canonical Z with a short fraction: %s", utcOutput)
	}
	if bytes.Contains(utcOutput, []byte("+01:00")) || bytes.Contains(utcOutput, []byte(".500000000")) {
		t.Fatalf("instant retained offset or redundant fraction")
	}

	monotonic := time.Now()
	monotonicBody := minimalPackBody(monotonic)
	plainBody := minimalPackBody(monotonic.Round(0).UTC())
	monotonicOutput, err := encodePackBody(monotonicBody)
	if err != nil {
		t.Fatalf("monotonic encode: %v", err)
	}
	plainOutput, err := encodePackBody(plainBody)
	if err != nil {
		t.Fatalf("plain encode: %v", err)
	}
	if !bytes.Equal(monotonicOutput, plainOutput) {
		t.Fatalf("monotonic and plain instants wrote different bytes")
	}

	invalid := []struct {
		name  string
		value time.Time
	}{
		{"zero", time.Time{}},
		{"pre2019", time.Date(2018, 12, 31, 23, 59, 59, 0, time.UTC)},
		{"unrepresentable", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, testCase := range invalid {
		t.Run(testCase.name, func(t *testing.T) {
			output, err := encodePackBody(minimalPackBody(testCase.value))
			if !errors.Is(err, errCanonInvalid) {
				t.Fatalf("want errCanonInvalid, got %v", err)
			}
			if output != nil {
				t.Fatalf("want nil bytes on error")
			}
		})
	}
}

func assertBodyRefused(t *testing.T, body packBody, secret string) error {
	t.Helper()
	output, err := encodePackBody(body)
	if err == nil {
		t.Fatalf("want refusal, got %d bytes", len(output))
	}
	if output != nil {
		t.Fatalf("want nil bytes on error, got %d", len(output))
	}
	if secret != "" && strings.Contains(err.Error(), secret) {
		t.Fatalf("error contains supplied text")
	}
	return err
}

func TestPackWriterSafety(t *testing.T) {
	credential := "tskey" + "-auth-" + strings.Repeat("A", 12)
	if err := tripwire.Check([]byte(credential)); err == nil {
		t.Fatalf("synthetic concatenated credential shape was not recognized")
	}
	credentialBody := minimalPackBody(fxAcquired)
	credentialBody.Format = credential
	if err := assertBodyRefused(t, credentialBody, credential); !errors.Is(err, errCanonInvalid) {
		t.Fatalf("want errCanonInvalid for credential text, got %v", err)
	}

	textCases := []struct {
		name  string
		value string
	}{
		{"invalid utf8", string([]byte{0xff, 0xfe})},
		{"4097 bytes", strings.Repeat("a", 4097)},
		{"control", "a\x01b"},
	}
	for _, testCase := range textCases {
		t.Run(testCase.name, func(t *testing.T) {
			body := minimalPackBody(fxAcquired)
			body.Format = testCase.value
			if err := assertBodyRefused(t, body, testCase.value); !errors.Is(err, errCanonInvalid) {
				t.Fatalf("want errCanonInvalid, got %v", err)
			}
		})
	}

	negative := minimalPackBody(fxAcquired)
	negative.EvaluatorVersion = -1
	if err := assertBodyRefused(t, negative, ""); !errors.Is(err, errCanonInvalid) {
		t.Fatalf("want errCanonInvalid for negative integer, got %v", err)
	}

	noValue := minimalPackBody(fxAcquired)
	noValue.Intent = &packIntent{Network: []packNetwork{{ID: "n", Src: "s", SrcPostureAttrs: []packAttribute{{Name: "a"}}}}}
	if err := assertBodyRefused(t, noValue, ""); !errors.Is(err, errCanonInvalid) {
		t.Fatalf("want errCanonInvalid for zero posture values, got %v", err)
	}

	twoValues := minimalPackBody(fxAcquired)
	twoValues.Intent = &packIntent{Network: []packNetwork{{ID: "n", Src: "s", SrcPostureAttrs: []packAttribute{{Bool: ptrBool(true), Number: ptrString("1"), Name: "a"}}}}}
	if err := assertBodyRefused(t, twoValues, ""); !errors.Is(err, errCanonInvalid) {
		t.Fatalf("want errCanonInvalid for two posture values, got %v", err)
	}

	catalogDuplicate := minimalPackBody(fxAcquired)
	catalogDuplicate.Catalog.Sources = []packSource{{Name: "a"}, {Name: "a"}}
	if err := assertBodyRefused(t, catalogDuplicate, ""); !errors.Is(err, errCanonInvalid) {
		t.Fatalf("want errCanonInvalid for duplicate catalog sources, got %v", err)
	}

	tooManyFacts := minimalPackBody(fxAcquired)
	tooManyFacts.Snapshot.Versions = make([]packVersion, 10001)
	for i := range tooManyFacts.Snapshot.Versions {
		tooManyFacts.Snapshot.Versions[i] = packVersion{Evidence: fixtureEvidence()}
	}
	if err := assertBodyRefused(t, tooManyFacts, ""); !errors.Is(err, errCanonInvalid) {
		t.Fatalf("want errCanonInvalid for too many facts, got %v", err)
	}

	tooManyRules := minimalPackBody(fxAcquired)
	tooManyRules.Access = &packAccess{Selected: []string{"x"}, Candidates: []packCandidate{{Expectation: "e", Rules: make([]packRule, 9)}}}
	if err := assertBodyRefused(t, tooManyRules, ""); !errors.Is(err, errCanonInvalid) {
		t.Fatalf("want errCanonInvalid for too many rules, got %v", err)
	}

	tooManyTags := minimalPackBody(fxAcquired)
	tooManyTags.Access = &packAccess{Selected: []string{"x"}, Owners: []packOwner{{Source: "o", Tags: []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}}}}
	if err := assertBodyRefused(t, tooManyTags, ""); !errors.Is(err, errCanonInvalid) {
		t.Fatalf("want errCanonInvalid for too many owner tags, got %v", err)
	}
}

type failNthWriter struct {
	calls  int
	failAt int
}

var errInjectedWrite = errors.New("injected write failure")

func (w *failNthWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		return 0, errInjectedWrite
	}
	return len(p), nil
}

// Every actual writer call in the full fixture can fail. This exercises error
// propagation at nested keys, values, arrays and object boundaries.
func TestPackWriterPropagatesFailures(t *testing.T) {
	fixture := codecFixture()
	counter := &failNthWriter{}
	if err := writePackBody(newCanonEncoder(counter, MaxPackBytes), fixture.Body); err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= counter.calls; n++ {
		w := &failNthWriter{failAt: n}
		err := writePackBody(newCanonEncoder(w, MaxPackBytes), fixture.Body)
		if !errors.Is(err, errInjectedWrite) {
			t.Fatalf("write %d of %d: expected injected error, got %v", n, counter.calls, err)
		}
	}
}

// This explicit manifest makes additions to the typed schema visible to reviewers.
func TestPackWireFieldManifest(t *testing.T) {
	manifest := map[reflect.Type]string{
		reflect.TypeOf(packEnvelope{}):       "Body Integrity Seal",
		reflect.TypeOf(packBody{}):           "Access Catalog CatalogSchemaVersion Collected Evaluation EvaluatorVersion Expected Format Intent PackSchemaVersion ReportSchemaVersion Snapshot",
		reflect.TypeOf(packCatalog{}):        "Digest Sources",
		reflect.TypeOf(packSource{}):         "Data Name SHA256",
		reflect.TypeOf(packEvaluation{}):     "At WorkBudget",
		reflect.TypeOf(packExpected{}):       "Access Counts Report",
		reflect.TypeOf(packExpectedCounts{}): "Devices Features Platforms Policies Versions",
		reflect.TypeOf(packExpectedReport{}): "Affected NotAffected PotentiallyAffected SHA256 Status TotalFindings Unknown",
		reflect.TypeOf(packExpectedAccess{}): "Met MetWithLimits NotEvaluated SHA256 Status Total Unknown Unmet",
		reflect.TypeOf(packSnapshot{}):       "Context Features KeyEpoch ObservedAt Platforms Policies Scope Versions",
		reflect.TypeOf(packVersion{}):        "Channel Evidence Name Role Value",
		reflect.TypeOf(packPlatform{}):       "Evidence OS Variant",
		reflect.TypeOf(packFeature{}):        "Evidence Name Value",
		reflect.TypeOf(packPolicy{}):         "Evidence Name Value",
		reflect.TypeOf(packEvidence{}):       "AcquiredAt Asset Context Error Freshness ObservedAt Origin Scope",
		reflect.TypeOf(packCoverage{}):       "Context Counts Explanation Source Status Target",
		reflect.TypeOf(packCoverageTarget{}): "Asset Dimension Scope",
		reflect.TypeOf(packCoverageCounts{}): "Assets Findings Potential Rules Unknown Withdrawn",
		reflect.TypeOf(packToken{}):          "Form Value",
		reflect.TypeOf(packIntent{}):         "Digest Network Revision SchemaVersion SSH",
		reflect.TypeOf(packNetwork{}):        "Accept Deny ID Proto Src SrcPostureAttrs",
		reflect.TypeOf(packSSH{}):            "Accept Check Deny Dst ID Src",
		reflect.TypeOf(packAttribute{}):      "Bool Name Number String",
		reflect.TypeOf(packAccess{}):         "Candidates Context EvaluatedAt Limit Limits Owners PolicyVersion RulesPartial Selected Witnesses",
		reflect.TypeOf(packWitness{}):        "Cell Expectation Observed Proof Reason",
		reflect.TypeOf(packCell{}):           "Destination Expect User",
		reflect.TypeOf(packProof{}):          "Canary LiveUnchanged",
		reflect.TypeOf(packCandidate{}):      "Expectation Omitted Rules",
		reflect.TypeOf(packLimits{}):         "Expectation Limits",
		reflect.TypeOf(packOwner{}):          "Omitted Source Tags",
		reflect.TypeOf(packRule{}):           "AllTraffic Broad Column Destination Index Line Ports Qualified Section Source Traffic",
	}
	for typ, fields := range manifest {
		want := strings.Fields(fields)
		if typ.NumField() != len(want) {
			t.Errorf("%s: got %d fields, manifest has %d", typ.Name(), typ.NumField(), len(want))
			continue
		}
		for i, name := range want {
			f := typ.Field(i)
			if f.Name != name || f.PkgPath != "" || f.Tag.Get("json") == "" {
				t.Errorf("%s field %d is not mapped as %s", typ.Name(), i, name)
			}
		}
	}
}

func FuzzPackWriter(f *testing.F) {
	f.Add("neutral", true)
	f.Add("quote\"slash\\é", false)
	f.Fuzz(func(t *testing.T, value string, withEnvelope bool) {
		if len(value) > 1024 {
			return
		}
		body := minimalPackBody(fxAcquired)
		body.Format = value
		var out []byte
		var err error
		if withEnvelope {
			out, err = encodePackEnvelope(packEnvelope{Body: body, Integrity: "fixed"})
		} else {
			out, err = encodePackBody(body)
		}
		if err != nil {
			if out != nil {
				t.Fatal("a refused write returned bytes")
			}
			return
		}
		if len(out) > MaxPackBytes || !utf8.Valid(out) || !json.Valid(out) {
			t.Fatal("accepted output was invalid or exceeded the budget")
		}
		if bytes.HasSuffix(out, []byte("\n")) != withEnvelope {
			t.Fatal("wrong document newline")
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(out, &object); err != nil {
			t.Fatal("accepted output is not a JSON object")
		}
		if withEnvelope {
			if len(object) != 2 || object["body"] == nil || object["integrity"] == nil {
				t.Fatal("wrong envelope shape")
			}
		} else if object["format"] == nil || object["snapshot"] == nil {
			t.Fatal("wrong body shape")
		}
	})
}

// Compare every field of the fixture with its own decoded object, including
// omission and pointer presence. This tests mappings rather than only tags.
func assertWireMapping(t *testing.T, value reflect.Value, raw json.RawMessage) {
	t.Helper()
	if value.Kind() == reflect.Pointer {
		assertWireMapping(t, value.Elem(), raw)
		return
	}
	if value.Type() == reflect.TypeOf(time.Time{}) {
		var decoded time.Time
		if err := json.Unmarshal(raw, &decoded); err != nil || !decoded.Equal(value.Interface().(time.Time)) {
			t.Fatal("instant did not round trip")
		}
		return
	}
	switch value.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < value.NumField(); i++ {
			field := value.Type().Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")
			child := value.Field(i)
			omit := len(tag) > 1 && tag[1] == "omitempty" && wireEmpty(child)
			entry, present := object[tag[0]]
			if present == omit {
				t.Fatalf("%s.%s: incorrect presence", value.Type().Name(), field.Name)
			}
			if present {
				assertWireMapping(t, child, entry)
				delete(object, tag[0])
			}
		}
		if len(object) != 0 {
			t.Fatalf("%s: unmapped keys", value.Type().Name())
		}
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			var decoded []byte
			if err := json.Unmarshal(raw, &decoded); err != nil || !bytes.Equal(decoded, value.Bytes()) {
				t.Fatal("binary value mismatch")
			}
			return
		}
		var entries []json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil || len(entries) != value.Len() {
			t.Fatal("array mapping mismatch")
		}
		for i := range entries {
			assertWireMapping(t, value.Index(i), entries[i])
		}
	case reflect.String:
		var decoded string
		if err := json.Unmarshal(raw, &decoded); err != nil || decoded != value.String() {
			t.Fatal("string mapping mismatch")
		}
	case reflect.Int:
		var decoded int64
		if err := json.Unmarshal(raw, &decoded); err != nil || decoded != value.Int() {
			t.Fatal("integer mapping mismatch")
		}
	case reflect.Bool:
		var decoded bool
		if err := json.Unmarshal(raw, &decoded); err != nil || decoded != value.Bool() {
			t.Fatal("boolean mapping mismatch")
		}
	default:
		t.Fatalf("unsupported field kind %s", value.Kind())
	}
}

func wireEmpty(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return value.Len() == 0
	default:
		return value.IsZero()
	}
}

// Exercise zero and nonzero numeric/boolean values across every populated wire
// object. In particular this checks optional omission and required false/zero
// alongside their nonzero/true counterparts without changing schema tags.
func setWireScalars(value reflect.Value, nonzero bool) {
	if value.Kind() == reflect.Pointer {
		if !value.IsNil() {
			setWireScalars(value.Elem(), nonzero)
		}
		return
	}
	if value.Type() == reflect.TypeOf(time.Time{}) {
		return
	}
	switch value.Kind() {
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			setWireScalars(value.Field(i), nonzero)
		}
	case reflect.Slice:
		if value.Type().Elem().Kind() != reflect.Uint8 {
			for i := 0; i < value.Len(); i++ {
				setWireScalars(value.Index(i), nonzero)
			}
		}
	case reflect.Bool:
		value.SetBool(nonzero)
	case reflect.Int:
		if nonzero {
			value.SetInt(7)
		} else {
			value.SetInt(0)
		}
	}
}

func TestPackWireMappings(t *testing.T) {
	zero, nonzero := codecFixture(), codecFixture()
	setWireScalars(reflect.ValueOf(&zero).Elem(), false)
	setWireScalars(reflect.ValueOf(&nonzero).Elem(), true)
	for _, envelope := range []packEnvelope{codecFixture(), zero, nonzero, {Body: minimalPackBody(fxAcquired)}} {
		out, err := encodePackEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		assertWireMapping(t, reflect.ValueOf(envelope), out)
	}
}

func TestPackExactOutputByteLimit(t *testing.T) {
	body := minimalPackBody(fxAcquired)
	attributes := make([]packAttribute, 4100)
	for i := range attributes {
		attributes[i] = packAttribute{Name: fmt.Sprintf("a%05d", i), String: ptrString("")}
	}
	body.Intent = &packIntent{Network: []packNetwork{{ID: "network", Src: "source", SrcPostureAttrs: attributes}}}
	baseline, err := encodePackBody(body)
	if err != nil {
		t.Fatal(err)
	}
	remaining := MaxPackBytes - len(baseline)
	for i := range attributes {
		n := min(remaining, 4096)
		*attributes[i].String = strings.Repeat("x", n)
		remaining -= n
	}
	if remaining != 0 {
		t.Fatal("fixture cannot reach the output limit")
	}
	out, err := encodePackBody(body)
	if err != nil || len(out) != MaxPackBytes {
		t.Fatalf("exact limit: bytes=%d err=%v", len(out), err)
	}
	for i := range attributes {
		if len(*attributes[i].String) < 4096 {
			*attributes[i].String += "x"
			break
		}
	}
	out, err = encodePackBody(body)
	if !errors.Is(err, errCanonTooLarge) || out != nil {
		t.Fatalf("over limit: bytes=%d err=%v", len(out), err)
	}
}

type packCountingWriter struct {
	bytes  int
	writes int
}

func (w *packCountingWriter) Write(p []byte) (int, error) {
	w.bytes += len(p)
	w.writes++
	return len(p), nil
}

func TestPackPreflightBeforeWriting(t *testing.T) {
	base := minimalPackBody(fxAcquired)
	testCases := []struct {
		name   string
		change func(*packBody)
	}{
		{"source count", func(body *packBody) { body.Catalog.Sources = make([]packSource, 65) }},
		{"source bytes", func(body *packBody) {
			body.Catalog.Sources = []packSource{{Data: make([]byte, 2<<20)}, {Data: make([]byte, (2<<20)+1)}}
		}},
		{"fact sum", func(body *packBody) {
			body.Snapshot.Features = make([]packFeature, 9999)
			body.Snapshot.Policies = make([]packPolicy, 2)
		}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body := base
			tc.change(&body)
			w := &packCountingWriter{}
			err := writePackBody(newCanonEncoder(w, MaxPackBytes), body)
			if !errors.Is(err, errCanonInvalid) || w.writes != 0 || w.bytes != 0 {
				t.Fatalf("preflight: err=%v writes=%d bytes=%d", err, w.writes, w.bytes)
			}
			out, err := encodePackBody(body)
			if !errors.Is(err, errCanonInvalid) || out != nil {
				t.Fatalf("body: err=%v bytes=%d", err, len(out))
			}
			out, err = encodePackEnvelope(packEnvelope{Body: body})
			if !errors.Is(err, errCanonInvalid) || out != nil {
				t.Fatalf("envelope: err=%v bytes=%d", err, len(out))
			}
		})
	}
	w := &packCountingWriter{}
	if err := writePackBody(newCanonEncoder(w, MaxPackBytes), base); err != nil || w.bytes == 0 {
		t.Fatalf("positive control: err=%v bytes=%d", err, w.bytes)
	}
}
