package securitypack

import (
	"errors"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/security"
)

func TestPackProducerRejectsContradictions(t *testing.T) {
	tests := []struct {
		name   string
		change func(*packInput)
	}{
		{"version", func(in *packInput) { in.EvaluatorVersion = 0 }},
		{"intent form without digest", func(in *packInput) { in.IntentDigestForm = "plain" }},
		{"access without intent", func(in *packInput) { in.Access = &accessInput{Selected: []string{"network-1"}} }},
		{"too many sources", func(in *packInput) { in.Sources = make([]advisory.Source, 65) }},
		{"too many coverage rows", func(in *packInput) { in.Collected = make([]security.Coverage, 3) }},
		{"too many facts", func(in *packInput) { in.Snapshot.Features = make([]security.FeatureFact, security.MaxObservations+1) }},
		{"too many witnesses", func(in *packInput) {
			in.Access = &accessInput{Input: security.AccessInput{Witnesses: make([]security.AccessWitness, 65)}}
		}},
		{"secret shape", func(in *packInput) { in.Snapshot.KeyEpoch = "ts" + "key-" + "api-" }},
	}
	if _, err := newPack(validPackInput(), nil); err != nil {
		t.Fatal("valid producer control failed")
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := validPackInput()
			tc.change(&in)
			if _, err := newPack(in, nil); err == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
	if _, err := newPack(validPackInput(), func([]byte) string { return "bad" }); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("bad callback: %v", err)
	}
	if _, err := packInputOf(EvidencePack{}); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("zero input: %v", err)
	}
}

func TestPackConversionRejectsContradictions(t *testing.T) {
	if _, err := sourcesToPack([]advisory.Source{{Name: "x", Data: make([]byte, maxCatalogBytes+1)}}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("source cap: %v", err)
	}
	if _, err := sourcesToPack([]advisory.Source{{Name: "z"}, {Name: "a"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := intentToPack(nil, "plain"); err == nil {
		t.Fatal("form without intent")
	}
	if _, err := intentToPack(&security.IntentSet{SchemaVersion: 1}, "plain"); err == nil {
		t.Fatal("form without digest")
	}
	for _, scalar := range []security.Scalar{{Kind: "unknown"}, {Kind: security.ScalarString, Bool: true}, {Kind: security.ScalarBool, Number: "1"}, {Kind: security.ScalarNumber, Number: "invalid"}, {Kind: security.ScalarNumber, Number: "1", Bool: true}} {
		if _, err := attributeToPack("attr", scalar); err == nil {
			t.Fatal("bad scalar accepted")
		}
	}
	if _, err := attributeFromPack(packAttribute{}); err == nil {
		t.Fatal("missing scalar accepted")
	}
	number := "nan"
	if _, err := attributeFromPack(packAttribute{Number: &number}); err == nil {
		t.Fatal("bad numeric scalar accepted")
	}
	if _, err := networkFromPack(packNetwork{SrcPostureAttrs: []packAttribute{{Name: "z"}, {Name: "a"}}}); err == nil {
		t.Fatal("bad attributes accepted")
	}
	if _, err := selectPackIntent(nil, []string{"network-1"}); err == nil {
		t.Fatal("missing intent accepted")
	}
	intent := security.IntentSet{SchemaVersion: 1, Network: []security.NetworkExpectation{{ID: "network-1"}}}
	for _, selected := range [][]string{{"network-1", "network-1"}, {"missing"}, nil} {
		if _, err := selectPackIntent(&intent, selected); err == nil {
			t.Fatal("bad selection accepted")
		}
	}
	if _, err := accessToPack(&accessInput{Selected: []string{"network-1"}, Input: security.AccessInput{NoIntent: true}}, &intent); err == nil {
		t.Fatal("contradictory NoIntent accepted")
	}
}

func TestPackCatalogShapes(t *testing.T) {
	for _, name := range []string{"", "UPPER", "wrong/name", strings.Repeat("a", 129)} {
		if validPackSourceName(name) {
			t.Fatal("bad name accepted")
		}
	}
	for _, digest := range []string{"", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if lowerHex64(digest) {
			t.Fatal("bad digest accepted")
		}
	}
	source := syntheticSource("ordinary")
	catalog := packCatalog{Digest: strings.Repeat("a", 64), Sources: []packSource{source}}
	if err := checkPackCatalog(catalog); err != nil {
		t.Fatal(err)
	}
	catalog.Sources = append(catalog.Sources, source)
	if err := checkPackCatalog(catalog); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("duplicate source: %v", err)
	}
	catalog.Sources = []packSource{{Name: "synthetic", Data: []byte("bad"), SHA256: strings.Repeat("a", 64)}}
	if err := checkPackCatalog(catalog); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("bad digest: %v", err)
	}
}

func TestPackRecordedStateRefusesCorruption(t *testing.T) {
	pack, err := newPack(validPackInput(), nil)
	if err != nil {
		t.Fatal(err)
	}
	pack.envelope.Integrity = "sha256:" + strings.Repeat("f", 64)
	if _, err := Encode(pack); !errors.Is(err, ErrIntegrityMismatch) {
		t.Fatalf("bad integrity: %v", err)
	}
	if _, err := packInputOf(pack); !errors.Is(err, ErrIntegrityMismatch) {
		t.Fatalf("bad reconstruction: %v", err)
	}
	pack.envelope.Body.Format = "other"
	if _, err := Encode(pack); !errors.Is(err, ErrNotAPack) {
		t.Fatalf("bad format: %v", err)
	}
}

func TestPackExpectedAccessCounts(t *testing.T) {
	valid := packExpectedAccess{SHA256: strings.Repeat("a", 64), Status: "complete", Total: 1, Met: 1}
	if err := checkPackExpectedAccess(&valid); err != nil {
		t.Fatal(err)
	}
	for _, value := range []packExpectedAccess{{SHA256: "bad", Status: "complete"}, {SHA256: strings.Repeat("a", 64), Status: "invalid"}, {SHA256: strings.Repeat("a", 64), Status: "complete"}, {SHA256: strings.Repeat("a", 64), Status: "incomplete", Total: 1}, {SHA256: strings.Repeat("a", 64), Status: "complete", Total: 1, Unknown: 1}} {
		if err := checkPackExpectedAccess(&value); !errors.Is(err, ErrInvalidPack) {
			t.Fatalf("bad access summary: %v", err)
		}
	}
}

func TestPackSealAndTextErrorsAreSanitized(t *testing.T) {
	pack, err := newPack(validPackInput(), nil)
	if err != nil {
		t.Fatal(err)
	}
	shape := "ts" + "key-" + "api-"
	pack.envelope.Body.Snapshot.KeyEpoch = shape
	if _, err := Encode(pack); !errors.Is(err, ErrSecretShaped) || strings.Contains(err.Error(), shape) {
		t.Fatalf("secret-shaped error: %v", err)
	}
	pack, err = newPack(validPackInput(), nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := "bad-seal"
	pack.envelope.Seal = &bad
	if _, err := Encode(pack); !errors.Is(err, ErrInvalidPack) || strings.Contains(err.Error(), bad) {
		t.Fatalf("malformed seal error: %v", err)
	}
}
