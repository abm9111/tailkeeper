package securitypack

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

// The writer refuses text the schema forbids, and checkedPackBytes reports that refusal as
// an invalid pack rather than writing a partial envelope.
func TestCheckedPackBytesMapsWriterRefusalsToInvalidPack(t *testing.T) {
	pack, err := newPack(validPackInput(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkedPackBytes(pack.envelope); err != nil {
		t.Fatalf("control: %v", err)
	}
	bad := "\xff"
	for _, tc := range []struct {
		name   string
		change func(*packEnvelope)
	}{
		{"integrity", func(e *packEnvelope) { e.Integrity = bad }},
		{"seal", func(e *packEnvelope) { e.Seal = &bad }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envelope := pack.envelope
			tc.change(&envelope)
			if _, err := encodePackEnvelope(envelope); !errors.Is(err, errCanonInvalid) {
				t.Fatalf("writer accepted the text: %v", err)
			}
			if got, err := checkedPackBytes(envelope); !errors.Is(err, ErrInvalidPack) || got != nil {
				t.Fatalf("got %q %v", got, err)
			}
		})
	}
}

func TestDecodeRefusesOversizedCatalogAndSecretShapedLeaves(t *testing.T) {
	in := validPackInput()
	shape := "ts" + "key-" + "api-"
	in.Snapshot.KeyEpoch = strings.Repeat("a", len(shape))
	pack, err := newPack(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := Encode(pack)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(wire, nil); err != nil {
		t.Fatalf("control: %v", err)
	}
	marker := []byte(`"key_epoch":"` + in.Snapshot.KeyEpoch + `"`)
	if !bytes.Contains(wire, marker) {
		t.Fatal("fixture marker missing")
	}
	shaped := bytes.Replace(wire, marker, []byte(`"key_epoch":"`+shape+`"`), 1)
	_, _, err = Decode(shaped, nil)
	if !errors.Is(err, ErrSecretShaped) || strings.Contains(err.Error(), shape) {
		t.Fatalf("secret-shaped leaf: %v", err)
	}

	envelope := pack.envelope
	envelope.Body.Catalog.Sources = []packSource{{Name: "big", Data: make([]byte, maxCatalogBytes+1), SHA256: strings.Repeat("0", 64)}}
	big, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(big, nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized catalog: %v", err)
	}
	if !packCatalogBytesWithinLimit(pack.envelope.Body.Catalog.Sources) || packCatalogBytesWithinLimit(envelope.Body.Catalog.Sources) {
		t.Fatal("limit predicate disagrees with the decoder")
	}
}

func TestPackTokenFormsAcceptKeyedDigests(t *testing.T) {
	digest := strings.Repeat("0123456789abcdef", 4)
	keyed := &packToken{Form: "keyed", Value: "hmac-sha256:" + digest}
	if !validIntentToken(keyed, digest[:12]) || validIntentToken(keyed, digest[1:13]) {
		t.Fatal("keyed intent digest must bind its revision")
	}
	if validIntentToken(&packToken{Form: "keyed", Value: "sha256:" + digest}, digest[:12]) {
		t.Fatal("keyed form accepted a plain prefix")
	}
	if validIntentToken(&packToken{Form: "other", Value: "hmac-sha256:" + digest}, digest[:12]) || !validIntentToken(nil, "") || validIntentToken(nil, "x") {
		t.Fatal("unknown form or absent digest handled wrongly")
	}
	if !validPolicyToken(keyed) || !validPolicyToken(nil) {
		t.Fatal("keyed policy token refused")
	}
	if validPolicyToken(&packToken{Form: "keyed", Value: "sha256:" + digest}) || validPolicyToken(&packToken{Form: "other", Value: keyed.Value}) {
		t.Fatal("wrong prefix or unknown form accepted")
	}
}

func TestPackEvidenceTimesMustBeUTC(t *testing.T) {
	snapshot := packSnapshot{Context: "ctx-local-only", Scope: "local"}
	at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	evidence := packEvidence{Context: snapshot.Context, Scope: snapshot.Scope, AcquiredAt: at, ObservedAt: &at}
	if !validPackEvidence(evidence, snapshot) {
		t.Fatal("control evidence")
	}
	local := at.In(time.FixedZone("offset", 3600))
	evidence.ObservedAt = &local
	if validPackEvidence(evidence, snapshot) {
		t.Fatal("observation time with a zone offset accepted")
	}
	evidence.ObservedAt = nil
	if !validPackEvidence(evidence, snapshot) {
		t.Fatal("evidence without an observation time refused")
	}
}

func TestPackTextAndCatalogChecksNameTheirRefusal(t *testing.T) {
	shape := "ts" + "key-" + "api-"
	for _, tc := range []struct {
		value string
		want  error
	}{{"plain text", nil}, {"\xff", ErrInvalidPack}, {"bad\x00text", ErrInvalidPack}, {shape, ErrSecretShaped}} {
		err := checkPackText(tc.value)
		if !errors.Is(err, tc.want) && !(tc.want == nil && err == nil) {
			t.Errorf("%q: got %v want %v", tc.value, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), tc.value) {
			t.Errorf("error repeats the refused text: %v", err)
		}
	}
	oversized := packCatalog{Digest: strings.Repeat("a", 64), Sources: []packSource{{Name: "big", Data: make([]byte, maxCatalogBytes+1)}}}
	if err := checkPackCatalog(oversized); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized catalog: %v", err)
	}
	source := syntheticSource("ordinary")
	if err := checkPackCatalogSource(source, "", new(int)); err != nil {
		t.Fatalf("control: %v", err)
	}
	source.Name = shape
	if err := checkPackCatalogSource(source, "", new(int)); !errors.Is(err, ErrSecretShaped) {
		t.Fatalf("secret-shaped source name: %v", err)
	}
}

func TestCheckPackAccessRefusesUnorderedMaps(t *testing.T) {
	full, value := accessConversionFixture()
	value.Input.Candidates = map[string]security.AccessCandidates{"network-1": {}, "network-2": {}}
	packed, err := accessToPack(value, full)
	if err != nil {
		t.Fatal(err)
	}
	packed.Context = "ctx-0123456789abcdef"
	packed.EvaluatedAt = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	snapshot := packSnapshot{Context: packed.Context, Scope: "fleet"}
	if err := checkPackAccess(packed, snapshot, full); err != nil {
		t.Fatalf("control: %v", err)
	}
	packed.Candidates = []packCandidate{packed.Candidates[1], packed.Candidates[0]}
	if err := checkPackAccess(packed, snapshot, full); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("unordered candidates: %v", err)
	}
}

func TestReplayFreshnessAndReferenceRefuseWhatTheyCannotBind(t *testing.T) {
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	_, good, _ := built(t, replayFixture(t), nil)
	if f := ReplayFreshness(good, at); !f.Valid {
		t.Fatalf("control: %+v", f)
	}
	// This pack records a catalog digest that its embedded sources do not produce.
	unbound, err := newPack(validPackInput(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if f := ReplayFreshness(unbound, at); f != (Freshness{}) {
		t.Fatalf("unbound catalog digest: %+v", f)
	}
	if _, err := Reference(EvidencePack{}, nil, true); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("zero pack: %v", err)
	}
	// A pack whose body still encodes but whose integrity no longer matches gets no reference.
	tampered := good
	tampered.envelope.Integrity = "sha256:" + strings.Repeat("0", 64)
	if ref, err := Reference(tampered, nil, true); !errors.Is(err, ErrIntegrityMismatch) || ref != "" {
		t.Fatalf("tampered pack: %q %v", ref, err)
	}
	if ref, err := Reference(good, nil, true); err != nil || len(ref) != 12 {
		t.Fatalf("control: %q %v", ref, err)
	}
}
