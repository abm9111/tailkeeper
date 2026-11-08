package securitypack

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPackSealBoundary(t *testing.T) {
	envelope := codecFixture()
	body, err := encodePackBody(envelope.Body)
	if err != nil {
		t.Fatal(err)
	}
	preimage := append([]byte("tailkeeper-evidence-pack/1\n"), body...)
	digest := sha256.Sum256(preimage)
	envelope.Integrity = fmt.Sprintf("sha256:%x", digest)
	envelope.Seal = nil
	calls := 0
	valid := "hmac-sha256:" + strings.Repeat("a", 64)
	seal := func(input []byte) string {
		calls++
		if !bytes.Equal(input, preimage) {
			t.Error("incorrect sealer input")
		}
		return valid
	}
	for _, tc := range []struct {
		name     string
		callback Sealer
		want     SealState
	}{
		{"absent", nil, SealAbsent}, {"absent with key", seal, SealAbsentKeyLoaded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reading, err := checkPackIntegrityAndSeal(envelope, tc.callback)
			if err != nil || reading.Seal != tc.want {
				t.Fatalf("reading = %+v, error = %v", reading, err)
			}
		})
	}
	if calls != 0 {
		t.Fatal("sealer called with absent seal")
	}
	envelope.Seal = &valid
	if reading, err := checkPackIntegrityAndSeal(envelope, nil); err != nil || reading.Seal != SealNotChecked {
		t.Fatalf("unchecked: %+v, %v", reading, err)
	}
	if reading, err := checkPackIntegrityAndSeal(envelope, seal); err != nil || reading.Seal != SealValid || calls != 1 {
		t.Fatalf("valid: %+v, %v", reading, err)
	}
	wrong := func([]byte) string { return "hmac-sha256:" + strings.Repeat("b", 64) }
	if _, err := checkPackIntegrityAndSeal(envelope, wrong); !errors.Is(err, ErrSealMismatch) {
		t.Fatalf("wrong seal: %v", err)
	}
	badShape := func([]byte) string { return "not-a-seal" }
	if _, err := checkPackIntegrityAndSeal(envelope, badShape); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("invalid callback: %v", err)
	}
	envelope.Integrity = "sha256:" + strings.Repeat("b", 64)
	if _, err := checkPackIntegrityAndSeal(envelope, wrong); !errors.Is(err, ErrIntegrityMismatch) {
		t.Fatalf("checksum precedence: %v", err)
	}
}
