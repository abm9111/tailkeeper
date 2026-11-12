package securitypack

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

// Sealer computes a keyed seal over the supplied domain-separated body.
// A nil Sealer means the caller has no key loaded.
type Sealer func([]byte) string

type SealState string

const (
	SealValid           SealState = "valid"
	SealNotChecked      SealState = "not_checked"
	SealAbsent          SealState = "absent"
	SealAbsentKeyLoaded SealState = "absent_key_loaded"
)

type Reading struct{ Seal SealState }

const packDomain = "tailkeeper-evidence-pack/1\n"

func validPrefixedDigest(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && lowerHex64(strings.TrimPrefix(value, prefix))
}

// packSealInput computes the exact domain-separated bytes shared by the
// integrity check and the caller-supplied sealer.
func packSealInput(body packBody) ([]byte, string, error) {
	encoded, err := encodePackBody(body)
	if errors.Is(err, errCanonTooLarge) {
		return nil, "", ErrTooLarge
	}
	if err != nil {
		return nil, "", ErrInvalidPack
	}
	input := make([]byte, 0, len(packDomain)+len(encoded))
	input = append(input, packDomain...)
	input = append(input, encoded...)
	digest := sha256.Sum256(input)
	return input, fmt.Sprintf("sha256:%x", digest), nil
}

func checkPackIntegrityAndSeal(envelope packEnvelope, seal Sealer) (Reading, error) {
	if !validPrefixedDigest(envelope.Integrity, "sha256:") {
		return Reading{}, ErrInvalidPack
	}
	if envelope.Seal != nil && !validPrefixedDigest(*envelope.Seal, "hmac-sha256:") {
		return Reading{}, ErrInvalidPack
	}
	input, expected, err := packSealInput(envelope.Body)
	if err != nil {
		return Reading{}, err
	}
	if expected != envelope.Integrity {
		return Reading{}, ErrIntegrityMismatch
	}
	if envelope.Seal == nil {
		if seal == nil {
			return Reading{Seal: SealAbsent}, nil
		}
		return Reading{Seal: SealAbsentKeyLoaded}, nil
	}
	if seal == nil {
		return Reading{Seal: SealNotChecked}, nil
	}
	actual := seal(input)
	if !validPrefixedDigest(actual, "hmac-sha256:") {
		return Reading{}, ErrInvalidPack
	}
	if actual != *envelope.Seal {
		return Reading{}, ErrSealMismatch
	}
	return Reading{Seal: SealValid}, nil
}
