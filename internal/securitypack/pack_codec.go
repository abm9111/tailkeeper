package securitypack

import (
	"errors"

	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

func checkPackBody(body packBody) error {
	if body.Format != "tailkeeper-evidence-pack" {
		return ErrNotAPack
	}
	if body.PackSchemaVersion != PackSchemaVersion {
		return ErrUnsupportedPackSchema
	}
	if body.ReportSchemaVersion != security.SchemaVersion {
		return ErrUnsupportedReportSchema
	}
	if body.CatalogSchemaVersion != 1 {
		return ErrUnsupportedCatalogSchema
	}
	if body.EvaluatorVersion < 0 || body.Evaluation.WorkBudget < 0 || body.Evaluation.WorkBudget > security.MaxCandidates {
		return ErrInvalidPack
	}
	if err := checkPackSnapshot(body.Snapshot, body.Evaluation.At); err != nil {
		return err
	}
	if err := checkPackExpected(body); err != nil {
		return err
	}
	if err := checkPackCoverage(body); err != nil {
		return err
	}
	if err := checkPackIntent(body.Intent); err != nil {
		return err
	}
	intent, _, err := intentFromPack(body.Intent)
	if err != nil {
		return err
	}
	if err := checkPackAccess(body.Access, body.Snapshot, intent); err != nil {
		return err
	}
	return checkPackCatalog(body.Catalog)
}

func checkPackEnvelope(envelope packEnvelope) error {
	if err := checkPackTextLeaves(envelope); err != nil {
		return err
	}
	return checkPackBody(envelope.Body)
}

func checkedPackBytes(envelope packEnvelope) ([]byte, error) {
	encoded, err := encodePackEnvelope(envelope)
	if errors.Is(err, errCanonTooLarge) {
		return nil, ErrTooLarge
	}
	if err != nil {
		return nil, ErrInvalidPack
	}
	if err := preflightPack(encoded); err != nil {
		return nil, err
	}
	if err := tripwire.Check(encoded); err != nil {
		return nil, ErrSecretShaped
	}
	return encoded, nil
}

// Encode preserves the recorded integrity and seal and never calls a sealer.
func Encode(pack EvidencePack) ([]byte, error) {
	if !pack.valid {
		return nil, ErrInvalidPack
	}
	if err := checkPackEnvelope(pack.envelope); err != nil {
		return nil, err
	}
	if _, err := checkPackIntegrityAndSeal(pack.envelope, nil); err != nil {
		return nil, err
	}
	return checkedPackBytes(pack.envelope)
}

// Decode validates a canonical evidence pack and reports the seal check state.
func Decode(data []byte, seal Sealer) (EvidencePack, Reading, error) {
	envelope, err := readPackEnvelope(data)
	if err != nil {
		return EvidencePack{}, Reading{}, err
	}
	if err := tripwire.Check(data); err != nil {
		return EvidencePack{}, Reading{}, ErrSecretShaped
	}
	if err := checkPackEnvelope(envelope); err != nil {
		return EvidencePack{}, Reading{}, err
	}
	reading, err := checkPackIntegrityAndSeal(envelope, seal)
	if err != nil {
		return EvidencePack{}, Reading{}, err
	}
	return EvidencePack{envelope: envelope, reading: reading, valid: true}, reading, nil
}

func newPack(in packInput, seal Sealer) (EvidencePack, error) {
	body, err := bodyFromInput(in)
	if err != nil {
		return EvidencePack{}, err
	}
	envelope := packEnvelope{Body: body}
	// Check all text leaves before schema checks or the writer so a credential
	// shape is reported consistently even when the containing field is invalid.
	if err := checkPackTextLeaves(envelope); err != nil {
		return EvidencePack{}, err
	}
	if err := checkPackBody(body); err != nil {
		return EvidencePack{}, err
	}
	input, integrity, err := packSealInput(body)
	if err != nil {
		return EvidencePack{}, err
	}
	envelope.Integrity = integrity
	reading := Reading{Seal: SealAbsent}
	if seal != nil {
		value := seal(input)
		if !validPrefixedDigest(value, "hmac-sha256:") {
			return EvidencePack{}, ErrInvalidPack
		}
		envelope.Seal = &value
		reading.Seal = SealValid
	}
	out := EvidencePack{envelope: envelope, reading: reading, valid: true}
	if _, err := Encode(out); err != nil {
		return EvidencePack{}, err
	}
	return out, nil
}

func packInputOf(pack EvidencePack) (packInput, error) {
	if !pack.valid {
		return packInput{}, ErrInvalidPack
	}
	if _, err := Encode(pack); err != nil {
		return packInput{}, err
	}
	return bodyToInput(pack.envelope.Body)
}
