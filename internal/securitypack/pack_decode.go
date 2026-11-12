package securitypack

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/guard"
)

var (
	ErrInvalidPack              = errors.New("invalid_pack")
	ErrUnsupportedPackSchema    = errors.New("unsupported_pack_schema")
	ErrUnsupportedReportSchema  = errors.New("unsupported_report_schema")
	ErrUnsupportedCatalogSchema = errors.New("unsupported_catalog_schema")
	ErrTooLarge                 = errors.New("too_large")
	ErrTooDeep                  = errors.New("too_deep")
	ErrTooManyValues            = errors.New("too_many_values")
	ErrNotCanonical             = errors.New("not_canonical")
	ErrSecretShaped             = errors.New("secret_shaped")
	ErrIntegrityMismatch        = errors.New("integrity_mismatch")
	ErrSealMismatch             = errors.New("seal_mismatch")
	ErrNotAPack                 = errors.New("not_a_pack")
	ErrProjectionNotReplayable  = errors.New("projection_not_replayable")
)

// preflightPack rejects unbounded input before the typed JSON decoder allocates.
func preflightPack(data []byte) error {
	if len(data) > MaxPackBytes {
		return ErrTooLarge
	}
	if !utf8.Valid(data) {
		return ErrInvalidPack
	}
	result := guard.Scan(data, maxCanonDepth)
	if result.TooDeep {
		return ErrTooDeep
	}
	if result.NodeBound > MaxPackNodes {
		return ErrTooManyValues
	}
	return nil
}

// readPackEnvelope is the syntax and canonical spelling boundary, not semantic
// validation. Callers must validate all fields and integrity before using it.
// encoding/json's []byte decoder allocates at most three quarters of the
// 16 MiB input for source data; the 4 MiB cumulative limit is then checked.
func readPackEnvelope(data []byte) (packEnvelope, error) {
	var envelope packEnvelope
	if err := preflightPack(data); err != nil {
		return envelope, err
	}
	if isPackProjection(data) {
		return envelope, ErrProjectionNotReplayable
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return packEnvelope{}, ErrInvalidPack
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return packEnvelope{}, ErrInvalidPack
	}
	if !packCatalogBytesWithinLimit(envelope.Body.Catalog.Sources) {
		return packEnvelope{}, ErrTooLarge
	}
	if err := checkPackTextLeaves(envelope); err != nil {
		return packEnvelope{}, err
	}
	canonical, err := encodePackEnvelope(envelope)
	if errors.Is(err, errCanonTooLarge) {
		return packEnvelope{}, ErrTooLarge
	}
	if err != nil {
		return packEnvelope{}, ErrInvalidPack
	}
	if !bytes.Equal(data, canonical) {
		return packEnvelope{}, ErrNotCanonical
	}
	return envelope, nil
}

func packCatalogBytesWithinLimit(sources []packSource) bool {
	total := 0
	for _, source := range sources {
		if len(source.Data) > maxCatalogBytes-total {
			return false
		}
		total += len(source.Data)
	}
	return true
}

// isPackProjection only recognizes the marker of one complete JSON object; it
// never treats projection fields as evidence or creates a replayable pack.
func isPackProjection(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var marker struct {
		Format string `json:"format"`
	}
	if err := decoder.Decode(&marker); err != nil {
		return false
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return false
	}
	return marker.Format == "tailkeeper-evidence-projection"
}
