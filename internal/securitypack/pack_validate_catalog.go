package securitypack

import (
	"crypto/sha256"
	"fmt"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// checkPackText never includes the supplied text in a returned error.
func checkPackText(value string) error {
	if err := tripwire.Check([]byte(value)); err != nil {
		return ErrSecretShaped
	}
	if !security.ValidText(value) {
		return ErrInvalidPack
	}
	return nil
}

func lowerHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validPackSourceName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func checkCatalogRecord(record security.AdvisoryRecord) error {
	values := []string{record.ID, record.Revision, record.Component, string(record.VersionRole), record.OS,
		record.Source, string(record.Severity), string(record.ReviewState), record.Mitigation}
	values = append(values, record.RequiredFeatures...)
	for _, r := range record.Ranges {
		values = append(values, r.Introduced, r.Fixed)
	}
	for _, value := range values {
		if err := checkPackText(value); err != nil {
			return err
		}
	}
	return nil
}

// checkPackCatalog validates exact source bytes and scans decoded text, which
// catches credential shapes concealed by JSON escapes in the source bytes.
func checkPackCatalog(catalog packCatalog) error {
	if !lowerHex64(catalog.Digest) || len(catalog.Sources) > maxCatalogSources {
		return ErrInvalidPack
	}
	if !packCatalogBytesWithinLimit(catalog.Sources) {
		return ErrTooLarge
	}
	previous, records := "", 0
	for _, source := range catalog.Sources {
		if err := checkPackCatalogSource(source, previous, &records); err != nil {
			return err
		}
		previous = source.Name
	}
	return nil
}

func checkPackCatalogSource(source packSource, previous string, records *int) error {
	if err := checkPackText(source.Name); err != nil {
		return err
	}
	if !validPackSourceName(source.Name) || source.Name <= previous || !lowerHex64(source.SHA256) {
		return ErrInvalidPack
	}
	digest := sha256.Sum256(source.Data)
	if fmt.Sprintf("%x", digest) != source.SHA256 {
		return ErrInvalidPack
	}
	catalog, err := advisory.Decode(source.Data)
	if err != nil {
		return ErrInvalidPack
	}
	if err := checkPackText(catalog.Digest); err != nil {
		return err
	}
	if len(catalog.Records) > security.MaxCatalogRecords-*records {
		return ErrInvalidPack
	}
	*records += len(catalog.Records)
	for _, record := range catalog.Records {
		if err := checkCatalogRecord(record); err != nil {
			return err
		}
	}
	return nil
}
