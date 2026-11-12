// Package advisory decodes untrusted catalog data; authenticity is a separate boundary.
package advisory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/security"
)

const (
	maxBytes = 4 << 20
	maxDepth = 32
)

// Decode reads a catalog in one streaming pass and validates it. The input is refused when
// it is over 4 MiB, is not valid UTF-8 or nests deeper than 32 levels; then every object
// must carry exactly the schema's keys (spelled exactly, once each, never null, none
// unknown) and every value its schema type. The records array, each ranges array and each
// required_features array are read element by element and refused at the first element
// past their bound (security.MaxCatalogRecords, security.MaxRanges), before that element
// is read, so a hostile input costs memory in proportion to the bound and not to its size.
//
// Any error returns the zero Catalog, never a part-filled one. On success the Digest field
// holds the SHA-256 of the exact input bytes in lowercase hex. That digest is not a content
// identity (the same catalog spelled with other white space has another one) and it does
// not authenticate the input: signature, rollback and freshness checks belong to the import
// boundary, not here.
func Decode(data []byte) (security.Catalog, error) {
	c, err := decode(data)
	if err != nil {
		return security.Catalog{}, err
	}
	return c, nil
}

func decode(data []byte) (security.Catalog, error) {
	var c security.Catalog
	switch {
	case len(data) > maxBytes:
		return c, fmt.Errorf("catalog is larger than %d bytes", maxBytes)
	case !utf8.Valid(data):
		return c, errors.New("catalog is not valid UTF-8")
	case guard.NestsDeeperThan(data, maxDepth):
		return c, fmt.Errorf("catalog nests deeper than %d levels", maxDepth)
	}
	r := reader{d: json.NewDecoder(bytes.NewReader(data))}
	if err := r.catalog(&c); err != nil {
		return c, err
	}
	if _, err := r.d.Token(); err != io.EOF {
		return c, errors.New("trailing catalog data")
	}
	if err := security.ValidateCatalog(c); err != nil {
		return c, err
	}
	sum := sha256.Sum256(data)
	c.Digest = hex.EncodeToString(sum[:])
	return c, nil
}

// reader reads the catalog schema from a token stream. It never matches a key
// case-insensitively and never skips a value it does not understand.
type reader struct{ d *json.Decoder }

func (r reader) catalog(c *security.Catalog) error {
	seen, err := r.object(func(key string) error {
		switch key {
		case "schema_version":
			return r.value(&c.SchemaVersion)
		case "revision":
			return r.value(&c.Revision)
		case "issued_at":
			return r.value(&c.IssuedAt)
		case "expires_at":
			return r.value(&c.ExpiresAt)
		case "records":
			return r.records(c)
		}
		return errUnknownField
	})
	if err != nil {
		return err
	}
	return require(seen, "schema_version", "revision", "issued_at", "expires_at", "records")
}

func (r reader) records(c *security.Catalog) error {
	if err := r.delim('['); err != nil {
		return err
	}
	c.Records = []security.AdvisoryRecord{}
	for r.d.More() {
		if len(c.Records) >= security.MaxCatalogRecords {
			return errors.New("too many records")
		}
		var rec security.AdvisoryRecord
		if err := r.record(&rec); err != nil {
			return fmt.Errorf("record %d: %w", len(c.Records), err)
		}
		c.Records = append(c.Records, rec)
	}
	return r.delim(']')
}

func (r reader) record(rec *security.AdvisoryRecord) error {
	seen, err := r.object(func(key string) error {
		switch key {
		case "ranges":
			return r.ranges(rec)
		case "required_features":
			return r.features(rec)
		}
		if dst := recordField(rec, key); dst != nil {
			return r.value(dst)
		}
		return errUnknownField
	})
	if err != nil {
		return err
	}
	return require(seen, "id", "revision", "component", "version_role", "source", "severity", "reviewed_at", "review_expires_at", "review_state")
}

// recordField is where the value of the schema's key goes in rec, or nil for a key the record
// has not, or one (ranges, required_features) that is read element by element.
func recordField(rec *security.AdvisoryRecord, key string) any {
	switch key {
	case "id":
		return &rec.ID
	case "revision":
		return &rec.Revision
	case "component":
		return &rec.Component
	case "version_role":
		return &rec.VersionRole
	case "os":
		return &rec.OS
	case "source":
		return &rec.Source
	case "severity":
		return &rec.Severity
	case "published_at":
		return &rec.PublishedAt
	case "updated_at":
		return &rec.UpdatedAt
	case "reviewed_at":
		return &rec.ReviewedAt
	case "review_expires_at":
		return &rec.ReviewExpiresAt
	case "source_checked_at":
		return &rec.SourceCheckedAt
	case "review_state":
		return &rec.ReviewState
	case "mitigation":
		return &rec.Mitigation
	}
	return nil
}

func (r reader) ranges(rec *security.AdvisoryRecord) error {
	if err := r.delim('['); err != nil {
		return err
	}
	rec.Ranges = []security.VersionRange{}
	for r.d.More() {
		if len(rec.Ranges) >= security.MaxRanges {
			return errors.New("too many ranges")
		}
		var rg security.VersionRange
		if _, err := r.object(func(key string) error {
			switch key {
			case "introduced":
				return r.value(&rg.Introduced)
			case "fixed":
				return r.value(&rg.Fixed)
			}
			return errUnknownField
		}); err != nil {
			return fmt.Errorf("range %d: %w", len(rec.Ranges), err)
		}
		rec.Ranges = append(rec.Ranges, rg)
	}
	return r.delim(']')
}

func (r reader) features(rec *security.AdvisoryRecord) error {
	if err := r.delim('['); err != nil {
		return err
	}
	rec.RequiredFeatures = []string{}
	for r.d.More() {
		if len(rec.RequiredFeatures) >= security.MaxRanges {
			return errors.New("too many required features")
		}
		var name string
		if err := r.value(&name); err != nil {
			return fmt.Errorf("required feature %d: %w", len(rec.RequiredFeatures), err)
		}
		rec.RequiredFeatures = append(rec.RequiredFeatures, name)
	}
	return r.delim(']')
}

// delim reads one token and requires it to be the delimiter want. A null, a scalar or the
// other kind of container in its place is an error.
func (r reader) delim(want json.Delim) error {
	t, err := r.d.Token()
	if err != nil {
		return unexpectedEOF(err)
	}
	if got, ok := t.(json.Delim); !ok || got != want {
		return fmt.Errorf("expected %c", rune(want))
	}
	return nil
}

// object reads the members of the object that starts at the next token. field is called
// with each member's key, before its value, and must consume the value or return
// errUnknownField for a key the schema does not have.
// A key that occurs twice, in any spelling that decodes to the same text, is an error. The
// keys seen are returned so the caller can require the mandatory ones.
func (r reader) object(field func(key string) error) (map[string]bool, error) {
	if err := r.delim('{'); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for r.d.More() {
		t, err := r.d.Token()
		if err != nil {
			return nil, unexpectedEOF(err)
		}
		key, ok := t.(string)
		if !ok {
			return nil, errors.New("invalid object key")
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate field %s", quote(key))
		}
		seen[key] = true
		if err := field(key); err != nil {
			if errors.Is(err, errUnknownField) {
				return nil, fmt.Errorf("unknown field %s", quote(key))
			}
			return nil, fmt.Errorf("%s: %w", key, err)
		}
	}
	if err := r.delim('}'); err != nil {
		return nil, err
	}
	return seen, nil
}

// value decodes the next value into dst. A null is an error: it would otherwise leave dst
// at its zero value and read as an absent member.
func (r reader) value(dst any) error {
	var raw json.RawMessage
	if err := r.d.Decode(&raw); err != nil {
		return unexpectedEOF(err)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("null is not allowed")
	}
	return json.Unmarshal(raw, dst)
}

func require(seen map[string]bool, keys ...string) error {
	for _, k := range keys {
		if !seen[k] {
			return fmt.Errorf("missing field %s", k)
		}
	}
	return nil
}

// errUnknownField is what a field function returns for a key the schema does not have;
// object turns it into an error that names the key.
var errUnknownField = errors.New("unknown field")

// quote shows a key from the input safely and briefly: escaped, and cut at 40 bytes.
func quote(s string) string {
	const limit = 40
	if len(s) > limit {
		cut := limit
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		return fmt.Sprintf("%q...", s[:cut])
	}
	return fmt.Sprintf("%q", s)
}

func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
