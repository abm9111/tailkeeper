package security

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"
)

// ValidateCatalog validates both decoded and directly constructed records; it does not authenticate them.
//
// Each rule has its own error, so the text of an error names the rule that failed. A rule
// error about a record is prefixed with the record's position ("record 3: ..."), never with
// text taken from the record.
func ValidateCatalog(c Catalog) error { return validateCatalog(context.Background(), c) }

func validateCatalog(ctx context.Context, c Catalog) error {
	if err := validateCatalogHeader(c); err != nil {
		return err
	}
	// The sizes of the nested lists are bounded before any record's text or ranges are read.
	for _, r := range c.Records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(r.Ranges) > MaxRanges {
			return errors.New("too many ranges")
		}
		if len(r.RequiredFeatures) > MaxRanges {
			return errors.New("too many required features")
		}
	}
	if err := validateText(reflect.ValueOf(c.IssuedAt)); err != nil {
		return err
	}
	if err := validateText(reflect.ValueOf(c.ExpiresAt)); err != nil {
		return err
	}
	if err := validateText(reflect.ValueOf(c.Digest)); err != nil {
		return err
	}
	ids := make(map[string]bool, len(c.Records))
	for i, r := range c.Records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateRecord(ctx, c, r, ids); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
	}
	return nil
}

func validateCatalogHeader(c Catalog) error {
	switch {
	case c.SchemaVersion != SchemaVersion:
		return errors.New("unsupported catalog schema version")
	case c.Revision == 0:
		return errors.New("catalog revision must be at least 1")
	case c.IssuedAt.IsZero() || c.ExpiresAt.IsZero():
		return errors.New("catalog issue or expiry time is missing")
	case !c.ExpiresAt.After(c.IssuedAt):
		return errors.New("catalog expiry is not after issue")
	case len(c.Records) > MaxCatalogRecords:
		return errors.New("too many records")
	}
	return nil
}

// validateRecord checks one record. The rules about what a record says come first; the
// format of its text and times (the checks reports share) come last, so a missing time is
// reported as missing and not as a time before the floor.
func validateRecord(ctx context.Context, c Catalog, r AdvisoryRecord, ids map[string]bool) error {
	if err := validateRecordFields(r, ids); err != nil {
		return err
	}
	if err := validateRecordReview(c, r); err != nil {
		return err
	}
	ids[r.ID] = true
	if err := validateRecordTimes(c, r); err != nil {
		return err
	}
	if r.ReviewState == ReviewApproved && len(r.Ranges) == 0 {
		return errors.New("approved advisory has no range")
	}
	if err := validateRequiredFeatures(r.RequiredFeatures); err != nil {
		return err
	}
	if err := validateRanges(ctx, r.Ranges); err != nil {
		return err
	}
	return validateText(reflect.ValueOf(r))
}

// validateRecordFields checks that a record names itself and its source: its identity, its
// component, its severity and the role of its version.
func validateRecordFields(r AdvisoryRecord, ids map[string]bool) error {
	switch {
	case r.ID == "":
		return errors.New("empty advisory id")
	case ids[r.ID]:
		return errors.New("duplicate advisory id")
	case r.Revision == "":
		return errors.New("empty advisory revision")
	case r.Component == "":
		return errors.New("empty advisory component")
	case r.Source == "":
		return errors.New("empty advisory source")
	case !validSeverity(r.Severity):
		return errors.New("invalid advisory severity")
	case !validRole(r.VersionRole):
		return errors.New("invalid advisory version role")
	}
	return nil
}

// validateRecordReview checks the review of a record against the catalog's issue, and then
// its operating system.
func validateRecordReview(c Catalog, r AdvisoryRecord) error {
	switch {
	case r.ReviewedAt.IsZero() || r.ReviewExpiresAt.IsZero():
		return errors.New("advisory review time is missing")
	case !r.ReviewExpiresAt.After(r.ReviewedAt):
		return errors.New("advisory review expiry is not after review")
	case r.ReviewedAt.After(c.IssuedAt):
		return errors.New("advisory reviewed after catalog issue")
	case r.ReviewState != ReviewApproved && r.ReviewState != ReviewPending && r.ReviewState != ReviewWithdrawn:
		return errors.New("invalid advisory review state")
	case r.OS != "" && !validOS(r.OS):
		return errors.New("unsupported advisory os")
	}
	return nil
}

// validateRecordTimes checks the times a record carries besides its review: each is set and
// not after the catalog's issue, and an update does not precede the publication.
func validateRecordTimes(c Catalog, r AdvisoryRecord) error {
	for _, p := range []*time.Time{r.PublishedAt, r.UpdatedAt, r.SourceCheckedAt} {
		if p != nil && (p.IsZero() || p.After(c.IssuedAt)) {
			return errors.New("advisory time is zero or after catalog issue")
		}
	}
	if r.PublishedAt != nil && r.UpdatedAt != nil && r.UpdatedAt.Before(*r.PublishedAt) {
		return errors.New("advisory update precedes publication")
	}
	return nil
}

// validateRequiredFeatures checks that the names of the features a record requires are not
// empty and are not repeated.
func validateRequiredFeatures(names []string) error {
	features := make(map[string]bool, len(names))
	for _, f := range names {
		if f == "" {
			return errors.New("empty required feature")
		}
		if features[f] {
			return errors.New("duplicate required feature")
		}
		features[f] = true
	}
	return nil
}

// validateRanges checks a record's ranges. Each bound is a bare release (the strict
// parser: no build suffix, prefix or space) with an even minor, because only the stable
// track is ranged: a fix on the unstable track (an odd minor) says nothing about the
// stable one, and a bound on it would clear or flag stable releases wrongly.
func validateRanges(ctx context.Context, ranges []VersionRange) error {
	for i, x := range ranges {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validateRange(i, x); err != nil {
			return err
		}
		for _, prev := range ranges[:i] {
			if err := ctx.Err(); err != nil {
				return err
			}
			if rangesOverlap(prev, x) {
				return fmt.Errorf("range %d: overlapping ranges", i)
			}
		}
	}
	return nil
}

// validateRange checks the i-th range on its own: it has a bound, each bound is a release
// of the stable track, and it matches some release.
func validateRange(i int, x VersionRange) error {
	if x.Introduced == "" && x.Fixed == "" {
		return fmt.Errorf("range %d: empty range", i)
	}
	var introduced, fixed numericVersion
	var err error
	if x.Introduced != "" {
		if introduced, err = rangeBound(i, "introduced", x.Introduced); err != nil {
			return err
		}
	}
	if x.Fixed != "" {
		if fixed, err = rangeBound(i, "fixed", x.Fixed); err != nil {
			return err
		}
	}
	if x.Introduced == "" && fixed == (numericVersion{}) {
		// No release is below 0.0.0, so a range that is fixed there and starts nowhere
		// matches nothing, and a rule made of it would clear every device it covers.
		return fmt.Errorf("range %d: fixed is 0.0.0 and nothing is introduced, so the range matches no release", i)
	}
	if x.Introduced != "" && x.Fixed != "" {
		switch cmp := compareVersions(introduced, fixed); {
		case cmp == 0:
			return fmt.Errorf("range %d: introduced equals fixed", i)
		case cmp > 0:
			return fmt.Errorf("range %d: introduced is after fixed", i)
		}
	}
	return nil
}

// rangeBound reads the bound of the i-th range that the text spells: a release with an even
// minor. name is "introduced" or "fixed".
func rangeBound(i int, name, text string) (numericVersion, error) {
	v, ok := parseVersion(text)
	if !ok {
		return numericVersion{}, fmt.Errorf("range %d: invalid %s version", i, name)
	}
	if v[1]%2 != 0 {
		return numericVersion{}, fmt.Errorf("range %d: %s version must have an even minor", i, name)
	}
	return v, nil
}
func validRole(r VersionRole) bool {
	return r == VersionAPIReported || r == VersionLocalCLI || r == VersionRunningDaemon
}
func rangesOverlap(a, b VersionRange) bool {
	if a.Fixed != "" && b.Introduced != "" {
		x, _ := parseVersion(a.Fixed)
		y, _ := parseVersion(b.Introduced)
		if compareVersions(x, y) <= 0 {
			return false
		}
	}
	if b.Fixed != "" && a.Introduced != "" {
		x, _ := parseVersion(b.Fixed)
		y, _ := parseVersion(a.Introduced)
		if compareVersions(x, y) <= 0 {
			return false
		}
	}
	return true
}
