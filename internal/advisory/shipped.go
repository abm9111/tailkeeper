package advisory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/abm9111/tailkeeper/data/advisories"
	"github.com/abm9111/tailkeeper/internal/security"
)

// Source is one catalog file: its name, which identifies it in the merged digest and in an
// error, and its exact bytes.
type Source struct {
	Name string
	Data []byte
}

// Shipped returns the catalog built into the binary: every data/advisories/*.json file,
// decoded by the checked decoder and merged by Merge. Any file that fails refuses the whole
// catalog; there is no partial one. The result is built afresh on each call and shares no
// memory with another.
func Shipped() (security.Catalog, error) {
	sources, err := ShippedSources()
	if err != nil {
		return security.Catalog{}, err
	}
	return Merge(sources)
}

// ShippedSources returns the exact bytes of each shipped catalog file.
func ShippedSources() ([]Source, error) { return sourcesFrom(advisories.Files) }

// shippedFrom merges the .json files directly in the root of fsys (a README or a directory
// is not a catalog file).
func shippedFrom(fsys fs.FS) (security.Catalog, error) {
	sources, err := sourcesFrom(fsys)
	if err != nil {
		return security.Catalog{}, err
	}
	return Merge(sources)
}

func sourcesFrom(fsys fs.FS) ([]Source, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("cannot list the shipped advisory files: %w", err)
	}
	var sources []Source
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("cannot read the shipped advisory file %s: %w", e.Name(), err)
		}
		sources = append(sources, Source{Name: e.Name(), Data: data})
	}
	return sources, nil
}

// Merge decodes each source with Decode and merges them into one catalog that is valid
// (security.ValidateCatalog) or none. It is the same catalog whatever the order of the
// sources:
//
//   - Records are those of the files taken in the order of their names, each file's in its
//     own order. A rule ID that two files hold is an error that names it and the second
//     file; so is a file name given twice or empty, a file that fails to decode, and an empty
//     list of sources.
//   - ExpiresAt is the earliest expiry of any file, so the merged catalog is stale as soon
//     as any file is; IssuedAt is the latest issue; Revision is the highest. Files whose
//     windows have no instant in common (one issued after another expires) fail the
//     validation of the merged catalog.
//   - Digest is the SHA-256, in lowercase hex, of the lines "name:digest" of the files, each
//     digest being the decoder's (the SHA-256 of the file's exact bytes), sorted, every line
//     ended by a line feed. A change to any byte of any file, or to a name, changes it. It
//     does not authenticate anything.
//
// A pending record stays pending, and the matcher gives its devices unknown only.
func Merge(sources []Source) (security.Catalog, error) {
	if len(sources) == 0 {
		return security.Catalog{}, errors.New("no advisory files to merge")
	}
	ordered := slices.Clone(sources)
	slices.SortFunc(ordered, func(a, b Source) int { return strings.Compare(a.Name, b.Name) })
	merged := security.Catalog{SchemaVersion: security.SchemaVersion, Records: []security.AdvisoryRecord{}}
	owner := map[string]string{} // rule ID -> the file that holds it
	var lines []string
	for i, s := range ordered {
		if s.Name == "" {
			return security.Catalog{}, errors.New("an advisory file has no name")
		}
		if i > 0 && s.Name == ordered[i-1].Name {
			return security.Catalog{}, fmt.Errorf("advisory file %s is given twice", s.Name)
		}
		c, err := Decode(s.Data)
		if err != nil {
			return security.Catalog{}, fmt.Errorf("advisory file %s: %w", s.Name, err)
		}
		for _, r := range c.Records {
			if first, dup := owner[r.ID]; dup {
				return security.Catalog{}, fmt.Errorf("advisory file %s: rule %s is already in %s", s.Name, r.ID, first)
			}
			owner[r.ID] = s.Name
		}
		merged.Records = append(merged.Records, c.Records...)
		if i == 0 || c.ExpiresAt.Before(merged.ExpiresAt) {
			merged.ExpiresAt = c.ExpiresAt
		}
		if i == 0 || c.IssuedAt.After(merged.IssuedAt) {
			merged.IssuedAt = c.IssuedAt
		}
		merged.Revision = max(merged.Revision, c.Revision)
		lines = append(lines, s.Name+":"+c.Digest)
	}
	slices.Sort(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n") + "\n"))
	merged.Digest = hex.EncodeToString(sum[:])
	if err := security.ValidateCatalog(merged); err != nil {
		return security.Catalog{}, fmt.Errorf("the merged advisory catalog is not valid: %w", err)
	}
	return merged, nil
}
