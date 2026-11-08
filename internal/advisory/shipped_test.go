package advisory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
)

// A synthetic catalog file: the id, the revision, the issue and expiry of the catalog, and
// the review expiry of its one approved record. Every date is far from the real clock.
func fileOf(id string, revision int, issued, expires string) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":1,"revision":%d,"issued_at":%q,"expires_at":%q,"records":[`+
		`{"id":%q,"revision":"1","component":"client","version_role":"running_daemon","source":"synthetic","severity":"low",`+
		`"reviewed_at":"2025-12-01T00:00:00Z","review_expires_at":%q,"review_state":"approved","ranges":[{"fixed":"1.32.3"}]}]}`,
		revision, issued, expires, id, expires))
}

func srcs(files ...Source) []Source { return files }

// Three files whose extremes are in three different files, so that a merge that takes the
// first file's value, or the last, gets at least one of them wrong.
func threeFiles() []Source {
	return srcs(
		Source{Name: "a.json", Data: fileOf("RULE-A", 3, "2026-03-01T00:00:00Z", "2027-09-01T00:00:00Z")},
		Source{Name: "b.json", Data: fileOf("RULE-B", 7, "2026-01-01T00:00:00Z", "2027-03-01T00:00:00Z")},
		Source{Name: "c.json", Data: fileOf("RULE-C", 5, "2026-06-01T00:00:00Z", "2027-12-01T00:00:00Z")},
	)
}

func TestMergeTakesTheEarliestExpiryTheLatestIssueAndTheHighestRevision(t *testing.T) {
	c, err := Merge(threeFiles())
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC); !c.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want the earliest expiry %v", c.ExpiresAt, want)
	}
	if want := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC); !c.IssuedAt.Equal(want) {
		t.Errorf("IssuedAt = %v, want the latest issue %v", c.IssuedAt, want)
	}
	if c.Revision != 7 {
		t.Errorf("Revision = %d, want the highest, 7", c.Revision)
	}
	var ids []string
	for _, r := range c.Records {
		ids = append(ids, r.ID)
	}
	if want := []string{"RULE-A", "RULE-B", "RULE-C"}; !slices.Equal(ids, want) {
		t.Errorf("records = %v, want %v (file name order)", ids, want)
	}
	if err := security.ValidateCatalog(c); err != nil {
		t.Errorf("the merged catalog does not validate: %v", err)
	}
}

func TestMergeIsOrderIndependent(t *testing.T) {
	files := threeFiles()
	want, err := Merge(files)
	if err != nil {
		t.Fatal(err)
	}
	for _, order := range [][]int{{2, 1, 0}, {1, 2, 0}, {0, 2, 1}, {2, 0, 1}, {1, 0, 2}} {
		shuffled := make([]Source, len(order))
		for i, j := range order {
			shuffled[i] = files[j]
		}
		got, err := Merge(shuffled)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("order %v gives another catalog:\n%+v\nwant\n%+v", order, got, want)
		}
	}
}

func TestMergeDoesNotChangeItsInput(t *testing.T) {
	files := threeFiles()
	before := []string{files[0].Name, files[1].Name, files[2].Name}
	files[0], files[2] = files[2], files[0]
	before[0], before[2] = before[2], before[0]
	if _, err := Merge(files); err != nil {
		t.Fatal(err)
	}
	for i, f := range files {
		if f.Name != before[i] {
			t.Fatalf("Merge reordered its argument: %s at %d, want %s", f.Name, i, before[i])
		}
	}
}

func TestMergeRefusesADuplicateRuleIDAcrossFiles(t *testing.T) {
	files := srcs(
		Source{Name: "a.json", Data: fileOf("SAME", 1, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")},
		Source{Name: "b.json", Data: fileOf("SAME", 2, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")},
	)
	c, err := Merge(files)
	if err == nil {
		t.Fatal("two files holding one rule ID merged")
	}
	if !strings.Contains(err.Error(), "SAME") || !strings.Contains(err.Error(), "b.json") {
		t.Errorf("the error does not name the rule and the second file: %v", err)
	}
	if !reflect.DeepEqual(c, security.Catalog{}) {
		t.Errorf("a refusal returned a part-filled catalog: %+v", c)
	}
}

func TestMergeRefusesTheWholeCatalogWhenOneFileIsCorrupt(t *testing.T) {
	good := fileOf("RULE-A", 1, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
	for name, bad := range map[string][]byte{
		"truncated":        good[:len(good)/2],
		"unknown field":    []byte(strings.Replace(string(good), `"records"`, `"extra":1,"records"`, 1)),
		"not json":         []byte("not json"),
		"empty":            nil,
		"trailing data":    append(slices.Clone(good), []byte(` {}`)...),
		"a record dropped": []byte(strings.Replace(string(good), `"review_state":"approved"`, `"review_state":"imaginary"`, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			for _, badFirst := range []bool{false, true} {
				files := srcs(Source{Name: "a.json", Data: good}, Source{Name: "b.json", Data: bad})
				if badFirst {
					files[0], files[1] = files[1], files[0]
				}
				c, err := Merge(files)
				if err == nil {
					t.Fatalf("a corrupt file was merged (bad file first: %v): %+v", badFirst, c)
				}
				if !reflect.DeepEqual(c, security.Catalog{}) {
					t.Errorf("a refusal returned a partial catalog: %+v", c)
				}
				if !strings.Contains(err.Error(), "b.json") && !badFirst {
					t.Errorf("the error does not name the file: %v", err)
				}
			}
		})
	}
}

func TestMergeRefusesNoFilesAndRepeatedNames(t *testing.T) {
	if _, err := Merge(nil); err == nil {
		t.Error("an empty set of files merged")
	}
	one := fileOf("RULE-A", 1, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
	if _, err := Merge(srcs(Source{Name: "a.json", Data: one}, Source{Name: "a.json", Data: one})); err == nil {
		t.Error("one file name given twice merged")
	}
	if _, err := Merge(srcs(Source{Name: "", Data: one})); err == nil {
		t.Error("a file without a name merged")
	}
}

// A catalog window that no instant is in: one file is issued after another has expired.
func TestMergeRefusesFilesWhoseWindowsDoNotOverlap(t *testing.T) {
	files := srcs(
		Source{Name: "a.json", Data: fileOf("RULE-A", 1, "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z")},
		Source{Name: "b.json", Data: fileOf("RULE-B", 1, "2026-09-01T00:00:00Z", "2027-06-01T00:00:00Z")},
	)
	if c, err := Merge(files); err == nil {
		t.Fatalf("files with no common instant merged: %+v", c)
	}
}

// Any byte of any file changes the digest, a byte that the decoder ignores included.
func TestMergeDigestChangesWithAnyByteOfAnyFile(t *testing.T) {
	files := threeFiles()
	base, err := Merge(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Digest) != 64 {
		t.Fatalf("digest %q is not 64 hex digits", base.Digest)
	}
	seen := map[string]string{base.Digest: "the original"}
	for i := range files {
		changed := slices.Clone(files)
		changed[i].Data = append(slices.Clone(files[i].Data), '\n')
		c, err := Merge(changed)
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[c.Digest]; dup {
			t.Errorf("a trailing newline in %s leaves the digest of %s", files[i].Name, prev)
		}
		seen[c.Digest] = files[i].Name
		if !reflect.DeepEqual(c.Records, base.Records) {
			t.Errorf("white space changed the records")
		}
	}
	// A file renamed is another set of files, even with the same bytes.
	renamed := slices.Clone(files)
	renamed[0].Name = "z.json"
	c, err := Merge(renamed)
	if err != nil {
		t.Fatal(err)
	}
	if c.Digest == base.Digest {
		t.Error("renaming a file leaves the digest")
	}
}

// The digest is what the contract says, computed here without the code under test: the
// SHA-256 of the sorted "name:digest" lines, one digest per file being the file's own.
func TestMergeDigestIsTheDigestOfTheSortedNameAndDigestLines(t *testing.T) {
	files := threeFiles()
	var lines []string
	for _, f := range files {
		sum := sha256.Sum256(f.Data)
		lines = append(lines, f.Name+":"+hex.EncodeToString(sum[:]))
	}
	slices.Sort(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n") + "\n"))
	c, err := Merge(files)
	if err != nil {
		t.Fatal(err)
	}
	if want := hex.EncodeToString(sum[:]); c.Digest != want {
		t.Errorf("digest %s, want %s", c.Digest, want)
	}
}

// diskFiles reads the shipped files straight from the directory, independently of the
// package under test.
func diskFiles(t *testing.T) []Source {
	t.Helper()
	paths, err := filepath.Glob("../../data/advisories/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no shipped advisory files: %v", err)
	}
	var out []Source
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, Source{Name: filepath.Base(p), Data: data})
	}
	return out
}

func TestShippedEmbedsEveryFileOfTheDirectory(t *testing.T) {
	disk := diskFiles(t)
	want, err := Merge(disk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Shipped()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the embedded catalog is not the merge of the files on disk:\n%+v\nwant\n%+v", got, want)
	}
	var ids []string
	for _, r := range got.Records {
		ids = append(ids, r.ID)
	}
	slices.Sort(ids)
	want5 := []string{"CVE-2022-41925", "TS-2026-014", "TS-2026-015", "TS-2026-016", "TS-2026-017"}
	if !slices.Equal(ids, want5) {
		t.Errorf("shipped rules = %v, want %v", ids, want5)
	}
}

// Pending rules stay pending in the merge: the matcher gives their devices unknown only.
func TestShippedKeepsPendingRulesPending(t *testing.T) {
	c, err := Shipped()
	if err != nil {
		t.Fatal(err)
	}
	pending, approved := 0, 0
	for _, r := range c.Records {
		switch r.ReviewState {
		case security.ReviewPending:
			pending++
			if !strings.HasPrefix(r.ID, "TS-2026-") {
				t.Errorf("%s is pending", r.ID)
			}
		case security.ReviewApproved:
			approved++
		default:
			t.Errorf("%s is %s", r.ID, r.ReviewState)
		}
	}
	if pending != 4 || approved != 1 {
		t.Errorf("pending %d approved %d, want 4 and 1", pending, approved)
	}
}

// The shipped catalog expires with the file that expires first, never later.
func TestShippedExpiresWithItsEarliestFile(t *testing.T) {
	var earliest time.Time
	for _, f := range diskFiles(t) {
		c, err := Decode(f.Data)
		if err != nil {
			t.Fatal(err)
		}
		if earliest.IsZero() || c.ExpiresAt.Before(earliest) {
			earliest = c.ExpiresAt
		}
	}
	got, err := Shipped()
	if err != nil {
		t.Fatal(err)
	}
	if !got.ExpiresAt.Equal(earliest) {
		t.Errorf("shipped catalog expires %v, want its earliest file's %v", got.ExpiresAt, earliest)
	}
}

// A corrupt embedded file refuses the whole catalog, never a partial one.
func TestShippedFromACorruptFileSystemRefusesEverything(t *testing.T) {
	good := fileOf("RULE-A", 1, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
	fsys := fstest.MapFS{
		"a.json":    {Data: good},
		"b.json":    {Data: good[:len(good)-5]},
		"README.md": {Data: []byte("not a catalog")},
	}
	c, err := shippedFrom(fsys)
	if err == nil {
		t.Fatalf("a file system with a corrupt catalog gave one: %+v", c)
	}
	if !reflect.DeepEqual(c, security.Catalog{}) {
		t.Errorf("a refusal returned a partial catalog: %+v", c)
	}
	// With the corrupt file gone, the rest is a catalog, and the README is not read.
	delete(fsys, "b.json")
	if c, err = shippedFrom(fsys); err != nil || len(c.Records) != 1 {
		t.Errorf("one good file and a README: %+v, %v", c, err)
	}
	if _, err := shippedFrom(fstest.MapFS{"README.md": {Data: []byte("x")}}); err == nil {
		t.Error("a file system with no catalog file gave a catalog")
	}
	var _ fs.FS = fsys
}

func TestShippedSourcesAreExactAndIndependent(t *testing.T) {
	sources, err := ShippedSources()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(sources, diskFiles(t)) {
		t.Fatal("embedded source names or bytes differ from disk")
	}
	merged, err := Merge(sources)
	if err != nil {
		t.Fatal(err)
	}
	shipped, err := Shipped()
	if err != nil || !reflect.DeepEqual(merged, shipped) {
		t.Fatalf("merge differs: %v", err)
	}
	sources[0].Data[0] ^= 1
	again, err := ShippedSources()
	if err != nil || reflect.DeepEqual(sources, again) {
		t.Fatalf("sources share data: %v", err)
	}
}
