package workflows

import (
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// archiveFile is one entry of an archive's files list: a path or glob, or an object
// whose src is one.
type archiveFile struct{ Src string }

func (f *archiveFile) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		return n.Decode(&f.Src)
	}
	var obj struct {
		Src string `yaml:"src"`
	}
	if err := n.Decode(&obj); err != nil {
		return err
	}
	f.Src = obj.Src
	return nil
}

// Every release archive carries the project's licence and notice and the licence texts of
// what the binary links (THIRD_PARTY_LICENSES): the BSD-3-Clause, MIT and Apache-2.0 terms
// of those modules require their text to travel with every copy. GoReleaser packs what the
// files list names and nothing else, and no other check notices an entry that is dropped:
// `make deps-check` holds the file's content, not that it ships, and the snapshot build
// succeeds without it. So the list is read here, archive by archive, and each file must
// also be in the repository, where an entry that names a missing file would pack nothing.
// The binary format, as an archive's format or an override for one OS, ships the bare
// binary and no files at all, so it is refused too.
func TestEveryArchiveCarriesTheLicences(t *testing.T) {
	data, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Archives []struct {
			ID              string   `yaml:"id"`
			Format          string   `yaml:"format"`
			Formats         []string `yaml:"formats"`
			FormatOverrides []struct {
				Goos    string   `yaml:"goos"`
				Format  string   `yaml:"format"`
				Formats []string `yaml:"formats"`
			} `yaml:"format_overrides"`
			Files []archiveFile `yaml:"files"`
		} `yaml:"archives"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	// With no archives section GoReleaser packs its default list, which has no NOTICE and
	// no THIRD_PARTY_LICENSES.
	if len(cfg.Archives) == 0 {
		t.Fatal(".goreleaser.yaml defines no archives")
	}
	required := []string{"LICENSE", "NOTICE", "THIRD_PARTY_LICENSES"}
	for _, name := range required {
		if _, err := os.Stat("../../" + name); err != nil {
			t.Errorf("%s is not in the repository: %v", name, err)
		}
	}
	for _, a := range cfg.Archives {
		if a.Format == "binary" || slices.Contains(a.Formats, "binary") {
			t.Errorf("archive %q has the binary format, which packs no files", a.ID)
		}
		for _, o := range a.FormatOverrides {
			if o.Format == "binary" || slices.Contains(o.Formats, "binary") {
				t.Errorf("archive %q overrides the format for %s to binary, which packs no files", a.ID, o.Goos)
			}
		}
		for _, problem := range archiveFilesProblems(a.ID, a.Files, required) {
			t.Error(problem)
		}
	}
}

// archiveFilesProblems says what is wrong with the files list of one archive: a required
// file that no entry packs, and an entry that is not a valid pattern.
func archiveFilesProblems(id string, files []archiveFile, required []string) []string {
	var out []string
	// GoReleaser reads ** as "any depth", and path.Match has no such thing: it reads ** as
	// two stars of one path element. An entry with one cannot be judged here, and saying
	// that the archive does not pack a file would send the reader looking for a missing
	// entry that is there. So it is named, and the list is not judged further.
	for _, f := range files {
		if strings.Contains(f.Src, "**") {
			out = append(out, fmt.Sprintf("archive %q: files entry %q uses **, which this test cannot read (it matches names with path.Match, which has no **): "+
				"write the entry as a plain name or a single-level glob", id, f.Src))
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, name := range required {
		found := false
		for _, f := range files {
			if ok, err := path.Match(f.Src, name); err != nil {
				out = append(out, fmt.Sprintf("archive %q: files entry %q is not a valid pattern: %v", id, f.Src, err))
			} else if ok {
				found = true
			}
		}
		if !found {
			out = append(out, fmt.Sprintf("archive %q does not pack %s: add it to its files list", id, name))
		}
	}
	return out
}
