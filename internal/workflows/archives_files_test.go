package workflows

import (
	"strings"
	"testing"
)

// The archives test matches the files list with path.Match, which has no **. A recursive
// entry used to come out as "does not pack LICENSE" although the entry might pack it, so
// the reader looked for a missing entry that was there. An entry with ** is named as one
// this test cannot read; a plain name and a single-level glob are read as before.
func TestArchiveFilesCheckNamesRecursiveGlobs(t *testing.T) {
	required := []string{"LICENSE", "NOTICE"}
	entries := func(srcs ...string) []archiveFile {
		out := make([]archiveFile, len(srcs))
		for i, s := range srcs {
			out[i] = archiveFile{Src: s}
		}
		return out
	}
	for _, c := range []struct {
		name  string
		files []archiveFile
		want  []string // substrings, one per problem, in order; none for a clean list
	}{
		{"plain names", entries("LICENSE", "NOTICE", "README.md"), nil},
		{"a single-level glob", entries("*"), nil},
		{"a recursive entry is named, and is not reported as a missing file", entries("**/LICENSE", "NOTICE"),
			[]string{`files entry "**/LICENSE" uses **`}},
		{"a recursive directory entry", entries("LICENSE", "NOTICE", "docs/**"),
			[]string{`files entry "docs/**" uses **`}},
		{"two recursive entries, two problems", entries("**/LICENSE", "**/NOTICE"),
			[]string{`"**/LICENSE" uses **`, `"**/NOTICE" uses **`}},
		{"a missing file", entries("NOTICE"), []string{"does not pack LICENSE"}},
		{"an invalid pattern", entries("LICENSE", "NOTICE", "["), []string{`files entry "[" is not a valid pattern`, `files entry "[" is not a valid pattern`}},
	} {
		got := archiveFilesProblems("default", c.files, required)
		if len(got) != len(c.want) {
			t.Errorf("%s: %d problems %q, want %d", c.name, len(got), got, len(c.want))
			continue
		}
		for i, w := range c.want {
			if !strings.Contains(got[i], w) {
				t.Errorf("%s: problem %d is %q, want it to contain %q", c.name, i, got[i], w)
			}
		}
	}
}
