package sanitize

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two inputs in testdata/fuzz/FuzzKeyedMaskTextMasksToItself (0.0.1.0@0 and 100::/1000::@0)
// were found by the fuzzer when the target still asserted that MaskText masks to itself. The
// target no longer asserts it, so under its properties as they are the two pass without
// being tested for what they were found for. They are kept as evidence, and this is the
// property they do exercise: what MaskText does to them, once and then again. The first is
// the non-idempotence of 0.3.0 that the target's comment describes ("24@x" is cut to "2…@x"
// by the email pass, and the next address pass reads "/2" as a wider prefix); the second
// reads the same on the second pass as on the first today.
//
// If a change makes the first one stable, this test fails: the limit is gone, and the want
// below, the comment above it and the one in the fuzz target are to be changed together.
func TestTheKeptFuzzSeedsPinWhatMaskTextDoesToThem(t *testing.T) {
	corpus := filepath.Join("testdata", "fuzz", "FuzzKeyedMaskTextMasksToItself")
	files, err := filepath.Glob(filepath.Join(corpus, "*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files in %s: %v", corpus, err)
	}
	var kept strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		kept.Write(b)
	}
	for _, c := range []struct{ in, once, twice string }{
		{"0.0.1.0@0", "0.0.1.0/2…@0", "0.0.0.0/2…@0"},
		{"100::/1000::@0", "100::/480::@0", "100::/480::@0"},
	} {
		if !strings.Contains(kept.String(), `string("`+c.in+`")`) {
			t.Errorf("%q is no longer in the corpus of FuzzKeyedMaskTextMasksToItself: this test describes a kept seed", c.in)
		}
		once := MaskText(c.in)
		if once != c.once {
			t.Errorf("MaskText(%q) = %q, want %q", c.in, once, c.once)
		}
		if twice := MaskText(once); twice != c.twice {
			t.Errorf("MaskText(MaskText(%q)) = %q, want %q", c.in, twice, c.twice)
		}
	}
}
