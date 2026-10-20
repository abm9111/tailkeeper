package guard

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// FuzzScan holds the pass to what it was moved from: whatever the bytes, it answers as the
// old pass did, the same for a string and for bytes, and never lets a deeper limit refuse
// what a shallower one allows.
func FuzzScan(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, limit int) {
		limit = min(max(limit, 0), 1100)
		s := string(data)
		r := Scan(data, limit)
		if r2 := Scan(s, limit); r2 != r {
			t.Fatalf("bytes and string disagree: %+v %+v", r, r2)
		}
		if r.TooDeep != refNestsDeeperThan(s, limit) {
			t.Fatalf("TooDeep = %v, the old pass says %v", r.TooDeep, !r.TooDeep)
		}
		if r.NodeBound < 1 {
			t.Fatalf("NodeBound = %d", r.NodeBound)
		}
		if r.TooDeep {
			if r.Line < 1 || r.Offset < 0 || r.Offset >= len(data) || (data[r.Offset] != '[' && data[r.Offset] != '{') {
				t.Fatalf("the position of the bracket past the limit: %+v", r)
			}
			if want := 1 + bytes.Count(data[:r.Offset], []byte("\n")); r.Line != want {
				t.Fatalf("Line = %d, want %d", r.Line, want)
			}
			if !NestsDeeperThan(data, max(limit-1, 0)) {
				t.Fatalf("too deep for %d and not for %d", limit, limit-1)
			}
		} else if r.Offset != 0 || r.Line != 0 {
			t.Fatalf("a position without a refusal: %+v", r)
		}
	})
}

var updateSeeds = flag.Bool("update-seeds", false, "rewrite testdata/fuzz")

type seed struct {
	name  string
	data  string
	limit int
}

func seeds() []seed {
	return []seed{
		{"five-thousand-brackets", strings.Repeat("[", 5000), 1000},
		{"exactly-at-the-limit", strings.Repeat("[", 1000) + strings.Repeat("]", 1000), 1000},
		{"one-past-the-limit", strings.Repeat("{\"a\":", 1001) + "1" + strings.Repeat("}", 1001), 1000},
		{"brackets-in-a-string", `"` + strings.Repeat("[", 50) + `"`, 3},
		{"escaped-quote", `"\"` + strings.Repeat("[", 50) + `"`, 3},
		{"line-comment", "// " + strings.Repeat("[", 50) + "\n[[[1]]]", 2},
		{"block-comment", "/* " + strings.Repeat("{", 50) + " */ [[1]]", 1},
		{"unterminated-comment", "/* [[[[", 1},
		{"unterminated-line-comment", "// [[[[", 1},
		{"closers-first", "]]]]]][[[1]]]", 2},
		{"policy-shape", `{"acls": [{"src": ["a"], "dst": ["b:1"]}], "groups": {"g": []}}`, 3},
		{"lines-then-depth", "\n\n\n[[[[", 3},
		{"slash-at-the-end", "[[/", 1},
		{"empty", "", 0},
	}
}

func corpus(s seed) []byte {
	var b bytes.Buffer
	b.WriteString("go test fuzz v1\n")
	fmt.Fprintf(&b, "[]byte(%s)\n", strconv.Quote(s.data))
	fmt.Fprintf(&b, "int(%d)\n", s.limit)
	return b.Bytes()
}

// isFuzzHash reports whether name is one Go gives a crashing input it writes to
// testdata/fuzz/<Target>: the first 16 hex digits of the SHA-256 of its contents. A crasher
// is committed under that name as a regression seed, and the seed test lets it stand.
func isFuzzHash(name string) bool {
	if len(name) != 16 {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// clearSeeds removes the generated seeds from dir and leaves the files Go wrote, which are
// named by hash.
func clearSeeds(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if isFuzzHash(e.Name()) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// seedProblems lists what is wrong with dir against the seeds that should be in it: a
// generated seed that is stale, one that is missing, and a file that is neither a seed nor
// named by a fuzz hash.
func seedProblems(dir string, want map[string][]byte) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	have := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		have[name] = true
		if isFuzzHash(name) {
			continue
		}
		w, ok := want[name]
		if !ok {
			out = append(out, name+" is not a seed the fixtures build, nor a crasher named by its hash (run the test with -update-seeds)")
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(content, w) {
			out = append(out, name+" is out of date (run the test with -update-seeds)")
		}
	}
	for name := range want {
		if !have[name] {
			out = append(out, name+" is missing (run the test with -update-seeds)")
		}
	}
	sort.Strings(out)
	return out, nil
}

// TestSeedDirKeepsCrashers holds the seed test to what Go's own workflow does: a crasher is
// committed as testdata/fuzz/<Target>/<hash>, and no other stray name stands.
func TestSeedDirKeepsCrashers(t *testing.T) {
	want := map[string][]byte{"seed-01-a": []byte("go test fuzz v1\n[]byte(\"a\")\n")}
	crasher := []byte("go test fuzz v1\n[]byte(\"b\")\n")
	for _, tc := range []struct {
		name  string
		extra string
		ok    bool
	}{
		{"a hash name", "0123456789abcdef", true},
		{"a hash name with letters", "fedcba9876543210", true},
		{"upper case hex", "0123456789ABCDEF", false},
		{"a hash too short", "0123456789abcde", false},
		{"a hash too long", "0123456789abcdef0", false},
		{"not hex", "0123456789abcdeg", false},
		{"a name of a seed", "seed-02-b", false},
		{"a crasher left as it was found", "crasher", false},
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "seed-01-a"), want["seed-01-a"], 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, tc.extra), crasher, 0o600); err != nil {
			t.Fatal(err)
		}
		problems, err := seedProblems(dir, want)
		if err != nil || (len(problems) == 0) != tc.ok {
			t.Errorf("%s: problems %q, err %v; ok = %v", tc.name, problems, err, tc.ok)
		}
		if tc.ok {
			if err := clearSeeds(dir); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dir, tc.extra)); err != nil {
				t.Errorf("%s: clearSeeds removed the crasher: %v", tc.name, err)
			}
			if _, err := os.Stat(filepath.Join(dir, "seed-01-a")); err == nil {
				t.Errorf("%s: clearSeeds left a generated seed", tc.name)
			}
		}
	}
	// A stale or missing seed is still a problem beside a crasher.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "seed-01-a"), []byte("go test fuzz v1\nedited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0123456789abcdef"), crasher, 0o600); err != nil {
		t.Fatal(err)
	}
	if problems, err := seedProblems(dir, want); err != nil || len(problems) != 1 || !strings.Contains(problems[0], "out of date") {
		t.Errorf("an edited seed: %q %v", problems, err)
	}
	if err := os.Remove(filepath.Join(dir, "seed-01-a")); err != nil {
		t.Fatal(err)
	}
	if problems, err := seedProblems(dir, want); err != nil || len(problems) != 1 || !strings.Contains(problems[0], "missing") {
		t.Errorf("a missing seed: %q %v", problems, err)
	}
}

// TestFuzzSeedsAreCurrent holds testdata/fuzz/FuzzScan to the seeds above; -update-seeds
// writes them.
func TestFuzzSeedsAreCurrent(t *testing.T) {
	dir := filepath.Join("testdata", "fuzz", "FuzzScan")
	want := map[string][]byte{}
	for i, s := range seeds() {
		want[fmt.Sprintf("seed-%02d-%s", i+1, s.name)] = corpus(s)
	}
	if n := len(want); n < 10 || n > 20 {
		t.Errorf("%d seeds; 10 to 20 are kept", n)
	}
	if *updateSeeds {
		if err := clearSeeds(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range want {
			if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil { //nolint:gosec // test data
				t.Fatal(err)
			}
		}
		return
	}
	problems, err := seedProblems(dir, want)
	if err != nil {
		t.Fatalf("%v (run the test with -update-seeds)", err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}
