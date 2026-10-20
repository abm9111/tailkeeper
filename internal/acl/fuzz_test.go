package acl

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
)

// The fuzz targets read what the engine is given as bytes and check properties that hold
// for every input and are deterministic for it: nothing in a property reads a clock, a
// random source or the order of a map. The seeds are real policy shapes (testdata/fuzz),
// because byte-level mutation of structured text mostly finds the syntax-error path
// without them. The required pull-request check replays the seeds and fuzzes each target
// for 20 seconds; the nightly job fuzzes longer.

func FuzzParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx := context.Background()
		d, err := Parse(ctx, data)
		d2, err2 := Parse(ctx, data)
		if (err == nil) != (err2 == nil) {
			t.Fatalf("Parse is not deterministic: %v then %v", err, err2)
		}
		if err != nil {
			var e, e2 *Error
			if !errors.As(err, &e) || (e.Code != CodeInvalid && e.Code != CodeTooComplex) || len(e.Message) > maxMessage+len("\u2026") {
				t.Fatalf("Parse returned %v", err)
			}
			if !errors.As(err2, &e2) || *e != *e2 {
				t.Fatalf("Parse is not deterministic: %v then %v", err, err2)
			}
			if e.Line < 0 || e.Column < 0 || (e.Line == 0) != (e.Column == 0) {
				t.Fatalf("a half position: %+v", e)
			}
			return
		}
		lines := d.Lines()
		for _, fnd := range d.Findings() {
			if fnd.Line < 1 || fnd.Line > lines || fnd.FirstLine < 1 || fnd.FirstLine > lines || fnd.Column < 1 || fnd.FirstColumn < 1 {
				t.Fatalf("a finding off the text: %+v (%d lines)", fnd, lines)
			}
		}
		nf, err := Normalise(ctx, d)
		if err != nil {
			if !errors.Is(err, ErrTooComplex) {
				t.Fatalf("Normalise returned %v", err)
			}
			return
		}
		again, err := Normalise(ctx, d)
		if err != nil || !bytes.Equal(nf.Bytes(), again.Bytes()) {
			t.Fatalf("Normalise is not deterministic: %v", err)
		}
		// Parsing the same bytes again gives the same policy: the same normal form.
		nf2, err := Normalise(ctx, d2)
		if err != nil || !bytes.Equal(nf.Bytes(), nf2.Bytes()) || d.Lines() != d2.Lines() || len(d.Findings()) != len(d2.Findings()) {
			t.Fatalf("a second Parse of the same bytes differs: %v", err)
		}
		// A policy means the same as itself, and as itself with its comments and trailing commas
		// replaced by spaces, and as itself formatted.
		self, err := Diff(ctx, d, d, DiffOptions{})
		if err != nil || !self.SemanticallyEqual || len(self.Changes) != 0 || self.Counts != (Counts{}) {
			t.Fatalf("a policy differs from itself: %v %+v", err, self)
		}
		// A slice and not a map: the order the transforms run in is the same on every run.
		transforms := []struct {
			name string
			fn   func(context.Context, []byte) ([]byte, error)
		}{{"Standardize", Standardize}, {"Format", Format}}
		for _, tr := range transforms {
			out, err := tr.fn(ctx, data)
			if err != nil {
				t.Fatalf("%s of a policy that parsed: %v", tr.name, err)
			}
			d2, err := Parse(ctx, out)
			if err != nil {
				t.Fatalf("%s wrote a text that does not parse: %v", tr.name, err)
			}
			r, err := Diff(ctx, d, d2, DiffOptions{})
			if err != nil || !r.SemanticallyEqual {
				t.Fatalf("%s changed what the policy means: %v\n%s", tr.name, err, describe(r))
			}
		}
		s, err := Summarise(ctx, d)
		if err != nil || len(s.Sections) < len(sections) {
			t.Fatalf("Summarise: %v", err)
		}
		if _, err := StripTests(ctx, data); err != nil {
			t.Fatalf("StripTests of a policy that parsed: %v", err)
		}
	})
}

func FuzzNormaliseDiff(f *testing.F) {
	f.Fuzz(func(t *testing.T, a, b []byte) {
		ctx := context.Background()
		da, err := Parse(ctx, a)
		if err != nil {
			return
		}
		db, err := Parse(ctx, b)
		if err != nil {
			return
		}
		ab, err := Diff(ctx, da, db, DiffOptions{PageSize: MaxPage})
		if err != nil {
			if !errors.Is(err, ErrTooComplex) {
				t.Fatalf("Diff returned %v", err)
			}
			return
		}
		ba, err := Diff(ctx, db, da, DiffOptions{PageSize: MaxPage})
		if err != nil {
			t.Fatalf("Diff the other way: %v", err)
		}
		if ab.SemanticallyEqual != ba.SemanticallyEqual || ab.Counts.Defaults != ba.Counts.Defaults {
			t.Fatalf("the two directions disagree: %+v %+v", ab.Counts, ba.Counts)
		}
		if x, y := ab.Counts.Semantic+ab.Counts.TestsReduced+ab.Counts.TailscaleWritten, ba.Counts.Semantic+ba.Counts.TestsReduced+ba.Counts.TailscaleWritten; x != y {
			t.Fatalf("%d changes one way and %d the other\n%s\n--\n%s", x, y, describe(ab), describe(ba))
		}
		// Equal in the diff is equal in the normal form's bytes, and the other way round.
		na, err1 := NormalFormBytes(ctx, da)
		nb, err2 := NormalFormBytes(ctx, db)
		if err1 != nil || err2 != nil {
			t.Fatalf("NormalFormBytes: %v %v", err1, err2)
		}
		if ab.SemanticallyEqual != bytes.Equal(na, nb) {
			t.Fatalf("Diff says equal = %v and the normal forms say %v\n%s", ab.SemanticallyEqual, bytes.Equal(na, nb), describe(ab))
		}
		for _, c := range ab.Changes {
			if c.Old.Len < len(c.Old.Text)-len("\u2026") || len(c.Old.Text) > maxPointer+len("\u2026") || len(c.New.Text) > maxPointer+len("\u2026") {
				t.Fatalf("a text past its cap: %+v", c)
			}
		}
		// A cursor taken from a page continues it.
		if ab.Truncated {
			next, err := Diff(ctx, da, db, DiffOptions{PageSize: MaxPage, Cursor: ab.NextChange})
			if err != nil || len(next.Changes) == 0 {
				t.Fatalf("the cursor of a page does not continue it: %v", err)
			}
		}
	})
}

func FuzzLocate(f *testing.F) {
	f.Fuzz(func(t *testing.T, policy []byte, src, dst string) {
		ctx := context.Background()
		d, err := Parse(ctx, policy)
		if err != nil {
			return
		}
		lines := d.Lines()
		for _, fail := range []Failure{{Src: src, Dst: dst}, {Src: src, Dst: dst, SSH: true}, {Src: src}} {
			locs, cut := Locate(d, fail)
			if len(locs) > MaxLocations || cut < 0 {
				t.Fatalf("%d locations, %d cut", len(locs), cut)
			}
			for _, l := range locs {
				if l.Line < 1 || l.Line > lines || l.Column < 1 || !strings.HasPrefix(l.Pointer, "/") {
					t.Fatalf("a location off the text: %+v (%d lines)", l, lines)
				}
				if l.Match == MatchSrcAndDestination && fail.Dst == "" {
					t.Fatalf("a destination match for a failure with none: %+v", l)
				}
				checkLocation(t, d, l)
			}
		}
		locs, more, err := LocateToken(ctx, d, src)
		if err != nil || more < 0 || len(locs) > MaxLocations {
			t.Fatalf("LocateToken: %d locations, %d more, %v", len(locs), more, err)
		}
		for _, l := range locs {
			if l.Line < 1 || l.Line > lines || (l.Match != MatchKey && l.Match != MatchValue) {
				t.Fatalf("a token location off the text: %+v", l)
			}
			checkLocation(t, d, l)
		}
	})
}

// candidate is a node a JSON Pointer can name: the value, and the member name it is the
// value of (nil for an element of an array).
type candidate struct{ name, val *hujson.Value }

// maxCandidates bounds the nodes a pointer through repeated names can mean.
const maxCandidates = 4096

// resolvePointer follows a pointer through the tree Parse read, in the test's own code and
// not the engine's. A repeated name leads to every member that holds it, so the result is
// every node the pointer can mean; ok is false when that set outgrows maxCandidates.
func resolvePointer(root *hujson.Value, pointer string) (cands []candidate, ok bool) {
	cands = []candidate{{nil, root}}
	for _, tok := range strings.Split(pointer[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		var next []candidate
		for _, c := range cands {
			switch x := c.val.Value.(type) {
			case *hujson.Object:
				for i := range x.Members {
					if nameOf(&x.Members[i].Name) == tok {
						next = append(next, candidate{&x.Members[i].Name, &x.Members[i].Value})
					}
				}
			case *hujson.Array:
				if i, err := strconv.Atoi(tok); err == nil && strconv.Itoa(i) == tok && i >= 0 && i < len(x.Elements) {
					next = append(next, candidate{nil, &x.Elements[i]})
				}
			}
		}
		if len(next) > maxCandidates {
			return nil, false
		}
		cands = next
	}
	return cands, true
}

// checkLocation requires a location to start where its pointer leads: the member name for a
// key, the value otherwise. The line and column are counted here from the text, one more
// than the line feeds before the offset and the bytes since the last. A pointer cut at its
// cap names no node and is not followed.
func checkLocation(t *testing.T, d *Doc, l Location) {
	t.Helper()
	if len(l.Pointer) > maxPointer {
		return
	}
	cands, ok := resolvePointer(&d.root, l.Pointer)
	if !ok {
		return
	}
	for _, c := range cands {
		v := c.val
		if l.Match == MatchKey {
			v = c.name
		}
		if v == nil {
			continue
		}
		before := d.src[:v.StartOffset]
		line := 1 + bytes.Count(before, []byte("\n"))
		col := v.StartOffset - (bytes.LastIndexByte(before, '\n') + 1) + 1
		if line == l.Line && col == l.Column {
			return
		}
	}
	t.Fatalf("a location does not start where its pointer leads: %+v (%d nodes named)", l, len(cands))
}

// --- the seeds ---

var updateSeeds = flag.Bool("update-seeds", false, "rewrite testdata/fuzz from the fixtures")

type seed struct {
	name string
	args [][]byte
}

func policySeeds(t testing.TB) []seed {
	basic := fixture(t, "basic.hujson")
	rule := `{"action":"accept","src":["group:eng"],"dst":["tag:web:443"],"proto":"tcp"}`
	grant := `{"src":["group:eng"],"dst":["tag:web"],"ip":["tcp:443"]}`
	return []seed{
		{"basic", [][]byte{basic}},
		{"crlf", [][]byte{fixture(t, "crlf.hujson")}},
		{"duplicates", [][]byte{fixture(t, "duplicates.hujson")}},
		{"byte-order-mark", [][]byte{fixture(t, "bom.hujson")}},
		{"utf16", [][]byte{fixture(t, "utf16le.hujson")}},
		{"lone-cr", [][]byte{fixture(t, "lone-cr.hujson")}},
		{"empty", [][]byte{nil}},
		{"empty-object", [][]byte{[]byte("{}")}},
		{"array", [][]byte{[]byte(`[{"src":"tag:p","accept":["tag:p:22"]}]`)}},
		{"comment-only", [][]byte{[]byte("// nothing\n")}},
		{"five-thousand-brackets", [][]byte{[]byte(strings.Repeat("[", 5000))}},
		{"deep-objects", [][]byte{[]byte(strings.Repeat(`{"a":`, 1100))}},
		{"acl-rule", [][]byte{[]byte(`{"acls":[` + rule + `]}`)}},
		{"grant", [][]byte{[]byte(`{"grants":[` + grant + `]}`)}},
		{"tests-only", [][]byte{[]byte(`{"tests":[{"src":"group:eng","accept":["tag:web:443"],"deny":["tag:db:22"]}],"sshTests":[{"src":"a","dst":["b"],"accept":["root"]}]}`)}},
		{"unknown-sections", [][]byte{[]byte(`{"nodeAttr":[],"futureSection":{"a":[1,2,{"b":null}]},"NodeAttrs":[{"target":["*"],"attr":["funnel"]}]}`)}},
		{"escapes", [][]byte{[]byte(`{"gr\u006fups":{"group:\u00e9\n":["a\/b","\ud800"]},"ACLS":[{"Action":"acc\u0065pt","SRC":["*"],"Dst":["*:*"]}]}`)}},
		{"wide-sources", [][]byte{[]byte(`{"acls":[{"action":"accept","src":[` + strings.Repeat(`"g",`, 300) + `"h"],"dst":["x:1-65535,80"]}]}`)}},
	}
}

func fuzzSeeds(t testing.TB) map[string][]seed {
	out := map[string][]seed{"FuzzParse": policySeeds(t)}
	basic := fixture(t, "basic.hujson")
	rule := `{"action":"accept","src":["group:eng"],"dst":["tag:web:443"],"proto":"tcp"}`
	pair := func(name, a, b string) seed { return seed{name, [][]byte{[]byte(a), []byte(b)}} }
	out["FuzzNormaliseDiff"] = []seed{
		{"basic-and-crlf", [][]byte{basic, fixture(t, "crlf.hujson")}},
		{"basic-and-empty", [][]byte{basic, []byte("{}")}},
		pair("acls-and-grants", `{"acls":[`+rule+`]}`, `{"grants":[{"src":["group:eng"],"dst":["tag:web"],"ip":["tcp:443"]}]}`),
		pair("rule-split-by-port", `{"acls":[{"action":"accept","src":["a"],"dst":["x:80","x:443"]}]}`, `{"acls":[{"action":"accept","src":["a"],"dst":["x:80"]},{"action":"accept","src":["a"],"dst":["x:443"]}]}`),
		pair("tests-reduced", `{"tests":[{"src":"a","accept":["x:1","x:2"]}]}`, `{"tests":[{"src":"a","accept":["x:1"]}]}`),
		pair("defaults", `{}`, `{"acls":[]}`),
		pair("widening", `{"acls":[{"action":"accept","src":["a"],"dst":["x:1"]}]}`, `{"acls":[{"action":"accept","src":["a","*"],"dst":["x:1"]}]}`),
		pair("tailscale-written", `{}`, `{"nodeAttrs":[{"target":["autogroup:member"],"attr":["funnel"]}]}`),
		pair("unknown-section", `{"future":{"a":1}}`, `{"future":{"a":2}}`),
		pair("ssh-check-to-accept", `{"ssh":[{"action":"check","src":["g"],"dst":["t"],"users":["u"]}]}`, `{"ssh":[{"action":"accept","src":["g"],"dst":["t"],"users":["u"]}]}`),
		pair("ipset-reorder", `{"ipsets":{"ipset:s":["add 192.0.2.1","remove 192.0.2.1"]}}`, `{"ipsets":{"ipset:s":["remove 192.0.2.1","add 192.0.2.1"]}}`),
		{"duplicates-and-basic", [][]byte{fixture(t, "duplicates.hujson"), basic}},
		pair("many-changes", `{"groups":{"a":["1"],"b":["2"],"c":["3"]}}`, `{"groups":{"a":["x"],"b":["y"],"d":["4"]},"hosts":{"h":"192.0.2.1"}}`),
	}
	locate := func(name, policy, src, dst string) seed {
		return seed{name, [][]byte{[]byte(policy), []byte(src), []byte(dst)}}
	}
	tests := `{"tests":[{"src":"group:a","accept":["tag:x:80"]},{"user":"group:a","deny":["tag:y:22"]}],"sshTests":[{"src":"group:a","dst":["tag:x"],"accept":["root"]}]}`
	out["FuzzLocate"] = []seed{
		locate("basic-test", string(basic), "group:eng", "tag:web:443"),
		locate("basic-ssh", string(basic), "group:eng", "tag:web"),
		locate("tests-src-and-dst", tests, "group:a", "tag:x:80"),
		locate("tests-src-only", tests, "group:a", ""),
		locate("tests-legacy-user", tests, "group:a", "tag:y:22"),
		locate("no-such-source", tests, "nobody", "tag:x:80"),
		locate("a-tag", string(basic), "tag:web", ""),
		locate("a-key", string(basic), "group:eng", "x"),
		locate("duplicates", string(fixture(t, "duplicates.hujson")), "tag:p", "tag:p:22"),
		locate("empty-policy", "{}", "", ""),
		locate("tests-twice", `{"tests":[{"src":"a","accept":["x:1"]}],"Tests":[{"src":"b","accept":["x:1"]}]}`, "b", "x:1"),
		locate("crlf", string(fixture(t, "crlf.hujson")), "group:ops", "tag:db:5432"),
	}
	return out
}

// corpusFile writes a seed in the format of Go's fuzz corpus.
func corpusFile(s seed, types []string) []byte {
	var b bytes.Buffer
	b.WriteString("go test fuzz v1\n")
	for i, a := range s.args {
		if types[i] == "string" {
			fmt.Fprintf(&b, "string(%s)\n", strconv.Quote(string(a)))
		} else {
			fmt.Fprintf(&b, "[]byte(%s)\n", strconv.Quote(string(a)))
		}
	}
	return b.Bytes()
}

var fuzzArgTypes = map[string][]string{
	"FuzzParse":         {"[]byte"},
	"FuzzNormaliseDiff": {"[]byte", "[]byte"},
	"FuzzLocate":        {"[]byte", "string", "string"},
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

// TestFuzzSeedsAreCurrent holds testdata/fuzz to what fuzzSeeds builds from the fixtures.
// Run it with -update-seeds to write them.
func TestFuzzSeedsAreCurrent(t *testing.T) {
	seeds := fuzzSeeds(t)
	targets := make([]string, 0, len(seeds))
	for target := range seeds {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	for _, target := range targets {
		dir := filepath.Join("testdata", "fuzz", target)
		list := seeds[target]
		if n := len(list); n < 10 || n > 20 {
			t.Errorf("%s has %d seeds; 10 to 20 are kept", target, n)
		}
		want := map[string][]byte{}
		for i, s := range list {
			want[fmt.Sprintf("seed-%02d-%s", i+1, s.name)] = corpusFile(s, fuzzArgTypes[target])
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
			continue
		}
		problems, err := seedProblems(dir, want)
		if err != nil {
			t.Fatalf("%s: %v (run the test with -update-seeds)", target, err)
		}
		for _, p := range problems {
			t.Errorf("%s/%s", target, p)
		}
	}
}
