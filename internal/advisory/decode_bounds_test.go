package advisory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/security"
)

const catalogHeader = `{"schema_version":1,"revision":1,"issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","records":[`

// goodRecord is a valid approved record; %s is its id.
const goodRecord = `{"id":%q,"revision":"1","component":"client","version_role":"running_daemon","source":"synthetic","severity":"low","reviewed_at":"2025-12-01T00:00:00Z","review_expires_at":"2027-01-01T00:00:00Z","review_state":"approved","ranges":[{"fixed":"1.32.3"}]}`

func record(id string) string { return fmt.Sprintf(goodRecord, id) }

func catalogOf(records ...string) []byte {
	return []byte(catalogHeader + strings.Join(records, ",") + `]}`)
}

// recordWith returns a valid record with one more member spliced in after the id.
func recordWith(member string) string {
	return strings.Replace(record("R1"), `"id":"R1",`, `"id":"R1",`+member+`,`, 1)
}

func mustDecode(t *testing.T, data []byte) security.Catalog {
	t.Helper()
	c, err := Decode(data)
	if err != nil {
		t.Fatalf("rejected a valid catalog: %v", err)
	}
	return c
}

// hostile builds an input of just under size bytes: prefix, the element repeated, suffix.
func hostile(size int, prefix, element, suffix string) []byte {
	var b bytes.Buffer
	b.WriteString(prefix)
	for b.Len() < size-len(suffix)-len(element) {
		b.WriteString(element)
	}
	b.WriteString(suffix)
	return b.Bytes()
}

// pendingRecordHead opens a valid pending record whose last member is an array.
const pendingRecordHead = `{"id":"R1","revision":"1","component":"client","version_role":"running_daemon","source":"s","severity":"low","reviewed_at":"2025-12-01T00:00:00Z","review_expires_at":"2027-01-01T00:00:00Z","review_state":"pending",`

// allocated runs Decode and returns what it allocated in total, with its result.
func allocated(in []byte) (c security.Catalog, delta uint64, err error) {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	c, err = Decode(in)
	runtime.ReadMemStats(&after)
	return c, after.TotalAlloc - before.TotalAlloc, err
}

// The hostile catalogs of the review (V7): 4 MiB of elements that are each trivially
// small. The decoder must give up at the bound without reading the rest, so what it
// allocates does not depend on the size of the input.
func TestDecodeStopsAtTheBoundBeforeAllocating(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want string // empty: any error
	}{
		// The design's acceptance input. Its first record is already incomplete.
		{"empty records", hostile(maxBytes, catalogHeader, "{},", "{}]}"), ""},
		{"empty ranges", hostile(maxBytes, catalogHeader+pendingRecordHead+`"ranges":[`, "{},", "{}]}]}"), "too many ranges"},
		{"empty required features", hostile(maxBytes, catalogHeader+pendingRecordHead+`"required_features":[`, `"",`, `""]}]}`), "too many required features"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.in) > maxBytes || len(tc.in) < maxBytes-4096 {
				t.Fatalf("the input must be just under %d bytes so that it passes the size check: %d", maxBytes, len(tc.in))
			}
			c, delta, err := allocated(tc.in)
			t.Logf("%d input bytes, %d KiB allocated, error: %v", len(tc.in), delta>>10, err)
			if err == nil {
				t.Fatal("accepted a hostile catalog")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			if !reflect.DeepEqual(c, security.Catalog{}) {
				t.Fatalf("an error must return the zero catalog: %+v", c)
			}
			if delta >= 32<<20 {
				t.Fatalf("decoding the hostile input allocated %d MiB (limit 32 MiB)", delta>>20)
			}
		})
	}
}

// Records that are complete cost something each, so there is no fixed byte limit for them;
// what must hold is that a catalog four times as long costs no more, because the 1001st
// record ends the work.
func TestDecodeAllocationDoesNotGrowWithInputSize(t *testing.T) {
	complete := func(size int) []byte {
		return hostile(size, catalogHeader, record("R1")+",", record("R1")+"]}")
	}
	small, large := complete(1<<20), complete(maxBytes)
	if _, _, err := allocated(small); err == nil { // warm-up: pools and type caches
		t.Fatal("accepted a hostile catalog")
	}
	_, deltaSmall, errSmall := allocated(small)
	c, deltaLarge, errLarge := allocated(large)
	t.Logf("%d input bytes: %d KiB; %d input bytes: %d KiB", len(small), deltaSmall>>10, len(large), deltaLarge>>10)
	for _, err := range []error{errSmall, errLarge} {
		if err == nil || !strings.Contains(err.Error(), "too many records") {
			t.Fatalf("want too many records, got %v", err)
		}
	}
	if !reflect.DeepEqual(c, security.Catalog{}) {
		t.Fatal("an error must return the zero catalog")
	}
	if deltaLarge > 2*deltaSmall+1<<20 {
		t.Fatalf("four times the input allocated %d KiB against %d KiB", deltaLarge>>10, deltaSmall>>10)
	}
}

// The elements after the bound are never decoded: each case puts something after the last
// allowed element that would fail differently if it were read.
func TestDecodeCountBoundsAreChecked(t *testing.T) {
	ids := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = record(fmt.Sprintf("R%d", i+1))
		}
		return out
	}
	t.Run("records at the bound", func(t *testing.T) {
		c := mustDecode(t, catalogOf(ids(security.MaxCatalogRecords)...))
		if len(c.Records) != security.MaxCatalogRecords {
			t.Fatalf("%d records", len(c.Records))
		}
	})
	t.Run("records past the bound", func(t *testing.T) {
		for name, extra := range map[string]string{"a valid record": record("EXTRA"), "an unknown member": `{"bogus":1}`, "a wrong type": `5`, "null": `null`} {
			c, err := Decode(catalogOf(append(ids(security.MaxCatalogRecords), extra)...))
			if err == nil || !strings.Contains(err.Error(), "too many records") {
				t.Errorf("%s as the 1001st: want too many records, got %v", name, err)
			}
			if !reflect.DeepEqual(c, security.Catalog{}) {
				t.Errorf("%s: want the zero catalog", name)
			}
		}
	})
	ranges := func(n int) string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf(`{"introduced":"1.%d.0","fixed":"1.%d.0"}`, 2*i, 2*i+2)
		}
		return strings.Join(out, ",")
	}
	t.Run("ranges at the bound", func(t *testing.T) {
		c := mustDecode(t, catalogOf(strings.Replace(record("R1"), `[{"fixed":"1.32.3"}]`, "["+ranges(security.MaxRanges)+"]", 1)))
		if got := len(c.Records[0].Ranges); got != security.MaxRanges {
			t.Fatalf("%d ranges", got)
		}
	})
	t.Run("ranges past the bound", func(t *testing.T) {
		for name, extra := range map[string]string{"a valid range": `{"introduced":"2.0.0"}`, "an unknown member": `{"bogus":1}`, "a wrong type": `5`} {
			in := catalogOf(strings.Replace(record("R1"), `[{"fixed":"1.32.3"}]`, "["+ranges(security.MaxRanges)+","+extra+"]", 1))
			if c, err := Decode(in); err == nil || !strings.Contains(err.Error(), "too many ranges") || !reflect.DeepEqual(c, security.Catalog{}) {
				t.Errorf("%s as the 33rd: want too many ranges and the zero catalog, got %v", name, err)
			}
		}
	})
	features := func(n int) string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("%q", fmt.Sprintf("feature-%d", i))
		}
		return strings.Join(out, ",")
	}
	t.Run("features at the bound", func(t *testing.T) {
		c := mustDecode(t, catalogOf(recordWith(`"required_features":[`+features(security.MaxRanges)+`]`)))
		if got := len(c.Records[0].RequiredFeatures); got != security.MaxRanges {
			t.Fatalf("%d features", got)
		}
	})
	t.Run("features past the bound", func(t *testing.T) {
		for name, extra := range map[string]string{"a valid name": `"extra"`, "a wrong type": `5`, "null": `null`} {
			in := catalogOf(recordWith(`"required_features":[` + features(security.MaxRanges) + `,` + extra + `]`))
			if c, err := Decode(in); err == nil || !strings.Contains(err.Error(), "too many required features") || !reflect.DeepEqual(c, security.Catalog{}) {
				t.Errorf("%s as the 33rd: want too many required features and the zero catalog, got %v", name, err)
			}
		}
	})
}

// A key from the input is echoed in an error only escaped and cut short, so a hostile key
// cannot put control characters or a megabyte of text into a log or a terminal.
func TestDecodeErrorsEchoKeysSafely(t *testing.T) {
	long := strings.Repeat("\u00e9", 40) // 80 bytes: the cut at 40 bytes falls between two characters
	skewed := "x" + long                 // 81 bytes: the cut at 40 bytes falls inside the 20th character
	for name, tc := range map[string]struct{ key, want, never string }{
		"control character":         {"a\\u0007b", `"a\ab"`, "\a"},
		"long key":                  {long, `"` + strings.Repeat("\u00e9", 20) + `"...`, long},
		"long key cut in character": {skewed, `"x` + strings.Repeat("\u00e9", 19) + `"...`, skewed},
		"long ascii key":            {strings.Repeat("k", 5000), `"` + strings.Repeat("k", 40) + `"...`, strings.Repeat("k", 41)},
	} {
		t.Run(name, func(t *testing.T) {
			in := strings.Replace(string(catalogOf(record("R1"))), `"revision":1,`, `"revision":1,"`+tc.key+`":1,`, 1)
			_, err := Decode([]byte(in))
			if err == nil || !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), tc.never) {
				t.Fatalf("want an unknown-field error containing %s and not the raw key, got %q", tc.want, err)
			}
		})
	}
}

// Every way Decode can fail returns the zero catalog, not a half-filled one.
func TestDecodeErrorsReturnTheZeroCatalog(t *testing.T) {
	synthetic, err := os.ReadFile("../../data/advisories/testdata/synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	replace := func(old, new string) []byte {
		if !bytes.Contains(synthetic, []byte(old)) {
			t.Fatalf("fixture lacks %q", old)
		}
		return bytes.Replace(synthetic, []byte(old), []byte(new), 1)
	}
	deep := `{"schema_version":1,"revision":1,"issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","records":[{"id":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}]}`
	for _, tc := range []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, "EOF"},
		{"not an object", []byte(`[]`), "expected {"},
		{"null document", []byte(`null`), "expected {"},
		{"scalar document", []byte(`1`), "expected {"},
		{"over the size bound", append([]byte(`{}`), bytes.Repeat([]byte(" "), maxBytes)...), "larger than"},
		{"invalid UTF-8", replace(`"synthetic test notice"`, "\"a\xffb\""), "UTF-8"},
		{"too deep", []byte(deep), "nests deeper"},
		{"syntax", []byte(`{"schema_version":`), ""},
		{"trailing comma", []byte(`{"schema_version":1,}`), ""},
		{"trailing data", append(append([]byte{}, synthetic...), []byte(` {}`)...), "trailing"},
		{"trailing text", append(append([]byte{}, synthetic...), []byte(`x`)...), "trailing"},
		{"duplicate top key", replace(`"revision": 1`, `"revision": 1, "revision": 1`), "duplicate"},
		{"duplicate escaped key", replace(`"schema_version": 1`, `"schema_version": 1, "schema_version": 1`), "duplicate"},
		{"duplicate record key", replace(`"id": "TEST-SSH-NOTICE"`, `"id": "TEST-SSH-NOTICE", "id": "TEST-SSH-NOTICE"`), "duplicate"},
		{"duplicate records key", replace(`"records": [`, `"records": [], "records": [`), "duplicate"},
		{"miscased key", replace(`"schema_version"`, `"Schema_version"`), "unknown field"},
		{"miscased record key", replace(`"id"`, `"ID"`), "unknown field"},
		{"unknown top key", replace(`"revision": 1`, `"revision": 1, "extra": 1`), "unknown field"},
		{"unknown record key", replace(`"id": "TEST-SSH-NOTICE"`, `"id": "TEST-SSH-NOTICE", "extra": 1`), "unknown field"},
		{"variant", replace(`"id": "TEST-SSH-NOTICE"`, `"id": "TEST-SSH-NOTICE", "variant": "gui"`), "unknown field"},
		{"missing top key", replace(`"revision": 1,`, ``), "missing"},
		{"missing record key", replace(`"component": "client",`, ``), "missing"},
		{"null scalar", replace(`"revision": 1`, `"revision": null`), "null"},
		{"null record scalar", replace(`"id": "TEST-SSH-NOTICE"`, `"id": null`), "null"},
		{"null array", replace(`"records": [`, `"records": null, "x": [`), ""},
		{"null optional", replace(`"required_features": ["ssh"]`, `"required_features": null`), "expected ["},
		{"null record", replace(`"records": [`, `"records": [null,`), "expected {"},
		{"wrong type", replace(`"revision": 1`, `"revision": "1"`), "revision"},
		{"negative revision", replace(`"revision": 1`, `"revision": -1`), "revision"},
		{"fractional revision", replace(`"revision": 1`, `"revision": 1.5`), "revision"},
		{"bad time", replace(`2026-01-01T00:00:00Z`, `invalid`), "issued_at"},
		{"records not an array", replace(`"records": [`, `"records": {"a": [`), ""},
		{"ranges not an array", replace(`"required_features": ["ssh"]`, `"ranges": {}`), "expected ["},
		{"range not an object", replace(`"required_features": ["ssh"]`, `"ranges": [5]`), "expected {"},
		{"unknown range key", replace(`"required_features": ["ssh"]`, `"ranges": [{"fixed": "1.2.0", "x": 1}]`), "unknown field"},
		{"duplicate range key", replace(`"required_features": ["ssh"]`, `"ranges": [{"fixed": "1.2.0", "fixed": "1.2.0"}]`), "duplicate"},
		{"null range value", replace(`"required_features": ["ssh"]`, `"ranges": [{"fixed": null}]`), "null"},
		{"feature of the wrong type", replace(`"required_features": ["ssh"]`, `"required_features": [5]`), ""},
		{"review state", replace(`"pending"`, `"imaginary"`), "invalid advisory review state"},
		{"validation after decoding", replace(`"revision": 1`, `"revision": 0`), "revision must be at least 1"},
		{"empty range", replace(`"required_features": ["ssh"]`, `"ranges": [{}]`), "empty range"},
		{"odd minor bound", replace(`"required_features": ["ssh"]`, `"ranges": [{"fixed": "1.33.257"}]`), "even minor"},
		{"build suffix in a bound", replace(`"required_features": ["ssh"]`, `"ranges": [{"fixed": "1.32.3-t0123456ab"}]`), "invalid fixed version"},
		{"os outside the vocabulary", replace(`"id": "TEST-SSH-NOTICE"`, `"id": "TEST-SSH-NOTICE", "os": "macOS"`), "unsupported advisory os"},
		{"control character", replace(`"synthetic test notice"`, `"a\u0007b"`), "control character"},
		{"newline in text", replace(`"synthetic test notice"`, `"a\nb"`), "control character"},
		{"time before the floor", replace(`"reviewed_at": "2025-12-01T00:00:00Z"`, `"reviewed_at": "2018-12-31T23:59:59Z"`), "before 2019-01-01T00:00:00Z"},
		{"non-UTC time", replace(`"issued_at": "2026-01-01T00:00:00Z"`, `"issued_at": "2026-01-01T01:00:00+01:00"`), "UTC offset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Decode(tc.in)
			if err == nil {
				t.Fatalf("accepted %q", tc.name)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
			if !reflect.DeepEqual(c, security.Catalog{}) {
				t.Errorf("an error must return the zero catalog, got %+v", c)
			}
		})
	}
}

func TestDecodeLimitsAreExact(t *testing.T) {
	base := string(catalogOf(record("R1")))
	// Insignificant white space pads a valid catalog to the limit without changing it.
	pad := func(n int) []byte { return []byte(base + strings.Repeat(" ", n-len(base))) }
	c := mustDecode(t, pad(maxBytes))
	if len(c.Records) != 1 || c.Digest == "" {
		t.Fatalf("a catalog of exactly %d bytes must decode: %+v", maxBytes, c)
	}
	if _, err := Decode(pad(maxBytes + 1)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("one byte over the limit: %v", err)
	}
	// Nesting of 32 levels passes the pre-scan (and then fails on the type); 33 does not.
	nested := func(depth int) []byte {
		return []byte(`{"schema_version":1,"revision":1,"issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","records":[{"id":` +
			strings.Repeat("[", depth) + strings.Repeat("]", depth) + `}]}`)
	}
	// records, record, id: three levels are used before the nested value starts.
	if _, err := Decode(nested(maxDepth - 3)); err == nil || strings.Contains(err.Error(), "nests deeper") {
		t.Fatalf("depth %d must pass the pre-scan and fail later: %v", maxDepth, err)
	}
	if _, err := Decode(nested(maxDepth - 2)); err == nil || !strings.Contains(err.Error(), "nests deeper") {
		t.Fatalf("depth %d must fail the pre-scan: %v", maxDepth+1, err)
	}
}

// The digest is the SHA-256 of the exact input bytes: another spelling of the same
// catalog has another digest, and nothing in the input can set it.
func TestDecodeDigestIsOfTheExactBytes(t *testing.T) {
	compact := catalogOf(record("R1"))
	spaced := append([]byte("\n"), compact...)
	a, b := mustDecode(t, compact), mustDecode(t, spaced)
	sum := sha256.Sum256(compact)
	if a.Digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest %s is not the SHA-256 of the input", a.Digest)
	}
	if a.Digest == b.Digest {
		t.Fatal("two spellings of one catalog must not share a digest: it is not a content identity")
	}
	a.Digest, b.Digest = "", ""
	if !reflect.DeepEqual(a, b) {
		t.Fatal("the two spellings must decode to the same catalog")
	}
	if _, err := Decode(bytes.Replace(compact, []byte(`"records"`), []byte(`"digest":"x","records"`), 1)); err == nil {
		t.Fatal("a digest member in the input must be refused")
	}
}

const richCatalog = `{
  "schema_version": 1, "revision": 7,
  "issued_at": "2026-10-01T00:00:00Z", "expires_at": "2026-10-08T00:00:00Z",
  "records": [
    {"id": "R-A", "revision": "3", "component": "client", "version_role": "running_daemon", "os": "linux",
     "ranges": [{"introduced": "1.0.0", "fixed": "1.2.0"}, {"introduced": "1.4.0"}, {"fixed": "0.8.0"}],
     "required_features": ["ssh", "serve"], "source": "https://example.invalid/a", "severity": "high",
     "published_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-02T00:00:00Z", "reviewed_at": "2026-09-30T00:00:00Z",
     "review_expires_at": "2026-12-30T00:00:00Z", "source_checked_at": "2026-09-30T00:00:00Z", "review_state": "approved",
     "mitigation": "Update Tailscale; café 日本"},
    {"id": "R-B", "revision": "1", "component": "client", "version_role": "api_reported", "source": "s", "severity": "unknown",
     "reviewed_at": "2026-09-30T00:00:00Z", "review_expires_at": "2026-12-30T00:00:00Z", "review_state": "pending"},
    {"id": "R-C", "revision": "2", "component": "client", "version_role": "local_cli", "os": "macos", "ranges": [], "required_features": [],
     "source": "s", "severity": "critical", "reviewed_at": "2026-09-30T00:00:00Z", "review_expires_at": "2026-12-30T00:00:00Z", "review_state": "withdrawn"}
  ]
}`

// stdDecode is the standard library's strict decoder, the reading the streaming decoder
// must agree with on every valid input.
func stdDecode(t *testing.T, data []byte) security.Catalog {
	t.Helper()
	var want security.Catalog
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&want); err != nil {
		t.Fatal(err)
	}
	return want
}

// On valid input the streaming decoder must produce what the standard library's strict
// decoder produces, so the stricter reading changes what is refused, not what is accepted.
func TestDecodeAgreesWithTheStandardDecoderOnValidCatalogs(t *testing.T) {
	inputs := map[string][]byte{
		"rich":          []byte(richCatalog),
		"empty records": []byte(`{"schema_version":1,"revision":1,"issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","records":[]}`),
	}
	for _, path := range []string{"../../data/advisories/testdata/synthetic.json", "../../data/advisories/cve-2022-41925.json"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		inputs[path] = data
	}
	for name, data := range inputs {
		t.Run(name, func(t *testing.T) {
			got := mustDecode(t, data)
			want := stdDecode(t, data)
			want.Digest = got.Digest
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("decoders differ:\n got %+v\nwant %+v", got, want)
			}
			if got.Records == nil {
				t.Fatal("an empty records array must decode to an empty slice, as the standard decoder does")
			}
		})
	}
}
