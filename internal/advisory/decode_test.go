package advisory

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/security"
)

func TestRejectDuplicateAndUnknownFields(t *testing.T) {
	for _, input := range []string{`{"schema_version":1,"schema_\u0076ersion":1}`, `{"Schema_version":1}`, `{} {}`} {
		if _, err := Decode([]byte(input)); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestSyntheticCatalog(t *testing.T) {
	data, err := os.ReadFile("../../data/advisories/testdata/synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Decode(data)
	if err != nil || len(c.Records) != 1 || c.Digest == "" {
		t.Fatalf("%v %v", c, err)
	}
}
func FuzzDecode(f *testing.F) {
	for _, s := range []string{`{"schema_version":1,"schema_\u0076ersion":2}`, `[[[[[[]]]]]]`, `{"issued_at":"bad"}`, `{"records":[{"ranges":[{},{}]}]}`,
		richCatalog, string(catalogOf(record("R1"))), `{"records":[null]}`, `{"records":[{"required_features":[null]}]}`, `{"records":[{"variant":"x"}]}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := Decode(b)
		if err != nil {
			if !reflect.DeepEqual(c, security.Catalog{}) {
				t.Fatalf("an error returned a non-zero catalog: %+v", c)
			}
			return
		}
		if err := security.ValidateCatalog(c); err != nil {
			t.Fatalf("Decode accepted a catalog that ValidateCatalog refuses: %v", err)
		}
		if c.Digest == "" || len(c.Records) > security.MaxCatalogRecords {
			t.Fatalf("an accepted catalog has no digest or too many records: %d", len(c.Records))
		}
	})
}

func TestStrictWireFailures(t *testing.T) {
	data, err := os.ReadFile("../../data/advisories/testdata/synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, old, new string }{
		{"duplicate escaped", `"schema_version": 1`, `"schema_version": 1, "schema_\u0076ersion": 1`},
		{"miscased", `"schema_version"`, `"Schema_version"`},
		{"null", `"revision": 1`, `"revision": null`},
		{"bad time", `2026-01-01T00:00:00Z`, `invalid`},
		{"bad review", `"pending"`, `"imaginary"`},
		{"empty range", `"required_features": ["ssh"]`, `"ranges": [{}]`},
		{"trailing", `}`, `} {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(string(data), tc.old, tc.new, 1)
			if _, err := Decode([]byte(input)); err == nil {
				t.Fatal("accepted invalid catalog")
			}
		})
	}
}
