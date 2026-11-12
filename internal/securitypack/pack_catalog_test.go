package securitypack

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

func syntheticSource(mitigation string) packSource {
	data := []byte(`{"schema_version":1,"revision":1,"issued_at":"2026-02-01T00:00:00Z","expires_at":"2027-02-01T00:00:00Z","records":[{"id":"SYNTHETIC-1","revision":"1","component":"client","version_role":"running_daemon","source":"synthetic","severity":"low","reviewed_at":"2026-01-01T00:00:00Z","review_expires_at":"2027-01-01T00:00:00Z","review_state":"approved","ranges":[{"fixed":"1.2.3"}],"mitigation":"` + mitigation + `"}]}`)
	digest := sha256.Sum256(data)
	return packSource{Name: "synthetic", Data: data, SHA256: fmt.Sprintf("%x", digest)}
}

func TestPackCatalogDecodedTripwire(t *testing.T) {
	shape := "ts" + "key-" + "api-"
	if err := tripwire.Check([]byte(shape)); err == nil {
		t.Fatal("positive control was not detected")
	}
	good := syntheticSource("ordinary")
	if _, err := advisory.Decode(good.Data); err != nil {
		t.Fatalf("synthetic oracle: %v", err)
	}
	catalog := packCatalog{Digest: strings.Repeat("a", 64), Sources: []packSource{good}}
	if err := checkPackCatalog(catalog); err != nil {
		t.Fatalf("valid synthetic catalog: %v", err)
	}
	bad := syntheticSource(`\u0074skey-api-`)
	if _, err := advisory.Decode(bad.Data); err != nil {
		t.Fatalf("semantic oracle: %v", err)
	}
	catalog.Sources = []packSource{bad}
	if err := checkPackCatalog(catalog); !errors.Is(err, ErrSecretShaped) {
		t.Fatalf("decoded secret shape: %v", err)
	}
	catalog.Sources[0].SHA256 = strings.Repeat("b", 64)
	if err := checkPackCatalog(catalog); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("tampered digest: %v", err)
	}
	catalog.Sources = nil
	if err := checkPackCatalog(catalog); err != nil {
		t.Fatalf("empty catalog sources: %v", err)
	}
}

func TestPackCatalogEscapedSecretEndToEnd(t *testing.T) {
	bad := syntheticSource(`\u0074skey-api-`)
	in := validPackInput()
	in.Sources[0].Data = bad.Data
	if _, err := newPack(in, nil); !errors.Is(err, ErrSecretShaped) {
		t.Fatalf("producer did not scan decoded source: %v", err)
	}
	valid, err := newPack(validPackInput(), nil)
	if err != nil {
		t.Fatal(err)
	}
	valid.envelope.Body.Catalog.Sources[0] = bad
	_, valid.envelope.Integrity, err = packSealInput(valid.envelope.Body)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodePackEnvelope(valid.envelope)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = Decode(wire, nil)
	if !errors.Is(err, ErrSecretShaped) {
		t.Fatalf("decoder did not scan decoded source: %v", err)
	}
}

func syntheticManyRecords(count int) packSource {
	base := string(syntheticSource("ordinary").Data)
	marker := `"records":[`
	position := strings.Index(base, marker) + len(marker)
	prefix := base[:position]
	record := strings.TrimSuffix(base[position:], `]}`)
	rows := make([]string, 0, count)
	for i := 0; i < count; i++ {
		rows = append(rows, strings.Replace(record, "SYNTHETIC-1", fmt.Sprintf("SYNTHETIC-%d", i), 1))
	}
	data := []byte(prefix + strings.Join(rows, ",") + `]}`)
	digest := sha256.Sum256(data)
	return packSource{Name: "synthetic", Data: data, SHA256: fmt.Sprintf("%x", digest)}
}

func TestPackCatalogCumulativeRecordBound(t *testing.T) {
	full := syntheticManyRecords(64)
	partial := syntheticManyRecords(40)
	catalog := packCatalog{Digest: strings.Repeat("a", 64)}
	for i := 0; i < 15; i++ {
		source := full
		source.Name = fmt.Sprintf("source-%02d", i)
		catalog.Sources = append(catalog.Sources, source)
	}
	partial.Name = "source-15"
	catalog.Sources = append(catalog.Sources, partial)
	if err := checkPackCatalog(catalog); err != nil {
		t.Fatalf("1000 records: %v", err)
	}
	extra := syntheticManyRecords(41)
	extra.Name = "source-15"
	catalog.Sources[len(catalog.Sources)-1] = extra
	if err := checkPackCatalog(catalog); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("1001 records: %v", err)
	}
}

func TestPackCatalogRangeAndFeatureBounds(t *testing.T) {
	for _, kind := range []string{"ranges", "features"} {
		for _, count := range []int{32, 33} {
			source := syntheticSource("ordinary")
			rows := make([]string, 0, count)
			for i := 0; i < count; i++ {
				if kind == "ranges" {
					rows = append(rows, fmt.Sprintf(`{"introduced":"1.2.%d","fixed":"1.2.%d"}`, 2*i+1, 2*i+2))
				} else {
					rows = append(rows, fmt.Sprintf(`"feature-%d"`, i))
				}
			}
			data := string(source.Data)
			if kind == "ranges" {
				data = strings.Replace(data, `"ranges":[{"fixed":"1.2.3"}]`, `"ranges":[`+strings.Join(rows, ",")+`]`, 1)
			} else {
				data = strings.Replace(data, `"mitigation":`, `"required_features":[`+strings.Join(rows, ",")+`],"mitigation":`, 1)
			}
			source.Data = []byte(data)
			digest := sha256.Sum256(source.Data)
			source.SHA256 = fmt.Sprintf("%x", digest)
			err := checkPackCatalog(packCatalog{Digest: strings.Repeat("a", 64), Sources: []packSource{source}})
			if count == 32 && err != nil {
				t.Fatalf("32 %s: %v", kind, err)
			}
			if count == 33 && !errors.Is(err, ErrInvalidPack) {
				t.Fatalf("33 %s: %v", kind, err)
			}
		}
	}
}

func TestPackCatalogEscapesInDecodedFreeTextFields(t *testing.T) {
	shape := `\u0074skey-api-`
	tests := []struct{ name, old, replacement string }{
		{"id", `"id":"SYNTHETIC-1"`, `"id":"` + shape + `"`},
		{"revision", `"revision":"1"`, `"revision":"` + shape + `"`},
		{"component", `"component":"client"`, `"component":"` + shape + `"`},
		{"source", `"source":"synthetic"`, `"source":"` + shape + `"`},
		{"mitigation", `"mitigation":"ordinary"`, `"mitigation":"` + shape + `"`},
		{"feature", `"mitigation":"ordinary"`, `"required_features":["` + shape + `"],"mitigation":"ordinary"`},
	}
	valid, err := newPack(validPackInput(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source := syntheticSource("ordinary")
			if !strings.Contains(string(source.Data), tc.old) {
				t.Fatal("fixture replacement did not match")
			}
			source.Data = []byte(strings.Replace(string(source.Data), tc.old, tc.replacement, 1))
			if _, err := advisory.Decode(source.Data); err != nil {
				t.Fatalf("synthetic advisory oracle: %v", err)
			}
			digest := sha256.Sum256(source.Data)
			source.SHA256 = fmt.Sprintf("%x", digest)
			in := validPackInput()
			in.Sources[0].Data = source.Data
			if _, err := newPack(in, nil); !errors.Is(err, ErrSecretShaped) {
				t.Fatalf("producer scan: %v", err)
			}
			envelope := valid.envelope
			envelope.Body.Catalog.Sources = []packSource{source}
			_, envelope.Integrity, err = packSealInput(envelope.Body)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := encodePackEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Decode(wire, nil); !errors.Is(err, ErrSecretShaped) {
				t.Fatalf("decoder scan: %v", err)
			}
		})
	}
}
