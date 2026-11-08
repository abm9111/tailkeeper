package securitypack

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestPackGoldenMinimal(t *testing.T) {
	in := validPackInput()
	in.Sources = nil
	pack, err := newPack(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Encode(pack)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"catalog":{"digest":"` + strings.Repeat("a", 64) + `","sources":[]},"catalog_schema_version":1,"evaluation":{"at":"2026-03-01T00:00:00Z","work_budget":0},"evaluator_version":1,"expected":{"counts":{"devices":0,"features":0,"platforms":0,"policies":0,"versions":0},"report":{"affected":0,"not_affected":0,"potentially_affected":0,"sha256":"` + strings.Repeat("b", 64) + `","status":"partial","total_findings":0,"unknown":0}},"format":"tailkeeper-evidence-pack","pack_schema_version":1,"report_schema_version":1,"snapshot":{"context":"ctx-local-only","observed_at":"2026-03-01T00:00:00Z","scope":"local"}}`
	digest := sha256.Sum256(append([]byte("tailkeeper-evidence-pack/1\n"), []byte(body)...))
	want := []byte(fmt.Sprintf("{\"body\":%s,\"integrity\":\"sha256:%x\"}\n", body, digest))
	if !bytes.Equal(got, want) {
		t.Fatal("minimal pack differs from independent literal")
	}
	if _, _, err := Decode(want, nil); err != nil {
		t.Fatalf("literal decode: %v", err)
	}
}
