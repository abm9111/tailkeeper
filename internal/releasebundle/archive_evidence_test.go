package releasebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchiveCanonicalHashEvidence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	name := filepath.Join(root, "tmp", "syft-archive-contents-123", "tailkeeper")
	sum := sha256.Sum256([]byte("trusted thin"))
	digest := hex.EncodeToString(sum[:])
	wrong := strings.Repeat("0", 64)
	cases := []struct {
		name, hash string
		accept     bool
	}{
		{"canonical", fmt.Sprintf(`{"alg":"SHA-256","content":%q}`, digest), true},
		{"wrong canonical shadowed", fmt.Sprintf(`{"alg":"SHA-256","content":%q,"Content":%q}`, wrong, digest), false},
		{"missing canonical content", fmt.Sprintf(`{"alg":"SHA-256","Content":%q}`, digest), false},
		{"missing canonical algorithm", fmt.Sprintf(`{"Alg":"SHA-256","content":%q}`, digest), false},
		{"both aliases", fmt.Sprintf(`{"Alg":"SHA-256","Content":%q}`, digest), false},
		{"non-string canonical algorithm", fmt.Sprintf(`{"alg":42,"content":%q}`, digest), false},
		{"non-string canonical content", `{"alg":"SHA-256","content":42}`, false},
		{"wrong canonical algorithm", fmt.Sprintf(`{"alg":"SHA-1","Alg":"SHA-256","content":%q}`, digest), false},
		{"canonical unaffected by aliases", fmt.Sprintf(`{"alg":"SHA-256","Alg":"SHA-1","content":%q,"Content":%q}`, digest, wrong), true},
		{"duplicate canonical keys", fmt.Sprintf(`{"alg":"SHA-256","content":%q,"content":%q}`, wrong, digest), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"metadata":{},"components":[{"type":"file","name":%q,"bom-ref":"stable","hashes":[%s]},{"type":"library","name":"go","purl":"pkg:golang/example@v1"}],"dependencies":[{"ref":"stable","dependsOn":[]}]}`, name, tc.hash))
			clean, err := scrubArchiveSBOM(raw, root, "tailkeeper", digest)
			if (err == nil) != tc.accept {
				t.Fatalf("accepted=%t, want %t, error=%v", err == nil, tc.accept, err)
			}
			if tc.accept {
				var doc struct {
					Components   []map[string]json.RawMessage `json:"components"`
					Dependencies []struct {
						Ref string `json:"ref"`
					} `json:"dependencies"`
				}
				if err = json.Unmarshal(clean, &doc); err != nil {
					t.Fatal(err)
				}
				if string(doc.Components[0]["bom-ref"]) != `"stable"` || len(doc.Dependencies) != 1 || doc.Dependencies[0].Ref != "stable" {
					t.Fatal("component or dependency reference changed")
				}
			}
		})
	}
}

func TestCanonicalGoModuleEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, component string
		accept          bool
	}{
		{"canonical", `{"purl":"pkg:golang/example@v1"}`, true},
		{"alias only", `{"PURL":"pkg:golang/example@v1"}`, false},
		{"canonical non-go with alias", `{"purl":"pkg:npm/example@v1","PURL":"pkg:golang/example@v1"}`, false},
		{"canonical go with alias", `{"purl":"pkg:golang/example@v1","PURL":"pkg:npm/example@v1"}`, true},
		{"missing", `{"name":"example"}`, false},
		{"invalid canonical type", `{"purl":42}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"metadata":{},"components":[%s]}`, tc.component))
			_, err := bindSBOM(raw, "archive.tar.gz", []byte("archive fixture"))
			if (err == nil) != tc.accept {
				t.Fatalf("accepted=%t, want %t, error=%v", err == nil, tc.accept, err)
			}
		})
	}
}
