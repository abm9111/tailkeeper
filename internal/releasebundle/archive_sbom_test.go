package releasebundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func archiveFixture(t *testing.T, target archiveTarget) (string, string) {
	t.Helper()
	dist := t.TempDir()
	dir := filepath.Join(dist, "tailkeeper_"+target.os+"_"+target.arch+"_v1")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, target.binary), []byte("binary fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dist, "tailkeeper_1.2.3_"+target.os+"_"+target.arch+target.suffix)
	if err := os.WriteFile(archive, []byte("binary fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	return archive, dist
}

func TestArchiveSBOMTargetsAndBinding(t *testing.T) {
	for _, target := range archiveTargets {
		t.Run(target.os+target.arch, func(t *testing.T) {
			archive, dist := archiveFixture(t, target)
			out := filepath.Join(dist, "result")
			if err := WriteArchiveSBOM(context.Background(), archive, dist, out, syftHelper(t, "archive")); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Metadata struct {
					Component struct {
						Name   string `json:"name"`
						Hashes []struct {
							Content string `json:"content"`
						} `json:"hashes"`
					} `json:"component"`
				} `json:"metadata"`
				Components []struct {
					Name string `json:"name"`
				} `json:"components"`
			}
			if err = json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256([]byte("binary fixture"))
			if doc.Metadata.Component.Name != filepath.Base(archive) || len(doc.Metadata.Component.Hashes) != 1 || doc.Metadata.Component.Hashes[0].Content != hex.EncodeToString(h[:]) || doc.Components[0].Name != target.binary {
				t.Fatal("incorrect binding or name")
			}
			if err = WriteArchiveSBOM(context.Background(), archive, dist, out, syftHelper(t, "archive")); err == nil {
				t.Fatal("overwrote output")
			}
		})
	}
}
func TestArchiveTargetValidation(t *testing.T) {
	for _, name := range []string{"tailkeeper_01.2.3_linux_amd64.tar.gz", "tailkeeper_1.2.3_windows_arm64.zip", "tailkeeper_1.2.3_linux_amd64.zip", "tailkeeper_1.2.3_darwin_universal.tar.gz", "other_1.2.3_linux_amd64.tar.gz"} {
		if _, err := archiveTargetFor(name); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	target := archiveTargets[0]
	archive, dist := archiveFixture(t, target)
	helper := syftHelper(t, "marker-archive")
	marker := filepath.Join(filepath.Dir(helper), "invoked")
	thin := filepath.Join(dist, "tailkeeper_darwin_amd64_v1", target.binary)
	if err := os.Remove(thin); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dist, "out")
	if err := WriteArchiveSBOM(context.Background(), archive, dist, out, helper); err == nil {
		t.Fatal("accepted missing thin")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("invoked helper before validation")
	}
	if err := os.WriteFile(thin, []byte("binary fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dist, "tailkeeper_darwin_amd64_v2")
	if err := os.Mkdir(extra, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extra, target.binary), []byte("binary fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteArchiveSBOM(context.Background(), archive, dist, out, helper); err == nil {
		t.Fatal("accepted duplicate thin")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("invoked helper before validation")
	}
}
func TestScrubArchiveSBOMStrict(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	name := filepath.Join(root, "tmp", "syft-archive-contents-123", "tailkeeper")
	h := sha256.Sum256([]byte("binary fixture"))
	digest := hex.EncodeToString(h[:])
	component := func(n, typ, hashes string) string {
		return fmt.Sprintf(`{"type":%q,"name":%q,"hashes":%s}`, typ, n, hashes)
	}
	hash := fmt.Sprintf(`[{"alg":"SHA-256","content":%q}]`, digest)
	good := component(name, "file", hash)
	doc := func(components, other string) []byte {
		return []byte(fmt.Sprintf(`{"metadata":%s,"components":[%s,{"type":"library","name":"go","purl":"pkg:golang/example"}]}`, other, components))
	}
	if _, err := scrubArchiveSBOM(doc(good, `{}`), root, "tailkeeper", digest); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, components, metadata string }{
		{"zero", `{"type":"file","name":"else"}`, `{}`},
		{"duplicate", good + "," + good, `{}`},
		{"type", component(name, "library", hash), `{}`},
		{"wrong hash", component(name, "file", `[{"alg":"SHA-256","content":"bad"}]`), `{}`},
		{"conflict", component(name, "file", strings.TrimSuffix(hash, "]")+`,{"alg":"SHA-256","content":"bad"}]`), `{}`},
		{"no hash", component(name, "file", `[]`), `{}`},
		{"malformed hashes", component(name, "file", `"bad"`), `{}`},
		{"escaped metadata path", good, `{"path":"` + strings.ReplaceAll(root, "/", `\u002f`) + `/home"}`},
		{"escaped metadata key", good, `{"` + strings.ReplaceAll(root, "/", `\u002f`) + `/home":true}`},
		{"empty random", component(filepath.Join(root, "tmp", "syft-archive-contents-", "tailkeeper"), "file", hash), `{}`},
		{"nested", component(filepath.Join(root, "tmp", "syft-archive-contents-1", "nested", "tailkeeper"), "file", hash), `{}`},
		{"metadata", good, fmt.Sprintf(`{"%s":true}`, root)},
		{"mixed", good + "," + component(filepath.Join(root, "home", "bad"), "file", hash), `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := scrubArchiveSBOM(doc(tc.components, tc.metadata), root, "tailkeeper", digest); err == nil {
				t.Fatal("accepted unsafe document")
			}
		})
	}
}

func TestArchiveSBOMRejectsInputAndToolFailures(t *testing.T) {
	target := archiveTargets[0]
	archive, dist := archiveFixture(t, target)
	helper := syftHelper(t, "marker-archive")
	marker := filepath.Join(filepath.Dir(helper), "invoked")
	out := filepath.Join(dist, "output")
	if err := os.WriteFile(out, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                     string
		ctx                      context.Context
		archive, dist, out, tool string
	}{
		{"nil context", nil, archive, dist, out, helper},
		{"missing archive", context.Background(), "", dist, out, helper},
		{"missing dist", context.Background(), archive, "", out, helper},
		{"missing output", context.Background(), archive, dist, "", helper},
		{"relative tool", context.Background(), archive, dist, out, "relative"},
		{"bad filename", context.Background(), filepath.Join(dist, "bad"), dist, out, helper},
		{"absent archive", context.Background(), filepath.Join(dist, "other", filepath.Base(archive)), dist, out, helper},
		{"absent dist", context.Background(), archive, filepath.Join(dist, "missing"), out, helper},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := WriteArchiveSBOM(tc.ctx, tc.archive, tc.dist, tc.out, tc.tool); err == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("helper invoked for invalid input")
	}
	for _, mode := range []string{"wrong-archive", "failure-archive", "empty-output-archive", "empty-components-archive", "leak-archive"} {
		t.Run(mode, func(t *testing.T) {
			if err := WriteArchiveSBOM(context.Background(), archive, dist, out, syftHelper(t, mode)); err == nil {
				t.Fatal("accepted invalid tool result")
			}
		})
	}
	b, err := os.ReadFile(out)
	if err != nil || string(b) != "preserve" {
		t.Fatal("existing output changed")
	}

}

func TestArchiveSBOMStagingFailuresAndCleanup(t *testing.T) {
	archive, dist := archiveFixture(t, archiveTargets[0])
	parent := t.TempDir()
	helper := syftHelper(t, "marker-archive")
	marker := filepath.Join(filepath.Dir(helper), "invoked")
	for _, kind := range []string{"temp-root", "root-lookup", "control-config", "archive-write"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "temp-root" {
				if err := os.WriteFile(filepath.Join(parent, "regular-parent"), []byte("x"), 0600); err != nil && !os.IsExist(err) {
					t.Fatal(err)
				}
			}
			root := ""
			ops := obstructSBOMStage(kind, parent, &root)
			if kind == "archive-write" {
				ops.writeFile = func(path string, data []byte, mode os.FileMode) error {
					if filepath.Base(path) == "archive.tar.gz" {
						if err := os.Mkdir(path, 0700); err != nil {
							return err
						}
					}
					return os.WriteFile(path, data, mode)
				}
			}
			out := filepath.Join(t.TempDir(), "out")
			if err := os.WriteFile(out, []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := writeArchiveSBOMWith(context.Background(), archive, dist, out, helper, ops); err == nil {
				t.Fatal("accepted staging error")
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("invoked helper on staging error")
			}
			if root != "" {
				if _, err := os.Stat(root); !os.IsNotExist(err) {
					t.Fatal("temporary root retained")
				}
			}
			b, err := os.ReadFile(out)
			if err != nil || string(b) != "preserve" {
				t.Fatal("existing output changed")
			}
		})
	}
}

func TestArchiveSBOMMalformedDocuments(t *testing.T) {
	for _, raw := range []string{`bad`, `null`, `{}`, `{"components":"bad"}`, `{"components":[{"name":1}]}`, `{"components":[{"name":"x","type":1}]}`} {
		if _, err := scrubArchiveSBOM([]byte(raw), "/private/root", "tailkeeper", "digest"); err == nil {
			t.Errorf("accepted malformed document %s", raw)
		}
	}
}
