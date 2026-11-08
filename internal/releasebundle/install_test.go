package releasebundle

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Extraction here is deliberately local and does not execute or install the image.
func TestMCPBInstallDoesNotReplaceExternalState(t *testing.T) {
	bundle, _ := fixtureBuild(t, fixtureRoot(t), false)
	root := t.TempDir()
	sentinels := map[string][]byte{
		filepath.Join(root, "direct", "tailkeeper"):    []byte("existing direct binary"),
		filepath.Join(root, "config", "config.hujson"): []byte("existing config"),
		filepath.Join(root, "state", "state.json"):     []byte("existing state"),
	}
	for path, content := range sentinels {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	packageDir := filepath.Join(root, "package")
	for attempt := 0; attempt < 2; attempt++ {
		if err := os.Mkdir(packageDir, 0o700); err != nil {
			t.Fatal(err)
		}
		z, err := zip.OpenReader(bundle)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range z.File {
			if !filepath.IsLocal(entry.Name) {
				t.Fatalf("unsafe entry %q", entry.Name)
			}
			path := filepath.Join(packageDir, filepath.FromSlash(entry.Name))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			r, err := entry.Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, entry.Mode().Perm()); err != nil {
				t.Fatal(err)
			}
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		for path, want := range sentinels {
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("external sentinel changed: %s: %v", path, err)
			}
		}
		if err := os.RemoveAll(packageDir); err != nil {
			t.Fatal(err)
		}
		for path, want := range sentinels {
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("external sentinel changed after removal: %s: %v", path, err)
			}
		}
	}
}
