//go:build !windows

package releasebundle

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveSBOMRejectsSymlinkThin(t *testing.T) {
	target := archiveTargets[0]
	archive, dist := archiveFixture(t, target)
	helper := syftHelper(t, "marker-archive")
	thin := filepath.Join(dist, "tailkeeper_darwin_amd64_v1", target.binary)
	if err := os.Remove(thin); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(archive, thin); err != nil {
		t.Fatal(err)
	}
	if err := WriteArchiveSBOM(context.Background(), archive, dist, filepath.Join(dist, "out"), helper); err == nil {
		t.Fatal("accepted symlink thin")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(helper), "invoked")); !os.IsNotExist(err) {
		t.Fatal("helper invoked for symlink")
	}
}

func TestArchiveSBOMRejectsSymlinkThinDirectory(t *testing.T) {
	archive, dist := archiveFixture(t, archiveTargets[0])
	helper := syftHelper(t, "marker-archive")
	if err := os.Symlink(filepath.Join(dist, "tailkeeper_darwin_amd64_v1"), filepath.Join(dist, "tailkeeper_darwin_amd64_v2")); err != nil {
		t.Fatal(err)
	}
	if err := WriteArchiveSBOM(context.Background(), archive, dist, filepath.Join(dist, "out"), helper); err == nil {
		t.Fatal("accepted symlink directory")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(helper), "invoked")); !os.IsNotExist(err) {
		t.Fatal("helper invoked for symlink")
	}
}
