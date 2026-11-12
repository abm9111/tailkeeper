//go:build !windows

package releasebundle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildRejectsSymlinkDocument(t *testing.T) {
	root := fixtureRoot(t)
	u := filepath.Join(t.TempDir(), "universal")
	if err := os.WriteFile(u, fat(thin(0x01000007, 3), thin(0x0100000c, 0), false), 0600); err != nil {
		t.Fatal(err)
	}
	opts := BuildOptions{Version: "1.2.3", UniversalPath: u, RootDir: root, OutputPath: filepath.Join(t.TempDir(), "bundle")}
	if err := Build(opts); err != nil {
		t.Fatal(err)
	}
	opts.OutputPath = filepath.Join(t.TempDir(), "bundle")
	doc := filepath.Join(root, "NOTICE")
	if err := os.Remove(doc); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "LICENSE"), doc); err != nil {
		t.Fatal(err)
	}
	if err := Build(opts); err == nil {
		t.Fatal("accepted symlink document")
	}
}

func TestVerifyRejectsSymlinkThinInput(t *testing.T) {
	bundle, dist := fixtureBuild(t, fixtureRoot(t), false)
	version := "0.6.0-SNAPSHOT-abc123"
	if err := Verify(bundle, dist, version); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dist, "tailkeeper_darwin_arm64_v8.0", "tailkeeper")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bundle, path); err != nil {
		t.Fatal(err)
	}
	if err := Verify(bundle, dist, version); err == nil {
		t.Fatal("accepted symlink thin input")
	}
}

func TestVerifyRejectsSymlinkThinBuildDirectory(t *testing.T) {
	bundle, dist := fixtureBuild(t, fixtureRoot(t), false)
	version := "0.6.0-SNAPSHOT-abc123"
	if err := Verify(bundle, dist, version); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dist, "tailkeeper_darwin_amd64_v1"), filepath.Join(dist, "tailkeeper_darwin_amd64_symlink")); err != nil {
		t.Fatal(err)
	}
	if err := Verify(bundle, dist, version); err == nil {
		t.Fatal("accepted symlink build directory")
	}
}
