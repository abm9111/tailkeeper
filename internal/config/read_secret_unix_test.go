//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Checking a safe pathname must not approve a different unsafe descriptor when
// an ancestor switches between inspection, permission checking and opening.
func TestSecretDescriptorRejectsDifferentPathApproval(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "unsafe"), filepath.Join(root, "safe")
	for _, dir := range []string{a, b} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []struct {
		dir  string
		mode os.FileMode
	}{{a, 0o644}, {b, 0o600}} {
		p := filepath.Join(f.dir, "secret")
		if err := os.WriteFile(p, []byte(strings.Repeat("x", 1<<20)), f.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, f.mode); err != nil {
			t.Fatal(err)
		}
	}
	// Exactly-at-cap private data is a known-positive; rejecting everything is wrong.
	if data, err := ReadSecretFile(filepath.Join(b, "secret")); err != nil || len(data) != 1<<20 {
		t.Fatalf("private file at cap rejected: %v", err)
	}
	link := filepath.Join(root, "current")
	switchTo := func(dir string) {
		t.Helper()
		if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
	}
	switchTo(a)
	path := filepath.Join(link, "secret")
	want, err := inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	switchTo(b)
	if err := CheckSecretFile(path); err != nil {
		t.Fatal(err)
	}
	switchTo(a)
	data, err := readCheckedLimit(path, want, 1<<20)
	if !isCode(err, tkerr.ConfigUnsafe) || len(data) != 0 {
		t.Fatal("read unsafe descriptor after pathname approved another file")
	}
}
