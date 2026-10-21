//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// inspect takes the identity from a handle that does not follow a reparse point, so a
// symbolic link is refused where the configuration is inspected. An account that may not
// make symbolic links logs it and returns, except where CI is set: there a runner that
// cannot make a link fails the test, so that it never passes for nothing.
func TestInspectRefusesAReparsePoint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "read.env")
	if err := os.WriteFile(target, []byte("A=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.env")
	if err := os.Symlink(target, link); err != nil {
		// Not a skip: a skip on Windows would have to be listed in docs/windows.md.
		if os.Getenv("CI") != "" {
			t.Fatalf("this runner cannot make a symbolic link, so the test proves nothing: %v", err)
		}
		t.Logf("this account cannot make a symbolic link: %v", err)
		return
	}
	if _, err := inspect(link); err == nil {
		t.Error("inspect accepted a symbolic link")
	}
}

// Windows reads no owner: OwnedBy refuses what CheckOwnership refuses there, a file that
// is not a regular one, and nothing else.
func TestOwnedByOnWindowsRefusesOnlyANonRegularFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "invariants.hujson")
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := OwnedBy(0)(p, fi); err != nil {
		t.Errorf("a regular file: %v", err)
	}
	dir, err := os.Stat(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := tkerr.As(OwnedBy(0)(p, dir)); !ok || e.Code != tkerr.ConfigUnsafe {
		t.Errorf("a directory: %v", e)
	}
}
