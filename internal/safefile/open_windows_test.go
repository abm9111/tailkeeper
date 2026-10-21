//go:build windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Identify reads the identity from a handle that does not follow a reparse point, and
// refuses a link: a symbolic link at the path is itself the file inspected, and it is
// a reparse point. An account that may not make symbolic links logs it and returns,
// except where CI is set: there a runner that cannot make a link fails the test.
func TestIdentifyRefusesAReparsePoint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "policy.hujson")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.hujson")
	if err := os.Symlink(target, link); err != nil {
		// Not a skip: a skip on Windows would have to be listed in docs/windows.md.
		if os.Getenv("CI") != "" {
			t.Fatalf("this runner cannot make a symbolic link, so the test proves nothing: %v", err)
		}
		t.Logf("this account cannot make a symbolic link: %v", err)
		return
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Identify(link, fi); !errors.Is(err, errReparse) {
		t.Errorf("Identify of a symbolic link = %v, want errReparse", err)
	}
}
