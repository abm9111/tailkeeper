//go:build !windows

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// An appender that opened the log before a rotation, and waited for its lock
// while the rotation ran, must append to the new log, not to the archive.
func TestAppendAfterARotationItWaitedThroughWritesTheNewLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	l, err := Open(path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 2)
	l.SetLockWait(testLockWait)
	holder, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	opened := make(chan struct{})
	l.opened = func() {
		l.opened = nil // only the appender's first open
		close(opened)
	}
	done := make(chan error, 1)
	go func() { done <- l.Append("read", map[string]any{"tool": "waited"}) }()
	select {
	case <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("the appender never opened the log")
	}
	// Rotate as another process would, while the appender waits on the old file:
	// the archive is a second name for it, and a new log replaces the path.
	archive := filepath.Join(filepath.Dir(path), "audit-20261010T090000Z.jsonl")
	if err := os.Link(path, archive); err != nil {
		t.Fatal(err)
	}
	fresh := &Log{path: filepath.Join(filepath.Dir(path), "fresh.jsonl"), now: fixedNow}
	if f, err := os.OpenFile(fresh.path, os.O_CREATE|os.O_WRONLY, 0o600); err != nil {
		t.Fatal(err)
	} else if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Append("startup", map[string]any{"note": "stand-in"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(fresh.path, path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Append still blocked 5 s after the lock was released")
	}
	if err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(archive); err != nil || n != 2 {
		t.Errorf("archive: %d lines, %v; want the 2 lines it had", n, err)
	}
	lines := readLines(t, path)
	if len(lines) != 2 || lines[1]["tool"] != "waited" {
		t.Errorf("new log = %v; want the stand-in and the waited append", lines)
	}
}

// A rotation that cannot create its archive leaves the log as it was.
func TestRotateInAReadOnlyDirectoryChangesNothing(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 2)
	before, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(l.Path())
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Error(err)
		}
	}()
	if _, err := l.Rotate(); err == nil || !strings.Contains(err.Error(), "cannot create the archive") {
		t.Errorf("Rotate in a read-only directory = %v", err)
	}
	if after, _ := os.ReadFile(l.Path()); string(after) != string(before) {
		t.Errorf("the log changed")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("directory holds %d entries, want the log alone", len(entries))
	}
}
