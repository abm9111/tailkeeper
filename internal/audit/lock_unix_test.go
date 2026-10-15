//go:build !windows

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func TestAppendGivesUpOnAStuckLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	l, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	const wait = 100 * time.Millisecond
	l.SetLockWait(wait)
	// A second open file description holds the lock, as another process would.
	holder, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	// In a goroutine, so that a lock which never times out fails the test instead
	// of hanging the suite.
	done := make(chan error, 1)
	go func() { done <- l.Append("read", map[string]any{"tool": "devices_list"}) }()
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Append still blocked 5 s into a 100 ms lock wait: the lock does not time out")
	}
	if e := tkerr.From(err); err == nil || e.Code != tkerr.AuditUnavailable || !strings.Contains(e.Message, "stayed locked") {
		t.Fatalf("Append under a held lock = %v, want audit_unavailable naming the lock", err)
	}
	if waited := time.Since(start); waited < wait || waited > 5*time.Second {
		t.Errorf("Append gave up after %s, want just over %s", waited, wait)
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
		t.Fatalf("Append once the lock is free: %v", err)
	}
	if n, err := Verify(path); err != nil || n != 1 {
		t.Errorf("Verify = %d, %v; want 1 line: the refused append must leave nothing behind", n, err)
	}
}
