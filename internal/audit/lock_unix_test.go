//go:build !windows

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// openLocked's wait is one deadline for the whole call, not one per reopen. Each of
// the three files the appender opens is locked by a holder for 800 ms and then
// replaced at the path, as a rotation does, which sends the appender round again.
// With a 2 s wait the third lock has only about 400 ms left and must give up as
// stuck; a wait that restarted on every reopen would last 2.4 s in all, and run
// out of reopens instead ("rotated three times"). The times are wide so that a
// loaded machine's scheduling cannot close the 400 ms margin.
func TestOpenLockedKeepsOneDeadlineAcrossReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	l, err := Open(path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	const (
		wait  = 2 * time.Second
		hold  = 800 * time.Millisecond
		bound = 5 * time.Second
	)
	l.SetLockWait(wait)
	opens := 0
	var rotations sync.WaitGroup
	l.opened = func() {
		opens++
		// The hook runs after the appender opened the file at the path and before it
		// locks, so the holder takes the lock the appender is about to wait for.
		holder, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Error(err)
			return
		}
		if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
			t.Error(err)
			_ = holder.Close()
			return
		}
		next := filepath.Join(filepath.Dir(path), fmt.Sprintf("next-%d.jsonl", opens))
		if f, err := os.OpenFile(next, os.O_CREATE|os.O_WRONLY, 0o600); err != nil {
			t.Error(err)
		} else if err := f.Close(); err != nil {
			t.Error(err)
		}
		rotations.Add(1)
		go func() {
			defer rotations.Done()
			defer func() { _ = holder.Close() }()
			time.Sleep(hold)
			if err := os.Rename(next, path); err != nil {
				t.Error(err)
			}
			if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_UN); err != nil {
				t.Error(err)
			}
		}()
	}
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- l.Append("read", map[string]any{"tool": "devices_list"}) }()
	select {
	case err = <-done:
	case <-time.After(bound):
		t.Fatalf("Append still blocked %s into a %s lock wait", bound, wait)
	}
	waited := time.Since(start)
	rotations.Wait()
	if e := tkerr.From(err); err == nil || e.Code != tkerr.AuditUnavailable || !strings.Contains(e.Message, "stayed locked for "+wait.String()) {
		t.Fatalf("Append = %v after %s, want audit_unavailable: the audit log stayed locked for %s (the one wait ran out), not another reopen", err, waited, wait)
	}
	if opens != 3 {
		t.Errorf("the log was opened %d times, want 3: the third lock is the one that ran out", opens)
	}
	if waited < wait {
		t.Errorf("Append gave up after %s, before the %s wait was over", waited, wait)
	}
}
