//go:build !windows

package safefile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// readWithin fails the test if Read does not return in time: a read that waits for
// a writer on a FIFO never would.
func readWithin(t *testing.T, path string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := Read(path, Options{}); done <- err }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("Read(%s) blocked", path)
		return nil
	}
}

// release opens a FIFO for writing without blocking, so a Read that did block
// does not leave its goroutine stuck in the test binary.
func release(path string) {
	if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
		_ = f.Close()
	}
}

func TestAFifoIsRefusedNotWaitedOn(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.hujson")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("cannot make a FIFO here: %v", err)
	}
	t.Cleanup(func() { release(p) })
	refused(t, "fifo", readWithin(t, p), tkerr.Usage, "is not a regular file")
}

// A FIFO put in the file's place between the inspection and the open is the case
// O_NONBLOCK exists for: the open returns, and the kind check refuses it.
func TestAFifoSwappedInAfterTheInspectionIsRefusedNotWaitedOn(t *testing.T) {
	p := write(t, []byte("{}"))
	afterLstat = func(path string) {
		if err := os.Remove(path); err != nil {
			t.Error(err) // not Fatal: this runs on the reader's goroutine
			return
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Error(err) // not Fatal: this runs on the reader's goroutine
			return
		}
	}
	t.Cleanup(func() { afterLstat = func(string) {}; release(p) })
	err := readWithin(t, p)
	refused(t, "swapped fifo", err, tkerr.Usage, "changed while it was being opened")
}
