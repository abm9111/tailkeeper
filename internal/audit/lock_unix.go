//go:build !windows

package audit

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// canRotate: rotation relies on the lock (an appender re-checks the file once it
// holds it), which only exists here.
const canRotate = true

// lock takes the exclusive lock without blocking, retrying with a short backoff
// until wait has passed; then it returns errLockTimeout.
func lock(f *os.File, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for delay := time.Millisecond; ; delay = min(2*delay, 50*time.Millisecond) {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		if time.Now().After(deadline) {
			return errLockTimeout
		}
		time.Sleep(delay)
	}
}

func unlock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
