package audit

import "time"

// procLock serialises the appenders of this process where the platform offers
// no file lock (Windows today). It is one lock for the whole process, not one per
// Log or per path: the MCP server's calls share a Log, but every Open of the same
// file, under whatever spelling of its path, must meet the same lock. It is
// compiled on every platform so that Linux and macOS CI test it.
var procLock = make(chan struct{}, 1)

// lockProc takes procLock, giving up with errLockTimeout after wait.
func lockProc(wait time.Duration) error {
	select {
	case procLock <- struct{}{}:
		return nil
	default:
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case procLock <- struct{}{}:
		return nil
	case <-t.C:
		return errLockTimeout
	}
}

// unlockProc releases procLock; releasing an unheld lock does nothing.
func unlockProc() {
	select {
	case <-procLock:
	default:
	}
}
