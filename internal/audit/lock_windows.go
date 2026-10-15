//go:build windows

package audit

import (
	"os"
	"time"
)

// Windows file locking arrives with Windows hardened mode. Until then the
// appenders of one process are serialised in memory (proclock.go), which is what
// one MCP server's parallel calls need; two tailkeeper processes writing at the
// same moment can still fork the chain, and Rotate, which needs a lock that
// excludes other processes, refuses.
const canRotate = false

// lock and unlock take and release the in-process lock. When a file lock is added
// here, take this one first and the file's second, and release them in reverse.
func lock(_ *os.File, wait time.Duration) error { return lockProc(wait) }
func unlock(*os.File) error                     { unlockProc(); return nil }
