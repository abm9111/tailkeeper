//go:build !windows

package local

import (
	"os"
	"strconv"
	"syscall"
)

// closeInheritedOnExec marks every open descriptor above standard error close-on-exec,
// so the CLI child gets only the standard streams Run gives it. Go opens its own files
// close-on-exec, but a descriptor that whatever started tailkeeper left open without
// that flag stays open across exec and would reach the child. The descriptors stay open
// in tailkeeper itself. It covers only what /dev/fd lists: when it cannot be read (a
// Linux system without /proc), nothing is marked, and when a read fails part way, the
// entries read before the error are still marked. The marking is process-wide; only
// Run calls it, before each CLI run.
func closeInheritedOnExec() {
	// On an error, ReadDir still returns the entries it read before it.
	entries, _ := os.ReadDir("/dev/fd")
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd <= 2 {
			continue
		}
		syscall.CloseOnExec(fd)
	}
}
