//go:build !windows

package config

import (
	"os"
	"syscall"
)

// sameChangeTime reports whether a and b carry the same change time (ctime). A file
// without one (no *syscall.Stat_t behind it) is never the same: the comparison fails
// closed, as checkOne does when a file has no ownership information.
func sameChangeTime(a, b os.FileInfo) bool {
	sa, okA := a.Sys().(*syscall.Stat_t)
	sb, okB := b.Sys().(*syscall.Stat_t)
	if !okA || !okB {
		return false
	}
	secA, nsecA := ctimeOf(sa)
	secB, nsecB := ctimeOf(sb)
	return secA == secB && nsecA == nsecB
}
