//go:build linux || openbsd || dragonfly || solaris || aix

package config

import "syscall"

// ctimeOf is the change time of st: the field is Ctim on these systems.
func ctimeOf(st *syscall.Stat_t) (sec, nsec int64) {
	return int64(st.Ctim.Sec), int64(st.Ctim.Nsec)
}
