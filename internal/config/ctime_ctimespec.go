//go:build darwin || freebsd || netbsd

package config

import "syscall"

// ctimeOf is the change time of st: the field is Ctimespec on these systems.
func ctimeOf(st *syscall.Stat_t) (sec, nsec int64) {
	return int64(st.Ctimespec.Sec), int64(st.Ctimespec.Nsec)
}
