//go:build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// StrictModeEnforced reports whether CheckOwnership and CheckSecretFile verify
// ownership and permissions on this platform.
const StrictModeEnforced = true

// openFlags are the extra flags readChecked opens with: a symlink fails the open,
// and a FIFO put in the file's place cannot block it.
const openFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// CheckOwnership is the default Checker: path must be a regular file (not a symlink)
// and path and its directory must be owned by one of allowOwners and writable by
// neither group nor others.
func CheckOwnership(path string, allowOwners ...int) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return tkerr.Wrap(tkerr.ConfigUnsafe, err, "cannot inspect "+path, "")
	}
	if !fi.Mode().IsRegular() {
		return unsafe(path, "is not a regular file (symlinks are refused)", "replace it with a regular file")
	}
	if err := checkOne(path, fi, allowOwners); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	di, err := os.Stat(dir)
	if err != nil {
		return tkerr.Wrap(tkerr.ConfigUnsafe, err, "cannot inspect "+dir, "")
	}
	return checkOne(dir, di, allowOwners)
}

// CheckSecretFile is stricter: owner-only permissions (no group or other access at all).
func CheckSecretFile(path string) error {
	if err := CheckOwnership(path, os.Getuid(), 0); err != nil {
		return err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return tkerr.Wrap(tkerr.ConfigUnsafe, err, "cannot inspect "+path, "")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return unsafe(path, fmt.Sprintf("has mode %04o", fi.Mode().Perm()), "run: chmod 600 "+shellQuote(path))
	}
	return nil
}

func checkOne(path string, fi os.FileInfo, allowOwners []int) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return unsafe(path, "has no ownership information", "")
	}
	owned := false
	for _, uid := range allowOwners {
		if int(st.Uid) == uid {
			owned = true
		}
	}
	if !owned {
		return unsafe(path, fmt.Sprintf("is owned by uid %d", st.Uid), "it must be owned by root or by you")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return unsafe(path, fmt.Sprintf("is writable by group or others (mode %04o)", fi.Mode().Perm()), "run: chmod go-w "+shellQuote(path))
	}
	return nil
}

func unsafe(path, what, hint string) error {
	return tkerr.New(tkerr.ConfigUnsafe, path+" "+what, hint)
}

// shellQuote quotes a path for a POSIX shell, so a hint can be pasted as it is
// (the macOS user directory is under "Application Support").
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
