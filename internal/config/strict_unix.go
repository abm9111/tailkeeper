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
	return ownedFileAndDirectory(path, fi, allowOwners)
}

// OwnedBy returns the check for safefile.Options.Verify that holds a file to the rule
// CheckOwnership applies, on the file that was opened: fi is the open file's Stat, so
// what is judged is the file that is read, not whatever the path names a moment before
// or after. The file must be regular, and it and its directory must be owned by one of
// owners and writable by neither group nor others. Windows reads no owner; there it
// refuses a file that is not a regular one and nothing else.
func OwnedBy(owners ...int) func(path string, opened os.FileInfo) error {
	return func(path string, opened os.FileInfo) error {
		if !opened.Mode().IsRegular() {
			return unsafe(path, "is not a regular file", "replace it with a regular file")
		}
		return ownedFileAndDirectory(path, opened, owners)
	}
}

// ownedFileAndDirectory is the ownership rule for a regular file whose FileInfo is fi
// and for the directory that holds it.
func ownedFileAndDirectory(path string, fi os.FileInfo, allowOwners []int) error {
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
