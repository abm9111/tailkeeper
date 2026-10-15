//go:build windows

package config

import (
	"os"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// StrictModeEnforced is false on Windows: CheckOwnership and CheckSecretFile only
// refuse non-regular files there.
const StrictModeEnforced = false

// openFlags: Windows has no O_NOFOLLOW; CheckOwnership refuses non-regular files.
const openFlags = 0

// CheckOwnership on Windows only refuses non-regular files. Windows has no strict
// mode until Windows hardened mode (spec §4): ownership and ACLs are not checked
// and %ProgramData% comes from the environment.
func CheckOwnership(path string, _ ...int) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return tkerr.Wrap(tkerr.ConfigUnsafe, err, "cannot inspect "+path, "")
	}
	if !fi.Mode().IsRegular() {
		return tkerr.New(tkerr.ConfigUnsafe, path+" is not a regular file", "")
	}
	return nil
}

// CheckSecretFile on Windows has the same limits as CheckOwnership.
func CheckSecretFile(path string) error { return CheckOwnership(path) }

// sameChangeTime is true on Windows: Go's FileInfo carries no change time there, so
// readChecked compares the kind, mode, size and modification time only.
func sameChangeTime(_, _ os.FileInfo) bool { return true }
