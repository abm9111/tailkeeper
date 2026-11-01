package workflows

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// errPrivilegeNotHeld is ERROR_PRIVILEGE_NOT_HELD, what os.Symlink returns on an account
// without the symbolic-link privilege (Developer Mode off, not an administrator).
const errPrivilegeNotHeld syscall.Errno = 1314

func symlinkPrivilegeMissing(err error) bool {
	return errors.Is(err, errPrivilegeNotHeld)
}

func TestSymlinkPrivilegeMissingIsOnlyThePrivilegeError(t *testing.T) {
	if !symlinkPrivilegeMissing(&os.LinkError{Op: "symlink", Err: errPrivilegeNotHeld}) {
		t.Error("the missing privilege was not recognised")
	}
	if symlinkPrivilegeMissing(&os.LinkError{Op: "symlink", Err: syscall.ERROR_ACCESS_DENIED}) {
		t.Error("access denied was taken for the missing privilege")
	}
}
