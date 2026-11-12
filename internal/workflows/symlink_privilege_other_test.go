//go:build !windows

package workflows

// symlinkPrivilegeMissing is false off Windows: there making a symbolic link needs no
// privilege, so a failure is a real one.
func symlinkPrivilegeMissing(error) bool { return false }
