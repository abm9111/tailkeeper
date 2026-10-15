//go:build !windows

package creds

import (
	"os"
	"syscall"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Reexec replaces this process with: wrapper argv..., self, args...
// The wrapper (a secret manager's run command; see docs/recipes/) injects the
// read credential into the environment of the tailkeeper it starts. File
// descriptors survive exec, so this works for the stdio MCP server too.
func Reexec(wrapper []string, self string, args []string) error {
	argv := append(append(append([]string{}, wrapper...), self), args...)
	env := reexecEnv(os.Environ())
	err := syscall.Exec(wrapper[0], argv, env)
	return tkerr.Wrap(tkerr.CredentialUnavailable, err, "cannot start the credential wrapper "+wrapper[0], "")
}
