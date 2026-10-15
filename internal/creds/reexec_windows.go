//go:build windows

package creds

import "github.com/abm9111/tailkeeper/internal/tkerr"

// Reexec is not available on Windows yet: run tailkeeper under the wrapper yourself
// (the secret manager's run command, then `tailkeeper mcp`) and use the env provider.
func Reexec(wrapper []string, self string, args []string) error {
	return tkerr.New(tkerr.ConfigInvalid, "the exec provider is not supported on Windows yet",
		"start tailkeeper under the wrapper and use the env provider")
}
