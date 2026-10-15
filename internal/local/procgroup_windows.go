//go:build windows

package local

import "os/exec"

// configureProcessGroup does nothing on Windows yet: on timeout exec.CommandContext
// kills tailscale.exe itself, but not processes it started (that needs a Job
// Object). Run's WaitDelay still bounds the call.
func configureProcessGroup(*exec.Cmd) {}
