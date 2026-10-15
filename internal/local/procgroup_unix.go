//go:build !windows

package local

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the CLI in its own process group and kills the whole
// group when the context ends, so no child survives a timeout.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
