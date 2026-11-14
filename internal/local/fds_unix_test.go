//go:build !windows

package local

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// readStray reads the stray descriptor's file from its start, through a fresh offset.
func readStray(t *testing.T, fd int) string {
	t.Helper()
	if _, err := syscall.Seek(fd, 0, 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := syscall.Read(fd, buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

// A descriptor that whatever started tailkeeper left open without close-on-exec does
// not reach the CLI child, and stays open in tailkeeper. The control first shows that a
// child started without Run inherits it, so the fixture is one a child could see.
func TestTheCLIChildDoesNotInheritAStrayDescriptor(t *testing.T) {
	const marker = "stray-descriptor-marker"
	p := filepath.Join(t.TempDir(), "stray")
	if err := os.WriteFile(p, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	// syscall.Open, unlike os.Open, does not set close-on-exec.
	fd, err := syscall.Open(p, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(fd) }()
	read := "cat <&" + strconv.Itoa(fd) + " 2>/dev/null; true"

	control, err := exec.Command("/bin/sh", "-c", read).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(control), marker) {
		t.Fatalf("a plain child did not inherit the stray descriptor (output %q): the fixture proves nothing", control)
	}

	if _, err := syscall.Seek(fd, 0, 0); err != nil {
		t.Fatal(err)
	}
	// The stand-in is written here, not with fakeCLI: this file is not compiled on Windows,
	// and fakeCLI's Windows skip would list the test as one that skips there.
	cli := filepath.Join(t.TempDir(), "tailscale")
	if err := os.WriteFile(cli, []byte("#!/bin/sh\n"+read+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	res, err := runner(cli).Run(context.Background(), 5*time.Second, "status")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Stdout), marker) {
		t.Fatalf("the CLI child read the stray descriptor: %q", res.Stdout)
	}
	if got := readStray(t, fd); got != marker {
		t.Fatalf("the stray descriptor no longer reads in tailkeeper: %q", got)
	}
}
