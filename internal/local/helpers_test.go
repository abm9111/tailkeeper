package local

import (
	"strconv"
	"syscall"
	"testing"
)

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func syscallZero() syscall.Signal { return syscall.Signal(0) }
