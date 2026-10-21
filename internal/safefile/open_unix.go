//go:build !windows

package safefile

import (
	"os"
	"syscall"
)

// identity is the file Read inspected. Lstat here reads the device and the inode at
// once, so os.SameFile compares the file that was inspected with the one opened.
type identity struct{ fi os.FileInfo }

func identify(_ string, fi os.FileInfo) (identity, error) { return identity{fi}, nil }

// OpenNoFollow opens path for reading: a symlink fails the open, and a FIFO put in the
// file's place after the inspection cannot block it. O_NONBLOCK is for that FIFO alone:
// it stays set on the descriptor of a regular file and has no effect there, so a read
// of a regular file is an ordinary blocking read.
func OpenNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// is reports whether got, the opened file's Stat, is the file inspected.
func (id identity) is(_ *os.File, got os.FileInfo) (bool, error) { return os.SameFile(id.fi, got), nil }
