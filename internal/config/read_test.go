package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// infoWith is a FileInfo that reports the given mode, size and modification time and
// leaves everything else (its Sys, so its change time) to the file behind it.
type infoWith struct {
	os.FileInfo
	mode  os.FileMode
	size  int64
	mtime time.Time
}

func (i infoWith) Mode() os.FileMode  { return i.mode }
func (i infoWith) Size() int64        { return i.size }
func (i infoWith) ModTime() time.Time { return i.mtime }

// What readChecked compares besides the device and inode: each field alone refuses.
// The change time cannot be moved on its own through a FileInfo; the Unix tests do
// it with a chmod.
func TestUnchangedComparesKindModeSizeAndModificationTime(t *testing.T) {
	p := filepath.Join(t.TempDir(), "read.env")
	if err := os.WriteFile(p, []byte("A=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	with := func(mutate func(*infoWith)) os.FileInfo {
		i := infoWith{fi, fi.Mode(), fi.Size(), fi.ModTime()}
		mutate(&i)
		return i
	}
	for _, c := range []struct {
		name string
		got  os.FileInfo
		want bool
	}{
		{"the file as it was", fi, true},
		{"the same fields from another FileInfo", with(func(*infoWith) {}), true},
		{"another mode", with(func(i *infoWith) { i.mode ^= 0o010 }), false},
		{"another size", with(func(i *infoWith) { i.size++ }), false},
		{"a modification time a nanosecond later", with(func(i *infoWith) { i.mtime = i.mtime.Add(time.Nanosecond) }), false},
		{"a FIFO", with(func(i *infoWith) { i.mode = os.ModeNamedPipe | 0o600 }), false},
		{"a directory", with(func(i *infoWith) { i.mode = os.ModeDir | 0o700 }), false},
		{"a symlink", with(func(i *infoWith) { i.mode = os.ModeSymlink | 0o777 }), false},
	} {
		if got := unchanged(fi, c.got); got != c.want {
			t.Errorf("%s: unchanged = %v, want %v", c.name, got, c.want)
		}
	}
	// A file that is not regular is refused even when the checked file was the same.
	fifo := with(func(i *infoWith) { i.mode = os.ModeNamedPipe | 0o600 })
	if unchanged(fifo, fifo) {
		t.Error("a FIFO that equals itself was accepted: only a regular file may be read")
	}
}

// An unchanged file is read, and read again with the same Lstat: opening and reading
// it moves nothing the comparison looks at.
func TestReadCheckedReadsAnUnchangedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "read.env")
	if err := os.WriteFile(p, []byte("A=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if data, err := readChecked(p, want); err != nil || string(data) != "A=b\n" {
			t.Fatalf("read %d: %q, %v", i, data, err)
		}
	}
}
