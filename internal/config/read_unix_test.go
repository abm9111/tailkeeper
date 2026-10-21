//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// A FIFO put in the file's place after the check cannot hang the read. The open does
// not wait for a writer (O_NONBLOCK), and what it opens is not the file that was
// checked, so the read is refused. Without O_NONBLOCK the open blocks for good.
func TestAFifoSwappedInAfterTheCheckIsRefusedNotWaitedOn(t *testing.T) {
	swapInFifo := func(path string) error {
		if err := os.Remove(path); err != nil {
			return err
		}
		return syscall.Mkfifo(path, 0o600)
	}
	// A blocked open waits for a writer; opening the FIFO for writing frees it, so a
	// failure here does not leave a goroutine stuck in the test binary.
	release := func(path string) {
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	}
	wait := func(t *testing.T, what string, done <-chan error) {
		t.Helper()
		select {
		case err := <-done:
			if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ConfigUnsafe {
				t.Errorf("%s: err = %v, want config_unsafe", what, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: blocked on a FIFO that replaced the file", what)
		}
	}

	t.Run("readChecked", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "read.env")
		if err := os.WriteFile(p, []byte("A=b\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		want, err := inspect(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := swapInFifo(p); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { release(p) })
		done := make(chan error, 1)
		go func() { _, err := readChecked(p, want); done <- err }()
		wait(t, "readChecked", done)
	})

	t.Run("Load", func(t *testing.T) {
		root := t.TempDir()
		d := Dirs{System: filepath.Join(root, "sys"), User: filepath.Join(root, "usr")}
		writeConfig(t, d.User, validConfig)
		path := filepath.Join(d.User, FileName)
		t.Cleanup(func() { release(path) })
		approveThenSwap := func(p string, owners ...int) error {
			if err := CheckOwnership(p, owners...); err != nil {
				return err
			}
			return swapInFifo(path)
		}
		done := make(chan error, 1)
		go func() { _, err := Load(d, approveThenSwap); done <- err }()
		wait(t, "Load", done)
	})
}

// O_NOFOLLOW is not only a second guard behind the same-file comparison: a symlink
// that leads back to the very file that was checked is refused too, as
// CheckOwnership refuses a symlink, instead of being followed to the approved inode.
func TestReadCheckedDoesNotFollowASymlinkToTheCheckedFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "read.env")
	if err := os.WriteFile(p, []byte("A=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := inspect(p)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(dir, "moved.env")
	if err := os.Rename(p, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, p); err != nil {
		t.Fatal(err)
	}
	if data, err := readChecked(p, want); !isCode(err, tkerr.ConfigUnsafe) {
		t.Errorf("a symlink to the checked file: read %q, err = %v, want config_unsafe", data, err)
	}
}

// A file system may give a new file the inode number of one just removed (ext4 does,
// which is what failed TestAFifoSwappedInAfterTheCheckIsRefusedNotWaitedOn on a
// Linux runner while macOS, btrfs and tmpfs passed it). The device and inode of such
// a file are the checked file's, so they cannot be the whole identity. This test
// builds that state on any file system: want is the Lstat of the FIFO itself, so the
// FIFO has exactly the identity the comparison looks at, and only what kind of file
// it is can refuse it.
func TestReadCheckedRefusesAFifoThatHasTheCheckedFilesDeviceAndInode(t *testing.T) {
	wait := func(t *testing.T, what string, done <-chan error) {
		t.Helper()
		select {
		case err := <-done:
			if !isCode(err, tkerr.ConfigUnsafe) {
				t.Errorf("%s: err = %v, want config_unsafe", what, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: blocked on a FIFO", what)
		}
	}
	t.Run("readChecked", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "read.env")
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
		want, err := inspect(p)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := readChecked(p, want); done <- err }()
		wait(t, "readChecked", done)
	})
	// The configuration reaches the same state through Load when the Checker lets a
	// FIFO pass; CheckOwnership never does. Before the comparison looked at the kind
	// of file, this read an empty FIFO and failed as an invalid configuration.
	t.Run("Load", func(t *testing.T) {
		root := t.TempDir()
		d := Dirs{System: filepath.Join(root, "sys"), User: filepath.Join(root, "usr")}
		if err := os.MkdirAll(d.User, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(d.User, FileName), 0o600); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := Load(d, allowAll); done <- err }()
		wait(t, "Load", done)
	})
}

// A file of the same kind, at the same inode, rewritten between the Lstat and the open
// is not the file that was checked either: its size and times moved.
func TestReadCheckedRefusesAFileRewrittenInPlaceAfterTheCheck(t *testing.T) {
	p := filepath.Join(t.TempDir(), "read.env")
	if err := os.WriteFile(p, []byte("A=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := inspect(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("A=evil and longer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readChecked(p, want); !isCode(err, tkerr.ConfigUnsafe) {
		t.Errorf("a rewritten file: read %q, err = %v, want config_unsafe", data, err)
	}
}

// The change time is the one a process without the right to set it cannot forge: it
// moves on every write and every chmod, whatever the file's mtime was set back to. A
// chmod to another mode and back leaves the mode, size and modification time as they
// were, so only the change time can refuse here. (A chmod to the mode the file already
// has moves the change time on most file systems, but not on all: a macOS directory
// bind-mounted into a container does not.) A file system's clock ticks every few
// milliseconds, so the chmods are repeated until a tick has passed; a file system whose
// change time never moves fails the test, as it would fail to protect the read.
func TestReadCheckedRefusesAFileWhoseChangeTimeMovedAfterTheCheck(t *testing.T) {
	p := filepath.Join(t.TempDir(), "read.env")
	if err := os.WriteFile(p, []byte("A=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := inspect(p)
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		for _, mode := range []os.FileMode{0o640, 0o600} {
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := readChecked(p, want); isCode(err, tkerr.ConfigUnsafe) {
			return
		} else if err != nil {
			t.Fatalf("err = %v, want nil or config_unsafe", err)
		}
	}
	t.Error("a chmod to another mode and back after the check never made the read refuse: the change time is not compared")
}

// A rewrite of the same size with the modification time put back straight after the
// check changes nothing the comparison sees but the change time, and that moves by
// nanoseconds, inside one second: a change time compared in whole seconds lets the read
// through. The rewrite is repeated until the change time has moved inside the second
// the check was taken in (a second boundary between the two starts the attempt again).
func TestReadCheckedRefusesASameSizeRewriteWithTheModTimeRestoredWithinTheSecond(t *testing.T) {
	ctime := func(fi os.FileInfo) (int64, int64) {
		t.Helper()
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatal("no Stat_t")
		}
		return ctimeOf(st)
	}
	for attempt := 0; attempt < 30; attempt++ {
		p := filepath.Join(t.TempDir(), "read.env")
		if err := os.WriteFile(p, []byte("A=b\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		want, err := inspect(p)
		if err != nil {
			t.Fatal(err)
		}
		wsec, wnsec := ctime(want.fi)
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			if err := os.WriteFile(p, []byte("A=c\n"), 0o600); err != nil { // the same size
				t.Fatal(err)
			}
			if err := os.Chtimes(p, want.fi.ModTime(), want.fi.ModTime()); err != nil {
				t.Fatal(err)
			}
			got, err := os.Lstat(p)
			if err != nil {
				t.Fatal(err)
			}
			sec, nsec := ctime(got)
			if sec != wsec {
				break // a second boundary: start again
			}
			if nsec == wnsec {
				continue // the clock has not ticked
			}
			if data, err := readChecked(p, want); !isCode(err, tkerr.ConfigUnsafe) {
				t.Fatalf("a same-size rewrite with the mtime restored, its change time moved by %d ns: read %q, err = %v, want config_unsafe", nsec-wnsec, data, err)
			}
			return
		}
	}
	t.Skip("this file system's change time never moved inside a second in 30 attempts")
}

// Reading a file moves its access time, and on some file systems the read of an
// untouched file is the only thing that does. Neither the access time nor a read
// moves anything the comparison looks at, so an unchanged file is read, as many
// times as it is asked. The access time is set far back first, and the test logs
// when it did not move, so that a pass can be told from a pass with nothing to move.
func TestReadCheckedReadsAnUnchangedFileWhoseAccessTimeMoves(t *testing.T) {
	atime := func(fi os.FileInfo) time.Time {
		t.Helper()
		st := reflect.ValueOf(fi.Sys()).Elem()
		for _, name := range []string{"Atim", "Atimespec"} {
			if ts := st.FieldByName(name); ts.IsValid() {
				return time.Unix(ts.FieldByName("Sec").Int(), ts.FieldByName("Nsec").Int())
			}
		}
		t.Fatal("Stat_t has neither Atim nor Atimespec")
		return time.Time{}
	}
	p := filepath.Join(t.TempDir(), "read.env")
	if err := os.WriteFile(p, []byte("A=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	want, err := inspect(p)
	if err != nil {
		t.Fatal(err)
	}
	before := atime(want.fi)
	if _, err := os.ReadFile(p); err != nil { // moves the access time on a file system that records it
		t.Fatal(err)
	}
	after, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !atime(after).After(before) {
		// A noatime mount (macOS's data volume is one). The reads below still show that
		// reading leaves the compared fields alone; the movement itself is not tested.
		t.Log("this file system does not record the access time of a read")
	}
	for i := 0; i < 3; i++ {
		if data, err := readChecked(p, want); err != nil || string(data) != "A=b\n" {
			t.Fatalf("read %d of an unchanged file whose access time moved: %q, %v", i+1, data, err)
		}
	}
}

// A file that carries no Stat_t has no change time to compare, and is not the same.
func TestSameChangeTimeFailsClosedWithoutAStat(t *testing.T) {
	p := filepath.Join(t.TempDir(), "read.env")
	if err := os.WriteFile(p, []byte("A=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !sameChangeTime(fi, fi) {
		t.Fatal("a file's change time differs from itself")
	}
	if sameChangeTime(fi, noSys{fi}) || sameChangeTime(noSys{fi}, fi) {
		t.Error("a FileInfo with no Stat_t was taken as having the same change time")
	}
}

type noSys struct{ os.FileInfo }

func (noSys) Sys() any { return nil }
