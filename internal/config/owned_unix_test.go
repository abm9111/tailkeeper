//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/abm9111/tailkeeper/internal/safefile"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// statInfo is a FileInfo whose Stat_t, and optionally mode, are the test's.
type statInfo struct {
	os.FileInfo
	st   syscall.Stat_t
	mode os.FileMode
}

func (s statInfo) Sys() any          { return &s.st }
func (s statInfo) Mode() os.FileMode { return s.mode }
func withStat(t *testing.T, p string, change func(*statInfo)) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	s := statInfo{FileInfo: fi, st: *fi.Sys().(*syscall.Stat_t), mode: fi.Mode()}
	change(&s)
	return s
}

func writeOwned(t *testing.T) (dir, p string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "inv")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p = filepath.Join(dir, "invariants.hujson")
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, p
}

// OwnedBy judges the FileInfo it is given, the opened file's Stat, not the path: a file
// that is fine on disk is refused when the open file says another owner or a mode a
// group can write, and a directory or a pipe is never an owned file.
func TestOwnedByRefusesAnotherOwnerAndAGroupWritableFile(t *testing.T) {
	_, p := writeOwned(t)
	check := OwnedBy(os.Getuid())
	real, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := check(p, real); err != nil {
		t.Fatalf("a file of ours, mode 0600, in a 0700 directory: %v", err)
	}
	for name, c := range map[string]struct {
		info os.FileInfo
		want string
	}{
		"another owner": {withStat(t, p, func(s *statInfo) { s.st.Uid++ }), "is owned by uid"},
		"group-write":   {withStat(t, p, func(s *statInfo) { s.mode |= 0o020 }), "is writable by group or others"},
		"other-write":   {withStat(t, p, func(s *statInfo) { s.mode |= 0o002 }), "is writable by group or others"},
		"no Stat_t":     {noSys{real}, "has no ownership information"},
		"a directory":   {withStat(t, p, func(s *statInfo) { s.mode = os.ModeDir | 0o700 }), "is not a regular file"},
		"a pipe":        {withStat(t, p, func(s *statInfo) { s.mode = os.ModeNamedPipe | 0o600 }), "is not a regular file"},
	} {
		e, ok := tkerr.As(check(p, c.info))
		if !ok || e.Code != tkerr.ConfigUnsafe || !strings.Contains(e.Message, c.want) {
			t.Errorf("%s: %v, want config_unsafe with %q", name, e, c.want)
		}
	}
	// root is not "us": the invariants file does not take the configuration file's [0, uid].
	if e, ok := tkerr.As(OwnedBy(os.Getuid()+1)(p, real)); !ok || !strings.Contains(e.Message, "is owned by uid") {
		t.Errorf("a file owned by us, checked for another user: %v", e)
	}
	if err := OwnedBy(os.Getuid()+1, os.Getuid())(p, real); err != nil {
		t.Errorf("an owner in the list was refused: %v", err)
	}
}

// Whoever can write the directory can replace the file, so the directory is judged too,
// by the same rule as CheckOwnership applies.
func TestOwnedByChecksTheDirectoryToo(t *testing.T) {
	dir, p := writeOwned(t)
	real, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if e, ok := tkerr.As(OwnedBy(os.Getuid())(p, real)); !ok || e.Code != tkerr.ConfigUnsafe || !strings.Contains(e.Message, dir+" is writable by group") {
		t.Errorf("a group-writable directory: %v", e)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if e, ok := tkerr.As(OwnedBy(os.Getuid())(p, real)); !ok || e.Code != tkerr.ConfigUnsafe || !strings.Contains(e.Message, "cannot inspect "+dir) {
		t.Errorf("a directory that is gone: %v", e)
	}
}

// OwnedBy is what safefile.Read runs on the file it opened: the refusal keeps its code,
// whatever code the caller gave the read.
func TestOwnedByRefusesThroughSafefileRead(t *testing.T) {
	_, p := writeOwned(t)
	o := safefile.Options{Code: tkerr.Usage, Verify: OwnedBy(os.Getuid() + 1)}
	if _, err := safefile.Read(p, o); !isCode(err, tkerr.ConfigUnsafe) {
		t.Errorf("a file of another owner: err = %v, want config_unsafe", err)
	}
	o.Verify = OwnedBy(os.Getuid())
	if data, err := safefile.Read(p, o); err != nil || string(data) != "{}" {
		t.Errorf("a file of ours: %q, %v", data, err)
	}
}

// A file swapped for one of the same size, mode and times but another owner is not the
// file that was checked. The owner is compared with the rest; the control is the same
// FileInfo with the owner left alone.
func TestUnchangedRefusesAChangedOwner(t *testing.T) {
	_, p := writeOwned(t)
	want, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !unchanged(want, withStat(t, p, func(*statInfo) {})) {
		t.Fatal("a copy of the Stat_t was refused: the control is wrong")
	}
	if unchanged(want, withStat(t, p, func(s *statInfo) { s.st.Uid++ })) {
		t.Error("a file with another uid was taken for the checked file")
	}
	if unchanged(want, withStat(t, p, func(s *statInfo) { s.st.Gid++ })) {
		t.Error("a file with another gid was taken for the checked file")
	}
	if sameOwner(want, noSys{want}) || sameOwner(noSys{want}, want) {
		t.Error("a FileInfo with no Stat_t was taken as having the same owner")
	}
}
