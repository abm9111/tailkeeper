package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// A Checker that approves the file and then puts another file of the same size and
// the same modification time at its path gets a refusal: the file that is opened is
// compared with the identity taken at the inspection, which is not the same as
// comparing the two by path after the swap. On Linux and macOS this passes with the
// comparison by path too, because the inode and the change time of the new file
// differ; the run that tells the two apart is the Windows job, where os.SameFile
// reads both identities by path after the swap and compares the new file with itself.
func TestReadCheckedRefusesAFileReplacedWithTheSameSizeAndTime(t *testing.T) {
	root := t.TempDir()
	d := Dirs{System: filepath.Join(root, "sys"), User: filepath.Join(root, "usr")}
	writeConfig(t, d.User, validConfig)
	path := filepath.Join(d.User, FileName)
	orig, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(root, "other.hujson")
	if err := os.WriteFile(other, []byte(strings.Repeat("x", len(validConfig))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(other, orig.ModTime(), orig.ModTime()); err != nil {
		t.Fatal(err)
	}
	approveThenSwap := func(string, ...int) error { return os.Rename(other, path) }
	l, err := Load(d, approveThenSwap)
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.ConfigUnsafe || !strings.Contains(e.Message, "changed while it was being checked") {
		t.Errorf("err = %v, want config_unsafe, changed while it was being checked (loaded %v)", err, l != nil)
	}
}

// inspect is the Lstat of the path and the identity taken in the same step; a path
// that is not there is the Lstat's own error, which the callers classify.
func TestInspectTakesTheLstatAndTheIdentity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "read.env")
	if err := os.WriteFile(p, []byte("A=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := inspect(p)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(got.fi, fi) || got.fi.Size() != fi.Size() {
		t.Errorf("inspect saw %v, want the Lstat %v", got.fi, fi)
	}
	if _, err := inspect(filepath.Join(filepath.Dir(p), "missing.env")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing path: err = %v, want fs.ErrNotExist", err)
	}
}
