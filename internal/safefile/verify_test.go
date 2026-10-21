package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Verify sees the file that was opened: the FileInfo it gets is the open file's own
// Stat, and the path is the one Read was given.
func TestSafefileReadRunsVerifyOnTheOpenedFile(t *testing.T) {
	p := write(t, []byte("{}"))
	var gotPath string
	var gotInfo os.FileInfo
	o := Options{Verify: func(path string, opened os.FileInfo) error {
		gotPath, gotInfo = path, opened
		return nil
	}}
	data, err := Read(p, o)
	if err != nil || string(data) != "{}" {
		t.Fatalf("Read = %q, %v", data, err)
	}
	onDisk, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != p || gotInfo == nil || !os.SameFile(gotInfo, onDisk) {
		t.Errorf("Verify got (%q, %v), want the opened file at %q", gotPath, gotInfo, p)
	}
}

// A file put in the path's place after the inspection is refused by the identity
// check, and the Verify hook, which would judge the wrong file, never runs.
func TestAFileSwappedInAfterTheInspectionNeverReachesVerify(t *testing.T) {
	p := write(t, []byte("{}"))
	other := write(t, []byte("{}"))
	afterLstat = func(path string) {
		if err := os.Rename(other, path); err != nil {
			t.Error(err) // not Fatal: this runs on the reader's goroutine
		}
	}
	t.Cleanup(func() { afterLstat = func(string) {} })
	called := false
	_, err := Read(p, Options{Verify: func(string, os.FileInfo) error { called = true; return nil }})
	refused(t, "swapped file", err, tkerr.Usage, "changed while it was being opened")
	if called {
		t.Error("Verify ran on a file that was not the one inspected")
	}
}

// A refusal from Verify is the caller's own: its code and its identity survive, they
// are not rewrapped in Options.Code.
func TestAVerifyRefusalIsReturnedAsItIs(t *testing.T) {
	p := write(t, []byte("{}"))
	own := tkerr.New(tkerr.ConfigUnsafe, "owned by someone else", "chown it")
	_, err := Read(p, Options{Code: tkerr.Usage, Verify: func(string, os.FileInfo) error { return own }})
	if e, ok := tkerr.As(err); !ok || e != own || e.Code != tkerr.ConfigUnsafe {
		t.Errorf("err = %v, want the very error Verify returned, config_unsafe and not Options.Code", err)
	}
	plain := errors.New("plain")
	_, err = Read(p, Options{Verify: func(string, os.FileInfo) error { return plain }})
	if !errors.Is(err, plain) || err.Error() != "plain" {
		t.Errorf("a plain error from Verify came back as %v", err)
	}
}

// Identify reads the identity at the inspection: the file opened afterwards is that
// file or it is not. The replacement is another file that already exists, so no file
// system can hand it the inode of the one it replaces.
func TestIdentifyPinsTheFileAtTheInspection(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.hujson")
	other := filepath.Join(dir, "other.hujson")
	for _, f := range []string{p, other} {
		if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	id, err := Identify(p, fi)
	if err != nil {
		t.Fatal(err)
	}
	is := func() bool {
		t.Helper()
		f, err := OpenNoFollow(p)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }() // read only
		got, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		same, err := id.Is(f, got)
		if err != nil {
			t.Fatal(err)
		}
		return same
	}
	if !is() {
		t.Fatal("the file that was inspected is not itself")
	}
	if err := os.Rename(other, p); err != nil {
		t.Fatal(err)
	}
	if is() {
		t.Error("a file put in the path's place after the inspection was taken for the inspected file")
	}
	if (Identity{}) == id {
		t.Error("an identity taken from a file equals the zero identity")
	}
	f, err := OpenNoFollow(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }() // read only
	if same, err := (Identity{}).Is(f, fi); err != nil || same {
		t.Errorf("the zero identity matched a file: %v, %v", same, err)
	}
}
