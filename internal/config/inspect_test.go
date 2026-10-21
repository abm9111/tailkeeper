package config

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// failInspection makes the inspection of a path that is there fail with the error the
// system gives for a name that is too long, which is how a file the system refuses to
// inspect looks on every platform (on Windows, a reparse point is refused by the same
// step, but only Windows can produce one).
func failInspection(t *testing.T) {
	t.Helper()
	old := inspectPath
	inspectPath = func(path string) (inspected, error) {
		return inspected{}, &fs.PathError{Op: "lstat", Path: path, Err: syscall.ENAMETOOLONG}
	}
	t.Cleanup(func() { inspectPath = old })
}

// wantInspectRefusal checks the refusal of an inspection that failed: config_unsafe, a
// message that names the path and the reason (the reason is what the user can act on),
// and a hint that says what to do about a file the check cannot follow. The JSON form
// carries the reason too, because the wrapped error does not reach it.
func wantInspectRefusal(t *testing.T, what, path string, err error) {
	t.Helper()
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.ConfigUnsafe {
		t.Errorf("%s: err = %v, want config_unsafe", what, err)
		return
	}
	if want := "cannot inspect " + path + ": " + syscall.ENAMETOOLONG.Error(); e.Message != want {
		t.Errorf("%s: message = %q, want %q", what, e.Message, want)
	}
	for _, word := range []string{"symbolic link", "junction", "OneDrive Files On-Demand", "local copy"} {
		if !strings.Contains(e.Hint, word) {
			t.Errorf("%s: hint = %q, want it to mention %q", what, e.Hint, word)
		}
	}
	raw, jerr := json.Marshal(e)
	if jerr != nil || !strings.Contains(string(raw), syscall.ENAMETOOLONG.Error()) {
		t.Errorf("%s: JSON = %s (%v), want the reason in it", what, raw, jerr)
	}
}

// Load refuses a configuration file whose inspection fails as config_unsafe, with the
// reason and the hint. (The failure that the existing test provokes is caught earlier,
// by the check that the file exists; this one is the inspection that follows it.)
func TestLoadRefusesAnInspectionFailureAsUnsafeWithTheReasonAndAHint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	failInspection(t)
	_, err := Load(Dirs{System: filepath.Join(t.TempDir(), "sys"), User: dir}, allowAll)
	wantInspectRefusal(t, "Load", path, err)
}

// ReadSecretFile gives the same refusal for a file that is there and cannot be inspected.
func TestReadSecretFileRefusesAnInspectionFailureAsUnsafeWithTheReasonAndAHint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "read.env")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	failInspection(t)
	_, err := ReadSecretFile(path)
	wantInspectRefusal(t, "ReadSecretFile", path, err)
}
