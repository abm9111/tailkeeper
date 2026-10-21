//go:build !windows

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

// Every failure to inspect a file that is there is config_unsafe, in Load and in
// ReadSecretFile alike (Load said config_invalid). A name longer than the file system
// allows fails the inspection with an error that is not "does not exist", as a
// directory the user may not search does, and it does so for root too.
func TestAnInspectionFailureIsConfigUnsafeInLoadAndReadSecretFile(t *testing.T) {
	long := filepath.Join(t.TempDir(), strings.Repeat("d", 300))
	if _, err := os.Lstat(filepath.Join(long, FileName)); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Lstat of a 300-byte name = %v: this file system does not refuse it the way the test needs", err)
	}
	_, err := Load(Dirs{System: long, User: filepath.Join(t.TempDir(), "usr")}, allowAll)
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ConfigUnsafe || !strings.Contains(e.Message, "cannot inspect") {
		t.Errorf("Load: err = %v, want config_unsafe, cannot inspect", err)
	}
	_, err = ReadSecretFile(filepath.Join(long, "read.env"))
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ConfigUnsafe || !strings.Contains(e.Message, "cannot inspect") {
		t.Errorf("ReadSecretFile: err = %v, want config_unsafe, cannot inspect", err)
	}
}
