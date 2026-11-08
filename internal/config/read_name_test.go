package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// A credential, key or token file is held to the name rules a policy file is held to: on
// Windows a UNC path, a device name or an alternate data stream is refused before the file is
// opened (internal/safefile). These tests make the check refuse a name on every platform, so
// that the wiring is tested here and not only on a Windows runner; read_name_windows_test.go
// runs the real names there.

const refusedName = "device names are refused"

// refuseNameOf makes nameProblem refuse the path p, and only that one, for one test.
func refuseNameOf(t *testing.T, p string) {
	t.Helper()
	old := nameProblem
	nameProblem = func(q string) string {
		if q == p {
			return refusedName
		}
		return ""
	}
	t.Cleanup(func() { nameProblem = old })
}

func TestReadCheckedLimitRefusesANameBeforeItOpensTheFile(t *testing.T) {
	p, want := secretFile(t, 64)
	refuseNameOf(t, p)
	opened := false
	hooks(t, func(*os.File) { opened = true }, nil)
	data, err := readCheckedLimit(p, want, secretCap)
	code, msg := refusal(t, data, err)
	if code != tkerr.ConfigUnsafe || !strings.Contains(msg, p) || !strings.Contains(msg, refusedName) {
		t.Errorf("code %q, message %q: want config_unsafe naming the path and the reason", code, msg)
	}
	if opened {
		t.Error("the file was opened and read before its name was refused")
	}
	// The unbounded read (the configuration) shares the function, so it shares the refusal.
	if data, err := readCheckedLimit(p, want, 0); err == nil || len(data) != 0 {
		t.Errorf("the configuration read of a refused name: %d bytes, %v", len(data), err)
	}
}

func TestReadSecretFileRefusesANameBeforeItInspectsTheFile(t *testing.T) {
	p, _ := secretFile(t, 64)
	refuseNameOf(t, p)
	didInspect := false
	old := inspectPath
	inspectPath = func(q string) (inspected, error) { didInspect = true; return old(q) }
	t.Cleanup(func() { inspectPath = old })
	data, err := ReadSecretFile(p)
	code, msg := refusal(t, data, err)
	if code != tkerr.ConfigUnsafe || !strings.Contains(msg, p) || !strings.Contains(msg, refusedName) {
		t.Errorf("code %q, message %q: want config_unsafe naming the path and the reason", code, msg)
	}
	if strings.Contains(msg, "cannot inspect") || didInspect {
		t.Errorf("the file was inspected before its name was refused: %q", msg)
	}
}

// A name nothing refuses is read as before, so the check does not make a good path unreadable.
func TestAnAcceptedNameIsStillRead(t *testing.T) {
	p, want := secretFile(t, 64)
	refuseNameOf(t, filepath.Join(filepath.Dir(p), "other"))
	data, err := readCheckedLimit(p, want, secretCap)
	if err != nil || len(data) != 64 {
		t.Fatalf("%d bytes, %v", len(data), err)
	}
}
