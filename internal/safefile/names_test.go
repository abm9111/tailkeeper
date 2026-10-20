package safefile

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Every device name is refused whatever its directory, extension or case: the
// whole table, not a sample of it.
func TestEveryWindowsDeviceNameIsRefused(t *testing.T) {
	names := []string{"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
		"COM\u00b9", "COM\u00b2", "COM\u00b3", "LPT\u00b9", "LPT\u00b2", "LPT\u00b3"}
	for i := 0; i <= 9; i++ {
		d := string(rune('0' + i))
		names = append(names, "COM"+d, "LPT"+d)
	}
	for _, n := range names {
		for _, p := range []string{n, strings.ToLower(n), n + ".hujson", `dir\` + n, "dir/" + n + ".x", `C:\w\` + n, n + " .x"} {
			if got := windowsNameProblem(p); !strings.Contains(got, "device") {
				t.Errorf("windowsNameProblem(%q) = %q, want a device refusal", p, got)
			}
		}
	}
	if len(reserved) != 6+6+20 {
		t.Errorf("the table holds %d names, want 32", len(reserved))
	}
}

// The edges of the rules: two characters is enough for a UNC prefix and for a
// drive, one is not, and only a letter makes a drive.
func TestWindowsNameRulesAtTheirEdges(t *testing.T) {
	for p, want := range map[string]string{
		`\\`:       "UNC",
		`//`:       "UNC",
		`\/`:       "UNC",
		`/\`:       "UNC",
		`C:NUL`:    "device",
		`c:con.x`:  "device",
		`C:\NUL`:   "device",
		`@:x`:      "alternate data stream",
		`[:x`:      "alternate data stream",
		"`:x":      "alternate data stream",
		`{:x`:      "alternate data stream",
		`1:x`:      "alternate data stream",
		`::`:       "alternate data stream",
		`:x`:       "alternate data stream",
		`x:y:z`:    "alternate data stream",
		`C:a:b`:    "alternate data stream",
		`C:\a\b:c`: "alternate data stream",
	} {
		if got := windowsNameProblem(p); !strings.Contains(got, want) {
			t.Errorf("windowsNameProblem(%q) = %q, want it to mention %q", p, got, want)
		}
	}
	for _, p := range []string{"", `\`, `/`, `a`, `C:`, `A:x`, `Z:x`, `a:x`, `z:x`, `Z:`, `z:`, `A:\x`, `C:\`, `C:.`, `.`, `..`} {
		if got := windowsNameProblem(p); got != "" {
			t.Errorf("windowsNameProblem(%q) = %q, want none", p, got)
		}
	}
}

// The cap in force is the one given, down to a single byte, and the top of int64
// stops exactly one short of the top.
func TestTheLimitInForce(t *testing.T) {
	for in, want := range map[int64]int64{
		-1: MaxBytes, 0: MaxBytes, 1: 1, 2: 2, 16: 16, MaxBytes + 1: MaxBytes + 1,
		math.MaxInt64 - 1: math.MaxInt64 - 1, math.MaxInt64: math.MaxInt64 - 1,
	} {
		if got := (Options{Cap: in}).limit(); got != want {
			t.Errorf("limit with Cap %d = %d, want %d", in, got, want)
		}
	}
	p := filepath.Join(t.TempDir(), "p.hujson")
	if err := os.WriteFile(p, []byte("ab"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Read(p, Options{Cap: 1})
	refused(t, "a cap of one byte", err, tkerr.Usage, "is 2 bytes, more than the 1 bytes")
	if _, err := ReadAll(strings.NewReader("ab"), "standard input", Options{Cap: 1}); err == nil {
		t.Error("a stream of two bytes passed a cap of one")
	}
}

// The name rules belong to Windows: on any other platform a name they would
// refuse is an ordinary name, and on Windows the same name is refused before the
// file is looked at.
func TestTheNameRulesApplyOnlyOnWindows(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		for _, p := range []string{`\\?\` + filepath.Join(dir, "p.hujson"), filepath.Join(dir, "p.hujson") + ":stream", filepath.Join(dir, "nul.txt")} {
			refused(t, p, Check(p, Options{Code: tkerr.ConfigInvalid}), tkerr.ConfigInvalid, "refused")
			if _, err := Read(p, Options{}); err == nil {
				t.Errorf("Read(%q) succeeded on Windows", p)
			}
		}
		return
	}
	for _, name := range []string{"nul.txt", "con", "aux.hujson", "2026-10-17T10:00.hujson", "a:b"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := Check(p, Options{}); err != nil {
			t.Errorf("Check(%s) = %v, want a plain file name here", name, err)
		}
		if got, err := Read(p, Options{}); err != nil || string(got) != "{}" {
			t.Errorf("Read(%s) = %q, %v", name, got, err)
		}
	}
}
