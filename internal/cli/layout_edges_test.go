package cli

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"
)

// Every write of every layout is checked: when the writer fails at any position,
// whatever the case prints, the error comes back.
func TestEveryWriteOfEveryLayoutIsChecked(t *testing.T) {
	for _, c := range layoutCases {
		for at := 1; ; at++ {
			w := &failingWriter{at: at}
			err := formatText(w, c.rep, formatOptions{Names: c.names})
			if !w.tripped {
				if err != nil {
					t.Errorf("%s: a working writer failed after %d writes: %v", c.name, w.n, err)
				}
				break
			}
			if err == nil {
				t.Errorf("%s: write %d failed and formatText returned nil", c.name, at)
				break
			}
		}
	}
}

// The formats that exist are listed once each: text, then json, then the others in
// order.
func TestFormatNamesListEachFormatOnce(t *testing.T) {
	if got := strings.Join(formatNames(), ","); got != "text,json" {
		t.Errorf("formatNames = %s", got)
	}
	formatters["zeta"], formatters["alpha"] = formatText, formatText
	defer delete(formatters, "zeta")
	defer delete(formatters, "alpha")
	if got := strings.Join(formatNames(), ","); got != "text,json,alpha,zeta" {
		t.Errorf("formatNames with two more formats = %s", got)
	}
}

// Only a character device counts as a terminal: not a buffer, not a regular file.
func TestOnlyACharacterDeviceIsATerminal(t *testing.T) {
	if isTerminal(&bytes.Buffer{}) {
		t.Error("a buffer is not a terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if isTerminal(f) {
		t.Error("a regular file is not a terminal")
	}
	if runtime.GOOS == "windows" {
		return
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skip("no null device")
	}
	t.Cleanup(func() { _ = null.Close() })
	if !isTerminal(null) {
		t.Error("a character device is taken for a file")
	}
}

type absentFirstOut struct {
	Omitted *bool  `json:"omitted" tk:"absentok"`
	After   string `json:"after"`
}

// A field left out on purpose does not end the listing.
func TestRenderKeepsGoingPastAFieldLeftOutOnPurpose(t *testing.T) {
	var b strings.Builder
	if err := render(&b, absentFirstOut{After: "x"}); err != nil || b.String() != "after: x\n" {
		t.Errorf("render = %q, %v", b.String(), err)
	}
}
