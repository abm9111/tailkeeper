package registry

import (
	"runtime"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

type displayRow struct {
	Note string `json:"note" tk:"untrusted"`
}

type displayMailRow struct {
	Note string `json:"note" tk:"untrusted,emails"`
}

// Display reads a window of a long untrusted string, not all of it (VIGIL-PERF-001): a
// 4 MiB hostile string, dense with addresses, emails and credential shapes, once
// allocated about 337 MiB (84 times its size) to show 1,024 bytes of it, and 22 MiB in a
// field that masks emails only.
func TestDisplayOfAHostileStringCostsBoundedAllocation(t *testing.T) {
	const size = 4 << 20
	var b strings.Builder
	for b.Len() < size {
		b.WriteString("amy@example.com 203.0.113.77 2001:db8:abcd:1234:5678:9abc:def0:1111 tskey-api-kABCDEFGH ")
	}
	hostile := b.String()[:size]
	for name, display := range map[string]func() string{
		"untrusted text": func() string { row := displayRow{Note: hostile}; (&Env{}).Display(&row); return row.Note },
		"emails only":    func() string { row := displayMailRow{Note: hostile}; (&Env{}).Display(&row); return row.Note },
	} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		shown := display()
		runtime.ReadMemStats(&after)
		alloc := after.TotalAlloc - before.TotalAlloc
		t.Logf("%s: Display of a %d MiB hostile string allocated %d KiB", name, size>>20, alloc>>10)
		const limit = 12 << 20
		if alloc > limit {
			t.Errorf("%s: Display of a %d MiB hostile string allocated %d KiB, want at most %d KiB", name, size>>20, alloc>>10, limit>>10)
		}
		if len(shown) > ResultStringMax || !strings.HasSuffix(shown, "...[truncated]") || strings.Contains(shown, "amy@") || strings.Contains(shown, "tskey-") {
			t.Errorf("%s: shown %.120q (%d bytes)", name, shown, len(shown))
		}
	}
}

// Under the cap, and over it up to the window, Display shows what it always showed: the
// whole string masked, redacted, escaped and cut.
func TestDisplayIsByteIdenticalToMaskThenCapForStringsWithinTheWindow(t *testing.T) {
	for name, s := range map[string]string{
		"short":            "owner amy@example.com seen at 203.0.113.9",
		"empty":            "",
		"control":          "a\x1b[2Jb\u202e\x00c",
		"credential":       "see tskey-auth-abc123 and eyJabcdefghijk.eyJabcdefghijk.abcdefghijk",
		"on the cap":       strings.Repeat("x", ResultStringMax-1) + "é",
		"past the cap":     "amy@example.com " + strings.Repeat("filler ", 400) + "bob@example.com 8.8.8.8",
		"under the window": strings.Repeat("host amy@example.com 203.0.113.9 ", 1900),
	} {
		row := displayRow{Note: s}
		(&Env{}).Display(&row)
		want := displayRow{Note: s}
		sanitize.Mask(&want)
		want.Note = sanitize.String(tripwire.Redact(want.Note), ResultStringMax)
		if row.Note != want.Note {
			t.Errorf("%s: Display = %.100q, want %.100q", name, row.Note, want.Note)
		}
	}
}
