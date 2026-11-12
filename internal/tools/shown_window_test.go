package tools

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/registry"
)

// hostileText is a string of size bytes dense with addresses, emails and credential shapes.
func hostileText(size int) string {
	var b strings.Builder
	for b.Len() < size {
		b.WriteString("amy@example.com 203.0.113.77 2001:db8:abcd:1234:5678:9abc:def0:1111 tskey-api-kABCDEFGH ")
	}
	return b.String()[:size]
}

// allocated is the bytes f allocates.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// The helpers that count what a result will show (shownText, which budgets read) and that
// make the preview of an audit value (digestPreview) mask a long string through the same
// window as the registry does (VIGIL-PERF-001): a 4 MiB hostile string was masked whole
// to show 1,024 bytes of it, and 256 of a preview.
func TestShownTextAndPreviewMaskThroughTheWindow(t *testing.T) {
	const size = 4 << 20
	const limit = 12 << 20
	env := &registry.Env{}
	hostile := hostileText(size)

	var shown string
	alloc := allocated(func() { shown = shownText(env, hostile) })
	t.Logf("shownText of a %d MiB hostile string allocated %d KiB", size>>20, alloc>>10)
	if alloc > limit {
		t.Errorf("shownText of a %d MiB hostile string allocated %d KiB, want at most %d KiB", size>>20, alloc>>10, limit>>10)
	}
	if len(shown) > 128<<10 || strings.Contains(shown, "amy@") && !strings.Contains(shown, "a…@") {
		t.Errorf("shownText = %d bytes, %.80q", len(shown), shown)
	}

	raw, err := json.Marshal(hostile)
	if err != nil {
		t.Fatal(err)
	}
	var preview string
	alloc = allocated(func() { _, preview = digestPreview(raw, env, true) })
	t.Logf("digestPreview of a %d MiB hostile string allocated %d KiB", size>>20, alloc>>10)
	// The decoding of the value, the removal of credential-named values and the cut of URLs
	// before the mask still read the whole value (about four times its size, bounded by the
	// response cap); the masking and the cap no longer do. The whole-string pass allocated
	// 356,622 KiB.
	const previewLimit = 24 << 20
	if alloc > previewLimit {
		t.Errorf("digestPreview of a %d MiB hostile string allocated %d KiB, want at most %d KiB", size>>20, alloc>>10, previewLimit>>10)
	}
	if len(preview) > 256 || strings.Contains(preview, "amy@") || strings.Contains(preview, "203.0.113.77") {
		t.Errorf("preview = %q", preview)
	}
}

// A budget counts a value by what the registry shows of it: the cost of shownText is the
// length of what Display makes of the field, below the window and over it, masked and shown.
func TestShownCostCountsWhatDisplayShowsOverTheWindow(t *testing.T) {
	type row struct {
		Note string `json:"note" tk:"untrusted"`
	}
	ordinary := strings.Repeat("host amy@example.com seen at 203.0.113.9 and 2001:db8:abcd::1, ", 4000)
	for name, env := range map[string]*registry.Env{
		"masked": {},
		"shown":  {Config: &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}},
	} {
		for what, text := range map[string]string{
			"short":                "owner amy@example.com",
			"under the window":     ordinary[:60<<10],
			"over the window":      ordinary,
			"hostile, no cut byte": strings.Repeat("a", 100<<10) + "@example.com",
			"credential, cut":      strings.Repeat("filler ", 10000) + "tskey-api-k" + strings.Repeat("A", 60<<10),
		} {
			r := row{Note: text}
			env.Display(&r)
			if got, want := shownCost(shownText(env, text)), encodedLen(r.Note)+3; got != want {
				t.Errorf("%s, %s: shownCost(shownText) = %d, but Display shows %d", name, what, got, want)
			}
		}
	}
}
