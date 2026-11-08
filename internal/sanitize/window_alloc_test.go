package sanitize

import (
	"runtime"
	"strings"
	"testing"
)

// shown is what a result shows for an untrusted string: as registry.Env.Display runs it
// when the owner has not opted in to personal data.
func shown(m Masker, s string, limit int) string {
	r := struct {
		Name string `tk:"untrusted"`
	}{s}
	m.MaskCapped(&r, limit)
	Fields(&r, limit)
	return r.Name
}

// What a hostile string costs (VIGIL-PERF-001). A 4 MiB string dense with addresses,
// emails and credential shapes is masked, redacted and escaped whole before its first
// 1,024 bytes are kept. The window bounds the work by itself, not by the string.
func TestAHostileStringCostsBoundedAllocation(t *testing.T) {
	const size = 4 << 20
	keyed, _ := keyedMasker(t)
	var b strings.Builder
	for b.Len() < size {
		b.WriteString("amy@example.com 203.0.113.77 2001:db8:abcd:1234:5678:9abc:def0:1111 tskey-api-kABCDEFGH 0x08080808 ")
	}
	s := b.String()[:size]
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got := shown(keyed, s, DefaultMax)
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("a %d MiB hostile string allocated %d KiB (%.1f times its size)", size>>20, alloc>>10, float64(alloc)/size)
	const limit = 12 << 20
	if alloc > limit {
		t.Errorf("a %d MiB hostile string allocated %d KiB, want at most %d KiB", size>>20, alloc>>10, limit>>10)
	}
	if len(got) > DefaultMax || !strings.HasSuffix(got, truncatedSuffix) {
		t.Errorf("display = %.80q (%d bytes), want a capped text that ends with the notice", got, len(got))
	}
}
