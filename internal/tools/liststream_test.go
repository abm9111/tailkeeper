package tools

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestEmptyDeviceRowsDoNotAllocateGigabytes(t *testing.T) {
	const bodySize = 8 << 20
	var b strings.Builder
	b.Grow(bodySize + 32)
	b.WriteString(`{"devices":[`)
	for b.Len() < bodySize-2 {
		if b.Len() > len(`{"devices":[`) {
			b.WriteByte(',')
		}
		b.WriteString("{}")
	}
	b.WriteString(`]}`)

	var peak uint64
	var seen int
	n, _, err := readRows(bytes.NewReader([]byte(b.String())), "devices", func(json.RawMessage) error {
		seen++
		if seen%100000 == 0 {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak {
				peak = m.HeapAlloc
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 1000 {
		t.Fatalf("rows = %d, want thousands of empty objects", n)
	}
	const limit = 64 << 20
	if peak > limit {
		t.Fatalf("heap peaked at %d bytes for an %d byte body, limit %d", peak, b.Len(), limit)
	}
}
