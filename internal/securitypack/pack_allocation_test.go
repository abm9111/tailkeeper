package securitypack

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/security"
)

var packAllocationControl []byte

func packAllocationWithin(allocated, limit uint64) bool { return allocated <= limit }

func TestPackRepeatedNearLimitDecodeAllocations(t *testing.T) {
	// Construct and encode the full fixture before taking any measurements.
	in := validPackInput()
	in.Sources[0].Data = append(in.Sources[0].Data, bytes.Repeat([]byte{' '}, maxCatalogBytes-len(in.Sources[0].Data))...)
	evidence := security.EvidenceRef{Context: "ctx-local-only", Asset: "asset", Scope: security.ScopeLocal, Origin: security.OriginLocal, AcquiredAt: in.EvaluationAt, Freshness: security.FreshnessFresh}
	name := strings.Repeat("f", security.MaxTextBytes)
	in.Snapshot.Features = make([]security.FeatureFact, 2200)
	for i := range in.Snapshot.Features {
		in.Snapshot.Features[i] = security.FeatureFact{Name: name, Evidence: evidence}
	}
	in.Expected.Counts = packExpectedCounts{Devices: 1, Features: len(in.Snapshot.Features)}
	pack, err := newPack(in, nil)
	if err != nil {
		t.Fatalf("near-limit producer: %v", err)
	}
	wire, err := Encode(pack)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) < 14<<20 || len(wire) > MaxPackBytes {
		t.Fatalf("unexpected fixture size: %d", len(wire))
	}
	if _, _, err := Decode(wire, nil); err != nil {
		t.Fatalf("warm-up decode: %v", err)
	}

	// Positive control is 2 MiB, well below the test's fixture and budget.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	packAllocationControl = make([]byte, 2<<20)
	runtime.ReadMemStats(&after)
	control := after.TotalAlloc - before.TotalAlloc
	if control < 2<<20 || packAllocationWithin(control, 1<<20) {
		t.Fatalf("allocation detector positive control: %d", control)
	}
	packAllocationControl = nil

	const repetitions = 3
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < repetitions; i++ {
		decoded, _, err := Decode(wire, nil)
		if err != nil || !decoded.valid {
			t.Fatalf("repeated decode %d: %v", i, err)
		}
		runtime.KeepAlive(decoded)
	}
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	// This bounds cumulative Go-heap allocation across repetitions. It allows
	// The non-race budget is 32 input bytes per wire byte plus 8 MiB fixed
	// overhead per decode; the separate race build permits 64 times input.
	limit := uint64(repetitions) * (packAllocationMultiplier*uint64(len(wire)) + (8 << 20))
	t.Logf("wire_bytes=%d source_bytes=%d feature_text_bytes=%d repetitions=%d allocated_bytes=%d limit_bytes=%d control_bytes=%d", len(wire), len(in.Sources[0].Data), len(name)*len(in.Snapshot.Features), repetitions, allocated, limit, control)
	if !packAllocationWithin(allocated, limit) {
		t.Fatalf("repeated decode allocated %d bytes, above %d", allocated, limit)
	}
}
