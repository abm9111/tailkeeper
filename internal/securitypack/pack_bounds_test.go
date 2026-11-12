package securitypack

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/security"
)

func TestPackPreflightBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want error
	}{
		{"size inclusive", bytes.Repeat([]byte{' '}, MaxPackBytes), nil},
		{"size exceeded", bytes.Repeat([]byte{' '}, MaxPackBytes+1), ErrTooLarge},
		{"depth inclusive", []byte(strings.Repeat("[", 12) + strings.Repeat("]", 12)), nil},
		{"depth exceeded", []byte(strings.Repeat("[", 13) + strings.Repeat("]", 13)), ErrTooDeep},
		{"nodes inclusive", []byte("[" + strings.Repeat(",", MaxPackNodes-2) + "]"), nil},
		{"nodes exceeded", []byte("[" + strings.Repeat(",", MaxPackNodes-1) + "]"), ErrTooManyValues},
		{"invalid UTF-8", []byte{0xff}, ErrInvalidPack},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := preflightPack(tc.data); !errors.Is(got, tc.want) {
				t.Fatalf("preflightPack() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPackCatalogBytesLimit(t *testing.T) {
	if !packCatalogBytesWithinLimit([]packSource{{Data: make([]byte, maxCatalogBytes)}}) {
		t.Fatal("inclusive limit rejected")
	}
	if packCatalogBytesWithinLimit([]packSource{{Data: make([]byte, maxCatalogBytes)}, {Data: []byte{0}}}) {
		t.Fatal("cumulative over-limit accepted")
	}
}

func TestPackPreflightDoesNotAllocate(t *testing.T) {
	deep := []byte(strings.Repeat("[", 13))
	nodes := []byte("[" + strings.Repeat(",", MaxPackNodes-1) + "]")
	for _, data := range [][]byte{deep, nodes} {
		if allocations := testing.AllocsPerRun(3, func() { _ = preflightPack(data) }); allocations != 0 {
			t.Fatalf("preflight allocated %.1f times", allocations)
		}
	}
}

func TestPackLargeIntentAndPostureAreNotSilentlyCapped(t *testing.T) {
	in := validPackInput()
	intent := security.IntentSet{SchemaVersion: 1, Network: make([]security.NetworkExpectation, 10001)}
	attributes := make(security.PostureAttributes, 10001)
	for i := 0; i < 10001; i++ {
		intent.Network[i] = security.NetworkExpectation{ID: fmt.Sprintf("network-%d", i+1), Source: "group"}
		attributes[fmt.Sprintf("attribute-%05d", i)] = security.Scalar{Kind: security.ScalarBool}
	}
	intent.Network[0].SourcePostureAttributes = attributes
	in.Intent = &intent
	pack, err := newPack(in, nil)
	if err != nil {
		t.Fatalf("large bounded intent: %v", err)
	}
	wire, err := Encode(pack)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := Decode(wire, nil)
	if err != nil {
		t.Fatalf("decode large intent: %v", err)
	}
	out, err := packInputOf(decoded)
	if err != nil || len(out.Intent.Network) != 10001 || len(out.Intent.Network[0].SourcePostureAttributes) != 10001 {
		t.Fatalf("large intent truncated: %v", err)
	}
}

func TestPackCatalogSourceLimits(t *testing.T) {
	in := validPackInput()
	original := in.Sources[0].Data
	in.Sources[0].Data = append(original, bytes.Repeat([]byte{' '}, maxCatalogBytes-len(original))...)
	pack, err := newPack(in, nil)
	if err != nil {
		t.Fatalf("inclusive catalog byte limit: %v", err)
	}
	wire, err := Encode(pack)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(wire, nil); err != nil {
		t.Fatalf("inclusive catalog decode: %v", err)
	}
	in.Sources[0].Data = append(in.Sources[0].Data, ' ')
	if _, err := newPack(in, nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("catalog byte overflow: %v", err)
	}

	in = validPackInput()
	data := in.Sources[0].Data
	in.Sources = make([]advisory.Source, 64)
	for i := range in.Sources {
		in.Sources[i] = advisory.Source{Name: fmt.Sprintf("source-%02d", i), Data: data}
	}
	if _, err := newPack(in, nil); err != nil {
		t.Fatalf("inclusive source count: %v", err)
	}
	in.Sources = append(in.Sources, advisory.Source{Name: "source-64", Data: data})
	if _, err := newPack(in, nil); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("source count overflow: %v", err)
	}
}
