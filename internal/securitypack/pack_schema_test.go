package securitypack

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestPackTypedCanonicalBoundary(t *testing.T) {
	input, err := encodePackEnvelope(codecFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readPackEnvelope(input); err != nil {
		t.Fatalf("canonical fixture: %v", err)
	}
	for _, tc := range []struct {
		name string
		old  string
		new  string
		want error
	}{
		{"missing required false", `,"rules_partial":false`, ``, ErrNotCanonical},
		{"missing required zero", `,"limit":0`, ``, ErrNotCanonical},
		{"null required false", `"rules_partial":false`, `"rules_partial":null`, ErrNotCanonical},
		{"duplicate key", `"rules_partial":false`, `"rules_partial":false,"rules_partial":false`, ErrNotCanonical},
		{"wrong case key", `"rules_partial":false`, `"Rules_partial":false`, ErrNotCanonical},
		{"unknown key", `"rules_partial":false`, `"unknown":false,"rules_partial":false`, ErrInvalidPack},
		{"unnecessary escape", `"rules_partial":false`, `"rules_partial":false `, ErrNotCanonical},
		{"base64 pad bits", `"YWxwaGE="`, `"YWxwaGF="`, ErrNotCanonical},
		{"base64 missing padding", `"YWxwaGE="`, `"YWxwaGE"`, ErrInvalidPack},
		{"base64 escaped newline", `"YWxwaGE="`, `"YWxw\nYGE="`, ErrNotCanonical},
		{"negative zero", `"limit":0`, `"limit":-0`, ErrNotCanonical},
		{"fractional integer", `"limit":0`, `"limit":0.0`, ErrInvalidPack},
		{"exponent integer", `"limit":0`, `"limit":0e0`, ErrInvalidPack},
		{"zero optional integer", `"omitted":2`, `"omitted":0`, ErrNotCanonical},
		{"escaped key", `"rules_partial":false`, `"rules_\u0070artial":false`, ErrNotCanonical},
		{"utc offset", `2019-01-02T03:04:05.123456789Z`, `2019-01-02T03:04:05.123456789+00:00`, ErrNotCanonical},
		{"alternate time fraction", `2019-01-02T03:04:05.123456789Z`, `2019-01-02T03:04:05.1234567890Z`, ErrNotCanonical},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !bytes.Contains(input, []byte(tc.old)) {
				t.Fatal("test replacement did not match")
			}
			changed := bytes.Replace(input, []byte(tc.old), []byte(tc.new), 1)
			if _, err := readPackEnvelope(changed); !errors.Is(err, tc.want) {
				t.Fatalf("readPackEnvelope() = %v, want %v", err, tc.want)
			}
		})
	}
	for _, suffix := range [][]byte{nil, []byte("\n\n"), []byte("{}\n")} {
		changed := append(append([]byte(nil), input[:len(input)-1]...), suffix...)
		if _, err := readPackEnvelope(changed); err == nil {
			t.Fatal("accepted invalid root framing")
		}
	}
}

func FuzzPackDecodeSyntax(f *testing.F) {
	seed, err := encodePackEnvelope(codecFixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxPackBytes {
			t.Skip()
		}
		envelope, err := readPackEnvelope(data)
		if err != nil {
			return
		}
		encoded, err := encodePackEnvelope(envelope)
		if err != nil || !bytes.Equal(data, encoded) {
			t.Fatal("accepted input did not round-trip")
		}
	})
}

func TestPackRefusesProjectionMarker(t *testing.T) {
	input := []byte("{\"format\":\"tailkeeper-evidence-projection\"}\n")
	pack, reading, err := Decode(input, nil)
	if !errors.Is(err, ErrProjectionNotReplayable) || pack.valid || reading != (Reading{}) {
		t.Fatalf("projection refusal: %v", err)
	}
	tooDeep := append([]byte(strings.Repeat("[", 13)), input...)
	if _, _, err := Decode(tooDeep, nil); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("preflight must precede projection detection: %v", err)
	}
}
