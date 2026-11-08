package releasebundle

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"testing"
)

func thin(cpu uint32, sub uint32) []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], cpu)
	binary.LittleEndian.PutUint32(b[8:], sub)
	binary.LittleEndian.PutUint32(b[12:], 2)
	return b
}

func fat(a, b []byte, reverse bool) []byte {
	if reverse {
		a, b = b, a
	}
	out := make([]byte, 32768+len(b))
	binary.BigEndian.PutUint32(out, 0xcafebabe)
	binary.BigEndian.PutUint32(out[4:], 2)
	for i, p := range [][]byte{a, b} {
		off := 16384 + i*16384
		h := out[8+i*20:]
		binary.BigEndian.PutUint32(h, binary.LittleEndian.Uint32(p[4:]))
		binary.BigEndian.PutUint32(h[4:], binary.LittleEndian.Uint32(p[8:]))
		binary.BigEndian.PutUint32(h[8:], uint32(off))
		binary.BigEndian.PutUint32(h[12:], uint32(len(p)))
		binary.BigEndian.PutUint32(h[16:], 14)
		copy(out[off:], p)
	}
	return out
}

func TestCanonicalDarwinPreservesExactlyTwoSlices(t *testing.T) {
	a, b := thin(0x01000007, 3), thin(0x0100000c, 0)
	x, err := CanonicalDarwin(fat(a, b, false))
	if err != nil {
		t.Fatal(err)
	}
	y, err := CanonicalDarwin(fat(a, b, true))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x, y) {
		t.Fatal("slice order changed canonical output")
	}
	f, err := macho.NewFatFile(bytes.NewReader(x))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Arches) != 2 || !bytes.Equal(x[f.Arches[0].Offset:f.Arches[0].Offset+f.Arches[0].Size], a) || !bytes.Equal(x[f.Arches[1].Offset:f.Arches[1].Offset+f.Arches[1].Size], b) {
		t.Fatal("slice bytes changed")
	}
}

func TestCanonicalDarwinRejectsInvalid(t *testing.T) {
	a, b := thin(0x01000007, 3), thin(0x0100000c, 0)
	positive := fat(a, b, false)
	if _, err := CanonicalDarwin(positive); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]byte) []byte{
		"outer CPU mismatch": func(v []byte) []byte {
			binary.BigEndian.PutUint32(v[8:], 0x0100000c)
			binary.BigEndian.PutUint32(v[28:], 0x01000007)
			return v
		},
		"outer subtype mismatch": func(v []byte) []byte { binary.BigEndian.PutUint32(v[12:], 4); return v },
		"duplicate CPU":          func(v []byte) []byte { binary.BigEndian.PutUint32(v[28:], 0x01000007); return v },
		"unknown CPU":            func(v []byte) []byte { binary.BigEndian.PutUint32(v[28:], 0x01000012); return v },
		"oversize":               func(v []byte) []byte { binary.BigEndian.PutUint32(v[40:], 1024); return v },
		"overlap":                func(v []byte) []byte { binary.BigEndian.PutUint32(v[36:], 16384); return v },
		"header overlap":         func(v []byte) []byte { binary.BigEndian.PutUint32(v[16:], 0); return v },
		"trailing":               func(v []byte) []byte { return append(v, 0) },
		"nonzero padding":        func(v []byte) []byte { v[100] = 1; return v },
		"not executable":         func(v []byte) []byte { binary.LittleEndian.PutUint32(v[16384+12:], 1); return v },
		"bad count":              func(v []byte) []byte { binary.BigEndian.PutUint32(v[4:], 1); return v },
		"linux":                  func(v []byte) []byte { return []byte("\x7fELF") },
		"windows":                func(v []byte) []byte { return []byte("MZ") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := mutate(bytes.Clone(positive))
			if _, err := CanonicalDarwin(v); err == nil {
				t.Fatal("accepted malformed input")
			}
		})
	}
	for _, name := range []string{"outer CPU mismatch", "outer subtype mismatch", "oversize"} {
		v := cases[name](bytes.Clone(positive))
		if _, err := macho.NewFatFile(bytes.NewReader(v)); err != nil {
			t.Errorf("stdlib positive control %s: %v", name, err)
		}
	}
}

func sectionThin() []byte {
	b := make([]byte, 256)
	copy(b, thin(0x01000007, 3))
	binary.LittleEndian.PutUint32(b[16:], 1)
	binary.LittleEndian.PutUint32(b[20:], 152)
	cmd := b[32:]
	binary.LittleEndian.PutUint32(cmd, 0x19)
	binary.LittleEndian.PutUint32(cmd[4:], 152)
	binary.LittleEndian.PutUint64(cmd[48:], 256)
	binary.LittleEndian.PutUint32(cmd[64:], 1)
	sec := cmd[72:]
	binary.LittleEndian.PutUint64(sec[40:], 4)
	binary.LittleEndian.PutUint32(sec[48:], 200)
	return b
}

func TestCanonicalDarwinRejectsSectionsOverlappingHeaders(t *testing.T) {
	a, b := sectionThin(), thin(0x0100000c, 0)
	good := fat(a, b, false)
	if _, err := CanonicalDarwin(good); err != nil {
		t.Fatalf("positive fixture: %v", err)
	}
	bad := bytes.Clone(good)
	binary.LittleEndian.PutUint32(bad[16384+32+72+48:], 10)
	if _, err := macho.NewFatFile(bytes.NewReader(bad)); err != nil {
		t.Fatalf("parser control: %v", err)
	}
	if _, err := CanonicalDarwin(bad); err == nil {
		t.Fatal("accepted section overlapping Mach-O headers")
	}
	oversized := bytes.Clone(good)
	binary.LittleEndian.PutUint32(oversized[16384+32+72+48:], 254)
	if _, err := macho.NewFatFile(bytes.NewReader(oversized)); err != nil {
		t.Fatalf("section bounds parser control: %v", err)
	}
	if _, err := CanonicalDarwin(oversized); err == nil {
		t.Fatal("accepted section extending past slice")
	}
}

func TestCanonicalDarwinRejectsOverlappingSlicesAndInvalidSecondSlice(t *testing.T) {
	good := fat(thin(0x01000007, 3), thin(0x0100000c, 0), false)
	if _, err := CanonicalDarwin(good); err != nil {
		t.Fatal(err)
	}
	overlap := bytes.Clone(good)
	binary.BigEndian.PutUint32(overlap[20:], 16384+32)
	if _, err := macho.NewFatFile(bytes.NewReader(overlap)); err != nil {
		t.Fatalf("parser control: %v", err)
	}
	if _, err := CanonicalDarwin(overlap); err == nil {
		t.Fatal("accepted overlapping FAT slices")
	}
	duplicate := fat(thin(0x01000007, 3), thin(0x01000007, 3), false)
	if _, err := CanonicalDarwin(duplicate); err == nil {
		t.Fatal("accepted two valid amd64 slices")
	}
	broken := bytes.Clone(good)
	broken[32768] = 0
	if _, err := CanonicalDarwin(broken); err == nil {
		t.Fatal("accepted invalid second slice")
	}
}

func TestCanonicalDarwinChecksSegmentBoundsAndZeroFill(t *testing.T) {
	a := sectionThin()
	arm := thin(0x0100000c, 0)
	valid := fat(a, arm, false)
	if _, err := CanonicalDarwin(valid); err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Clone(valid)
	binary.LittleEndian.PutUint64(oversized[16384+32+48:], 257)
	if _, err := macho.NewFatFile(bytes.NewReader(oversized)); err != nil {
		t.Fatalf("parser control: %v", err)
	}
	if _, err := CanonicalDarwin(oversized); err == nil {
		t.Fatal("accepted segment exceeding slice")
	}
	zeroFill := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(zeroFill[16384+32+72+64:], 1)
	binary.LittleEndian.PutUint32(zeroFill[16384+32+72+48:], 0)
	if _, err := CanonicalDarwin(zeroFill); err != nil {
		t.Fatalf("valid zero-fill section: %v", err)
	}
}

func TestCanonicalDarwinRejectsBigEndianAndSectionsOutsideParent(t *testing.T) {
	a, b := sectionThin(), thin(0x0100000c, 0)
	if _, err := CanonicalDarwin(fat(a, b, false)); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	outside := fat(a, b, false)
	binary.LittleEndian.PutUint64(outside[16384+32+48:], 190)
	if _, err := macho.NewFatFile(bytes.NewReader(outside)); err != nil {
		t.Fatalf("parser control: %v", err)
	}
	if _, err := CanonicalDarwin(outside); err == nil {
		t.Error("accepted section outside parent segment")
	}
	big := make([]byte, 32)
	binary.BigEndian.PutUint32(big, 0xfeedfacf)
	binary.BigEndian.PutUint32(big[4:], 0x01000007)
	binary.BigEndian.PutUint32(big[8:], 3)
	binary.BigEndian.PutUint32(big[12:], 2)
	be := fat(a, b, false)
	copy(be[16384:], big)
	if _, err := macho.NewFatFile(bytes.NewReader(be)); err != nil {
		t.Fatalf("big endian parser control: %v", err)
	}
	if _, err := CanonicalDarwin(be); err == nil {
		t.Error("accepted big endian Darwin binary")
	}
}

func TestCanonicalDarwinChecksParentSegmentNameAndOtherLoadCommands(t *testing.T) {
	a, b := sectionThin(), thin(0x0100000c, 0)
	good := fat(a, b, false)
	if _, err := CanonicalDarwin(good); err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Clone(good)
	copy(wrong[16384+32+72+16:], "wrong-parent")
	if _, err := macho.NewFatFile(bytes.NewReader(wrong)); err != nil {
		t.Fatalf("parser control: %v", err)
	}
	if _, err := CanonicalDarwin(wrong); err == nil {
		t.Fatal("accepted wrong segment name")
	}
	withExtra := bytes.Clone(a)
	binary.LittleEndian.PutUint32(withExtra[16:], 2)
	binary.LittleEndian.PutUint32(withExtra[20:], 176)
	binary.LittleEndian.PutUint32(withExtra[32+72+48:], 220)
	binary.LittleEndian.PutUint32(withExtra[184:], 0x1b)
	binary.LittleEndian.PutUint32(withExtra[188:], 24)
	if _, err := CanonicalDarwin(fat(withExtra, b, false)); err != nil {
		t.Fatalf("valid additional load: %v", err)
	}
}

func TestCanonicalLayoutEnforcesLimitAndOverflow(t *testing.T) {
	off, total, err := canonicalLayout(32, 32)
	if err != nil || off != 32768 || total != 32800 {
		t.Fatalf("normal layout: %d %d %v", off, total, err)
	}
	offset := align(fatAlignment + 32)
	if _, total, err := canonicalLayout(32, maxBinarySize-offset); err != nil || total != maxBinarySize {
		t.Fatalf("exact limit: %d %v", total, err)
	}
	if _, _, err := canonicalLayout(32, maxBinarySize-offset+1); err == nil {
		t.Fatal("accepted one byte over limit")
	}
	for _, v := range []struct{ first, second uint64 }{{maxBinarySize, 1}, {1, maxBinarySize}, {^uint64(0), 1}, {1, ^uint64(0)}} {
		if _, _, err := canonicalLayout(v.first, v.second); err == nil {
			t.Errorf("accepted oversized layout: %d %d", v.first, v.second)
		}
	}
}
