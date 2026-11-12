package releasebundle

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"sort"
)

const maxBinarySize = 256 << 20
const fatHeaderSize = 48
const fatAlignment = 16384

type fatSlice struct {
	cpu, sub     uint32
	offset, size uint32
	data         []byte
}

// CanonicalDarwin validates and rewrites a two-architecture FAT executable.
func CanonicalDarwin(data []byte) ([]byte, error) {
	slices, err := parseDarwin(data)
	if err != nil {
		return nil, err
	}
	sort.Slice(slices, func(i, j int) bool { return slices[i].cpu < slices[j].cpu })
	second, total, err := canonicalLayout(uint64(len(slices[0].data)), uint64(len(slices[1].data)))
	if err != nil {
		return nil, err
	}
	out := make([]byte, total)
	binary.BigEndian.PutUint32(out, 0xcafebabe)
	binary.BigEndian.PutUint32(out[4:], 2)
	for i, s := range slices {
		off := uint64(fatAlignment)
		if i == 1 {
			off = second
		}
		h := out[8+i*20:]
		binary.BigEndian.PutUint32(h, s.cpu)
		binary.BigEndian.PutUint32(h[4:], s.sub)
		put32(h[8:], off)
		put32(h[12:], uint64(len(s.data)))
		binary.BigEndian.PutUint32(h[16:], 14)
		copy(out[off:], s.data)
	}
	return out, nil
}

func put32(dst []byte, n uint64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], n)
	copy(dst, buf[4:])
}

func align(n uint64) uint64 { return (n + fatAlignment - 1) &^ (fatAlignment - 1) }

func parseDarwin(data []byte) ([]fatSlice, error) {
	if len(data) < fatHeaderSize || len(data) > maxBinarySize || binary.BigEndian.Uint32(data) != 0xcafebabe || binary.BigEndian.Uint32(data[4:]) != 2 {
		return nil, fmt.Errorf("expected two-slice FAT executable")
	}
	slices := make([]fatSlice, 2)
	for i := range slices {
		s, err := parseFatSlice(data, i)
		if err != nil {
			return nil, err
		}
		slices[i] = s
	}
	if slices[0].cpu == slices[1].cpu {
		return nil, fmt.Errorf("duplicate architecture")
	}
	sort.Slice(slices, func(i, j int) bool { return slices[i].offset < slices[j].offset })
	end := uint64(fatHeaderSize)
	for _, s := range slices {
		if uint64(s.offset) < end {
			return nil, fmt.Errorf("overlapping FAT slices")
		}
		if !allZero(data[end:uint64(s.offset)]) {
			return nil, fmt.Errorf("nonzero FAT padding")
		}
		end = uint64(s.offset) + uint64(s.size)
	}
	if end != uint64(len(data)) {
		return nil, fmt.Errorf("trailing FAT data")
	}
	return slices, nil
}

func parseFatSlice(data []byte, i int) (fatSlice, error) {
	h := data[8+i*20:]
	s := fatSlice{cpu: binary.BigEndian.Uint32(h), sub: binary.BigEndian.Uint32(h[4:]), offset: binary.BigEndian.Uint32(h[8:]), size: binary.BigEndian.Uint32(h[12:])}
	exp := binary.BigEndian.Uint32(h[16:])
	if s.cpu != 0x01000007 && s.cpu != 0x0100000c {
		return s, fmt.Errorf("unsupported architecture")
	}
	if exp > 30 || s.offset < fatHeaderSize || uint64(s.offset)%(uint64(1)<<exp) != 0 || s.size == 0 || uint64(s.offset)+uint64(s.size) > uint64(len(data)) {
		return s, fmt.Errorf("invalid FAT slice bounds or alignment")
	}
	s.data = data[s.offset : uint64(s.offset)+uint64(s.size)]
	f, err := macho.NewFile(bytes.NewReader(s.data))
	if err != nil {
		return s, fmt.Errorf("invalid Mach-O: %w", err)
	}
	if f.ByteOrder != binary.LittleEndian || f.Magic != macho.Magic64 || uint32(f.Cpu) != s.cpu || f.SubCpu != s.sub || f.Type != macho.TypeExec {
		return s, fmt.Errorf("FAT identity or executable mismatch")
	}
	if err := validateMachOBounds(f, uint64(len(s.data))); err != nil {
		return s, err
	}
	return s, nil
}

func validateMachOBounds(f *macho.File, size uint64) error {
	index := 0
	for _, load := range f.Loads {
		seg, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		if seg.Offset > size || seg.Filesz > size-seg.Offset {
			return fmt.Errorf("Mach-O segment exceeds slice")
		}
		for n := uint32(0); n < seg.Nsect; n++ {
			if index >= len(f.Sections) {
				return fmt.Errorf("missing Mach-O section")
			}
			if err := validateSection(f.Sections[index], seg, f.Cmdsz, size); err != nil {
				return err
			}
			index++
		}
	}
	if index != len(f.Sections) {
		return fmt.Errorf("unmatched Mach-O sections")
	}
	return nil
}

func validateSection(s *macho.Section, seg *macho.Segment, cmdSize uint32, size uint64) error {
	if s.Seg != seg.Name {
		return fmt.Errorf("Mach-O section has wrong parent")
	}
	kind := s.Flags & 0xff
	if kind == 1 || kind == 0xc || kind == 0x12 {
		return nil
	}
	start := uint64(s.Offset)
	if (s.Size > 0 && start < 32+uint64(cmdSize)) || start > size || s.Size > size-start {
		return fmt.Errorf("Mach-O section exceeds slice")
	}
	if start < seg.Offset || start-seg.Offset > seg.Filesz || s.Size > seg.Filesz-(start-seg.Offset) {
		return fmt.Errorf("Mach-O section exceeds parent segment")
	}
	return nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func canonicalLayout(first, second uint64) (uint64, uint64, error) {
	if first > maxBinarySize-fatAlignment || second > maxBinarySize {
		return 0, 0, fmt.Errorf("canonical executable exceeds limit")
	}
	offset := align(uint64(fatAlignment) + first)
	if second > maxBinarySize-offset {
		return 0, 0, fmt.Errorf("canonical executable exceeds limit")
	}
	return offset, offset + second, nil
}
