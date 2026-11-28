package releasebundle

import (
	"archive/zip"
	"bytes"
	"context"
	"debug/macho"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestEncodeBundleNamesAMissingEntry(t *testing.T) {
	complete := map[string][]byte{}
	for _, name := range entryNames {
		complete[name] = []byte(name)
	}
	if _, err := encodeBundle(complete); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, name := range entryNames {
		t.Run(name, func(t *testing.T) {
			partial := map[string][]byte{}
			for k, v := range complete {
				if k != name {
					partial[k] = v
				}
			}
			b, err := encodeBundle(partial)
			if err == nil || !strings.Contains(err.Error(), "missing bundle entry "+name) || b != nil {
				t.Fatalf("got %q %v", b, err)
			}
		})
	}
}

// methodFailingClose is a ZIP method no real bundle uses; its reader reads fine and fails on Close.
const methodFailingClose uint16 = 0xfa11

var errFailingClose = errors.New("close failed")

type failingCloser struct{ io.Reader }

func (failingCloser) Close() error { return errFailingClose }

var registerFailingClose sync.Once

func TestReadBundleEntryReportsAFailedClose(t *testing.T) {
	registerFailingClose.Do(func() {
		zip.RegisterDecompressor(methodFailingClose, func(r io.Reader) io.ReadCloser { return failingCloser{r} })
	})
	content := []byte("document")
	entry := func(method uint16) *zip.File {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		out, err := w.CreateRaw(&zip.FileHeader{Name: "NOTICE", Method: method, CRC32: crc32.ChecksumIEEE(content), CompressedSize64: uint64(len(content)), UncompressedSize64: uint64(len(content))})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = out.Write(content); err != nil {
			t.Fatal(err)
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatal(err)
		}
		return r.File[0]
	}
	if got, err := readBundleEntry(entry(zip.Store)); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("control: %q %v", got, err)
	}
	if got, err := readBundleEntry(entry(methodFailingClose)); !errors.Is(err, errFailingClose) || got != nil {
		t.Fatalf("an entry that read completely but did not close cleanly: %q %v", got, err)
	}
}

// The input fits the limit, but the canonical layout (16 KiB aligned slices) would not.
func TestCanonicalDarwinRefusesALayoutThatOutgrowsTheLimit(t *testing.T) {
	amd64, arm64 := thin(0x01000007, 3), thin(0x0100000c, 0)
	data := make([]byte, maxBinarySize)
	binary.BigEndian.PutUint32(data, 0xcafebabe)
	binary.BigEndian.PutUint32(data[4:], 2)
	slice := func(i int, cpu, sub, offset, size uint32) {
		h := data[8+i*20:]
		binary.BigEndian.PutUint32(h, cpu)
		binary.BigEndian.PutUint32(h[4:], sub)
		binary.BigEndian.PutUint32(h[8:], offset)
		binary.BigEndian.PutUint32(h[12:], size)
		binary.BigEndian.PutUint32(h[16:], 0)
	}
	second := fatHeaderSize + uint32(len(amd64))
	slice(0, 0x01000007, 3, fatHeaderSize, uint32(len(amd64)))
	slice(1, 0x0100000c, 0, second, uint32(maxBinarySize)-second)
	copy(data[fatHeaderSize:], amd64)
	copy(data[second:], arm64)
	if _, err := parseDarwin(data); err != nil {
		t.Fatalf("the input itself is a valid FAT executable: %v", err)
	}
	got, err := CanonicalDarwin(data)
	if err == nil || !strings.Contains(err.Error(), "canonical executable exceeds limit") || got != nil {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}
}

func TestValidateMachOBoundsMatchesSectionsToSegments(t *testing.T) {
	segment := func(name string, sections uint32) macho.Load {
		return &macho.Segment{SegmentHeader: macho.SegmentHeader{Name: name, Nsect: sections}}
	}
	// A zero-fill section has no file range, so only its place in the load commands is checked.
	section := func(parent string) *macho.Section {
		return &macho.Section{SectionHeader: macho.SectionHeader{Seg: parent, Flags: 1}}
	}
	file := func(loads []macho.Load, sections ...*macho.Section) *macho.File {
		return &macho.File{Loads: loads, Sections: sections}
	}
	if err := validateMachOBounds(file([]macho.Load{segment("__TEXT", 2)}, section("__TEXT"), section("__TEXT")), 4096); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, tc := range []struct {
		name string
		file *macho.File
		want string
	}{
		{"a segment announces more sections than the file lists", file([]macho.Load{segment("__TEXT", 3)}, section("__TEXT"), section("__TEXT")), "missing Mach-O section"},
		{"a section belongs to no segment", file([]macho.Load{segment("__TEXT", 1)}, section("__TEXT"), section("__TEXT")), "unmatched Mach-O sections"},
		{"sections without any segment", file(nil, section("__TEXT")), "unmatched Mach-O sections"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateMachOBounds(tc.file, 4096); err == nil || err.Error() != tc.want {
				t.Fatalf("got %v want %q", err, tc.want)
			}
		})
	}
}

// inspectJSONValue and inspectJSONObject are only handed tokens in grammar by leaksPrivatePath;
// each still refuses a token that is out of place rather than reading past it.
func TestInspectJSONRefusesTokensOutOfGrammar(t *testing.T) {
	open := func(doc string) *json.Decoder {
		d := json.NewDecoder(strings.NewReader(doc))
		if _, err := d.Token(); err != nil {
			t.Fatal(err)
		}
		return d
	}
	if found, err := inspectJSONValue(json.NewDecoder(strings.NewReader(`{"a":[1,"b"]}`)), "private"); found || err != nil {
		t.Fatalf("control: %v %v", found, err)
	}
	if _, err := inspectJSONValue(open(`{}`), "private"); err == nil || err.Error() != "unexpected JSON delimiter" {
		t.Fatalf("closing delimiter in value position: %v", err)
	}
	if _, err := inspectJSONObject(open(`[1]`), "private"); err == nil || err.Error() != "invalid JSON key" {
		t.Fatalf("number in key position: %v", err)
	}
	if found, err := inspectJSONObject(open(`{"private-key":1}`), "private"); !found || err != nil {
		t.Fatalf("private path in a key: %v %v", found, err)
	}
}

func TestScanAndWriteRefusesABoundNameThatLeaksAPrivatePath(t *testing.T) {
	bundle, _ := fixtureBuild(t, fixtureRoot(t), false)
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	entries, slices, err := sbomEntries(data)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	scan, env, err := stageSBOM(root, entries, slices, testSBOMFSOps())
	if err != nil {
		t.Fatal(err)
	}
	helper := syftHelper(t, "ok")
	control := filepath.Join(t.TempDir(), "control")
	if err = scanAndWrite(context.Background(), helper, scan, root, env, bundle, control, data); err != nil {
		t.Fatalf("control: %v", err)
	}
	if _, err = os.Stat(control); err != nil {
		t.Fatal("control wrote nothing")
	}
	// The bundle's own name is what the binding adds; if it were private, the document must not be written.
	out := filepath.Join(t.TempDir(), "out")
	err = scanAndWrite(context.Background(), helper, scan, filepath.Base(bundle), env, bundle, out, data)
	if err == nil || err.Error() != "SBOM contains private path" {
		t.Fatalf("got %v", err)
	}
	if _, err = os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("a document with a private path was written")
	}
}

func TestArchiveSBOMReportsToolAndDocumentFailures(t *testing.T) {
	archive, dist := archiveFixture(t, archiveTargets[0])
	for _, tc := range []struct {
		name, tool, want string
	}{
		{"tool missing", filepath.Join(t.TempDir(), "missing-syft"), "syft failed"},
		{"no Go module in the document", syftHelper(t, "nogo-archive"), "no Go module components"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(dist, "out-"+strings.ReplaceAll(tc.name, " ", "-"))
			err := WriteArchiveSBOM(context.Background(), archive, dist, out, tc.tool)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v want %q", err, tc.want)
			}
			if _, err = os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("a failed scan produced output")
			}
		})
	}
}
