package releasebundle

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/safefile"
	"github.com/google/jsonschema-go/jsonschema"
)

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, n := range []string{"LICENSE", "NOTICE", "THIRD_PARTY_LICENSES", "README.md", "CHANGELOG.md", "SECURITY.md"} {
		if err := os.WriteFile(filepath.Join(root, n), []byte(n), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "packaging/mcpb"), 0700); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../packaging/mcpb/manifest.json.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "packaging/mcpb/manifest.json.tmpl"), b, 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

func fixtureBuild(t *testing.T, root string, reversed bool) (string, string) {
	t.Helper()
	a, b := thin(0x01000007, 3), thin(0x0100000c, 0)
	dist := t.TempDir()
	for _, v := range []struct {
		dir  string
		data []byte
	}{{"tailkeeper_darwin_amd64_v1", a}, {"tailkeeper_darwin_arm64_v8.0", b}} {
		d := filepath.Join(dist, v.dir)
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "tailkeeper"), v.data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	u := filepath.Join(t.TempDir(), "universal")
	if err := os.WriteFile(u, fat(a, b, reversed), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "bundle.mcpb")
	if err := Build(BuildOptions{Version: "0.6.0-SNAPSHOT-abc123", UniversalPath: u, RootDir: root, OutputPath: output}); err != nil {
		t.Fatal(err)
	}
	return output, dist
}

func TestBundleDeterministicAcrossSliceOrderTimeAndRoot(t *testing.T) {
	root1, root2 := fixtureRoot(t), fixtureRoot(t)
	stamp := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	for _, name := range []string{"LICENSE", "NOTICE", "THIRD_PARTY_LICENSES", "README.md", "CHANGELOG.md", "SECURITY.md"} {
		if err := os.Chtimes(filepath.Join(root2, name), stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	x, dx := fixtureBuild(t, root1, false)
	y, _ := fixtureBuild(t, root2, true)
	a, err := os.ReadFile(x)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(y)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("bundles differ")
	}
	if err = Verify(x, dx, "0.6.0-SNAPSHOT-abc123"); err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(dx, "tailkeeper_darwin_arm64_v8.0", "tailkeeper")
	if err = os.WriteFile(wrong, thin(0x01000007, 3), 0600); err != nil {
		t.Fatal(err)
	}
	if err = Verify(x, dx, "0.6.0-SNAPSHOT-abc123"); err == nil {
		t.Fatal("accepted wrong thin input")
	}
}

func TestBundleManifestMatchesPinnedSchema(t *testing.T) {
	path, _ := fixtureBuild(t, fixtureRoot(t), false)
	z, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = z.Close() }()
	var manifest []byte
	for _, f := range z.File {
		if f.Name == "manifest.json" {
			r, e := f.Open()
			if e != nil {
				t.Fatal(e)
			}
			manifest, e = io.ReadAll(r)
			if e != nil {
				t.Fatal(e)
			}
			if e = r.Close(); e != nil {
				t.Fatal(e)
			}
		}
	}
	schemaBytes, err := os.ReadFile("testdata/mcpb-manifest-v0.3.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema jsonschema.Schema
	if err = json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatal(err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]interface{}
	if err = json.Unmarshal(manifest, &value); err != nil {
		t.Fatal(err)
	}
	if err = resolved.Validate(value); err != nil {
		t.Fatal(err)
	}
	compat, ok := value["compatibility"].(map[string]interface{})
	if !ok {
		t.Fatal("missing compatibility")
	}
	compat["architectures"] = []string{"arm64"}
	if err = resolved.Validate(value); err == nil {
		t.Fatal("schema accepted unsupported architectures")
	}
}

func TestBundleRejectsInvalidVersionAndExistingOutput(t *testing.T) {
	root := fixtureRoot(t)
	u := filepath.Join(t.TempDir(), "universal")
	if err := os.WriteFile(u, fat(thin(0x01000007, 3), thin(0x0100000c, 0), false), 0600); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"", "v1.2.3", "1.2", "01.2.3", "1.2.3-01", "1.2.3/evil", "1.2.3+"} {
		if err := Build(BuildOptions{Version: v, UniversalPath: u, RootDir: root, OutputPath: filepath.Join(t.TempDir(), "x")}); err == nil {
			t.Errorf("accepted %q", v)
		}
	}
	out := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(out, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Build(BuildOptions{Version: "1.2.3", UniversalPath: u, RootDir: root, OutputPath: out}); err == nil {
		t.Fatal("overwrote file")
	}
	b, err := os.ReadFile(out)
	if err != nil || string(b) != "preserve" {
		t.Fatal("existing output changed")
	}
}

func TestVerifyRejectsChangedArchiveAndThinInventory(t *testing.T) {
	path, dist := fixtureBuild(t, fixtureRoot(t), false)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]byte) []byte{
		"trailing byte":   func(b []byte) []byte { return append(b, 0) },
		"local header":    func(b []byte) []byte { b[10] ^= 1; return b },
		"archive comment": func(b []byte) []byte { b[len(b)-2] = 1; return append(b, 'x') },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "mutated")
			if e := os.WriteFile(p, change(bytes.Clone(original)), 0600); e != nil {
				t.Fatal(e)
			}
			if e := Verify(p, dist, "0.6.0-SNAPSHOT-abc123"); e == nil {
				t.Fatal("accepted changed archive")
			}
		})
	}
	if err := Verify(path, dist, "0.6.0-other"); err == nil {
		t.Fatal("accepted wrong version")
	}
	dup := filepath.Join(dist, "tailkeeper_darwin_arm64_other")
	if err := os.Mkdir(dup, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dup, "tailkeeper"), thin(0x0100000c, 0), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path, dist, "0.6.0-SNAPSHOT-abc123"); err == nil {
		t.Fatal("accepted duplicate thin binaries")
	}
}

func TestBuildRejectsOversizeInputs(t *testing.T) {
	root := fixtureRoot(t)
	u := filepath.Join(t.TempDir(), "universal")
	if err := os.WriteFile(u, fat(thin(0x01000007, 3), thin(0x0100000c, 0), false), 0600); err != nil {
		t.Fatal(err)
	}
	opts := BuildOptions{Version: "1.2.3", UniversalPath: u, RootDir: root, OutputPath: filepath.Join(t.TempDir(), "out")}
	if err := Build(opts); err != nil {
		t.Fatal(err)
	}
	opts.OutputPath = filepath.Join(t.TempDir(), "out")
	doc := filepath.Join(root, "NOTICE")
	f, err := os.Create(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(maxDocumentSize + 1); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Build(opts); err == nil {
		t.Fatal("accepted oversized document")
	}
	opts.UniversalPath = doc
	if err := os.Truncate(doc, maxBinarySize+1); err != nil {
		t.Fatal(err)
	}
	if err := Build(opts); err == nil {
		t.Fatal("accepted oversized binary")
	}
}

func TestBundleCumulativeLimit(t *testing.T) {
	small := map[string][]byte{}
	for _, name := range entryNames {
		small[name] = []byte("x")
	}
	if _, err := encodeBundle(small); err != nil {
		t.Fatal(err)
	}
	// Reuse one allocation to exercise the total-size guard without creating an oversized archive.
	large := make([]byte, maxBinarySize/len(entryNames)+1)
	for _, name := range entryNames {
		small[name] = large
	}
	if _, err := encodeBundle(small); err == nil {
		t.Fatal("accepted oversized aggregate")
	}
}

func TestValidVersion(t *testing.T) {
	for _, v := range []string{"1.2.3", "0.6.0-SNAPSHOT-abc123", "1.2.3-rc.1+build.01"} {
		if !validVersion(v) {
			t.Errorf("rejected valid version %q", v)
		}
	}
	for _, v := range []string{"1.2.3-01", "1.02.3", "1.2.3-", "1.2.3+", "v1.2.3"} {
		if validVersion(v) {
			t.Errorf("accepted invalid version %q", v)
		}
	}
}

func TestBuildRefusesUnavailableOrAlteredInputs(t *testing.T) {
	root := fixtureRoot(t)
	u := filepath.Join(t.TempDir(), "universal")
	if err := os.WriteFile(u, fat(thin(0x01000007, 3), thin(0x0100000c, 0), false), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "bundle")
	opts := BuildOptions{Version: "1.0.0", UniversalPath: u, RootDir: root, OutputPath: output}
	cases := []struct {
		name    string
		prepare func(*testing.T, *BuildOptions)
	}{
		{"missing manifest", func(t *testing.T, o *BuildOptions) { t.Helper(); o.RootDir = t.TempDir() }},
		{"changed manifest", func(t *testing.T, o *BuildOptions) {
			t.Helper()
			o.RootDir = fixtureRoot(t)
			p := filepath.Join(o.RootDir, "packaging/mcpb/manifest.json.tmpl")
			if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing executable", func(t *testing.T, o *BuildOptions) {
			t.Helper()
			o.UniversalPath = filepath.Join(t.TempDir(), "absent")
		}},
		{"invalid executable", func(t *testing.T, o *BuildOptions) {
			t.Helper()
			o.UniversalPath = filepath.Join(t.TempDir(), "invalid")
			if err := os.WriteFile(o.UniversalPath, []byte("not executable"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing output directory", func(t *testing.T, o *BuildOptions) {
			t.Helper()
			o.OutputPath = filepath.Join(t.TempDir(), "missing", "bundle")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := opts
			tc.prepare(t, &o)
			if err := Build(o); err == nil {
				t.Fatal("accepted unavailable or altered input")
			}
			if _, err := os.Lstat(o.OutputPath); !os.IsNotExist(err) {
				t.Fatalf("output unexpectedly exists: %v", err)
			}
		})
	}
	if err := Build(opts); err != nil {
		t.Fatalf("positive control: %v", err)
	}
}

func TestVerifyRefusesMissingAndMalformedInputs(t *testing.T) {
	bundle, dist := fixtureBuild(t, fixtureRoot(t), false)
	version := "0.6.0-SNAPSHOT-abc123"
	if err := Verify(bundle, dist, version); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, path, dist, version string }{
		{"bad version", bundle, dist, "bad"}, {"missing bundle", filepath.Join(t.TempDir(), "missing"), dist, version},
		{"missing dist", bundle, filepath.Join(t.TempDir(), "["), version},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Verify(tc.path, tc.dist, tc.version); err == nil {
				t.Fatal("accepted malformed input")
			}
		})
	}
	raw, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := decodeBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		executable []byte
	}{
		{"invalid Mach-O", []byte("bad")}, {"reversed architectures", fat(thin(0x01000007, 3), thin(0x0100000c, 0), true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			altered := make(map[string][]byte, len(entries))
			for k, v := range entries {
				altered[k] = v
			}
			altered["server/tailkeeper"] = tc.executable
			b, e := encodeBundle(altered)
			if e != nil {
				t.Fatal(e)
			}
			p := filepath.Join(t.TempDir(), "bundle")
			if e = os.WriteFile(p, b, 0600); e != nil {
				t.Fatal(e)
			}
			if e = Verify(p, dist, version); e == nil {
				t.Fatal("accepted altered executable")
			}
		})
	}

}

func archiveForTest(t *testing.T, names []string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, name := range names {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestVerifyRejectsMalformedZIPEntries(t *testing.T) {
	bundle, dist := fixtureBuild(t, fixtureRoot(t), false)
	version := "0.6.0-SNAPSHOT-abc123"
	good, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err = Verify(bundle, dist, version); err != nil {
		t.Fatal(err)
	}
	wrongNames := append([]string(nil), entryNames...)
	wrongNames[0] = "evil"
	central := bytes.Index(good, []byte{'P', 'K', 1, 2})
	if central < 0 {
		t.Fatal("missing central directory")
	}
	sizeBomb := bytes.Clone(good)
	binary.LittleEndian.PutUint32(sizeBomb[central+24:], maxBinarySize)
	oversized := bytes.Clone(good)
	binary.LittleEndian.PutUint32(oversized[central+24:], maxDocumentSize+1)
	badMethod := bytes.Clone(good)
	binary.LittleEndian.PutUint16(badMethod[central+10:], 99)
	damaged := bytes.Clone(good)
	nameLen := int(binary.LittleEndian.Uint16(damaged[26:]))
	extraLen := int(binary.LittleEndian.Uint16(damaged[28:]))
	damaged[30+nameLen+extraLen] ^= 1
	cases := map[string][]byte{"not ZIP": []byte("not a zip"), "missing entries": archiveForTest(t, entryNames[:7]), "unexpected entry": archiveForTest(t, wrongNames), "aggregate size": sizeBomb, "oversized entry": oversized, "unsupported method": badMethod, "checksum corruption": damaged}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "bundle")
			if e := os.WriteFile(p, b, 0600); e != nil {
				t.Fatal(e)
			}
			if e := Verify(p, dist, version); e == nil {
				t.Fatal("accepted invalid ZIP")
			}
		})
	}
}

func TestBuildRejectsManifestAboveLimit(t *testing.T) {
	root := fixtureRoot(t)
	u := filepath.Join(t.TempDir(), "universal")
	if err := os.WriteFile(u, fat(thin(0x01000007, 3), thin(0x0100000c, 0), false), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "bundle")
	version := "1.2.3+" + strings.Repeat("a", maxDocumentSize)
	if err := Build(BuildOptions{Version: version, RootDir: root, UniversalPath: u, OutputPath: output}); err == nil {
		t.Fatal("accepted manifest larger than verifier limit")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("output exists: %v", err)
	}
}

func TestVerifyAcceptsLiteralDistDirectoryWithGlobCharacters(t *testing.T) {
	bundle, dist := fixtureBuild(t, fixtureRoot(t), false)
	literal := filepath.Join(t.TempDir(), "dist [one]")
	if err := os.Rename(dist, literal); err != nil {
		t.Fatal(err)
	}
	if err := Verify(bundle, literal, "0.6.0-SNAPSHOT-abc123"); err != nil {
		t.Fatalf("literal directory: %v", err)
	}
	dup := filepath.Join(literal, "tailkeeper_darwin_amd64_second")
	if err := os.Mkdir(dup, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dup, "tailkeeper"), thin(0x01000007, 3), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(bundle, literal, "0.6.0-SNAPSHOT-abc123"); err == nil {
		t.Fatal("accepted duplicate in literal directory")
	}
}

type failingPublicationFile struct {
	*os.File
	stage   string
	failure error
}

func (f *failingPublicationFile) Chmod(mode os.FileMode) error {
	if f.stage == "chmod" {
		return f.failure
	}
	return f.File.Chmod(mode)
}
func (f *failingPublicationFile) Write(b []byte) (int, error) {
	n, err := f.File.Write(b)
	if err != nil {
		return n, err
	}
	if f.stage == "write" {
		return n, f.failure
	}
	if f.stage == "short write" {
		return n - 1, nil
	}
	return n, nil
}
func (f *failingPublicationFile) Sync() error {
	if f.stage == "sync" {
		return f.failure
	}
	return f.File.Sync()
}
func (f *failingPublicationFile) Close() error {
	err := f.File.Close()
	if err != nil {
		return err
	}
	if f.stage == "close" {
		return f.failure
	}
	return nil
}

func TestPublicationFailuresLeaveNoBundleOrTemporaryFile(t *testing.T) {
	for _, stage := range []string{"chmod", "write", "short write", "sync", "close"} {
		t.Run(stage, func(t *testing.T) {
			for _, existing := range []bool{false, true} {
				t.Run(fmt.Sprintf("existing=%t", existing), func(t *testing.T) {
					dir := t.TempDir()
					dest := filepath.Join(dir, "bundle")
					sentinel := errors.New("injected " + stage)
					if existing {
						if err := os.WriteFile(dest, []byte("existing"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					ops := publicationOps{create: func(dir, pattern string) (publicationFile, error) {
						f, err := os.CreateTemp(dir, pattern)
						if err != nil {
							return nil, err
						}
						return &failingPublicationFile{File: f, stage: stage, failure: sentinel}, nil
					}, remove: os.Remove, link: os.Link}
					if stage == "short write" {
						sentinel = io.ErrShortWrite
					}
					if err := writeNewWith(dest, []byte("content"), ops); !errors.Is(err, sentinel) {
						t.Fatalf("expected injected failure, got %v", err)
					}
					entries, err := os.ReadDir(dir)
					if err != nil {
						t.Fatal(err)
					}
					if existing {
						b, err := os.ReadFile(dest)
						if err != nil || string(b) != "existing" || len(entries) != 1 {
							t.Fatalf("existing target or temporary files changed: %v", err)
						}
					} else if len(entries) != 0 {
						t.Fatal("failure published or left temporary file")
					}
				})
			}
		})
	}
}

func TestVerifyIgnoresUnrelatedThinBuildCandidates(t *testing.T) {
	bundle, dist := fixtureBuild(t, fixtureRoot(t), false)
	version := "0.6.0-SNAPSHOT-abc123"
	if err := os.Mkdir(filepath.Join(dist, "tailkeeper_darwin_amd64_empty"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "tailkeeper_darwin_amd64_file"), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(bundle, dist, version); err != nil {
		t.Fatalf("ignored incomplete candidates: %v", err)
	}
}

func TestBundleUsesCanonicalUTCZipTimestamp(t *testing.T) {
	bundle, dist := fixtureBuild(t, fixtureRoot(t), false)
	version := "0.6.0-SNAPSHOT-abc123"
	if err := Verify(bundle, dist, version); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	epoch := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	extra := []byte{0x55, 0x54, 5, 0, 1, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(extra[5:], uint32(epoch.Unix()))
	for _, entry := range z.File {
		if !entry.Modified.Equal(epoch) || !bytes.Equal(entry.Extra, extra) {
			t.Fatalf("unexpected ZIP timestamp metadata for %s", entry.Name)
		}
	}
	central := bytes.Index(data, []byte{'P', 'K', 1, 2})
	if central < 0 {
		t.Fatal("central header missing")
	}
	for name, change := range map[string]func([]byte){
		"timestamp": func(b []byte) { b[central+12] ^= 1 },
		"extra field": func(b []byte) {
			nameLen := int(binary.LittleEndian.Uint16(b[central+28:]))
			b[central+46+nameLen+5] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Clone(data)
			change(bad)
			p := filepath.Join(t.TempDir(), "bundle")
			if e := os.WriteFile(p, bad, 0600); e != nil {
				t.Fatal(e)
			}
			if e := Verify(p, dist, version); e == nil {
				t.Fatal("accepted noncanonical timestamp metadata")
			}
		})
	}
}

type failingInputFile struct {
	*os.File
	stage string
	grew  bool
}

func (f *failingInputFile) identityFile() *os.File { return f.File }

func (f *failingInputFile) Stat() (os.FileInfo, error) {
	if f.stage == "stat" {
		if err := f.File.Close(); err != nil {
			return nil, err
		}
	}
	return f.File.Stat()
}
func (f *failingInputFile) Read(b []byte) (int, error) {
	if f.stage == "read" {
		if err := f.File.Close(); err != nil {
			return 0, err
		}
	}
	if f.stage == "growth" && !f.grew {
		f.grew = true
		w, err := os.OpenFile(f.Name(), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return 0, err
		}
		_, err = w.Write([]byte("!"))
		closeErr := w.Close()
		if err != nil {
			return 0, err
		}
		if closeErr != nil {
			return 0, closeErr
		}
	}
	return f.File.Read(b)
}

func inputFailureOps(stage, other string, opened **os.File) inputOps {
	return inputOps{open: func(path string) (inputFile, error) {
		if stage == "open" || stage == "identity" {
			if err := os.Remove(path); err != nil {
				return nil, err
			}
		}
		if stage == "identity" {
			if err := os.Rename(other, path); err != nil {
				return nil, err
			}
		}
		f, err := safefile.OpenNoFollow(path)
		if err != nil {
			return nil, err
		}
		*opened = f
		return &failingInputFile{File: f, stage: stage}, nil
	}}
}

func checkInputFailure(t *testing.T, stage string, err error) {
	t.Helper()
	switch stage {
	case "open":
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("wrong open error: %v", err)
		}
	case "read":
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("wrong read error: %v", err)
		}
	case "growth":
		if !strings.Contains(err.Error(), "exceeds limit") {
			t.Fatalf("wrong growth error: %v", err)
		}
	case "identity", "stat":
		if !strings.Contains(err.Error(), "changed while opening") {
			t.Fatalf("wrong stat error: %v", err)
		}
	}
}

func TestReadRegularRefusesInputFailures(t *testing.T) {
	for _, stage := range []string{"open", "stat", "identity", "read", "growth"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "input")
			other := filepath.Join(dir, "other")
			output := filepath.Join(dir, "output")
			if err := os.WriteFile(path, []byte("input"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(other, []byte("other"), 0600); err != nil {
				t.Fatal(err)
			}
			normal, err := readRegular(path, 5)
			if err != nil || string(normal) != "input" {
				t.Fatalf("positive control: %q %v", normal, err)
			}
			var descriptor *os.File
			got, err := readRegularWith(path, 5, inputFailureOps(stage, other, &descriptor))
			if err == nil || got != nil {
				t.Fatal("accepted input failure")
			}
			checkInputFailure(t, stage, err)
			if descriptor != nil {
				if _, err := descriptor.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
					t.Fatalf("input descriptor not closed: %v", err)
				}
			}
			if _, err = os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("output appeared: %v", err)
			}
		})
	}
}

func TestFindThinRejectsCandidateStatFailure(t *testing.T) {
	dir := t.TempDir()
	build := filepath.Join(dir, "tailkeeper_darwin_amd64_v1")
	path := filepath.Join(build, "tailkeeper")
	if err := os.Mkdir(build, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("thin"), 0600); err != nil {
		t.Fatal(err)
	}
	paths, err := findThin(dir, "amd64")
	if err != nil || len(paths) != 1 {
		t.Fatalf("positive control: %v %v", paths, err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	_, cause := f.Stat()
	var pe *os.PathError
	if !errors.As(cause, &pe) {
		t.Fatalf("closed Stat did not produce a PathError: %v", cause)
	}
	paths, err = findThinWith(dir, "amd64", func(string) (os.FileInfo, error) { return f.Stat() })
	var got *os.PathError
	if !errors.Is(err, pe.Err) || !errors.As(err, &got) || got.Op != pe.Op || got.Path != pe.Path || len(paths) != 0 {
		t.Fatalf("accepted candidate stat failure: %v %v", paths, err)
	}
}

func TestOpenInputUsesNoFollowAndReportsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("input"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openInput(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	f, err = openInput(path)
	if f != nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing-file error: %v", err)
	}
}
