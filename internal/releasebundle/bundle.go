package releasebundle

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/safefile"
)

const maxDocumentSize = 16 << 20
const manifestTemplate = `{
  "manifest_version": "0.3",
  "name": "tailkeeper",
  "version": "{{VERSION}}",
  "description": "Read-only Tailscale tools for MCP clients",
  "author": {"name": "tailkeeper contributors"},
  "license": "Apache-2.0",
  "server": {
    "type": "binary",
    "entry_point": "server/tailkeeper",
    "mcp_config": {"command": "${__dirname}/server/tailkeeper", "args": ["mcp"]}
  },
  "compatibility": {"platforms": ["darwin"]}
}
`

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)
var entryNames = []string{"CHANGELOG.md", "LICENSE", "NOTICE", "README.md", "SECURITY.md", "THIRD_PARTY_LICENSES", "manifest.json", "server/tailkeeper"}

type BuildOptions struct {
	Version       string
	UniversalPath string
	RootDir       string
	OutputPath    string
}

func validVersion(v string) bool {
	if len(v) > maxDocumentSize-len(manifestTemplate)+len("{{VERSION}}") {
		return false
	}
	m := versionPattern.FindStringSubmatch(v)
	if m == nil {
		return false
	}
	for _, p := range strings.Split(m[4], ".") {
		if len(p) > 1 && p[0] == '0' && strings.Trim(p, "0123456789") == "" {
			return false
		}
	}
	return true
}
func manifest(v string) []byte { return []byte(strings.Replace(manifestTemplate, "{{VERSION}}", v, 1)) }

// Build creates a deterministic MCPB without replacing an existing file.
func Build(opts BuildOptions) error {
	if !validVersion(opts.Version) || opts.UniversalPath == "" || opts.RootDir == "" || opts.OutputPath == "" {
		return fmt.Errorf("invalid build options")
	}
	template, err := readRegular(filepath.Join(opts.RootDir, "packaging/mcpb/manifest.json.tmpl"), maxDocumentSize)
	if err != nil {
		return err
	}
	if string(template) != manifestTemplate {
		return fmt.Errorf("unexpected manifest template")
	}
	binary, err := readRegular(opts.UniversalPath, maxBinarySize)
	if err != nil {
		return err
	}
	binary, err = CanonicalDarwin(binary)
	if err != nil {
		return err
	}
	entries := make(map[string][]byte, len(entryNames))
	entries["manifest.json"] = manifest(opts.Version)
	entries["server/tailkeeper"] = binary
	remaining := int64(maxBinarySize - len(binary) - len(entries["manifest.json"]) - 4096)
	for _, name := range entryNames[:6] {
		if remaining < 0 {
			return fmt.Errorf("bundle exceeds limit")
		}
		limit := int64(maxDocumentSize)
		if remaining < limit {
			limit = remaining
		}
		entries[name], err = readRegular(filepath.Join(opts.RootDir, name), limit)
		if err != nil {
			return err
		}
		remaining -= int64(len(entries[name]))
	}
	bundle, err := encodeBundle(entries)
	if err != nil {
		return err
	}
	return writeNew(opts.OutputPath, bundle)
}

func openInput(path string) (inputFile, error) {
	f, err := safefile.OpenNoFollow(path)
	if err != nil {
		return nil, err
	}
	return &realInputFile{File: f}, nil
}

func readRegular(path string, limit int64) ([]byte, error) {
	return readRegularWith(path, limit, inputOps{open: openInput})
}

func readRegularWith(path string, limit int64, ops inputOps) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat input: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("input is not a bounded regular file")
	}
	identity, err := safefile.Identify(path, info)
	if err != nil {
		return nil, fmt.Errorf("inspect input identity: %w", err)
	}
	f, err := ops.open(path)
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	defer func() { _ = f.Close() }()
	now, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("input changed while opening")
	}
	same, err := identity.Is(f.identityFile(), now)
	if err != nil || !same || !now.Mode().IsRegular() {
		return nil, fmt.Errorf("input changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("input exceeds limit")
	}
	return b, nil
}

func encodeBundle(entries map[string][]byte) ([]byte, error) {
	var total uint64 = 4096
	for _, name := range entryNames {
		total += uint64(len(entries[name]))
		if total > maxBinarySize {
			return nil, fmt.Errorf("bundle exceeds limit")
		}
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range entryNames {
		content, ok := entries[name]
		if !ok {
			return nil, fmt.Errorf("missing bundle entry %s", name)
		}
		h := &zip.FileHeader{Name: name, Method: zip.Store, Modified: time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)}
		mode := os.FileMode(0644)
		if name == "server/tailkeeper" {
			mode = 0755
		}
		h.SetMode(mode)
		out, err := w.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err = out.Write(content); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > maxBinarySize {
		return nil, fmt.Errorf("bundle exceeds limit")
	}
	return buf.Bytes(), nil
}

func writeNew(path string, data []byte) error {
	ops := publicationOps{
		create: func(dir, pattern string) (publicationFile, error) { return os.CreateTemp(dir, pattern) },
		remove: os.Remove,
		link:   os.Link,
	}
	return writeNewWith(path, data, ops)
}

func writeNewWith(path string, data []byte, ops publicationOps) error {
	f, err := ops.create(filepath.Dir(path), ".tailkeeper-mcpb-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = ops.remove(tmp) }()
	if err = f.Chmod(0644); err != nil {
		_ = f.Close()
		return err
	}
	n, err := f.Write(data)
	if err != nil {
		_ = f.Close()
		return err
	}
	if n != len(data) {
		_ = f.Close()
		return io.ErrShortWrite
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = ops.link(tmp, path); err != nil {
		return fmt.Errorf("publish bundle: %w", err)
	}
	return nil
}

// Verify checks the canonical archive and both independently built thin binaries.
func Verify(bundlePath, distDir, version string) error {
	if !validVersion(version) || bundlePath == "" || distDir == "" {
		return fmt.Errorf("invalid verification options")
	}
	data, err := readRegular(bundlePath, maxBinarySize)
	if err != nil {
		return err
	}
	entries, err := decodeBundle(data)
	if err != nil {
		return err
	}
	if !bytes.Equal(entries["manifest.json"], manifest(version)) {
		return fmt.Errorf("manifest mismatch")
	}
	executable := entries["server/tailkeeper"]
	canonical, err := CanonicalDarwin(executable)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, executable) {
		return fmt.Errorf("noncanonical executable")
	}
	slices, err := parseDarwin(executable)
	if err != nil {
		return err
	}
	for _, s := range slices {
		if err = verifyThin(distDir, s); err != nil {
			return err
		}
	}
	return nil
}

func decodeBundle(data []byte) (map[string][]byte, error) {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	if len(z.File) != len(entryNames) {
		return nil, fmt.Errorf("wrong bundle entry count")
	}
	if err := checkBundleSizes(z.File); err != nil {
		return nil, err
	}
	entries := make(map[string][]byte, len(entryNames))
	for i, f := range z.File {
		if f.Name != entryNames[i] {
			return nil, fmt.Errorf("unexpected bundle entry")
		}
		content, err := readBundleEntry(f)
		if err != nil {
			return nil, err
		}
		entries[f.Name] = content
	}
	canonical, err := encodeBundle(entries)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(data, canonical) {
		return nil, fmt.Errorf("noncanonical ZIP")
	}
	return entries, nil
}

func checkBundleSizes(files []*zip.File) error {
	var total uint64 = 4096
	for _, f := range files {
		if f.UncompressedSize64 > maxBinarySize-total {
			return fmt.Errorf("bundle exceeds limit")
		}
		total += f.UncompressedSize64
	}
	return nil
}

func readBundleEntry(f *zip.File) ([]byte, error) {
	limit := uint64(maxDocumentSize)
	if f.Name == "server/tailkeeper" {
		limit = maxBinarySize
	}
	if f.UncompressedSize64 > limit || f.CompressedSize64 > limit {
		return nil, fmt.Errorf("oversized bundle entry")
	}
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	b, readErr := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	closeErr := r.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if uint64(len(b)) > limit {
		return nil, fmt.Errorf("oversized entry")
	}
	return b, nil
}

func verifyThin(dist string, s fatSlice) error {
	arch := "amd64"
	if s.cpu == 0x0100000c {
		arch = "arm64"
	}
	paths, err := findThin(dist, arch)
	if err != nil {
		return err
	}
	if len(paths) != 1 {
		return fmt.Errorf("expected exactly one %s thin binary; found %d", arch, len(paths))
	}
	b, err := readRegular(paths[0], maxBinarySize)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, s.data) {
		return fmt.Errorf("%s thin binary differs", arch)
	}
	return nil
}

func findThin(dist, arch string) ([]string, error) {
	return findThinWith(dist, arch, os.Lstat)
}

func findThinWith(dist, arch string, lstat func(string) (os.FileInfo, error)) ([]string, error) {
	return findTargetThin(dist, "darwin", arch, "tailkeeper", lstat)
}

func findTargetThin(dist, goos, arch, binary string, lstat func(string) (os.FileInfo, error)) ([]string, error) {
	entries, err := os.ReadDir(dist)
	if err != nil {
		return nil, err
	}
	prefix := "tailkeeper_" + goos + "_" + arch + "_"
	var paths []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("thin build directory is a symlink")
		}
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(dist, entry.Name(), binary)
		_, err := lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}

type publicationFile interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}
type publicationOps struct {
	create func(string, string) (publicationFile, error)
	remove func(string) error
	link   func(string, string) error
}

type inputFile interface {
	io.Reader
	Stat() (os.FileInfo, error)
	Close() error
	identityFile() *os.File
}

type realInputFile struct{ *os.File }

func (f *realInputFile) identityFile() *os.File { return f.File }

type inputOps struct {
	open func(string) (inputFile, error)
}
