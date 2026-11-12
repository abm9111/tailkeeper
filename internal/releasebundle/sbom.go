package releasebundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const sbomLimit = 64 << 20

type boundedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buf.Len() {
		return 0, fmt.Errorf("subprocess output exceeds limit")
	}
	return b.buf.Write(p)
}

type sbomFSOps struct {
	mkdirTemp    func(string, string) (string, error)
	evalSymlinks func(string) (string, error)
	mkdir        func(string, os.FileMode) error
	mkdirAll     func(string, os.FileMode) error
	writeFile    func(string, []byte, os.FileMode) error
}

// WriteSBOM scans only the validated bundle and its two thin slices, with isolated Syft state.
func WriteSBOM(ctx context.Context, bundlePath, outputPath, syftPath string) error {
	ops := sbomFSOps{mkdirTemp: os.MkdirTemp, evalSymlinks: filepath.EvalSymlinks, mkdir: os.Mkdir, mkdirAll: os.MkdirAll, writeFile: os.WriteFile}
	return writeSBOMWith(ctx, bundlePath, outputPath, syftPath, ops)
}

func writeSBOMWith(ctx context.Context, bundlePath, outputPath, syftPath string, ops sbomFSOps) error {
	if ctx == nil || bundlePath == "" || outputPath == "" || !filepath.IsAbs(syftPath) {
		return fmt.Errorf("invalid SBOM options")
	}
	data, err := readRegular(bundlePath, maxBinarySize)
	if err != nil {
		return err
	}
	entries, slices, err := sbomEntries(data)
	if err != nil {
		return err
	}
	root, err := ops.mkdirTemp("", "tailkeeper-sbom-")
	if err != nil {
		return err
	}
	temporary := root
	defer func() { _ = os.RemoveAll(temporary) }()
	root, err = ops.evalSymlinks(root)
	if err != nil {
		return err
	}
	scan, env, err := stageSBOM(root, entries, slices, ops)
	if err != nil {
		return err
	}
	return scanAndWrite(ctx, syftPath, scan, root, env, bundlePath, outputPath, data)

}

func scanAndWrite(ctx context.Context, syftPath, scan, root string, env []string, bundlePath, outputPath string, data []byte) error {
	version, err := runSyft(ctx, syftPath, scan, env, "version")
	if err != nil {
		return err
	}
	if !strings.Contains(string(version), "Version:       1.54.0\n") {
		return fmt.Errorf("unexpected Syft version")
	}
	raw, err := runSyft(ctx, syftPath, scan, env, "scan", "dir:.", "-o", "cyclonedx-json", "--enrich", "none", "-c", "../control/syft.yaml")
	if err != nil {
		return err
	}
	clean, err := scrubSBOM(raw, scan, root)
	if err != nil {
		return err
	}
	final, err := bindSBOM(clean, filepath.Base(bundlePath), data)
	if err != nil {
		return err
	}
	if leaksPrivatePath(final, root) {
		return fmt.Errorf("SBOM contains private path")
	}
	return writeNew(outputPath, final)
}

func sbomEntries(data []byte) (map[string][]byte, []fatSlice, error) {
	entries, err := decodeBundle(data)
	if err != nil {
		return nil, nil, err
	}
	var manifestData struct {
		Version string `json:"version"`
	}
	if err = json.Unmarshal(entries["manifest.json"], &manifestData); err != nil || !validVersion(manifestData.Version) || !bytes.Equal(entries["manifest.json"], manifest(manifestData.Version)) {
		return nil, nil, fmt.Errorf("invalid manifest")
	}
	executable := entries["server/tailkeeper"]
	canonical, err := CanonicalDarwin(executable)
	if err != nil || !bytes.Equal(canonical, executable) {
		return nil, nil, fmt.Errorf("invalid universal executable")
	}
	slices, err := parseDarwin(executable)
	if err != nil {
		return nil, nil, err
	}
	return entries, slices, nil
}

func stageSBOM(root string, entries map[string][]byte, slices []fatSlice, ops sbomFSOps) (string, []string, error) {
	scan, env, err := stageSyftControl(root, ops)
	if err != nil {
		return "", nil, err
	}
	for _, name := range entryNames {
		dst := filepath.Join(scan, filepath.FromSlash(name))
		if err = ops.mkdirAll(filepath.Dir(dst), 0700); err != nil {
			return "", nil, err
		}
		if err = ops.writeFile(dst, entries[name], 0600); err != nil {
			return "", nil, err
		}
	}
	if err = ops.mkdir(filepath.Join(scan, "slices"), 0700); err != nil {
		return "", nil, err
	}
	for _, s := range slices {
		arch := "amd64"
		if s.cpu == 0x0100000c {
			arch = "arm64"
		}
		if err = ops.writeFile(filepath.Join(scan, "slices", "tailkeeper-"+arch), s.data, 0600); err != nil {
			return "", nil, err
		}
	}
	return scan, env, nil
}

func stageSyftControl(root string, ops sbomFSOps) (string, []string, error) {
	var err error
	scan := filepath.Join(root, "scan")
	for _, d := range []string{scan, filepath.Join(root, "control"), filepath.Join(root, "home"), filepath.Join(root, "config"), filepath.Join(root, "cache"), filepath.Join(root, "tmp")} {
		if err = ops.mkdir(d, 0700); err != nil {
			return "", nil, err
		}
	}
	if err = ops.writeFile(filepath.Join(root, "control", "syft.yaml"), []byte("{}\n"), 0600); err != nil {
		return "", nil, err
	}

	env := []string{"HOME=" + filepath.Join(root, "home"), "XDG_CONFIG_HOME=" + filepath.Join(root, "config"), "XDG_CACHE_HOME=" + filepath.Join(root, "cache"), "SYFT_CHECK_FOR_APP_UPDATE=false", "PATH=/usr/bin:/bin", "TMPDIR=" + filepath.Join(root, "tmp"), "TMP=" + filepath.Join(root, "tmp"), "TEMP=" + filepath.Join(root, "tmp")}
	return scan, env, nil
}

func runSyft(ctx context.Context, path, dir string, env []string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = dir
	cmd.Env = env
	stdout := &boundedBuffer{limit: sbomLimit}
	stderr := &boundedBuffer{limit: 1 << 20}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("syft failed: %w", err)
	}
	return stdout.buf.Bytes(), nil
}

// leaksPrivatePath decodes JSON tokens, including object keys, and fails closed on malformed or duplicate-key input.
func leaksPrivatePath(data []byte, path string) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	found, err := inspectJSONValue(decoder, path)
	if err != nil || found {
		return true
	}
	_, err = decoder.Token()
	return !errors.Is(err, io.EOF)
}

func inspectJSONValue(decoder *json.Decoder, path string) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	switch value := token.(type) {
	case string:
		return path != "" && strings.Contains(value, path), nil
	case json.Delim:
		switch value {
		case '{':
			return inspectJSONObject(decoder, path)
		case '[':
			return inspectJSONArray(decoder, path)
		default:
			return false, fmt.Errorf("unexpected JSON delimiter")
		}
	default:
		return false, nil
	}
}

func inspectJSONObject(decoder *json.Decoder, path string) (bool, error) {
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false, err
		}
		key, ok := token.(string)
		if !ok {
			return false, fmt.Errorf("invalid JSON key")
		}
		if _, exists := seen[key]; exists {
			return false, fmt.Errorf("duplicate JSON key")
		}
		seen[key] = struct{}{}
		if path != "" && strings.Contains(key, path) {
			return true, nil
		}
		found, err := inspectJSONValue(decoder, path)
		if err != nil || found {
			return found, err
		}
	}
	_, err := decoder.Token()
	return false, err
}

func inspectJSONArray(decoder *json.Decoder, path string) (bool, error) {
	for decoder.More() {
		found, err := inspectJSONValue(decoder, path)
		if err != nil || found {
			return found, err
		}
	}
	_, err := decoder.Token()
	return false, err
}

// scrubSBOM replaces only known Syft binary component paths; all other private paths fail closed.
func scrubSBOM(raw []byte, scan, root string) ([]byte, error) {
	// Reject duplicate keys before decoding into maps, which otherwise discard earlier values.
	if leaksPrivatePath(raw, "") {
		return nil, fmt.Errorf("invalid or ambiguous Syft JSON")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil || doc == nil {
		return nil, fmt.Errorf("invalid Syft JSON")
	}
	var components []map[string]json.RawMessage
	if err := json.Unmarshal(doc["components"], &components); err != nil {
		return nil, fmt.Errorf("invalid Syft components")
	}
	allowed := []string{"server/tailkeeper", "slices/tailkeeper-amd64", "slices/tailkeeper-arm64"}
	for _, component := range components {
		var name string
		if err := json.Unmarshal(component["name"], &name); err != nil {
			return nil, fmt.Errorf("invalid component name")
		}
		for _, rel := range allowed {
			if name == filepath.Join(scan, filepath.FromSlash(rel)) {
				value, err := json.Marshal(rel)
				if err != nil {
					return nil, err
				}
				component["name"] = value
			}
		}
	}
	c, err := json.Marshal(components)
	if err != nil {
		return nil, err
	}
	doc["components"] = c
	clean, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if leaksPrivatePath(clean, root) {
		return nil, fmt.Errorf("syft output contains unexpected private path")
	}
	return clean, nil
}

func bindSBOM(raw []byte, name string, bundle []byte) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil || doc == nil {
		return nil, fmt.Errorf("invalid Syft JSON")
	}
	var components []map[string]json.RawMessage
	if err := json.Unmarshal(doc["components"], &components); err != nil {
		return nil, fmt.Errorf("invalid Syft components")
	}
	found := false
	for _, c := range components {
		purl, err := exactJSONString(c, "purl")
		if err != nil {
			return nil, fmt.Errorf("invalid component purl")
		}
		if strings.HasPrefix(purl, "pkg:golang/") {
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("no Go module components")
	}
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(doc["metadata"], &metadata); err != nil || metadata == nil {
		return nil, fmt.Errorf("invalid Syft metadata")
	}
	digest := sha256.Sum256(bundle)
	component := struct {
		Type   string `json:"type"`
		Name   string `json:"name"`
		Hashes []struct {
			Alg     string `json:"alg"`
			Content string `json:"content"`
		} `json:"hashes"`
	}{Type: "file", Name: name}
	component.Hashes = append(component.Hashes, struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	}{Alg: "SHA-256", Content: hex.EncodeToString(digest[:])})
	c, err := json.Marshal(component)
	if err != nil {
		return nil, err
	}
	metadata["component"] = c
	m, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	doc["metadata"] = m
	result, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append(result, '\n'), nil
}

// exactJSONString reads only the named JSON member, without case-insensitive struct matching.
func exactJSONString(object map[string]json.RawMessage, key string) (string, error) {
	var value string
	if raw, ok := object[key]; ok {
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", err
		}
	}
	return value, nil
}
