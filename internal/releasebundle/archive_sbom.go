package releasebundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type archiveTarget struct{ os, arch, suffix, binary string }

var archiveTargets = []archiveTarget{
	{"darwin", "amd64", ".tar.gz", "tailkeeper"},
	{"darwin", "arm64", ".tar.gz", "tailkeeper"},
	{"linux", "amd64", ".tar.gz", "tailkeeper"},
	{"linux", "arm64", ".tar.gz", "tailkeeper"},
	{"windows", "amd64", ".zip", "tailkeeper.exe"},
}

// WriteArchiveSBOM scans a release archive using an isolated Syft process.
func WriteArchiveSBOM(ctx context.Context, archivePath, distDir, outputPath, syftPath string) error {
	ops := sbomFSOps{mkdirTemp: os.MkdirTemp, evalSymlinks: filepath.EvalSymlinks, mkdir: os.Mkdir, mkdirAll: os.MkdirAll, writeFile: os.WriteFile}
	return writeArchiveSBOMWith(ctx, archivePath, distDir, outputPath, syftPath, ops)
}

func archiveTargetFor(name string) (archiveTarget, error) {
	for _, target := range archiveTargets {
		end := "_" + target.os + "_" + target.arch + target.suffix
		if strings.HasPrefix(name, "tailkeeper_") && strings.HasSuffix(name, end) {
			version := strings.TrimSuffix(strings.TrimPrefix(name, "tailkeeper_"), end)
			if validVersion(version) {
				return target, nil
			}
		}
	}
	return archiveTarget{}, fmt.Errorf("invalid archive name")
}

func writeArchiveSBOMWith(ctx context.Context, archivePath, distDir, outputPath, syftPath string, ops sbomFSOps) error {
	if ctx == nil || archivePath == "" || distDir == "" || outputPath == "" || !filepath.IsAbs(syftPath) {
		return fmt.Errorf("invalid archive SBOM options")
	}
	target, archive, binary, err := archiveInputs(archivePath, distDir)
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
	scan, env, err := stageArchiveSBOM(root, archive, target.suffix, ops)
	if err != nil {
		return err
	}
	return scanArchiveAndWrite(ctx, syftPath, scan, root, env, archivePath, outputPath, target, archive, binary)
}

func archiveInputs(archivePath, distDir string) (archiveTarget, []byte, []byte, error) {
	target, err := archiveTargetFor(filepath.Base(archivePath))
	if err != nil {
		return target, nil, nil, err
	}
	archive, err := readRegular(archivePath, maxBinarySize)
	if err != nil {
		return target, nil, nil, err
	}
	paths, err := findTargetThin(distDir, target.os, target.arch, target.binary, os.Lstat)
	if err != nil {
		return target, nil, nil, err
	}
	if len(paths) != 1 {
		return target, nil, nil, fmt.Errorf("expected exactly one thin binary; found %d", len(paths))
	}
	binary, err := readRegular(paths[0], maxBinarySize)
	return target, archive, binary, err
}

func scanArchiveAndWrite(ctx context.Context, syftPath, scan, root string, env []string, archivePath, outputPath string, target archiveTarget, archive, binary []byte) error {
	version, err := runSyft(ctx, syftPath, scan, env, "version")
	if err != nil {
		return err
	}
	if !strings.Contains(string(version), "Version:       1.54.0\n") {
		return fmt.Errorf("unexpected Syft version")
	}
	var raw []byte
	if target.suffix == ".zip" {
		raw, err = runSyft(ctx, syftPath, scan, env, "scan", "file:archive.zip", "-o", "cyclonedx-json", "--enrich", "none", "-c", "../control/syft.yaml")
	} else {
		raw, err = runSyft(ctx, syftPath, scan, env, "scan", "file:archive.tar.gz", "-o", "cyclonedx-json", "--enrich", "none", "-c", "../control/syft.yaml")
	}
	if err != nil {
		return err
	}
	digest := sha256.Sum256(binary)
	clean, err := scrubArchiveSBOM(raw, root, target.binary, hex.EncodeToString(digest[:]))
	if err != nil {
		return err
	}
	final, err := bindSBOM(clean, filepath.Base(archivePath), archive)
	if err != nil {
		return err
	}
	if leaksPrivatePath(final, root) {
		return fmt.Errorf("SBOM contains private path")
	}
	return writeNew(outputPath, final)
}

func stageArchiveSBOM(root string, archive []byte, suffix string, ops sbomFSOps) (string, []string, error) {
	scan, env, err := stageSyftControl(root, ops)
	if err != nil {
		return "", nil, err
	}
	if err = ops.writeFile(filepath.Join(scan, "archive"+suffix), archive, 0600); err != nil {
		return "", nil, err
	}
	return scan, env, nil
}

func scrubArchiveSBOM(raw []byte, root, binary, digest string) ([]byte, error) {
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
	count, err := normalizeArchiveComponents(components, root, binary, digest)
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, fmt.Errorf("expected exactly one archive binary component; found %d", count)
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

func normalizeArchiveComponents(components []map[string]json.RawMessage, root, binary, digest string) (int, error) {
	count := 0
	for _, component := range components {
		var name, kind string
		if err := json.Unmarshal(component["name"], &name); err != nil {
			return 0, fmt.Errorf("invalid component name")
		}
		if err := json.Unmarshal(component["type"], &kind); err != nil {
			return 0, fmt.Errorf("invalid component type")
		}
		if kind != "file" || !archiveExtractionName(name, root, binary) {
			continue
		}
		if err := archiveComponentHash(component["hashes"], digest); err != nil {
			return 0, err
		}
		value, err := json.Marshal(binary)
		if err != nil {
			return 0, err
		}
		component["name"] = value
		count++
	}
	return count, nil
}

func archiveComponentHash(raw json.RawMessage, digest string) error {
	var hashes []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &hashes); err != nil {
		return fmt.Errorf("invalid component hashes")
	}
	found := false
	for _, hash := range hashes {
		alg, err := exactJSONString(hash, "alg")
		if err != nil {
			return fmt.Errorf("invalid component hash algorithm")
		}
		content, err := exactJSONString(hash, "content")
		if err != nil {
			return fmt.Errorf("invalid component hash content")
		}
		if alg == "SHA-256" {
			if content != digest {
				return fmt.Errorf("binary hash mismatch")
			}
			found = true
		}
	}
	if !found {
		return fmt.Errorf("missing binary hash")
	}
	return nil
}

func archiveExtractionName(name, root, binary string) bool {
	prefix := filepath.Join(root, "tmp") + string(filepath.Separator) + "syft-archive-contents-"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, prefix)
	child, rest, ok := strings.Cut(suffix, string(filepath.Separator))
	return ok && child != "" && child != "." && child != ".." && rest == binary && filepath.Clean(name) == name
}
