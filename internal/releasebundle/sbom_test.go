package releasebundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "scan") {
		os.Exit(fakeSyft())
	}
	os.Exit(m.Run())
}
func fakeSyft() int {
	mode := filepath.Base(os.Args[0])
	if strings.Contains(mode, "marker") {
		if err := os.WriteFile(filepath.Join(filepath.Dir(os.Args[0]), "invoked"), []byte("yes"), 0600); err != nil {
			return 17
		}
	}
	if os.Args[1] == "version" {
		if strings.Contains(mode, "wrong") {
			fmt.Println("Version:       9.0.0")
			return 0
		}
		fmt.Println("Version:       1.54.0")
		return 0
	}
	if strings.Contains(mode, "archive") {
		return fakeArchiveSyft(mode)
	}
	if !reflect.DeepEqual(os.Args[1:], []string{"scan", "dir:.", "-o", "cyclonedx-json", "--enrich", "none", "-c", "../control/syft.yaml"}) {
		return 11
	}
	cwd, err := os.Getwd()
	if err != nil || filepath.Base(cwd) != "scan" {
		return 12
	}
	if !validSyftHelperEnv(os.Environ(), cwd, runtime.GOOS) {
		return 13
	}
	cfg, err := os.ReadFile("../control/syft.yaml")
	if err != nil || string(cfg) != "{}\n" {
		return 14
	}
	count := 0
	err = filepath.WalkDir(".", func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() {
			count++
		}
		return nil
	})
	if err != nil || count != 10 {
		return 15
	}
	switch {
	case strings.Contains(mode, "failure"):
		return 16
	case strings.Contains(mode, "empty-output"):
		return 0
	case strings.Contains(mode, "empty-components"):
		fmt.Print(`{"metadata":{},"components":[]}`)
		return 0
	case strings.Contains(mode, "malformed-object-key"):
		fmt.Print(`{"metadata":{"nested":{"unterminated`)
		return 0
	case strings.Contains(mode, "leak"):
		fmt.Printf(`{"metadata":{"canary":%q},"components":[{"name":"x","purl":"pkg:golang/example"}]}`, filepath.Dir(cwd))
		return 0
	}
	fmt.Printf(`{"metadata":{"component":{"name":"."}},"components":[{"name":%q,"purl":"pkg:golang/example@v1"}],"other":{"preserved":true}}`, filepath.Join(cwd, "server", "tailkeeper"))
	return 0
}

// validSyftHelperEnv rejects duplicates and inherited variables; Windows exec adds SYSTEMROOT.
func validSyftHelperEnv(env []string, cwd, goos string) bool {
	expected := map[string]string{"HOME": filepath.Join(filepath.Dir(cwd), "home"), "XDG_CONFIG_HOME": filepath.Join(filepath.Dir(cwd), "config"), "XDG_CACHE_HOME": filepath.Join(filepath.Dir(cwd), "cache"), "SYFT_CHECK_FOR_APP_UPDATE": "false", "PATH": "/usr/bin:/bin", "TMPDIR": filepath.Join(filepath.Dir(cwd), "tmp"), "TMP": filepath.Join(filepath.Dir(cwd), "tmp"), "TEMP": filepath.Join(filepath.Dir(cwd), "tmp")}
	if goos == "windows" {
		expected["SYSTEMROOT"] = os.Getenv("SYSTEMROOT")
	}
	if len(env) != len(expected) {
		return false
	}
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			return false
		}
		if goos == "windows" {
			key = strings.ToUpper(key)
		}
		want, exists := expected[key]
		if !exists || value != want {
			return false
		}
		delete(expected, key)
	}
	return len(expected) == 0
}

func syftHelperName(mode, goos string) string {
	name := "fake-syft-" + mode
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

func syftHelper(t *testing.T, mode string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	dir := filepath.Join(t.TempDir(), "path with spaces")
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, syftHelperName(mode, runtime.GOOS))
	dst, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err = dst.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestWriteSBOMIsolatedAndBound(t *testing.T) {
	t.Setenv("UNTRUSTED_CREDENTIAL_CANARY", "do-not-inherit")
	bundle, _ := fixtureBuild(t, fixtureRoot(t), false)
	out := filepath.Join(t.TempDir(), "bundle with spaces.json")
	if err := WriteSBOM(context.Background(), bundle, out, syftHelper(t, "ok")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Metadata struct {
			Component struct {
				Name   string `json:"name"`
				Hashes []struct {
					Alg     string `json:"alg"`
					Content string `json:"content"`
				} `json:"hashes"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Name string `json:"name"`
		} `json:"components"`
		Other struct {
			Preserved bool `json:"preserved"`
		} `json:"other"`
	}
	if err = json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(b)
	if doc.Metadata.Component.Name != filepath.Base(bundle) || len(doc.Metadata.Component.Hashes) != 1 || doc.Metadata.Component.Hashes[0].Alg != "SHA-256" || doc.Metadata.Component.Hashes[0].Content != hex.EncodeToString(hash[:]) || !doc.Other.Preserved || doc.Components[0].Name != "server/tailkeeper" {
		t.Fatal("SBOM binding, sanitization or preservation failed")
	}
	if err = WriteSBOM(context.Background(), bundle, out, syftHelper(t, "ok")); err == nil {
		t.Fatal("overwrote output")
	}
}
func TestWriteSBOMRejectsFailures(t *testing.T) {
	bundle, _ := fixtureBuild(t, fixtureRoot(t), false)
	for _, mode := range []string{"wrong", "failure", "empty-output", "empty-components", "malformed-object-key", "leak"} {
		t.Run(mode, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			if err := WriteSBOM(context.Background(), bundle, out, syftHelper(t, mode)); err == nil {
				t.Fatal("accepted invalid Syft output")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("failure produced output")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WriteSBOM(ctx, bundle, filepath.Join(t.TempDir(), "out"), syftHelper(t, "ok")); err == nil {
		t.Fatal("accepted cancelled context")
	}
	if err := WriteSBOM(context.Background(), bundle, filepath.Join(t.TempDir(), "out"), "relative"); err == nil {
		t.Fatal("accepted relative executable")
	}
	if err := WriteSBOM(context.Background(), "missing", filepath.Join(t.TempDir(), "out"), syftHelper(t, "ok")); err == nil {
		t.Fatal("accepted missing bundle")
	}
}
func TestScrubSBOMRejectsPrivatePathCanary(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private canary")
	scan := filepath.Join(root, "scan")
	for _, v := range []string{fmt.Sprintf(`{"metadata":{"x":%q},"components":[{"name":"ok","purl":"pkg:golang/x"}]}`, root), fmt.Sprintf(`{"metadata":{},"components":[{"name":%q,"purl":"pkg:golang/x"}]}`, filepath.Join(scan, "unexpected"))} {
		if _, err := scrubSBOM([]byte(v), scan, root); err == nil {
			t.Fatal("accepted private path")
		}
	}
}

func TestSBOMRejectsMixedKnownAndUnknownPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private root")
	scan := filepath.Join(root, "scan")
	doc := fmt.Sprintf(`{"metadata":{},"components":[{"name":%q,"purl":"pkg:golang/x"},{"name":%q,"purl":"pkg:golang/y"}]}`, filepath.Join(scan, "server", "tailkeeper"), filepath.Join(root, "home", "unexpected"))
	if _, err := scrubSBOM([]byte(doc), scan, root); err == nil {
		t.Fatal("accepted unexpected path beside a known binary")
	}
}
func TestSBOMDocumentAndLimits(t *testing.T) {
	for _, raw := range []string{``, `null`, `{}`, `{"metadata":{},"components":[{"name":"x"}]}`, `{"metadata":null,"components":[{"name":"x","purl":"pkg:golang/x"}]}`, `{"metadata":{},"components":"bad"}`} {
		if _, err := bindSBOM([]byte(raw), "name", []byte("data")); err == nil {
			t.Errorf("accepted invalid document %q", raw)
		}
	}
	for _, raw := range []string{`bad`, `null`, `{}`, `{"components":[{"name":1}]}`} {
		if _, err := scrubSBOM([]byte(raw), "/private/scan", "/private"); err == nil {
			t.Errorf("accepted invalid raw document %q", raw)
		}
	}
	var b boundedBuffer
	b.limit = 3
	if _, err := b.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("d")); err == nil {
		t.Fatal("accepted output beyond limit")
	}
	if b.buf.String() != "abc" {
		t.Fatal("overflow changed buffered output")
	}
}
func TestSBOMStageRejectsFilesystemErrors(t *testing.T) {
	root := t.TempDir()
	entries := map[string][]byte{}
	if _, _, err := stageSBOM(filepath.Join(root, "missing"), entries, nil, testSBOMFSOps()); err == nil {
		t.Fatal("accepted missing staging parent")
	}
	if err := os.Mkdir(filepath.Join(root, "scan"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stageSBOM(root, entries, nil, testSBOMFSOps()); err == nil {
		t.Fatal("accepted existing scan directory")
	}
	if _, _, err := sbomEntries([]byte("not zip")); err == nil {
		t.Fatal("accepted malformed bundle")
	}
}

func TestSBOMRejectsMalformedBundleContents(t *testing.T) {
	bundle, _ := fixtureBuild(t, fixtureRoot(t), false)
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := decodeBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	originalManifest := entries["manifest.json"]
	originalBinary := entries["server/tailkeeper"]
	for _, tc := range []struct {
		name             string
		manifest, binary []byte
	}{
		{"malformed manifest", []byte("{"), originalBinary},
		{"invalid version", []byte(`{"version":"bad"}`), originalBinary},
		{"noncanonical manifest", append(append([]byte{}, originalManifest...), ' '), originalBinary},
		{"invalid executable", originalManifest, []byte("invalid")},
		{"noncanonical executable", originalManifest, fat(thin(0x01000007, 3), thin(0x0100000c, 0), true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries["manifest.json"] = tc.manifest
			entries["server/tailkeeper"] = tc.binary
			b, err := encodeBundle(entries)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = sbomEntries(b); err == nil {
				t.Fatal("accepted malformed content")
			}
		})
	}
}
func TestWriteSBOMOutputAndToolErrors(t *testing.T) {
	bundle, _ := fixtureBuild(t, fixtureRoot(t), false)
	tool := syftHelper(t, "ok")
	for _, tc := range []struct{ name, bundle, out, tool string }{
		{"missing output parent", bundle, filepath.Join(t.TempDir(), "missing", "out"), tool},
		{"missing executable", bundle, filepath.Join(t.TempDir(), "out"), filepath.Join(t.TempDir(), "missing")},
		{"missing bundle", "", filepath.Join(t.TempDir(), "out"), tool},
		{"missing output", bundle, "", tool},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := WriteSBOM(context.Background(), tc.bundle, tc.out, tc.tool); err == nil {
				t.Fatal("accepted invalid input or I/O failure")
			}
		})
	}
}

func TestSBOMDecodedPrivatePathsFailClosed(t *testing.T) {
	root := "/private/staging-canary"
	scan := filepath.Join(root, "scan")
	known, err := json.Marshal(filepath.Join(scan, "server", "tailkeeper"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, nested string }{
		{"escaped slash value", `{"inner":[{"path":"\/private\/staging-canary\/home"}]}`},
		{"unicode slash value", `{"inner":[{"path":"\u002fprivate\u002fstaging-canary\u002fhome"}]}`},
		{"escaped property key", `{"inner":{"\/private\/staging-canary\/home":true}}`},
		{"unicode property key", `{"inner":{"\u002fprivate\u002fstaging-canary\u002fhome":true}}`},
		{"plain nested array", `{"inner":[["/private/staging-canary/home"]]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"metadata":%s,"components":[{"name":%s,"purl":"pkg:golang/x"}]}`, tc.nested, known))
			// Check the detector independently before relying on the scrubber's rejection.
			if !leaksPrivatePath([]byte(tc.nested), root) {
				t.Error("detector missed decoded private path")
			}
			if _, err := scrubSBOM(raw, scan, root); err == nil {
				t.Error("accepted decoded private path beside known component")
			}
		})
	}
	clean := []byte(`{"nested":["/public/path",{"key":"safe"}]}`)
	if leaksPrivatePath(clean, root) {
		t.Fatal("detector rejected unrelated data")
	}
}

func TestSyftHelperEnvironmentAllowlist(t *testing.T) {
	cwd := filepath.Join("root", "scan")
	base := []string{"HOME=" + filepath.Join("root", "home"), "XDG_CONFIG_HOME=" + filepath.Join("root", "config"), "XDG_CACHE_HOME=" + filepath.Join("root", "cache"), "SYFT_CHECK_FOR_APP_UPDATE=false", "PATH=/usr/bin:/bin", "TMPDIR=" + filepath.Join("root", "tmp"), "TMP=" + filepath.Join("root", "tmp"), "TEMP=" + filepath.Join("root", "tmp")}
	if !validSyftHelperEnv(base, cwd, "darwin") {
		t.Fatal("rejected expected environment")
	}
	windows := append(append([]string{}, base...), "SYSTEMROOT="+os.Getenv("SYSTEMROOT"))
	if !validSyftHelperEnv(windows, cwd, "windows") {
		t.Fatal("rejected Windows critical environment")
	}
	if validSyftHelperEnv(base, cwd, "windows") || validSyftHelperEnv(windows, cwd, "darwin") {
		t.Fatal("accepted wrong platform environment")
	}
	if validSyftHelperEnv(append(windows, "INHERITED_CANARY=x"), cwd, "windows") {
		t.Fatal("accepted inherited environment")
	}
	bad := append([]string{}, windows...)
	bad[0] = bad[1]
	if validSyftHelperEnv(bad, cwd, "windows") {
		t.Fatal("accepted duplicate and missing environment keys")
	}
}

func TestSBOMRejectsDuplicateJSONKeys(t *testing.T) {
	raw := []byte(`{"metadata":{"path":"/private/staging-canary/home","path":"safe"},"components":[{"name":"ok","purl":"pkg:golang/x"}]}`)
	if !leaksPrivatePath(raw, "") {
		t.Fatal("duplicate key was not detected")
	}
	if _, err := scrubSBOM(raw, "/private/staging-canary/scan", "/private/staging-canary"); err == nil {
		t.Fatal("accepted duplicate JSON keys")
	}
}

func TestSyftHelperExecutableName(t *testing.T) {
	if got := syftHelperName("ok", "windows"); got != "fake-syft-ok.exe" {
		t.Fatalf("Windows helper name = %q", got)
	}
	if got := syftHelperName("ok", "darwin"); got != "fake-syft-ok" {
		t.Fatalf("Darwin helper name = %q", got)
	}
}

func testSBOMFSOps() sbomFSOps {
	return sbomFSOps{mkdirTemp: os.MkdirTemp, evalSymlinks: filepath.EvalSymlinks, mkdir: os.Mkdir, mkdirAll: os.MkdirAll, writeFile: os.WriteFile}
}

// obstructSBOMStage delegates every operation to the filesystem and inserts one private obstruction.
func obstructSBOMStage(kind, parent string, created *string) sbomFSOps {
	ops := testSBOMFSOps()
	ops.mkdirTemp = func(_ string, pattern string) (string, error) {
		dir := parent
		if kind == "temp-root" {
			dir = filepath.Join(parent, "regular-parent")
		}
		root, err := os.MkdirTemp(dir, pattern)
		*created = root
		return root, err
	}
	ops.evalSymlinks = func(path string) (string, error) {
		if kind == "root-lookup" {
			if err := os.Remove(path); err != nil {
				return "", err
			}
		}
		return filepath.EvalSymlinks(path)
	}
	ops.mkdir = func(path string, mode os.FileMode) error {
		if kind == "slice-directory" && filepath.Base(path) == "slices" {
			if err := os.WriteFile(path, []byte("obstruction"), 0600); err != nil {
				return err
			}
		}
		return os.Mkdir(path, mode)
	}
	ops.mkdirAll = func(path string, mode os.FileMode) error {
		if kind == "entry-parent" && filepath.Base(path) == "server" {
			if err := os.WriteFile(path, []byte("obstruction"), 0600); err != nil {
				return err
			}
		}
		return os.MkdirAll(path, mode)
	}
	ops.writeFile = func(path string, data []byte, mode os.FileMode) error {
		base := filepath.Base(path)
		if (kind == "control-config" && base == "syft.yaml") || (kind == "entry-write" && base == "LICENSE") || (kind == "slice-write" && base == "tailkeeper-amd64") {
			if err := os.Mkdir(path, 0700); err != nil {
				return err
			}
		}
		return os.WriteFile(path, data, mode)
	}
	return ops
}

func TestWriteSBOMStagingIOFailures(t *testing.T) {
	bundle, _ := fixtureBuild(t, fixtureRoot(t), false)
	helper := syftHelper(t, "marker")
	marker := filepath.Join(filepath.Dir(helper), "invoked")
	parent := t.TempDir()
	var created string
	control := obstructSBOMStage("none", parent, &created)
	if err := writeSBOMWith(context.Background(), bundle, filepath.Join(parent, "control-output"), helper, control); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("successful control did not invoke helper")
	}
	if _, err := os.Stat(created); !os.IsNotExist(err) {
		t.Fatal("successful control retained staging root")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "regular-parent"), []byte("parent"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"temp-root", "root-lookup", "control-config", "entry-parent", "entry-write", "slice-directory", "slice-write"} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%t", kind, existing), func(t *testing.T) {
				output := filepath.Join(t.TempDir(), "result.json")
				if existing {
					if err := os.WriteFile(output, []byte("preserve"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				root := ""
				ops := obstructSBOMStage(kind, parent, &root)
				err := writeSBOMWith(context.Background(), bundle, output, helper, ops)
				var pathErr *os.PathError
				if !errors.As(err, &pathErr) {
					t.Fatalf("expected filesystem PathError, got %v", err)
				}
				if pathErr.Op != "mkdir" && pathErr.Op != "open" && pathErr.Op != "lstat" && pathErr.Op != "stat" {
					t.Errorf("unexpected filesystem operation %q", pathErr.Op)
				}
				wantBase := map[string]string{"control-config": "syft.yaml", "entry-parent": "server", "entry-write": "LICENSE", "slice-directory": "slices", "slice-write": "tailkeeper-amd64"}[kind]
				if wantBase != "" && filepath.Base(pathErr.Path) != wantBase {
					t.Errorf("filesystem failure targeted %q, want %q", filepath.Base(pathErr.Path), wantBase)
				}
				if _, err = os.Stat(marker); !os.IsNotExist(err) {
					t.Error("helper was invoked after staging failure")
				}
				if existing {
					b, e := os.ReadFile(output)
					if e != nil || string(b) != "preserve" {
						t.Error("existing output changed")
					}
				} else if _, e := os.Stat(output); !os.IsNotExist(e) {
					t.Error("failure published output")
				}
				if root != "" {
					if _, e := os.Stat(root); !os.IsNotExist(e) {
						t.Error("temporary root remained after failure")
					}
				}
			})
		}
	}
}

func TestWriteSBOMRejectsMalformedInputBeforeSyft(t *testing.T) {
	parent := t.TempDir()
	input := filepath.Join(parent, "invalid.mcpb")
	output := filepath.Join(parent, "output")
	if err := os.WriteFile(input, []byte("not a ZIP"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	helper := syftHelper(t, "marker")
	var root string
	ops := obstructSBOMStage("none", parent, &root)
	if err := writeSBOMWith(context.Background(), input, output, helper, ops); err == nil {
		t.Fatal("accepted malformed bundle")
	}
	if root != "" {
		t.Fatal("created temporary root for malformed bundle")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(helper), "invoked")); !os.IsNotExist(err) {
		t.Fatal("invoked helper for malformed bundle")
	}
	b, err := os.ReadFile(output)
	if err != nil || string(b) != "preserve" {
		t.Fatal("changed existing output")
	}
}

func fakeArchiveSyft(mode string) int {
	if strings.Contains(mode, "failure") {
		return 16
	}
	if strings.Contains(mode, "empty-output") {
		return 0
	}
	if strings.Contains(mode, "empty-components") {
		fmt.Print(`{"metadata":{},"components":[]}`)
		return 0
	}
	if strings.Contains(mode, "leak") {
		fmt.Print(`{"metadata":{"canary":"private"},"components":[]}`)
		return 0
	}
	if len(os.Args) != 9 || os.Args[1] != "scan" || (os.Args[2] != "file:archive.tar.gz" && os.Args[2] != "file:archive.zip") || !reflect.DeepEqual(os.Args[3:], []string{"-o", "cyclonedx-json", "--enrich", "none", "-c", "../control/syft.yaml"}) {
		return 21
	}
	cwd, err := os.Getwd()
	if err != nil || !validSyftHelperEnv(os.Environ(), cwd, runtime.GOOS) {
		return 22
	}
	data, err := os.ReadFile(strings.TrimPrefix(os.Args[2], "file:"))
	if err != nil {
		return 23
	}
	hash := sha256.Sum256(data)
	binary := "tailkeeper"
	if strings.HasSuffix(os.Args[2], ".zip") {
		binary += ".exe"
	}
	name := filepath.Join(filepath.Dir(cwd), "tmp", "syft-archive-contents-123", binary)
	fmt.Printf(`{"metadata":{},"components":[{"type":"file","name":%q,"hashes":[{"alg":"SHA-256","content":%q}]},{"type":"library","name":"example","purl":"pkg:golang/example@v1"}]}`, name, hex.EncodeToString(hash[:]))
	return 0
}
