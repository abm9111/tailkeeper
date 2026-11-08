//go:build !windows

package workflows

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/releasebundle"
)

// The shim only translates the workflow's fixed go run invocation to the real,
// prebuilt verifier. Checksums, extraction, comparisons and verification execute.
func reproductionScript(t *testing.T) string {
	t.Helper()
	wf, _ := loadWorkflow(t)
	for _, s := range wf.Jobs["reproduce"].Steps {
		if strings.Contains(s.Run, "go run ./scripts/mcpb.go verify") {
			return s.Run
		}
	}
	t.Fatal("reproduction script missing")
	return ""
}
func reproduceThin(cpu, sub uint32) []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b, 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], cpu)
	binary.LittleEndian.PutUint32(b[8:], sub)
	binary.LittleEndian.PutUint32(b[12:], 2)
	return b
}
func reproduceFat(a, b []byte) []byte {
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
func reproduceWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func reproduceArchive(t *testing.T, path, name string, data []byte) {
	t.Helper()
	var buf bytes.Buffer
	if strings.HasSuffix(path, ".zip") {
		z := zip.NewWriter(&buf)
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
	}
	reproduceWrite(t, path, buf.Bytes())
}
func reproduceChecksums(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, "released")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	for _, e := range entries {
		if e.Name() == "checksums.txt" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&text, "%x  %s\n", sha256.Sum256(b), e.Name())
	}
	reproduceWrite(t, filepath.Join(dir, "checksums.txt"), []byte(text.String()))
}
func reproduceFixture(t *testing.T, verifier string) string {
	t.Helper()
	root := t.TempDir()
	a, b := reproduceThin(0x01000007, 3), reproduceThin(0x0100000c, 0)
	for _, tc := range []struct {
		target string
		data   []byte
	}{{"darwin_amd64", a}, {"darwin_arm64", b}, {"linux_amd64", []byte("linux-a")}, {"linux_arm64", []byte("linux-b")}, {"windows_amd64", []byte("windows")}} {
		name, ext := "tailkeeper", "tar.gz"
		if tc.target == "windows_amd64" {
			name, ext = "tailkeeper.exe", "zip"
		}
		reproduceWrite(t, filepath.Join(root, "dist", "tailkeeper_"+tc.target+"_v1", name), tc.data)
		reproduceArchive(t, filepath.Join(root, "released", "tailkeeper_1.2.3_"+tc.target+"."+ext), name, tc.data)
	}
	universal := filepath.Join(root, "universal")
	reproduceWrite(t, universal, reproduceFat(a, b))
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "released", "tailkeeper_1.2.3_darwin_universal.mcpb")
	if err := releasebundle.Build(releasebundle.BuildOptions{Version: "1.2.3", UniversalPath: universal, RootDir: repo, OutputPath: bundle}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	reproduceWrite(t, filepath.Join(root, "dist", filepath.Base(bundle)), data)
	reproduceChecksums(t, root)
	shim := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> \"$REPRO_INVOKES\"\n[ \"$1\" = run ] && [ \"$2\" = ./scripts/mcpb.go ] || exit 98\nshift 2\nexec %q \"$@\"\n", verifier)
	reproduceWrite(t, filepath.Join(root, "shim", "go"), []byte(shim))
	if err := os.Chmod(filepath.Join(root, "shim", "go"), 0700); err != nil {
		t.Fatal(err)
	}
	return root
}
func runReproduction(t *testing.T, script, root string) (string, string, error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = root
	log := filepath.Join(root, "invocations")
	cmd.Env = []string{"PATH=" + filepath.Join(root, "shim") + ":" + os.Getenv("PATH"), "RUNNER_TEMP=" + root, "GITHUB_REF_NAME=v1.2.3", "REPRO_INVOKES=" + log}
	out, err := cmd.CombinedOutput()
	calls, _ := os.ReadFile(log)
	return string(out), string(calls), err
}
func TestExecutedReleaseReproduction(t *testing.T) {
	script := reproductionScript(t)
	verifier := filepath.Join(t.TempDir(), "verifier")
	build := exec.Command("go", "build", "-o", verifier, "./scripts/mcpb.go")
	build.Dir = "../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build verifier: %v: %s", err, out)
	}
	cases := []struct {
		name   string
		mutate func(string)
		wantOK bool
	}{
		{"clean", func(string) {}, true},
		{"missing archive", func(r string) {
			_ = os.Remove(filepath.Join(r, "released", "tailkeeper_1.2.3_linux_amd64.tar.gz"))
			reproduceChecksums(t, r)
		}, false},
		{"duplicate archive", func(r string) {
			p := filepath.Join(r, "released", "tailkeeper_1.2.3_linux_amd64.tar.gz")
			b, _ := os.ReadFile(p)
			reproduceWrite(t, filepath.Join(r, "released", "tailkeeper_other_linux_amd64.tar.gz"), b)
			reproduceChecksums(t, r)
		}, false},
		{"missing build", func(r string) { _ = os.Remove(filepath.Join(r, "dist", "tailkeeper_linux_amd64_v1", "tailkeeper")) }, false},
		{"duplicate build", func(r string) {
			reproduceWrite(t, filepath.Join(r, "dist", "tailkeeper_linux_amd64_duplicate", "tailkeeper"), []byte("linux-a"))
		}, false},
		{"binary mismatch", func(r string) {
			reproduceWrite(t, filepath.Join(r, "dist", "tailkeeper_linux_amd64_v1", "tailkeeper"), []byte("different"))
		}, false},
		{"missing bundle", func(r string) {
			_ = os.Remove(filepath.Join(r, "released", "tailkeeper_1.2.3_darwin_universal.mcpb"))
			reproduceChecksums(t, r)
		}, false},
		{"duplicate bundle", func(r string) {
			p := filepath.Join(r, "released", "tailkeeper_1.2.3_darwin_universal.mcpb")
			b, _ := os.ReadFile(p)
			reproduceWrite(t, filepath.Join(r, "released", "extra.mcpb"), b)
			reproduceChecksums(t, r)
		}, false},
		{"invalid bundle", func(r string) {
			p := filepath.Join(r, "released", "tailkeeper_1.2.3_darwin_universal.mcpb")
			b, _ := os.ReadFile(p)
			b = append(b, 0)
			reproduceWrite(t, p, b)
			reproduceWrite(t, filepath.Join(r, "dist", filepath.Base(p)), b)
			reproduceChecksums(t, r)
		}, false},
		{"bundle mismatch", func(r string) {
			reproduceWrite(t, filepath.Join(r, "dist", "tailkeeper_1.2.3_darwin_universal.mcpb"), []byte("different"))
		}, false},
		{"checksum mismatch", func(r string) {
			f, err := os.OpenFile(filepath.Join(r, "released", "tailkeeper_1.2.3_linux_amd64.tar.gz"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := reproduceFixture(t, verifier)
			tc.mutate(root)
			out, calls, err := runReproduction(t, script, root)
			if (err == nil) != tc.wantOK {
				t.Fatalf("unexpected result: %v\n%s", err, out)
			}
			if tc.wantOK && strings.TrimSpace(calls) != "run ./scripts/mcpb.go verify -bundle released/tailkeeper_1.2.3_darwin_universal.mcpb -dist dist -version 1.2.3" {
				t.Fatalf("verifier invocation: %q", calls)
			}
		})
	}
	for _, tc := range []struct{ name, needle, scenario string }{{"binary comparison", `cmp "${builds[0]}" "$work/$target/$binary"`, "binary mismatch"}, {"bundle comparison", `cmp "${bundles[0]}" "$rebuilt"`, "bundle mismatch"}, {"verifier", `go run ./scripts/mcpb.go verify -bundle`, "invalid bundle"}} {
		t.Run("commented "+tc.name, func(t *testing.T) {
			lines := strings.Split(script, "\n")
			found := false
			for i, line := range lines {
				if strings.Contains(line, tc.needle) {
					lines[i] = "# " + line
					found = true
					break
				}
			}
			if !found {
				t.Fatal("mutation target missing")
			}
			mutant := strings.Join(lines, "\n")
			root := reproduceFixture(t, verifier)
			for _, c := range cases {
				if c.name == tc.scenario {
					c.mutate(root)
				}
			}
			if out, _, err := runReproduction(t, mutant, root); err != nil {
				t.Fatalf("mutation did not defeat control: %v\n%s", err, out)
			}
		})
	}
}
