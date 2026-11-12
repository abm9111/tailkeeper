//go:build !windows

package safefile

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestPrivateLifecycle(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pack")
	content := []byte("complete private content")
	calls := 0
	err := WritePrivate(path, content, func() error {
		calls++
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("final exists before callback: %v", err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("temporary count: %d", len(entries))
		}
		b, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
		if err != nil || !bytes.Equal(b, content) {
			t.Fatalf("temporary incomplete: %v", err)
		}
		return nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("write: %v calls %d", err, calls)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: %v %v", fi, err)
	}
	b, err := ReadPrivate(path)
	if err != nil || !bytes.Equal(b, content) {
		t.Fatalf("read: %v", err)
	}
	if err := WritePrivate(path, []byte("overwrite"), nil); err == nil {
		t.Fatal("overwrote existing file")
	}
	b, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(b, content) {
		t.Fatalf("existing content changed: %v", err)
	}
}

func TestPrivateFailureCleanup(t *testing.T) {
	for _, stage := range []string{"callback", "write", "short", "sync", "chmod", "close"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "pack")
			sentinel := errors.New("injected failure")
			calls := 0
			ops := privateWriteOps{}
			switch stage {
			case "write":
				ops.write = func(_ *os.File, _ []byte) (int, error) { return 0, sentinel }
			case "short":
				ops.write = func(_ *os.File, _ []byte) (int, error) { return 0, nil }
			case "sync":
				ops.sync = func(_ *os.File) error { return sentinel }
			case "chmod":
				ops.chmod = func(_ *os.File, _ os.FileMode) error { return sentinel }
			case "close":
				ops.close = func(f *os.File) error { return errors.Join(f.Close(), sentinel) }
			}
			err := writePrivate(path, []byte("data"), func() error { calls++; return sentinel }, ops)
			if err == nil || (stage != "short" && !errors.Is(err, sentinel)) {
				t.Fatalf("failure missing: %v", err)
			}
			if stage == "short" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short write: %v", err)
			}
			if stage == "callback" && (calls != 1 || reflect.ValueOf(err).Pointer() != reflect.ValueOf(sentinel).Pointer()) {
				t.Fatalf("callback identity/calls: %v %d", err, calls)
			}
			if stage != "callback" && calls != 0 {
				t.Fatalf("callback on earlier failure: %d", calls)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("leaked files %v: %v", entries, err)
			}
		})
	}
}

func TestPrivateSafety(t *testing.T) {
	t.Run("directory spellings", testPrivateDirectorySpellings)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pack")
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(path, nil, nil); err == nil {
		t.Fatal("accepted symlink final")
	}
	if _, err := ReadPrivate(path); err == nil {
		t.Fatal("read symlink final")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, parentLink); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(filepath.Join(parentLink, "pack"), nil, nil); err == nil {
		t.Fatal("accepted symlink parent")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(path, nil, nil); err == nil {
		t.Fatal("accepted shared parent")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(path, nil, nil); err == nil {
		t.Fatal("accepted git worktree file")
	}
	if err := os.Remove(filepath.Join(dir, ".git")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(path, nil, nil); err == nil {
		t.Fatal("accepted git worktree directory")
	}
	if err := os.Remove(filepath.Join(dir, ".git")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("private"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(path); err == nil {
		t.Fatal("accepted public file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(privateCap + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(path); err == nil {
		t.Fatal("accepted oversized file")
	}
}

type privateFakeInfo struct {
	os.FileInfo
	sys *syscall.Stat_t
}

func (f privateFakeInfo) Sys() interface{} {
	if f.sys == nil {
		return nil
	}
	return f.sys
}
func TestPrivateOwnerInfo(t *testing.T) {
	dir := t.TempDir()
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := *fi.Sys().(*syscall.Stat_t)
	st.Uid++
	if err := privateInfo(privateFakeInfo{fi, &st}, true, 0o077); err == nil {
		t.Fatal("accepted another owner")
	}
	if err := privateInfo(privateFakeInfo{fi, nil}, true, 0o077); err == nil {
		t.Fatal("accepted missing owner")
	}
}

func TestPrivateReadReplacement(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pack")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readPrivate(path, func() {
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path+".old", path); err != nil {
			t.Fatal(err)
		}
	})
	if err == nil {
		t.Fatal("accepted a file replaced with a symlink after inspection")
	}
}

func TestPrivateExactCap(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pack")
	want := bytes.Repeat([]byte("x"), privateCap)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPrivate(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("exact cap: %v", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(path); err == nil {
		t.Fatal("accepted cap plus one")
	}
}

func TestPrivateParentReplacement(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "private")
	other := filepath.Join(base, "other")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := writePrivate(filepath.Join(dir, "pack"), []byte("data"), func() error { calls++; return nil }, privateWriteOps{afterParentInspect: func() {
		if err := os.Rename(dir, dir+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, dir); err != nil {
			t.Fatal(err)
		}
	}})
	if err == nil || calls != 0 {
		t.Fatalf("parent replacement: %v, calls %d", err, calls)
	}
	entries, err := os.ReadDir(other)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unexpected publication: %v %v", entries, err)
	}
}

func TestPrivatePostLinkFailure(t *testing.T) {
	for _, stage := range []string{"remove", "sync"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "pack")
			sentinel := errors.New("post-link failure")
			ops := privateWriteOps{}
			if stage == "remove" {
				calls := 0
				ops.remove = func(root *os.Root, name string) error {
					calls++
					if calls == 1 {
						return sentinel
					}
					return root.Remove(name)
				}
			} else {
				ops.syncDir = func(_ *os.File) error { return sentinel }
			}
			err := writePrivate(path, []byte("complete"), nil, ops)
			if !errors.Is(err, sentinel) {
				t.Fatalf("failure not returned: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "complete" {
				t.Fatalf("published file missing or incomplete: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("temporary remains: %v %v", entries, err)
			}
		})
	}
}

func TestPrivateUmask(t *testing.T) {
	if os.Getenv("TAILKEEPER_TEST_PRIVATE_UMASK") == "child" {
		base := t.TempDir()
		dir := filepath.Join(base, "private")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(dir)
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("parent mode: %v %v", fi, err)
		}
		path := filepath.Join(dir, "pack")
		if err := WritePrivate(path, []byte("data"), nil); err != nil {
			t.Fatal(err)
		}
		fi, err = os.Stat(path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("file mode: %v %v", fi, err)
		}
		return
	}
	for _, mask := range []string{"0000", "0077"} {
		t.Run(mask, func(t *testing.T) {
			cmd := exec.Command("/bin/sh", "-c", `umask "$1"; exec "$2" -test.run '^TestPrivateUmask$'`, "sh", mask, os.Args[0])
			cmd.Env = append(os.Environ(), "TAILKEEPER_TEST_PRIVATE_UMASK=child")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("umask %s: %v: %s", mask, err, output)
			}
		})
	}
}

func testPrivateDirectorySpellings(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "nested")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, dir)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{dir + string(filepath.Separator), dir + "/.", dir + "/..", dir + "/../pack", relative + "/"}
	for _, path := range []string{"pack", "./pack", "nested/pack"} {
		if name, err := privatePathName(path); err != nil || name != "pack" {
			t.Errorf("valid relative path %q: %q %v", path, name, err)
		}
	}
	calls := 0
	for _, path := range paths {
		if err := WritePrivate(path, []byte("data"), func() error { calls++; return nil }); err == nil {
			t.Errorf("accepted directory spelling %q for write", path)
		}
	}
	if calls != 0 {
		t.Errorf("callback called %d times", calls)
	}
	child := filepath.Join(dir, "nested")
	if _, err := os.Lstat(child); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected file created: %v", err)
	}
	if err := os.WriteFile(child, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if _, err := ReadPrivate(path); err == nil {
			t.Errorf("accepted directory spelling %q for read", path)
		}
	}
}
