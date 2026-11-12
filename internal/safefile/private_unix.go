//go:build !windows

package safefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

const privateCap = 16 << 20

func privateError(message string, err error) error {
	if err == nil {
		return tkerr.New(tkerr.ConfigUnsafe, message, "")
	}
	return tkerr.Wrap(tkerr.ConfigUnsafe, err, message, "")
}

func privateInfo(fi os.FileInfo, dir bool, mask os.FileMode) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return privateError("private path is not owned by the current user", nil)
	}
	if dir && !fi.IsDir() || !dir && !fi.Mode().IsRegular() {
		return privateError("private path has an unsafe file type", nil)
	}
	if fi.Mode().Perm()&mask != 0 {
		return tkerr.New(tkerr.ConfigUnsafe, "private path has unsafe permissions", "restrict permissions with chmod")
	}
	return nil
}

// privateRoot opens and checks the actual parent directory before using it as an
// anchor. The identity comparison refuses a directory replaced during the open.
func privateRoot(path string, mask os.FileMode, afterInspect func()) (*os.Root, error) {
	parent := filepath.Dir(path)
	fi, err := os.Lstat(parent)
	if err != nil {
		return nil, privateError("cannot inspect private parent", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, privateError("private parent is a symbolic link", nil)
	}
	if afterInspect != nil {
		afterInspect()
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, privateError("cannot open private parent", err)
	}
	opened, err := root.Stat(".")
	if err == nil && !os.SameFile(fi, opened) {
		err = privateError("private parent changed while opening", nil)
	}
	if err == nil {
		err = privateInfo(opened, true, mask)
	}
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return root, nil
}

// refuseGit checks both .git directories and worktree .git files, and treats
// errors other than absence as refusals. Resolve ancestors before walking them.
func refuseGit(parent string) error {
	dir, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return privateError("cannot resolve private parent", err)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return privateError("cannot resolve private parent", err)
	}
	for {
		_, err = os.Lstat(filepath.Join(dir, ".git"))
		if err == nil {
			return privateError("private output inside a git work tree is refused", nil)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return privateError("cannot inspect git work tree", err)
		}
		next := filepath.Dir(dir)
		if next == dir {
			return nil
		}
		dir = next
	}
}

// WritePrivate publishes a complete private file without replacing an existing path.
// beforePublish, when non-nil, runs after the temporary is closed and before linking.
func WritePrivate(path string, data []byte, beforePublish func() error) error {
	return writePrivate(path, data, beforePublish, privateWriteOps{})
}

type privateWriteOps struct {
	afterParentInspect func()
	remove             func(*os.Root, string) error
	syncDir            func(*os.File) error
	write              func(*os.File, []byte) (int, error)
	sync               func(*os.File) error
	chmod              func(*os.File, os.FileMode) error
	close              func(*os.File) error
}

func (ops privateWriteOps) defaults() privateWriteOps {
	if ops.remove == nil {
		ops.remove = (*os.Root).Remove
	}
	if ops.syncDir == nil {
		ops.syncDir = (*os.File).Sync
	}
	if ops.write == nil {
		ops.write = (*os.File).Write
	}
	if ops.sync == nil {
		ops.sync = (*os.File).Sync
	}
	if ops.chmod == nil {
		ops.chmod = (*os.File).Chmod
	}
	if ops.close == nil {
		ops.close = (*os.File).Close
	}
	return ops
}

func privatePathName(path string) (string, error) {
	_, name := filepath.Split(path)
	if name == "" || name == "." || name == ".." {
		return "", privateError("invalid private file path", nil)
	}
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == ".." {
			return "", privateError("private file path contains a parent component", nil)
		}
	}
	return name, nil
}

func writePrivate(path string, data []byte, beforePublish func() error, ops privateWriteOps) (result error) {
	name, err := privatePathName(path)
	if err != nil {
		return err
	}
	root, err := privateRoot(path, 0o077, ops.afterParentInspect)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			result = errors.Join(result, closeErr)
		}
	}()
	if err = refuseGit(filepath.Dir(path)); err != nil {
		return err
	}
	if err = privateDestinationAbsent(root, name); err != nil {
		return err
	}
	temp, f, err := createPrivateTemp(root)
	if err != nil {
		return err
	}
	ops = ops.defaults()
	defer func() {
		if e := ops.remove(root, temp); e != nil && !errors.Is(e, os.ErrNotExist) {
			result = errors.Join(result, privateError("cannot remove private temporary", e))
		}
	}()
	if err = finishPrivateTemp(f, data, ops); err != nil {
		return err
	}
	if beforePublish != nil {
		if err = beforePublish(); err != nil {
			return err
		}
	}
	return publishPrivate(root, temp, name, ops)
}

func privateDestinationAbsent(root *os.Root, name string) error {
	_, err := root.Lstat(name)
	if err == nil {
		return privateError("private output already exists", nil)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return privateError("cannot inspect private output", err)
	}
	return nil
}

func createPrivateTemp(root *os.Root) (string, *os.File, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", nil, privateError("cannot create private temporary name", err)
	}
	temp := ".tailkeeper-" + hex.EncodeToString(random[:]) + ".tmp"
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", nil, privateError("cannot create private temporary", err)
	}
	return temp, f, nil
}

func finishPrivateTemp(f *os.File, data []byte, ops privateWriteOps) error {
	n, writeErr := ops.write(f, data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = ops.sync(f)
	}
	if writeErr == nil {
		writeErr = ops.chmod(f, 0o600)
	}
	closeErr := ops.close(f)
	if writeErr != nil || closeErr != nil {
		return privateError("cannot finish private temporary", errors.Join(writeErr, closeErr))
	}
	return nil
}

func publishPrivate(root *os.Root, temp, name string, ops privateWriteOps) error {
	if err := root.Link(temp, name); err != nil {
		return privateError("cannot publish private output using a non-overwriting hard link", err)
	}
	if err := ops.remove(root, temp); err != nil {
		return privateError("private output published but temporary removal failed", err)
	}
	dir, err := root.Open(".")
	if err != nil {
		return privateError("private output published but parent cannot be opened for sync", err)
	}
	syncErr := ops.syncDir(dir)
	closeErr := dir.Close()
	if syncErr != nil || closeErr != nil {
		return privateError("private output published but parent sync failed", errors.Join(syncErr, closeErr))
	}
	return nil
}

// ReadPrivate reads at most 16 MiB after checking the opened file and parent.
func ReadPrivate(path string) ([]byte, error) {
	return readPrivate(path, nil)
}

func readPrivate(path string, afterInspect func()) (data []byte, result error) {
	name, err := privatePathName(path)
	if err != nil {
		return nil, err
	}
	root, err := privateRoot(path, 0o022, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			result = errors.Join(result, closeErr)
		}
	}()
	want, err := root.Lstat(name)
	if err != nil {
		return nil, privateError("cannot inspect private file", err)
	}
	if !want.Mode().IsRegular() {
		return nil, privateError("private file is not regular", nil)
	}
	if afterInspect != nil {
		afterInspect()
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, privateError("cannot open private file", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			result = errors.Join(result, closeErr)
		}
	}()
	got, err := f.Stat()
	if err != nil {
		return nil, privateError("cannot inspect opened private file", err)
	}
	if !os.SameFile(want, got) {
		return nil, privateError("private file changed while opening", nil)
	}
	if err = privateInfo(got, false, 0o077); err != nil {
		return nil, err
	}
	data, err = io.ReadAll(io.LimitReader(f, privateCap+1))
	if err != nil {
		return nil, privateError("cannot read private file", err)
	}
	if len(data) > privateCap {
		return nil, privateError(fmt.Sprintf("private file exceeds %d bytes", privateCap), nil)
	}
	return data, nil
}
