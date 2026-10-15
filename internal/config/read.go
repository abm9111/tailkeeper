package config

import (
	"io"
	"os"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// readChecked reads path through one open file, and only if that file is the one
// described by want, the Lstat taken just before the check. The check inspects a
// path; reading by path afterwards would read whatever the path names by then. The
// open refuses a symlink (O_NOFOLLOW), and the comparison refuses another file put
// in its place: not the same device and inode only, because a file system may give
// a new file the inode number of one just removed (ext4 does), but also a regular
// file with the mode, size, modification time and change time of the Lstat.
func readChecked(path string, want os.FileInfo) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|openFlags, 0)
	if err != nil {
		return nil, tkerr.Wrap(tkerr.ConfigUnsafe, err, "cannot open "+path+" without following a symlink", "")
	}
	defer func() { _ = f.Close() }() // read only
	got, err := f.Stat()
	if err != nil {
		return nil, tkerr.Wrap(tkerr.ConfigUnsafe, err, "cannot inspect "+path, "")
	}
	if !os.SameFile(want, got) || !unchanged(want, got) {
		return nil, tkerr.New(tkerr.ConfigUnsafe, path+" changed while it was being checked", "run tailkeeper again; if it repeats, find what replaces the file")
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, tkerr.Wrap(tkerr.ConfigInvalid, err, "cannot read "+path, "")
	}
	return data, nil
}

// unchanged reports whether got, the file that was opened, still has the kind, mode,
// size, modification time and change time that want, the earlier Lstat, recorded, and
// is a regular file. The access time is left out on purpose: a read moves it, and a
// read of an unchanged file must pass. The change time is what a process that
// cannot set it cannot forge: it moves with every write, chmod and rename.
func unchanged(want, got os.FileInfo) bool {
	return got.Mode().IsRegular() && want.Mode() == got.Mode() && want.Size() == got.Size() &&
		want.ModTime().Equal(got.ModTime()) && sameChangeTime(want, got)
}

// ReadSecretFile is CheckSecretFile and the read in one step: the bytes come from
// the file that was checked.
func ReadSecretFile(path string) ([]byte, error) {
	want, err := os.Lstat(path)
	if err != nil {
		return nil, tkerr.Wrap(tkerr.ConfigUnsafe, err, "cannot inspect "+path, "")
	}
	if err := CheckSecretFile(path); err != nil {
		return nil, err
	}
	return readChecked(path, want)
}
