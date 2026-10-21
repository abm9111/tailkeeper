package config

import (
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/abm9111/tailkeeper/internal/safefile"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// inspected is what the inspection of a path saw: its Lstat, and the identity of the
// file read at the same moment. On Windows the identity comes from a handle that does
// not follow a reparse point; comparing the Lstat of the path with the open file by
// os.SameFile there reads both identities by path afterwards, so a file put at the
// path in between would be compared with itself.
type inspected struct {
	fi os.FileInfo
	id safefile.Identity
}

// inspect takes the Lstat and the identity of path. The error is the system's own, so
// that a caller can tell a missing file from an unreadable one.
func inspect(path string) (inspected, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return inspected{}, err
	}
	id, err := safefile.Identify(path, fi)
	if err != nil {
		return inspected{}, err
	}
	return inspected{fi: fi, id: id}, nil
}

// inspectPath is inspect, in a variable so that a test can make the inspection of a
// file that is there fail: only Windows can fail it for a real file (a reparse point).
var inspectPath = inspect

// inspectRefused is the refusal of a file that is there and cannot be inspected. The
// message carries the reason, because the wrapped error reaches neither the text nor the
// JSON form; the hint is for the one case a user can fix, a file that sits behind a link
// or a placeholder (on Windows the inspection refuses a reparse point).
func inspectRefused(path string, err error) error {
	why := err.Error()
	var pe *fs.PathError
	if errors.As(err, &pe) {
		why = pe.Err.Error()
	}
	return tkerr.Wrap(tkerr.ConfigUnsafe, err, "cannot inspect "+path+": "+why,
		"if the file is a symbolic link, a junction or a OneDrive Files On-Demand file, it is refused: keep a local copy of it outside the synchronised folder and point tailkeeper at the copy")
}

// readChecked reads path through one open file, and only if that file is the one
// that inspect saw. The check inspects a path; reading by path afterwards would read
// whatever the path names by then. The open refuses a symlink where the system can
// (safefile.OpenNoFollow), the identity refuses another file put in its place, and
// unchanged refuses a regular file with another mode, size, owner, modification time
// or change time than the Lstat recorded: not the identity alone, because a file
// system may give a new file the inode number of one just removed (ext4 does).
func readChecked(path string, want inspected) ([]byte, error) {
	f, err := safefile.OpenNoFollow(path)
	if err != nil {
		return nil, tkerr.Wrap(tkerr.ConfigUnsafe, err, "cannot open "+path+" without following a symlink", "")
	}
	defer func() { _ = f.Close() }() // read only
	got, err := f.Stat()
	if err != nil {
		return nil, tkerr.Wrap(tkerr.ConfigUnsafe, err, "cannot inspect "+path, "")
	}
	same, err := want.id.Is(f, got)
	if err != nil || !same || !unchanged(want.fi, got) {
		return nil, tkerr.New(tkerr.ConfigUnsafe, path+" changed while it was being checked", "run tailkeeper again; if it repeats, find what replaces the file")
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, tkerr.Wrap(tkerr.ConfigInvalid, err, "cannot read "+path, "")
	}
	return data, nil
}

// unchanged reports whether got, the file that was opened, still has the kind, mode,
// size, owner, modification time and change time that want, the earlier Lstat, recorded,
// and is a regular file. The access time is left out on purpose: a read moves it, and a
// read of an unchanged file must pass. The change time is what a process that
// cannot set it cannot forge: it moves with every write, chmod and rename.
func unchanged(want, got os.FileInfo) bool {
	return got.Mode().IsRegular() && want.Mode() == got.Mode() && want.Size() == got.Size() &&
		want.ModTime().Equal(got.ModTime()) && sameChangeTime(want, got) && sameOwner(want, got)
}

// ReadSecretFile is CheckSecretFile and the read in one step: the bytes come from
// the file that was checked. A file that is not there is the system's own error, with
// no code, so that the caller can name what to create and give it the code that fits
// (credential_unavailable, privacy_key_unavailable); a file that is there and cannot
// be inspected is config_unsafe.
func ReadSecretFile(path string) ([]byte, error) {
	want, err := inspectPath(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, inspectRefused(path, err)
	}
	if err := CheckSecretFile(path); err != nil {
		return nil, err
	}
	return readChecked(path, want)
}
