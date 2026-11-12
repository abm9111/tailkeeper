package config

import (
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/abm9111/tailkeeper/internal/safefile"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// nameProblem is safefile.NameProblem, in a variable so that a test can have a name refused
// on a platform that refuses none.
var nameProblem = safefile.NameProblem

// refuseName is the refusal of a path whose name Windows reads as a network share, a device
// namespace, a device or an alternate data stream: the refusal a policy file gets from
// safefile, applied to every file this package reads, before the file is touched. A UNC path
// would reach out to another machine, and a device name opens a device, not a file. Off
// Windows no name is refused.
func refuseName(path string) error {
	if why := nameProblem(path); why != "" {
		return tkerr.New(tkerr.ConfigUnsafe, path+": "+why, "name a regular local file")
	}
	return nil
}

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

// reasonOf is the system's own reason in err, without the operation and path that a
// *fs.PathError repeats, for a message that carries it because the wrapped error reaches
// neither the text nor the JSON form.
func reasonOf(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// inspectRefused is the refusal of a file that is there and cannot be inspected. The
// message carries the reason, because the wrapped error reaches neither the text nor the
// JSON form; the hint is for the one case a user can fix, a file that sits behind a link
// or a placeholder (on Windows the inspection refuses a reparse point).
func inspectRefused(path string, err error) error {
	return tkerr.Wrap(tkerr.ConfigUnsafe, err, "cannot inspect "+path+": "+reasonOf(err),
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
	return readCheckedLimit(path, want, 0)
}

// Test hooks of readCheckedLimit. Both are nil outside tests. A test that must change the
// file while it is read changes it at one of these two fixed points, so that the change
// happens every time and is not raced for.
var (
	// beforeSecretRead runs once the open file has passed every check and before its
	// first byte is read.
	beforeSecretRead func(f *os.File)
	// afterSecretRead runs after the last byte is read and before the second Stat.
	afterSecretRead func(f *os.File)
)

// changedWhileChecked is the refusal of an open file that is not the one that was
// inspected. cause is why its identity could not be read (on Windows, a handle that
// fails or a reparse point), or nil when the identity was read and differs. The refusal
// keeps the cause, so that errors.Is and errors.As find it, and says it in the message,
// because the wrapped error reaches neither the text nor the JSON form.
func changedWhileChecked(path string, cause error) error {
	const hint = "run tailkeeper again; if it repeats, find what replaces the file"
	if cause == nil {
		return tkerr.New(tkerr.ConfigUnsafe, path+" changed while it was being checked", hint)
	}
	return tkerr.Wrap(tkerr.ConfigUnsafe, cause, path+" changed while it was being checked: "+reasonOf(cause), hint)
}

// readCheckedLimit bounds secret material without changing general config sizes.
func readCheckedLimit(path string, want inspected, limit int64) ([]byte, error) {
	if err := refuseName(path); err != nil {
		return nil, err
	}
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
		return nil, changedWhileChecked(path, err)
	}
	if err := checkSecretSize(path, got, limit); err != nil {
		return nil, err
	}
	data, err := readLimited(path, f, limit)
	if err != nil {
		return nil, err
	}
	if err := checkUnchangedAfterRead(path, f, got); err != nil {
		return nil, err
	}
	return data, nil
}

// checkSecretSize refuses a file whose mode or size a bounded secret read does not accept.
// With no limit (0 or less) nothing is checked.
func checkSecretSize(path string, got os.FileInfo, limit int64) error {
	if limit <= 0 {
		return nil
	}
	if err := checkSecretFileInfo(path, got); err != nil {
		return err
	}
	if got.Size() > limit {
		return tkerr.New(tkerr.ConfigUnsafe, "secret file exceeds 1 MiB", "use a smaller private credential file")
	}
	return nil
}

// readLimited reads the open file f, a byte past the limit at most, and refuses what it
// reads if that is more than the limit. beforeSecretRead runs first, once the file has
// passed every check.
func readLimited(path string, f *os.File, limit int64) ([]byte, error) {
	if beforeSecretRead != nil {
		beforeSecretRead(f)
	}
	var reader io.Reader = f
	if limit > 0 {
		reader = io.LimitReader(f, limit+1)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, tkerr.Wrap(tkerr.ConfigInvalid, err, "cannot read "+path, "")
	}
	if limit > 0 && int64(len(data)) > limit {
		return nil, tkerr.New(tkerr.ConfigUnsafe, "secret file exceeds 1 MiB", "use a smaller private credential file")
	}
	return data, nil
}

// checkUnchangedAfterRead asks f for its state again once it is read, and refuses it if
// that is not the state got, taken before the read, recorded. afterSecretRead runs first.
func checkUnchangedAfterRead(path string, f *os.File, got os.FileInfo) error {
	if afterSecretRead != nil {
		afterSecretRead(f)
	}
	const hint = "run tailkeeper again; if it repeats, find what modifies the file"
	after, err := f.Stat()
	if err != nil {
		// Nothing says the file changed: it could not be asked again. The refusal keeps the
		// cause, as the other refusals of this function do.
		return tkerr.Wrap(tkerr.ConfigUnsafe, err, "cannot inspect "+path+" after reading it: "+reasonOf(err), hint)
	}
	if !unchanged(got, after) {
		return tkerr.New(tkerr.ConfigUnsafe, "file changed while it was being read", hint)
	}
	return nil
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
	if err := refuseName(path); err != nil {
		return nil, err
	}
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
	return readCheckedLimit(path, want, 1<<20)
}
