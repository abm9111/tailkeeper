package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// RotateSupported reports whether Rotate works here: it needs the file lock,
// which Windows does not have yet.
func RotateSupported() bool { return canRotate }

// archivePrefix starts the name of every archive Rotate makes.
const archivePrefix = "audit-"

// tempPrefix names the new log while Rotate writes it. A file left by a crash is
// removed by the next rotation: every Rotate holds the lock, so none is running.
const tempPrefix = ".audit-rotate-"

// Rotate starts a new log and keeps the old one beside it as an archive named
// audit-<UTC time>.jsonl, which it returns. The new log's first entry, event
// "rotated", names the archive and its last seq and hash: Verify checks that a
// present archive still ends there, and VerifyHistory also checks its chain.
//
// Rotate refuses a log that fails verification, so a rotation never hides damage,
// and a symbolic link, which the rename would replace with a file. The log path
// never goes missing: the archive is a hard link made first, and the new log
// replaces the path in one rename. Archives are kept until the owner deletes them.
func (l *Log) Rotate() (string, error) {
	if !canRotate {
		return "", tkerr.New(tkerr.ValidationFailed, "audit rotate is not available on Windows yet: the log has no file lock there",
			"stop every tailkeeper process, then move the log aside; the next run starts a new one")
	}
	if fi, err := os.Lstat(l.path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return "", tkerr.New(tkerr.ValidationFailed, l.path+" is a symbolic link, which a rotation would replace with a file",
			"rotate the file it points to by hand, or replace the link with that file")
	}
	// Verify the bulk without the lock, so appenders are not held up; under it,
	// only what was appended meanwhile, or the whole log if another rotation
	// replaced it meanwhile.
	st, verified, err := verifyUnlocked(l.path)
	if err != nil {
		return "", notRotated(err)
	}
	f, err := l.openLocked()
	if err != nil {
		return "", err
	}
	// Rotate only reads through f: the new log is written through its own handle,
	// whose Close error replace returns. Closing f drops the lock as well.
	defer func() { _ = unlockFile(f); _ = f.Close() }()
	seq, hash, size, err := lastLine(f)
	if err != nil {
		return "", notRotated(err)
	}
	if fi, err := f.Stat(); err != nil || !os.SameFile(fi, verified) {
		st = chainState{}
	} else if size < st.size {
		return "", notRotated(tkerr.New(tkerr.AuditUnavailable, "the audit log shrank while it was being verified", "run `tailkeeper audit verify`"))
	}
	if size > st.size {
		if _, err := verifyLines(io.NewSectionReader(f, st.size, size-st.size), l.path, st, true); err != nil {
			return "", notRotated(err)
		}
	}
	if seq == 0 {
		return "", tkerr.New(tkerr.ValidationFailed, "the audit log is empty: there is nothing to rotate", "")
	}
	dir := filepath.Dir(l.path)
	sweepTemps(dir)
	archive, err := l.link(dir)
	if err != nil {
		return "", err
	}
	syncDir(dir) // the archive's name is on disk before the log path moves
	if err := l.replace(dir, seq, hash, archive); err != nil {
		if rerr := os.Remove(archive); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			e := tkerr.From(err)
			return "", tkerr.New(e.Code, e.Message+"; and "+archive+", a second name for the unchanged log, could not be removed: "+rerr.Error(),
				"remove "+archive+" by hand")
		}
		return "", err
	}
	syncDir(dir)
	return archive, nil
}

// verifyUnlocked verifies the log at path, without the lock and up to its last
// complete line, and returns how far it got and which file it read.
func verifyUnlocked(path string) (chainState, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return chainState{}, nil, unavailable(err, "cannot open "+path)
	}
	defer func() { _ = f.Close() }() // read only
	fi, err := f.Stat()
	if err != nil {
		return chainState{}, nil, unavailable(err, "cannot stat "+path)
	}
	st, err := verifyLines(f, path, chainState{}, false)
	return st, fi, err
}

// link gives the log a second name, the archive's, and returns it.
func (l *Log) link(dir string) (string, error) {
	stamp := archivePrefix + l.now().UTC().Format("20060102T150405Z")
	for i := 0; i < 100; i++ {
		name := stamp
		if i > 0 {
			name = fmt.Sprintf("%s-%d", stamp, i)
		}
		p := filepath.Join(dir, name+".jsonl")
		err := os.Link(l.path, p)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", unavailable(err, "cannot create the archive "+p)
		}
	}
	return "", tkerr.New(tkerr.AuditUnavailable, "100 archives already carry this second's name", "wait a second and retry")
}

// replace writes the new log, whose first entry continues the archive, and puts
// it at the log path in one rename.
func (l *Log) replace(dir string, seq uint64, hash, archive string) error {
	line, err := l.encodeLine(1, "", "rotated", map[string]any{"from": filepath.Base(archive), "fromSeq": seq, "fromHash": hash})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, tempPrefix+"*")
	if err != nil {
		return unavailable(err, "cannot create a new audit log in "+dir)
	}
	_, err = tmp.Write(append(line, '\n'))
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		rename := l.rename
		if rename == nil {
			rename = os.Rename
		}
		err = rename(tmp.Name(), l.path)
	}
	if err != nil {
		msg := "cannot replace " + l.path
		if rerr := os.Remove(tmp.Name()); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			msg += "; and the unused new log " + tmp.Name() + " could not be removed: " + rerr.Error()
		}
		return unavailable(err, msg)
	}
	return nil
}

func sweepTemps(dir string) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tempPrefix) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// syncDir makes the directory's entries durable, on a best-effort basis: an
// error here leaves nothing to undo.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// notRotated says that a rotation was refused, and why.
func notRotated(err error) error {
	e := tkerr.From(err)
	if e == nil {
		return err
	}
	return tkerr.New(e.Code, "not rotated: "+e.Message, e.Hint)
}

// continues checks that the archive a "rotated" entry names still ends at the seq
// and hash the entry recorded, and returns the archive's name. An archive the
// owner deleted cannot be checked here, and is not an error; VerifyHistory says
// so.
func continues(dir string, entry map[string]any) (string, error) {
	name, _ := entry["from"].(string)
	if !strings.HasPrefix(name, archivePrefix) || filepath.Base(name) != name {
		return "", broken(1, "is a rotation that names no archive it continues")
	}
	f, err := os.Open(filepath.Join(dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return name, nil
	}
	if err != nil {
		return "", unavailable(err, "cannot open the archive "+name)
	}
	defer func() { _ = f.Close() }() // read only
	seq, hash, _, err := lastLine(f)
	if err != nil {
		return "", inArchive(name, err)
	}
	if fromSeq, _ := entry["fromSeq"].(json.Number); fromSeq.String() != fmt.Sprint(seq) || entry["fromHash"] != hash {
		return "", broken(1, "does not continue "+name+": the archive no longer ends where the log was rotated")
	}
	return name, nil
}

// inArchive names the archive an error is about. An error that already names
// one, deeper in the history, is left as it is.
func inArchive(name string, err error) error {
	e := tkerr.From(err)
	if e == nil || strings.HasPrefix(e.Message, "archive ") {
		return err
	}
	hint := e.Hint
	if strings.Contains(hint, "audit verify") {
		hint = "keep the archive for investigation; do not repair it by hand" // verify is what reported it
	}
	return tkerr.New(e.Code, "archive "+name+": "+e.Message, hint)
}

// Segment is one file of a log's history.
type Segment struct {
	Path    string
	Lines   int  // valid lines
	Missing bool // named by the newer file's rotation but not present, so not checked
}

// VerifyHistory verifies the log and then, through the rotation each file starts
// with, every archive before it that is still present, newest first. A missing
// archive ends the history, and its Segment says so.
func VerifyHistory(path string) ([]Segment, error) {
	var out []Segment
	seen := map[string]bool{}
	for p := path; ; {
		st, err := verifyFile(p)
		if err != nil {
			if p != path {
				err = inArchive(filepath.Base(p), err)
			}
			return out, err
		}
		out = append(out, Segment{Path: p, Lines: st.lines})
		seen[p] = true
		if st.from == "" {
			return out, nil
		}
		next := filepath.Join(filepath.Dir(p), st.from)
		if seen[next] {
			return out, tkerr.New(tkerr.AuditUnavailable, "the archives' rotations form a loop at "+st.from, "keep the files for investigation")
		}
		if _, err := os.Stat(next); errors.Is(err, fs.ErrNotExist) { // a dangling link too, as Verify sees it
			return append(out, Segment{Path: next, Missing: true}), nil
		}
		p = next
	}
}
