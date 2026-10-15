// Package audit is tailkeeper's append-only, hash-chained JSONL log (spec §14).
//
// Each line carries seq (1, 2, ...), prev (the previous line's hash, "" for the
// first) and hash ("sha256:" + hex of the canonical JSON of the line without its
// hash field). A plain SHA-256 chain detects damage and naive edits; it does not
// stop someone who can rewrite the file and recompute the chain, and it cannot
// tell when lines were removed from the end. Exports anchor both (spec §14).
//
// Rotate starts a new log and keeps the old one beside it as an archive; the new
// log's first entry records where the archive ends, and Verify checks it.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tripwire"
)

// FileName is the audit log's name inside the logs directory.
const FileName = "audit.jsonl"

// Version is the line format version.
const Version = 2

// MaxLine is the largest line Append writes. Append reads the previous line from
// the last 64 KiB of the file, so every line must fit well inside that.
const MaxLine = 32 << 10

// reserved field names that callers may not set.
var reserved = map[string]bool{"v": true, "seq": true, "ts": true, "prev": true, "event": true, "hash": true}

// defaultLockWait bounds how long Append waits for the lock.
const defaultLockWait = 2 * time.Second

// errLockTimeout means the lock stayed held for the whole wait: by another process
// where the platform has a file lock, and on Windows, where the lock is in memory,
// possibly by another call of this process.
var errLockTimeout = errors.New("the lock stayed held")

// lockFile and unlockFile are the platform's lock, as variables so a test can
// stand in for a platform without one.
var (
	lockFile   = lock
	unlockFile = unlock
)

// Log appends to one audit file. It is safe for concurrent use by several
// processes: appends take an exclusive file lock. Windows has no file lock yet:
// there the appends of one process exclude each other, and two processes can
// still fork the chain.
type Log struct {
	path     string
	now      func() time.Time
	lockWait atomic.Int64 // nanoseconds; 0: defaultLockWait

	// Seams for tests: opened runs after openLocked opens the log, before it locks;
	// rename replaces os.Rename in Rotate.
	opened func()
	rename func(oldpath, newpath string) error
}

// Open creates the directory (0700) and file (0600) if needed.
func Open(path string, now func() time.Time) (*Log, error) {
	if now == nil {
		now = time.Now
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, unavailable(err, "cannot create "+dir)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, unavailable(err, "cannot open "+path)
	}
	_ = f.Close()
	// MkdirAll and OpenFile set modes only on creation; an existing path keeps
	// whatever it had, so tighten both.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, unavailable(err, "cannot restrict "+dir+" to mode 0700")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, unavailable(err, "cannot restrict "+path+" to mode 0600")
	}
	return &Log{path: path, now: now}, nil
}

// Path is the log file path.
func (l *Log) Path() string { return l.path }

// SetLockWait sets how long Append waits for a lock someone else holds; 0
// restores the default of 2 seconds.
func (l *Log) SetLockWait(d time.Duration) { l.lockWait.Store(int64(d)) }

// wait is the lock wait Append uses.
func (l *Log) wait() time.Duration {
	if d := time.Duration(l.lockWait.Load()); d != 0 {
		return d
	}
	return defaultLockWait
}

// Append writes one event. fields must be JSON-marshalable and must not use the
// reserved names v, seq, ts, prev, event or hash.
func (l *Log) Append(event string, fields map[string]any) (err error) {
	for k := range fields {
		if reserved[k] {
			return tkerr.New(tkerr.Internal, "audit field name "+k+" is reserved", "")
		}
	}
	f, err := l.openLocked()
	if err != nil {
		return err
	}
	// The log was written through f: a Close that fails is returned, unless an
	// earlier error is. Closing drops the lock as well, so a failed unlock changes
	// nothing and is not reported.
	defer func() {
		_ = unlockFile(f)
		if cerr := f.Close(); cerr != nil && err == nil {
			err = unavailable(cerr, "the entry was written and synced, but closing "+l.path+" failed")
		}
	}()
	seq, prev, size, err := lastLine(f)
	if err != nil {
		return err
	}
	line, err := l.encodeLine(seq+1, prev, event, fields)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		// Never leave half a line behind: the next Append would refuse the log.
		_ = f.Truncate(size)
		return unavailable(err, "cannot write "+l.path)
	}
	if err := f.Sync(); err != nil {
		return unavailable(err, "cannot sync "+l.path)
	}
	return nil
}

// encodeLine builds the line for one entry, hashed exactly as Verify will rebuild
// it: decoded with UseNumber into plain maps, so struct field order or a custom
// marshaller cannot make an untouched line fail verification.
func (l *Log) encodeLine(seq uint64, prev, event string, fields map[string]any) ([]byte, error) {
	entry := map[string]any{}
	for k, v := range fields {
		entry[k] = v
	}
	entry["v"] = Version
	entry["seq"] = seq
	entry["ts"] = l.now().UTC().Format(time.RFC3339Nano)
	entry["prev"] = prev
	entry["event"] = event
	canon, err := canonical(entry)
	if err != nil {
		return nil, err
	}
	sum, err := hashOf(canon)
	if err != nil {
		return nil, err
	}
	canon["hash"] = sum
	line, err := json.Marshal(canon)
	if err != nil {
		return nil, tkerr.Wrap(tkerr.Internal, err, "cannot encode audit entry", "")
	}
	if len(line)+1 > MaxLine {
		return nil, tkerr.New(tkerr.Internal, fmt.Sprintf("an audit entry of %d bytes exceeds the %d-byte line limit", len(line)+1, MaxLine),
			"audit entries hold metadata only; this is a tailkeeper bug")
	}
	if err := tripwire.Check(line); err != nil {
		return nil, err
	}
	return line, nil
}

// openLocked opens the log and takes its lock. A rotation replaces the file at
// the path while an appender may hold the old one open, waiting for its lock; that
// handle would write to the archive. So a handle that is no longer the file at the
// path once locked is dropped, and the path opened again, within the same wait.
func (l *Log) openLocked() (*os.File, error) {
	// A stuck holder must not block every audited call forever: give up after the
	// wait. Reads then continue unaudited and warn; a write is refused.
	wait := l.wait()
	deadline := time.Now().Add(wait)
	for range 3 {
		f, err := os.OpenFile(l.path, os.O_RDWR|os.O_APPEND, 0o600)
		if err != nil {
			return nil, unavailable(err, "cannot open "+l.path)
		}
		if l.opened != nil {
			l.opened()
		}
		if err := lockFile(f, time.Until(deadline)); errors.Is(err, errLockTimeout) {
			_ = f.Close() // nothing was written through f
			return nil, tkerr.New(tkerr.AuditUnavailable, fmt.Sprintf("the audit log stayed locked for %s", wait),
				"look for a stuck tailkeeper process holding "+l.path)
		} else if err != nil {
			_ = f.Close() // nothing was written through f
			return nil, unavailable(err, "cannot lock "+l.path)
		}
		if current(f, l.path) {
			return f, nil
		}
		_ = unlockFile(f)
		_ = f.Close() // nothing was written through f
	}
	return nil, tkerr.New(tkerr.AuditUnavailable, "the audit log was rotated three times while tailkeeper waited for its lock",
		"retry; rotations are not normally that frequent")
}

// current reports whether f is still the file at path.
func current(f *os.File, path string) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	pi, err := os.Stat(path)
	return err == nil && os.SameFile(fi, pi)
}

// canonical round-trips entry through JSON, as Verify sees it.
func canonical(entry map[string]any) (map[string]any, error) {
	b, err := json.Marshal(entry)
	if err != nil {
		return nil, tkerr.Wrap(tkerr.Internal, err, "cannot encode audit entry", "")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, tkerr.Wrap(tkerr.Internal, err, "cannot encode audit entry", "")
	}
	return out, nil
}

// hashOf hashes the canonical JSON (sorted keys, as encoding/json writes maps) of
// entry without its "hash" field.
func hashOf(entry map[string]any) (string, error) {
	clean := make(map[string]any, len(entry))
	for k, v := range entry {
		if k != "hash" {
			clean[k] = v
		}
	}
	b, err := json.Marshal(clean)
	if err != nil {
		return "", tkerr.Wrap(tkerr.Internal, err, "cannot encode audit entry", "")
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// lastLine returns the seq and hash of the final line (0, "" for an empty file)
// and the file's size.
func lastLine(f *os.File) (uint64, string, int64, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, "", 0, unavailable(err, "cannot stat audit log")
	}
	size := st.Size()
	if size == 0 {
		return 0, "", 0, nil
	}
	const chunk = 64 << 10
	start := max(size-chunk, 0)
	buf := make([]byte, size-start)
	if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
		return 0, "", 0, unavailable(err, "cannot read audit log")
	}
	if buf[len(buf)-1] != '\n' {
		return 0, "", 0, tkerr.New(tkerr.AuditUnavailable, "the audit log does not end with a newline: it was truncated or edited",
			"run `tailkeeper audit verify`; do not delete the log")
	}
	buf = bytes.TrimRight(buf, "\n")
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		buf = buf[i+1:]
	}
	var last struct {
		Seq  uint64 `json:"seq"`
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(buf, &last); err != nil || last.Hash == "" {
		return 0, "", 0, tkerr.New(tkerr.AuditUnavailable, "the last audit line is unreadable",
			"run `tailkeeper audit verify`; do not delete the log")
	}
	return last.Seq, last.Hash, size, nil
}

// Verify checks the whole chain and returns the number of valid lines. The error
// names the first broken line. A log that starts with a rotation must continue
// the archive it names, when that archive is present; VerifyHistory also checks
// the archives' own chains.
func Verify(path string) (int, error) {
	st, err := verifyFile(path)
	return st.lines, err
}

// chainState is how far a verification got: the lines checked, the last one's
// hash, the bytes they take, and the archive a leading "rotated" entry names.
type chainState struct {
	lines int
	hash  string
	size  int64
	from  string
}

func verifyFile(path string) (chainState, error) {
	f, err := os.Open(path)
	if err != nil {
		return chainState{}, unavailable(err, "cannot open "+path)
	}
	defer func() { _ = f.Close() }() // read only
	return verifyLines(f, path, chainState{}, true)
}

// maxVerifiedLine bounds one line Verify reads; Append writes at most MaxLine.
const maxVerifiedLine = 4 << 20

// verifyLines checks the lines r holds, continuing from st, and returns how far
// they verified, counting the bytes as they are on disk (a CRLF line too). path
// names the file, whose directory holds its archives. A last line with no newline
// is a break when complete is set; otherwise it is left alone: read without the
// lock, it can be an append still being written.
func verifyLines(r io.Reader, path string, st chainState, complete bool) (chainState, error) {
	br := bufio.NewReaderSize(r, maxVerifiedLine)
	for {
		raw, rerr := br.ReadSlice('\n')
		switch {
		case errors.Is(rerr, bufio.ErrBufferFull):
			return st, broken(st.lines+1, "is longer than 4 MiB")
		case rerr != nil && rerr != io.EOF:
			return st, unavailable(rerr, "cannot read "+path)
		case len(raw) == 0, rerr == io.EOF && !complete:
			return st, nil
		case rerr == io.EOF:
			// Append and Rotate refuse such a log, so Verify must not pass it.
			return st, broken(st.lines+1, "has no newline at its end: the log was cut short or edited")
		}
		n := st.lines + 1
		line := bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte("\n")), []byte("\r"))
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		var entry map[string]any
		if err := dec.Decode(&entry); err != nil {
			return st, broken(n, "is not JSON")
		}
		if _, err := dec.Token(); err != io.EOF {
			return st, broken(n, "has data after its entry")
		}
		seq, _ := entry["seq"].(json.Number)
		if seq.String() != fmt.Sprint(n) {
			return st, broken(n, fmt.Sprintf("has seq %v, want %d (a line was removed or inserted)", entry["seq"], n))
		}
		if p, _ := entry["prev"].(string); p != st.hash {
			return st, broken(n, "does not chain to the previous line")
		}
		want, err := hashOf(entry)
		if err != nil {
			return st, err
		}
		got, _ := entry["hash"].(string)
		if got != want {
			return st, broken(n, "hash does not match its content (the line was modified)")
		}
		if n == 1 && entry["event"] == "rotated" {
			if st.from, err = continues(filepath.Dir(path), entry); err != nil {
				return st, err
			}
		}
		st.lines, st.hash, st.size = n, got, st.size+int64(len(raw))
		if rerr == io.EOF {
			return st, nil
		}
	}
}

// Tail returns up to n of the most recent entries, oldest first.
func Tail(path string, n int) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, unavailable(err, "cannot open "+path)
	}
	defer func() { _ = f.Close() }() // read only
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	var ring []map[string]any
	line := 0
	for sc.Scan() {
		line++
		var entry map[string]any
		if err := json.Unmarshal(sc.Bytes(), &entry); err != nil {
			// Shown, not skipped: a damaged line is exactly what a reader must see.
			entry = map[string]any{"line": line, "unreadable": "the line is not JSON; run `tailkeeper audit verify`"}
		}
		ring = append(ring, entry)
		if len(ring) > n {
			ring = ring[1:]
		}
	}
	return ring, sc.Err()
}

func broken(line int, what string) error {
	return tkerr.New(tkerr.AuditUnavailable, fmt.Sprintf("audit log line %d %s", line, what),
		"keep the file for investigation and do not repair it by hand; to go on, move it aside while no tailkeeper process runs, and the next run starts a new log")
}

func unavailable(err error, msg string) error {
	return tkerr.Wrap(tkerr.AuditUnavailable, err, msg, "check disk space and permissions of the logs directory")
}
