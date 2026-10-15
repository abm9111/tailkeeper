//go:build !windows

package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func appendN(t *testing.T, l *Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := l.Append("read", map[string]any{"tool": "devices_list", "bytes": i}); err != nil {
			t.Fatal(err)
		}
	}
}

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

func TestRotateKeepsTheArchiveAndContinuesTheChain(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 3)
	before, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	last := readLines(t, l.Path())[2]
	archive, err := l.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(archive) != filepath.Dir(l.Path()) || filepath.Base(archive) != "audit-20261010T090000Z.jsonl" {
		t.Errorf("archive = %s", archive)
	}
	if got, _ := os.ReadFile(archive); string(got) != string(before) {
		t.Errorf("the archive differs from the rotated log")
	}
	if n, err := Verify(archive); err != nil || n != 3 {
		t.Errorf("Verify(archive) = %d, %v", n, err)
	}
	first := readLines(t, l.Path())
	if len(first) != 1 || first[0]["event"] != "rotated" || first[0]["seq"].(float64) != 1 || first[0]["prev"] != "" ||
		first[0]["from"] != filepath.Base(archive) || first[0]["fromSeq"].(float64) != 3 || first[0]["fromHash"] != last["hash"] {
		t.Fatalf("new log = %v", first)
	}
	appendN(t, l, 2)
	if n, err := Verify(l.Path()); err != nil || n != 3 {
		t.Errorf("Verify(new log) = %d, %v", n, err)
	}
	for _, p := range []string{l.Path(), archive} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v, %v; want 0600", p, fi.Mode().Perm(), err)
		}
	}
	// A second rotation in the same second gets its own name.
	if again, err := l.Rotate(); err != nil || filepath.Base(again) != "audit-20261010T090000Z-1.jsonl" {
		t.Errorf("second Rotate = %s, %v", again, err)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(l.Path()), ".audit-rotate-*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestVerifyChecksTheArchiveARotatedLogContinues(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 2)
	archive, err := l.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	// An archive that gained a line no longer ends where the log was rotated.
	extra := &Log{path: archive, now: fixedNow}
	if err := extra.Append("read", map[string]any{"tool": "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(l.Path()); err == nil || !strings.Contains(err.Error(), "does not continue "+filepath.Base(archive)) {
		t.Errorf("Verify with a changed archive = %v, want a continuity error", err)
	}
	// A deleted archive cannot be checked; that is the owner's retention, not damage.
	if err := os.Remove(archive); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(l.Path()); err != nil || n != 1 {
		t.Errorf("Verify without the archive = %d, %v", n, err)
	}
}

func TestVerifyRefusesARotatedEntryNamingNoArchive(t *testing.T) {
	for _, from := range []any{"", "../audit-20261010T090000Z.jsonl", "audit.jsonl", 7} {
		dir := t.TempDir()
		l, err := Open(filepath.Join(dir, FileName), fixedNow)
		if err != nil {
			t.Fatal(err)
		}
		line, err := l.encodeLine(1, "", "rotated", map[string]any{"from": from, "fromSeq": 1, "fromHash": "sha256:x"})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(l.Path(), append(line, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(l.Path()); err == nil || !strings.Contains(err.Error(), "names no archive") {
			t.Errorf("from %v: Verify = %v", from, err)
		}
	}
}

func TestRotateRefusesAnEmptyOrDamagedLog(t *testing.T) {
	l := openLog(t)
	if _, err := l.Rotate(); tkerr.From(err).Code != tkerr.ValidationFailed {
		t.Errorf("empty log: err = %v, want validation_failed", err)
	}
	appendN(t, l, 1)
	if err := os.WriteFile(l.Path(), []byte(`{"seq":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Rotate(); tkerr.From(err).Code != tkerr.AuditUnavailable {
		t.Errorf("damaged log: err = %v, want audit_unavailable", err)
	}
	if archives, _ := filepath.Glob(filepath.Join(filepath.Dir(l.Path()), "audit-*")); len(archives) != 0 {
		t.Errorf("a refused rotation left archives: %v", archives)
	}
}

func TestMissingLogIsUnavailable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), FileName)
	if _, err := Verify(missing); tkerr.From(err).Code != tkerr.AuditUnavailable {
		t.Errorf("Verify = %v", err)
	}
	if _, err := Tail(missing, 5); tkerr.From(err).Code != tkerr.AuditUnavailable {
		t.Errorf("Tail = %v", err)
	}
	l := &Log{path: missing, now: fixedNow}
	if err := l.Append("read", nil); tkerr.From(err).Code != tkerr.AuditUnavailable {
		t.Errorf("Append = %v", err)
	}
	if _, err := l.Rotate(); tkerr.From(err).Code != tkerr.AuditUnavailable {
		t.Errorf("Rotate = %v", err)
	}
	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(notDir, FileName), fixedNow); tkerr.From(err).Code != tkerr.AuditUnavailable {
		t.Errorf("Open under a file = %v", err)
	}
}

// damage rewrites line n's tool field, leaving its hash: the chain breaks there.
func damage(t *testing.T, path string, n int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	lines[n-1] = strings.Replace(lines[n-1], `"tool":"devices_list"`, `"tool":"devices_lisT"`, 1)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A rotation must never hide damage: a log that fails verification is refused,
// and no archive is made.
func TestRotateRefusesALogThatFailsVerification(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 4)
	damage(t, l.Path(), 2)
	if _, err := l.Rotate(); err == nil || !strings.Contains(err.Error(), "not rotated: audit log line 2 hash does not match") {
		t.Errorf("Rotate of a damaged log = %v", err)
	}
	if archives, _ := filepath.Glob(filepath.Join(filepath.Dir(l.Path()), "audit-*")); len(archives) != 0 {
		t.Errorf("archives = %v", archives)
	}
}

func TestVerifyHistoryFollowsEveryArchive(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 3)
	first, err := l.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 2)
	second, err := l.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 1)
	segs, err := VerifyHistory(l.Path())
	if err != nil || len(segs) != 3 || segs[0].Lines != 2 || segs[1].Path != second || segs[1].Lines != 3 || segs[2].Path != first || segs[2].Lines != 3 {
		t.Fatalf("VerifyHistory = %+v, %v", segs, err)
	}
	// Damage inside the oldest archive: Verify of the live log cannot see it, the
	// history does, and names the archive.
	damage(t, first, 2)
	if _, err := Verify(l.Path()); err != nil {
		t.Errorf("Verify of the live log = %v", err)
	}
	if _, err := VerifyHistory(l.Path()); err == nil || !strings.Contains(err.Error(), "archive "+filepath.Base(first)+": audit log line 2") {
		t.Errorf("VerifyHistory with a damaged archive = %v", err)
	}
	// A deleted archive ends the history, and says it was not checked.
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	segs, err = VerifyHistory(l.Path())
	if err != nil || len(segs) != 3 || !segs[2].Missing || segs[2].Path != first {
		t.Errorf("VerifyHistory without the oldest archive = %+v, %v", segs, err)
	}
}

// The archive's last line replaced by a valid line with the same seq: its own
// chain verifies, but the log no longer continues it.
func TestVerifyCatchesAReplacedLastArchiveLine(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 3)
	archive, err := l.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, archive)
	b, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	kept := strings.SplitAfterN(string(b), "\n", 3)
	other := &Log{path: archive, now: fixedNow}
	line, err := other.encodeLine(3, lines[1]["hash"].(string), "read", map[string]any{"tool": "something_else"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, []byte(kept[0]+kept[1]+string(line)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(archive); err != nil || n != 3 {
		t.Fatalf("the rewritten archive must verify on its own: %d, %v", n, err)
	}
	if _, err := Verify(l.Path()); err == nil || !strings.Contains(err.Error(), "does not continue") {
		t.Errorf("Verify = %v, want a continuity error", err)
	}
}

// A rename that fails after the archive was linked leaves the log as it was,
// with no archive and no temporary file.
func TestRotateFailureAfterTheLinkChangesNothing(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 2)
	before, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	l.rename = func(string, string) error { return errors.New("rename refused") }
	if _, err := l.Rotate(); err == nil || !strings.Contains(err.Error(), "cannot replace") {
		t.Fatalf("Rotate = %v", err)
	}
	if after, _ := os.ReadFile(l.Path()); string(after) != string(before) {
		t.Error("the log changed")
	}
	if entries, _ := os.ReadDir(filepath.Dir(l.Path())); len(entries) != 1 {
		t.Errorf("directory holds %d entries, want the log alone", len(entries))
	}
}

func TestRotateSweepsStaleTempsAndRefusesASymlink(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 1)
	dir := filepath.Dir(l.Path())
	stale := filepath.Join(dir, tempPrefix+"crashed")
	if err := os.WriteFile(stale, []byte("half a log"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stale temporary file: %v", err)
	}

	target := filepath.Join(t.TempDir(), "real.jsonl")
	link := &Log{path: filepath.Join(t.TempDir(), FileName), now: fixedNow}
	if err := os.Rename(l.Path(), target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link.path); err != nil {
		t.Fatal(err)
	}
	if _, err := link.Rotate(); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("Rotate of a symlinked log = %v", err)
	}
}

// Appends racing rotations: every acknowledged line appears exactly once across
// the log and its archives, and the whole history verifies.
func TestConcurrentAppendsAndRotationsKeepEveryLineOnce(t *testing.T) {
	l := openLog(t)
	l.SetLockWait(testLockWait)
	appendN(t, l, 1)
	var mu sync.Mutex
	acked := map[string]bool{}
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				id := fmt.Sprintf("w%d-%d", w, i)
				if l.Append("read", map[string]any{"tool": id}) == nil {
					mu.Lock()
					acked[id] = true
					mu.Unlock()
				}
			}
		}()
	}
	rotations := 0
	for r := 0; r < 5; r++ {
		if _, err := l.Rotate(); err != nil {
			t.Errorf("rotation %d: %v", r, err)
		} else {
			rotations++
		}
	}
	wg.Wait()
	segs, err := VerifyHistory(l.Path())
	if err != nil || len(segs) != rotations+1 || segs[len(segs)-1].Missing {
		t.Fatalf("VerifyHistory = %+v, %v (rotations %d)", segs, err, rotations)
	}
	seen := map[string]int{}
	for _, s := range segs {
		for _, e := range readLines(t, s.Path) {
			if id, _ := e["tool"].(string); strings.HasPrefix(id, "w") {
				seen[id]++
			}
		}
	}
	for id := range acked {
		if seen[id] != 1 {
			t.Errorf("%s appears %d times", id, seen[id])
		}
	}
	if len(seen) != len(acked) {
		t.Errorf("%d lines written, %d acknowledged", len(seen), len(acked))
	}
}

// Lines appended between the unlocked verification and the lock are verified
// under it: a damaged one still refuses the rotation.
func TestRotateVerifiesLinesAppendedWhileItWaited(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 2)
	l.opened = func() {
		l.opened = nil
		f, err := os.OpenFile(l.Path(), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		}()
		// Readable as a last line, so only the chain check can refuse it.
		if _, err := f.WriteString(`{"seq":3,"prev":"sha256:other","hash":"sha256:forged","tool":"forged"}` + "\n"); err != nil {
			t.Error(err)
		}
	}
	if _, err := l.Rotate(); err == nil || !strings.Contains(err.Error(), "not rotated: audit log line 3") {
		t.Errorf("Rotate = %v, want the appended line refused", err)
	}
}

// A log converted to CRLF line ends still verifies, so it must also rotate: the
// verification counts the bytes as they are on disk.
func TestRotateCountsCRLFLines(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 3)
	b, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.Path(), []byte(strings.ReplaceAll(string(b), "\n", "\r\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 1)
	if n, err := Verify(l.Path()); err != nil || n != 4 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
	if _, err := l.Rotate(); err != nil {
		t.Errorf("Rotate of a CRLF log = %v", err)
	}
}

// Without the lock, the last line can be an append still being written: the
// unlocked pass leaves it to the pass under the lock.
func TestRotateWaitsForALineBeingWritten(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 2)
	last := readLines(t, l.Path())[1]
	line, err := l.encodeLine(3, last["hash"].(string), "read", map[string]any{"tool": "in_flight"})
	if err != nil {
		t.Fatal(err)
	}
	write := func(b []byte) {
		f, err := os.OpenFile(l.Path(), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		}()
		if _, err := f.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	write(line[:len(line)/2])
	l.opened = func() { // the append completes before Rotate takes the lock
		l.opened = nil
		write(append(line[len(line)/2:], '\n'))
	}
	archive, err := l.Rotate()
	if err != nil {
		t.Fatalf("Rotate = %v", err)
	}
	if n, err := Verify(archive); err != nil || n != 3 {
		t.Errorf("archive: %d lines, %v", n, err)
	}
}

// A rotation by another process between the unlocked pass and the lock replaces
// the file: the new one is verified whole, not reported as a log that shrank.
func TestOverlappingRotationsBothSucceed(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 4)
	other := &Log{path: l.Path(), now: fixedNow}
	l.opened = func() {
		l.opened = nil
		if _, err := other.Rotate(); err != nil {
			t.Errorf("the other rotation: %v", err)
		}
	}
	if _, err := l.Rotate(); err != nil {
		t.Fatalf("Rotate = %v", err)
	}
	if segs, err := VerifyHistory(l.Path()); err != nil || len(segs) != 3 || segs[2].Lines != 4 {
		t.Errorf("VerifyHistory = %+v, %v", segs, err)
	}
}

// The same file losing lines between the unlocked pass and the lock is refused.
func TestRotateRefusesALogThatShrankMeanwhile(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 3)
	b, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	keep := strings.SplitAfterN(string(b), "\n", 3)
	l.opened = func() {
		l.opened = nil
		if err := os.Truncate(l.Path(), int64(len(keep[0])+len(keep[1]))); err != nil {
			t.Error(err)
		}
	}
	if _, err := l.Rotate(); err == nil || !strings.Contains(err.Error(), "shrank") {
		t.Errorf("Rotate = %v, want a refusal for a log that shrank", err)
	}
}

// An archive that cannot be read is named in the error, with a hint that does not
// send the owner back to the command that reported it.
func TestArchiveErrorsNameTheArchive(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 2)
	archive, err := l.Rotate() // the oldest of two, so the error comes from deep in the history
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, 1)
	if _, err := l.Rotate(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, b[:len(b)-1], 0o600); err != nil { // no final newline
		t.Fatal(err)
	}
	_, err = VerifyHistory(l.Path())
	e := tkerr.From(err)
	if e == nil || !strings.HasPrefix(e.Message, "archive "+filepath.Base(archive)+": ") || strings.Count(e.Message, "archive ") != 1 ||
		strings.Contains(e.Hint, "audit verify") {
		t.Errorf("VerifyHistory = %v, want the damaged archive named once", err)
	}
}

// An archive replaced by a dangling link is missing to Verify and VerifyHistory alike.
func TestADanglingArchiveLinkIsMissing(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 1)
	archive, err := l.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(archive); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "gone"), archive); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(l.Path()); err != nil {
		t.Errorf("Verify = %v", err)
	}
	if segs, err := VerifyHistory(l.Path()); err != nil || len(segs) != 2 || !segs[1].Missing {
		t.Errorf("VerifyHistory = %+v, %v", segs, err)
	}
}

// A log whose last line lost its newline is refused by Append and Rotate, so
// Verify reports it too, instead of passing it.
func TestVerifyReportsAMissingFinalNewline(t *testing.T) {
	l := openLog(t)
	appendN(t, l, 3)
	b, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.Path(), b[:len(b)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(l.Path()); err == nil || n != 2 || !strings.Contains(err.Error(), "line 3 has no newline") || !strings.Contains(tkerr.From(err).Hint, "move it aside") {
		t.Errorf("Verify = %d, %v", n, err)
	}
}
