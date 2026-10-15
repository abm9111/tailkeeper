package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// procLockOnly stands in, for one test, for a platform with no file lock
// (Windows today): the in-process lock is then all that serialises appenders.
func procLockOnly(t *testing.T) {
	t.Helper()
	l, u := lockFile, unlockFile
	t.Cleanup(func() { lockFile, unlockFile = l, u })
	lockFile = func(_ *os.File, wait time.Duration) error { return lockProc(wait) }
	unlockFile = func(*os.File) error { unlockProc(); return nil }
}

// appendInParallel has goroutines goroutines each append per lines, goroutine g
// through logs[g%len(logs)], and waits for all of them.
func appendInParallel(t *testing.T, logs []*Log, goroutines, per int) {
	t.Helper()
	for _, l := range logs {
		l.SetLockWait(testLockWait)
	}
	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := logs[g%len(logs)]
			for range per {
				if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func wantLines(t *testing.T, path string, want int) {
	t.Helper()
	if n, err := Verify(path); n != want || err != nil {
		t.Errorf("Verify = %d, %v; want %d, nil", n, err, want)
	}
}

// Where the platform has no file lock (Windows today), the appenders of one
// process must still be serialised, or one MCP server's parallel calls fork the
// chain: two lines with one sequence number. The stand-in lock reproduces that
// platform here.
func TestTheInProcessLockKeepsOneProcessChainWithoutAFileLock(t *testing.T) {
	procLockOnly(t)
	l := openLog(t)
	appendInParallel(t, []*Log{l}, 4, 25)
	wantLines(t, l.Path(), 100)
}

// The lock is the process's, not a Log's and not a path spelling's: the MCP
// server shares one Log, but the CLI, doctor and any second Open in the same
// process reach the same file through their own Log and often another spelling
// of the path.
func TestTheInProcessLockIsOneLockWhateverTheLogOrThePathSpelling(t *testing.T) {
	procLockOnly(t)
	dir := t.TempDir()
	sep := string(filepath.Separator)
	abs := filepath.Join(dir, FileName)
	spellings := []string{
		abs,
		dir + sep + "." + sep + FileName, // not cleaned
		dir + sep + "sub" + sep + ".." + sep + FileName, // not cleaned either
	}
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		spellings = append(spellings, filepath.Join(real, FileName)) // /private/var for /var on macOS
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	spellings = append(spellings, FileName) // relative
	var logs []*Log
	for _, p := range spellings {
		l, err := Open(p, fixedNow)
		if err != nil {
			t.Fatal(err)
		}
		logs = append(logs, l)
	}
	appendInParallel(t, logs, 2*len(logs), 10)
	wantLines(t, abs, 2*len(logs)*10)
}

// The same run through the platform's own lock, with no stand-in: on Windows
// this is the in-process lock; elsewhere it is flock. Either way, one Log shared
// by four goroutines, as the MCP server shares it, must keep the chain.
func TestParallelAppendsOnOneLogKeepChain(t *testing.T) {
	l := openLog(t)
	appendInParallel(t, []*Log{l}, 4, 25)
	wantLines(t, l.Path(), 100)
}

func TestTheInProcessLockGivesUpAfterTheWait(t *testing.T) {
	if err := lockProc(time.Second); err != nil {
		t.Fatal(err)
	}
	defer unlockProc()
	start := time.Now()
	if err := lockProc(50 * time.Millisecond); !errors.Is(err, errLockTimeout) {
		t.Errorf("second lock = %v, want errLockTimeout", err)
	}
	if d := time.Since(start); d < 50*time.Millisecond {
		t.Errorf("gave up after %v, before the wait", d)
	}
}

func TestTheInProcessLockCanBeTakenAgainOnceReleased(t *testing.T) {
	if err := lockProc(time.Second); err != nil {
		t.Fatal(err)
	}
	unlockProc()
	unlockProc() // releasing an unheld lock does nothing
	if err := lockProc(time.Second); err != nil {
		t.Fatalf("lock after release = %v", err)
	}
	unlockProc()
}

// An Append that waits out the in-process lock fails as a locked log does, and
// goes through once the holder lets go.
func TestAppendReportsALogStuckBehindTheInProcessLock(t *testing.T) {
	procLockOnly(t)
	l := openLog(t)
	if err := lockProc(time.Second); err != nil {
		t.Fatal(err)
	}
	l.SetLockWait(50 * time.Millisecond)
	err := l.Append("read", map[string]any{"tool": "devices_list"})
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.AuditUnavailable || !strings.Contains(e.Message, "stayed locked") {
		t.Errorf("Append while the lock is held = %v, want audit_unavailable: stayed locked", err)
	} else if strings.Contains(e.Message, "another process") {
		// The holder here is this process, as it can be on Windows: the message names
		// no holder it cannot know.
		t.Errorf("the message blames another process for a lock this one holds: %q", e.Message)
	}
	unlockProc()
	if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
		t.Errorf("Append after the release = %v", err)
	}
	wantLines(t, l.Path(), 1)
}

// An Append that fails after it took the lock must give the lock back, or the
// process could write no audit line again.
func TestAFailedAppendReleasesTheInProcessLock(t *testing.T) {
	procLockOnly(t)
	shape := "tskey" + "-api-" + strings.Repeat("C", 12) // assembled so no literal matches a scanner rule
	for name, prepare := range map[string]func(*testing.T, *Log) map[string]any{
		"corrupt tail": func(t *testing.T, l *Log) map[string]any {
			if err := os.WriteFile(l.Path(), []byte("not json\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return map[string]any{"tool": "devices_list"}
		},
		"refused entry": func(*testing.T, *Log) map[string]any { return map[string]any{"note": shape} },
	} {
		l := openLog(t)
		fields := prepare(t, l)
		if err := l.Append("read", fields); err == nil {
			t.Errorf("%s: Append succeeded", name)
			continue
		}
		if err := lockProc(50 * time.Millisecond); err != nil {
			t.Errorf("%s: the failed Append left the in-process lock held (%v)", name, err)
			continue
		}
		unlockProc()
	}
}
