package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func fixedNow() time.Time { return time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC) }

// testLockWait replaces the 2 s production lock wait in tests whose writers wait
// on each other or on the test itself for as long as it takes: on a loaded runner
// a correct log can stay locked past 2 s. The tests of the wait set their own.
const testLockWait = 30 * time.Second

func openLog(t *testing.T) *Log {
	t.Helper()
	l, err := Open(filepath.Join(t.TempDir(), "logs", FileName), fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestAppendChainsAndVerifies(t *testing.T) {
	l := openLog(t)
	for i := 0; i < 5; i++ {
		if err := l.Append("read", map[string]any{"tool": "devices_list", "bytes": i}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := Verify(l.Path())
	if err != nil || n != 5 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
	entries, err := Tail(l.Path(), 2)
	if err != nil || len(entries) != 2 || entries[1]["seq"].(float64) != 5 {
		t.Fatalf("Tail = %v, %v", entries, err)
	}
	if runtime.GOOS != "windows" { // Windows reports no POSIX modes
		fi, _ := os.Stat(l.Path())
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("log mode = %04o, want 0600", fi.Mode().Perm())
		}
		di, _ := os.Stat(filepath.Dir(l.Path()))
		if di.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode = %04o, want 0700", di.Mode().Perm())
		}
	}
}

// Append writes through the handle it closes, so a Close that fails is returned. A
// stand-in unlock closes the handle early, which makes the deferred Close fail; the
// entry itself was written and synced, and the chain still verifies.
func TestAppendReturnsACloseError(t *testing.T) {
	l := openLog(t)
	prev := unlockFile
	t.Cleanup(func() { unlockFile = prev })
	unlockFile = func(f *os.File) error { _ = prev(f); return f.Close() }
	err := l.Append("read", map[string]any{"tool": "devices_list"})
	unlockFile = prev
	if e := tkerr.From(err); err == nil || e.Code != tkerr.AuditUnavailable || !strings.Contains(e.Message, "closing") {
		t.Fatalf("Append with a failing Close = %v, want audit_unavailable naming the close", err)
	}
	if n, err := Verify(l.Path()); err != nil || n != 1 {
		t.Errorf("Verify = %d, %v; want the one entry that was written", n, err)
	}
	if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
		t.Errorf("the next Append: %v", err)
	}
}

// A Close that fails is returned unless an earlier error is: the entry that was not
// written is the news, and the Close of a handle that failed says less. The tests close
// the handle early, as above, so that the deferred Close fails too: once after the line
// could not be encoded, once after lastLine refused the log. (Closing the handle in the
// lock instead would fail in openLocked, which never hands Append a handle, and so
// reach neither the code under test nor its deferred Close.)
func TestAppendReturnsTheEncodingErrorWhenCloseFailsToo(t *testing.T) {
	prevUnlock := unlockFile
	t.Cleanup(func() { unlockFile = prevUnlock })
	closeEarly := func(f *os.File) error { _ = prevUnlock(f); return f.Close() }

	// The entry cannot be encoded (a channel is no JSON), and the Close fails.
	l := openLog(t)
	unlockFile = closeEarly
	err := l.Append("read", map[string]any{"tool": make(chan int)})
	unlockFile = prevUnlock
	if err == nil || strings.Contains(err.Error(), "closing") || strings.Contains(err.Error(), "already closed") {
		t.Fatalf("Append of an entry that cannot be encoded, with a failing Close = %v, want the encoding error", err)
	}
	if n, verr := Verify(l.Path()); verr != nil || n != 0 {
		t.Errorf("Verify = %d, %v; want an empty, intact log", n, verr)
	}
	if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
		t.Errorf("the next Append: %v", err)
	}

}

// The log does not end with a newline, so lastLine refuses it, and the Close fails.
func TestAppendReturnsTheLogErrorWhenCloseFailsToo(t *testing.T) {
	prevUnlock := unlockFile
	t.Cleanup(func() { unlockFile = prevUnlock })
	closeEarly := func(f *os.File) error { _ = prevUnlock(f); return f.Close() }

	l := openLog(t)
	if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(l.Path(), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"half a line`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	unlockFile = closeEarly
	err = l.Append("read", map[string]any{"tool": "devices_list"})
	unlockFile = prevUnlock
	if e := tkerr.From(err); err == nil || e.Code != tkerr.AuditUnavailable || !strings.Contains(e.Message, "does not end with a newline") ||
		strings.Contains(e.Message, "closing") {
		t.Fatalf("Append to a log without a final newline, with a failing Close = %v, want audit_unavailable for the log, not the close", err)
	}
	if after, rerr := os.ReadFile(l.Path()); rerr != nil || !bytes.Equal(after, before) {
		t.Errorf("the log changed: %q, %v", after, rerr)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	cases := map[string]struct {
		mutate func([][]byte) [][]byte
		line   string
	}{
		"modified": {func(lines [][]byte) [][]byte {
			lines[1] = bytes.Replace(lines[1], []byte("devices_list"), []byte("devices_lisT"), 1)
			return lines
		}, "line 2"},
		"removed":  {func(lines [][]byte) [][]byte { return append(lines[:1], lines[2:]...) }, "line 2"},
		"inserted": {func(lines [][]byte) [][]byte { return append(lines[:2], append([][]byte{lines[0]}, lines[2:]...)...) }, "line 3"},
	}
	for name, c := range cases {
		l := openLog(t)
		for i := 0; i < 4; i++ {
			if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
				t.Fatal(err)
			}
		}
		data, _ := os.ReadFile(l.Path())
		lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
		lines = c.mutate(lines)
		if err := os.WriteFile(l.Path(), append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Verify(l.Path())
		if e, ok := tkerr.As(err); !ok || e.Code != tkerr.AuditUnavailable || !strings.Contains(e.Message, c.line) {
			t.Errorf("%s: Verify err = %v, want a break at %s", name, err, c.line)
		}
	}
}

func TestReservedFieldsRefused(t *testing.T) {
	l := openLog(t)
	if err := l.Append("read", map[string]any{"seq": 99}); err == nil {
		t.Fatal("reserved field accepted")
	}
}

func TestConcurrentAppendsKeepChain(t *testing.T) {
	l := openLog(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l2, err := Open(l.Path(), fixedNow)
			if err != nil {
				t.Error(err)
				return
			}
			l2.SetLockWait(testLockWait)
			if err := l2.Append("read", map[string]any{"tool": "x"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n, err := Verify(l.Path()); err != nil || n != 20 {
		t.Fatalf("Verify after concurrent appends = %d, %v", n, err)
	}
}

func TestAppendRefusesCorruptTail(t *testing.T) {
	l := openLog(t)
	if err := os.WriteFile(l.Path(), []byte("not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.Append("read", nil); err == nil {
		t.Fatal("Append chained onto a corrupt line")
	}
}

func TestAppendRefusesCredentialShapes(t *testing.T) {
	l := openLog(t)
	shape := "tskey" + "-api-" + strings.Repeat("C", 12) // assembled so no literal matches a scanner rule
	err := l.Append("read", map[string]any{"tool": "devices_list", "note": shape})
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.OutputWithheld {
		t.Fatalf("err = %v, want output_withheld", err)
	}
	data, _ := os.ReadFile(l.Path())
	if strings.Contains(string(data), "CCCC") {
		t.Fatal("a credential-shaped value reached the audit file")
	}
}

func TestTailShowsDamagedLines(t *testing.T) {
	l := openLog(t)
	for i := 0; i < 3; i++ {
		if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.OpenFile(l.Path(), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("garbage\n")
	_ = f.Close()
	got, err := Tail(l.Path(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1]["unreadable"] == nil || got[1]["line"] != 4 {
		t.Fatalf("tail = %v", got)
	}
}

func TestVerifyRejectsDataAfterAnEntry(t *testing.T) {
	l := openLog(t)
	if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(l.Path())
	forged := append(bytes.TrimRight(data, "\n"), []byte(`{"event":"forged"}`+"\n")...)
	if err := os.WriteFile(l.Path(), forged, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(l.Path()); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("Verify = %v, want line 1 broken", err)
	}
}

func TestAppendRefusesALogWithoutAFinalNewline(t *testing.T) {
	l := openLog(t)
	if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(l.Path())
	cut := bytes.TrimRight(data, "\n")
	if err := os.WriteFile(l.Path(), cut, 0o600); err != nil {
		t.Fatal(err)
	}
	err := l.Append("read", map[string]any{"tool": "dns_get"})
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.AuditUnavailable {
		t.Fatalf("err = %v, want audit_unavailable", err)
	}
	if after, _ := os.ReadFile(l.Path()); !bytes.Equal(after, cut) {
		t.Fatal("Append changed a log it refused")
	}
}

func TestAppendRefusesOversizedLines(t *testing.T) {
	l := openLog(t)
	if err := l.Append("read", map[string]any{"note": strings.Repeat("x", MaxLine)}); err == nil {
		t.Fatal("an oversized line was written")
	}
	if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
		t.Fatalf("the log is unusable after a refused line: %v", err)
	}
	if n, err := Verify(l.Path()); err != nil || n != 1 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
}

func TestStructValuedFieldsVerify(t *testing.T) {
	l := openLog(t)
	type requester struct {
		Zed string `json:"zed"`
		Abc string `json:"abc"`
	}
	if err := l.Append("read", map[string]any{"requester": requester{Zed: "z", Abc: "a"}, "n": int64(9007199254740993)}); err != nil {
		t.Fatal(err)
	}
	if n, err := Verify(l.Path()); err != nil || n != 1 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
}

func TestOpenTightensExistingModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reports no POSIX modes: os.Chmod only sets the read-only attribute there")
	}
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, fixedNow); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", p, got, want)
		}
	}
}

func TestVerifyDetectsARewrittenChainLink(t *testing.T) {
	l := openLog(t)
	for i := 0; i < 2; i++ {
		if err := l.Append("read", map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(l.Path())
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	dec := json.NewDecoder(bytes.NewReader(lines[1]))
	dec.UseNumber()
	var entry map[string]any
	if err := dec.Decode(&entry); err != nil {
		t.Fatal(err)
	}
	// A forger who recomputes the line's own hash still breaks the link to line 1.
	entry["prev"] = "sha256:" + strings.Repeat("0", 64)
	sum, err := hashOf(entry)
	if err != nil {
		t.Fatal(err)
	}
	entry["hash"] = sum
	lines[1], _ = json.Marshal(entry)
	if err := os.WriteFile(l.Path(), append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(l.Path()); err == nil || !strings.Contains(err.Error(), "does not chain") {
		t.Fatalf("Verify = %v, want a broken chain at line 2", err)
	}
}

func TestAppendWaitsTwoSecondsUnlessTold(t *testing.T) {
	// The changelog states this wait.
	l, err := Open(filepath.Join(t.TempDir(), FileName), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		set, want time.Duration
	}{{0, 2 * time.Second}, {5 * time.Millisecond, 5 * time.Millisecond}, {0, 2 * time.Second}} {
		l.SetLockWait(c.set)
		if got := l.wait(); got != c.want {
			t.Errorf("after SetLockWait(%s): wait = %s, want %s", c.set, got, c.want)
		}
	}
}
