package audit

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// halfWrite writes the first half of the line through f, as a full disk might, and then
// fails.
func halfWrite(f *os.File, b []byte) (int, error) {
	n, err := f.Write(b[:len(b)/2])
	if err != nil {
		return n, err
	}
	return n, errors.New("no space left on device")
}

func sizeOf(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// appendAfterAFailedWrite appends one entry, then a second whose write fails halfway, and
// returns the log's size before the second and the second's error.
func appendAfterAFailedWrite(t *testing.T, l *Log) (int64, error) {
	t.Helper()
	if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
		t.Fatal(err)
	}
	before := sizeOf(t, l.Path())
	l.write = halfWrite
	err := l.Append("read", map[string]any{"tool": "device_get"})
	l.write, l.truncate, l.truncatePath = nil, nil, nil
	return before, err
}

// requireCutBack checks that the failed write left the log as it was, and that the next
// append extends the chain.
func requireCutBack(t *testing.T, l *Log, err error, before int64) {
	t.Helper()
	if e := tkerr.From(err); err == nil || e.Code != tkerr.AuditUnavailable || !strings.HasPrefix(e.Message, "cannot write ") || strings.Contains(e.Message, "cutting") {
		t.Fatalf("Append with a failed write = %v, want audit_unavailable saying only that the write failed", err)
	}
	if after := sizeOf(t, l.Path()); after != before {
		t.Fatalf("the log is %d bytes after the failed write, want the %d it had: half a line was left behind", after, before)
	}
	if err := l.Append("read", map[string]any{"tool": "dns_get"}); err != nil {
		t.Fatalf("the next Append: %v", err)
	}
	if n, err := Verify(l.Path()); err != nil || n != 2 {
		t.Fatalf("Verify = %d, %v; want the two entries that were written", n, err)
	}
}

// TestAppendCutsAFailedWriteBack runs the real truncation. On Windows the handle was
// opened with O_APPEND and cannot be truncated, so this also runs the fallback by path.
func TestAppendCutsAFailedWriteBack(t *testing.T) {
	l := openLog(t)
	before, err := appendAfterAFailedWrite(t, l)
	requireCutBack(t, l, err, before)
}

// TestAppendCutsBackByPathWhenTheHandleCannotTruncate makes the handle refuse, as a
// Windows append handle does, on every platform.
func TestAppendCutsBackByPathWhenTheHandleCannotTruncate(t *testing.T) {
	l := openLog(t)
	if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
		t.Fatal(err)
	}
	before := sizeOf(t, l.Path())
	l.write = halfWrite
	l.truncate = func(*os.File, int64) error { return errors.New("access is denied") }
	err := l.Append("read", map[string]any{"tool": "device_get"})
	l.write, l.truncate = nil, nil
	requireCutBack(t, l, err, before)
}

// TestAppendSaysWhenTheCutBackFails: with neither truncation working, the error says the
// log may end in part of a line and points at audit verify, and the next append refuses
// the log as it refuses any log cut short.
func TestAppendSaysWhenTheCutBackFails(t *testing.T) {
	l := openLog(t)
	if err := l.Append("read", map[string]any{"tool": "devices_list"}); err != nil {
		t.Fatal(err)
	}
	before := sizeOf(t, l.Path())
	l.write = halfWrite
	l.truncate = func(*os.File, int64) error { return errors.New("access is denied") }
	l.truncatePath = func(string, int64) error { return errors.New("the device is not ready") }
	err := l.Append("read", map[string]any{"tool": "device_get"})
	l.write, l.truncate, l.truncatePath = nil, nil, nil
	e := tkerr.From(err)
	if err == nil || e.Code != tkerr.AuditUnavailable {
		t.Fatalf("Append = %v, want audit_unavailable", err)
	}
	for _, want := range []string{"cannot write ", "cutting it back", "part of a line"} {
		if !strings.Contains(e.Message, want) {
			t.Errorf("the message %q does not say %q", e.Message, want)
		}
	}
	if !strings.Contains(e.Hint, "audit verify") {
		t.Errorf("the hint %q does not point at audit verify", e.Hint)
	}
	if after := sizeOf(t, l.Path()); after <= before {
		t.Fatalf("the log is %d bytes, want more than %d: the test meant to leave part of a line", after, before)
	}
	if err := l.Append("read", map[string]any{"tool": "dns_get"}); err == nil || !strings.Contains(tkerr.From(err).Message, "does not end with a newline") {
		t.Errorf("the next Append = %v, want the refusal of a log that does not end with a newline", err)
	}
}
