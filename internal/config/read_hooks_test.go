package config

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// The tests below change a secret file at the two fixed points of readCheckedLimit
// (beforeSecretRead and afterSecretRead), so that a change during the read is reproduced
// every time and not raced for. Each pins one guard of the function: removing that guard
// fails its test and no other. The files are synthetic and private, in t.TempDir.

const secretCap = 1 << 20

// secretFile writes a private file of size bytes and returns its path and the inspection
// that readCheckedLimit is handed, taken before the hooks run.
func secretFile(t *testing.T, size int) (string, inspected) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), size), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := inspect(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, want
}

// hooks installs the two hooks for one test and takes them off afterwards, so that no test
// leaves one behind for the production path of the next.
func hooks(t *testing.T, before, after func(f *os.File)) {
	t.Helper()
	beforeSecretRead, afterSecretRead = before, after
	t.Cleanup(func() { beforeSecretRead, afterSecretRead = nil, nil })
}

// appendBytes adds n bytes to the file at path, as a writer that is not the reader would.
func appendBytes(t *testing.T, path string, n int) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(bytes.Repeat([]byte("y"), n)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// refusal returns what the refusal of a read says: its code and message.
func refusal(t *testing.T, data []byte, err error) (tkerr.Code, string) {
	t.Helper()
	e, ok := tkerr.As(err)
	if !ok {
		t.Fatalf("read %d bytes, err = %v: want a refusal", len(data), err)
	}
	if len(data) != 0 {
		t.Errorf("a refused read still returned %d bytes", len(data))
	}
	return e.Code, e.Message
}

// The hooks are where the tests below say they are: the first before any byte is read, the
// second after the last one. A hook that moved would leave the tests below passing for
// another reason.
func TestTheReadHooksRunAroundTheRead(t *testing.T) {
	p, want := secretFile(t, 64)
	var offsets []int64
	at := func(f *os.File) {
		off, err := f.Seek(0, io.SeekCurrent)
		if err != nil {
			t.Fatal(err)
		}
		offsets = append(offsets, off)
	}
	hooks(t, at, at)
	data, err := readCheckedLimit(p, want, secretCap)
	if err != nil || len(data) != 64 {
		t.Fatalf("an unchanged file: read %d bytes, err = %v", len(data), err)
	}
	if !slices.Equal(offsets, []int64{0, 64}) {
		t.Errorf("the hooks ran at offsets %v, want [0 64]: before the first byte and after the last", offsets)
	}
}

// A file that passed the size check and then grows far past the cap must be read only up
// to the cap. The read stops by io.LimitReader at the cap and one byte, so what the reader
// holds does not follow the writer. The refusal alone cannot show that: the length check
// after the read refuses a file that was read whole too, so the test measures what the read
// allocated. Without the limit it allocates more than the growth.
func TestAGrowingSecretFileIsReadOnlyUpToTheCap(t *testing.T) {
	const growth = 32 << 20
	p, want := secretFile(t, secretCap) // exactly at the cap: the size check lets it through
	hooks(t, func(*os.File) {
		if err := os.Truncate(p, secretCap+growth); err != nil {
			t.Fatal(err)
		}
	}, nil)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	data, err := readCheckedLimit(p, want, secretCap)
	runtime.ReadMemStats(&after)
	// Which refusal it is belongs to the next test; this one is about what was read.
	if code, msg := refusal(t, data, err); code != tkerr.ConfigUnsafe {
		t.Errorf("a file grown by %d MiB: %s: %s, want config_unsafe", growth>>20, code, msg)
	}
	if read := after.TotalAlloc - before.TotalAlloc; read > growth/2 {
		t.Errorf("the read of a file grown by %d MiB allocated %d MiB: it was not stopped at the cap", growth>>20, read>>20)
	}
}

// A file at the cap that grows by one byte between the size check and the read comes back
// one byte over the cap, and the length check says so. Without the check the next one, the
// comparison after the read, refuses it too, but as a file that changed: this test requires
// the refusal that names the cap.
func TestASecretFileThatGrowsPastTheCapIsRefusedAsOverTheCap(t *testing.T) {
	p, want := secretFile(t, secretCap)
	hooks(t, func(*os.File) { appendBytes(t, p, 1) }, nil)
	data, err := readCheckedLimit(p, want, secretCap)
	code, msg := refusal(t, data, err)
	if code != tkerr.ConfigUnsafe || !strings.Contains(msg, "exceeds 1 MiB") {
		t.Errorf("%s: %s, want config_unsafe, exceeds 1 MiB", code, msg)
	}
}

// A file that changes after its last byte was read, before the second Stat, is refused:
// the bytes in hand are not the ones the checks saw. A byte more changes the size, which
// the comparison reads, so it holds on any file system.
func TestASecretFileChangedAfterTheReadIsRefused(t *testing.T) {
	p, want := secretFile(t, 64)
	hooks(t, nil, func(*os.File) { appendBytes(t, p, 1) })
	data, err := readCheckedLimit(p, want, secretCap)
	code, msg := refusal(t, data, err)
	if code != tkerr.ConfigUnsafe || !strings.Contains(msg, "changed while it was being read") {
		t.Errorf("%s: %s, want config_unsafe, changed while it was being read", code, msg)
	}
}

// A second Stat that fails refuses the read too: a file that cannot be asked again cannot
// be said to be unchanged. The hook closes the file, which is what makes the Stat fail on
// every platform. The refusal is not the one for a file that changed (nothing says it did):
// it says the file could not be inspected again, and it keeps the cause, so that errors.Is
// finds it, and says it in the message, because the cause reaches neither the text nor the
// JSON form.
func TestASecretFileThatCannotBeStatedAfterTheReadIsRefused(t *testing.T) {
	p, want := secretFile(t, 64)
	hooks(t, nil, func(f *os.File) {
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	})
	data, err := readCheckedLimit(p, want, secretCap)
	code, msg := refusal(t, data, err)
	if code != tkerr.ConfigUnsafe || !strings.Contains(msg, "cannot inspect "+p+" after reading it") || !strings.Contains(msg, os.ErrClosed.Error()) {
		t.Errorf("%s: %s, want config_unsafe, cannot inspect the file after reading it, and why", code, msg)
	}
	if strings.Contains(msg, "changed while it was being read") {
		t.Errorf("a Stat that failed is reported as a change: %s", msg)
	}
	if !errors.Is(err, os.ErrClosed) {
		t.Errorf("the cause of the Stat error was dropped: errors.Is does not find it in %v", err)
	}
	var pe *fs.PathError
	if !errors.As(err, &pe) || pe.Op != "stat" {
		t.Errorf("errors.As does not find the stat error in %v", err)
	}
	// A change, by contrast, has no cause to keep.
	p2, want2 := secretFile(t, 64)
	hooks(t, nil, func(*os.File) { appendBytes(t, p2, 1) })
	_, changed := readCheckedLimit(p2, want2, secretCap)
	if e, ok := tkerr.As(changed); !ok || errors.Unwrap(e) != nil || !strings.Contains(e.Message, "changed while it was being read") {
		t.Errorf("a changed file: %v", changed)
	}
}

// The identity of an open file that cannot be read (on Windows, a handle that fails or a
// reparse point) is the cause of the refusal, and the refusal keeps it: errors.Is and
// errors.As see it, and the message says it, because the cause reaches neither the text
// nor the JSON form. A file that is simply not the one inspected has no cause to keep.
func TestARefusalToIdentifyTheOpenFileKeepsItsCause(t *testing.T) {
	cause := errors.New("the handle is invalid")
	err := changedWhileChecked("/p/secret", cause)
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.ConfigUnsafe {
		t.Fatalf("err = %v, want config_unsafe", err)
	}
	if !errors.Is(err, cause) {
		t.Error("the cause of the identity error was dropped: errors.Is does not find it")
	}
	if !strings.Contains(e.Message, "/p/secret changed while it was being checked") || !strings.Contains(e.Message, cause.Error()) {
		t.Errorf("message = %q, want the refusal and its cause", e.Message)
	}
	plain, ok := tkerr.As(changedWhileChecked("/p/secret", nil))
	if !ok || plain.Code != tkerr.ConfigUnsafe || plain.Message != "/p/secret changed while it was being checked" || errors.Unwrap(plain) != nil {
		t.Errorf("a file that is not the one inspected: %+v", plain)
	}
}
