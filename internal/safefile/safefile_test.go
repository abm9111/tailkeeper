package safefile

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func write(t *testing.T, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.hujson")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// refused asserts err is a refusal with the given code whose message holds want.
func refused(t *testing.T, what string, err error, code tkerr.Code, want string) {
	t.Helper()
	e, ok := tkerr.As(err)
	if !ok || e.Code != code || !strings.Contains(e.Message, want) {
		t.Errorf("%s: err = %v, want code %s and %q in the message", what, err, code, want)
	}
}

func TestReadReturnsTheFileBytesUntouched(t *testing.T) {
	// A BOM and CRLF are the engine's to refuse or count: the reader keeps them.
	body := []byte("\xef\xbb\xbf{\r\n  // c\r\n}\r\n")
	for name, in := range map[string][]byte{"bytes": body, "empty": {}} {
		got, err := Read(write(t, in), Options{})
		if err != nil || !bytes.Equal(got, in) {
			t.Errorf("%s: got %q, %v", name, got, err)
		}
	}
}

func TestTheCapIsInclusiveAndCapPlusOneIsRefused(t *testing.T) {
	o := Options{Cap: 16, Code: tkerr.ConfigInvalid}
	if got, err := Read(write(t, bytes.Repeat([]byte("x"), 16)), o); err != nil || len(got) != 16 {
		t.Errorf("exactly the cap: %d bytes, %v", len(got), err)
	}
	refused(t, "cap+1", func() error { _, err := Read(write(t, bytes.Repeat([]byte("x"), 17)), o); return err }(),
		tkerr.ConfigInvalid, "is 17 bytes, more than the 16 bytes tailkeeper reads")
	// The default cap is tailkeeper's own 4 MiB.
	if MaxBytes != 4<<20 || (Options{}).limit() != 4<<20 || (Options{}).code() != tkerr.Usage {
		t.Errorf("defaults: cap %d, code %s", (Options{}).limit(), (Options{}).code())
	}
}

// A cap at the top of int64 must not overflow the cap-plus-one the reader asks
// for: that would be a negative limit and an empty result without an error.
func TestAnEnormousCapStillReadsTheWholeFile(t *testing.T) {
	o := Options{Cap: math.MaxInt64}
	got, err := Read(write(t, []byte("{}")), o)
	if err != nil || string(got) != "{}" {
		t.Errorf("Read with the largest cap: %q, %v", got, err)
	}
	got, err = ReadAll(strings.NewReader("{}"), "standard input", o)
	if err != nil || string(got) != "{}" {
		t.Errorf("ReadAll with the largest cap: %q, %v", got, err)
	}
}

// A file that grows after it was inspected is still read through the limit: the
// size seen by Lstat is not what bounds the read.
func TestAFileThatGrowsAfterTheInspectionIsStillCapped(t *testing.T) {
	p := write(t, []byte("small"))
	afterLstat = func(path string) {
		if err := os.WriteFile(path, bytes.Repeat([]byte("y"), 100), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { afterLstat = func(string) {} })
	_, err := Read(p, Options{Cap: 16})
	refused(t, "grown file", err, tkerr.Usage, "more than the 16 bytes tailkeeper reads")
}

func TestAFileReplacedAfterTheInspectionIsRefused(t *testing.T) {
	p := write(t, []byte("original"))
	other := write(t, []byte("replacement"))
	afterLstat = func(path string) {
		// A rename puts a different file, with its own identity, at the path.
		if err := os.Rename(other, path); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { afterLstat = func(string) {} })
	got, err := Read(p, Options{})
	if err == nil {
		t.Fatalf("read %q from a file replaced after the check", got)
	}
	refused(t, "replaced file", err, tkerr.Usage, "changed while it was being opened")
}

// A symlink put at the path between the inspection and the open is not followed: the
// open refuses it (O_NOFOLLOW), or on Windows, which has none, the opened link is not the
// file inspected.
func TestASymlinkSwappedInAfterTheInspectionIsRefused(t *testing.T) {
	p := write(t, []byte("{}"))
	target := write(t, []byte(`{"swapped": true}`))
	if err := os.Symlink(target, filepath.Join(t.TempDir(), "probe")); err != nil {
		// Not a skip: a skip on Windows would have to be listed in docs/windows.md.
		t.Logf("this platform or account cannot make a symlink: %v", err)
		return
	}
	afterLstat = func(path string) {
		if err := os.Remove(path); err != nil {
			t.Error(err) // not Fatal: the reader calls this
			return
		}
		if err := os.Symlink(target, path); err != nil {
			t.Error(err) // not Fatal: the reader calls this
			return
		}
	}
	t.Cleanup(func() { afterLstat = func(string) {} })
	got, err := Read(p, Options{})
	if err == nil {
		t.Fatalf("read %q through a symlink swapped in after the check", got)
	}
	want := "without following a symlink"
	if runtime.GOOS == "windows" {
		want = "changed while it was being opened"
	}
	refused(t, "swapped symlink", err, tkerr.Usage, want)
}

func TestMissingAndNotRegularFilesAreRefused(t *testing.T) {
	dir := t.TempDir()
	_, err := Read(filepath.Join(dir, "missing.hujson"), Options{Code: tkerr.ConfigInvalid})
	refused(t, "missing", err, tkerr.ConfigInvalid, "cannot inspect")
	_, err = Read(dir, Options{})
	refused(t, "directory", err, tkerr.Usage, "is not a regular file")
	link := filepath.Join(t.TempDir(), "link.hujson")
	if err := os.Symlink(write(t, []byte("{}")), link); err != nil {
		// Not a skip: a skip on Windows would have to be listed in docs/windows.md.
		t.Logf("this platform or account cannot make a symlink: %v", err)
		return
	}
	_, err = Read(link, Options{})
	refused(t, "symlink", err, tkerr.Usage, "is a symbolic link; symlinks are refused")
}

func TestCheckRefusesWithoutReading(t *testing.T) {
	if err := Check(write(t, []byte("{}")), Options{}); err != nil {
		t.Errorf("a regular file: %v", err)
	}
	refused(t, "too big", Check(write(t, bytes.Repeat([]byte("x"), 17)), Options{Cap: 16}), tkerr.Usage, "more than the 16 bytes")
	refused(t, "directory", Check(t.TempDir(), Options{}), tkerr.Usage, "is not a regular file")
	refused(t, "missing", Check(filepath.Join(t.TempDir(), "nope"), Options{}), tkerr.Usage, "cannot inspect")
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("pipe broke") }

func TestReadAllCapsAStream(t *testing.T) {
	o := Options{Cap: 16, Code: tkerr.ValidationFailed}
	if got, err := ReadAll(strings.NewReader(strings.Repeat("x", 16)), "standard input", o); err != nil || len(got) != 16 {
		t.Errorf("exactly the cap: %d, %v", len(got), err)
	}
	_, err := ReadAll(strings.NewReader(strings.Repeat("x", 17)), "standard input", o)
	refused(t, "cap+1", err, tkerr.ValidationFailed, "standard input is more than the 16 bytes tailkeeper reads")
	_, err = ReadAll(failingReader{}, "standard input", o)
	refused(t, "read error", err, tkerr.ValidationFailed, "cannot read standard input")
	if got, err := ReadAll(io.NopCloser(strings.NewReader("")), "standard input", o); err != nil || len(got) != 0 {
		t.Errorf("empty stream: %q, %v", got, err)
	}
}

// endless offers more bytes than anyone should take and counts what was taken.
type endless struct{ taken int64 }

func (e *endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	e.taken += int64(len(p))
	return len(p), nil
}

// The reader asks its source for the cap plus one byte and no more: the extra byte
// is what tells a file of exactly the cap from a longer one, and a source with no
// end must not be read to exhaustion.
func TestReadAllStopsPullingAtCapPlusOneBytes(t *testing.T) {
	src := &endless{}
	_, err := ReadAll(src, "standard input", Options{Cap: 16})
	refused(t, "endless source", err, tkerr.Usage, "standard input is more than the 16 bytes tailkeeper reads")
	if src.taken > 17 {
		t.Errorf("pulled %d bytes from the source, want at most the cap plus one (17)", src.taken)
	}
}

// The Windows rules are a pure function of the name, so they are tested on every
// platform; Read applies them only where the platform has such names.
func TestWindowsNameRules(t *testing.T) {
	for p, want := range map[string]string{
		`\\server\share\policy.hujson`: "UNC",
		`//server/share/policy.hujson`: "UNC",
		`\\?\C:\policy.hujson`:         "UNC",
		`\\.\pipe\policy`:              "UNC",
		`C:\work\NUL`:                  "device",
		`nul.txt`:                      "device",
		`dir\Con.hujson`:               "device",
		`COM1`:                         "device",
		`lpt9.x`:                       "device",
		`C:\work\NUL .txt`:             "device",
		"com\u00b9":                    "device",
		`CONOUT$`:                      "device",
		`\/server/share/x`:             "UNC paths",
		`/\server\share\x`:             "UNC paths",
		`\/?/C:/x`:                     "UNC paths",
		`/\.\pipe/policy`:              "UNC paths",
		// The NT namespace prefix is the same kind of path as \\?\, in any mix of
		// separators, and a drive letter behind it is not the thing that is wrong.
		`\??\UNC\server\share\f`:       "UNC paths",
		`\??\C:\x`:                     "UNC paths",
		`/??/C:/x`:                     "UNC paths",
		`\??/x`:                        "UNC paths",
		`/??\x`:                        "UNC paths",
		`COM0`:                         "device",
		`com0.txt`:                     "device",
		`dir/LPT0`:                     "device",
		`Lpt0.x`:                       "device",
		`C:\work\policy.hujson:stream`: "alternate data stream",
		`policy.hujson::$DATA`:         "alternate data stream",
	} {
		got := windowsNameProblem(p)
		if !strings.Contains(got, want) {
			t.Errorf("windowsNameProblem(%q) = %q, want it to mention %q", p, got, want)
		}
		if want == "UNC paths" && strings.Contains(got, "alternate") {
			t.Errorf("windowsNameProblem(%q) = %q, a UNC path must not be reported as a stream", p, got)
		}
	}
	for _, p := range []string{`C:\Users\me\policy.hujson`, `policy.hujson`, `./a/b.hujson`, `C:policy.hujson`, `console.txt`,
		`nullable`, `aux1`, `COM10`, `LPT00`, `a/b/lpt.hujson`, `/tmp/policy.hujson`, ` CON`, `/a\server\x`,
		`/a\??\x`, `??\x`, `\???\x`, `\??`} {
		if got := windowsNameProblem(p); got != "" {
			t.Errorf("windowsNameProblem(%q) = %q, want none", p, got)
		}
	}
}
