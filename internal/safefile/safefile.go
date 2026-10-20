// Package safefile reads a file that holds policy content: one an operator names
// on the command line (--from, --against, --patch, --invariants) or in the
// configuration (acl.invariantsFile). The rules: inspect the name, refuse a
// symlink and anything but a regular file, open it, check that what was opened is
// what was inspected, and read at most the cap plus one byte through a limit
// reader into one buffer, so the bytes that are parsed are the bytes that are
// sent and no second read can see a different file.
//
// MCP tools never take a path; this package is for the operator's own files.
package safefile

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"strings"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// MaxBytes is the most a policy file may hold: tailkeeper's own cap, since
// Tailscale publishes none.
const MaxBytes = 4 << 20

// Options say how much may be read and how a refusal is reported.
type Options struct {
	Cap  int64      // the most bytes accepted; MaxBytes when 0
	Code tkerr.Code // the code of every refusal; tkerr.Usage when empty
}

// limit is the cap in force. It stops one short of the top of int64 so that the
// cap plus one byte, which the reader asks for, cannot overflow.
func (o Options) limit() int64 {
	switch {
	case o.Cap <= 0:
		return MaxBytes
	case o.Cap == math.MaxInt64:
		return math.MaxInt64 - 1
	}
	return o.Cap
}

func (o Options) code() tkerr.Code {
	if o.Code != "" {
		return o.Code
	}
	return tkerr.Usage
}

func (o Options) refuse(msg, hint string) error { return tkerr.New(o.code(), msg, hint) }

// afterLstat runs between the inspection and the open. It is a seam for tests that
// change the file at that moment; it does nothing otherwise.
var afterLstat = func(string) {}

// Check refuses a path that Read would refuse for its name or its kind, without
// opening it: the first process of a command checks, before the credential
// wrapper starts, and the process that holds the credential reads.
func Check(path string, o Options) error {
	_, err := inspect(path, o)
	return err
}

func inspect(path string, o Options) (os.FileInfo, error) {
	if runtime.GOOS == "windows" {
		if why := windowsNameProblem(path); why != "" {
			return nil, o.refuse(path+": "+why, "name a regular local file")
		}
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, o.refuse("cannot inspect "+path+": "+reason(err), "")
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return nil, o.refuse(path+" is a symbolic link; symlinks are refused", "name the file itself")
	case !fi.Mode().IsRegular():
		return nil, o.refuse(path+" is not a regular file (a directory, device or pipe)", "name a regular file")
	case fi.Size() > o.limit():
		return nil, o.refuse(fmt.Sprintf("%s is %d bytes, more than the %d bytes tailkeeper reads", path, fi.Size(), o.limit()), "")
	}
	return fi, nil
}

// reason is an error's text without the operation and path os repeats.
func reason(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// Read returns the bytes of the regular file at path, at most Cap of them.
func Read(path string, o Options) ([]byte, error) {
	want, err := inspect(path, o)
	if err != nil {
		return nil, err
	}
	id, err := identify(path, want)
	if err != nil {
		return nil, o.refuse("cannot inspect "+path+": "+reason(err), "")
	}
	afterLstat(path)
	f, err := openNoFollow(path)
	if err != nil {
		return nil, o.refuse("cannot open "+path+" without following a symlink: "+reason(err), "")
	}
	defer func() { _ = f.Close() }() // read only
	got, err := f.Stat()
	if err != nil {
		return nil, o.refuse("cannot inspect "+path+": "+reason(err), "")
	}
	same, err := id.is(f, got)
	if err != nil {
		return nil, o.refuse(path+" changed while it was being opened: "+reason(err), "run the command again; if it repeats, find what replaces the file")
	}
	if !got.Mode().IsRegular() || !same {
		return nil, o.refuse(path+" changed while it was being opened", "run the command again; if it repeats, find what replaces the file")
	}
	return readCapped(f, path, o)
}

// ReadAll reads r, standard input for `--from -`, with the same cap. name is how a
// message calls it.
func ReadAll(r io.Reader, name string, o Options) ([]byte, error) { return readCapped(r, name, o) }

func readCapped(r io.Reader, name string, o Options) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, o.limit()+1))
	if err != nil {
		return nil, o.refuse("cannot read "+name+": "+reason(err), "")
	}
	if int64(len(data)) > o.limit() {
		return nil, o.refuse(fmt.Sprintf("%s is more than the %d bytes tailkeeper reads", name, o.limit()), "")
	}
	return data, nil
}

// reserved are the Windows device names, which open a device whatever extension
// or directory they carry. COM and LPT come with the digits 0 to 9 and with the
// superscript digits 1 to 3.
var reserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true, "CONIN$": true, "CONOUT$": true,
	"COM\u00b9": true, "COM\u00b2": true, "COM\u00b3": true, "LPT\u00b9": true, "LPT\u00b2": true, "LPT\u00b3": true,
}

func init() {
	for i := '0'; i <= '9'; i++ {
		reserved["COM"+string(i)] = true
		reserved["LPT"+string(i)] = true
	}
}

func isSeparator(c rune) bool { return c == '\\' || c == '/' }

// windowsNameProblem says why a path is refused on Windows, or "": a UNC path or
// one with a \\?\, \\.\ or \??\ prefix (a network share, a device namespace or the
// NT object namespace; Windows reads / and \ alike, so any mix of the two counts),
// a name that is a device, and an alternate data stream (a colon past the drive
// letter). The \??\ prefix is refused because it names the same kind of path as
// \\?\; that Windows reads it so is not checked on a Windows host.
// It looks at the name only, so it is tested on every platform.
func windowsNameProblem(p string) string {
	const prefixed = `UNC paths and \\?\, \\.\ and \??\ paths are refused`
	if len(p) >= 2 && isSeparator(rune(p[0])) && isSeparator(rune(p[1])) {
		return prefixed
	}
	if len(p) >= 4 && isSeparator(rune(p[0])) && p[1] == '?' && p[2] == '?' && isSeparator(rune(p[3])) {
		return prefixed
	}
	rest := p
	if len(rest) >= 2 && rest[1] == ':' && (rest[0] >= 'A' && rest[0] <= 'Z' || rest[0] >= 'a' && rest[0] <= 'z') {
		rest = rest[2:]
	}
	if strings.Contains(rest, ":") {
		return "alternate data streams are refused"
	}
	for _, part := range strings.FieldsFunc(rest, isSeparator) {
		base, _, _ := strings.Cut(part, ".")
		if reserved[strings.ToUpper(strings.TrimRight(base, " "))] {
			return "device names are refused"
		}
	}
	return ""
}
