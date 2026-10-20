package acl

import (
	"bytes"
	"testing"
)

// A fixture that exists for a byte property must still have it: a checkout that rewrote
// line ends would make the CRLF tests pass without testing anything.
func TestFixturesKeepTheBytesTheyExistFor(t *testing.T) {
	if b := fixture(t, "crlf.hujson"); !bytes.Contains(b, []byte("\r\n")) || bytes.Count(b, []byte("\r\n")) != bytes.Count(b, []byte("\n")) {
		t.Error("crlf.hujson: not every line feed follows a carriage return")
	}
	if b := fixture(t, "bom.hujson"); !bytes.HasPrefix(b, []byte("\xef\xbb\xbf")) {
		t.Error("bom.hujson does not start with a UTF-8 byte order mark")
	}
	if b := fixture(t, "utf16le.hujson"); !bytes.HasPrefix(b, []byte("\xff\xfe")) || !bytes.Contains(b, []byte{0}) {
		t.Error("utf16le.hujson is not UTF-16 little endian with a byte order mark")
	}
	if b := fixture(t, "lone-cr.hujson"); bytes.Contains(b, []byte("\n")) || !bytes.Contains(b, []byte("\r")) {
		t.Error("lone-cr.hujson must hold carriage returns and no line feed")
	}
	if b := fixture(t, "basic.hujson"); !bytes.Contains(b, []byte("\t")) || bytes.Contains(b, []byte("\r")) {
		t.Error("basic.hujson must be indented with tabs and use line feeds only")
	}
}
