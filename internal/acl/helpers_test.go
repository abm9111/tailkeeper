package acl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture reads a policy from testdata/policies. The directory is byte-exact in git
// (.gitattributes), which the CRLF, byte order mark and UTF-16 fixtures depend on.
func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "policies", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustParse(t testing.TB, text string) *Doc {
	t.Helper()
	d, err := Parse(context.Background(), []byte(text))
	if err != nil {
		t.Fatalf("Parse(%q): %v", text, err)
	}
	return d
}

// parseError parses text and returns the engine error it must produce.
func parseError(t testing.TB, text string) *Error {
	t.Helper()
	_, err := Parse(context.Background(), []byte(text))
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("Parse(%.60q) = %v, want an *Error", text, err)
	}
	return e
}

// replaceOnce replaces the first occurrence of old in s, and panics if there is none: a
// vector that no longer contains what it changes would pass vacuously.
func replaceOnce(s, old, repl string) string {
	i := strings.Index(s, old)
	if i < 0 {
		panic("replaceOnce: " + old + " is not in " + s)
	}
	return s[:i] + repl + s[i+len(old):]
}
