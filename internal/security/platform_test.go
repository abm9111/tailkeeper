package security

import "testing"

// specOSTable is the exact mapping table of the design (C2) with the six identity values
// the owner added after T1 (js, aix, dragonfly, netbsd, tamago, wasip1: Go GOOS names that
// version.OS() passes through unchanged): every operating-system spelling a source may
// report, and the canonical name it reads as.
var specOSTable = map[string]string{
	"linux":   "linux",
	"windows": "windows",
	"macOS":   "macos",
	"darwin":  "macos",
	"iOS":     "ios",
	"ios":     "ios",
	"tvOS":    "tvos",
	"android": "android",
	"freebsd": "freebsd",
	"openbsd": "openbsd",
	"illumos": "illumos",
	"solaris": "solaris",
	"plan9":   "plan9",

	"js":        "js",
	"aix":       "aix",
	"dragonfly": "dragonfly",
	"netbsd":    "netbsd",
	"tamago":    "tamago",
	"wasip1":    "wasip1",
}

var specCanonicalOS = []string{"linux", "windows", "macos", "ios", "tvos", "android", "freebsd", "openbsd", "illumos", "solaris", "plan9", "js", "aix", "dragonfly", "netbsd", "tamago", "wasip1"}

func TestNormaliseOSMapsTheExactTable(t *testing.T) {
	for in, want := range specOSTable {
		got, ok := NormaliseOS(in)
		if !ok || got != want {
			t.Errorf("NormaliseOS(%q) = %q, %v; want %q, true", in, got, ok, want)
		}
	}
}

// The mapping is exact and case-sensitive: nothing is trimmed, folded or guessed.
func TestNormaliseOSRejectsEverythingElse(t *testing.T) {
	for _, in := range []string{
		"", " ", "Linux", "LINUX", "linux ", " linux", "linux\n", "linux\x00", "linux-gnu",
		"Windows", "WINDOWS", "win32", "win",
		"macos", "MacOS", "MACOS", "osx", "OSX", "mac", "macOS 14", "macOS ",
		"Darwin", "DARWIN",
		"IOS", "Ios", "ipados", "iPadOS",
		"tvos", "TVOS",
		"Android", "FreeBSD", "OpenBSD", "Illumos", "SunOS", "Solaris", "Plan9", "plan 9", "plan9 ",
		"JS", "Js", "AIX", "Aix", "Dragonfly", "DragonFly", "NetBSD", "Netbsd", "TamaGo", "Tamago", "WASIP1", "wasi", "wasip2", "wasm", "js/wasm", "js ", " js",
		"nacl", "zos", "ios ", "unknown", "other", "apple",
	} {
		if got, ok := NormaliseOS(in); ok || got != "" {
			t.Errorf("NormaliseOS(%q) = %q, %v; want no match", in, got, ok)
		}
	}
}

func TestCanonicalOSVocabularyIsClosedAndReachable(t *testing.T) {
	canonical := map[string]bool{}
	for _, c := range specCanonicalOS {
		canonical[c] = true
		if !validOS(c) {
			t.Errorf("canonical name %q is not valid", c)
		}
	}
	// Every spelling reads as a canonical name, and every canonical name has a spelling.
	image := map[string]bool{}
	for in := range specOSTable {
		got, ok := NormaliseOS(in)
		if !ok || !canonical[got] {
			t.Errorf("%q reads as %q, which is not canonical", in, got)
		}
		image[got] = true
	}
	for _, c := range specCanonicalOS {
		if !image[c] {
			t.Errorf("no reported spelling reads as %q", c)
		}
	}
	// A rule names a canonical value only: a reported spelling that differs is refused.
	for _, bad := range []string{"", "Linux", "LINUX", "macOS", "darwin", "iOS", "tvOS", "Windows", "unknown", "beos", "NetBSD", "linux ", " linux"} {
		if validOS(bad) {
			t.Errorf("accepted %q as a canonical name", bad)
		}
	}
}
