package security

// Operating-system names as a source reports them. The table is closed, exact and
// case-sensitive: a spelling it does not name is not guessed at, and the device is then
// os_unrecognised. "darwin" and "ios" are the raw GOOS spellings of macOS and iOS.
// "js", "aix", "dragonfly", "netbsd", "tamago" and "wasip1" are read as themselves.

// NormaliseOS reads an operating-system name as a source reports it and returns the
// canonical name, or false when the spelling is not in the table. The table is exact:
// there is no case folding, trimming or prefix matching, and the canonical spellings
// "macos" and "tvos" are not themselves reported spellings.
func NormaliseOS(reported string) (string, bool) {
	switch reported {
	case "macOS", "darwin":
		return "macos", true
	case "iOS", "ios":
		return "ios", true
	case "tvOS":
		return "tvos", true
	case "linux", "windows", "android", "freebsd", "openbsd", "illumos", "solaris", "plan9",
		"js", "aix", "dragonfly", "netbsd", "tamago", "wasip1":
		return reported, true // reported as its canonical name
	}
	return "", false
}

// validOS reports whether os is a canonical name, the only kind a catalog rule may use.
func validOS(os string) bool {
	switch os {
	case "linux", "windows", "macos", "ios", "tvos", "android", "freebsd", "openbsd", "illumos", "solaris", "plan9",
		"js", "aix", "dragonfly", "netbsd", "tamago", "wasip1":
		return true
	}
	return false
}
