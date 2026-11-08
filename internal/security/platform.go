package security

// Operating-system names.
//
// A source reports an operating system in its own spelling. Tailscale's version.OS()
// (tailscale/tailscale, version/prop.go, read on the default branch on 30 October 2026)
// returns "tvOS" for the Apple TV network extension, "iOS" for GOOS "ios", "macOS" for GOOS
// "darwin", and runtime.GOOS for everything else; its own list of those strings,
// osEmoji in ipn/ipnstate/ipnstate.go, names linux, macOS, windows, iOS, tvOS, android,
// freebsd, openbsd, illumos and solaris. plan9 is a GOOS the daemon builds for (plan9
// build tags in the same repository, and a plan9 case in cmd/tailscaled/tailscaled.go).
// A local source may report the raw runtime.GOOS instead: "darwin" was observed for macOS
// and "ios" is its counterpart, so both raw spellings are read too.
//
// Six more GOOS values are passed through by version.OS() unchanged, and the same
// repository handles each as a platform of its own. The owner added them on 30 October
// 2026, after the evidence below was read (T1 report section 9, re-read for T2 in a
// checkout of the same commit, b6fc02d, committed 2026-10-30):
//
//	js         cmd/tailscaled/tailscaled.go:462 (case "js"); net/netmon/state.go:535;
//	           net/neterror/neterror_js.go:4 (//go:build js || wasip1 || wasm)
//	aix        cmd/tailscaled/tailscaled.go:85 (case "aix", "solaris", "illumos")
//	dragonfly  net/netutil/ip_forward.go:68 (case "dragonfly", "netbsd", "openbsd")
//	netbsd     net/netutil/ip_forward.go:68
//	tamago     net/netmon/state.go:535 (GOOS == "js" || GOOS == "tamago");
//	           logtail/filch/filch_stub.go:4
//	wasip1     net/neterror/neterror_js.go:4
//
// Each reads as itself (an identity entry). The vocabulary stays closed: a rule names a
// canonical value; a reported spelling is read through an exact, case-sensitive table, and
// one outside it is not guessed at (a rule then cannot be judged for that device:
// os_unrecognised). A spelling Tailscale adds reads as unrecognised until it is added here
// with its source, and no spelling is added from memory.

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
