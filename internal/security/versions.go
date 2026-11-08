package security

import (
	"strconv"
	"strings"
)

type numericVersion [3]uint64

// parseVersion accepts only three canonical decimal components. Suffixes are never proof of a fix.
// It is the parser for catalog range bounds, which are bare releases.
func parseVersion(s string) (numericVersion, bool) {
	var v numericVersion
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		if p == "" || len(p) > 9 || (len(p) > 1 && p[0] == '0') {
			return v, false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return v, false
			}
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// parseRelease reads the version of a version fact. It accepts exactly
//
//	^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-t[0-9a-f]{7,40}(-g[0-9a-f]{7,40})?)?$
//
// that is, a release X.Y.Z optionally followed by the build suffix Tailscale appends,
// -t<hex> or -t<hex>-g<hex>, and returns the release. The suffix is dropped for matching
// (the caller keeps the raw string as evidence); no other suffix, prefix, space or spelling
// is read as a release, so anything else is an unrecognised build. A fixed release never
// depends on the commit a build names: Tailscale states fixes by release.
func parseRelease(s string) (numericVersion, bool) {
	core, build, hasBuild := strings.Cut(s, "-")
	v, ok := parseVersion(core)
	if !ok || (hasBuild && !validBuildSuffix(build)) {
		return numericVersion{}, false
	}
	return v, true
}

// validBuildSuffix reports whether b, the text after the first hyphen of a version, is
// t<hex> or t<hex>-g<hex> with 7 to 40 lowercase hexadecimal digits in each hex part.
func validBuildSuffix(b string) bool {
	rest, ok := strings.CutPrefix(b, "t")
	if !ok {
		return false
	}
	hash, g, hasG := strings.Cut(rest, "-")
	if !lowerHex(hash) {
		return false
	}
	if !hasG {
		return true
	}
	gHash, ok := strings.CutPrefix(g, "g")
	return ok && lowerHex(gHash)
}

func lowerHex(s string) bool {
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// trackReason says why a version fact cannot be compared with a range, or returns the
// empty reason when it can. A fact is evaluated only when its channel is stable and the
// minor of its release is even: Tailscale numbers stable releases with even minors and
// unstable ones with odd minors, and a fix on the unstable track says nothing about the
// stable one. An unknown channel gives channel_unknown, whatever the minor; an unstable
// channel, or an odd minor, gives unstable_track. Any channel value other than stable or
// unstable is treated as unknown.
func trackReason(channel VersionChannel, v numericVersion) UnknownReason {
	switch channel {
	case ChannelStable:
		if v[1]%2 != 0 {
			return ReasonUnstableTrack
		}
		return ""
	case ChannelUnstable:
		return ReasonUnstableTrack
	default:
		return ReasonChannelUnknown
	}
}

// compareVersions orders two releases by major, then minor, then patch.
func compareVersions(a, b numericVersion) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
