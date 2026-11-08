package security

import (
	"regexp"
	"strconv"
	"testing"
)

// releaseGrammar is the release grammar of the fix-wave design (C1), written out
// independently of the parser so the two can be compared.
var releaseGrammar = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-t[0-9a-f]{7,40}(-g[0-9a-f]{7,40})?)?$`)

// Synthetic hex only: none of these is a real commit.
const (
	relHex7        = "0123456"
	relHex9        = "0123456ab"
	relHex9g       = "fedcba987"
	relHex40       = "0123456789abcdef0123456789abcdef01234567"
	relHex41       = "0123456789abcdef0123456789abcdef012345678"
	relHex7Upper   = "0123456AB"
	relHex6        = "012345"
	relMaxDigits   = "999999999"
	relTenDigits   = "1234567890"
	relSuffixT9    = "-t" + relHex9
	relSuffixT9G9  = "-t" + relHex9 + "-g" + relHex9g
	relSuffixT7G40 = "-t" + relHex7 + "-g" + relHex40
)

func TestParseReleaseAcceptsExactlyTheBuildGrammar(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want numericVersion
	}{
		{"1.104.2", numericVersion{1, 104, 2}},
		{"1.104.2" + relSuffixT9, numericVersion{1, 104, 2}},
		{"1.104.2" + relSuffixT9G9, numericVersion{1, 104, 2}},
		{"2.0.0", numericVersion{2, 0, 0}},
		{"0.0.0", numericVersion{0, 0, 0}},
		{relMaxDigits + "." + relMaxDigits + "." + relMaxDigits, numericVersion{999999999, 999999999, 999999999}},
		{"1.104.2-t" + relHex7, numericVersion{1, 104, 2}},
		{"1.104.2-t" + relHex40, numericVersion{1, 104, 2}},
		{"1.104.2" + relSuffixT7G40, numericVersion{1, 104, 2}},
		{"1.104.2-t" + relHex40 + "-g" + relHex7, numericVersion{1, 104, 2}},
	} {
		t.Run(tc.in, func(t *testing.T) {
			if !releaseGrammar.MatchString(tc.in) {
				t.Fatal("the fixture is not in the grammar")
			}
			got, ok := parseRelease(tc.in)
			if !ok || got != tc.want {
				t.Fatalf("parseRelease(%q) = %v, %v; want %v, true", tc.in, got, ok, tc.want)
			}
		})
	}
}

func TestParseReleaseRejectsEverythingElse(t *testing.T) {
	for _, in := range []string{
		// The rejected vectors of the design.
		"1.104.2-g" + relHex9,      // -g without -t
		"1.104.2-t" + relHex6,      // six hex digits
		"1.104.2-t" + relHex7Upper, // uppercase hex
		"v1.104.2",
		"1.104",
		"1.104.2.1",
		"01.104.2",
		" 1.104.2",
		"1.104.2-dev20261030",
		"1.104.2-ERR-BuildInfo",
		"1.104.2+dfsg-1",
		"1.104.2-rc1",
		relTenDigits + ".1.1",
		"1." + relTenDigits + ".1",
		"1.1." + relTenDigits,
		// Further shapes next to the grammar.
		"",
		"-",
		"1.104.2-",
		"1.104.2-t",
		"1.104.2-" + relHex9,  // hex with no -t
		"1.104.2-" + relHex40, // hex with no -t
		"1.104.2-T" + relHex9,
		"1.104.2--t" + relHex9,
		"1.104.2" + relSuffixT9 + "-",
		"1.104.2" + relSuffixT9 + "-g",
		"1.104.2" + relSuffixT9 + "-" + relHex9g, // second hex with no -g
		"1.104.2" + relSuffixT9 + "-g" + relHex6,
		"1.104.2" + relSuffixT9 + "-g" + relHex7Upper,
		"1.104.2" + relSuffixT9 + "-G" + relHex9g,
		"1.104.2" + relSuffixT9 + "--g" + relHex9g,
		"1.104.2" + relSuffixT9 + "-t" + relHex9,
		"1.104.2" + relSuffixT9G9 + "-g" + relHex9g,
		"1.104.2" + relSuffixT9G9 + "-x",
		"1.104.2-t" + relHex41,
		"1.104.2" + relSuffixT9 + "-g" + relHex41,
		"1.104.2-t" + relHex7 + "g",
		"1.104.2 ",
		"1.104.2\n",
		"1.104.2\x00",
		"1.104.2" + relSuffixT9 + "\n",
		"1.104.2" + relSuffixT9 + " ",
		"1.104.2" + relSuffixT9G9 + " ",
		"1.104.2-t" + relHex7 + "é",
		"1.-1.2",
		"1.+1.2",
		"1..2",
		".1.2",
		"1.2.",
		"1,104,2",
		"１.104.2",          // fullwidth digit
		"١.104.2",          // Arabic-indic digit
		"1.104.2-t０123456", // fullwidth hex digit
	} {
		if releaseGrammar.MatchString(in) {
			t.Fatalf("the fixture %q is inside the grammar", in)
		}
		if got, ok := parseRelease(in); ok {
			t.Errorf("accepted %q as %v", in, got)
		}
	}
}

// Every combination of a core and a suffix is compared with the grammar, so the parser
// and the grammar cannot drift apart on a shape neither table above names.
func TestParseReleaseAgreesWithTheGrammar(t *testing.T) {
	cores := []string{
		"1.104.2", "0.0.0", "01.2.3", "1.2", "1.2.3.4", "1.02.3", "1.2.03", relMaxDigits + ".0.1", relTenDigits + ".0.1",
		"", "a.b.c", "1.2.3 ", " 1.2.3", "-1.2.3", "+1.2.3", "1,2,3", "1.2.3-", "1.2.3-1",
	}
	suffixes := []string{
		"", "-", "-t", "-" + relHex7, "-t" + relHex7, "-t" + relHex6, "-t" + relHex40, "-t" + relHex41, "-tABCDEF1", "-t" + relHex7 + "-g",
		"-t" + relHex7 + "-g" + relHex7, "-t" + relHex7 + "-g" + relHex6, "-g" + relHex7, "-t" + relHex7 + "-t" + relHex7,
		"-t" + relHex7 + "-g" + relHex7 + "-g" + relHex7, "-rc1", "-dev1", "+x", "-t" + relHex7 + "\n", "-T" + relHex7,
		"-t" + relHex7 + "-G" + relHex7, "--t" + relHex7, "-t" + relHex7 + " ", "-t" + relHex7 + "-g" + relHex40, "-t" + relHex7 + "-g" + relHex41,
	}
	for _, core := range cores {
		for _, suffix := range suffixes {
			in := core + suffix
			m := releaseGrammar.FindStringSubmatch(in)
			got, ok := parseRelease(in)
			if ok != (m != nil) {
				t.Fatalf("parseRelease(%q) ok=%v, grammar match=%v", in, ok, m != nil)
			}
			if !ok {
				continue
			}
			for i := 0; i < 3; i++ {
				n, err := strconv.ParseUint(m[i+1], 10, 64)
				if err != nil || got[i] != n {
					t.Fatalf("parseRelease(%q) component %d = %d, grammar says %q", in, i, got[i], m[i+1])
				}
			}
		}
	}
}

func TestParseReleaseSuffixNeverChangesTheRelease(t *testing.T) {
	bare, ok := parseRelease("1.104.2")
	if !ok {
		t.Fatal("bare release rejected")
	}
	for _, suffix := range []string{relSuffixT9, relSuffixT9G9, "-t" + relHex40 + "-g" + relHex40} {
		if got, ok := parseRelease("1.104.2" + suffix); !ok || got != bare {
			t.Errorf("suffix %q changed the release: %v %v", suffix, got, ok)
		}
	}
	// The strict bare parser, used for catalog bounds, still refuses every suffix.
	for _, in := range []string{"1.104.2" + relSuffixT9, "1.104.2" + relSuffixT9G9} {
		if _, ok := parseVersion(in); ok {
			t.Errorf("parseVersion accepted %q", in)
		}
	}
}

func TestCompareVersionsComparesEveryComponent(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b numericVersion
		want int
	}{
		{"equal", numericVersion{1, 104, 2}, numericVersion{1, 104, 2}, 0},
		{"zero", numericVersion{0, 0, 0}, numericVersion{0, 0, 0}, 0},
		{"major only", numericVersion{2, 104, 2}, numericVersion{1, 104, 2}, 1},
		{"major outweighs minor and patch", numericVersion{2, 0, 0}, numericVersion{1, 999999999, 999999999}, 1},
		{"minor only", numericVersion{1, 105, 2}, numericVersion{1, 104, 2}, 1},
		{"minor outweighs patch", numericVersion{1, 105, 0}, numericVersion{1, 104, 999999999}, 1},
		{"patch only", numericVersion{1, 104, 3}, numericVersion{1, 104, 2}, 1},
		{"zero major", numericVersion{0, 1, 0}, numericVersion{0, 0, 9}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := compareVersions(tc.a, tc.b); got != tc.want {
				t.Errorf("compareVersions(%v, %v) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			if got := compareVersions(tc.b, tc.a); got != -tc.want {
				t.Errorf("compareVersions(%v, %v) = %d, want %d", tc.b, tc.a, got, -tc.want)
			}
		})
	}
}

func TestTrackReason(t *testing.T) {
	for _, tc := range []struct {
		name    string
		channel VersionChannel
		version numericVersion
		want    UnknownReason
	}{
		{"stable even minor", ChannelStable, numericVersion{1, 104, 2}, ""},
		{"stable minor zero", ChannelStable, numericVersion{1, 0, 0}, ""},
		{"stable odd minor", ChannelStable, numericVersion{1, 105, 0}, ReasonUnstableTrack},
		{"unstable even minor", ChannelUnstable, numericVersion{1, 104, 2}, ReasonUnstableTrack},
		{"unstable odd minor", ChannelUnstable, numericVersion{1, 105, 0}, ReasonUnstableTrack},
		{"unknown channel even minor", ChannelUnknown, numericVersion{1, 104, 2}, ReasonChannelUnknown},
		{"unknown channel odd minor", ChannelUnknown, numericVersion{1, 105, 0}, ReasonChannelUnknown},
		{"empty channel", "", numericVersion{1, 104, 2}, ReasonChannelUnknown},
		{"foreign channel", "beta", numericVersion{1, 104, 2}, ReasonChannelUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := trackReason(tc.channel, tc.version); got != tc.want {
				t.Fatalf("trackReason(%q, %v) = %q, want %q", tc.channel, tc.version, got, tc.want)
			}
		})
	}
}

// Every byte value at every position of a version is judged as the grammar judges it, so a
// range of characters cannot be shifted by one at either end without a test failing: the
// digits of the release, and the hex digits of each build part.
func TestParseReleaseJudgesEveryByteAtEveryPositionLikeTheGrammar(t *testing.T) {
	for _, base := range []string{
		"1.104.2",
		"1.104.2" + relSuffixT9,
		"1.104.2" + relSuffixT9G9,
	} {
		for pos := 0; pos < len(base); pos++ {
			for b := 0; b < 256; b++ {
				in := base[:pos] + string([]byte{byte(b)}) + base[pos+1:]
				_, ok := parseRelease(in)
				if want := releaseGrammar.MatchString(in); ok != want {
					t.Fatalf("parseRelease(%q) accepted = %v, the grammar says %v", in, ok, want)
				}
			}
		}
	}
}
