package api

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// aDay is the longest wait parseRetryAfter reports: a longer Retry-After is read as this long.
const aDay = 24 * time.Hour

func TestParseRetryAfterClampsHugeSeconds(t *testing.T) {
	for _, c := range []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"", 0, false},
		{"abc", 0, false},
		{"-5", 0, false},
		{"0", 0, true},
		{"7", 7 * time.Second, true},
		{" 7 ", 7 * time.Second, true},
		{"86400", aDay, true},
		{"86401", aDay, true},
		// 9.3e9 s is 9.3e18 ns, past the 9.22e18 of an int64: it used to wrap to a negative duration.
		{"9300000000", aDay, true},
		// A count of seconds of any length is a count of seconds: one past the largest int64,
		// more than any integer, and a run of digits longer than any number type holds all
		// ask for a very long wait, and are read as the longest one.
		{"9223372036854775807", aDay, true},
		{"9223372036854775808", aDay, true},
		{"99999999999999999999", aDay, true},
		{" 99999999999999999999 ", aDay, true},
		{strings.Repeat("9", 400), aDay, true},
		{"000000000000000000000000000000000000007", 7 * time.Second, true},
		// A sign, a fraction or a letter among the digits is not a count of seconds.
		{"-99999999999999999999", 0, false},
		{"99999999999999999999.5", 0, false},
		{"99999999999999999999s", 0, false},
	} {
		got, ok := parseRetryAfter(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseRetryAfter(%.40q) = %v, %v; want %v, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestParseRetryAfterReadsDatesAheadAndIgnoresDatesPast(t *testing.T) {
	date := func(d time.Duration) string { return time.Now().Add(d).UTC().Format(http.TimeFormat) }
	if got, ok := parseRetryAfter(date(-time.Hour)); ok || got != 0 {
		t.Errorf("a date an hour ago = %v, %v; want 0, false", got, ok)
	}
	if got, ok := parseRetryAfter(date(time.Minute)); !ok || got < 30*time.Second || got > time.Minute {
		t.Errorf("a date a minute ahead = %v, %v; want between 30s and 1m", got, ok)
	}
	if got, ok := parseRetryAfter(date(7 * 24 * time.Hour)); !ok || got != aDay {
		t.Errorf("a date a week ahead = %v, %v; want %v", got, ok, aDay)
	}
}
