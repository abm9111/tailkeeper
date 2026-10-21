package api

import (
	"testing"
	"time"
)

func TestWholeSecondsRoundsUpAndIsCutAtADay(t *testing.T) {
	for _, c := range []struct {
		wait time.Duration
		want int
	}{
		{0, 0},
		{time.Nanosecond, 1},
		{time.Second, 1},
		{time.Second + time.Nanosecond, 2},
		{59500 * time.Millisecond, 60},
		{maxRetryAfter, 86400},
		{100 * time.Hour, 86400},
	} {
		if got := wholeSeconds(c.wait); got != c.want {
			t.Errorf("wholeSeconds(%v) = %d, want %d", c.wait, got, c.want)
		}
	}
}
