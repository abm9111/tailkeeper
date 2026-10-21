package tkerr

import (
	"strings"
	"testing"
)

// Whether a program may retry is the one thing every program hint must get
// right: a transient failure says to retry once, and every other code says that
// retrying the same call does not help.
func TestProgramHintsSayWhetherToRetry(t *testing.T) {
	retryable := map[Code]bool{APIRateLimited: true, UpstreamUnavailable: true, LocalTimeout: true, LocalRateLimited: true, ValidateRateLimited: true}
	for c := range declaredCodes(t) {
		h := strings.ToLower(ProgramHint(c))
		saysOnce := strings.Contains(h, "retry once")
		forbids := strings.Contains(h, "not retry") || strings.Contains(h, "retrying")
		switch {
		case retryable[c] && (!saysOnce || strings.Contains(h, "not retry")):
			t.Errorf("%s: %q must allow one retry", c, ProgramHint(c))
		case !retryable[c] && (saysOnce || !forbids):
			t.Errorf("%s: %q must say that retrying the same call does not help", c, ProgramHint(c))
		}
	}
}
