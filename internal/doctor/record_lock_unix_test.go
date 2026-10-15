//go:build !windows

package doctor

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// When doctor's own reads cannot be recorded, the audit-log check must say so
// instead of reporting ok.
func TestUnrecordedReadsWarnInTheAuditLogCheck(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","expires":"2027-01-01T00:00:00Z"}`)
	const wait = 300 * time.Millisecond
	a.Audit.SetLockWait(wait)
	holder, err := os.OpenFile(a.Audit.Path(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	r := Run(context.Background(), Input{App: a, Now: now})
	// Doctor stops recording after the first failure: one wait, not one per read.
	if took := time.Since(start); took > 2*wait {
		t.Errorf("doctor took %s under a held lock, want about one %s wait", took, wait)
	}
	for _, c := range r.Checks {
		if c.Name == "audit log" {
			if c.Status != Warn || !strings.Contains(c.Detail, "were not recorded") || !strings.Contains(c.Detail, "stayed locked") {
				t.Errorf("audit log check = %+v, want a warning that doctor's reads were not recorded", c)
			}
			return
		}
	}
	t.Fatal("no audit log check")
}
