//go:build !windows

package mcpserver

import (
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The audit warning reports each outage once: a brief lock timeout must not use
// it up, so a later failure, after reads were recorded again, warns again.
func TestAuditWarningRearmsAfterRecovery(t *testing.T) {
	a := newApp(t, nil)
	a.Audit.SetLockWait(50 * time.Millisecond)
	var mu sync.Mutex
	var warnings []string
	cs := connect(t, a, Options{Warn: func(s string) {
		mu.Lock()
		defer mu.Unlock()
		warnings = append(warnings, s)
	}})
	holder, err := os.OpenFile(a.AuditPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	lock := func(how int) {
		t.Helper()
		if err := syscall.Flock(int(holder.Fd()), how); err != nil {
			t.Fatal(err)
		}
	}
	lock(syscall.LOCK_EX) // outage 1: two reads, one warning
	callTool(t, cs, "local_status", map[string]any{})
	callTool(t, cs, "local_version", map[string]any{})
	lock(syscall.LOCK_UN)
	callTool(t, cs, "local_status", map[string]any{}) // recorded: the warning re-arms
	lock(syscall.LOCK_EX)                             // outage 2: warns again
	callTool(t, cs, "local_status", map[string]any{})
	lock(syscall.LOCK_UN)
	mu.Lock()
	defer mu.Unlock()
	if len(warnings) != 2 || !strings.Contains(warnings[0], "stayed locked") || !strings.Contains(warnings[1], "stayed locked") {
		t.Errorf("warnings = %q, want one per outage", warnings)
	}
}
