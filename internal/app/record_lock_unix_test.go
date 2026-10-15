//go:build !windows

package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// An unavailable log is not a refused line: Record must report it at once, not
// retry with the withheld fallback. Retried, it waited twice as long and, once the
// lock came free, wrote a stripped line_withheld entry and returned nil.
func TestRecordDoesNotRetryAnUnavailableLog(t *testing.T) {
	f := apitest.New(t)
	env := map[string]string{creds.EnvClientID: apitest.ClientID, creds.EnvClientSecret: apitest.ClientSecret}
	d := dirs(t, envConfig)
	a, err := Build(context.Background(), Options{Dirs: d, Stat: noCLI, Getenv: func(k string) string { return env[k] },
		API: api.Options{BaseURL: f.URL(), Sleep: func(context.Context, time.Duration) error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	const wait = 300 * time.Millisecond
	a.Audit.SetLockWait(wait)
	path := filepath.Join(d.Logs, "audit.jsonl")
	holder, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	// Free the lock after the first wait has ended but inside a retry's wait.
	freed := make(chan struct{})
	go func() {
		defer close(freed)
		time.Sleep(wait + wait/2)
		_ = syscall.Flock(int(holder.Fd()), syscall.LOCK_UN)
	}()
	defer func() { <-freed }() // before the deferred Close
	err = a.Record(map[string]any{"tool": "devices_list", "bytes": 10})
	if e := tkerr.From(err); err == nil || e.Code != tkerr.AuditUnavailable {
		t.Fatalf("Record under a held lock = %v, want audit_unavailable", err)
	}
	time.Sleep(wait) // past the moment a retry would have written
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "" {
		t.Errorf("audit log = %s, want nothing written", data)
	}
}
