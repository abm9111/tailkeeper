package mcpserver

import (
	"strings"
	"sync"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
)

// A privacy key that looks set and did not load is said once at startup, in the same place
// and way as a malformed one; one that failed is said by the warning for failures alone.
func TestAPrivacyKeyThatDidNotLoadWarnsOnceAtStartup(t *testing.T) {
	const note = "TAILKEEPER_PRIVACY_KEY is set but empty"
	var mu sync.Mutex
	var warnings []string
	warn := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		warnings = append(warnings, s)
	}
	a := newApp(t, nil)
	a.Provider, a.PrivacyNote = config.Provider{Provider: "env"}, note
	cs := connect(t, a, Options{Warn: warn})
	callTool(t, cs, "local_status", map[string]any{})
	callTool(t, cs, "local_version", map[string]any{})
	mu.Lock()
	got := append([]string(nil), warnings...)
	warnings = nil
	mu.Unlock()
	if len(got) != 1 || !strings.Contains(got[0], "no privacy key was loaded ("+note+")") {
		t.Errorf("warnings = %q, want one that says the key did not load", got)
	}
	b := newApp(t, nil)
	b.Provider, b.PrivacyNote = config.Provider{Provider: "env"}, note
	_, b.Env.PrivacyErr = privacy.Parse("zz")
	connect(t, b, Options{Warn: warn})
	mu.Lock()
	defer mu.Unlock()
	if len(warnings) != 1 || strings.Contains(warnings[0], "no privacy key was loaded") {
		t.Errorf("a key that failed: warnings = %q, want only the warning for a malformed key", warnings)
	}
}
