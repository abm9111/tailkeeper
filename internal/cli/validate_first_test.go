package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
)

// execHarness is a harness whose credential still has to come from the exec
// provider's wrapper, with a count of the times Build ran.
func execHarness(t *testing.T) (*harness, *int) {
	t.Helper()
	h := newHarness(t, nil)
	h.app.Env.APIErr = creds.ErrReexecRequired
	h.app.Provider = config.Provider{Provider: "exec", Command: []string{"/usr/local/bin/op", "run", "--"}}
	builds := 0
	h.r.Build = func(context.Context, string) (*app.App, error) { builds++; return h.app, nil }
	return h, &builds
}

// A value the tool refuses must not cost a secret-manager unlock: the wrapper is
// the exec provider's unlock, and the configuration is not even loaded.
func TestBadArgumentsNeverStartTheWrapper(t *testing.T) {
	// refused runs one command line and checks that it is refused with exit 2 and
	// the given error code, with the wrapper never started.
	refused := func(args []string, code string) {
		t.Helper()
		h, builds := execHarness(t)
		if exit := h.run(args...); exit != 2 {
			t.Errorf("%v: exit %d, want 2 (stderr %q)", args, exit, h.err)
		}
		if h.reexecProvider != nil || *builds != 0 {
			t.Errorf("%v: the wrapper started (%v) or the configuration loaded (%d times) for input the tool refuses", args, h.reexecProvider != nil, *builds)
		}
		if !strings.HasPrefix(h.err.String(), "tailkeeper: "+code+": ") {
			t.Errorf("%v: stderr = %q, want the code %s", args, h.err, code)
		}
	}
	// The flag layer refuses a value that is not an integer before the tool sees it.
	refused([]string{"logs", "network", "--max-records", "0x"}, "usage")
	// A policy and a patch are one group of flags: the binder refuses both of them.
	refused([]string{"acl", "validate", "--from", "a.hujson", "--patch", "b.json"}, "usage")
	refused([]string{"acl", "diff", "--from", "a.hujson", "--patch", "b.json"}, "usage")
	for _, args := range [][]string{
		{"acl", "test", "tag:ci"},                                               // no destination
		{"acl", "test", "tag:ci", "--accept", "tag:prod"},                       // not host:port
		{"acl", "get", "--max-bytes", "5"},                                      // below the page minimum
		{"acl", "get", "--view", "raw"},                                         // not a view
		{"acl", "get", "--view", "summary", "--from-line", "2"},                 // the summary has no pages
		{"acl", "diff", "--section", "nope"},                                    // not a section
		{"devices", "list", "--stale-days", "9999"},                             // out of range
		{"devices", "list", "--tags", "prod"},                                   // not tag:name
		{"users", "list", "--type", "robot"},                                    // unknown type
		{"users", "list", "--role", "wizard"},                                   // unknown role
		{"logs", "audit", "--limit", "99999"},                                   // out of range
		{"logs", "audit", "--cursor", "abc", "--start", "2026-01-01T00:00:00Z"}, // a cursor fixes the window
		{"logs", "network", "--max-records", "99999"},                           // out of range
		{"logs", "streaming", "--log-type", "audit"},                            // unknown log type
		{"keys", "get", "bad id"},                                               // not an identifier
		{"users", "get", "bad id"},
		{"webhooks", "get", "bad id"},
		{"invites", "device", "bad id"},
		{"devices", "get", " "}, // empty after trimming
		{"devices", "routes", " "},
		{"devices", "posture", " "},
		{"invites", "devices", " "},
		{"logs", "audit", "--start", "garbage"}, // not a time
		{"logs", "audit", "--cursor", "abc"},    // no page issued it
		{"logs", "audit", "--start", "2026-01-02T00:00:00Z", "--end", "2026-01-01T00:00:00Z"},
		{"logs", "network", "--start", "garbage"},
		{"logs", "network", "--start", "2026-01-01T00:00:00Z", "--end", "2026-01-01T03:00:00Z"}, // over an hour
	} {
		refused(args, "validation_failed")
	}
}

// The control: the same harness does start the wrapper for a valid command line,
// so the test above would notice a wrapper that started.
func TestValidArgumentsStartTheWrapper(t *testing.T) {
	for _, args := range [][]string{{"acl", "test", "tag:ci", "--accept", "tag:prod:22"}, {"acl", "get", "--view", "summary"}, {"acl", "diff", "--section", "groups"}, {"devices", "list", "--stale-days", "30"},
		{"logs", "audit", "--limit", "10"}, {"keys", "get", "kABC123CNTRL"}} {
		h, builds := execHarness(t)
		h.run(args...)
		if h.reexecProvider == nil || *builds != 1 {
			t.Errorf("%v: wrapper started %v, Build ran %d times; want true and 1", args, h.reexecProvider != nil, *builds)
		}
	}
}

// The error a refused value gets is the tool's own, masked, as MCP gives it.
func TestAValidationErrorIsTheToolsOwnAndMasked(t *testing.T) {
	h, _ := execHarness(t)
	if code := h.run("acl", "test", "amy@example.com"); code != 2 || !strings.Contains(h.err.String(), "give at least one destination") ||
		strings.Contains(h.err.String(), "amy@") {
		t.Errorf("exit %d, stderr %q", code, h.err)
	}
}
