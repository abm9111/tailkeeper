package cli

import (
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// A privacy key the owner appears to have set and that did not load leaves masking without
// pseudonyms, which nothing in a result would say: every tool call says it on standard
// error, once, before the call. The commands that are not tool calls do not: doctor reports
// the key itself, and the rest read no configuration.
func TestAPrivacyKeyThatDidNotLoadIsWarnedOnEveryToolCall(t *testing.T) {
	const note = "TAILKEEPER_PRIVACY_KEY is set but empty"
	h := newHarness(t, nil)
	h.app.Provider = config.Provider{Provider: "env"}
	h.app.PrivacyNote = note
	for i := 1; i <= 2; i++ {
		h.err.Reset()
		h.run("local", "version")
		if got := strings.Count(h.err.String(), "tailkeeper: warning: no privacy key was loaded ("+note+")"); got != 1 {
			t.Errorf("call %d: %d warnings, stderr %q", i, got, h.err)
		}
	}
	for _, args := range [][]string{{"version"}, {"scopes"}, {"self", "info"}, {"docs"}} {
		h.err.Reset()
		h.run(args...)
		if strings.Contains(h.err.String(), "privacy key") {
			t.Errorf("%v warned about the privacy key: %q", args, h.err)
		}
	}
	h.app.PrivacyNote = ""
	h.err.Reset()
	h.run("local", "version")
	if strings.Contains(h.err.String(), "privacy key") {
		t.Errorf("no note, and a warning: %q", h.err)
	}
}

// A privacy key that is set and malformed or unreadable leaves masking without pseudonyms
// too, and nothing in a result says so: each tool command says it on standard error, once,
// before the call, as the MCP server says it at start. Commands that are not tool calls and
// an absent key say nothing.
func TestAMalformedPrivacyKeyIsWarnedOnEveryToolCall(t *testing.T) {
	const typed = "zz-not-the-key-zz"
	const warning = "tailkeeper: the privacy key is malformed or unreadable (privacy_key_unavailable)"
	h := newHarness(t, nil)
	h.app.Provider = config.Provider{Provider: "env"}
	_, h.app.Env.PrivacyErr = privacy.Parse(typed)
	for i := 1; i <= 2; i++ {
		h.err.Reset()
		h.run("local", "version")
		if got := strings.Count(h.err.String(), warning); got != 1 || strings.Contains(h.err.String(), typed) {
			t.Errorf("call %d: %d warnings, stderr %q", i, got, h.err)
		}
	}
	for _, args := range [][]string{{"version"}, {"scopes"}, {"self", "info"}} {
		h.err.Reset()
		h.run(args...)
		if strings.Contains(h.err.String(), "privacy key") {
			t.Errorf("%v warned about the privacy key: %q", args, h.err)
		}
	}
	h.app.Env.PrivacyErr = tkerr.New(tkerr.PrivacyKeyUnavailable, "key file \u202ebad\x1b[2J", "")
	h.err.Reset()
	h.run("local", "version")
	if e := h.err.String(); strings.ContainsAny(e, "\u202e\x1b") || !strings.Contains(e, `\u{202E}bad\u{001B}[2J`) {
		t.Errorf("the warning prints an invisible character raw, or not escaped: %q", e)
	}
	h.app.Env.PrivacyErr = nil
	h.err.Reset()
	h.run("local", "version")
	if strings.Contains(h.err.String(), "privacy key") {
		t.Errorf("an absent key warned: %q", h.err)
	}
}
