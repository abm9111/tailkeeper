package cli

import (
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
)

// With no intent set nothing is asked of Tailscale, so no credential is needed: the wrapper of the
// exec provider is not started for it, and a command with no credential at all says the same.
func TestExplainNoIntentNeedsNoCredential(t *testing.T) {
	t.Run("no credential configured", func(t *testing.T) {
		h := newHarness(t, nil)
		if code := h.explain(t, ""); code != 1 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
		if !strings.Contains(h.out.String(), "no intent set: nothing explained") {
			t.Errorf("output %q", h.out)
		}
	})
	t.Run("the exec provider's wrapper is not started", func(t *testing.T) {
		h := newHarness(t, nil)
		h.app.Env.APIErr = creds.ErrReexecRequired
		if code := h.explain(t, ""); code != 1 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
		if h.reexecProvider != nil {
			t.Error("the wrapper of the exec provider was started to explain nothing")
		}
		if !strings.Contains(h.out.String(), "no intent set: nothing explained") {
			t.Errorf("output %q", h.out)
		}
	})
	t.Run("an intent file named on the command line starts it", func(t *testing.T) {
		h := newHarness(t, nil)
		h.app.Env.APIErr = creds.ErrReexecRequired
		h.explain(t, writeIntent(t, cliExplainIntent))
		if h.reexecProvider == nil {
			t.Error("a run with an intent file did not start the wrapper that holds the credential")
		}
	})
	t.Run("a configured intent file starts it", func(t *testing.T) {
		h := newHarness(t, nil)
		h.app.Env.APIErr = creds.ErrReexecRequired
		h.app.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: "/no/such/file.hujson"}}}
		h.explain(t, "")
		if h.reexecProvider == nil {
			t.Error("a run with a configured intent file did not start the wrapper that holds the credential")
		}
	})
}
