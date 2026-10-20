package creds

import (
	"context"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// A TAILKEEPER_REEXEC inherited from a parent process looks like a wrapper that
// ran. The message says what tailkeeper concluded from the variable, so the owner
// who sees it with no wrapper configured knows to unset it.
func TestNoCredentialAfterTheMarkerNamesTheMarker(t *testing.T) {
	p := config.Provider{Provider: "exec", Command: []string{"/usr/bin/true"}}
	_, err := Resolve(context.Background(), p, sys(map[string]string{EnvReexec: "1"}, nil))
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.CredentialUnavailable {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{EnvReexec + "=1 is set, so tailkeeper took the exec wrapper to have run, but no credential came with it"} {
		if !strings.Contains(e.Message, want) {
			t.Errorf("message %q lacks %q", e.Message, want)
		}
	}
	for _, want := range []string{"check the wrapper's env file", "if no wrapper ran, " + EnvReexec + " was inherited from a parent process: unset it"} {
		if !strings.Contains(e.Hint, want) {
			t.Errorf("hint %q lacks %q", e.Hint, want)
		}
	}
}

// The "fix" for a missing credential is an action, and the explanation of the TS_*
// variables stays as a second sentence.
func TestNoCredentialHintIsAnAction(t *testing.T) {
	_, err := Resolve(context.Background(), config.Provider{Provider: "env"}, sys(nil, nil))
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.CredentialUnavailable {
		t.Fatalf("err = %v", err)
	}
	want := "set " + EnvClientID + " and " + EnvClientSecret + " (or " + EnvAPIKey + ") where the provider reads them (README, Configure); tailkeeper ignores TS_* and TAILSCALE_* variables on purpose"
	if e.Hint != want {
		t.Errorf("hint = %q, want %q", e.Hint, want)
	}
}
