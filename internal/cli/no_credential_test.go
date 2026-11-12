package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/app"
)

func TestCredentialFreeToolUsesItsOwnBuilder(t *testing.T) {
	h := newHarness(t, nil)
	withFixture(t, h)
	normal, none := 0, 0
	h.r.Build = func(context.Context, string) (*app.App, error) { normal++; return h.app, nil }
	h.r.BuildNoCredential = func(context.Context, string) (*app.App, error) { none++; return h.app, nil }
	if got := h.run("gate", "check", "--status", "pass", "--json"); got != 0 {
		t.Fatalf("exit %d: %s", got, h.err)
	}
	if normal != 0 || none != 1 || h.reexecProvider != nil || strings.Contains(h.err.String(), "credential_unavailable") {
		t.Errorf("builders=%d/%d wrapper=%v stderr=%s", normal, none, h.reexecProvider, h.err)
	}
	h.out.Reset()
	h.err.Reset()
	if got := h.run("fixture", "check", "--json"); got != 0 {
		t.Fatalf("read tool exit %d: %s", got, h.err)
	}
	if normal != 1 || none != 1 {
		t.Errorf("builders=%d/%d", normal, none)
	}
}
