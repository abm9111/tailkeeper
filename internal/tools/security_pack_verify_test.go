package tools

import (
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

// An owner must be able to invoke verify without exposing it to MCP callers.
func TestSecurityVerifyRegisteredForOwnerOnly(t *testing.T) {
	owner := registry.New()
	RegisterOwnerOnly(owner)
	if _, ok := owner.Get("security_verify"); !ok {
		t.Fatal("security verify is not registered for the owner")
	}
	shared := registry.New()
	Register(shared)
	if _, ok := shared.Get("security_verify"); ok {
		t.Fatal("security verify is exposed to MCP callers")
	}
}
