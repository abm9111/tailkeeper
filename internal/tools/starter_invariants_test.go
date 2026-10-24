package tools

import (
	"context"
	"os"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
)

func TestTheStarterIsAnInvariantsFileTheValidatorAccepts(t *testing.T) {
	b, err := os.ReadFile("testdata/starter.hujson")
	if err != nil {
		t.Fatal(err)
	}
	set, problems, err := parseInvariants(context.Background(), string(b))
	if err != nil || len(problems) != 0 || set == nil || len(set.Tests) != 1 || len(set.SSHTests) != 0 {
		t.Fatalf("parseInvariants: set=%v problems=%v err=%v", set, problems, err)
	}
	out, err := aclValidate(context.Background(), &registry.Env{}, ACLValidateInput{Offline: true, Invariants: string(b)})
	if err != nil || out.Status != statusPass || out.ExitCode() != 0 {
		t.Fatalf("offline validate: status %s exit %d err %v", out.Status, out.ExitCode(), err)
	}
}
