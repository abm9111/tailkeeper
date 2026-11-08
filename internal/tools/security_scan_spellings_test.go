package tools_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// One invariants file that uses the deprecated spellings of a test (user for src, allow for
// accept) is taken by `acl validate`'s loader and by a scan alike, and both read the same
// assertions in it as in the file written in the current spellings: the normal form of
// internal/acl is the same, and the scan names the same number of expectations.
func TestAnInvariantsFileWithLegacySpellingsIsTakenByTheLoaderAndTheScanAlike(t *testing.T) {
	const legacy = `{
	"tests": [
		{"user": "owner-one@example.com", "allow": ["tag:db-one:5432"], "deny": ["tag:vault-one:22"]},
		{"src": "tag:ci-one", "accept": ["tag:db-one:5432"], "allow": ["tag:db-one:6432"]},
	],
	"sshTests": [
		{"src": "tag:ci-one", "dst": ["tag:ssh-one"], "allow": ["root"], "check": ["ops"]},
	],
}
`
	const current = `{
	"tests": [
		{"src": "owner-one@example.com", "accept": ["tag:db-one:5432"], "deny": ["tag:vault-one:22"]},
		{"src": "tag:ci-one", "accept": ["tag:db-one:5432", "tag:db-one:6432"]},
	],
	"sshTests": [
		{"src": "tag:ci-one", "dst": ["tag:ssh-one"], "accept": ["root"], "check": ["ops"]},
	],
}
`
	normalForm := func(text string) string {
		d, err := acl.Parse(context.Background(), []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		b, err := acl.NormalFormBytes(context.Background(), d)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if normalForm(legacy) != normalForm(current) {
		t.Fatal("the premise: internal/acl reads the two files as the same assertions")
	}
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	for name, file := range map[string]string{"legacy": legacy, "current": current} {
		// acl validate's loader, offline: the file is taken, and its three tests counted.
		v, err := runValidate(t, &registry.Env{Now: func() time.Time { return at }}, func(in *tools.ACLValidateInput) {
			in.Invariants, in.Offline, in.Operator = file, true, true
		})
		if err != nil || v.Status != "pass" || len(v.Errors) != 0 {
			t.Fatalf("%s: acl validate took the file as %+v, %v", name, v, err)
		}
		var noted bool
		for _, n := range v.Notices {
			noted = noted || strings.Contains(n.Message, "holds 3 tests")
		}
		if !noted {
			t.Errorf("%s: acl validate does not count three tests: %+v", name, v.Notices)
		}
		// The scan takes the same file and names the same set.
		r := scanRig(t, at)
		out, err := r.scanWith(t, "local", operator(file, false))
		if err != nil {
			t.Fatalf("%s: the scan refused a file acl validate takes: %v", name, err)
		}
		if out.Intent.Source != "cli" || out.Intent.Expectations != 3 {
			t.Errorf("%s: intent %+v, want three expectations from the command line", name, out.Intent)
		}
		if row, _ := coverageRow(out, "intent"); !strings.Contains(row.Explanation, "3 expectations supplied") {
			t.Errorf("%s: intent row %+v", name, row)
		}
	}
}
