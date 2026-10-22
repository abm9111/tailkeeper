//go:build !windows

package tools_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// The configured file is opened by the rules of every file that holds policy content, and
// must be owned by the user who runs tailkeeper and writable by no one else, as the
// configuration is: a group-writable file is config_unsafe (exit 6), a symlink is refused.
func TestTheConfiguredInvariantsFileIsReadWithOwnershipChecks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invariants.hujson")
	if err := os.WriteFile(path, []byte(invariantsText), 0o600); err != nil {
		t.Fatal(err)
	}
	f, _, env := apiEnv(t)
	env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
	serveLive(f, peoplePolicy, nil, nil)
	serveInvariants(f, func(tag string) apitest.Shape { return apitest.TestsFailed(canaryEntry(tag)) })
	reg := newRegistry(t)

	if out := validateOnline(t, env, `{}`); out.Status != "pass" || out.InvariantsApplied != 3 {
		t.Fatalf("a file only the owner can write: %+v", out)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	before := len(f.Requests())
	_, err := call(t, reg, env, "acl_validate", `{}`)
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ConfigUnsafe || tkerr.ExitCode(err) != 6 || len(f.Requests()) != before {
		t.Errorf("a group-writable file: err = %v with %d new requests, want config_unsafe (exit 6) and none", err, len(f.Requests())-before)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.hujson")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: link}}}
	_, err = call(t, reg, env, "acl_validate", `{}`)
	if code(err) != tkerr.ConfigInvalid || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("a symlink: err = %v, want config_invalid naming the symlink", err)
	}
}
