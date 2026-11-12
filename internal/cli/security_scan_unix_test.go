//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/local"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// A stand-in tailscale command that answers the three reads of a security collection: this
// node (nSELF1CNTRL, a current stable release), its versions and its preferences.
const standInTailscale = `#!/bin/sh
case "$*" in
"status --json --peers=false") echo '{"BackendState":"Running","Self":{"ID":"nSELF1CNTRL","OS":"linux"}}' ;;
"version --json --daemon") echo '{"long":"1.102.5-t0123456ab","daemonLong":"1.102.5-t0123456ab-gfedcba987"}' ;;
"get --json") echo '{"accept-dns":true,"ssh":false}' ;;
*) echo "stand-in: no answer for $*" >&2; exit 97 ;;
esac
`

// approvedCatalog is one approved rule, fixed in 1.32.3, fresh at the clock.
func approvedCatalog(at time.Time) func() (security.Catalog, error) {
	rule := security.AdvisoryRecord{ID: "RULE-1", Revision: "1", Component: "client", VersionRole: security.VersionRunningDaemon,
		Ranges: []security.VersionRange{{Fixed: "1.32.3"}}, Source: "synthetic", Severity: security.SeverityHigh,
		ReviewedAt: at.Add(-72 * time.Hour), ReviewExpiresAt: at.Add(72 * time.Hour), ReviewState: security.ReviewApproved, Mitigation: "Synthetic mitigation."}
	c := security.Catalog{SchemaVersion: security.SchemaVersion, Revision: 1, IssuedAt: at.Add(-48 * time.Hour), ExpiresAt: at.Add(48 * time.Hour),
		Digest: strings.Repeat("0", 64), Records: []security.AdvisoryRecord{rule}}
	return func() (security.Catalog, error) { return c, nil }
}

// scanWithApprovedRules is a harness that scans by an approved rule of its own and has a
// working local node, so that every source is whole.
func scanWithApprovedRules(t *testing.T, at time.Time, devs ...map[string]any) *harness {
	t.Helper()
	h := scanHarness(t, at, devs...)
	dir := t.TempDir()
	bin := filepath.Join(dir, "tailscale")
	if err := os.WriteFile(bin, []byte(standInTailscale), 0o755); err != nil { //nolint:gosec // an executable stand-in in a temporary directory
		t.Fatal(err)
	}
	h.app.Env.Local, h.app.Env.LocalErr = &local.Runner{Bin: local.Binary{Path: bin, Variant: local.VariantConfigured}, Home: dir, PerMinute: 1000}, nil
	reg := registry.New()
	reg.MustAdd(tools.SecurityScanTool(approvedCatalog(at)))
	h.r.Registry = func() *registry.Registry { return reg }
	return h
}

// With no intent set configured and every rule approved, a scan whose every source is whole
// is complete and exits 0 through the command line; a finding makes it 8 though it is complete.
func TestAScanWithEveryRequestedCoverageCompleteExitsZero(t *testing.T) {
	at := scanAt(t)
	h := scanWithApprovedRules(t, at, scanDevice(at, "nSELF1CNTRL", "1.102.5-t0123456ab", nil), scanDevice(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil))
	if code := h.run("--json", "security", "scan", "fleet"); code != 0 {
		t.Fatalf("exit %d: %s %s", code, h.out, h.err)
	}
	out := decode(t, h.out.Bytes())
	if out["status"] != "complete" || out["totalFindings"] != float64(2) || out["counts"].(map[string]any)["notAffected"] != float64(2) {
		t.Fatalf("the result: %v", out)
	}
	var intent map[string]any
	for _, r := range out["coverage"].([]any) {
		if m := r.(map[string]any); m["dimension"] == "intent" {
			intent = m
		}
	}
	if intent == nil || intent["status"] != "not_requested" || !strings.Contains(intent["explanation"].(string), "no intent set is configured") {
		t.Errorf("the intent row: %v", intent)
	}
	// --quiet prints nothing on success.
	h.out.Reset()
	if code := h.run("security", "scan", "fleet", "--quiet"); code != 0 || h.out.Len() != 0 {
		t.Errorf("--quiet: exit %d, %q", code, h.out)
	}
	// The text layout says it plainly.
	h.out.Reset()
	if code := h.run("security", "scan", "fleet"); code != 0 || !strings.Contains(h.out.String(), "fleet scan: complete") || !strings.Contains(h.out.String(), "coverage intent: not_requested") {
		t.Errorf("text: exit %d\n%s", code, h.out)
	}

	// Markdown says the same, with the same exit.
	h.out.Reset()
	if code := h.run("security", "scan", "fleet", "--format", "markdown"); code != 0 || !strings.HasPrefix(h.out.String(), "**fleet scan: complete; 0 affected, 0 potentially affected, 0 unknown, 2 not affected (2 findings, 2 listed)**\n") {
		t.Errorf("markdown: exit %d\n%s", code, h.out)
	}
	assertInertMarkdown(t, "Markdown of a complete scan", h.out.String())

	// A finding at the threshold is 8, and the scan is complete all the same.
	h = scanWithApprovedRules(t, at, scanDevice(at, "nSELF1CNTRL", "1.102.5-t0123456ab", nil), scanDevice(at, "nOLD01CNTRL", "1.28.2-t0123456ab", nil))
	if code := h.run("--json", "security", "scan", "fleet"); code != 8 {
		t.Fatalf("exit %d: %s %s", code, h.out, h.err)
	}
	if got := decode(t, h.out.Bytes()); got["status"] != "complete" || got["atThreshold"].(map[string]any)["affected"] != float64(1) {
		t.Errorf("an affected device in a complete scan: %v", got)
	}
	// And a source that fails keeps the same scan from being complete: 1.
	h = scanWithApprovedRules(t, at, scanDevice(at, "nSELF1CNTRL", "1.102.5-t0123456ab", nil))
	h.app.Env.Local, h.app.Env.LocalErr = nil, tkerr.New(tkerr.LocalBinaryMissing, "no tailscale CLI found", "")
	if code := h.run("--json", "security", "scan", "fleet"); code != 1 {
		t.Errorf("a failed local source: exit %d", code)
	}
}

// The same whole fleet that exits 0 with no intent exits 1 when it is given one: the intent is
// requested, nothing judges it yet, and the report says so in every layout. --no-invariants
// puts the exit back to 0 even when the configuration names a file.
func TestAScanGivenAnIntentIsPartialThroughTheCommandLine(t *testing.T) {
	at := scanAt(t)
	whole := func() *harness {
		return withKey(scanWithApprovedRules(t, at, scanDevice(at, "nSELF1CNTRL", "1.102.5-t0123456ab", nil), scanDevice(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil)))
	}
	path := writeIntent(t, cliIntentFile)

	h := whole()
	if code := h.run("--json", "security", "scan", "fleet"); code != 0 {
		t.Fatalf("the premise: the fleet is whole and exits 0 with no intent: exit %d: %s %s", code, h.out, h.err)
	}
	h = whole()
	if code := h.run("--json", "security", "scan", "fleet", "--invariants", path); code != 1 {
		t.Fatalf("exit %d, want 1: %s %s", code, h.out, h.err)
	}
	out := decode(t, h.out.Bytes())
	if out["status"] != "partial" || intentOf(t, out)["source"] != "cli" {
		t.Errorf("status %v, intent %v", out["status"], out["intent"])
	}
	for _, d := range []string{"versions", "features", "catalog"} {
		for _, r := range out["coverage"].([]any) {
			if m := r.(map[string]any); m["dimension"] == d && m["status"] != "complete" {
				t.Errorf("%s is %v: the intent alone should keep this scan from passing", d, m["status"])
			}
		}
	}
	h = whole()
	if code := h.run("security", "scan", "fleet", "--invariants", path, "--format", "markdown"); code != 1 || !strings.HasPrefix(h.out.String(), "**fleet scan: partial;") ||
		!strings.Contains(h.out.String(), "- intent: cli file, revision "+revisionOfDigest(keyedDigest(cliIntentFile))+", 3 expectations; none is judged in this version, so the scan is partial\n") ||
		!strings.Contains(h.out.String(), "- coverage intent: partial - intent not evaluated") {
		t.Errorf("markdown: exit %d\n%s", code, h.out)
	}
	h = whole()
	h.app.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
	if code := h.run("--json", "security", "scan", "fleet"); code != 1 || intentOf(t, decode(t, h.out.Bytes()))["source"] != "configured" {
		t.Errorf("the configured file: exit %d: %s", code, h.out)
	}
	h = whole()
	h.app.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
	if code := h.run("--json", "security", "scan", "fleet", "--no-invariants"); code != 0 || intentOf(t, decode(t, h.out.Bytes()))["source"] != "none" {
		t.Errorf("--no-invariants: exit %d: %s", code, h.out)
	}
}
