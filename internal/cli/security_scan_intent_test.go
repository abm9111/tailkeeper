package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/mcpserver"
	"github.com/abm9111/tailkeeper/internal/privacy"
)

// The intent of a scan through the command line and the MCP server: the file --invariants
// names, the configured acl.invariantsFile, or none. The files are synthetic; the zq-canary
// words are the ones no output, error or audit line may repeat.

const cliIntentFile = `// the owner's intent, synthetic
{
	"tests": [
		{"src": "zq-canary-owner@example.com", "accept": ["tag:zq-canary-db:5432"], "deny": ["tag:zq-canary-vault:22"]},
		{"src": "tag:zq-canary-ci", "proto": "tcp", "srcPostureAttrs": {"custom:zqcanaryattr": "zq-canary-value"}, "accept": ["198.51.100.9:443"]},
	],
	"sshTests": [
		{"src": "zq-canary-owner@example.com", "dst": ["tag:zq-canary-ssh"], "accept": ["zqcanaryuser"], "check": ["zqcanaryroot"]},
	],
}
`

const cliOtherIntentFile = `{"tests": [{"src": "zq-canary-other@example.com", "accept": ["tag:zq-canary-other:80"]}]}`

// The port carries its colon: the audit log is full of hexadecimal digests, and four digits alone
// would be found in one of them now and then.
var cliIntentNeedles = []string{"zq-canary", "zqcanary", "198.51.100.9", "tag:zq", ":5432"}

func writeIntent(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "intent.hujson")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// cliKey is the privacy key of the tests that look at the digest of the intent file: while
// personal data is masked, the digest is a keyed one and there is none without a key.
var cliKey = func() *privacy.Key {
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		panic(err)
	}
	return k
}()

// withKey loads the privacy key into the harness.
func withKey(h *harness) *harness {
	h.app.Env.Privacy = cliKey
	return h
}

// keyedDigest is the digest a result shows of a file with the key above, and revisionOfDigest the
// revision that names it.
func keyedDigest(text string) string { return cliKey.Digest([]byte(text)) }

func revisionOfDigest(d string) string { return strings.TrimPrefix(d, "hmac-sha256:")[:12] }

// sha256Hex is the plain SHA-256 of a file, which no result shows while personal data is masked.
func sha256Hex(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// collectLines counts the lines of the audit log that record a source of a collection.
func collectLines(t *testing.T, h *harness) int {
	t.Helper()
	data, err := os.ReadFile(h.app.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), `"event":"collect"`)
}

func intentOf(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	m, ok := out["intent"].(map[string]any)
	if !ok {
		t.Fatalf("the result has no intent: %v", out)
	}
	return m
}

func TestScanInvariantsFlagThroughTheCommandLine(t *testing.T) {
	at := scanAt(t)
	clean := scanDevice(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil)

	t.Run("a named file is the intent: requested, named by digest, partial", func(t *testing.T) {
		h := withKey(scanHarness(t, at, clean))
		path := writeIntent(t, cliIntentFile)
		if code := h.run("--json", "security", "scan", "fleet", "--invariants", path); code != 1 {
			t.Fatalf("exit %d, want 1 (nothing found, and the intent is not judged): %s %s", code, h.out, h.err)
		}
		out := decode(t, h.out.Bytes())
		in := intentOf(t, out)
		d := keyedDigest(cliIntentFile)
		if in["source"] != "cli" || in["digest"] != d || in["revision"] != revisionOfDigest(d) || in["expectations"] != float64(3) {
			t.Errorf("intent %v, want the file's keyed digest %s and 3 expectations", in, d)
		}
		if strings.Contains(h.out.String(), sha256Hex(cliIntentFile)) {
			t.Errorf("the result holds the plain SHA-256 of the file while personal data is masked")
		}
		for _, r := range out["coverage"].([]any) {
			if m := r.(map[string]any); m["dimension"] == "intent" && (m["status"] != "partial" || !strings.Contains(m["explanation"].(string), "3 expectations supplied")) {
				t.Errorf("intent row: %v", m)
			}
		}
	})
	t.Run("the deprecated spellings acl validate takes (user, allow) are taken", func(t *testing.T) {
		h := withKey(scanHarness(t, at, clean))
		legacy := `{"tests": [{"user": "zq-canary-owner@example.com", "allow": ["tag:zq-canary-db:5432"]}], "sshTests": [{"src": "tag:zq-canary-ci", "dst": ["tag:zq-canary-ssh"], "allow": ["zqcanaryuser"]}]}`
		if code := h.run("--json", "security", "scan", "fleet", "--invariants", writeIntent(t, legacy)); code != 1 {
			t.Fatalf("exit %d, want 1 (the file is taken, and the intent is not judged): %s %s", code, h.out, h.err)
		}
		if in := intentOf(t, decode(t, h.out.Bytes())); in["source"] != "cli" || in["expectations"] != float64(2) || in["digest"] != keyedDigest(legacy) {
			t.Errorf("intent %v", in)
		}
	})
	t.Run("it replaces the configured file", func(t *testing.T) {
		h := withKey(scanHarness(t, at, clean))
		h.app.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: writeIntent(t, cliIntentFile)}}}
		if code := h.run("--json", "security", "scan", "fleet", "--invariants", writeIntent(t, cliOtherIntentFile)); code != 1 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
		in := intentOf(t, decode(t, h.out.Bytes()))
		if in["source"] != "cli" || in["digest"] != keyedDigest(cliOtherIntentFile) || in["expectations"] != float64(1) {
			t.Errorf("intent %v: the configured file was used", in)
		}
	})
	t.Run("the configured file is used when no flag is given", func(t *testing.T) {
		h := withKey(scanHarness(t, at, clean))
		h.app.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: writeIntent(t, cliIntentFile)}}}
		if code := h.run("--json", "security", "scan", "fleet"); code != 1 {
			t.Fatalf("exit %d: %s %s", code, h.out, h.err)
		}
		if in := intentOf(t, decode(t, h.out.Bytes())); in["source"] != "configured" || in["digest"] != keyedDigest(cliIntentFile) {
			t.Errorf("intent %v", in)
		}
	})
	t.Run("--no-invariants means none, whatever is configured", func(t *testing.T) {
		h := scanHarness(t, at, clean)
		h.app.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: filepath.Join(t.TempDir(), "gone.hujson")}}}
		if code := h.run("--json", "security", "scan", "fleet", "--no-invariants"); code != 1 {
			t.Fatalf("exit %d (the other rows are partial here): %s %s", code, h.out, h.err)
		}
		out := decode(t, h.out.Bytes())
		if in := intentOf(t, out); in["source"] != "none" || in["digest"] != nil {
			t.Errorf("intent %v", in)
		}
		for _, r := range out["coverage"].([]any) {
			if m := r.(map[string]any); m["dimension"] == "intent" && m["status"] != "not_requested" {
				t.Errorf("intent row: %v", m)
			}
		}
	})
	t.Run("both flags together are a usage error, with nothing read", func(t *testing.T) {
		h := scanHarness(t, at, clean)
		code := h.run("--json", "security", "scan", "fleet", "--invariants", writeIntent(t, cliIntentFile), "--no-invariants")
		e, _ := decode(t, h.out.Bytes())["error"].(map[string]any)
		if code != 2 || e == nil || e["code"] != "validation_failed" || !strings.Contains(e["message"].(string), "not both") {
			t.Errorf("exit %d, %s", code, h.out)
		}
		if n := collectLines(t, h); n != 0 {
			t.Errorf("%d sources were recorded for a refused command", n)
		}
	})
}

func TestScanInvariantsFileRefusals(t *testing.T) {
	at := scanAt(t)
	run := func(t *testing.T, text string) (int, map[string]any, *harness) {
		t.Helper()
		h := scanHarness(t, at, fleet(at)...)
		code := h.run("--json", "security", "scan", "fleet", "--invariants", writeIntent(t, text))
		return code, decode(t, h.out.Bytes()), h
	}
	for name, c := range map[string]struct {
		text, want string
	}{
		"a field the adapter does not map": {"{\n\t\"tests\": [\n\t\t{\"src\": \"zq-canary-a\", \"zz-unmapped\": [\"x\"]},\n\t],\n}\n", "unsupported_field in entry 1 of tests (line 3, column 3)"},
		"another section":                  {`{"zq-canary-section": []}`, "structure"},
		"a syntax error":                   {`{"tests": [zq-canary-bad]}`, "syntax"},
	} {
		code, out, h := run(t, c.text)
		e, _ := out["error"].(map[string]any)
		if code != 2 || e == nil || e["code"] != "validation_failed" || !strings.Contains(e["message"].(string), c.want) {
			t.Errorf("%s: exit %d, %s", name, code, h.out)
		}
		if n := collectLines(t, h); n != 0 {
			t.Errorf("%s: %d sources were recorded for a refused file", name, n)
		}
		for _, needle := range cliIntentNeedles {
			if strings.Contains(h.out.String()+h.err.String(), needle) {
				t.Errorf("%s: the output repeats %q", name, needle)
			}
		}
	}
	t.Run("an empty file is refused by the command line, not read as no intent", func(t *testing.T) {
		h := scanHarness(t, at, fleet(at)...)
		path := writeIntent(t, "")
		if code := h.run("security", "scan", "fleet", "--invariants", path); code != 2 || !strings.Contains(h.err.String(), "is empty") {
			t.Errorf("exit %d: %s", code, h.err)
		}
	})
	t.Run("a missing file is a usage error", func(t *testing.T) {
		h := scanHarness(t, at, fleet(at)...)
		if code := h.run("security", "scan", "fleet", "--invariants", filepath.Join(t.TempDir(), "gone.hujson")); code != 2 {
			t.Errorf("exit %d: %s", code, h.err)
		}
	})
}

// A configured file that cannot be used is exit 6 on every call, with no source read: not an
// intent that is quietly not requested, which would turn a partial scan into a complete one.
func TestUnreadableConfiguredInvariantsIsConfigInvalidFromTheCommandLine(t *testing.T) {
	at := scanAt(t)
	for name, path := range map[string]string{
		"missing":       filepath.Join(t.TempDir(), "gone.hujson"),
		"a directory":   t.TempDir(),
		"with a defect": writeIntent(t, `{"zq-canary-key": []}`),
		// past the engine's budgets: the file reads, and the engine refuses it
		"too complex": writeIntent(t, tooComplexCLIIntentFile()),
	} {
		h := scanHarness(t, at, fleet(at)...)
		h.app.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
		code := h.run("--json", "security", "scan", "fleet")
		e, _ := decode(t, h.out.Bytes())["error"].(map[string]any)
		if code != 6 || e == nil || e["code"] != "config_invalid" {
			t.Errorf("%s: exit %d, %s", name, code, h.out)
		}
		if n := collectLines(t, h); n != 0 {
			t.Errorf("%s: %d sources were recorded: the scan went on without its intent", name, n)
		}
		if strings.Contains(h.out.String()+h.err.String(), "zq-canary") {
			t.Errorf("%s: the output repeats the file", name)
		}
	}
}

// No format (text, JSON, Markdown, GitHub annotations and MCP), error or audit line repeats a word of the intent file: not a source, a
// destination, a login, a posture attribute or a destination port. The premise is checked in
// each: the same output names the file's digest or revision, so the file was read.
func TestScanReportRepeatsNoIntentText(t *testing.T) {
	at := scanAt(t)
	devs := append(fleet(at), scanDevice(at, "nOFF01CNTRL", "1.28.2-t0123456ab", map[string]any{"connectedToControl": false}))
	for _, source := range []string{"configured", "cli"} {
		h := withKey(scanHarness(t, at, devs...))
		path := writeIntent(t, cliIntentFile)
		var flag []string
		if source == "configured" {
			h.app.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
		} else {
			flag = []string{"--invariants", path}
		}
		d, rev := keyedDigest(cliIntentFile), revisionOfDigest(keyedDigest(cliIntentFile))

		outputs := map[string]string{}
		h.run(append([]string{"security", "scan", "fleet"}, flag...)...)
		outputs["cli text"] = h.out.String() + h.err.String()
		h.out.Reset()
		h.err.Reset()
		h.run(append([]string{"--json", "security", "scan", "fleet"}, flag...)...)
		outputs["cli json"] = h.out.String() + h.err.String()
		for _, format := range []string{"markdown", "github"} {
			h.out.Reset()
			h.err.Reset()
			h.run(append([]string{"security", "scan", "fleet", "--format", format}, flag...)...)
			outputs["cli "+format] = h.out.String() + h.err.String()
		}
		if !strings.Contains(outputs["cli text"], rev) || !strings.Contains(outputs["cli json"], d) {
			t.Fatalf("%s: the premise: the outputs do not name the file's revision and digest:\n%s", source, outputs["cli text"])
		}
		for _, format := range []string{"markdown", "github"} {
			if !strings.Contains(outputs["cli "+format], rev) {
				t.Fatalf("%s: the premise: the %s layout does not name the file's revision:\n%.1500s", source, format, outputs["cli "+format])
			}
		}
		if source == "configured" {
			srv, err := mcpserver.New(h.app, mcpserver.Options{Profile: "reads"})
			if err != nil {
				t.Fatal(err)
			}
			res, err := connectMCP(t, srv).CallTool(context.Background(), &mcp.CallToolParams{Name: "security_scan", Arguments: map[string]any{"scope": "fleet"}})
			if err != nil || res.IsError {
				t.Fatalf("mcp: %v %+v", err, res)
			}
			b, _ := json.Marshal(res)
			outputs["mcp"] = string(b)
			if !strings.Contains(outputs["mcp"], d) {
				t.Fatalf("the premise: the MCP result does not name the digest")
			}
		}
		audit, err := os.ReadFile(h.app.AuditPath)
		if err != nil || len(audit) == 0 {
			t.Fatalf("audit log: %v (%d bytes)", err, len(audit))
		}
		outputs["audit log"] = string(audit)

		for name, text := range outputs {
			for _, needle := range cliIntentNeedles {
				if strings.Contains(text, needle) {
					t.Errorf("%s, %s holds %q", source, name, needle)
				}
			}
			if strings.Contains(text, path) || strings.Contains(text, filepath.Base(path)) {
				t.Errorf("%s, %s holds the path of the intent file", source, name)
			}
			if strings.Contains(text, sha256Hex(cliIntentFile)) {
				t.Errorf("%s, %s holds the plain SHA-256 of the file while personal data is masked", source, name)
			}
		}
	}
}

// tooComplexCLIIntentFile is a file the engine refuses for its size in values, well under the
// byte cap of a file.
func tooComplexCLIIntentFile() string {
	return `{"tests": [` + strings.Repeat("{},", acl.MaxNodes) + `]}`
}

// A file the command line names that the engine refuses is a usage error with the code the
// engine's refusal has (too_complex, exit 2): the configured one is exit 6, and this is not.
func TestANamedIntentFilePastTheEnginesBudgetsIsAUsageError(t *testing.T) {
	at := scanAt(t)
	h := scanHarness(t, at, fleet(at)...)
	code := h.run("--json", "security", "scan", "fleet", "--invariants", writeIntent(t, tooComplexCLIIntentFile()))
	e, _ := decode(t, h.out.Bytes())["error"].(map[string]any)
	if code != 2 || e == nil || e["code"] != "too_complex" {
		t.Errorf("exit %d, %.300s", code, h.out)
	}
	if n := collectLines(t, h); n != 0 {
		t.Errorf("%d sources were recorded for a refused file", n)
	}
}

// While personal data is masked and no privacy key is loaded (the default), the intent has no
// digest and no revision, in any layout: an unkeyed hash of a file that holds logins would
// confirm a guessed file. The set is still named by its source and its count, and the layouts
// say why there is no digest.
func TestTheIntentDigestIsLeftOutWhileMaskedWithNoKey(t *testing.T) {
	at := scanAt(t)
	h := scanHarness(t, at, fleet(at)...)
	path := writeIntent(t, cliIntentFile)
	plain := sha256Hex(cliIntentFile)
	scan := []string{"security", "scan", "fleet", "--invariants", path}
	outputs := map[string]string{}
	for name, args := range map[string][]string{
		"json": append([]string{"--json"}, scan...), "text": scan,
		"markdown": append(append([]string{}, scan...), "--format", "markdown"), "github": append(append([]string{}, scan...), "--format", "github"),
	} {
		h.out.Reset()
		h.err.Reset()
		h.run(args...)
		outputs[name] = h.out.String() + h.err.String()
		if name == "json" {
			outputs[name] = h.out.String() // the exit is 8, and standard error says why
		}
	}
	in := intentOf(t, decode(t, []byte(outputs["json"])))
	if in["source"] != "cli" || in["expectations"] != float64(3) || in["digest"] != nil || in["revision"] != nil {
		t.Errorf("intent %v: want its source and count, and no digest or revision", in)
	}
	for name, text := range outputs {
		if strings.Contains(text, plain) || strings.Contains(text, plain[:12]) {
			t.Errorf("%s holds the plain SHA-256 of the file or its start", name)
		}
		if name != "json" && !strings.Contains(text, "no digest") {
			t.Errorf("%s does not say why there is no digest", name)
		}
	}
}
