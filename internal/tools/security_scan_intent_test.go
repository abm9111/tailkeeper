package tools_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// The intent of a scan: the file acl.invariantsFile names, or the file --invariants names, or
// none. Everything here is synthetic (reserved addresses and example.com), and the distinctive
// words of the fixture (the zq-canary ones) are what the leak checks look for.

// intentFile has two tests and one SSH test, with comments and a trailing comma, as an owner
// writes them. Its words are the ones no result may repeat.
const intentFile = `// the owner's intent, synthetic
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

// otherIntentFile is a second file with one test, for the tests of which file wins.
const otherIntentFile = `{"tests": [{"src": "zq-canary-other@example.com", "accept": ["tag:zq-canary-other:80"]}]}`

// intentNeedles are the words of the two files above that must appear in no result, error or
// audit line.
var intentNeedles = []string{"zq-canary", "zqcanary", "198.51.100.9", "tag:zq", ":5432"}

// digestOf is the digest a result shows of a file with personalData show: the plain SHA-256.
func digestOf(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// revisionOf is the revision of a digest: the first twelve hexadecimal digits of its hex part.
func revisionOf(digest string) string { return strings.TrimPrefix(digest, "sha256:")[:12] }

// show makes the rig's configuration show personal data, so that the digest of the intent file
// is the plain one (the other modes are the subject of their own test).
func (r *rig) show() {
	if r.env.Config == nil {
		r.env.Config = &config.Loaded{}
	}
	r.env.Config.Config.PersonalData = config.PersonalDataShow
}

// intentPath writes text to a private file and returns its path.
func intentPath(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "intent.hujson")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// configure makes the rig's configuration name an invariants file.
func (r *rig) configure(path string) {
	r.env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
}

// scanWith runs the scan as the command line would: the typed input, with what the operator
// chose set by mod. It returns the output or the error.
func (r *rig) scanWith(t *testing.T, scope string, mod func(*tools.SecurityScanInput)) (tools.SecurityScanOutput, error) {
	t.Helper()
	p, err := scanTool(t).Validate(json.RawMessage(`{"scope":"` + scope + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	in := p.Input().(*tools.SecurityScanInput)
	if mod != nil {
		mod(in)
	}
	out, err := p.Run(registry.WithCaller(context.Background(), registry.Caller{Kind: "cli"}), r.env)
	if err != nil {
		return tools.SecurityScanOutput{}, err
	}
	return out.(tools.SecurityScanOutput), nil
}

// operator is what the command line sets: the file it names, and the mark that it was a person.
func operator(file string, none bool) func(*tools.SecurityScanInput) {
	return func(in *tools.SecurityScanInput) { in.Invariants, in.NoInvariants, in.Operator = file, none, true }
}

// wholeFleet is a rig in which every source is whole and the catalog has one approved rule, so
// that the scan with no intent is complete and exits 0: any change to that is the intent's.
// The stand-in CLI is a shell script, so a test that calls this does so inside a subtest.
func wholeFleet(t *testing.T) (*rig, time.Time) {
	t.Helper()
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	useCatalog(t, at, scanRule(at, "RULE-OK", "1.32.3", security.SeverityHigh, security.ReviewApproved))
	r := withCLI(scanRig(t, at))
	serveScanLocal(r, "1.102.5-t0123456ab", "1.102.5-t0123456ab-gfedcba987")
	r.devices(scanDev(at, selfID, "1.102.5-t0123456ab", nil), scanDev(at, "nNEW01CNTRL", "1.102.5-t0123456ab", nil))
	return r, at
}

func TestScanWithoutInvariantsHasIntentNotRequested(t *testing.T) {
	t.Run("nothing configured: not requested, and the scan can be complete", func(t *testing.T) {
		r, _ := wholeFleet(t)
		out, err := r.scanWith(t, "fleet", nil)
		if err != nil {
			t.Fatal(err)
		}
		row, ok := coverageRow(out, "intent")
		if !ok || row.Status != "not_requested" || !strings.Contains(row.Explanation, "no intent set is configured") {
			t.Errorf("intent row: %+v", row)
		}
		if out.Intent != (tools.SecurityScanIntent{Source: "none"}) {
			t.Errorf("intent: %+v, want only its source, none", out.Intent)
		}
		if out.Status != "complete" || out.ExitCode() != 0 {
			t.Errorf("status %s exit %d, want complete and 0", out.Status, out.ExitCode())
		}
	})
	t.Run("a configuration that names no file is the same", func(t *testing.T) {
		r := scanRig(t, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
		r.env.Config = &config.Loaded{}
		out, err := r.scanWith(t, "local", nil)
		if err != nil {
			t.Fatal(err)
		}
		if row, _ := coverageRow(out, "intent"); row.Status != "not_requested" || out.Intent.Source != "none" {
			t.Errorf("intent row %+v, intent %+v", row, out.Intent)
		}
	})
}

func TestScanWithConfiguredInvariantsIsPartialAndCarriesDigest(t *testing.T) {
	t.Run("the same fleet, now partial", func(t *testing.T) {
		r, _ := wholeFleet(t)
		r.configure(intentPath(t, intentFile))
		r.show()
		out, err := r.scanWith(t, "fleet", nil)
		if err != nil {
			t.Fatal(err)
		}
		// The premise: everything else is whole, so the intent alone keeps this scan from passing.
		for _, d := range []string{"versions", "features", "catalog"} {
			if c, ok := coverageRow(out, d); !ok || c.Status != "complete" {
				t.Fatalf("%s row: %+v", d, c)
			}
		}
		if out.Status != "partial" || out.ExitCode() != 1 {
			t.Errorf("status %s exit %d, want partial and 1: a supplied intent is requested, and nothing judges it yet", out.Status, out.ExitCode())
		}
		row, _ := coverageRow(out, "intent")
		if row.Status != "partial" || !strings.Contains(row.Explanation, "3 expectations supplied") || !strings.Contains(row.Explanation, "not evaluated") {
			t.Errorf("intent row: %+v", row)
		}
		d := digestOf(intentFile)
		want := tools.SecurityScanIntent{Source: "configured", Digest: d, Revision: revisionOf(d), Expectations: 3}
		if out.Intent != want {
			t.Errorf("intent %+v, want %+v", out.Intent, want)
		}
		b, _ := json.Marshal(out)
		for _, needle := range intentNeedles {
			if strings.Contains(string(b), needle) {
				t.Errorf("the result repeats %q", needle)
			}
		}
	})
	t.Run("a finding still outranks it: 8", func(t *testing.T) {
		at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
		useCatalog(t, at, scanRule(at, "RULE-OK", "1.32.3", security.SeverityHigh, security.ReviewApproved))
		r := scanRig(t, at)
		r.devices(scanDev(at, "nOLD01CNTRL", "1.28.2-t0123456ab", nil))
		r.configure(intentPath(t, intentFile))
		out, err := r.scanWith(t, "fleet", nil)
		if err != nil {
			t.Fatal(err)
		}
		if out.Status != "partial" || out.ExitCode() != 8 || out.Counts.Affected != 1 {
			t.Errorf("status %s exit %d counts %+v", out.Status, out.ExitCode(), out.Counts)
		}
	})
	t.Run("over MCP the configured file is the only source, and the call needs no operator", func(t *testing.T) {
		at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
		r := scanRig(t, at)
		r.configure(intentPath(t, intentFile))
		r.show()
		out, err := scanTool(t).Call(registry.WithCaller(context.Background(), registry.Caller{Kind: "mcp"}), r.env, json.RawMessage(`{"scope":"local"}`))
		if err != nil {
			t.Fatal(err)
		}
		if got := out.(tools.SecurityScanOutput).Intent; got.Source != "configured" || got.Digest != digestOf(intentFile) {
			t.Errorf("intent %+v", got)
		}
	})
}

func TestScanInvariantsFlagReplacesConfiguredFile(t *testing.T) {
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	r := scanRig(t, at)
	r.configure(intentPath(t, intentFile))
	r.show()
	out, err := r.scanWith(t, "local", operator(otherIntentFile, false))
	if err != nil {
		t.Fatal(err)
	}
	d := digestOf(otherIntentFile)
	if want := (tools.SecurityScanIntent{Source: "cli", Digest: d, Revision: revisionOf(d), Expectations: 1}); out.Intent != want {
		t.Errorf("intent %+v, want the named file's, not the configured one's: %+v", out.Intent, want)
	}
	if row, _ := coverageRow(out, "intent"); !strings.Contains(row.Explanation, "1 expectation supplied") {
		t.Errorf("intent row: %+v", row)
	}
}

func TestScanNoInvariantsIgnoresConfiguredFile(t *testing.T) {
	t.Run("a readable file is not read for its digest", func(t *testing.T) {
		r, _ := wholeFleet(t)
		r.configure(intentPath(t, intentFile))
		out, err := r.scanWith(t, "fleet", operator("", true))
		if err != nil {
			t.Fatal(err)
		}
		if out.Intent.Source != "none" || out.Status != "complete" || out.ExitCode() != 0 {
			t.Errorf("intent %+v status %s exit %d", out.Intent, out.Status, out.ExitCode())
		}
		if row, _ := coverageRow(out, "intent"); row.Status != "not_requested" {
			t.Errorf("intent row: %+v", row)
		}
	})
	t.Run("nor is one that could not be read", func(t *testing.T) {
		// --no-invariants means none: a configured path that is missing is not looked at.
		r := scanRig(t, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
		r.configure(filepath.Join(t.TempDir(), "gone.hujson"))
		out, err := r.scanWith(t, "local", operator("", true))
		if err != nil || out.Intent.Source != "none" {
			t.Errorf("out %+v, err %v", out.Intent, err)
		}
	})
}

func TestScanInvariantsAndNoInvariantsConflict(t *testing.T) {
	r := scanRig(t, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
	r.configure(intentPath(t, intentFile))
	_, err := r.scanWith(t, "fleet", operator(otherIntentFile, true))
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.ValidationFailed || tkerr.ExitCode(err) != 2 || !strings.Contains(e.Message, "not both") {
		t.Fatalf("err = %v, want validation_failed (exit 2) saying not both", err)
	}
	if n := len(r.f.Requests()); n != 0 || len(r.got) != 0 {
		t.Errorf("%d API requests and %d recorded sources for a refused call", n, len(r.got))
	}
	for _, needle := range intentNeedles {
		if strings.Contains(err.Error(), needle) {
			t.Errorf("the error repeats %q", needle)
		}
	}
}

// Only the command line chooses the file or switches the intent off, and it marks its call as
// the operator's: a call that carries the choice without the mark is refused.
func TestScanIntentChoiceNeedsTheOperator(t *testing.T) {
	for name, mod := range map[string]func(*tools.SecurityScanInput){
		"a file":              func(in *tools.SecurityScanInput) { in.Invariants = otherIntentFile },
		"switched off":        func(in *tools.SecurityScanInput) { in.NoInvariants = true },
		"a file and the mark": func(in *tools.SecurityScanInput) { in.Invariants, in.Operator = otherIntentFile, false },
	} {
		r := scanRig(t, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
		_, err := r.scanWith(t, "local", mod)
		if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ValidationFailed {
			t.Errorf("%s: err = %v, want validation_failed", name, err)
		}
		if len(r.f.Requests()) != 0 || len(r.got) != 0 {
			t.Errorf("%s: a source was asked", name)
		}
	}
}

// A configured file that cannot be used is never a silent none: that would turn a partial scan
// into a complete one. It is config_invalid (exit 6) on every call, before any source is asked.
func TestUnreadableConfiguredInvariantsIsConfigInvalid(t *testing.T) {
	for name, c := range map[string]struct {
		path func(t *testing.T) string
	}{
		"missing":               {func(t *testing.T) string { return filepath.Join(t.TempDir(), "gone.hujson") }},
		"a directory":           {func(t *testing.T) string { return t.TempDir() }},
		"a file with a problem": {func(t *testing.T) string { return intentPath(t, `{"zq-canary-key": []}`) }},
		"a file past the engine's budgets": {func(t *testing.T) string {
			return intentPath(t, `{"tests": [`+strings.Repeat("{},", acl.MaxNodes)+`]}`)
		}},
		"a file the adapter won't": {func(t *testing.T) string {
			return intentPath(t, `{"tests": [{"src": "zq-canary-x", "zz-unmapped": ["tag:zq-canary:1"]}]}`)
		}},
	} {
		for _, via := range []string{"command line", "mcp"} {
			r := scanRig(t, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
			r.configure(c.path(t))
			var err error
			if via == "mcp" {
				_, err = scanTool(t).Call(registry.WithCaller(context.Background(), registry.Caller{Kind: "mcp"}), r.env, json.RawMessage(`{"scope":"fleet"}`))
			} else {
				_, err = r.scanWith(t, "fleet", operator("", false))
			}
			e, ok := tkerr.As(err)
			if !ok || e.Code != tkerr.ConfigInvalid || tkerr.ExitCode(err) != 6 {
				t.Errorf("%s via %s: err = %v, want config_invalid (exit 6)", name, via, err)
			}
			if n := len(r.f.Requests()); n != 0 || len(r.got) != 0 {
				t.Errorf("%s via %s: %d API requests and %d recorded sources: the scan went on without its intent", name, via, n, len(r.got))
			}
			if err != nil {
				for _, needle := range append(intentNeedles, "zq-canary-key") {
					if strings.Contains(err.Error(), needle) || (ok && strings.Contains(e.Hint, needle)) {
						t.Errorf("%s via %s: the error repeats %q: %v", name, via, needle, err)
					}
				}
			}
		}
	}
}

// A file named on the command line that the loader or the adapter refuses is a usage error
// (exit 2), by kind and place.
func TestScanRefusesAnInvariantsFileItCannotTake(t *testing.T) {
	r := scanRig(t, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC))
	_, err := r.scanWith(t, "fleet", operator("{\n\t\"tests\": [\n\t\t{\"src\": \"zq-canary-a\", \"zz-unmapped\": [\"x\"]},\n\t],\n}\n", false))
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.ValidationFailed || tkerr.ExitCode(err) != 2 {
		t.Fatalf("err = %v, want validation_failed (exit 2)", err)
	}
	if !strings.Contains(e.Message, "unsupported_field in entry 1 of tests (line 3, column 3)") {
		t.Errorf("message %q does not name the kind and the place", e.Message)
	}
	if strings.Contains(e.Message+e.Hint, "zq-canary") || strings.Contains(e.Message, "zz-unmapped") {
		t.Errorf("the error repeats the file: %q", e.Message)
	}
	if len(r.f.Requests()) != 0 || len(r.got) != 0 {
		t.Errorf("a source was asked")
	}
}

// The digest and the revision of the intent file follow the rule the other digests of a policy
// follow (the audit log's digests, the policy version of acl_get): an unkeyed hash of an operator
// file that holds logins would confirm a guessed file, so while personal data is masked the
// digest is a keyed one when a privacy key is loaded and is left out when none is, and the plain
// SHA-256 is shown only with personalData show. The revision is the first twelve digits of
// whatever digest is shown, and is left out with it. This holds for the configured file and for
// a named one.
func TestTheIntentDigestFollowsTheRuleOfThePolicyDigests(t *testing.T) {
	key, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(intentFile))
	plain := hex.EncodeToString(sum[:])
	keyed := key.Digest([]byte(intentFile))
	hexOf := func(d string) string { return d[strings.LastIndex(d, ":")+1:] }
	for name, c := range map[string]struct {
		key    *privacy.Key
		show   bool
		digest string
	}{
		"masked, no key":             {nil, false, ""},
		"masked, a key":              {key, false, keyed},
		"personal data shown":        {nil, true, "sha256:" + plain},
		"personal data shown, keyed": {key, true, "sha256:" + plain},
	} {
		for _, origin := range []string{"configured", "cli"} {
			at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
			r := scanRig(t, at)
			r.env.Privacy = c.key
			var mod func(*tools.SecurityScanInput)
			if origin == "configured" {
				r.configure(intentPath(t, intentFile))
			} else {
				r.env.Config = &config.Loaded{}
				mod = operator(intentFile, false)
			}
			if c.show {
				r.env.Config.Config.PersonalData = config.PersonalDataShow
			}
			out, err := r.scanWith(t, "local", mod)
			if err != nil {
				t.Fatal(err)
			}
			want := tools.SecurityScanIntent{Source: origin, Digest: c.digest, Expectations: 3}
			if c.digest != "" {
				want.Revision = hexOf(c.digest)[:12]
			}
			if out.Intent != want {
				t.Errorf("%s, %s: intent %+v, want %+v", name, origin, out.Intent, want)
			}
			b, _ := json.Marshal(out)
			if !c.show && strings.Contains(string(b), plain) {
				t.Errorf("%s, %s: the result holds the plain SHA-256 of the file while personal data is masked", name, origin)
			}
			// The layouts say why there is no digest, and do not print an empty revision.
			var line string
			for _, l := range out.Details() {
				if strings.HasPrefix(l, "intent: ") {
					line = l
				}
			}
			if c.digest == "" && (!strings.Contains(line, "no digest") || strings.Contains(line, "revision ")) {
				t.Errorf("%s, %s: the intent line does not say there is no digest: %q", name, origin, line)
			}
			if c.digest != "" && (!strings.Contains(line, "revision "+want.Revision) || strings.Contains(line, "no digest")) {
				t.Errorf("%s, %s: the intent line lacks the revision: %q", name, origin, line)
			}
		}
	}
}
