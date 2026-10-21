package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

const validConfig = `{
  // HuJSON: comments and trailing commas are allowed.
  "contexts": {
    "prod": {
      "tailnetId": "T1234CNTRL",
      "credentials": {"read": {"provider": "env"}},
    },
  },
  "mcp": {"profile": "reads"},
}`

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(validConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Contexts["prod"].TailnetID != "T1234CNTRL" {
		t.Fatalf("tailnetId = %q", c.Contexts["prod"].TailnetID)
	}
}

func TestParsePersonalData(t *testing.T) {
	for _, v := range []string{"", `,"personalData":"mask"`, `,"personalData":"show"`} {
		c, err := Parse([]byte(`{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"env"}}}}` + v + `}`))
		if err != nil {
			t.Errorf("%q: %v", v, err)
			continue
		}
		if want := strings.Trim(strings.TrimPrefix(v, `,"personalData":`), `"`); c.PersonalData != want {
			t.Errorf("%q: personalData = %q", v, c.PersonalData)
		}
	}
}

func TestParseRejects(t *testing.T) {
	// Each refusal is config_invalid, and its message says which rule refused it: a
	// refusal for another reason would pass a check of the code alone.
	cases := []struct{ name, in, want string }{
		{"unknown key", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"env"}}}},"approverz":[]}`, "approverz is not a configuration key"},
		{"no contexts", `{"contexts":{}}`, "at least one context is required"},
		{"dash tailnet", `{"contexts":{"p":{"tailnetId":"-","credentials":{"read":{"provider":"env"}}}}}`, "tailnetId must be the explicit tailnet ID"},
		{"bad provider", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"keychain"}}}}}`, "provider \"keychain\" must be env, file, exec or oidc"},
		{"relative exec", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"exec","command":["wrapper","--"]}}}}}`, "the exec provider needs \"command\" with an absolute program path"},
		{"env with extras", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"env","path":"/x"}}}}}`, "the env provider takes no other fields"},
		{"oidc no client", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"oidc"}}}}}`, "the oidc provider needs \"clientId\""},
		{"bad default", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"env"}}}},"defaultContext":"q"}`, "defaultContext \"q\" is not a defined context"},
		{"bad profile", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"env"}}}},"mcp":{"profile":"all"}}`, "mcp.profile \"all\" must be reads, core or full"},
		{"relative tailscale", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"env"}}}},"local":{"tailscaleBinary":"tailscale"}}`, "local.tailscaleBinary must be an absolute path"},
		{"trailing data", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"env"}}}}} {}`, "after top-level value"},
		{"bad personalData", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"env"}}}},"personalData":"all"}`, "personalData \"all\" must be mask or show"},
		{"bad context name", `{"contexts":{"Prod Net":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"env"}}}}}`, "context name \"Prod Net\" must match"},
		{"bad audit reads", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"env"}}}},"audit":{"reads":"all"}}`, "audit.reads \"all\" must be metadata or none"},
		{"relative socket", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"env"}}}},"local":{"socket":"tailscaled.sock"}}`, "local.socket must be an absolute path"},
		{"relative file", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"file","path":"read.env"}}}}}`, "the file provider needs an absolute \"path\""},
		{"relative tokenFile", `{"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"oidc","clientId":"c","tokenFile":"tok"}}}}}`, "oidc \"tokenFile\" must be an absolute path"},
		{"wrong type", `{"contexts":[]}`, "does not match the schema"},
		{"not JSON", `{"contexts":`, "is not valid HuJSON"},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.in))
		e, ok := tkerr.As(err)
		if !ok || e.Code != tkerr.ConfigInvalid || !strings.Contains(e.Message, c.want) {
			t.Errorf("%s: err = %v, want config_invalid with %q", c.name, err, c.want)
		}
	}
}

// HuJSON's parser recurses once for each level of nesting and has no bound, and a Go stack
// overflow ends the process, so text nested deeper than any configuration is refused before it
// is parsed. A configuration of exactly the deepest allowed nesting is read as before.
func TestParseRefusesNestingBeyondTheGuard(t *testing.T) {
	nested := func(depth int) []byte {
		return []byte(`{"contexts": {}, "x": ` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + `}`)
	}
	for _, depth := range []int{guard.MaxDepth, 5 * guard.MaxDepth, 1_000_000} {
		_, err := Parse(nested(depth))
		e, ok := tkerr.As(err)
		if !ok || e.Code != tkerr.ConfigInvalid {
			t.Fatalf("depth %d: err = %v, want config_invalid", depth, err)
		}
		deep := strings.Contains(e.Message, "nested")
		// The object around the value is one more level, so MaxDepth levels of array make
		// MaxDepth+1 levels in all.
		if want := depth >= guard.MaxDepth; deep != want {
			t.Errorf("depth %d: the error says it is too deep = %v, want %v: %v", depth, deep, want, err)
		}
	}
	_, err := Parse(nested(guard.MaxDepth - 1))
	if e, ok := tkerr.As(err); !ok || strings.Contains(e.Message, "nested") {
		t.Errorf("the deepest nesting allowed was refused as too deep: %v", err)
	}
}

func allowAll(string, ...int) error { return nil }

func writeConfig(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSystemWinsWithoutMerging(t *testing.T) {
	root := t.TempDir()
	d := Dirs{System: filepath.Join(root, "sys"), User: filepath.Join(root, "usr")}
	writeConfig(t, d.System, validConfig)
	writeConfig(t, d.User, strings.Replace(validConfig, "T1234CNTRL", "TUSERCNTRL", 1))
	l, err := Load(d, allowAll)
	if err != nil {
		t.Fatal(err)
	}
	if l.Source != SourceSystem || !l.IgnoredUserConfig {
		t.Fatalf("Source=%s IgnoredUserConfig=%v", l.Source, l.IgnoredUserConfig)
	}
	if l.Config.Contexts["prod"].TailnetID != "T1234CNTRL" {
		t.Fatal("user config leaked into the system configuration")
	}
}

func TestLoadUserWhenNoSystem(t *testing.T) {
	root := t.TempDir()
	d := Dirs{System: filepath.Join(root, "sys"), User: filepath.Join(root, "usr")}
	writeConfig(t, d.User, validConfig)
	l, err := Load(d, allowAll)
	if err != nil || l.Source != SourceUser {
		t.Fatalf("Load = %v, %v", l, err)
	}
}

func TestLoadMissing(t *testing.T) {
	root := t.TempDir()
	_, err := Load(Dirs{System: filepath.Join(root, "s"), User: filepath.Join(root, "u")}, allowAll)
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ConfigMissing {
		t.Fatalf("err = %v, want config_missing", err)
	}
}

func TestLoadPropagatesCheckerRefusal(t *testing.T) {
	root := t.TempDir()
	d := Dirs{System: filepath.Join(root, "s"), User: filepath.Join(root, "u")}
	writeConfig(t, d.User, validConfig)
	refuse := func(string, ...int) error { return tkerr.New(tkerr.ConfigUnsafe, "nope", "make it safe") }
	l, err := Load(d, refuse)
	e, ok := tkerr.As(err)
	if l != nil || !ok || e.Code != tkerr.ConfigUnsafe || e.Message != "nope" || e.Hint != "make it safe" {
		t.Fatalf("Load = %v, %v; want the checker's own refusal, config_unsafe: nope", l, err)
	}
}

func TestCheckOwnershipRefusesGroupWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SKIPPED: Windows has no strict mode until Windows hardened mode (spec §4)")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, FileName)
	if err := os.WriteFile(p, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckOwnership(p, os.Getuid()); err != nil {
		t.Fatalf("0600 file in 0700 dir refused: %v", err)
	}
	if err := os.Chmod(p, 0o620); err != nil {
		t.Fatal(err)
	}
	if e, ok := tkerr.As(CheckOwnership(p, os.Getuid())); !ok || e.Code != tkerr.ConfigUnsafe {
		t.Fatal("group-writable file accepted")
	}
	link := filepath.Join(dir, "link.hujson")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckOwnership(link, os.Getuid()); err == nil {
		t.Fatal("symlink accepted")
	}
	// With a clean mode, only the owner check can refuse this.
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if e, ok := tkerr.As(CheckOwnership(p, 4242424)); !ok || !strings.Contains(e.Message, "is owned by uid") {
		t.Fatalf("file owned by another uid: %v", e)
	}
}

func TestStrictModeChecksTheDirectoryAndSecretModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SKIPPED: Windows has no strict mode until Windows hardened mode (spec §4)")
	}
	dir := filepath.Join(t.TempDir(), "Application Support's")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "secret")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckSecretFile(p); err != nil {
		t.Fatalf("0600 secret file refused: %v", err)
	}
	quoted := "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if e, ok := tkerr.As(CheckSecretFile(p)); !ok || e.Code != tkerr.ConfigUnsafe || e.Hint != "run: chmod 600 "+quoted {
			t.Errorf("mode %04o: %v", mode, e)
		}
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	// Whoever can write the directory can replace the file.
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if e, ok := tkerr.As(CheckOwnership(p, os.Getuid())); !ok || !strings.Contains(e.Message, dir+" is writable by group") ||
		e.Hint != "run: chmod go-w '"+strings.ReplaceAll(dir, "'", `'\''`)+"'" {
		t.Errorf("group-writable directory: %v", e)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestSelect(t *testing.T) {
	two := `{"contexts":{
	  "a":{"tailnetId":"TACNTRL","credentials":{"read":{"provider":"env"}}},
	  "b":{"tailnetId":"TBCNTRL","credentials":{"read":{"provider":"env"}}}}}`
	c, err := Parse([]byte(two))
	if err != nil {
		t.Fatal(err)
	}
	l := &Loaded{Config: c}
	env := func(k string) string { return map[string]string{"TAILKEEPER_CONTEXT": "b"}[k] }
	none := func(string) string { return "" }
	if name, ctx, err := l.Select("a", env); err != nil || name != "a" || ctx.TailnetID != "TACNTRL" {
		t.Errorf("flag should win, got %q, %+v, %v", name, ctx, err)
	}
	if name, ctx, err := l.Select("", env); err != nil || name != "b" || ctx.TailnetID != "TBCNTRL" {
		t.Errorf("env should be second, got %q, %+v, %v", name, ctx, err)
	}
	if _, _, err := l.Select("", none); err == nil {
		t.Error("ambiguous selection should fail")
	}
	if _, _, err := l.Select("zzz", none); err == nil {
		t.Error("unknown context should fail")
	}
}

func TestParseRejectsDuplicateAndMiscasedKeys(t *testing.T) {
	ctx := func(id string) string {
		return `{"tailnetId": "` + id + `", "credentials": {"read": {"provider": "env"}}}`
	}
	for name, body := range map[string]string{
		"duplicate context":  `{"contexts": {"home": ` + ctx("T1") + `, "home": ` + ctx("T2") + `}}`,
		"duplicate field":    `{"contexts": {"home": {"tailnetId": "T1", "tailnetId": "T2", "credentials": {"read": {"provider": "env"}}}}}`,
		"miscased field":     `{"contexts": {"home": {"TailnetID": "T1", "credentials": {"read": {"provider": "env"}}}}}`,
		"miscased top level": `{"Contexts": {"home": ` + ctx("T1") + `}}`,
	} {
		_, err := Parse([]byte(body))
		if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ConfigInvalid {
			t.Errorf("%s: err = %v, want config_invalid", name, err)
		}
	}
	if _, err := Parse([]byte(`{"contexts": {"home": ` + ctx("T1") + `, "work": ` + ctx("T2") + `}}`)); err != nil {
		t.Errorf("two distinct contexts refused: %v", err)
	}
}

// Load reads the file the Checker approved, not whatever is at the path a moment
// later: a Checker that approves the real file and then puts something else at its
// path (a symlink the check would refuse, or another regular file) gets a refusal.
func TestLoadReadsOnlyTheFileTheCheckApproved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SKIPPED: Windows has no strict mode until Windows hardened mode (spec §4)")
	}
	evil := strings.Replace(validConfig, "T1234CNTRL", "TEVILCNTRL", 1)
	for name, swap := range map[string]func(path, other string) error{
		"a symlink": func(path, other string) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Symlink(other, path)
		},
		"another regular file": func(path, other string) error { return os.Rename(other, path) },
	} {
		root := t.TempDir()
		d := Dirs{System: filepath.Join(root, "sys"), User: filepath.Join(root, "usr")}
		writeConfig(t, d.User, validConfig)
		other := filepath.Join(root, "other.hujson")
		if err := os.WriteFile(other, []byte(evil), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(d.User, FileName)
		swapAfterCheck := func(p string, owners ...int) error {
			if err := CheckOwnership(p, owners...); err != nil {
				return err
			}
			return swap(path, other)
		}
		l, err := Load(d, swapAfterCheck)
		if e, ok := tkerr.As(err); !ok || e.Code != tkerr.ConfigUnsafe {
			t.Errorf("%s: err = %v, want config_unsafe (loaded %v)", name, err, l != nil)
		}
	}
}

func TestReadSecretFileChecksAndReadsTheSameFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SKIPPED: Windows has no strict mode until Windows hardened mode (spec §4)")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "read.env")
	if err := os.WriteFile(p, []byte("A=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadSecretFile(p); err != nil || string(data) != "A=b\n" {
		t.Fatalf("0600 file: %q, %v", data, err)
	}
	// What the check refuses, the read refuses too.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecretFile(p); !isCode(err, tkerr.ConfigUnsafe) {
		t.Errorf("0644 file: err = %v, want config_unsafe", err)
	}
	// A file put in the path's place after the Lstat that preceded the check is not read.
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := inspect(p)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.env")
	if err := os.WriteFile(other, []byte("A=evil\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, p); err != nil {
		t.Fatal(err)
	}
	if data, err := readChecked(p, want); !isCode(err, tkerr.ConfigUnsafe) {
		t.Errorf("replaced file: read %q, err = %v, want config_unsafe", data, err)
	}
}

// isCode reports whether err is a tkerr error with the given code; a nil error is
// not (tkerr.From(nil) is nil, and reading its Code would panic instead of failing).
func isCode(err error, c tkerr.Code) bool {
	e, ok := tkerr.As(err)
	return ok && e.Code == c
}
