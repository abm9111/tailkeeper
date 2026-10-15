package tools_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/local"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

var now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

// tailnetPath is the API path prefix of the fake tailnet.
const tailnetPath = "/api/v2/tailnet/" + apitest.Tailnet

func r(cp rune) string { return string(cp) }

func newRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	reg := registry.New()
	tools.Register(reg)
	return reg
}

// apiEnv returns a fake API, a registry, and an Env whose client talks to the fake.
func apiEnv(t *testing.T) (*apitest.Fake, *registry.Registry, *registry.Env) {
	t.Helper()
	f := apitest.New(t)
	return f, newRegistry(t), &registry.Env{API: f.Client(t), Now: func() time.Time { return now }}
}

// call runs a tool with JSON arguments and returns its output marshalled as JSON.
func call(t *testing.T, reg *registry.Registry, env *registry.Env, name, args string) (string, error) {
	t.Helper()
	tool, ok := reg.Get(name)
	if !ok {
		t.Fatalf("tool %s is not registered", name)
	}
	out, err := tool.Call(context.Background(), env, json.RawMessage(args))
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal %s output: %v", name, err)
	}
	return string(b), nil
}

// mustCall is call that fails the test on error and decodes the output into out.
func mustCall(t *testing.T, reg *registry.Registry, env *registry.Env, name, args string, out any) string {
	t.Helper()
	s, err := call(t, reg, env, name, args)
	if err != nil {
		t.Fatalf("%s %s: %v", name, args, err)
	}
	if out != nil {
		if err := json.Unmarshal([]byte(s), out); err != nil {
			t.Fatalf("decode %s output: %v", name, err)
		}
	}
	return s
}

func code(err error) tkerr.Code {
	if e, ok := tkerr.As(err); ok {
		return e.Code
	}
	return ""
}

// absent fails the test if any canary appears in s.
func absent(t *testing.T, s string, canaries ...string) {
	t.Helper()
	for _, c := range canaries {
		if strings.Contains(s, c) {
			t.Errorf("output contains %q, which must never be returned:\n%s", c, s)
		}
	}
}

// jsonString returns s as a JSON string literal, escaping control characters.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// fakeCLI is a stand-in tailscale CLI. Every call is appended to calls.log; the
// response to an argument list is registered with on(). An unregistered call
// exits 97 so a test notices it.
type fakeCLI struct {
	t   *testing.T
	dir string
}

const fakeScript = `#!/bin/sh
d="$(dirname "$0")"
k=$(printf '%s ' "$@" | od -An -tx1 | tr -d ' \n')
printf '%s\n' "$*" >> "$d/calls.log"
if [ ! -f "$d/$k.out" ]; then echo "fake: no response for: $*" >&2; exit 97; fi
cat "$d/$k.out"
if [ -f "$d/$k.err" ]; then cat "$d/$k.err" >&2; fi
if [ -f "$d/$k.code" ]; then exit "$(cat "$d/$k.code")"; fi
exit 0
`

func newFakeCLI(t *testing.T) *fakeCLI {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in tailscale CLI is a shell script")
	}
	f := &fakeCLI{t: t, dir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(f.dir, "tailscale"), []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

// on registers the response to a space-separated argument list.
func (f *fakeCLI) on(args string, exit int, stdout, stderr string) {
	f.t.Helper()
	key := hex.EncodeToString([]byte(args + " "))
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(f.dir, key+name), []byte(body), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
	write(".out", stdout)
	if stderr != "" {
		write(".err", stderr)
	}
	if exit != 0 {
		write(".code", strconv.Itoa(exit))
	}
}

// calls returns the argument lists the CLI was invoked with, in order.
func (f *fakeCLI) calls() []string {
	b, err := os.ReadFile(filepath.Join(f.dir, "calls.log"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func (f *fakeCLI) env() *registry.Env {
	return &registry.Env{
		Local: &local.Runner{Bin: local.Binary{Path: filepath.Join(f.dir, "tailscale"), Variant: local.VariantConfigured},
			Home: f.dir, PerMinute: 1000},
		Now: func() time.Time { return now },
	}
}
