//go:build !windows

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
)

func mcpbFixtureConfig(t *testing.T, dir, name string, provider config.Provider) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Contexts: map[string]config.Context{name: {TailnetID: apitest.Tailnet, Credentials: config.Credentials{Read: provider}}}, Audit: config.Audit{Reads: "none"}}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, config.FileName), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMCPBProviderReferencesRemainExternal(t *testing.T) {
	for _, kind := range []string{"env", "file", "exec"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			dirs := config.Dirs{System: filepath.Join(root, "system"), User: filepath.Join(root, "user"), State: filepath.Join(root, "state"), Logs: filepath.Join(root, "logs")}
			external := filepath.Join(root, "external")
			if err := os.Mkdir(external, 0o700); err != nil {
				t.Fatal(err)
			}
			keyFile := filepath.Join(external, "read.env")
			if err := os.WriteFile(keyFile, []byte(creds.EnvAPIKey+"="+apitest.AccessToken+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			provider := config.Provider{Provider: kind}
			vars := map[string]string{creds.EnvAPIKey: apitest.AccessToken}
			switch kind {
			case "file":
				provider.Path = keyFile
				vars = map[string]string{}
			case "exec":
				provider.Command = []string{filepath.Join(external, "wrapper")}
			}
			mcpbFixtureConfig(t, dirs.User, "fixture", provider)
			f := apitest.New(t)
			f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/devices", 200, `{"devices":[]}`)
			h := newHarness(t, nil)
			h.r.Build = func(ctx context.Context, name string) (*app.App, error) {
				return app.Build(ctx, app.Options{Context: name, Dirs: &dirs, Getenv: func(k string) string { return vars[k] }, API: api.Options{BaseURL: f.URL()}})
			}
			reexec := 0
			h.r.Reexec = func(config.Provider) error { reexec++; return nil }
			if exit := h.run("devices", "list", "--json"); exit != 0 {
				t.Fatalf("exit %d: %s", exit, h.err)
			}
			if reexec != 0 || len(f.Requests()) != 1 {
				t.Fatalf("reexec=%d, fake requests=%d", reexec, len(f.Requests()))
			}
			if strings.Contains(h.out.String()+h.err.String(), apitest.AccessToken) {
				t.Fatal("fixture value appeared in output")
			}
			if b, err := os.ReadFile(keyFile); err != nil || string(b) != creds.EnvAPIKey+"="+apitest.AccessToken+"\n" {
				t.Fatalf("external fixture changed: %v", err)
			}
		})
	}
}

func TestMCPBSystemConfigPrecedence(t *testing.T) {
	root := t.TempDir()
	dirs := config.Dirs{System: filepath.Join(root, "system"), User: filepath.Join(root, "user"), State: filepath.Join(root, "state"), Logs: filepath.Join(root, "logs")}
	mcpbFixtureConfig(t, dirs.User, "user", config.Provider{Provider: "env"})
	mcpbFixtureConfig(t, dirs.System, "system", config.Provider{Provider: "env"})
	loaded, err := config.Load(dirs, func(string, ...int) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	name, _, err := loaded.Select("", func(string) string { return "" })
	if err != nil || name != "system" || loaded.Source != config.SourceSystem || !loaded.IgnoredUserConfig || len(loaded.Config.Contexts) != 1 {
		t.Fatalf("precedence: name=%q, source=%q, ignored=%t, contexts=%d, error=%v", name, loaded.Source, loaded.IgnoredUserConfig, len(loaded.Config.Contexts), err)
	}
	if _, exists := loaded.Config.Contexts["user"]; exists {
		t.Fatal("user config merged into system config")
	}
}
