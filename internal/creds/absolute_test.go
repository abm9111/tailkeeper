package creds

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// absPath makes the Unix-style absolute path of a fixture absolute on this platform. On
// Windows a path with a root and no drive is not absolute, and a file: reference to one is
// refused like a relative path, so the fixtures there get a drive letter.
func absPath(p string) string {
	if runtime.GOOS == "windows" {
		return "C:" + filepath.FromSlash(p)
	}
	return p
}

// A file: reference, and the tokenFile of the oidc provider, name an absolute path. A
// relative one would be read from whatever directory tailkeeper happens to run in, which
// the owner did not choose and an agent's working directory may be. It is refused before
// anything is read, with an error that names the variable (never the path), says what to
// write instead, and is the same wherever the reference sits.
func TestAFileReferenceMustNameAnAbsolutePath(t *testing.T) {
	const hex = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
	good := absPath("/run/secrets/value")
	type site struct {
		name     string
		variable string     // what the refusal names
		code     tkerr.Code // what the refusal is
		ref      func(path string) string
		run      func(ref string, read func(string) ([]byte, error)) (string, error)
	}
	asFile := func(path string) string { return "file:" + path }
	asIs := func(path string) string { return path }
	env := func(vars map[string]string, read func(string) ([]byte, error)) System {
		return System{Getenv: func(k string) string { return vars[k] }, ReadSecretFile: read}
	}
	credential := func(p config.Provider, vars map[string]string, field func(Read) string) func(string, func(string) ([]byte, error)) (string, error) {
		return func(_ string, read func(string) ([]byte, error)) (string, error) {
			r, err := Resolve(context.Background(), p, env(vars, read))
			if err != nil {
				return "", err
			}
			return field(r), nil
		}
	}
	clientID := func(r Read) string { return r.ClientID }
	secret := func(r Read) string { return r.ClientSecret.Reveal() }
	apiKey := func(r Read) string { return r.APIKey.Reveal() }
	// with returns the variables of a site with ref in the one it tests.
	with := func(name, ref string, others ...string) map[string]string {
		vars := map[string]string{name: ref}
		for i := 0; i+1 < len(others); i += 2 {
			vars[others[i]] = others[i+1]
		}
		return vars
	}
	sites := []site{
		{"client ID", EnvClientID, tkerr.ConfigInvalid, asFile, func(ref string, read func(string) ([]byte, error)) (string, error) {
			return credential(config.Provider{Provider: "env"}, with(EnvClientID, ref, EnvClientSecret, "s"), clientID)(ref, read)
		}},
		{"client secret", EnvClientSecret, tkerr.ConfigInvalid, asFile, func(ref string, read func(string) ([]byte, error)) (string, error) {
			return credential(config.Provider{Provider: "env"}, with(EnvClientSecret, ref, EnvClientID, "c"), secret)(ref, read)
		}},
		{"API key", EnvAPIKey, tkerr.ConfigInvalid, asFile, func(ref string, read func(string) ([]byte, error)) (string, error) {
			return credential(config.Provider{Provider: "env"}, with(EnvAPIKey, ref), apiKey)(ref, read)
		}},
		{"API key under the exec provider", EnvAPIKey, tkerr.ConfigInvalid, asFile, func(ref string, read func(string) ([]byte, error)) (string, error) {
			return credential(config.Provider{Provider: "exec", Command: []string{"/bin/true"}}, with(EnvAPIKey, ref), apiKey)(ref, read)
		}},
		{"API key inside the file provider's file", EnvAPIKey, tkerr.ConfigInvalid, asFile, func(ref string, read func(string) ([]byte, error)) (string, error) {
			wrapped := func(p string) ([]byte, error) {
				if p == "provider.env" {
					return []byte(EnvAPIKey + "=" + ref + "\n"), nil
				}
				return read(p)
			}
			r, err := Resolve(context.Background(), config.Provider{Provider: "file", Path: "provider.env"}, env(nil, wrapped))
			if err != nil {
				return "", err
			}
			return r.APIKey.Reveal(), nil
		}},
		{"OIDC token variable", EnvOIDCToken, tkerr.ConfigInvalid, asFile, func(ref string, read func(string) ([]byte, error)) (string, error) {
			r, err := Resolve(context.Background(), config.Provider{Provider: "oidc", ClientID: "c"}, env(map[string]string{EnvOIDCToken: ref}, read))
			if err != nil {
				return "", err
			}
			return r.IDToken(context.Background())
		}},
		{"OIDC tokenFile", "tokenFile", tkerr.ConfigInvalid, asIs, func(ref string, read func(string) ([]byte, error)) (string, error) {
			r, err := Resolve(context.Background(), config.Provider{Provider: "oidc", ClientID: "c", TokenFile: ref}, env(nil, read))
			if err != nil {
				return "", err
			}
			return r.IDToken(context.Background())
		}},
		{"privacy key", privacy.EnvKey, tkerr.PrivacyKeyUnavailable, asFile, func(ref string, read func(string) ([]byte, error)) (string, error) {
			k, err := PrivacyKey(config.Provider{Provider: "env"}, env(map[string]string{privacy.EnvKey: ref}, read))
			if err != nil {
				return "", err
			}
			if k == nil {
				return "", nil
			}
			return "present", nil
		}},
		{"privacy key inside the file provider's file", privacy.EnvKey, tkerr.PrivacyKeyUnavailable, asFile, func(ref string, read func(string) ([]byte, error)) (string, error) {
			wrapped := func(p string) ([]byte, error) {
				if p == "provider.env" {
					return []byte(privacy.EnvKey + "=" + ref + "\n"), nil
				}
				return read(p)
			}
			k, err := PrivacyKey(config.Provider{Provider: "file", Path: "provider.env"}, env(nil, wrapped))
			if err != nil {
				return "", err
			}
			if k == nil {
				return "", nil
			}
			return "present", nil
		}},
	}
	for _, s := range sites {
		t.Run(s.name, func(t *testing.T) {
			var reads []string
			read := func(p string) ([]byte, error) {
				reads = append(reads, p)
				return []byte(hex + "\n"), nil
			}
			// The control: an absolute path is read, once, and gives the file's value. Without it
			// a site that refuses everything would pass the refusals below.
			if got, err := s.run(s.ref(good), read); err != nil || got == "" || len(reads) != 1 || reads[0] != good {
				t.Fatalf("an absolute path: value %q, err %v, reads %v; want one read of %s", got, err, reads, good)
			}
			for _, rel := range []string{"secrets/very-distinct-name", "./very-distinct-name", "../very-distinct-name", "very-distinct-name", ""} {
				if rel == "" && s.ref(rel) == "" {
					continue // an empty tokenFile is none, not a relative path
				}
				reads = nil
				_, err := s.run(s.ref(rel), read)
				e, ok := tkerr.As(err)
				if !ok || e.Code != s.code {
					t.Errorf("%q: err = %v, want %s", s.ref(rel), err, s.code)
					continue
				}
				if !strings.Contains(e.Message, "absolute path") || !strings.Contains(e.Message, s.variable) || strings.Contains(e.Message+e.Hint, "very-distinct-name") {
					t.Errorf("%q: message %q, hint %q: want one that names %s and an absolute path, and not the path typed", s.ref(rel), e.Message, e.Hint, s.variable)
				}
				if len(reads) != 0 {
					t.Errorf("%q: a relative path was read before it was refused: %v", s.ref(rel), reads)
				}
			}
		})
	}
}

// The hint shows an example path, and the example must be absolute where the hint is read:
// "/absolute/path" is not on Windows, where an absolute path starts with a drive.
func TestTheHintsExampleIsAbsoluteOnThisPlatform(t *testing.T) {
	_, err := value(EnvClientSecret, "file:secrets/key", func(string) ([]byte, error) { return nil, nil })
	e, ok := tkerr.As(err)
	if !ok {
		t.Fatalf("err = %v, want a refusal", err)
	}
	_, after, found := strings.Cut(e.Hint, "file:")
	example, _, _ := strings.Cut(after, ",")
	if !found || example == "" {
		t.Fatalf("the hint %q shows no file: example", e.Hint)
	}
	if !filepath.IsAbs(example) {
		t.Errorf("the hint's example %q is not an absolute path on %s", example, runtime.GOOS)
	}
	// The same on the platform this test cannot run on: the spelling of each.
	if got := absoluteExample("windows"); len(got) < 3 || got[1] != ':' || got[2] != '\\' {
		t.Errorf("the Windows example %q does not start with a drive", got)
	}
	if got := absoluteExample("linux"); !strings.HasPrefix(got, "/") {
		t.Errorf("the Unix example %q is not rooted", got)
	}
}
