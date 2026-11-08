package creds

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

var indirectionKinds = []string{"env-key", "env-id", "env-secret", "exec", "file", "oidc-file", "oidc-env", "privacy-env", "privacy-exec", "privacy-file"}

// Removing a checked read from any provider must make the unsafe-file cases fail.
// All files and credential material here are synthetic and kept in t.TempDir.
func resolveIndirection(t *testing.T, kind, path string) (string, error) {
	t.Helper()
	vars := map[string]string{}
	p := config.Provider{Provider: "env"}
	switch kind {
	case "env-id":
		vars[EnvClientID], vars[EnvClientSecret] = "file:"+path, strings.Repeat("s", 32)
	case "env-secret":
		vars[EnvClientID], vars[EnvClientSecret] = "fixture-client", "file:"+path
	case "exec":
		p.Provider = "exec"
		vars[EnvAPIKey] = "file:" + path
	case "file":
		p.Provider = "file"
	case "oidc-file":
		p.Provider, p.TokenFile = "oidc", path
	case "oidc-env":
		p.Provider = "oidc"
		vars[EnvOIDCToken] = "file:" + path
	case "privacy-env", "privacy-exec", "privacy-file":
		vars[privacy.EnvKey] = "file:" + path
		if kind == "privacy-exec" {
			p.Provider = "exec"
		}
		if kind == "privacy-file" {
			p.Provider = "file"
		}
	default:
		vars[EnvAPIKey] = "file:" + path
	}
	if p.Provider == "file" {
		p.Path = filepath.Join(filepath.Dir(path), "provider.env")
		name := EnvAPIKey
		if kind == "privacy-file" {
			name = privacy.EnvKey
		}
		if err := os.WriteFile(p.Path, []byte(name+"=file:"+path+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := System{Getenv: func(k string) string { return vars[k] }}
	if strings.HasPrefix(kind, "privacy-") {
		key, err := PrivacyKey(p, s)
		if err != nil {
			return "", err
		}
		if key == nil {
			t.Fatal("missing key from a valid indirection")
		}
		return "present", nil
	}
	r, err := Resolve(context.Background(), p, s)
	if err != nil {
		return "", err
	}
	if p.Provider == "oidc" {
		return r.IDToken(context.Background())
	}
	if kind == "env-id" {
		return r.ClientID, nil
	}
	if kind == "env-secret" {
		return r.ClientSecret.Reveal(), nil
	}
	return r.APIKey.Reveal(), nil
}

func TestIndirectionRejectsSymlinkAndReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires Windows privileges; reparse rejection is covered in config tests")
	}
	for _, kind := range indirectionKinds {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "secret")
			body := strings.Repeat("5a", 32)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := resolveIndirection(t, kind, path)
			want := body
			if strings.HasPrefix(kind, "privacy-") {
				want = "present"
			}
			if err != nil || got != want {
				t.Fatalf("private regular file failed: %v", err)
			}
			moved := filepath.Join(dir, "moved")
			if err := os.Rename(path, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, path); err != nil {
				t.Fatal(err)
			}
			if _, err := resolveIndirection(t, kind, path); err == nil {
				t.Fatal("followed a replacement symlink to the previously valid file")
			}
		})
	}
}

func TestIndirectionRejectsUnsafeOwnerModeAndOversize(t *testing.T) {
	for _, kind := range indirectionKinds {
		t.Run(kind, func(t *testing.T) {
			for _, scenario := range []string{"mode", "oversize"} {
				t.Run(scenario, func(t *testing.T) {
					if scenario == "mode" && !config.StrictModeEnforced {
						t.Skip("Windows checked reader does not enforce owner/ACL privacy")
					}
					path := filepath.Join(t.TempDir(), "secret")
					body := strings.Repeat("5a", 32)
					mode := os.FileMode(0o644)
					if scenario == "oversize" {
						body = oversizeBody(kind)
						mode = 0o600
					}
					if err := os.WriteFile(path, []byte(body), mode); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(path, mode); err != nil {
						t.Fatal(err)
					}
					_, err := resolveIndirection(t, kind, path)
					want := tkerr.ConfigUnsafe
					if strings.HasPrefix(kind, "privacy-") {
						want = tkerr.PrivacyKeyUnavailable
					}
					if code(err) != want {
						t.Fatalf("%s accepted or misclassified: got %s, want %s", scenario, code(err), want)
					}
					// The code alone is not the proof: a privacy key is refused with the same code
					// when it is malformed. The size limit is the cause that must be there.
					if scenario == "oversize" && !strings.Contains(causes(err), "secret file exceeds 1 MiB") {
						t.Fatalf("oversize refused for another reason than the size limit: %s", causes(err))
					}
				})
			}
		})
	}
}

// oversizeBody is a file just over the 1 MiB cap that the code under test would accept if it
// read it whole: a token for the credential kinds (any text is one), and for the privacy key a
// valid key padded with trailing line feeds, which privacy.Parse trims. A body that the reader
// would refuse anyway (one megabyte of x, which is not hexadecimal) would pass the test with
// no size check at all.
func oversizeBody(kind string) string {
	const size = (1 << 20) + 1
	if strings.HasPrefix(kind, "privacy-") {
		key := strings.Repeat("5a", 32)
		return key + strings.Repeat("\n", size-len(key))
	}
	return strings.Repeat("x", size)
}

// causes is the message of err and of every error it wraps, because a refusal that is
// reclassified (a privacy key's) keeps the reason of the one it replaces as its cause.
func causes(err error) string {
	var parts []string
	for ; err != nil; err = errors.Unwrap(err) {
		parts = append(parts, err.Error())
	}
	return strings.Join(parts, " | ")
}

// The padded key of oversizeBody is a key: with the cap out of the way it parses. This is what
// makes the oversize cases above able to fail.
func TestTheOversizePrivacyBodyIsAKeyWhenReadWhole(t *testing.T) {
	body := oversizeBody("privacy-env")
	if len(body) != (1<<20)+1 {
		t.Fatalf("the body is %d bytes, want one over the cap", len(body))
	}
	if k, err := privacy.Parse(body); err != nil || k == nil {
		t.Fatalf("privacy.Parse refuses the body, so the oversize cases would pass without a size check: %v", err)
	}
}

func TestIndirectionRejectsMixedReferencesAndUnsafeOwner(t *testing.T) {
	valid, unsafePath := absPath("/valid"), absPath("/unsafe")
	for _, provider := range []string{"env", "exec", "file"} {
		t.Run(provider, func(t *testing.T) {
			checked := func(path string) ([]byte, error) {
				switch path {
				case "provider":
					return []byte(EnvClientID + "=file:" + valid + "\n" + EnvClientSecret + "=file:" + unsafePath + "\n"), nil
				case valid:
					return []byte("fixture-client"), nil
				default:
					return nil, tkerr.New(tkerr.ConfigUnsafe, "unexpected owner", "")
				}
			}
			s := System{Getenv: func(k string) string {
				if k == EnvClientID {
					return "file:" + valid
				}
				if k == EnvClientSecret {
					return "file:" + unsafePath
				}
				return ""
			}, ReadSecretFile: checked}
			_, err := Resolve(context.Background(), config.Provider{Provider: provider, Path: "provider"}, s)
			if code(err) != tkerr.ConfigUnsafe {
				t.Fatalf("unchecked fallback or mixed acceptance: %v", err)
			}
		})
	}
}

func TestIndirectionFailureDoesNotEchoSecret(t *testing.T) {
	canary := strings.Repeat("private-fixture-", 8)
	s := System{Getenv: func(k string) string {
		if k == EnvAPIKey {
			return "file:" + absPath("/fixture")
		}
		return ""
	}, ReadSecretFile: func(string) ([]byte, error) { return nil, errors.New(canary) }}
	_, err := Resolve(context.Background(), config.Provider{Provider: "env"}, s)
	if code(err) != tkerr.CredentialUnavailable {
		t.Fatalf("error classification: %v", err)
	}
	b, jerr := json.Marshal(tkerr.From(err))
	if jerr != nil {
		t.Fatal(jerr)
	}
	if strings.Contains(err.Error(), canary) || strings.Contains(string(b), canary) {
		t.Fatal("credential-shaped read cause reached public output")
	}
}
