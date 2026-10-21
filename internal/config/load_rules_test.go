package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// A system configuration that cannot be used is an error, never a reason to use the
// user's file instead: the system file wins outright, and a machine whose policy file is
// broken or unsafe must not silently run on whatever a user wrote.
func TestABrokenOrUnsafeSystemConfigurationDoesNotFallBackToTheUsers(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		root := t.TempDir()
		d := Dirs{System: filepath.Join(root, "sys"), User: filepath.Join(root, "usr")}
		writeConfig(t, d.System, `{"contexts": {}}`)
		writeConfig(t, d.User, validConfig)
		l, err := Load(d, allowAll)
		if e, ok := tkerr.As(err); l != nil || !ok || e.Code != tkerr.ConfigInvalid {
			t.Errorf("Load = %v, %v; want config_invalid and no configuration", l, err)
		}
	})
	t.Run("unsafe", func(t *testing.T) {
		root := t.TempDir()
		d := Dirs{System: filepath.Join(root, "sys"), User: filepath.Join(root, "usr")}
		writeConfig(t, d.System, validConfig)
		writeConfig(t, d.User, validConfig)
		var asked []string
		check := func(path string, _ ...int) error {
			asked = append(asked, path)
			return tkerr.New(tkerr.ConfigUnsafe, "refused", "")
		}
		l, err := Load(d, check)
		if e, ok := tkerr.As(err); l != nil || !ok || e.Code != tkerr.ConfigUnsafe {
			t.Errorf("Load = %v, %v; want config_unsafe and no configuration", l, err)
		}
		if want := []string{filepath.Join(d.System, FileName)}; !reflect.DeepEqual(asked, want) {
			t.Errorf("the checker was asked about %v, want only %v: the user's file is not looked at", asked, want)
		}
	})
}

// The context is the flag's, then TAILKEEPER_CONTEXT's, then defaultContext's, and only
// then the one context there is. A configuration with several contexts and a default
// uses the default; the rule for a single context never overrides a default (Parse
// refuses a default that names no context, so with one context the two agree).
func TestDefaultContextBeatsTheOnlyContextRule(t *testing.T) {
	ctx := func(id string) string {
		return `{"tailnetId": "` + id + `", "credentials": {"read": {"provider": "env"}}}`
	}
	parse := func(body string) *Loaded {
		t.Helper()
		c, err := Parse([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		return &Loaded{Config: c}
	}
	none := func(string) string { return "" }
	env := func(k string) string { return map[string]string{"TAILKEEPER_CONTEXT": "work"}[k] }
	two := parse(`{"defaultContext": "home", "contexts": {"home": ` + ctx("THOMECNTRL") + `, "work": ` + ctx("TWORKCNTRL") + `}}`)
	for _, c := range []struct {
		name, flag string
		getenv     func(string) string
		want, id   string
	}{
		{"the default, with two contexts", "", none, "home", "THOMECNTRL"},
		{"the environment beats the default", "", env, "work", "TWORKCNTRL"},
		{"the flag beats the environment", "home", env, "home", "THOMECNTRL"},
	} {
		name, got, err := two.Select(c.flag, c.getenv)
		if err != nil || name != c.want || got.TailnetID != c.id {
			t.Errorf("%s: Select = %q, %+v, %v; want %q (%s)", c.name, name, got, err, c.want, c.id)
		}
	}
	one := parse(`{"contexts": {"only": ` + ctx("TONLYCNTRL") + `}}`)
	if name, got, err := one.Select("", none); err != nil || name != "only" || got.TailnetID != "TONLYCNTRL" {
		t.Errorf("the only context: Select = %q, %+v, %v", name, got, err)
	}
	several := parse(`{"contexts": {"home": ` + ctx("THOMECNTRL") + `, "work": ` + ctx("TWORKCNTRL") + `}}`)
	if e, ok := tkerr.As(func() error { _, _, err := several.Select("", none); return err }()); !ok || e.Code != tkerr.Usage {
		t.Errorf("several contexts and no default: %v, want usage", e)
	}
}

// Load tells the Checker who may own the file: root alone for the system file, root or
// the user running tailkeeper for the user's.
func TestLoadPassesTheOwnersItPromises(t *testing.T) {
	root := t.TempDir()
	d := Dirs{System: filepath.Join(root, "sys"), User: filepath.Join(root, "usr")}
	var got [][]int
	record := func(_ string, owners ...int) error {
		got = append(got, owners)
		return nil
	}
	writeConfig(t, d.User, validConfig)
	if _, err := Load(d, record); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, d.System, validConfig)
	if _, err := Load(d, record); err != nil {
		t.Fatal(err)
	}
	if want := [][]int{{0, os.Getuid()}, {0}}; !reflect.DeepEqual(got, want) {
		t.Errorf("owners passed to the checker = %v, want %v (the user's file, then the system's)", got, want)
	}
}

// A credential file that is not there is the caller's to name: ReadSecretFile returns
// the system's own "does not exist", with no code, so that the provider can say what to
// create and which code that is.
func TestReadSecretFileOfAMissingFileIsAnUntypedNotExist(t *testing.T) {
	_, err := ReadSecretFile(filepath.Join(t.TempDir(), "missing.env"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}
	if e, ok := tkerr.As(err); ok {
		t.Errorf("the error carries the code %s: the caller's code is lost", e.Code)
	}
}
