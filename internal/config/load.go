package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Dirs are the directories tailkeeper reads and writes.
type Dirs struct {
	System string // root-owned gate configuration (wins outright when it has a config)
	User   string // personal-mode configuration
	State  string // plans and other state (later milestones)
	Logs   string // audit log
}

// DefaultDirs returns the platform directories of spec §15.
func DefaultDirs() (Dirs, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Dirs{}, tkerr.Wrap(tkerr.ConfigInvalid, err, "cannot determine the home directory", "")
	}
	switch runtime.GOOS {
	case "darwin":
		app := filepath.Join(home, "Library", "Application Support", "tailkeeper")
		return Dirs{
			System: "/etc/tailkeeper",
			User:   app,
			State:  app,
			Logs:   filepath.Join(home, "Library", "Logs", "tailkeeper"),
		}, nil
	case "windows":
		pd := os.Getenv("ProgramData")
		ad := os.Getenv("AppData")
		lad := os.Getenv("LocalAppData")
		if pd == "" || ad == "" || lad == "" {
			return Dirs{}, tkerr.New(tkerr.ConfigInvalid, "ProgramData, AppData and LocalAppData must be set", "")
		}
		return Dirs{
			System: filepath.Join(pd, "tailkeeper"),
			User:   filepath.Join(ad, "tailkeeper"),
			State:  filepath.Join(lad, "tailkeeper"),
			Logs:   filepath.Join(lad, "tailkeeper"),
		}, nil
	default:
		cfg := os.Getenv("XDG_CONFIG_HOME")
		if cfg == "" {
			cfg = filepath.Join(home, ".config")
		}
		state := os.Getenv("XDG_STATE_HOME")
		if state == "" {
			state = filepath.Join(home, ".local", "state")
		}
		return Dirs{
			System: "/etc/tailkeeper",
			User:   filepath.Join(cfg, "tailkeeper"),
			State:  filepath.Join(state, "tailkeeper"),
			Logs:   filepath.Join(state, "tailkeeper"),
		}, nil
	}
}

// Source says which directory the configuration came from.
type Source string

const (
	SourceSystem Source = "system"
	SourceUser   Source = "user"
)

// Loaded is a configuration together with where it came from.
type Loaded struct {
	Config            Config
	Source            Source
	Path              string
	Dirs              Dirs
	IgnoredUserConfig bool // a user config exists but the system config won (spec §15: no merging)
}

// Checker verifies that path is safe to load. allowOwners lists acceptable owner UIDs.
type Checker func(path string, allowOwners ...int) error

// Load reads the configuration. When the system directory has a config file, it is
// the only configuration used; the user directory is ignored entirely.
func Load(d Dirs, check Checker) (*Loaded, error) {
	sys := filepath.Join(d.System, FileName)
	usr := filepath.Join(d.User, FileName)
	sysExists, err := exists(sys)
	if err != nil {
		return nil, err
	}
	usrExists, err := exists(usr)
	if err != nil {
		return nil, err
	}
	var path string
	var src Source
	var owners []int
	switch {
	case sysExists:
		path, src, owners = sys, SourceSystem, []int{0}
	case usrExists:
		path, src, owners = usr, SourceUser, []int{0, os.Getuid()}
	default:
		return nil, tkerr.New(tkerr.ConfigMissing,
			fmt.Sprintf("no configuration found at %s or %s", sys, usr),
			"create "+usr+" (see the Configure section of README.md); tailkeeper never falls back to an implicit tailnet")
	}
	want, err := os.Lstat(path)
	if err != nil {
		return nil, tkerr.Wrap(tkerr.ConfigInvalid, err, "cannot inspect "+path, "")
	}
	if err := check(path, owners...); err != nil {
		return nil, err
	}
	data, err := readChecked(path, want)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return &Loaded{Config: cfg, Source: src, Path: path, Dirs: d, IgnoredUserConfig: src == SourceSystem && usrExists}, nil
}

func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, tkerr.Wrap(tkerr.ConfigInvalid, err, "cannot inspect "+path, "")
}

// Select picks the context: the flag value, then TAILKEEPER_CONTEXT, then
// defaultContext, then the only context if there is exactly one.
func (l *Loaded) Select(flagValue string, getenv func(string) string) (string, Context, error) {
	name := flagValue
	if name == "" {
		name = getenv("TAILKEEPER_CONTEXT")
	}
	if name == "" {
		name = l.Config.DefaultContext
	}
	if name == "" && len(l.Config.Contexts) == 1 {
		for only := range l.Config.Contexts {
			name = only
		}
	}
	if name == "" {
		return "", Context{}, tkerr.New(tkerr.Usage, "several contexts are configured and none is selected",
			"pass --context, set TAILKEEPER_CONTEXT, or set defaultContext")
	}
	ctx, ok := l.Config.Contexts[name]
	if !ok {
		return "", Context{}, tkerr.New(tkerr.Usage, fmt.Sprintf("context %q is not configured", name), "")
	}
	return name, ctx, nil
}
