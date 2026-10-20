// Package config loads tailkeeper's gate configuration (spec §15).
//
// In M1 the configuration holds contexts (tailnet ID plus read credential), local CLI
// settings, the MCP profile and audit settings. Unknown keys are rejected: a typo must
// never be silently ignored.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// FileName is the configuration file inside a configuration directory.
const FileName = "config.hujson"

// Config is the decoded config.hujson.
type Config struct {
	Contexts       map[string]Context `json:"contexts"`
	DefaultContext string             `json:"defaultContext,omitempty"`
	Local          Local              `json:"local,omitzero"`
	MCP            MCP                `json:"mcp,omitzero"`
	Audit          Audit              `json:"audit,omitzero"`
	ACL            ACL                `json:"acl,omitzero"`
	// PersonalData is "mask" (the default) or "show": whether tool results carry
	// login names, display names, email addresses and public IP addresses whole
	// (spec Appendix C).
	PersonalData string `json:"personalData,omitempty"`
}

// Values of Config.PersonalData.
const (
	PersonalDataMask = "mask"
	PersonalDataShow = "show"
)

// Context binds one tailnet to its credentials. It never carries gate settings.
type Context struct {
	TailnetID   string      `json:"tailnetId"`
	Credentials Credentials `json:"credentials"`
}

// Credentials per class. M1 implements the read class only.
type Credentials struct {
	Read Provider `json:"read"`
}

// Provider says where a credential comes from (spec §7.3).
type Provider struct {
	Provider  string   `json:"provider"`            // "env", "file", "exec" or "oidc"
	Command   []string `json:"command,omitempty"`   // exec: absolute wrapper argv, e.g. ["/path/to/wrapper","--env-file=/etc/tailkeeper/read.env","--"]
	Path      string   `json:"path,omitempty"`      // file: absolute path to a 0600 NAME=value file
	ClientID  string   `json:"clientId,omitempty"`  // oidc: federated identity client ID (not a secret)
	Audience  string   `json:"audience,omitempty"`  // oidc: defaults to api.tailscale.com/<clientId>
	TokenFile string   `json:"tokenFile,omitempty"` // oidc: file holding a platform identity token
}

// Local configures the local tailscale CLI tools.
type Local struct {
	TailscaleBinary   string   `json:"tailscaleBinary,omitempty"`
	Socket            string   `json:"socket,omitempty"`
	DNSQueryAllowlist []string `json:"dnsQueryAllowlist,omitempty"`
}

// MCP configures the stdio MCP server.
type MCP struct {
	Profile     string `json:"profile,omitempty"` // "reads" (default), "core", "full"
	EnableAlpha bool   `json:"enableAlpha,omitempty"`
}

// Audit configures tailkeeper's own audit log.
type Audit struct {
	Reads string `json:"reads,omitempty"` // "metadata" (default) or "none"
}

// ACL configures the policy checks (acl validate, acl diff). The keys are read by
// 0.6.0 and later: a 0.5.0 binary refuses them as unknown (config_invalid), so
// they belong in a context only 0.6.0 uses.
type ACL struct {
	// InvariantsFile is the absolute path of the invariants file: tests every
	// validation must also pass (a HuJSON object with optional "tests" and
	// "sshTests"). Unset means no invariants. A set path that is missing or
	// unreadable fails every call that uses it; it is never taken for none.
	InvariantsFile string `json:"invariantsFile,omitempty"`
	// ValidatePerMinute is the process's own limit on policy validation requests,
	// 1 to 120. Unset means DefaultValidatePerMinute.
	ValidatePerMinute *int `json:"validatePerMinute,omitempty"`
}

// The bounds of ACL.ValidatePerMinute.
const (
	DefaultValidatePerMinute = 30
	MinValidatePerMinute     = 1
	MaxValidatePerMinute     = 120
)

// ValidateRate is the validation requests per minute this process may send.
func (a ACL) ValidateRate() int {
	if a.ValidatePerMinute == nil {
		return DefaultValidatePerMinute
	}
	return *a.ValidatePerMinute
}

var (
	contextNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	tailnetIDRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,252}$`)
)

// Parse decodes HuJSON configuration bytes strictly and validates them.
func Parse(data []byte) (Config, error) {
	// HuJSON's parser recurses once for each level of nesting and has no bound, and a Go stack
	// overflow ends the process: text nested deeper than any configuration is refused unread.
	if guard.NestsDeeperThan(data, guard.MaxDepth) {
		return Config{}, tkerr.New(tkerr.ConfigInvalid, fmt.Sprintf("configuration is nested more than %d levels deep", guard.MaxDepth), configHint)
	}
	std, err := hujson.Standardize(data)
	if err != nil {
		return Config{}, tkerr.Wrap(tkerr.ConfigInvalid, err, "configuration is not valid HuJSON: "+err.Error(), "")
	}
	if err := strictKeys(std); err != nil {
		return Config{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, tkerr.Wrap(tkerr.ConfigInvalid, err, "configuration does not match the schema: "+err.Error(), configHint)
	}
	if dec.More() {
		return Config{}, tkerr.New(tkerr.ConfigInvalid, "configuration has trailing data after the top-level object", "")
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks every field that can be checked without touching the system.
func (c Config) Validate() error {
	if len(c.Contexts) == 0 {
		return invalid("at least one context is required under \"contexts\"")
	}
	names := make([]string, 0, len(c.Contexts))
	for name := range c.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ctx := c.Contexts[name]
		if !contextNameRE.MatchString(name) {
			return invalid(fmt.Sprintf("context name %q must match %s", name, contextNameRE))
		}
		if ctx.TailnetID == "-" || !tailnetIDRE.MatchString(ctx.TailnetID) {
			return invalid(fmt.Sprintf("context %q: tailnetId must be the explicit tailnet ID (never \"-\")", name))
		}
		if err := ctx.Credentials.Read.validate(name + ".credentials.read"); err != nil {
			return err
		}
	}
	if c.DefaultContext != "" {
		if _, ok := c.Contexts[c.DefaultContext]; !ok {
			return invalid(fmt.Sprintf("defaultContext %q is not a defined context", c.DefaultContext))
		}
	}
	switch c.MCP.Profile {
	case "", "reads", "core", "full":
	default:
		return invalid(fmt.Sprintf("mcp.profile %q must be reads, core or full", c.MCP.Profile))
	}
	switch c.PersonalData {
	case "", PersonalDataMask, PersonalDataShow:
	default:
		return invalid(fmt.Sprintf("personalData %q must be mask or show", c.PersonalData))
	}
	switch c.Audit.Reads {
	case "", "metadata", "none":
	default:
		return invalid(fmt.Sprintf("audit.reads %q must be metadata or none", c.Audit.Reads))
	}
	if f := c.ACL.InvariantsFile; f != "" && !filepath.IsAbs(f) {
		return invalid("acl.invariantsFile must be an absolute path")
	}
	if n := c.ACL.ValidatePerMinute; n != nil && (*n < MinValidatePerMinute || *n > MaxValidatePerMinute) {
		return invalid(fmt.Sprintf("acl.validatePerMinute must be a whole number from %d to %d", MinValidatePerMinute, MaxValidatePerMinute))
	}
	if c.Local.TailscaleBinary != "" && !filepath.IsAbs(c.Local.TailscaleBinary) {
		return invalid("local.tailscaleBinary must be an absolute path")
	}
	if c.Local.Socket != "" && !filepath.IsAbs(c.Local.Socket) {
		return invalid("local.socket must be an absolute path")
	}
	return nil
}

func (p Provider) validate(where string) error {
	switch p.Provider {
	case "env":
		if len(p.Command) > 0 || p.Path != "" || p.ClientID != "" || p.TokenFile != "" {
			return invalid(where + ": the env provider takes no other fields")
		}
	case "file":
		if !filepath.IsAbs(p.Path) {
			return invalid(where + ": the file provider needs an absolute \"path\"")
		}
	case "exec":
		if len(p.Command) == 0 || !filepath.IsAbs(p.Command[0]) {
			return invalid(where + ": the exec provider needs \"command\" with an absolute program path")
		}
	case "oidc":
		if p.ClientID == "" {
			return invalid(where + ": the oidc provider needs \"clientId\"")
		}
		if p.TokenFile != "" && !filepath.IsAbs(p.TokenFile) {
			return invalid(where + ": oidc \"tokenFile\" must be an absolute path")
		}
	default:
		return invalid(fmt.Sprintf("%s: provider %q must be env, file, exec or oidc", where, p.Provider))
	}
	return nil
}

func invalid(msg string) error {
	return tkerr.New(tkerr.ConfigInvalid, msg, configHint)
}

const configHint = "see the Configure section of README.md"

// strictKeys rejects what encoding/json would accept silently: an object key
// that appears twice (the last value would win) and a struct key whose case
// differs from the field's name (encoding/json matches names case-insensitively).
// A reviewer reading the file must see exactly what tailkeeper uses.
func strictKeys(std []byte) error {
	dec := json.NewDecoder(bytes.NewReader(std))
	if err := walkKeys(dec, reflect.TypeFor[Config](), ""); err != nil {
		if _, ok := tkerr.As(err); ok {
			return err
		}
		return tkerr.Wrap(tkerr.ConfigInvalid, err, "configuration is not valid JSON: "+err.Error(), configHint)
	}
	return nil
}

func walkKeys(dec *json.Decoder, t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar: the decoder checks its type
	}
	switch delim {
	case '[':
		elem := t
		if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			elem = t.Elem()
		}
		for i := 0; dec.More(); i++ {
			if err := walkKeys(dec, elem, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case '{':
		fields := jsonFields(t)
		seen := map[string]bool{}
		for dec.More() {
			ktok, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := ktok.(string)
			at := key
			if path != "" {
				at = path + "." + key
			}
			if seen[key] {
				return invalid(at + " appears twice; tailkeeper would silently use the last value")
			}
			seen[key] = true
			next := t
			switch t.Kind() {
			case reflect.Struct:
				ft, ok := fields[key]
				if !ok {
					return invalid(at + " is not a configuration key (keys are case-sensitive)")
				}
				next = ft
			case reflect.Map:
				next = t.Elem()
			}
			if err := walkKeys(dec, next, at); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing ] or }
	return err
}

// jsonFields maps a struct's JSON field names to their types.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	if t.Kind() != reflect.Struct {
		return nil
	}
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}
