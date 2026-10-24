package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// untestableControls are the controls an invariants file cannot express. The
// same sentences are the comment at the top of the starter.
var untestableControls = []string{
	"autogroup:admin as a source",
	"an application capability",
	"via",
	"SSH autogroups and groups",
}

const (
	credTagsRead       = "read"
	credTagsNone       = "none"
	credTagsUnreadable = "unreadable (needs oauth_keys:read or federated_keys:read)"
	credTagsNotFound   = "not found (the credential's key record is not in this tailnet)"

	sshTestsComment = "SSH invariants need the owner's SSH users."
)

// StarterInput is the doctor's request for an invariants starter.
type StarterInput struct {
	Out         string   // required; a path, never "-" and never standard output
	Tags        []string // --tag, repeatable
	AdminGroups []string // --admin-group, repeatable
	WithLogins  bool     // --with-logins: admin logins become tests; needs users:read
}

// StarterResult is what doctor prints after the file is written. It carries no login.
type StarterResult struct {
	Path       string   `json:"path"`
	Tests      int      `json:"tests"`
	SSHTests   int      `json:"sshTests"`
	CredTags   string   `json:"credTags"`
	Untestable []string `json:"untestable"`
}

// CheckStarterInput refuses a starter the command could not write, before the
// configuration is loaded and so before any credential is asked for: a path that is
// not a new file, a tag or group that is not spelled as the policy spells it, and a
// starter that names no source of a test. The path is looked at again when the file
// is created.
func CheckStarterInput(in StarterInput) error {
	switch {
	case in.Out == "" || in.Out == "-":
		return tkerr.New(tkerr.Usage, "--policy needs --out FILE, and the starter is never written to standard output", "name a new file")
	case strings.ContainsAny(in.Out, "\r\n") || !utf8.ValidString(in.Out):
		return tkerr.New(tkerr.Usage, "--out must be one line naming a file", "name a new file")
	}
	for _, tag := range in.Tags {
		if !validTag(tag) {
			return tkerr.New(tkerr.Usage, "--tag must look like tag:name", "pass the tag as the policy spells it")
		}
	}
	for _, g := range in.AdminGroups {
		if !validGroup(g) {
			return tkerr.New(tkerr.Usage, "--admin-group must look like group:name", "pass the group as the policy spells it")
		}
	}
	if len(in.AdminGroups) == 0 && !in.WithLogins {
		return noTestsError()
	}
	return inspectOut(in.Out)
}

// noTestsError refuses a starter that would hold no test, which passes validation and
// checks nothing.
func noTestsError() error {
	return tkerr.New(tkerr.Usage, "the starter would hold no test",
		"pass --admin-group GROUP (or --with-logins) for the sources and --tag TAG for the destinations; --tag may be left out when the credential's key has tags")
}

// inspectOut refuses an output path that is not a new file: a symbolic link, a
// directory, a file that exists, or a path that cannot be inspected. It is the one
// classification the early check and the creation share.
func inspectOut(path string) error {
	fi, err := os.Lstat(path)
	switch {
	case err == nil && fi.Mode()&os.ModeSymlink != 0:
		return tkerr.New(tkerr.Usage, path+" is a symbolic link; symlinks are refused", "name the file itself")
	case err == nil && fi.IsDir():
		return tkerr.New(tkerr.Usage, path+" is a directory", "name a new file")
	case err == nil:
		return tkerr.New(tkerr.Usage, path+" already exists; the starter never overwrites a file", "remove it first, or name a new file")
	case !errors.Is(err, os.ErrNotExist):
		return tkerr.New(tkerr.Usage, "cannot inspect "+path+": "+pathReason(err), "")
	}
	return nil
}

// WriteStarter writes an invariants starter the owner reviews. Each admin group,
// and with WithLogins each owner and admin login, is accepted on port 22 of each
// tag named with --tag and of each tag on the credential's key. The file is
// created with O_EXCL and mode 0600: an existing path, a symlink and a directory
// are refused, and nothing is written to standard output.
func WriteStarter(ctx context.Context, a *app.App, in StarterInput) (StarterResult, error) {
	start := time.Now()
	var recorded bool
	finish := func(res StarterResult, err error) (StarterResult, error) {
		if !recorded {
			recorded = true
			recordDoctor(ctx, a, "doctor.policy", start, err)
		}
		return res, err
	}
	if err := CheckStarterInput(in); err != nil {
		return finish(StarterResult{}, err)
	}
	tags := append([]string(nil), in.Tags...)
	credTags := credTagsNone
	if a.KeyID != "" {
		var key tools.Key
		args, err := json.Marshal(map[string]string{"id": a.KeyID})
		if err != nil {
			return finish(StarterResult{}, err)
		}
		err = call(ctx, a, "key_get", string(args), &key)
		switch {
		case err == nil:
			for _, tag := range key.Tags {
				if !validTag(tag) {
					return finish(StarterResult{}, tkerr.New(tkerr.APIError, "the credential's key record has a tag the starter cannot write", "name the tags with --tag"))
				}
			}
			if len(key.Tags) == 0 {
				credTags = credTagsNone
			} else {
				credTags = credTagsRead
				tags = append(tags, key.Tags...)
			}
		case tkerr.From(err).Code == tkerr.ScopeMissing:
			credTags = credTagsUnreadable
		case tkerr.From(err).Code == tkerr.NotFound:
			credTags = credTagsNotFound
		default:
			return finish(StarterResult{}, err)
		}
	}
	var logins []string
	if in.WithLogins {
		var err error
		logins, err = adminLogins(ctx, a)
		if err != nil {
			return finish(StarterResult{}, err)
		}
	}
	groups, names, tagList := uniqueSorted(in.AdminGroups), uniqueSorted(logins), uniqueSorted(tags)
	nTests := (len(groups) + len(names)) * len(tagList)
	if nTests == 0 {
		return finish(StarterResult{}, noTestsError())
	}
	body, err := starterText(groups, names, tagList)
	if err != nil {
		return finish(StarterResult{}, err)
	}
	if err := createStarter(in.Out, body); err != nil {
		return finish(StarterResult{}, err)
	}
	return finish(StarterResult{
		Path: in.Out, Tests: nTests, SSHTests: 0,
		CredTags: credTags, Untestable: slices.Clone(untestableControls),
	}, nil)
}

func starterText(groups, logins, tags []string) ([]byte, error) {
	var b strings.Builder
	b.WriteString("// This file is a template the owner edits. It is not enforced until acl.invariantsFile points at it.\n")
	b.WriteString("// Keep it in the base branch beside CODEOWNERS.\n")
	b.WriteString("// A login in this file must not be committed to a public repository.\n")
	b.WriteString("// Tailscale's test language cannot express these controls:\n")
	for _, c := range untestableControls {
		b.WriteString("// - " + c + "\n")
	}
	b.WriteString("{\n\t\"tests\": [\n")
	sources := append(append([]string{}, groups...), logins...)
	n := 0
	for _, src := range sources {
		for _, tag := range tags {
			line, err := marshalTest(src, tag+":22")
			if err != nil {
				return nil, err
			}
			if n > 0 {
				b.WriteString(",\n")
			}
			b.WriteString("\t\t")
			b.Write(line)
			n++
		}
	}
	if n > 0 {
		b.WriteByte('\n')
	}
	b.WriteString("\t],\n")
	b.WriteString("\t// " + sshTestsComment + "\n")
	b.WriteString("\t\"sshTests\": []\n}\n")
	return []byte(b.String()), nil
}

func marshalTest(src, dst string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(struct {
		Src    string   `json:"src"`
		Accept []string `json:"accept"`
	}{src, []string{dst}}); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func validTag(s string) bool {
	name, ok := strings.CutPrefix(s, "tag:")
	if !ok || name == "" || strings.Contains(name, ":") {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && (r >= '0' && r <= '9' || r == '-' || r == '_'):
		default:
			return false
		}
	}
	return true
}

func validGroup(s string) bool {
	name, ok := strings.CutPrefix(s, "group:")
	if !ok || name == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

func validLogin(s string) bool {
	if s == "" || len(s) > 256 || !strings.Contains(s, "@") || strings.Contains(s, "[p:") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' || r == ' ' {
			return false
		}
	}
	return true
}

type listedUser struct {
	LoginName string `json:"loginName"`
	Role      string `json:"role"`
}

func adminLogins(ctx context.Context, a *app.App) ([]string, error) {
	if a.Env == nil || a.Env.API == nil {
		if a.Env != nil && a.Env.APIErr != nil {
			return nil, maskUsersErr(a.Env.APIErr)
		}
		return nil, tkerr.New(tkerr.CredentialUnavailable, "no read credential is configured", "")
	}
	scopes, known := a.Env.API.GrantedScopes()
	if known && !covers(scopes, "users:read") {
		return nil, usersReadMissing()
	}
	var logins []string
	for _, role := range []string{"owner", "admin"} {
		start := time.Now()
		var page struct {
			Users []listedUser `json:"users"`
		}
		err := a.Env.API.Get(ctx, a.Env.API.TailnetPath("/users"), url.Values{"role": {role}, "type": {"all"}}, &page)
		if err != nil && tkerr.From(err).Code == tkerr.ScopeMissing {
			err = usersReadMissing()
		}
		recordDoctor(ctx, a, "doctor.users", start, err)
		if err != nil {
			return nil, maskUsersErr(err)
		}
		for _, u := range page.Users {
			if u.Role != role || !validLogin(u.LoginName) {
				return nil, tkerr.New(tkerr.APIError, "the users list has a login the starter cannot write", "omit --with-logins and add the logins yourself")
			}
			logins = append(logins, u.LoginName)
		}
	}
	return logins, nil
}

// maskUsersErr masks the message and the hint of an error the users read raised, the way
// the registry masks a tool's error: without a pseudonym, and cut only after masking.
// It masks whatever the owner's personalData setting says, which is the safe direction:
// a starter is written for review, and its errors are read by whoever ran it.
func maskUsersErr(err error) error {
	e := tkerr.From(err)
	if e == nil {
		return err
	}
	c := *e
	c.Message = sanitize.String(sanitize.MaskText(c.Message), sanitize.DefaultMax)
	c.Hint = sanitize.String(sanitize.MaskText(c.Hint), sanitize.DefaultMax)
	return &c
}

func usersReadMissing() error {
	return tkerr.New(tkerr.ScopeMissing, "reading admin logins needs the optional scope users:read",
		"grant users:read to the read credential, or run doctor --policy without --with-logins")
}

func createStarter(path string, body []byte) error {
	if err := inspectOut(path); err != nil {
		return err
	}
	f, err := openNew(path)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return tkerr.New(tkerr.Internal, "cannot write "+path+": "+pathReason(err), "")
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return tkerr.New(tkerr.Internal, "cannot set the mode of "+path+": "+pathReason(err), "")
	}
	if err := f.Close(); err != nil {
		return tkerr.New(tkerr.Internal, "cannot close "+path+": "+pathReason(err), "")
	}
	remove = false
	return nil
}

// openNew creates path for writing, mode 0600, and only if nothing is there: O_EXCL
// fails on an existing file and on a link, dangling or not, which the check before it
// cannot promise once another process has acted.
func openNew(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, tkerr.New(tkerr.Usage, path+" already exists; the starter never overwrites a file", "remove it first, or name a new file")
		}
		return nil, tkerr.New(tkerr.Usage, "cannot create "+path+": "+pathReason(err), "")
	}
	return f, nil
}

func pathReason(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

func recordDoctor(ctx context.Context, a *app.App, tool string, start time.Time, err error) {
	if a == nil {
		return
	}
	f := map[string]any{
		"tool": tool, "tier": "read", "requester": map[string]any{"kind": "doctor"},
		"ms": time.Since(start).Milliseconds(), "status": "ok", "bytes": 0,
	}
	if err != nil {
		f["status"], f["code"] = "error", string(tkerr.From(err).Code)
	}
	if rl, _ := ctx.Value(readLogKey{}).(*readLog); rl != nil {
		if rl.err == nil {
			rl.err = a.Record(f)
		}
		return
	}
	_ = a.Record(f)
}
