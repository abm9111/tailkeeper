// Package cli is the tailkeeper command line (spec §16). Tool commands come from
// the registry: `tailkeeper <area> <verb>` runs the tool with that area and verb,
// and its flags come from the tool's input type, so the CLI and MCP accept the
// same parameters and share validation.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/audit"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/creds"
	"github.com/abm9111/tailkeeper/internal/docsgen"
	"github.com/abm9111/tailkeeper/internal/doctor"
	"github.com/abm9111/tailkeeper/internal/mcpserver"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
	"github.com/abm9111/tailkeeper/internal/tripwire"
	"github.com/abm9111/tailkeeper/internal/version"
)

// Runner runs one command line. Its dependencies are injected for tests.
type Runner struct {
	Stdout, Stderr io.Writer
	// Build loads configuration for the named context (app.Build in production).
	Build func(ctx context.Context, contextName string) (*app.App, error)
	// Reexec replaces the process with the exec provider's wrapper; it returns only on failure.
	Reexec func(p config.Provider) error
	// ServeMCP serves srv until the client goes away (stdio in production).
	ServeMCP func(ctx context.Context, srv *mcp.Server) error
	Now      func() time.Time
}

// flagOutput is where a FlagSet writes its errors and usage text. The flag
// package echoes a mistyped flag's name as typed, so what it prints is escaped
// like every other string tailkeeper shows (line feeds and tabs stay, for the
// usage layout). Every FlagSet in this package takes it: fs.SetOutput(flagOutput{r.Stderr}).
type flagOutput struct{ w io.Writer }

func (f flagOutput) Write(p []byte) (int, error) {
	if _, err := io.WriteString(f.w, sanitize.Text(string(p), 0)); err != nil {
		return 0, err
	}
	return len(p), nil
}

type globals struct {
	context string
	json    bool
}

// Run executes args (without the program name) and returns the exit code.
func (r *Runner) Run(ctx context.Context, args []string) int {
	g, rest, err := parseGlobals(args)
	if err != nil {
		return r.fail(tkerr.New(tkerr.Usage, err.Error(), "run `tailkeeper help`"), false)
	}
	if len(rest) == 0 {
		r.usage(r.Stderr)
		return 2
	}
	switch rest[0] {
	case "help", "-h", "--help":
		r.usage(r.Stdout)
		return 0
	case "version":
		_, _ = fmt.Fprintln(r.Stdout, "tailkeeper "+version.Version)
		return 0
	case "docs":
		return r.docs(rest[1:])
	case "scopes":
		return r.scopes(g, rest[1:])
	case "mcp":
		return r.mcp(ctx, g, rest[1:])
	case "doctor":
		return r.doctor(ctx, g, rest[1:])
	case "audit":
		if len(rest) > 1 && (rest[1] == "verify" || rest[1] == "tail" || rest[1] == "rotate") {
			return r.audit(ctx, g, rest[1], rest[2:])
		}
	}
	return r.tool(ctx, g, rest)
}

// parseGlobals reads --context and --json placed before the command.
func parseGlobals(args []string) (globals, []string, error) {
	var g globals
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-h" && args[0] != "--help" {
		switch a := args[0]; {
		case a == "--json" || a == "-json":
			g.json, args = true, args[1:]
		case a == "--context" || a == "-context":
			if len(args) < 2 {
				return g, nil, errors.New("--context needs a value")
			}
			g.context, args = args[1], args[2:]
		case strings.HasPrefix(a, "--context="):
			g.context, args = strings.TrimPrefix(a, "--context="), args[1:]
		default:
			return g, nil, fmt.Errorf("unknown flag %s", a)
		}
	}
	return g, args, nil
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func newRegistry() *registry.Registry {
	reg := registry.New()
	tools.Register(reg)
	return reg
}

func (r *Runner) usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `tailkeeper reads a Tailscale tailnet and this node's Tailscale state.

Usage:
  tailkeeper [--context NAME] [--json] <area> <verb> [flags] [argument]
  tailkeeper mcp [--profile reads|core|full] [--enable-alpha]
  tailkeeper doctor [--probe]
  tailkeeper scopes [--alpha]
  tailkeeper audit verify | audit tail [-n N] | audit rotate
  tailkeeper docs [--scopes] [--check FILE]
  tailkeeper version

Areas and verbs:
`)
	tw := map[string][]string{}
	var areas []string
	for _, t := range newRegistry().All() {
		if _, ok := tw[t.Meta.Area]; !ok {
			areas = append(areas, t.Meta.Area)
		}
		tw[t.Meta.Area] = append(tw[t.Meta.Area], t.Meta.Verb)
	}
	for _, a := range areas {
		_, _ = fmt.Fprintf(w, "  %-11s %s\n", a, strings.Join(tw[a], " | "))
	}
	_, _ = fmt.Fprint(w, "\nRun `tailkeeper <area> <verb> --help` for a command's flags.\n")
}

func (r *Runner) fail(err error, asJSON bool) int {
	fe := tkerr.From(err)
	if fe == nil {
		// nil, or a typed-nil *tkerr.Error
		fe = tkerr.New(tkerr.Internal, "an operation failed without an error", "")
	}
	e := *fe
	// Errors raised outside the registry (configuration, Build, audit) have not been
	// through its scrub: escape them, and withhold text holding a credential shape.
	e.Message, e.Hint = sanitize.String(e.Message, sanitize.DefaultMax), sanitize.String(e.Hint, sanitize.DefaultMax)
	if hit := tripwire.Check([]byte(e.Message + "\n" + e.Hint)); hit != nil {
		w := tkerr.From(hit)
		e.Message, e.Hint = w.Message, w.Hint
	}
	if asJSON {
		_ = writeJSON(r.Stdout, map[string]any{"error": &e})
	} else {
		_, _ = fmt.Fprintf(r.Stderr, "tailkeeper: %s: %s\n", e.Code, e.Message)
		if e.Hint != "" {
			_, _ = fmt.Fprintf(r.Stderr, "  fix: %s\n", e.Hint)
		}
	}
	return tkerr.ExitCode(&e)
}

// reexecIfNeeded re-runs tailkeeper under the exec provider's wrapper when the
// read credential is still missing. It returns false when execution continues.
func (r *Runner) reexecIfNeeded(a *app.App) (int, bool) {
	if !errors.Is(a.Env.APIErr, creds.ErrReexecRequired) {
		return 0, false
	}
	if r.Reexec == nil {
		return r.fail(a.Env.APIErr, false), true
	}
	return r.fail(r.Reexec(a.Provider), false), true
}

func (r *Runner) tool(ctx context.Context, g globals, args []string) int {
	reg := newRegistry()
	area := args[0]
	if len(args) == 1 || args[1] == "-h" || args[1] == "--help" || args[1] == "help" {
		return r.areaUsage(reg, area, len(args) == 1)
	}
	t, ok := reg.ByCommand(area, args[1])
	if !ok {
		return r.fail(tkerr.New(tkerr.Usage, fmt.Sprintf("unknown command `tailkeeper %s %s`", area, args[1]), "run `tailkeeper help`"), g.json)
	}
	fs := flag.NewFlagSet("tailkeeper "+area+" "+args[1], flag.ContinueOnError)
	fs.SetOutput(flagOutput{r.Stderr})
	jsonOut := fs.Bool("json", g.json, "print JSON instead of a table")
	ctxName := fs.String("context", g.context, "configuration context to use")
	b, err := bind(fs, t.InputType, func(name string) string {
		if p, ok := t.InputSchema.Properties[name]; ok {
			return p.Description
		}
		return ""
	})
	if err != nil {
		return r.fail(tkerr.Wrap(tkerr.Internal, err, "cannot build flags for "+t.Meta.Name, ""), g.json)
	}
	fs.Usage = func() {
		arg := ""
		if b.positional != "" {
			arg = " [" + b.positional + "]"
		}
		_, _ = fmt.Fprintf(r.Stderr, "Usage: tailkeeper %s %s [flags]%s\n\n%s\nMCP tool: %s\n\nFlags:\n", area, args[1], arg, t.Meta.Summary, t.Meta.Name)
		fs.PrintDefaults()
	}
	positional, err := parseInterspersed(fs, args[2:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	raw, err := b.arguments(positional)
	if err != nil {
		return r.fail(tkerr.New(tkerr.Usage, err.Error(), "see `tailkeeper "+area+" "+args[1]+" --help`"), *jsonOut)
	}
	a, err := r.Build(ctx, *ctxName)
	if err != nil {
		return r.fail(err, *jsonOut)
	}
	if t.Meta.Credential == registry.CredRead {
		if code, done := r.reexecIfNeeded(a); done {
			return code
		}
	}
	start := r.now()
	out, err := t.Call(ctx, a.Env, raw)
	r.record(a, t, start, out, err)
	if err != nil {
		return r.fail(err, *jsonOut)
	}
	if *jsonOut {
		err = writeJSON(r.Stdout, out)
	} else {
		err = render(r.Stdout, out)
	}
	if err != nil {
		return r.fail(tkerr.Wrap(tkerr.Internal, err, "cannot print the result", ""), false)
	}
	// A result can carry its own exit status: a failed acl test exits 9.
	if ec, ok := out.(interface{ ExitCode() int }); ok {
		return ec.ExitCode()
	}
	return 0
}

func (r *Runner) areaUsage(reg *registry.Registry, area string, missingVerb bool) int {
	found := false
	for _, t := range reg.All() {
		if t.Meta.Area == area {
			if !found {
				_, _ = fmt.Fprintf(r.Stderr, "Usage: tailkeeper %s <verb> [flags]\n\nVerbs:\n", area)
				found = true
			}
			_, _ = fmt.Fprintf(r.Stderr, "  %-14s %s\n", t.Meta.Verb, t.Meta.Summary)
		}
	}
	if !found {
		return r.fail(tkerr.New(tkerr.Usage, fmt.Sprintf("unknown area %q", area), "run `tailkeeper help`"), false)
	}
	if missingVerb {
		return 2
	}
	return 0
}

// record appends the metadata-only read event; a failure is reported, not fatal.
func (r *Runner) record(a *app.App, t registry.Tool, start time.Time, out any, err error) {
	f := map[string]any{"tool": t.Meta.Name, "tier": string(t.Meta.Tier), "requester": map[string]any{"kind": "cli"},
		"ms": r.now().Sub(start).Milliseconds(), "status": "ok", "bytes": 0}
	if err != nil {
		f["status"], f["code"] = "error", string(tkerr.From(err).Code)
	} else if b, merr := json.Marshal(out); merr == nil {
		f["bytes"] = len(b)
	}
	if aerr := a.Record(f); aerr != nil {
		_, _ = fmt.Fprintf(r.Stderr, "tailkeeper: warning: this read was not audited: %s\n", sanitize.String(tkerr.From(aerr).Message, sanitize.DefaultMax))
	}
}

func (r *Runner) docs(args []string) int {
	fs := flag.NewFlagSet("tailkeeper docs", flag.ContinueOnError)
	fs.SetOutput(flagOutput{r.Stderr})
	check := fs.String("check", "", "compare FILE with the generated reference and fail if it is stale")
	scopes := fs.Bool("scopes", false, "render docs/scopes.md (the OAuth scopes) instead of docs/tools.md")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if code, refused := r.refuseArguments(fs, "docs"); refused {
		return code
	}
	md, gen := docsgen.Markdown(newRegistry()), "tailkeeper docs"
	if *scopes {
		md, gen = docsgen.ScopesMarkdown(newRegistry()), "tailkeeper docs --scopes"
	}
	if *check == "" {
		_, _ = fmt.Fprint(r.Stdout, md)
		return 0
	}
	cur, err := os.ReadFile(*check)
	if err != nil {
		why := "it cannot be read"
		if errors.Is(err, os.ErrNotExist) {
			why = "it does not exist"
		}
		return r.fail(tkerr.Wrap(tkerr.Usage, err, "cannot check "+*check+": "+why, "generate it with `make docs` ("+gen+" > "+*check+")"), false)
	}
	if string(cur) != md {
		// The path is what the caller typed: escape it like every other string shown.
		shown := sanitize.String(*check, sanitize.DefaultMax)
		_, _ = fmt.Fprintf(r.Stderr, "tailkeeper: %s is stale; regenerate it with `%s > %s`\n", shown, gen, shown)
		return 1
	}
	return 0
}

// scopes prints the OAuth scopes the tools need: what to grant the read
// credential. Alpha tools' scopes are listed only with --alpha.
func (r *Runner) scopes(g globals, args []string) int {
	fs := flag.NewFlagSet("tailkeeper scopes", flag.ContinueOnError)
	fs.SetOutput(flagOutput{r.Stderr})
	alpha := fs.Bool("alpha", false, "also list the scopes only tools for alpha features need")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if code, refused := r.refuseArguments(fs, "scopes"); refused {
		return code
	}
	var uses []docsgen.ScopeUse
	heldBack := false
	for _, u := range docsgen.Scopes(newRegistry()) {
		if *alpha || !u.AlphaOnly {
			uses = append(uses, u)
		} else {
			heldBack = true
		}
	}
	if err := writeScopes(r.Stdout, uses, heldBack, g.json); err != nil {
		// A cut list must not look whole: the exit code is 1, as for a result that
		// cannot be printed.
		return r.fail(tkerr.Wrap(tkerr.Internal, err, "cannot print the result", ""), false)
	}
	return 0
}

// refuseArguments fails a command that takes flags only when it was given a
// positional argument (`tailkeeper docs tools.md` would otherwise print the
// reference and ignore the name). The argument is what the caller typed: fail
// escapes it like every other message.
func (r *Runner) refuseArguments(fs *flag.FlagSet, command string) (int, bool) {
	if fs.NArg() == 0 {
		return 0, false
	}
	return r.fail(tkerr.New(tkerr.Usage, command+` takes no arguments, got "`+fs.Arg(0)+`"`, "see `tailkeeper "+command+" --help`"), false), true
}

// writeScopes prints uses as JSON or as a table, and returns the first write
// error. heldBack means the caller left alpha-only scopes out of uses; the table
// says so, because otherwise a default listing looks complete.
func writeScopes(w io.Writer, uses []docsgen.ScopeUse, heldBack, asJSON bool) error {
	if asJSON {
		return writeJSON(w, struct {
			Scopes []docsgen.ScopeUse `json:"scopes"`
		}{uses})
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SCOPE\tTOOLS"); err != nil {
		return err
	}
	for _, u := range uses {
		list := strings.Join(u.Tools, ", ")
		if len(u.PartialTools) > 0 {
			if list != "" {
				list += "; "
			}
			list += "in part: " + strings.Join(u.PartialTools, ", ")
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\n", u.Scope, list); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "\nGrant these as read scopes on one OAuth client (docs/scopes.md explains each). `tailkeeper doctor` reports what a configured client lacks."); err != nil {
		return err
	}
	if !heldBack {
		return nil
	}
	_, err := fmt.Fprintln(w, "Not listed: the scopes only tools for alpha features need. `tailkeeper scopes --alpha` includes them.")
	return err
}

func (r *Runner) mcp(ctx context.Context, g globals, args []string) int {
	fs := flag.NewFlagSet("tailkeeper mcp", flag.ContinueOnError)
	fs.SetOutput(flagOutput{r.Stderr})
	profile := fs.String("profile", "", "reads, core or full (default: mcp.profile from the configuration, else reads)")
	alpha := fs.Bool("enable-alpha", false, "also advertise tools for alpha Tailscale features")
	ctxName := fs.String("context", g.context, "configuration context to use")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	// stdout belongs to the protocol from here on: errors go to stderr only.
	a, err := r.Build(ctx, *ctxName)
	if err != nil {
		return r.fail(err, false)
	}
	if code, done := r.reexecIfNeeded(a); done {
		return code
	}
	p, enableAlpha := *profile, *alpha
	if a.Loaded != nil {
		if p == "" {
			p = a.Loaded.Config.MCP.Profile
		}
		enableAlpha = enableAlpha || a.Loaded.Config.MCP.EnableAlpha
	}
	if p == "" {
		p = "reads"
	}
	srv, err := mcpserver.New(a, mcpserver.Options{Profile: p, EnableAlpha: enableAlpha,
		Warn: r.warn, Shutdown: ctx})
	if err != nil {
		return r.fail(err, false)
	}
	if err := r.ServeMCP(ctx, srv); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		return r.fail(tkerr.Wrap(tkerr.Internal, err, "the MCP session ended with an error: "+err.Error(), ""), false)
	}
	return 0
}

// warn prints one warning line from the MCP server to stderr. The warnings quote
// the configuration and the audit log, so the line is escaped whatever the caller
// composed.
func (r *Runner) warn(s string) { _, _ = fmt.Fprintln(r.Stderr, sanitize.String(s, 0)) }

func (r *Runner) doctor(ctx context.Context, g globals, args []string) int {
	fs := flag.NewFlagSet("tailkeeper doctor", flag.ContinueOnError)
	fs.SetOutput(flagOutput{r.Stderr})
	probe := fs.Bool("probe", false, "also call read endpoints whose scope or availability is unverified, and send acl_test a canary test (POST .../acl/validate, which changes nothing)")
	jsonOut := fs.Bool("json", g.json, "print JSON")
	ctxName := fs.String("context", g.context, "configuration context to use")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	a, err := r.Build(ctx, *ctxName)
	if err == nil {
		if code, done := r.reexecIfNeeded(a); done {
			return code
		}
	}
	rep := doctor.Run(ctx, doctor.Input{App: a, BuildErr: err, Probe: *probe, Now: r.now()})
	if *jsonOut {
		_ = writeJSON(r.Stdout, rep)
	} else {
		_ = render(r.Stdout, rep)
		for _, c := range rep.Checks {
			if c.Hint != "" && c.Status != doctor.OK {
				_, _ = fmt.Fprintf(r.Stdout, "fix %s: %s\n", c.Name, sanitize.String(c.Hint, sanitize.DefaultMax))
			}
		}
	}
	return tkerr.ExitCode(rep.Err())
}

func (r *Runner) audit(ctx context.Context, g globals, verb string, args []string) int {
	fs := flag.NewFlagSet("tailkeeper audit "+verb, flag.ContinueOnError)
	fs.SetOutput(flagOutput{r.Stderr})
	n := fs.Int("n", 20, "number of entries (tail)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		// `audit verify <archive>` must not pass by checking the live log instead.
		_, _ = fmt.Fprintf(r.Stderr, "tailkeeper audit %s takes no arguments: it works on the configured log and the archives it continues\n", verb)
		return 2
	}
	a, err := r.Build(ctx, g.context)
	if err != nil {
		return r.fail(err, g.json)
	}
	if verb == "verify" {
		segs, err := audit.VerifyHistory(a.AuditPath)
		if err != nil {
			return r.fail(err, g.json)
		}
		for i, s := range segs {
			// The log's path is the configuration's; an archive's name is read from a
			// rotation entry in a file. Both are escaped like all other output.
			name := sanitize.String(filepath.Base(s.Path), sanitize.DefaultMax)
			switch {
			case i == 0:
				_, _ = fmt.Fprintf(r.Stdout, "%s: %d lines, chain intact\n", sanitize.String(s.Path, 0), s.Lines)
			case s.Missing:
				// Retention, not damage: the exit code stays 0. The first line says
				// "chain intact" about the live log alone, so the gap is also a warning.
				_, _ = fmt.Fprintf(r.Stdout, "  continues %s, which is not present, so it was not checked\n", name)
				_, _ = fmt.Fprintf(r.Stderr, "tailkeeper: warning: %s is not present, so the calls recorded in it cannot be checked\n", name)
			default:
				_, _ = fmt.Fprintf(r.Stdout, "  continues %s: %d lines, chain intact\n", name, s.Lines)
			}
		}
		return 0
	}
	if verb == "rotate" {
		if a.Audit == nil {
			return r.fail(a.AuditErr, g.json)
		}
		archive, err := a.Audit.Rotate()
		if err != nil {
			return r.fail(err, g.json)
		}
		_, _ = fmt.Fprintf(r.Stdout, "%s: started a new log; the old one is kept as %s\n", sanitize.String(a.AuditPath, 0), sanitize.String(archive, 0))
		return 0
	}
	entries, err := audit.Tail(a.AuditPath, *n)
	if err != nil {
		return r.fail(tkerr.Wrap(tkerr.AuditUnavailable, err, "cannot read "+a.AuditPath, ""), g.json)
	}
	// Every entry carries the tailnet ID: show only its start, as doctor does,
	// unless the owner opted in to whole values.
	show := a.Loaded != nil && a.Loaded.Config.PersonalData == config.PersonalDataShow
	enc := json.NewEncoder(r.Stdout)
	for _, e := range entries {
		if id, ok := e["tailnet"].(string); ok && !show {
			e["tailnet"] = sanitize.MaskID(id)
		}
		_ = enc.Encode(e)
	}
	return 0
}
