// Package cli is the tailkeeper command line (spec §16). Tool commands come from
// the registry: `tailkeeper <area> <verb>` runs the tool with that area and verb,
// and its flags come from the tool's input type, so the CLI and MCP accept the
// same parameters and share validation.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/api"
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
	// Stdin is standard input, read by a flag such as --from - in the process that
	// holds the credential; nil reads as empty.
	Stdin io.Reader
	// Registry returns the tools the commands run; nil means the product's. Tests
	// set it to run the framework through tools of their own.
	Registry func() *registry.Registry
	// Probe runs `probe-acl`, the owner's live probes of the validate endpoint. It
	// is nil in every build but one made with -tags probe, which only `make probe-acl` makes;
	// with it nil the command does not exist: it is not in the help and answers as an unknown
	// area.
	Probe func(ctx context.Context, c *api.Client, args []string, stdout, stderr io.Writer) int
	// Getenv reads the environment (os.Getenv when nil): TAILKEEPER_LIVE for probe-acl, and
	// NO_COLOR and TERM for the colour of the human layout. IsTerminal says whether a writer
	// is a terminal (a character device when nil).
	Getenv     func(string) string
	IsTerminal func(io.Writer) bool
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
//
// Everything the command line prints to standard output and standard error goes
// through guardLine, line by line, here, so that no writer of a command can forget
// it: usage text, warnings, the lines of audit and doctor, and the text of errors.
// The JSON a command prints is escaped by writeJSON and writeJSONLine, which leave
// a line the guard has nothing to change. The mcp command does not write to
// standard output through the Runner: its stdout is the protocol's, and ServeMCP
// owns it.
func (r *Runner) Run(ctx context.Context, args []string) int {
	guarded := *r
	out, errOut := &lineGuard{w: r.Stdout}, &lineGuard{w: r.Stderr}
	guarded.Stdout, guarded.Stderr = out, errOut
	code := guarded.run(ctx, args)
	// A last line without its newline is written now. Standard output that cannot
	// take it is exit 1, as for any result that cannot be printed; standard error
	// has never carried an exit code.
	_ = errOut.Flush()
	if err := out.Flush(); err != nil && code == 0 {
		code = 1
	}
	return code
}

func (r *Runner) run(ctx context.Context, args []string) int {
	g, rest, err := parseGlobals(args)
	if err != nil {
		// The flags after the bad one were not read: look for --json in all of them.
		return r.fail(tkerr.New(tkerr.Usage, err.Error(), "run `tailkeeper help`"), g.json || jsonRequested(args))
	}
	if len(rest) == 0 {
		if g.json {
			return r.fail(tkerr.New(tkerr.Usage, "a command is required", "run `tailkeeper help`"), true)
		}
		r.usage(r.Stderr)
		return 2
	}
	switch rest[0] {
	case "help", "-h", "--help":
		r.usage(r.Stdout)
		return 0
	case "version":
		return r.print(g.json, map[string]string{"version": version.Version}, func(w io.Writer) error {
			_, err := fmt.Fprintln(w, "tailkeeper "+version.Version)
			return err
		})
	case "docs":
		return r.docs(g, rest[1:])
	case "scopes":
		return r.scopes(g, rest[1:])
	case "mcp":
		return r.mcp(ctx, g, rest[1:])
	case "doctor":
		return r.doctor(ctx, g, rest[1:])
	case "probe-acl":
		if r.Probe != nil {
			return r.probeACL(ctx, g, rest[1:])
		}
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

// flags is a FlagSet whose own output goes to a buffer, escaped by flagOutput. The
// flag package writes an error and then every flag to its output, which cannot be
// sent as JSON and buries the error: parse reports errors through fail, and the
// buffer is copied out for -h only.
type flags struct {
	*flag.FlagSet
	out *bytes.Buffer
}

func newFlags(name string) *flags {
	f := &flags{out: &bytes.Buffer{}}
	f.FlagSet = flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(flagOutput{f.out})
	f.Usage = func() {}
	return f
}

// printUsage writes header, then the flags and their descriptions, to w.
func (f *flags) printUsage(w io.Writer, header string) {
	f.out.Reset()
	f.PrintDefaults()
	_, _ = io.WriteString(w, header)
	_, _ = io.Copy(w, f.out)
	f.out.Reset()
}

// usageOf returns the function that prints the usage the way the flag package does.
func (r *Runner) usageOf(f *flags) func() {
	return func() { f.printUsage(r.Stderr, fmt.Sprintf("Usage of %s:\n", f.Name())) }
}

// parse runs do, which parses a command line into fs, and reports the outcome: done
// means the command is over, with the exit code. An error is a usage error (exit 2)
// shaped as asJSON says; -h prints usage and exits 0.
func (r *Runner) parse(name string, asJSON func() bool, usage func(), do func() error) (code int, done bool) {
	err := do()
	switch {
	case err == nil:
		return 0, false
	case errors.Is(err, flag.ErrHelp):
		usage()
		return 0, true
	}
	return r.fail(tkerr.New(tkerr.Usage, err.Error(), "see `tailkeeper "+name+" --help`"), asJSON()), true
}

// jsonRequested reports whether args ask for JSON: by --json, or by --format json,
// which is the same. A command line that failed to parse may not have reached its
// flags, so errors look for them too. --format takes its value from the next
// argument when it is not joined by "="; scanning stops at "--".
func jsonRequested(args []string) bool {
	json, formatJSON := false, false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "--":
			return json || formatJSON
		case "-json", "--json":
			json = true
		case "-format", "--format":
			if i+1 < len(args) {
				if args[i+1] == "--" {
					return json || formatJSON
				}
				i++
				formatJSON = args[i] == "json"
			}
		case "-format=json", "--format=json":
			formatJSON = true
		default:
			if strings.HasPrefix(a, "-format=") || strings.HasPrefix(a, "--format=") {
				formatJSON = false
			}
			if v, ok := jsonValue(a); ok {
				// The spellings of a boolean are the flag package's own; a value that is
				// not one is not the switch, and the flag package refuses it too.
				if b, err := strconv.ParseBool(v); err == nil {
					json = b
				}
			}
		}
	}
	return json || formatJSON
}

// jsonValue returns the value of an argument written -json=VALUE or --json=VALUE.
func jsonValue(a string) (string, bool) {
	if v, ok := strings.CutPrefix(a, "--json="); ok {
		return v, true
	}
	return strings.CutPrefix(a, "-json=")
}

// print writes a result as JSON or, by text, for people. A write that fails is exit
// 1: a result that could not be printed in full must not look whole.
func (r *Runner) print(asJSON bool, v any, text func(io.Writer) error) int {
	var err error
	if asJSON {
		err = writeJSON(r.Stdout, v)
	} else {
		err = text(r.Stdout)
	}
	if err != nil {
		// The write that failed is standard output's: the error goes to standard error.
		return r.fail(tkerr.Wrap(tkerr.Internal, err, "cannot print the result", ""), false)
	}
	return 0
}

// foldWriteError makes a failed write of a report that has no exit code of its own
// to carry exit 1; a code the report already has is kept.
func foldWriteError(rc int, err error) int {
	if err != nil && rc == 0 {
		return 1
	}
	return rc
}

// chooseFormat checks --format against --json and the formats that exist. Naming
// json is --json; text, or nothing, is the human layout.
func chooseFormat(format string, jsonOut *bool) error {
	switch format {
	case "":
	case "json":
		*jsonOut = true
	default:
		if _, ok := formatters[format]; !ok {
			return tkerr.New(tkerr.Usage, fmt.Sprintf("--format: %q is not one of %s", format, strings.Join(formatNames(), ", ")), "")
		}
		if *jsonOut {
			return tkerr.New(tkerr.Usage, "--json and --format "+format+" contradict each other", "use one of them")
		}
	}
	return nil
}

func orText(format string) string {
	if format == "" || format == "json" {
		return "text"
	}
	return format
}

// safeReport builds a result's report; a panic in the tool's code is an internal
// error, not a crash of the command.
func safeReport(rp registry.Reporter) (rep registry.Report, err error) {
	defer func() {
		if recover() != nil {
			err = tkerr.New(tkerr.Internal, "unexpected internal error building the report", "report this with `tailkeeper version` output")
		}
	}()
	return rp.Report(), nil
}

// tools returns the registry the commands run.
func (r *Runner) tools() *registry.Registry {
	if r.Registry != nil {
		return r.Registry()
	}
	return newRegistry()
}

// stdin returns standard input for a file flag; empty when none was given.
func (r *Runner) stdin() io.Reader {
	if r.Stdin != nil {
		return r.Stdin
	}
	return strings.NewReader("")
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
  tailkeeper mcp [--context NAME] [--profile reads|core|full] [--enable-alpha]
  tailkeeper doctor [--context NAME] [--json] [--probe]
  tailkeeper scopes [--json] [--alpha]
  tailkeeper audit verify [--json] | audit tail [-n N] [--json] | audit rotate [--json]
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
	if e.Hint == "" {
		e.Hint = tkerr.ProgramHint(e.Code)
	}
	// Errors raised outside the registry (configuration, Build, audit) have not been
	// through its scrub: escape them, and withhold text holding a credential shape.
	e.Message, e.Hint = sanitize.String(e.Message, sanitize.DefaultMax), sanitize.String(e.Hint, sanitize.DefaultMax)
	if hit := tripwire.Check([]byte(e.Message + "\n" + e.Hint)); hit != nil {
		w := tkerr.From(hit)
		e.Message, e.Hint = w.Message, w.Hint
	}
	if asJSON && writeJSON(r.Stdout, map[string]any{"error": &e}) == nil {
		return tkerr.ExitCode(&e)
	}
	// Plain text, also when standard output is gone and the JSON could not be sent.
	_, _ = fmt.Fprintln(r.Stderr, guardLine(fmt.Sprintf("tailkeeper: %s: %s", e.Code, e.Message)))
	if e.Hint != "" {
		_, _ = fmt.Fprintln(r.Stderr, guardLine(fmt.Sprintf("  fix: %s", e.Hint)))
	}
	return tkerr.ExitCode(&e)
}

// reexecIfNeeded re-runs tailkeeper under the exec provider's wrapper when the
// read credential is still missing. It returns false when execution continues.
func (r *Runner) reexecIfNeeded(a *app.App, asJSON bool) (int, bool) {
	if !errors.Is(a.Env.APIErr, creds.ErrReexecRequired) {
		return 0, false
	}
	if r.Reexec == nil {
		return r.fail(a.Env.APIErr, asJSON), true
	}
	return r.fail(r.Reexec(a.Provider), asJSON), true
}

func (r *Runner) tool(ctx context.Context, g globals, args []string) int {
	reg := r.tools()
	area := args[0]
	// Until the command's own flags are parsed, --json anywhere after the area counts.
	routeJSON := g.json || jsonRequested(args[1:])
	flagFirst := len(args) > 1 && strings.HasPrefix(args[1], "-") && args[1] != "-h" && args[1] != "--help"
	if len(args) == 1 || flagFirst || args[1] == "-h" || args[1] == "--help" || args[1] == "help" {
		// A flag where the verb belongs is an area without a verb.
		return r.areaUsage(reg, area, len(args) == 1 || flagFirst, routeJSON)
	}
	t, ok := reg.ByCommand(area, args[1])
	if !ok {
		return r.fail(tkerr.New(tkerr.Usage, fmt.Sprintf("unknown command `tailkeeper %s %s`", area, args[1]), "run `tailkeeper help`"), routeJSON)
	}
	fs := newFlags("tailkeeper " + area + " " + args[1])
	jsonOut := fs.Bool("json", g.json, "print JSON instead of a table")
	ctxName := fs.String("context", g.context, "configuration context to use")
	// A command whose result carries a verdict takes --quiet; one whose result can
	// be gated takes --fail-on. The flags follow the output type, so a command that
	// cannot honour them does not offer them.
	coded := t.OutputType.Implements(reflect.TypeFor[registry.ExitCoder]())
	gated := t.OutputType.Implements(reflect.TypeFor[registry.Gated]())
	reported := t.OutputType.Implements(reflect.TypeFor[registry.Reporter]())
	quiet, failOnValues, format := new(bool), &listValue{}, new(string)
	if reported {
		fs.StringVar(format, "format", "", "output format: "+strings.Join(formatNames(), ", ")+" (default text; json is --json)")
	}
	if coded || gated || reported {
		quiet = fs.Bool("quiet", false, "print nothing when the command succeeds (exit 0)")
	}
	if gated {
		// A command whose result says which kinds it computes lists those; the rest list all.
		kinds := failOnTokens
		if computed, ok := computedKinds(t); ok {
			kinds = computed
		}
		fs.Var(failOnValues, "fail-on", "exit 8 when the result has findings of these kinds: "+strings.Join(kinds, ", ")+" (comma-separated, repeatable)")
	}
	b, err := bind(fs.FlagSet, t.InputType, func(name string) string {
		if p, ok := t.InputSchema.Properties[name]; ok {
			return p.Description
		}
		return ""
	})
	if err != nil {
		return r.fail(tkerr.Wrap(tkerr.Internal, err, "cannot build flags for "+t.Meta.Name+": "+err.Error(), ""), routeJSON)
	}
	usage := func() {
		fs.printUsage(r.Stderr, fmt.Sprintf("Usage: tailkeeper %s %s [flags]%s\n\n%s\nMCP tool: %s\n\nFlags:\n", area, args[1], b.usageArgs(), t.Meta.Summary, t.Meta.Name))
	}
	var positional []string
	asJSON := func() bool { return g.json || *jsonOut || jsonRequested(args[2:]) }
	if code, done := r.parse(area+" "+args[1], asJSON, usage, func() (err error) {
		positional, err = parseInterspersed(fs.FlagSet, args[2:])
		return err
	}); done {
		return code
	}
	// The output format is decided once the flags parsed, before any later refusal:
	// every error from here on is shaped by it, and --format json is --json.
	if err := chooseFormat(*format, jsonOut); err != nil {
		return r.fail(err, *jsonOut)
	}
	if failOnValues.big > 0 {
		return r.fail(tkerr.New(tkerr.Usage, longFlagValue("--fail-on", failOnValues.big), "see `tailkeeper "+area+" "+args[1]+" --help`"), *jsonOut)
	}
	raw, err := b.arguments(positional)
	if err != nil {
		return r.fail(tkerr.New(tkerr.Usage, err.Error(), "see `tailkeeper "+area+" "+args[1]+" --help`"), *jsonOut)
	}
	gate, err := parseFailOn(failOnValues.v)
	if err != nil {
		return r.fail(err, *jsonOut)
	}
	if err := checkKinds(t, gate, b.given()["offline"]); err != nil {
		return r.fail(err, *jsonOut)
	}
	// The tool's own checks come first: a value it refuses must not cost the
	// configuration load or, with the exec provider, a secret-manager unlock.
	p, err := t.Validate(raw)
	if err != nil {
		return r.fail(err, *jsonOut)
	}
	// What the binder can refuse without reading, it refuses now. The files and
	// standard input are read below, once, by the process that holds the credential:
	// the wrapper replaces this process, and standard input goes with it unread.
	if err := b.check(); err != nil {
		return r.fail(err, *jsonOut)
	}
	in := reflect.ValueOf(p.Input()).Elem()
	b.setSwitches(in)
	a, err := r.Build(ctx, *ctxName)
	if err != nil {
		return r.fail(err, *jsonOut)
	}
	if p.NeedsCredential(b.given()) {
		if code, done := r.reexecIfNeeded(a, *jsonOut); done {
			return code
		}
	}
	names, err := b.load(in, r.stdin())
	if err != nil {
		return r.fail(err, *jsonOut)
	}
	// Whatever reaches the tool from a command line is the operator's own.
	b.setOperator(in)
	start := r.now()
	out, err := p.Run(ctx, a.Env)
	r.record(a, t, start, out, err)
	if err != nil {
		return r.fail(err, *jsonOut)
	}
	// The result's own verdict and the --fail-on gates decide the exit code first, so
	// --quiet knows whether the command succeeded.
	code, matched := exitFor(out, gate)
	if !(*quiet && code == 0) {
		text := func(w io.Writer) error { return render(w, out) }
		if rp, ok := out.(registry.Reporter); ok {
			f := formatters[orText(*format)]
			text = func(w io.Writer) error {
				rep, err := safeReport(rp)
				if err != nil {
					return err
				}
				o := formatOptions{Names: names, Color: r.color(w)}
				o.Dir, o.Root, o.Outside = r.repoDir()
				if g, ok := w.(*lineGuard); ok {
					o.Trusted = g.Trusted()
				}
				return f(w, rep, o)
			}
		}
		if c := r.print(*jsonOut, out, text); c != 0 {
			return c
		}
	}
	if code == 8 {
		_, _ = fmt.Fprintf(r.Stderr, "tailkeeper: %s: --fail-on matched %s\n", tkerr.FindingsPresent, strings.Join(matched, ", "))
	}
	return code
}

func (r *Runner) areaUsage(reg *registry.Registry, area string, missingVerb, asJSON bool) int {
	var verbs []string
	for _, t := range reg.All() {
		if t.Meta.Area == area {
			verbs = append(verbs, t.Meta.Verb)
		}
	}
	if len(verbs) == 0 {
		return r.fail(tkerr.New(tkerr.Usage, fmt.Sprintf("unknown area %q", area), "run `tailkeeper help`"), asJSON)
	}
	if missingVerb && asJSON {
		return r.fail(tkerr.New(tkerr.Usage, fmt.Sprintf("`tailkeeper %s` needs a verb: %s", area, strings.Join(verbs, " | ")), "run `tailkeeper help`"), true)
	}
	_, _ = fmt.Fprintf(r.Stderr, "Usage: tailkeeper %s <verb> [flags]\n\nVerbs:\n", area)
	for _, t := range reg.All() {
		if t.Meta.Area == area {
			_, _ = fmt.Fprintf(r.Stderr, "  %-14s %s\n", t.Meta.Verb, t.Meta.Summary)
		}
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

func (r *Runner) docs(g globals, args []string) int {
	fs := newFlags("tailkeeper docs")
	check := fs.String("check", "", "compare FILE with the generated reference and fail if it is stale")
	scopes := fs.Bool("scopes", false, "render docs/scopes.md (the OAuth scopes) instead of docs/tools.md")
	if code, done := r.parse("docs", func() bool { return g.json || jsonRequested(args) }, r.usageOf(fs), func() error { return fs.Parse(args) }); done {
		return code
	}
	if code, refused := r.refuseArguments(fs, "docs", g.json || jsonRequested(args)); refused {
		return code
	}
	md, gen := docsgen.Markdown(newRegistry()), "tailkeeper docs"
	if *scopes {
		md, gen = docsgen.ScopesMarkdown(newRegistry()), "tailkeeper docs --scopes"
	}
	if *check == "" {
		if _, err := io.WriteString(r.Stdout, md); err != nil {
			return r.fail(tkerr.Wrap(tkerr.Internal, err, "cannot print the result", ""), false)
		}
		return 0
	}
	cur, err := os.ReadFile(*check)
	if err != nil {
		why := "it cannot be read"
		if errors.Is(err, os.ErrNotExist) {
			why = "it does not exist"
		}
		return r.fail(tkerr.Wrap(tkerr.Usage, err, "cannot check "+*check+": "+why, "generate it with `"+gen+" > "+*check+"`"), g.json)
	}
	if string(cur) != md {
		// The path is what the caller typed: fail escapes it like every other string shown.
		return r.fail(tkerr.New(tkerr.Conflict, *check+" is stale", "regenerate it with `"+gen+" > "+*check+"`"), g.json || jsonRequested(args))
	}
	return 0
}

// scopes prints the OAuth scopes the tools need: what to grant the read
// credential. Alpha tools' scopes are listed only with --alpha.
func (r *Runner) scopes(g globals, args []string) int {
	fs := newFlags("tailkeeper scopes")
	alpha := fs.Bool("alpha", false, "also list the scopes only tools for alpha features need")
	jsonOut := fs.Bool("json", g.json, "print JSON")
	if code, done := r.parse("scopes", func() bool { return g.json || *jsonOut || jsonRequested(args) }, r.usageOf(fs), func() error { return fs.Parse(args) }); done {
		return code
	}
	if code, refused := r.refuseArguments(fs, "scopes", *jsonOut); refused {
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
	// A cut list must not look whole: the exit code is 1, as for a result that
	// cannot be printed.
	if err := writeScopes(r.Stdout, uses, heldBack, *jsonOut); err != nil {
		return r.fail(tkerr.Wrap(tkerr.Internal, err, "cannot print the result", ""), false)
	}
	return 0
}

// refuseArguments fails a command that takes flags only when it was given a
// positional argument (`tailkeeper docs tools.md` would otherwise print the
// reference and ignore the name). The argument is what the caller typed: fail
// escapes it like every other message.
func (r *Runner) refuseArguments(fs *flags, command string, asJSON bool) (int, bool) {
	if fs.NArg() == 0 {
		return 0, false
	}
	return r.fail(tkerr.New(tkerr.Usage, command+` takes no arguments, got "`+fs.Arg(0)+`"`, "see `tailkeeper "+command+" --help`"), asJSON), true
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
		if len(u.OptionalTools) > 0 {
			if list != "" {
				list += "; "
			}
			parts := make([]string, len(u.OptionalTools))
			for i, o := range u.OptionalTools {
				parts[i] = o.Tool + " (" + o.Reason + ")"
			}
			list += "optionally: " + strings.Join(parts, ", ")
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
	fs := newFlags("tailkeeper mcp")
	profile := fs.String("profile", "", "reads, core or full (default: mcp.profile from the configuration, else reads)")
	alpha := fs.Bool("enable-alpha", false, "also advertise tools for alpha Tailscale features")
	ctxName := fs.String("context", g.context, "configuration context to use")
	// stdout belongs to the protocol: the mcp command reports its errors as text on
	// stderr only, whatever --json says.
	if code, done := r.parse("mcp", func() bool { return false }, r.usageOf(fs), func() error { return fs.Parse(args) }); done {
		return code
	}
	a, err := r.Build(ctx, *ctxName)
	if err != nil {
		return r.fail(err, false)
	}
	if code, done := r.reexecIfNeeded(a, false); done {
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
	fs := newFlags("tailkeeper doctor")
	probe := fs.Bool("probe", false, "also call read endpoints whose scope or availability is unverified, and send acl_test a canary test (POST .../acl/validate, which changes nothing)")
	jsonOut := fs.Bool("json", g.json, "print JSON")
	ctxName := fs.String("context", g.context, "configuration context to use")
	if code, done := r.parse("doctor", func() bool { return g.json || *jsonOut || jsonRequested(args) }, r.usageOf(fs), func() error { return fs.Parse(args) }); done {
		return code
	}
	a, err := r.Build(ctx, *ctxName)
	if err == nil {
		if code, done := r.reexecIfNeeded(a, *jsonOut); done {
			return code
		}
	}
	rep := doctor.Run(ctx, doctor.Input{App: a, BuildErr: err, Probe: *probe, Now: r.now()})
	return r.printReport(rep, *jsonOut)
}

// printReport writes the doctor report. When standard output cannot take it the
// error is said in text on standard error, nothing more is written to the dead
// output, and the report's own exit code is kept (a clean report becomes 1).
func (r *Runner) printReport(rep doctor.Report, asJSON bool) int {
	var werr error
	if asJSON {
		werr = writeJSON(r.Stdout, rep)
	} else {
		werr = render(r.Stdout, rep)
		for _, c := range rep.Checks {
			if werr != nil {
				break
			}
			if c.Hint != "" && c.Status != doctor.OK {
				_, werr = fmt.Fprintf(r.Stdout, "fix %s: %s\n", c.Name, sanitize.String(c.Hint, sanitize.DefaultMax))
			}
		}
	}
	if werr != nil {
		r.fail(tkerr.Wrap(tkerr.Internal, werr, "cannot print the result", ""), false)
	}
	return foldWriteError(tkerr.ExitCode(rep.Err()), werr)
}

// probeACL runs the live probes. They send documents to Tailscale for validation and read
// the tailnet's policy, so the command refuses to start unless TAILKEEPER_LIVE=1 is set,
// which only `make probe-acl` does; the check comes before the configuration is read and
// before the credential wrapper runs. The run is audited like a tool call.
func (r *Runner) probeACL(ctx context.Context, g globals, args []string) int {
	getenv := r.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	if getenv("TAILKEEPER_LIVE") != "1" {
		return r.fail(tkerr.New(tkerr.Usage, "probe-acl reads the configured tailnet and sends documents to its validate endpoint, so it is opt-in",
			"run it with `make probe-acl`, which sets TAILKEEPER_LIVE=1"), g.json)
	}
	a, err := r.Build(ctx, g.context)
	if err != nil {
		return r.fail(err, g.json)
	}
	if code, done := r.reexecIfNeeded(a, g.json); done {
		return code
	}
	if a.Env.API == nil {
		return r.fail(a.Env.APIErr, g.json)
	}
	start := r.now()
	code := r.Probe(ctx, a.Env.API, args, r.Stdout, r.Stderr)
	status := "ok"
	if code != 0 {
		status = "error"
	}
	if aerr := a.Record(map[string]any{"tool": "probe_acl", "tier": string(registry.TierRead), "requester": map[string]any{"kind": "cli"},
		"ms": r.now().Sub(start).Milliseconds(), "status": status, "bytes": 0}); aerr != nil {
		_, _ = fmt.Fprintf(r.Stderr, "tailkeeper: warning: this run was not audited: %s\n", sanitize.String(tkerr.From(aerr).Message, sanitize.DefaultMax))
	}
	return code
}

func (r *Runner) audit(ctx context.Context, g globals, verb string, args []string) int {
	fs := newFlags("tailkeeper audit " + verb)
	n := fs.Int("n", 20, "number of entries (tail)")
	jsonOut := fs.Bool("json", g.json, "print JSON")
	asJSON := func() bool { return g.json || *jsonOut || jsonRequested(args) }
	if code, done := r.parse("audit "+verb, asJSON, r.usageOf(fs), func() error { return fs.Parse(args) }); done {
		return code
	}
	if fs.NArg() > 0 {
		// `audit verify <archive>` must not pass by checking the live log instead.
		return r.fail(tkerr.New(tkerr.Usage, "tailkeeper audit "+verb+" takes no arguments: it works on the configured log and the archives it continues",
			"see `tailkeeper audit "+verb+" --help`"), asJSON())
	}
	a, err := r.Build(ctx, g.context)
	if err != nil {
		return r.fail(err, asJSON())
	}
	if verb == "verify" {
		segs, err := audit.VerifyHistory(a.AuditPath)
		if err != nil {
			return r.fail(err, asJSON())
		}
		type segment struct {
			Path    string `json:"path"`
			Lines   int    `json:"lines"`
			Missing bool   `json:"missing,omitempty"`
		}
		list := make([]segment, len(segs))
		for i, s := range segs {
			// The log's path is the configuration's; an archive's name is read from a
			// rotation entry in a file. Both are escaped like all other output.
			list[i] = segment{Path: sanitize.String(s.Path, 0), Lines: s.Lines, Missing: s.Missing}
		}
		code := r.print(asJSON(), struct {
			Segments []segment `json:"segments"`
		}{list}, func(w io.Writer) error {
			for i, s := range segs {
				name := sanitize.String(filepath.Base(s.Path), sanitize.DefaultMax)
				var err error
				switch {
				case i == 0:
					_, err = fmt.Fprintf(w, "%s: %d lines, chain intact\n", sanitize.String(s.Path, 0), s.Lines)
				case s.Missing:
					// Retention, not damage: the exit code stays 0. The first line says
					// "chain intact" about the live log alone, so the gap is also a warning.
					_, err = fmt.Fprintf(w, "  continues %s, which is not present, so it was not checked\n", name)
				default:
					_, err = fmt.Fprintf(w, "  continues %s: %d lines, chain intact\n", name, s.Lines)
				}
				if err != nil {
					return err
				}
			}
			return nil
		})
		for i, s := range segs {
			if i > 0 && s.Missing {
				_, _ = fmt.Fprintf(r.Stderr, "tailkeeper: warning: %s is not present, so the calls recorded in it cannot be checked\n", sanitize.String(filepath.Base(s.Path), sanitize.DefaultMax))
			}
		}
		return code
	}
	if verb == "rotate" {
		if a.Audit == nil {
			return r.fail(a.AuditErr, asJSON())
		}
		archive, err := a.Audit.Rotate()
		if err != nil {
			return r.fail(err, asJSON())
		}
		return r.print(asJSON(), map[string]string{"log": sanitize.String(a.AuditPath, 0), "archive": sanitize.String(archive, 0)}, func(w io.Writer) error {
			_, err := fmt.Fprintf(w, "%s: started a new log; the old one is kept as %s\n", sanitize.String(a.AuditPath, 0), sanitize.String(archive, 0))
			return err
		})
	}
	entries, err := audit.Tail(a.AuditPath, *n)
	if err != nil {
		return r.fail(tkerr.Wrap(tkerr.AuditUnavailable, err, "cannot read "+a.AuditPath, ""), asJSON())
	}
	// Every entry carries the tailnet ID: show only its start, as doctor does,
	// unless the owner opted in to whole values.
	show := a.Loaded != nil && a.Loaded.Config.PersonalData == config.PersonalDataShow
	for _, e := range entries {
		if id, ok := e["tailnet"].(string); ok && !show {
			e["tailnet"] = sanitize.MaskID(id)
		}
		_ = writeJSONLine(r.Stdout, e)
	}
	return 0
}
