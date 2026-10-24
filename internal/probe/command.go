package probe

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/sanitize"
)

// DefaultGap is the pause before every request after the first: about 50 validate calls
// and ten reads, spaced 2 s apart, stay well under the API's rate limit.
const DefaultGap = 2 * time.Second

// Command is `tailkeeper probe-acl`, built into the binary only with -tags probe
// (cmd/tailkeeper/probe_on.go). The caller has checked TAILKEEPER_LIVE=1 and resolved the
// read credential; c is the client built from it, whose guard allows GET and the validate
// POST only. It prints the report to stdout and, with --out DIR, writes one skeleton file
// per probe into DIR. The exit code is 0 when every probe ran, 1 when a probe ended in an
// error, was not run, was refused (every request a 401 or 403), or a file could not be
// written, and 2 for a usage error. A check that differs from the probe table
// (docs/design.md §22) is a finding, not a failure.
func Command(ctx context.Context, c *api.Client, args []string, stdout, stderr io.Writer) int {
	// The same opt-in as the command that calls this: a tagged binary still does not
	// read the tailnet unless the switch is set, which only the owner-run targets do.
	if os.Getenv("TAILKEEPER_LIVE") != "1" {
		usageError(stderr, "probe-acl reads the configured tailnet, so it is opt-in: run it with `make probe-acl`, which sets TAILKEEPER_LIVE=1")
		return 2
	}
	// The requests are spaced 2 s apart; only the tests, through command, may go faster.
	if a, err := parseArgs(args); err == nil && a.gap < DefaultGap {
		usageError(stderr, "--gap below "+DefaultGap.String()+" is refused: the live run sends one request every "+DefaultGap.String()+" at most")
		return 2
	}
	return command(ctx, c, args, stdout, stderr, time.Now)
}

// runProbes is Run; the tests replace it to see the options the command passes.
var runProbes = Run

type commandArgs struct {
	out       string
	against   string
	only      []string
	gap       time.Duration
	selfCheck bool
}

func parseArgs(args []string) (commandArgs, error) {
	a := commandArgs{gap: DefaultGap}
	known := map[string]bool{}
	for _, p := range All() {
		known[p.ID] = true
	}
	for i := 0; i < len(args); i++ {
		name, value, hasValue := strings.Cut(args[i], "=")
		take := func() (string, error) {
			if hasValue {
				return value, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", name)
			}
			i++
			return args[i], nil
		}
		switch name {
		case "--out":
			v, err := take()
			if err != nil {
				return a, err
			}
			if v == "" {
				return a, fmt.Errorf("--out needs a directory")
			}
			a.out = v
		case "--only":
			v, err := take()
			if err != nil {
				return a, err
			}
			for _, id := range strings.Split(v, ",") {
				if !known[id] {
					return a, fmt.Errorf("%q is not a probe (A-1 to A-14 and H-1)", id)
				}
				a.only = append(a.only, id)
			}
		case "--gap":
			v, err := take()
			if err != nil {
				return a, err
			}
			d, err := time.ParseDuration(v)
			if err != nil || d < 0 || d > time.Minute {
				return a, fmt.Errorf("--gap takes a duration between 0 and 1m, such as 2s")
			}
			a.gap = d
		case "--self-check":
			a.selfCheck = true
		case "--against":
			v, err := take()
			if err != nil {
				return a, err
			}
			if v == "" {
				return a, fmt.Errorf("--against needs a directory")
			}
			a.against = v
		default:
			return a, fmt.Errorf("unknown argument %q", name)
		}
	}
	return a, nil
}

func usageError(stderr io.Writer, msg string) {
	_, _ = fmt.Fprintf(stderr, "tailkeeper: probe-acl: %s\nusage: probe-acl [--out DIR] [--only A-1,A-3] [--gap 2s] [--self-check --against DIR] (--gap is at least 2s)\n", sanitize.String(msg, sanitize.DefaultMax))
}

func command(ctx context.Context, a API, args []string, stdout, stderr io.Writer, now func() time.Time) int {
	opts, err := parseArgs(args)
	if err != nil {
		usageError(stderr, err.Error())
		return 2
	}
	if opts.against != "" && !opts.selfCheck {
		usageError(stderr, "--against belongs to --self-check, which compares a fresh run with the committed captures")
		return 2
	}
	probes := All()
	selected := len(probes)
	if len(opts.only) > 0 {
		selected = 0
		for _, p := range probes {
			if contains(opts.only, p.ID) {
				selected++
			}
		}
	}
	if opts.selfCheck {
		if opts.against == "" {
			usageError(stderr, "--self-check needs --against DIR, the committed captures")
			return 2
		}
		return selfCheckCommand(ctx, a, opts, stdout, stderr, now)
	}
	_, _ = fmt.Fprintf(stdout, "probe-acl: %d %s, read-only (GET, and POST .../acl/validate, which changes nothing), one request every %s; "+
		"nothing from the tailnet is printed: statuses, key paths, error texts reduced to templates, counts and booleans\n", selected, plural(selected, "probe", "probes"), opts.gap)
	onStart := func(id string) {
		_, _ = fmt.Fprintf(stderr, "tailkeeper: probe-acl: %s\n", sanitize.String(id, sanitize.DefaultMax))
	}
	results := runProbes(ctx, a, probes, Options{Gap: opts.gap, Only: opts.only, OnStart: onStart})
	Render(stdout, results)
	code := 0
	if _, _, errored, notRun := Tally(results); errored > 0 || notRun > 0 {
		code = 1
	}
	for _, r := range results {
		if refused(r) {
			code = 1
		}
	}
	if opts.out != "" {
		names, err := WriteFiles(opts.out, results, now().UTC().Format("2006-01-02"))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "tailkeeper: probe-acl: cannot write the skeletons: %s\n", sanitize.String(err.Error(), sanitize.DefaultMax))
			_, _ = fmt.Fprintf(stderr, "tailkeeper: probe-acl: %s written before the failure\n", files(len(names)))
			for _, n := range names {
				_, _ = fmt.Fprintf(stderr, "  %s\n", sanitize.String(n, sanitize.DefaultMax))
			}
			return 1
		}
		// WriteFiles skips a probe that ended in an error, did not run or was refused, so say which, and why.
		for _, r := range results {
			if r.NotRun {
				_, _ = fmt.Fprintf(stderr, "tailkeeper: probe-acl: no file for %s: not run\n", sanitize.String(r.ID, sanitize.DefaultMax))
				continue
			}
			if r.Error != "" {
				_, _ = fmt.Fprintf(stderr, "tailkeeper: probe-acl: no file for %s: %s\n", sanitize.String(r.ID, sanitize.DefaultMax), sanitize.String(r.Error, sanitize.DefaultMax))
			} else if refused(r) {
				_, _ = fmt.Fprintf(stderr, "tailkeeper: probe-acl: no file for %s: every request was refused (401 or 403); check the credential and its scopes\n", sanitize.String(r.ID, sanitize.DefaultMax))
			}
		}
		_, _ = fmt.Fprintf(stdout, "wrote %s to %s: read them, run both scanners over them, then commit them\n", files(len(names)), sanitize.String(opts.out, sanitize.DefaultMax))
	}
	return code
}

// files is "1 skeleton file" or "N skeleton files".
func files(n int) string {
	if n == 1 {
		return "1 skeleton file"
	}
	return fmt.Sprintf("%d skeleton files", n)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
