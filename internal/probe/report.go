package probe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Render prints the results for a person: for each probe what the probe table (docs/design.md §22) expected, then
// for each request what it expected of it beside what was observed, then the checks
// with MATCH or DIFFERS. Every dynamic piece is a skeleton field, a count, a boolean or
// a fixed sentence from probes.go; no value from the tailnet reaches it.
func Render(w io.Writer, rs []Result) {
	p := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	for _, r := range rs {
		p("\n%s  %s\n", r.ID, r.Title)
		p("  sends:    %s\n  expected: %s\n  branch:   %s\n", r.Sends, r.Expected, r.Branch)
		if r.NotRun {
			p("  NOT RUN: an earlier request stopped the run\n")
			continue
		}
		for _, o := range r.Observations {
			p("  - %s\n", o.Label)
			if o.Expect != "" {
				p("      expect:   %s\n", o.Expect)
			}
			p("      request:  %s\n", o.Request)
			if o.Error != "" {
				p("      observed: no answer (%s)\n", o.Error)
				continue
			}
			sk := o.Result
			p("      observed: HTTP %d, body %s", sk.Status, sk.Body)
			if o.ETag != "" {
				p(", ETag %s", o.ETag)
			}
			p("\n")
			if len(sk.Paths) > 0 {
				var ps []string
				for _, k := range sk.Paths {
					ps = append(ps, k.Path+": "+k.Type)
				}
				p("      paths:    %s\n", strings.Join(ps, "; "))
			}
			for _, t := range sk.Texts {
				p("      text:     %s\n", t)
			}
			if sk.Truncated {
				p("      (cut: the caps in internal/skeleton were reached)\n")
			}
		}
		for _, c := range r.Checks {
			verdict := "MATCH  "
			if !c.Matches() {
				verdict = "DIFFERS"
			}
			p("  %s %s (expected %v, observed %v)\n", verdict, c.Name, c.Want, c.Got)
		}
		for _, name := range sortedKeys(r.Facts) {
			p("  fact      %s: %v\n", name, r.Facts[name])
		}
		for _, name := range sortedKeys(r.Counts) {
			p("  count     %s: %d\n", name, r.Counts[name])
		}
		for _, s := range r.Skipped {
			p("  skipped   %s\n", s)
		}
		if r.Error != "" {
			p("  ERROR     the probe stopped: %s\n", r.Error)
		}
	}
	m, d, e, n := Tally(rs)
	p("\nprobes: %d checks match, %d differ, %d %s stopped by an error, %d not run\n", m, d, e, plural(e, "probe", "probes"), n)
}

// Tally counts the checks that match and differ, the probes that ended in an error, and
// the probes that did not run.
func Tally(rs []Result) (match, differ, errored, notRun int) {
	for _, r := range rs {
		for _, c := range r.Checks {
			if c.Matches() {
				match++
			} else {
				differ++
			}
		}
		if r.Error != "" {
			errored++
		}
		if r.NotRun {
			notRun++
		}
	}
	return match, differ, errored, notRun
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// file is the JSON a probe's skeleton is committed as: internal/api/apitest/testdata/observed/<probe>.json.
type file struct {
	ObservedOn string `json:"observedOn"`
	Result
}

// idRE is what a probe ID looks like (the probe table: A-1 to A-14, H-1); no other ID becomes a file name.
var idRE = regexp.MustCompile(`^[AH]-[0-9]+$`)

// refused reports whether the API refused the credential for a probe: the probe has at
// least one observation and every observation has a Result whose Status is 401 or 403.
// An observation with no Result (a transport error) sets the probe's Error and is not part
// of this rule, and a probe with any observation of another status saw something, so it is
// not refused.
func refused(r Result) bool {
	if len(r.Observations) == 0 {
		return false
	}
	for _, o := range r.Observations {
		if o.Result == nil || (o.Result.Status != 401 && o.Result.Status != 403) {
			return false
		}
	}
	return true
}

// WriteFiles writes one <probe>.json per result into dir, creating it, and returns the
// names it wrote. day is the run's date (YYYY-MM-DD). A probe that did not run, that
// stopped on an error (a 429, the budget, a cancellation, a transport error), or that the
// API refused (every observation a 401 or 403: a revoked key or a missing scope) is not
// written: its file from an earlier complete run stays as it was. A result whose ID is not
// of the form A-n or H-n is refused before anything is written.
func WriteFiles(dir string, rs []Result, day string) ([]string, error) {
	for _, r := range rs {
		if !r.NotRun && r.Error == "" && !refused(r) && !idRE.MatchString(r.ID) {
			return nil, fmt.Errorf("probe ID %q is not of the form A-n or H-n", r.ID)
		}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	var names []string
	for _, r := range rs {
		if r.NotRun || r.Error != "" || refused(r) {
			continue
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false) // the templates hold <s>, <n> and <key>, which the owner reads
		enc.SetIndent("", "  ")
		if err := enc.Encode(file{ObservedOn: day, Result: r}); err != nil {
			return names, err
		}
		b := buf.Bytes()
		name := filepath.Join(dir, r.ID+".json")
		if err := os.WriteFile(name, b, 0o600); err != nil {
			return names, err
		}
		names = append(names, name)
	}
	return names, nil
}
