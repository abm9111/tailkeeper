package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/sanitize"
)

// shapeProbeIDs are the probes whose committed captures the self-check compares
// with a fresh run: status and (path, type) sets, not the templated texts.
var shapeProbeIDs = []string{"A-1", "A-8", "A-9", "A-10", "H-1"}

// policyCheckNames are the checks of the live policy against itself, in the order they run.
var policyCheckNames = []string{"reformat", "round-trip", "summary", "etag"}

// SelfCheckCount is how many checks a full self-check makes: the policy checks and one shape
// check for each shape probe. A run that prints fewer dropped some.
func SelfCheckCount() int { return len(policyCheckNames) + len(shapeProbeIDs) }

// SelfCheck is one consistency or shape result. Name is a fixed word or a probe
// ID. Held is whether the check passed. Count is a number of changes, sections
// or differing paths, never a length of a policy text. Note is a fixed word for a
// check that could not be made (noteNotRead, noteNoCapture, noteNotRun,
// noteProbeFailed); Held is false then and Count is 0. Skipped names what the
// check left out because it depends on what the tailnet holds: fixed words only,
// plus a count of unknown sections, never a name from the tailnet.
type SelfCheck struct {
	Name    string
	Held    bool
	Count   int
	Note    string
	Skipped []string
}

// The notes a check that could not be made carries.
const (
	noteNotRead     = "not read"
	noteNoCapture   = "capture missing"
	noteNotRun      = "not run"
	noteProbeFailed = "probe failed"
)

// formatPolicy lays a policy out the way the reformat check compares it. A test
// replaces it with a rewrite that means something else, which the check must report.
var formatPolicy = acl.Format

// summarisePolicy is the summary the summary check counts. A test replaces it with one whose
// counts are wrong, which the check must report.
var summarisePolicy = acl.Summarise

// RunSelfCheck reads the live policy through x and returns the policy checks, then
// the shape checks when x was built with Options.Against set. Each result is a
// boolean and a count. Nothing in it is a name or a text from the tailnet.
func RunSelfCheck(ctx context.Context, x *Exec) []SelfCheck {
	var shapeChecks []SelfCheck
	if x.o.Against != "" {
		var shapes []Result
		shapeChecks, shapes = x.shapeChecks(ctx)
		x.shapes = shapes
	}
	x.res = &Result{}
	return append(x.policyChecks(ctx), shapeChecks...)
}

func (x *Exec) policyChecks(ctx context.Context) []SelfCheck {
	if x.res == nil {
		x.res = &Result{}
	}
	live, err := x.Live(ctx)
	if err != nil || live == nil || !live.Parsed {
		out := make([]SelfCheck, 0, len(policyCheckNames))
		for _, name := range policyCheckNames {
			out = append(out, SelfCheck{Name: name, Note: noteNotRead})
		}
		return out
	}
	text := append([]byte(nil), live.Text...)
	return []SelfCheck{
		reformatCheck(ctx, text),
		roundTripCheck(ctx, text),
		summaryCheck(ctx, text),
		etagCheck(text, live.ETag),
	}
}

func reformatCheck(ctx context.Context, text []byte) SelfCheck {
	formatted, err := formatPolicy(ctx, text)
	if err != nil {
		return SelfCheck{Name: "reformat", Note: noteNotRead}
	}
	same, n, err := meanTheSame(ctx, text, formatted)
	if err != nil {
		return SelfCheck{Name: "reformat", Note: noteNotRead}
	}
	return SelfCheck{Name: "reformat", Held: same, Count: n}
}

// meanTheSame reports whether a and b are one policy, and a count: format-only
// and comment-only changes when they are, and every other class when they are not.
// A dropped rule is not the same policy.
func meanTheSame(ctx context.Context, a, b []byte) (bool, int, error) {
	da, err := acl.Parse(ctx, a)
	if err != nil {
		return false, 0, err
	}
	db, err := acl.Parse(ctx, b)
	if err != nil {
		return false, 0, err
	}
	d, err := acl.Diff(ctx, da, db, acl.DiffOptions{})
	if err != nil {
		return false, 0, err
	}
	if !d.SemanticallyEqual {
		n := d.Counts.Semantic + d.Counts.Defaults + d.Counts.TestsReduced + d.Counts.Widening + d.Counts.TailscaleWritten
		return false, n, nil
	}
	return true, d.Counts.FormatOnly + d.Counts.CommentOnly, nil
}

func roundTripCheck(ctx context.Context, text []byte) SelfCheck {
	first, err := acl.Parse(ctx, text)
	if err != nil {
		return SelfCheck{Name: "round-trip", Note: noteNotRead}
	}
	formatted, err := formatPolicy(ctx, text)
	if err != nil {
		return SelfCheck{Name: "round-trip", Note: noteNotRead}
	}
	second, err := acl.Parse(ctx, formatted)
	if err != nil {
		return SelfCheck{Name: "round-trip", Note: noteNotRead}
	}
	b1, err := acl.NormalFormBytes(ctx, first)
	if err != nil {
		return SelfCheck{Name: "round-trip", Note: noteNotRead}
	}
	b2, err := acl.NormalFormBytes(ctx, second)
	if err != nil {
		return SelfCheck{Name: "round-trip", Note: noteNotRead}
	}
	if !bytes.Equal(b1, b2) {
		return SelfCheck{Name: "round-trip", Count: 1}
	}
	return SelfCheck{Name: "round-trip", Held: true}
}

func summaryCheck(ctx context.Context, text []byte) SelfCheck {
	d, err := acl.Parse(ctx, text)
	if err != nil {
		return SelfCheck{Name: "summary", Note: noteNotRead}
	}
	s, err := summarisePolicy(ctx, d)
	if err != nil {
		return SelfCheck{Name: "summary", Note: noteNotRead}
	}
	indep, err := independentSectionCounts(text)
	if err != nil {
		return SelfCheck{Name: "summary", Note: noteNotRead}
	}
	held, n := countsMatch(s.Sections, indep)
	return SelfCheck{Name: "summary", Held: held, Count: n, Skipped: indep.skippedWords()}
}

// countsMatch reports whether each present known section's count equals the
// independent count of that top-level member, and how many sections were compared.
// An absent section is not a member. A member the summary does not name is a miss.
// A section the independent side did not count (see sectionCounts) is not compared.
func countsMatch(sections []acl.SectionSummary, indep sectionCounts) (bool, int) {
	held := true
	matched := 0
	seen := map[string]bool{}
	for _, sec := range sections {
		if !sec.Known {
			continue
		}
		key := strings.ToLower(sec.Name)
		if indep.skipped[key] {
			continue
		}
		want, ok := indep.counts[key]
		if sec.State == acl.StateAbsent {
			if ok {
				held = false
			}
			continue
		}
		if !ok || want != sec.Count {
			held = false
			continue
		}
		seen[key] = true
		matched++
	}
	for k := range indep.counts {
		if !seen[k] {
			held = false
		}
	}
	return held, matched
}

// sectionKind is how the summary counts a known section's value.
type sectionKind int

const (
	kindArray  sectionKind = iota // the elements of an array
	kindMap                       // the entries of an object
	kindStruct                    // autoApprovers, derpMap: see structEntries
	kindScalar                    // 1
)

// knownSectionKinds are the sections the summary counts, by lower-case name. It is
// written here, not read from the acl package, so the check does not depend on the
// table it checks; a test holds it to that table.
var knownSectionKinds = map[string]sectionKind{
	"acls": kindArray, "grants": kindArray, "ssh": kindArray, "nodeattrs": kindArray,
	"sshtests": kindArray, "tests": kindArray, "extradnsrecords": kindArray, "defaultsrcposture": kindArray,
	"groups": kindMap, "hosts": kindMap, "ipsets": kindMap, "postures": kindMap, "tagowners": kindMap,
	"externaltailnets": kindMap, "attrconfig": kindMap,
	"autoapprovers": kindStruct, "derpmap": kindStruct,
	"disableipv4": kindScalar, "onecgnatroute": kindScalar, "randomizeclientport": kindScalar,
}

// sectionCounts is the independent count of a policy's top-level members.
type sectionCounts struct {
	counts  map[string]int  // known sections that hold a value, by lower-case name
	skipped map[string]bool // known sections not counted: spelled twice with different case
	unknown int             // members the table does not know: the summary lists at most MaxNames of them, so they are not compared
}

// skippedWords names what was left out, in fixed words and a count.
func (c sectionCounts) skippedWords() []string {
	var out []string
	for _, sec := range acl.Sections() {
		if c.skipped[strings.ToLower(sec.Name)] {
			out = append(out, sec.Name)
		}
	}
	if c.unknown > 0 {
		out = append(out, fmt.Sprintf("%d unknown", c.unknown))
	}
	return out
}

// independentSectionCounts counts each known top-level member of text by the rule
// the summary documents: the elements of an array section, the entries of a map
// section, one entry per route, service or region for a field of autoApprovers or
// derpMap that is an object with members and one for any other field, 1 for a
// scalar, and 1 for a value of the wrong type. A null member is absent. A member
// the table does not know is counted, not compared; so is a known section written
// twice in different case.
func independentSectionCounts(text []byte) (sectionCounts, error) {
	out := sectionCounts{counts: map[string]int{}, skipped: map[string]bool{}}
	std, err := hujson.Standardize(append([]byte(nil), text...))
	if err != nil {
		return out, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(std, &doc); err != nil {
		return out, err
	}
	spellings := map[string]int{}
	for k := range doc {
		spellings[strings.ToLower(k)]++
	}
	for k, raw := range doc {
		key := strings.ToLower(k)
		first := firstByte(raw)
		if first == 0 || first == 'n' {
			continue
		}
		kind, known := knownSectionKinds[key]
		switch {
		case !known:
			out.unknown++
			continue
		case spellings[key] > 1:
			out.skipped[key] = true
			continue
		}
		n, err := countSection(kind, first, raw)
		if err != nil {
			return out, err
		}
		out.counts[key] = n
	}
	return out, nil
}

func countSection(kind sectionKind, first byte, raw json.RawMessage) (int, error) {
	switch {
	case kind == kindScalar:
		return 1, nil
	case kind == kindArray && first == '[':
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return 0, err
		}
		return len(items), nil
	case first != '{', kind == kindArray:
		return 1, nil // a value of the wrong type is one entry
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return 0, err
	}
	if kind == kindMap {
		return len(members), nil
	}
	return structEntries(members), nil
}

// structEntries counts the fields of autoApprovers or derpMap as the summary does:
// a field that is an object with members counts each member, any other field counts 1.
func structEntries(fields map[string]json.RawMessage) int {
	n := 0
	for _, raw := range fields {
		var sub map[string]json.RawMessage
		if firstByte(raw) == '{' && json.Unmarshal(raw, &sub) == nil && len(sub) > 0 {
			n += len(sub)
			continue
		}
		n++
	}
	return n
}

func firstByte(raw json.RawMessage) byte {
	for _, c := range raw {
		if c == ' ' || c == '\n' || c == '\t' || c == '\r' {
			continue
		}
		return c
	}
	return 0
}

func etagCheck(text []byte, etag string) SelfCheck {
	if etag == "" {
		return SelfCheck{Name: "etag", Note: noteNotRead}
	}
	if etag != api.ETagOf(text) {
		return SelfCheck{Name: "etag"}
	}
	return SelfCheck{Name: "etag", Held: true, Count: 1}
}

// shapeChecks runs the selected shape probes and compares each with its committed
// capture. The committed captures come from a full run, where an earlier probe has
// already read the live policy; so the live policy is read once here, into no probe's
// result, and the five shapes see it held in memory as they do in a full run.
func (x *Exec) shapeChecks(ctx context.Context) ([]SelfCheck, []Result) {
	ids := x.selectedShapes()
	checks := make([]SelfCheck, 0, len(ids))
	results := make([]Result, 0, len(ids))
	if len(ids) > 0 && x.stopped == nil && ctx.Err() == nil {
		x.res = &Result{}
		_, _ = x.Live(ctx) // an error stays in x.liveErr, where the probes that need the policy see it
	}
	for _, id := range ids {
		p, ok := probeByID(id)
		if !ok {
			checks = append(checks, SelfCheck{Name: id, Note: noteNotRun})
			continue
		}
		if x.stopped != nil || ctx.Err() != nil {
			checks = append(checks, SelfCheck{Name: id, Note: noteNotRun})
			results = append(results, Result{ID: p.ID, Title: p.Title, Sends: p.Sends, Expected: p.Expected, Branch: p.Branch, NotRun: true})
			continue
		}
		if x.o.OnStart != nil {
			x.o.OnStart(id)
		}
		r := Result{ID: p.ID, Title: p.Title, Sends: p.Sends, Expected: p.Expected, Branch: p.Branch}
		x.res = &r
		if err := x.runOne(ctx, p); err != nil {
			r.Error = errorCode(err)
		}
		if x.stopped != nil {
			r.Error = errorCode(x.stopped)
		}
		results = append(results, r)
		if r.Error != "" {
			checks = append(checks, SelfCheck{Name: id, Note: noteProbeFailed})
			continue
		}
		committed, err := loadCapture(x.o.Against, id)
		if err != nil {
			checks = append(checks, SelfCheck{Name: id, Note: noteNoCapture})
			continue
		}
		n, skipped := shapeDrift(id, committed, r)
		checks = append(checks, SelfCheck{Name: id, Held: n == 0, Count: n, Skipped: skipped})
	}
	return checks, results
}

func (x *Exec) selectedShapes() []string {
	if len(x.o.Only) == 0 {
		return shapeProbeIDs
	}
	var out []string
	for _, id := range shapeProbeIDs {
		if contains(x.o.Only, id) {
			out = append(out, id)
		}
	}
	return out
}

func probeByID(id string) (Probe, bool) {
	for _, p := range All() {
		if p.ID == id {
			return p, true
		}
	}
	return Probe{}, false
}

func loadCapture(dir, id string) (Result, error) {
	if !idRE.MatchString(id) {
		return Result{}, fmt.Errorf("probe ID %q is not of the form A-n or H-n", id)
	}
	b, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		return Result{}, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return Result{}, err
	}
	return f.Result, nil
}

// dependentStep is a part of a probe's result that depends on what the tailnet holds. Word
// is how the check line names it. Omit are observation labels of steps that exist only when
// the tailnet holds something of their kind; StatusOnly are labels whose body is the policy
// text itself, compared by status alone; Paths are the key paths (with what lies below them)
// whose type depends on the policy's content.
type dependentStep struct {
	Word       string
	Omit       []string
	StatusOnly []string
	Paths      []string
	// Keep are paths below Paths that are compared all the same.
	Keep []string
}

// tailnetDependentSteps are those parts, by probe ID: a tag, a host alias, a login written
// as an address and a service for A-9's tests-mode requests; A-10's request built from the
// first ssh rule; for A-8 the plain policy text, which is JSON or not as the policy is
// written, and the warnings and errors of a details answer, which are null when the policy
// has none and lists when it has; for H-1 the entries of the audit log, whose fields depend
// on who edited the policy (a person, an API key, nobody) and on whether anyone did. A shape
// comparison leaves them out on both sides: what the tailnet holds is not a shape of the API.
// H-1 keeps what acl_history and acl_diff read of an entry when both sides hold one
// (h1EntrySteps).
var tailnetDependentSteps = map[string][]dependentStep{
	"A-8": {
		{Word: "the form of the policy text", StatusOnly: []string{"plain, Accept: application/hujson", "plain, If-None-Match: the plain ETag"}},
		{Word: "warnings and errors", Paths: []string{"warnings", "errors"}},
	},
	"A-9": {
		{Word: a9KindTag, Omit: []string{a9Label(a9KindTag)}},
		{Word: a9KindHost, Omit: []string{a9Label(a9KindHost)}},
		{Word: a9KindUser, Omit: []string{a9Label(a9KindUser)}},
		{Word: a9KindService, Omit: []string{a9Label(a9KindService)}},
	},
	"A-10": {{Word: "the ssh fallback", Omit: []string{a10Fallback}}},
	"H-1":  {{Word: "the audit log entries", Paths: []string{"logs"}}},
}

// h1EntrySteps are the parts of H-1 left out when both the capture and the run hold an entry
// of the audit log. The entry's time and its old and new texts are compared by type, for they
// are what a policy version is read from; who made the entry, what it names and the fields an
// entry may leave out are not.
var h1EntrySteps = []dependentStep{{
	Word:  "the actor and target of an entry, and the fields an entry may omit",
	Paths: []string{"logs"},
	Keep:  []string{"logs", "logs[]", "logs[].eventTime", "logs[].old", "logs[].new"},
}}

// holdsEntries reports whether a probe result has an entry in a list of the audit log.
func holdsEntries(r Result) bool {
	for _, o := range r.Observations {
		if _, ok := pathTypes(o.Result)["logs[]"]; ok {
			return true
		}
	}
	return false
}

// dependentSteps are the parts a shape comparison of probe id leaves out of a capture and a
// run. H-1 compares the shape of an entry of the audit log when both hold one, and leaves the
// entries out when either has none.
func dependentSteps(id string, committed, now Result) []dependentStep {
	if id == "H-1" && holdsEntries(committed) && holdsEntries(now) {
		return h1EntrySteps
	}
	return tailnetDependentSteps[id]
}

// dependentLabels is the observation labels a shape comparison with these steps leaves out.
func dependentLabels(steps []dependentStep) map[string]bool {
	out := map[string]bool{}
	for _, d := range steps {
		for _, l := range d.Omit {
			out[l] = true
		}
	}
	return out
}

// dependentPath reports whether a difference at path, in the observation labelled label, is
// one a shape comparison with these steps leaves out.
func dependentPath(steps []dependentStep, label, path string) bool {
	for _, d := range steps {
		for _, l := range d.StatusOnly {
			if label == l && path != "status" {
				return true
			}
		}
		for _, p := range d.Paths {
			if (path == p || strings.HasPrefix(path, p+"[]") || strings.HasPrefix(path, p+".")) && !contains(d.Keep, path) {
				return true
			}
		}
	}
	return false
}

// dependentWords names what a shape comparison with these steps leaves out.
func dependentWords(steps []dependentStep) []string {
	var out []string
	for _, d := range steps {
		out = append(out, d.Word)
	}
	return out
}

// shapeDrift is how many (path, type) pairs and statuses differ between a committed
// capture and a fresh run of probe id, matched by observation label. A label on only one
// side counts as one difference. Texts are not compared, and neither are the parts that
// depend on what the tailnet holds (tailnetDependentSteps).
func shapeDrift(id string, committed, now Result) (int, []string) {
	steps := dependentSteps(id, committed, now)
	skip := dependentLabels(steps)
	byLabel := map[string]Observation{}
	for _, o := range committed.Observations {
		if !skip[o.Label] {
			byLabel[o.Label] = o
		}
	}
	n := 0
	seen := map[string]bool{}
	for _, o := range now.Observations {
		if skip[o.Label] {
			continue
		}
		c, ok := byLabel[o.Label]
		if !ok {
			n++
			continue
		}
		seen[o.Label] = true
		for _, d := range Compare(c, o) {
			if !dependentPath(steps, o.Label, d) {
				n++
			}
		}
	}
	for _, o := range committed.Observations {
		if !skip[o.Label] && !seen[o.Label] {
			n++
		}
	}
	return n, dependentWords(steps)
}

func selfCheckCommand(ctx context.Context, a API, opts commandArgs, stdout, stderr io.Writer, now func() time.Time) int {
	onStart := func(id string) {
		_, _ = fmt.Fprintf(stderr, "tailkeeper: probe-acl: %s\n", sanitize.String(id, sanitize.DefaultMax))
	}
	x := newExec(a, Options{Gap: opts.gap, Only: opts.only, Against: opts.against, OnStart: onStart})
	checks := RunSelfCheck(ctx, x)
	all := renderSelfCheck(stdout, checks)
	if opts.out != "" {
		names, err := WriteFiles(opts.out, x.shapes, now().UTC().Format("2006-01-02"))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "tailkeeper: probe-acl: cannot write the skeletons: %s\n", sanitize.String(err.Error(), sanitize.DefaultMax))
			_, _ = fmt.Fprintf(stderr, "tailkeeper: probe-acl: %s written before the failure\n", files(len(names)))
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "wrote %s to %s: read them, run both scanners over them, then commit them\n", files(len(names)), sanitize.String(opts.out, sanitize.DefaultMax))
	}
	if all {
		return 0
	}
	return 1
}

func renderSelfCheck(w io.Writer, checks []SelfCheck) bool {
	all := true
	missed := 0
	for _, c := range checks {
		if !c.Held {
			all = false
			missed++
		}
		skipped := ""
		if len(c.Skipped) > 0 {
			skipped = " (not compared: " + strings.Join(c.Skipped, ", ") + ")"
		}
		if idRE.MatchString(c.Name) {
			switch {
			case c.Note != "":
				_, _ = fmt.Fprintf(w, "shape: %s %s\n", c.Name, c.Note)
			case c.Held:
				_, _ = fmt.Fprintf(w, "shape: %s same%s\n", c.Name, skipped)
			default:
				_, _ = fmt.Fprintf(w, "shape: %s differs: %d paths%s\n", c.Name, c.Count, skipped)
			}
			continue
		}
		switch {
		case c.Note != "":
			_, _ = fmt.Fprintf(w, "self-check: %s %s\n", c.Name, c.Note)
		case c.Held:
			_, _ = fmt.Fprintf(w, "self-check: %s held %d%s\n", c.Name, c.Count, skipped)
		default:
			_, _ = fmt.Fprintf(w, "self-check: %s not held %d%s\n", c.Name, c.Count, skipped)
		}
	}
	if all {
		_, _ = fmt.Fprintf(w, "self-check: %d checks, all held\n", len(checks))
	} else {
		_, _ = fmt.Fprintf(w, "self-check: %d checks, %d not held\n", len(checks), missed)
	}
	return all
}

// LineKind says what a line of the self-check's output is.
type LineKind int

// The kinds of line the self-check prints. Nothing but these is printed to stdout.
const (
	LineUnknown LineKind = iota // not a line the self-check prints
	LineCheck                   // one check: a policy check or a shape
	LineClosing                 // the closing count
)

var (
	// notComparedRE is what a line says it left out: fixed words and a count of unknown sections.
	notComparedRE = `( \(not compared: [A-Za-z0-9 ,]+\))?`
	policyLineRE  = regexp.MustCompile(`^self-check: (reformat|round-trip|summary|etag) (held [0-9]+|not held [0-9]+|not read)` + notComparedRE + `$`)
	shapeLineRE   = regexp.MustCompile(`^shape: [AH]-[0-9]+ (same|differs: [0-9]+ paths|capture missing|not run|probe failed)` + notComparedRE + `$`)
	closingLineRE = regexp.MustCompile(`^self-check: ([0-9]+) checks, (all held|([0-9]+) not held)$`)
)

// ClassifyLine reports what a line printed by the self-check is. For the closing line it also
// returns how many checks the line counts and how many of them did not hold. Every line of
// a kind other than LineUnknown holds a fixed word, a probe ID or a count, so it is fit to
// log whatever the checks found.
func ClassifyLine(line string) (kind LineKind, checks, notHeld int) {
	if policyLineRE.MatchString(line) || shapeLineRE.MatchString(line) {
		return LineCheck, 0, 0
	}
	if m := closingLineRE.FindStringSubmatch(line); m != nil {
		checks, _ = strconv.Atoi(m[1])
		if m[3] != "" {
			notHeld, _ = strconv.Atoi(m[3])
		}
		return LineClosing, checks, notHeld
	}
	return LineUnknown, 0, 0
}
