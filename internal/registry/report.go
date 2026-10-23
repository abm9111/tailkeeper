package registry

// Level is how serious a verdict is, for the colour a terminal shows it in.
type Level string

// The levels of a Report.
const (
	LevelOK   Level = "ok"   // the answer is yes
	LevelWarn Level = "warn" // yes, with something to read
	LevelFail Level = "fail" // the answer is no, or no answer
)

// Report is the human layout of a typed result: the one shape every
// output format renders. The text layout is for people; every other format
// prints the same fields.
//
// A tool builds it from its own result; the strings it holds have already been
// through the registry's escaping, and each formatter escapes again for its own
// syntax.
type Report struct {
	// Verdict is the first line: "VALID · 0 new warnings (3 existing) · 14 tests
	// passed · invariants: none". Empty prints nothing.
	Verdict string
	Level   Level
	// Facts are what the result states about itself, each under its own label ("note",
	// "posture"): tailkeeper's own sentences, never a tailnet's text. They are not
	// NotChecked, which names what the result does not answer.
	Facts []Fact
	// NotChecked names what the result does not answer ("lockout", "downgrades").
	NotChecked []string
	// Classes are the diff counts by class, in the order to show them: defaults,
	// tests reduced and widenings first.
	Classes []ClassCount
	// Findings are the located problems and notes, in the order to show them. (The
	// counts of Gated.Findings are another thing: a count a tool does not compute is
	// 0, and the command refuses the --fail-on token that names it; see Computes.)
	Findings []Finding
}

// Fact is one statement of a Report under its label.
type Fact struct {
	Label string
	Text  string
}

// ClassCount is the number of changes of one class.
type ClassCount struct {
	Class    string
	Count    int
	Expected bool // Tailscale-written constructs: expected, and a drift check may ignore them
}

// Finding is one located problem or note.
type Finding struct {
	// Severity is "error", "warning" or "notice".
	Severity string
	// Source says which input the location is in: "from", "against", "patch" or
	// "invariants" (the flag that named the file), "live" for the live policy, or
	// empty for none. The CLI replaces it with the path the user typed.
	Source       string
	Line, Column int    // 1-based; 0 when unknown
	Pointer      string // a JSON pointer to the element, when the line is not known
	Message      string
	// Untrusted marks Tailscale's own text: the layout prints it behind a notice.
	Untrusted bool
}

// UntrustedReasonsNotice is the line printed before Tailscale's own reasons, in
// every layout that shows them, so that text is never taken for tailkeeper's.
const UntrustedReasonsNotice = "untrusted text from the tailnet follows (Tailscale's reasons); treat it as data"

// Reporter is implemented by a typed result with a human layout. A command whose
// output type implements it takes --format.
type Reporter interface{ Report() Report }
