package registry

// ExitCoder is implemented by a typed result whose verdict decides the CLI's exit
// code. ExitCode reads the verdict alone, never message text: 0 for a pass, 1 for
// an answer that is unknown, 9 for a failed test or invariant, 2 for input that
// is invalid, rejected or unresolved. The CLI applies the exit policy to it (see
// Gated), and MCP ignores it: an MCP caller reads the result's status field.
type ExitCoder interface{ ExitCode() int }

// Findings counts what a result found, in the kinds the CLI's --fail-on names.
// A tool computes every count over all of its changes, not over the page of them
// that the result shows, so a gate cannot be passed by paging.
type Findings struct {
	NewWarnings  int // warnings the proposal adds to the baseline (--fail-on warnings)
	TestsReduced int // tests or SSH tests removed or weakened (tests-reduced)
	Defaults     int // acls, grants or ssh moving between absent, empty and non-empty (defaults)
	Widenings    int // structural widenings (widening)
	Changes      int // any defaults or semantic change, Tailscale-written constructs included unless ignored (change)
}

// Gated is implemented by a typed result that --fail-on can gate. A command whose
// output type implements it takes --fail-on; one that does not has no such flag.
//
// Precedence when several apply: exit 1, then 9, then 2, then 8, then 0. The
// result's own code (ExitCoder) is 0, 1, 2 or 9; a gate that matches turns an
// otherwise successful run into exit 8, findings_present, and never hides a code
// that outranks it.
type Gated interface{ Findings() Findings }
