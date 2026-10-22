package tools

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/registry"
)

// acl_diff compares two policies by what they mean. The old side is the policy in against, or
// the live one; the new side is the policy in policy, or the live one with the patch applied,
// or the live one; they are never both the live one. Nothing is sent to Tailscale for
// validation: a diff reads the live policy (and who manages it) and changes nothing, so the
// tool is not open-world. The texts are prepared as acl_validate prepares them, by the same
// code: the subject rule, the credential tripwire and the pseudonyms of an MCP caller, the
// operator's own files as they are.

// The statuses of an ACLDiffOutput, besides invalid (shared with acl_validate).
const (
	statusEqual   = "equal"   // 0: no change of the five classes (Tailscale-written ones left out when asked)
	statusChanged = "changed" // 0: a difference is not a failure; --fail-on decides
)

// The sources of a side, as ACLDiffSide.Source says them. A text is MCP text; a file is what
// the operator named on the command line.
const (
	sideLive  = "live"
	sideText  = "text"
	sideFile  = "file"
	sidePatch = "patch"
)

// maxSideFindings is how many findings a side lists, and sideFindingsCost the most characters
// they take together (see acl.DisplayCost); the rest are counted in its Omitted. The two keep
// a result under the characters the tool declares whatever the policy holds.
const (
	maxSideFindings  = 64
	sideFindingsCost = 26000
)

// ACLDiffInput says which two policies to compare, and which changes to list.
type ACLDiffInput struct {
	Policy                 string `json:"policy,omitempty" cli:"file:from,stdin,group=new,arg=2,as=NEW" jsonschema:"the new policy as HuJSON text, a top-level object; leave it and patch out to make the live policy the new side"`
	Patch                  string `json:"patch,omitempty" cli:"file:patch,stdin,group=new" jsonschema:"RFC 6902 operations, as JSON text, applied to the live policy to make the new side; over MCP a user is named by pseudonym, in a file by login"`
	Against                string `json:"against,omitempty" cli:"file:against,stdin,live,arg=1,as=OLD" jsonschema:"the old policy as HuJSON text; leave it out to make the live policy the old side"`
	Section                string `json:"section,omitempty" tk:"short" jsonschema:"list only the changes in one section: a section name in any case, or unknown for the sections this version does not know"`
	FromChange             string `json:"fromChange,omitempty" tk:"short" jsonschema:"continue a listing: the nextChange of the previous result for the same two policies"`
	IgnoreTailscaleWritten bool   `json:"ignoreTailscaleWritten,omitempty" jsonschema:"leave the constructs Tailscale writes itself out of the list and out of equal; they are still counted"`
	Offline                bool   `json:"-" cli:"bool:offline" jsonschema:"compare two files here only and need no credential; refused when a side is the live policy"`
	Operator               bool   `json:"-" cli:"operator"`
}

// RunsOffline says that two files, or --offline, need no credential. --offline with a live
// side is refused by the tool, which says so.
func (in ACLDiffInput) RunsOffline(g registry.Given) bool {
	return g["offline"] || g["from"] && g["against"]
}

// Check refuses a policy and a patch together, and a section that is no section, before
// anything is read. That both sides are the live policy is told by the tool, since on the
// command line the files are not read yet.
func (in ACLDiffInput) Check() error {
	if in.Policy != "" && in.Patch != "" {
		return validationf("give a policy or a patch for the new side, not both: the policy is the whole new side, the patch is applied to the live policy")
	}
	if s := in.Section; s != "" && !strings.EqualFold(s, "unknown") {
		if _, ok := acl.SectionByName(s); !ok {
			return validationf(fmt.Sprintf("%s is not a section of the policy file; use a section name, or unknown for the sections tailkeeper does not know", quoteName(s)))
		}
	}
	return nil
}

// ACLDiffOutput is the comparison. An invalid side is a typed result too (status invalid,
// exit 2) with its findings under the side, so that a hostile name is redacted by the
// registry and not withheld with the rest.
type ACLDiffOutput struct {
	Status            string          `json:"status" jsonschema:"equal, changed or invalid (a side is not a policy, and nothing was compared)"`
	SemanticallyEqual bool            `json:"semanticallyEqual" jsonschema:"the two mean the same: exact when true; false can be a false changed for a rewrite the normal form does not reduce (see normalFormLimits)"`
	Old               ACLDiffSide     `json:"old"`
	New               ACLDiffSide     `json:"new"`
	Counts            ACLChangeCounts `json:"counts" jsonschema:"the changes of every page, by class; commentOnly and formatOnly are counts only"`
	Changes           []ACLChange     `json:"changes,omitempty" jsonschema:"one page of the changes, defaults, testsReduced and widening first"`
	Section           string          `json:"section,omitempty" jsonschema:"the section filter this result applied, in the engine's spelling; the counts are of every section, matched and changes are of this one"`
	Matched           int             `json:"matched" jsonschema:"the changes the section filter and the options select, over every page"`
	Truncated         bool            `json:"truncated" jsonschema:"more changes follow this page: call again with fromChange set to nextChange"`
	NextChange        string          `json:"nextChange,omitempty"`
	NormalFormLimits  []string        `json:"normalFormLimits,omitempty" jsonschema:"why a changed may be false"`
	NotChecked        []string        `json:"notChecked" jsonschema:"what a comparison does not establish: a small change to an alias or a group can widen access"`

	TailscaleWrittenAsOf    string `json:"tailscaleWrittenAsOf" jsonschema:"the date of the list of constructs Tailscale writes itself"`
	TailscaleWrittenIgnored bool   `json:"tailscaleWrittenIgnored" jsonschema:"ignoreTailscaleWritten was set: they are counted and not listed, and they do not make the result changed"`

	ExternallyManaged     string `json:"externallyManaged,omitempty" jsonschema:"true, false or unknown: the live policy is managed outside the admin console; absent when no side is live"`
	ExternalLink          string `json:"externalLink,omitempty" tk:"untrusted,plain"`
	ExternallyManagedNote string `json:"externallyManagedNote,omitempty" jsonschema:"why it is unknown"`
	CheckedAt             string `json:"checkedAt"`
}

// ACLDiffSide describes one side of the comparison.
type ACLDiffSide struct {
	Source        string       `json:"source" jsonschema:"live, text (the text of an MCP call), file (named on the command line) or patch (the live policy with the patch applied)"`
	PolicyVersion string       `json:"policyVersion,omitempty" jsonschema:"for the live policy: a keyed digest of its ETag, or the ETag with personalData show; absent otherwise"`
	PolicySHA256  string       `json:"policySha256,omitempty" jsonschema:"SHA-256 of the policy as acl_get shows it"`
	Findings      []ACLProblem `json:"findings,omitempty" jsonschema:"what was found in this side by itself: a text that is not a policy, a key written twice, a section this version does not know"`
	Omitted       int          `json:"omitted,omitempty" jsonschema:"findings left out past the cap"`
}

// ACLChange is one difference. Entry, Old and New are cut at 1 KiB each by the engine, so
// that one element is never a blob and a page is bounded.
type ACLChange struct {
	Class      string          `json:"class" jsonschema:"defaults, testsReduced, widening, tailscaleWritten or semantic"`
	Op         string          `json:"op" jsonschema:"added, removed or changed"`
	Section    string          `json:"section" tk:"untrusted,emails" jsonschema:"acls, grants, acls+grants (a rule in both), another section, or the name of a section this version does not know"`
	Entry      string          `json:"entry,omitempty" tk:"untrusted,emails" jsonschema:"the entry's key, or a summary of the rule or assertion"`
	Old        string          `json:"old,omitempty" tk:"untrusted,emails" jsonschema:"the entry on the old side, in canonical form"`
	New        string          `json:"new,omitempty" tk:"untrusted,emails" jsonschema:"the entry on the new side, in canonical form"`
	Truncated  bool            `json:"truncated,omitempty" jsonschema:"old or new was cut at 1 KiB"`
	OldCount   int             `json:"oldCount,omitempty" jsonschema:"how many times a repeated entry (a test) is on the old side"`
	NewCount   int             `json:"newCount,omitempty"`
	Fields     []ACLFieldDelta `json:"fields,omitempty" jsonschema:"what a changed entry gained and lost, field by field"`
	Note       string          `json:"note,omitempty" jsonschema:"a fixed sentence that qualifies the change; it never quotes the policy: what a note is about is in fields"`
	OldPointer string          `json:"oldPointer,omitempty" tk:"untrusted,emails" jsonschema:"JSON pointer into the old side"`
	NewPointer string          `json:"newPointer,omitempty" tk:"untrusted,emails" jsonschema:"JSON pointer into the new side"`
	OldLine    int             `json:"oldLine,omitempty" jsonschema:"in the old side's text, from 1"`
	NewLine    int             `json:"newLine,omitempty" jsonschema:"in the new side's text, from 1; never for a patch: the caller wrote operations, not that text"`
}

// ACLFieldDelta is what a changed entry gained and lost in one field.
type ACLFieldDelta struct {
	Field       string   `json:"field" tk:"untrusted,emails"`
	Added       []string `json:"added,omitempty" tk:"untrusted,emails"`
	Removed     []string `json:"removed,omitempty" tk:"untrusted,emails"`
	AddedMore   int      `json:"addedMore,omitempty" jsonschema:"gained, not listed"`
	RemovedMore int      `json:"removedMore,omitempty" jsonschema:"lost, not listed"`
}

// ExitCode comes from the status alone: equal and changed 0, invalid 2, and a status this
// version does not know 1. The status is the engine's verdict on the whole normal forms, never
// a reading of the page or of the filter: a section that selects nothing, or a cursor past the
// last change, leaves the status changed.
func (o ACLDiffOutput) ExitCode() int {
	switch o.Status {
	case statusEqual, statusChanged:
		return 0
	case statusInvalid:
		return 2
	}
	return 1
}

// Findings counts what --fail-on can gate, over every change and not the page. The kind
// change fires for any of the five classes: a gate named change that stays silent for a
// widening or a removed test is the unsafe direction. The Tailscale-written class counts
// unless the caller asked to ignore it.
func (o ACLDiffOutput) Findings() registry.Findings {
	c := o.Counts
	f := registry.Findings{TestsReduced: c.TestsReduced, Defaults: c.Defaults, Widenings: c.Widening}
	f.Changes = changedEntries(c, !o.TailscaleWrittenIgnored)
	return f
}

// changedEntries is the number of changes that --fail-on change counts. The classes the engine
// counts do not overlap, but a widening is a finding about a rule that changed, listed beside
// it: adding the two would call one widened rule two changes. The rule it belongs to is in the
// semantic count, so the larger of the two stands for both, and the count is 0 only when
// nothing changed. Tailscale-written changes count unless they are ignored.
func changedEntries(c ACLChangeCounts, written bool) int {
	n := c.Defaults + c.TestsReduced + max(c.Semantic, c.Widening)
	if written {
		n += c.TailscaleWritten
	}
	return n
}

// FailOnKinds: acl_diff computes four kinds; it has no warnings to count.
func (ACLDiffOutput) FailOnKinds() []string {
	return []string{"tests-reduced", "defaults", "widening", "change"}
}

// aclDiff compares the two sides the input names.
func aclDiff(ctx context.Context, env *registry.Env, in ACLDiffInput) (out ACLDiffOutput, err error) {
	liveOld, liveNew := in.Against == "", in.Policy == "" && in.Patch == ""
	switch {
	case in.Offline && in.Patch != "":
		return ACLDiffOutput{}, validationf("a patch is applied to the live policy, so it cannot be compared offline: give the whole new policy (--from FILE)")
	case liveOld && liveNew:
		return ACLDiffOutput{}, validationf("both sides would be the live policy: give a new policy (--from FILE) or a patch (--patch FILE), or an old policy (--against FILE)")
	case in.Offline && (liveOld || liveNew):
		return ACLDiffOutput{}, validationf("--offline compares two files here and reads nothing from Tailscale: give both, --against FILE and --from FILE")
	}
	needsLive := liveOld || liveNew || in.Patch != ""

	// Each text side is a validation of its own text, so that it is read, screened and
	// prepared by the code acl_validate uses; the resolver is shared, so that a pseudonym
	// costs one read of the users.
	nv := newValidation(env, ACLValidateInput{Policy: in.Policy, Patch: in.Patch, Operator: in.Operator})
	ov := newValidation(env, ACLValidateInput{Policy: in.Against, Operator: in.Operator})
	ov.res = nv.res
	nv.uncapped, ov.uncapped = true, true
	defer func() {
		if err != nil {
			err = nv.res.HideError(err)
		}
	}()

	out = ACLDiffOutput{
		Status: statusChanged, NotChecked: slices.Clone(acl.NotChecked), TailscaleWrittenAsOf: acl.TailscaleWrittenAsOf,
		TailscaleWrittenIgnored: in.IgnoreTailscaleWritten,
		CheckedAt:               env.Clock().UTC().Format("2006-01-02T15:04:05Z"),
	}
	out.Old.Source, out.New.Source = sideSource(in, false), sideSource(in, true)

	// The local phase reads and screens the texts before any request: a literal login or a
	// credential shape is refused here, and a text that is no policy is a result.
	if err := ov.checkLocally(ctx); err != nil {
		return ACLDiffOutput{}, err
	}
	if err := nv.checkLocally(ctx); err != nil {
		return ACLDiffOutput{}, err
	}
	oldFound, newFound := relabel(ov.found(), sourceFrom, sourceAgainst), nv.found()
	if hasError(oldFound) || hasError(newFound) {
		return out.invalid(oldFound, newFound, ov.out.Omitted, nv.out.Omitted), nil
	}

	var live api.PolicyDetails
	var liveDoc *acl.Doc
	if needsLive {
		c, err := env.RequireAPI()
		if err != nil {
			return ACLDiffOutput{}, err
		}
		if live, err = c.GetPolicyDetails(ctx); err != nil {
			return ACLDiffOutput{}, err
		}
		found, omitted := []ACLProblem(nil), 0
		if liveDoc, found, omitted, err = nv.readLiveSide(ctx, live); err != nil {
			return ACLDiffOutput{}, err
		}
		// The old side is the live policy when no old text is given, the new side when no new
		// text and no patch is. A patch is made from the live policy: its side records the live
		// version the patch was applied to, and has no findings of the live policy's own.
		if liveOld {
			out.Old.PolicyVersion = policyVersion(env, live.ETag)
			oldFound, ov.out.Omitted = append(oldFound, found...), ov.out.Omitted+omitted
		}
		if liveNew {
			out.New.PolicyVersion = policyVersion(env, live.ETag)
			newFound, nv.out.Omitted = append(newFound, found...), nv.out.Omitted+omitted
		}
		if in.Patch != "" {
			out.New.PolicyVersion = policyVersion(env, live.ETag)
			if hasError(found) {
				newFound = append(newFound, found...)
			}
		}
		if hasError(found) {
			return out.invalid(oldFound, newFound, ov.out.Omitted, nv.out.Omitted), nil
		}
	}

	oldProp, oldMore, err := ov.prepare(ctx, live, liveDoc)
	if err != nil {
		return ACLDiffOutput{}, err
	}
	newProp, newMore, err := nv.prepare(ctx, live, liveDoc)
	if err != nil {
		return ACLDiffOutput{}, err
	}
	oldFound, newFound = append(oldFound, relabel(oldMore, sourceFrom, sourceAgainst)...), append(newFound, newMore...)
	if oldProp == nil || newProp == nil {
		return out.invalid(oldFound, newFound, ov.out.Omitted, nv.out.Omitted), nil
	}
	// The digest of a side is that of the text compared: for the live side, the live policy.
	_, _, _, out.Old.PolicySHA256 = maskedPolicy(env, string(oldProp.Sent))
	_, _, _, out.New.PolicySHA256 = maskedPolicy(env, string(newProp.Sent))

	// The sides are shown as acl_get shows a policy, with the pseudonym beside each masked
	// address, except an operator's own file: a pseudonym beside the operator's own text would
	// confirm a guess about it.
	opts := acl.DiffOptions{
		Section: in.Section, Cursor: in.FromChange, PageSize: acl.DefaultPage, IgnoreTailscaleWritten: in.IgnoreTailscaleWritten,
		OldShow: nv.res.Shown(!(in.Operator && in.Against != "")), NewShow: nv.res.Shown(!(in.Operator && in.Policy != "")),
	}
	if env.Privacy != nil {
		opts.Seal = env.Privacy.Digest
	}
	res, err := compareTexts(ctx, oldProp.Doc, newProp.Doc, opts)
	if err != nil {
		return ACLDiffOutput{}, nv.engineError(err)
	}
	out.Old.Findings, out.Old.Omitted = capFindings(oldFound, ov.out.Omitted)
	out.New.Findings, out.New.Omitted = capFindings(newFound, nv.out.Omitted)
	out.fill(res, in)
	if needsLive {
		out.ExternallyManaged, out.ExternalLink, out.ExternallyManagedNote = externalFacts(ctx, env)
	}
	return out, nil
}

// compareTexts is the engine's comparison; a test replaces it to make a call fail after a user
// was named.
var compareTexts = acl.Diff

// sideSource names where a side comes from.
func sideSource(in ACLDiffInput, newSide bool) string {
	text := func(s string) string {
		if s == "" {
			return sideLive
		}
		if in.Operator {
			return sideFile
		}
		return sideText
	}
	if !newSide {
		return text(in.Against)
	}
	if in.Patch != "" {
		return sidePatch
	}
	return text(in.Policy)
}

// found is every finding the local phase put on the validation, the errors first.
func (v *validation) found() []ACLProblem {
	return append(slices.Clone(v.out.Errors), v.out.Notices...)
}

// relabel returns ps with the source from changed to to.
func relabel(ps []ACLProblem, from, to string) []ACLProblem {
	out := slices.Clone(ps)
	for i := range out {
		if out[i].Source == from {
			out[i].Source = to
		}
	}
	return out
}

// capFindings keeps the first of a side's findings, as many as maxSideFindings and
// sideFindingsCost allow, and counts the rest.
func capFindings(ps []ACLProblem, omitted int) ([]ACLProblem, int) {
	cost, keep := 0, 0
	for _, p := range ps {
		if cost += 200 + acl.DisplayCost(p.Message) + acl.DisplayCost(p.Pointer); keep == maxSideFindings || cost > sideFindingsCost {
			break
		}
		keep++
	}
	return ps[:keep], omitted + len(ps) - keep
}

// readLiveSide parses the live policy and returns the structural findings it shows by
// itself, as notices: Tailscale stored it, so a key written twice is a remark and not a
// refusal. A live policy this version cannot read is one error finding, and the comparison
// does not run.
func (v *validation) readLiveSide(ctx context.Context, live api.PolicyDetails) (*acl.Doc, []ACLProblem, int, error) {
	d, err := v.parse(ctx, live.Text)
	if err != nil {
		p, perr := v.parseProblem(live.Text, err, sourceLive)
		if perr != nil {
			return nil, nil, 0, perr
		}
		p.Message = "this version of tailkeeper cannot read the live policy: " + p.Message
		return nil, []ACLProblem{p}, 0, nil
	}
	ps, omitted := v.structureProblems(d, sourceLive, true)
	return d, ps, omitted, nil
}

// invalid is the result of a comparison that did not run: a side is not a policy.
func (o ACLDiffOutput) invalid(oldFound, newFound []ACLProblem, oldOmitted, newOmitted int) ACLDiffOutput {
	o.Status = statusInvalid
	o.Old.Findings, o.Old.Omitted = capFindings(oldFound, oldOmitted)
	o.New.Findings, o.New.Omitted = capFindings(newFound, newOmitted)
	return o
}

// fill copies the engine's comparison into the result. The engine has already shown every
// string it quotes (see SubjectResolver.Shown): an operator's own file with its logins masked
// and no pseudonym beside them, the live policy and a caller's text as acl_get shows them, and
// the markers a policy forges rewritten in all of them.
func (o *ACLDiffOutput) fill(res *acl.DiffResult, in ACLDiffInput) {
	o.Status = statusChanged
	if res.Equal {
		o.Status = statusEqual
	}
	o.SemanticallyEqual = res.SemanticallyEqual
	o.Section = sectionSpelling(in.Section)
	o.Counts = ACLChangeCounts{Defaults: res.Counts.Defaults, TestsReduced: res.Counts.TestsReduced, Widening: res.Counts.Widening,
		TailscaleWritten: res.Counts.TailscaleWritten, Semantic: res.Counts.Semantic, CommentOnly: res.Counts.CommentOnly, FormatOnly: res.Counts.FormatOnly}
	o.Matched, o.Truncated, o.NextChange = res.Matched, res.Truncated, res.NextChange
	o.NormalFormLimits = slices.Clone(res.NormalFormLimits)
	o.NotChecked, o.TailscaleWrittenAsOf = slices.Clone(res.NotChecked), res.TailscaleWrittenAsOf
	for _, c := range res.Changes {
		ch := ACLChange{
			Class: string(c.Class), Op: string(c.Op), Section: c.Section, Entry: c.Key,
			Old: c.Old.Text, New: c.New.Text, Truncated: c.Old.Truncated || c.New.Truncated,
			OldCount: c.OldN, NewCount: c.NewN, Note: c.Note,
			OldPointer: c.OldPointer, NewPointer: c.NewPointer, OldLine: c.OldLine, NewLine: c.NewLine,
		}
		if in.Patch != "" {
			ch.NewLine = 0
		}
		for _, f := range c.Fields {
			ch.Fields = append(ch.Fields, ACLFieldDelta{Field: f.Field, Added: slices.Clone(f.Added), Removed: slices.Clone(f.Removed),
				AddedMore: f.AddedMore, RemovedMore: f.RemovedMore})
		}
		o.Changes = append(o.Changes, ch)
	}
}

// sectionSpelling is the section filter of a call as the engine names it: the section's own
// name whatever the case it was given in, unknown for the sections this version does not
// know, and nothing for a name Check refused.
func sectionSpelling(s string) string {
	if strings.EqualFold(s, "unknown") {
		return "unknown"
	}
	if sec, ok := acl.SectionByName(s); ok {
		return sec.Name
	}
	return ""
}

// Report is the human layout: the verdict line, what was not checked, the counts by class,
// then the findings of each side and the changes of the page, each behind a location. The
// strings are the registry's, already escaped and masked; a line that quotes a policy is the
// owner's own text and is not marked as Tailscale's.
func (o ACLDiffOutput) Report() registry.Report {
	rep := registry.Report{NotChecked: slices.Clone(o.NotChecked)}
	rep.Verdict, rep.Level = o.verdict()
	if o.Status != statusInvalid {
		c := o.Counts
		rep.Classes = []registry.ClassCount{
			{Class: "defaults", Count: c.Defaults},
			{Class: "tests reduced", Count: c.TestsReduced},
			{Class: "widening", Count: c.Widening},
			{Class: "tailscale-written", Count: c.TailscaleWritten, Expected: true},
			{Class: "semantic", Count: c.Semantic},
		}
	}
	located := false
	for i, side := range []ACLDiffSide{o.Old, o.New} {
		name := []string{"old", "new"}[i]
		for _, p := range side.Findings {
			rep.Findings = append(rep.Findings, registry.Finding{Severity: p.Severity, Source: p.Source, Line: p.Line, Column: p.Column,
				Pointer: p.Pointer, Message: p.Message, Untrusted: p.FromTailscale})
			located = located || p.Line > 0
		}
		if side.Omitted > 0 {
			rep.Findings = append(rep.Findings, registry.Finding{Severity: severityNotice,
				Message: fmt.Sprintf("%s (the %s side)", notListed(side.Omitted, "finding"), name)})
		}
	}
	for _, c := range o.Changes {
		rep.Findings = append(rep.Findings, o.changeFinding(c))
		located = located || c.OldLine > 0 || c.NewLine > 0
	}
	if n := o.Findings().Changes; o.Section != "" && o.Matched == 0 && n > 0 {
		// The filter narrows what is listed and never what the status says: a reader of an empty
		// list must not take it for "no change".
		rep.Findings = append(rep.Findings, registry.Finding{Severity: severityNotice,
			Message: fmt.Sprintf("the section filter %s selects none of the changes of this comparison: they are in other sections", quoteName(o.Section))})
	}
	for _, l := range o.NormalFormLimits {
		rep.Findings = append(rep.Findings, registry.Finding{Severity: severityNotice, Message: l})
	}
	if o.Truncated {
		rep.Findings = append(rep.Findings, registry.Finding{Severity: severityNotice,
			Message: fmt.Sprintf("%d changes are selected and %d are listed: continue with --from-change %s", o.Matched, len(o.Changes), o.NextChange)})
	}
	if located {
		rep.Findings = append(rep.Findings, registry.Finding{Severity: severityNotice,
			Message: "Lines are counted by line feed and columns in bytes, as Tailscale counts them: an editor that counts a lone carriage return may disagree."})
	}
	return rep
}

// diffLabels are the report's names for the classes, in the order they are listed.
var diffLabels = map[string]string{
	string(acl.ClassDefaults): "defaults", string(acl.ClassTestsReduced): "tests reduced", string(acl.ClassWidening): "widening",
	string(acl.ClassTailscaleWritten): "tailscale-written", string(acl.ClassSemantic): "semantic",
}

// changeFinding is one change as a located finding. A change that can only matter more than
// a rewrite (defaults, a removed test, a widening) is a warning, the rest a notice. It sits
// in the side that holds what it names: the old side for a removal, the new side for the rest.
func (o ACLDiffOutput) changeFinding(c ACLChange) registry.Finding {
	sev := severityNotice
	switch c.Class {
	case string(acl.ClassDefaults), string(acl.ClassTestsReduced), string(acl.ClassWidening):
		sev = severityWarning
	}
	f := registry.Finding{Severity: sev}
	if c.Op == string(acl.OpRemoved) {
		f.Source, f.Line, f.Pointer = reportSource(o.Old.Source, false), c.OldLine, c.OldPointer
	} else {
		f.Source, f.Line, f.Pointer = reportSource(o.New.Source, true), c.NewLine, c.NewPointer
	}
	if f.Line > 0 {
		f.Pointer = ""
	}
	msg := diffLabels[c.Class] + ": " + c.Op + " " + c.Section
	if c.Entry != "" {
		msg += ": " + c.Entry
	}
	for _, d := range c.Fields {
		if len(d.Added) > 0 || d.AddedMore > 0 {
			msg += fmt.Sprintf(" (%s gains %s)", d.Field, strings.Join(d.Added, ", ")+more(d.AddedMore))
		}
		if len(d.Removed) > 0 || d.RemovedMore > 0 {
			msg += fmt.Sprintf(" (%s loses %s)", d.Field, strings.Join(d.Removed, ", ")+more(d.RemovedMore))
		}
	}
	if c.Note != "" {
		msg += " — " + c.Note
	}
	f.Message = cutRunes(msg, 4096)
	return f
}

// more is the tail of a list of which some items are not shown.
func more(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" and %d more", n)
}

// reportSource is the flag-like name the layout replaces with the path the user typed.
func reportSource(side string, newSide bool) string {
	switch {
	case side == sideLive:
		return sourceLive
	case side == sidePatch:
		return sourcePatch
	case newSide:
		return sourceFrom
	}
	return sourceAgainst
}

// verdict is the first line of the report and the level it is shown at.
func (o ACLDiffOutput) verdict() (string, registry.Level) {
	switch o.Status {
	case statusEqual:
		line := "EQUAL · the two policies mean the same"
		if c := o.Counts; c.CommentOnly+c.FormatOnly > 0 {
			line += fmt.Sprintf(" (%d comment-only, %d format-only)", c.CommentOnly, c.FormatOnly)
		}
		if n := o.Counts.TailscaleWritten; o.TailscaleWrittenIgnored && n > 0 {
			line += fmt.Sprintf(" · %s ignored", plural(n, "Tailscale-written change"))
		}
		return line, registry.LevelOK
	case statusChanged:
		c := o.Counts
		parts := []string{}
		for _, p := range []struct {
			n    int
			word string
		}{{c.Defaults, "defaults"}, {c.TestsReduced, "tests reduced"}, {c.Widening, "widening"}, {c.TailscaleWritten, "tailscale-written"}, {c.Semantic, "semantic"}} {
			if p.n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", p.n, p.word))
			}
		}
		level := registry.LevelOK
		if c.Defaults+c.TestsReduced+c.Widening > 0 {
			level = registry.LevelWarn
		}
		// The classes overlap (a widened rule is a widening and a changed rule), so the line
		// lists them and does not add them up.
		return "CHANGED · " + strings.Join(parts, ", "), level
	case statusInvalid:
		return fmt.Sprintf("INVALID · %s found before anything was compared", plural(countErrors(o.Old.Findings, o.New.Findings), "problem")), registry.LevelFail
	}
	return "UNKNOWN · the comparison could not be established", registry.LevelFail
}

// countErrors counts the findings of severity error.
func countErrors(lists ...[]ACLProblem) int {
	n := 0
	for _, l := range lists {
		for _, p := range l {
			if p.Severity == severityError {
				n++
			}
		}
	}
	return n
}
