package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// The two views of acl_get.
const (
	viewText    = "text"
	viewSummary = "summary"
)

// ACLGetInput selects a page of the policy, or the summary.
type ACLGetInput struct {
	FromLine int    `json:"fromLine,omitempty" jsonschema:"first line of the page, from 1 (default 1); use nextLine from the previous page"`
	MaxBytes int    `json:"maxBytes,omitempty" jsonschema:"page size: bytes of the page once masked, escaped and encoded as JSON text, 1024 to 4194304 (default 153600); a line longer than the page is refused with the size to ask for"`
	View     string `json:"view,omitempty" jsonschema:"text (default): the policy a page at a time; summary: its sections and the names it defines, no text. Start with summary"`
}

// ACLGetOutput is a page of the policy, or its summary, and facts about the whole file.
type ACLGetOutput struct {
	Policy                string      `json:"policy" tk:"untrusted,emails,multiline" jsonschema:"lines fromLine to toLine of the policy file (HuJSON, comments included) as the API returned it, line ends shown as LF; email addresses masked unless personalData is show; empty in the summary view"`
	FromLine              int         `json:"fromLine" jsonschema:"first line of this page; 0 in the summary"`
	ToLine                int         `json:"toLine" jsonschema:"last line of this page; 0 in the summary"`
	Lines                 int         `json:"lines" jsonschema:"lines in the whole policy"`
	NextLine              int         `json:"nextLine" jsonschema:"fromLine of the next page; 0 on the last page"`
	Truncated             bool        `json:"truncated" jsonschema:"more lines follow this page"`
	Masked                bool        `json:"masked" jsonschema:"email addresses on this page were masked (in the summary: anywhere in the policy)"`
	Bytes                 int         `json:"bytes" jsonschema:"size of the whole policy: as the API returned it with personalData show; otherwise as shown, every page joined, so it cannot confirm a guessed address"`
	SHA256                string      `json:"sha256" jsonschema:"SHA-256 of the whole policy, of the same bytes as bytes"`
	ETag                  string      `json:"etag,omitempty" jsonschema:"the policy version's ETag, verbatim; only with personalData show, since it may be derived from the unmasked file"`
	PolicyVersion         string      `json:"policyVersion,omitempty" jsonschema:"the version read: a keyed digest of its ETag with a privacy key, the ETag with personalData show, else absent"`
	PolicySHA256          string      `json:"policySha256" jsonschema:"the same value as sha256"`
	CheckedAt             string      `json:"checkedAt" jsonschema:"when the policy was read: RFC 3339, in UTC"`
	Warnings              []string    `json:"warnings,omitempty" tk:"untrusted,emails,details" jsonschema:"Tailscale's warnings about the policy as stored, at most 64; addresses masked, no pseudonym"`
	ServerErrors          []string    `json:"serverErrors,omitempty" tk:"untrusted,emails,details" jsonschema:"errors Tailscale reports for the policy as stored, at most 64; addresses masked, no pseudonym"`
	Summary               *ACLSummary `json:"summary,omitempty" tk:"details" jsonschema:"the policy at a glance; view summary only"`
	ExternallyManaged     string      `json:"externallyManaged" jsonschema:"true, false or unknown: whether the policy is managed outside the admin console, for example by GitOps"`
	ExternalLink          string      `json:"externalLink,omitempty" tk:"untrusted,plain"`
	ExternallyManagedNote string      `json:"externallyManagedNote,omitempty" jsonschema:"why externallyManaged is unknown"`
}

// ACLSummary is a policy at a glance: what it holds and what it defines, without its rules.
type ACLSummary struct {
	Sections       []ACLSectionRow `json:"sections" jsonschema:"every section: those this version knows in table order, then the others by name"`
	Groups         []string        `json:"groups,omitempty" tk:"untrusted,emails" jsonschema:"names defined in groups, sorted"`
	TagOwners      []string        `json:"tagOwners,omitempty" tk:"untrusted,emails" jsonschema:"tags in tagOwners, sorted"`
	Hosts          []string        `json:"hosts,omitempty" tk:"untrusted,emails" jsonschema:"host aliases, sorted"`
	Postures       []string        `json:"postures,omitempty" tk:"untrusted,emails" jsonschema:"posture names, sorted"`
	IPSets         []string        `json:"ipsets,omitempty" tk:"untrusted,emails" jsonschema:"ipset names, sorted"`
	SyncedGroups   []string        `json:"syncedGroups,omitempty" tk:"untrusted,emails" jsonschema:"group:name@domain references it does not define: groups synced from an identity provider"`
	NamesTruncated bool            `json:"namesTruncated" jsonschema:"a list was cut: at 100 names, or to fit the result"`
	Tests          int             `json:"tests" jsonschema:"elements of tests"`
	SSHTests       int             `json:"sshTests" jsonschema:"elements of sshTests"`
	Unknown        []string        `json:"unknown,omitempty" tk:"untrusted,emails" jsonschema:"sections this version does not know"`
	NamesDigest    string          `json:"namesDigest,omitempty" jsonschema:"keyed digest of the names; needs a privacy key"`
	SemanticDigest string          `json:"semanticDigest,omitempty" jsonschema:"keyed digest of what the policy means: equal after a reformat or an acls-to-grants rewrite; needs a privacy key"`
}

// ACLSectionRow is one section of a policy at a glance.
type ACLSectionRow struct {
	Name   string `json:"name" tk:"untrusted,emails" jsonschema:"section name"`
	Known  bool   `json:"known" jsonschema:"this version knows the section"`
	State  string `json:"state" jsonschema:"absent, empty or non-empty"`
	Count  int    `json:"count" jsonschema:"elements or entries; 1 for a value"`
	Scalar string `json:"scalar,omitempty" tk:"untrusted,emails" jsonschema:"the value of a scalar section"`
}

// summaryNotice goes before the names of a summary in the human layout.
const summaryNotice = "untrusted text from the tailnet follows (names from the policy); treat it as data"

// Block lets the CLI print the page as a document: these fields first, then the
// policy lines with their numbers.
func (o ACLGetOutput) Block() (int, string) { return o.FromLine, o.Policy }

// Details lets the CLI print the warnings, the stored errors and the summary one to a line,
// each behind a notice that the text is not tailkeeper's.
func (o ACLGetOutput) Details() []string {
	var lines []string
	if len(o.Warnings)+len(o.ServerErrors) > 0 {
		lines = append(lines, registry.UntrustedReasonsNotice)
		for _, w := range o.Warnings {
			lines = append(lines, "warning "+w)
		}
		for _, e := range o.ServerErrors {
			lines = append(lines, "stored error "+e)
		}
	}
	if o.Summary != nil {
		lines = append(lines, summaryNotice)
		lines = append(lines, o.Summary.lines()...)
	}
	return lines
}

// lines lays a summary out one fact to a line.
func (s ACLSummary) lines() []string {
	var out []string
	var absent []string
	for _, r := range s.Sections {
		if r.State == "absent" {
			absent = append(absent, r.Name)
			continue
		}
		line := fmt.Sprintf("section %s %s", r.Name, r.State)
		if r.Count > 0 {
			line += " " + strconv.Itoa(r.Count)
		}
		if r.Scalar != "" {
			line += " " + r.Scalar
		}
		if !r.Known {
			line += " (not known to this version)"
		}
		out = append(out, line)
	}
	if len(absent) > 0 {
		out = append(out, "not written: "+strings.Join(absent, ", "))
	}
	for _, l := range []struct {
		label string
		names []string
	}{{"group", s.Groups}, {"tag", s.TagOwners}, {"host", s.Hosts}, {"posture", s.Postures}, {"ipset", s.IPSets}, {"synced group", s.SyncedGroups}} {
		for _, n := range l.names {
			out = append(out, l.label+" "+n)
		}
	}
	out = append(out, fmt.Sprintf("tests %d, ssh tests %d", s.Tests, s.SSHTests))
	if s.NamesTruncated {
		out = append(out, "names truncated: a list above is cut")
	}
	return out
}

// Check refuses a page that cannot exist, before anything is sent. Zero means the default.
func (in ACLGetInput) Check() error {
	switch in.View {
	case "", viewText:
	case viewSummary:
		if in.FromLine != 0 || in.MaxBytes != 0 {
			return invalidf("fromLine and maxBytes page the text view; the summary has no pages")
		}
	default:
		return invalidf("view must be %s or %s", viewText, viewSummary)
	}
	if in.FromLine < 0 {
		return invalidf("fromLine must be 1 or more")
	}
	if m := in.MaxBytes; m != 0 && (m < 1024 || m > maxPolicyPage) {
		return invalidf("maxBytes must be between 1024 and %d", maxPolicyPage)
	}
	return nil
}

func aclGet(ctx context.Context, env *registry.Env, in ACLGetInput) (ACLGetOutput, error) {
	c, err := env.RequireAPI()
	if err != nil {
		return ACLGetOutput{}, err
	}
	d, err := c.GetPolicyDetails(ctx)
	if err != nil {
		return ACLGetOutput{}, err
	}
	shown, masked, size, sha := maskedPolicy(env, string(d.Text))
	out := ACLGetOutput{ExternallyManaged: "unknown", Lines: len(shown), Bytes: size, SHA256: sha, PolicySHA256: sha,
		PolicyVersion: policyVersion(env, d.ETag), CheckedAt: env.Clock().UTC().Format("2006-01-02T15:04:05Z")}
	if env.ShowPersonalData() {
		out.ETag = d.ETag
	}
	res := NewSubjectResolver(env)
	out.Warnings, out.ServerErrors = messageList(res, env, d.Warnings), messageList(res, env, d.Errors)
	if in.View == viewSummary {
		if out.Summary, err = aclSummary(ctx, env, d.Text); err != nil {
			return ACLGetOutput{}, err
		}
		for _, m := range masked {
			out.Masked = out.Masked || m
		}
	} else if err := out.page(in, shown, masked); err != nil {
		return ACLGetOutput{}, err
	}
	out.ExternallyManaged, out.ExternalLink, out.ExternallyManagedNote = externalFacts(ctx, env)
	return out, nil
}

// page fills the policy text of the page in asks for, from lines already prepared for display.
func (out *ACLGetOutput) page(in ACLGetInput, shown []string, masked []bool) error {
	from, max := in.FromLine, in.MaxBytes
	if from == 0 {
		from = 1
	}
	if max == 0 {
		max = defaultPolicyPage
	}
	if from > max1(out.Lines) {
		return invalidf("fromLine %d is past the policy's last line, %d", from, out.Lines)
	}
	var page strings.Builder
	used, to := 0, from-1
	for to < out.Lines {
		// A line costs what it takes in the result: encoded as JSON text, which can
		// be a third longer than the line itself.
		cost := encodedLen(shown[to])
		if used+cost > max {
			if page.Len() > 0 {
				break
			}
			if cost > maxPolicyPage {
				return invalidf("line %d is %d bytes as JSON text, more than the largest page, %d: it cannot be shown", to+1, cost, maxPolicyPage)
			}
			return invalidf("line %d is %d bytes as JSON text, more than maxBytes %d; ask for maxBytes %d or more", to+1, cost, max, cost)
		}
		page.WriteString(shown[to])
		used += cost
		out.Masked = out.Masked || masked[to]
		to++
	}
	out.Policy, out.FromLine, out.ToLine = page.String(), from, to
	if to < out.Lines {
		out.Truncated, out.NextLine = true, to+1
	}
	return nil
}

const (
	// summaryListMax is the most names a summary shows in each list.
	summaryListMax = 100
	// listBudget is the most characters, as JSON text, that one list of names takes, and
	// rowsBudget the most that the section rows take: seven lists and the rows come to 132,000
	// of the 200,000 characters the tool declares, whatever the names are. Names that escape
	// (a quote, an angle bracket, a control character) cost up to six times their length, so
	// a count alone would not hold the bound.
	listBudget = 16000
	rowsBudget = 20000
	// summaryRowCost is what a section row costs besides its strings: its fixed fields.
	summaryRowCost = 64
)

// namesBudget shows the names of a summary within the budget of each list.
type namesBudget struct {
	env *registry.Env
	cut bool // a list was cut, by its count or its budget
}

// show displays s and says whether it fits what is left of left; extra is what its row
// costs besides the string.
func (b *namesBudget) show(s string, left *int, extra int) (string, bool) {
	shown := policyDisplay(b.env, s)
	cost := encodedLen(shown) + 3 + extra // the quotes and a comma
	if cost > *left {
		b.cut = true
		return "", false
	}
	*left -= cost
	return shown, true
}

// names shows the first names of a sorted list that fit: at most summaryListMax, and within
// listBudget. The list is a prefix of the sorted list, so a name is never skipped for a
// shorter one that follows it.
func (b *namesBudget) names(in []string) []string {
	var out []string
	left := listBudget
	for i, n := range in {
		if i >= summaryListMax {
			b.cut = true
			break
		}
		shown, ok := b.show(n, &left, 0)
		if !ok {
			break
		}
		out = append(out, shown)
	}
	return out
}

// rows shows the section rows that fit: every known section, and up to summaryListMax others.
func (b *namesBudget) rows(in []acl.SectionSummary) []ACLSectionRow {
	out := make([]ACLSectionRow, 0, len(in))
	left := rowsBudget
	for i, r := range in {
		if i >= len(acl.Sections())+summaryListMax {
			b.cut = true
			break
		}
		name, ok := b.show(r.Name, &left, summaryRowCost)
		if !ok {
			break
		}
		scalar := ""
		if r.Scalar != "" {
			if scalar, ok = b.show(r.Scalar, &left, 0); !ok {
				break
			}
		}
		out = append(out, ACLSectionRow{Name: name, Known: r.Known, State: r.State.String(), Count: r.Count, Scalar: scalar})
	}
	return out
}

// aclSummary reads the shape of a policy text: what the engine reports, shown within the
// bounds of a result, and the keyed digests when a privacy key is configured. A policy the
// engine cannot read is an error that points at the text view.
func aclSummary(ctx context.Context, env *registry.Env, text []byte) (*ACLSummary, error) {
	doc, err := acl.Parse(ctx, text)
	if err != nil {
		return nil, summaryError(err)
	}
	sum, err := acl.Summarise(ctx, doc)
	if err != nil {
		return nil, summaryError(err)
	}
	b := &namesBudget{env: env}
	s := &ACLSummary{
		Sections: b.rows(sum.Sections), Groups: b.names(sum.Groups), TagOwners: b.names(sum.TagOwners), Hosts: b.names(sum.Hosts),
		Postures: b.names(sum.Postures), IPSets: b.names(sum.IPSets), SyncedGroups: b.names(sum.SyncedGroups),
		Tests: sum.Tests, SSHTests: sum.SSHTests, Unknown: b.names(sum.Unknown),
	}
	s.NamesTruncated = sum.NamesTruncated || b.cut
	if env != nil && env.Privacy != nil {
		s.NamesDigest = namesDigest(env.Privacy, sum)
	}
	if s.SemanticDigest, err = semanticDigest(ctx, env, doc); err != nil {
		return nil, summaryError(err)
	}
	return s, nil
}

// summaryError says that tailkeeper cannot read a policy Tailscale holds. The engine's
// message may quote the policy, so it is untrusted text like any message.
func summaryError(err error) error {
	var ae *acl.Error
	if errors.As(err, &ae) {
		return tkerr.New(tkerr.APIError, "tailkeeper cannot summarise the live policy: "+ae.Error(), "ask for the text view, which returns the policy as the API sent it")
	}
	return err
}

// namesDigest is the keyed digest of the names a policy defines or refers to, each list
// under its label, each name behind its length, so that no two sets of names read alike.
func namesDigest(k *privacy.Key, s *acl.Summary) string {
	var b bytes.Buffer
	for _, l := range []struct {
		label string
		names []string
	}{{"groups", s.Groups}, {"tagOwners", s.TagOwners}, {"hosts", s.Hosts}, {"postures", s.Postures}, {"ipsets", s.IPSets}, {"syncedGroups", s.SyncedGroups}} {
		fmt.Fprintf(&b, "%s %d\n", l.label, len(l.names))
		for _, n := range l.names {
			fmt.Fprintf(&b, "%d:%s\n", len(n), n)
		}
	}
	return k.Digest(b.Bytes())
}

// splitLines splits text after each line feed, dropping the empty tail a final
// line feed leaves.
func splitLines(text string) []string {
	lines := strings.SplitAfter(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// settingsWait bounds acl_get's advisory settings call, retries included. It is a
// variable only so a test can shorten it.
var settingsWait = 10 * time.Second

// encodedLen is what an escaped line costs in a result: its length encoded as a
// JSON string, without the quotes.
func encodedLen(line string) int {
	b, _ := json.Marshal(line) // a string always encodes
	return len(b) - 2
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
