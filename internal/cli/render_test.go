package cli

import (
	"strings"
	"testing"
	"unicode"

	"github.com/abm9111/tailkeeper/internal/tools"
)

// A field the source leaves out on purpose is not "unknown": Tailnet Lock status
// has no node key signature while the lock is off, and says so by leaving it out.
func TestRenderLeavesOutAnAbsentFieldThatIsAbsentOnPurpose(t *testing.T) {
	var off strings.Builder
	if err := render(&off, tools.LockStatusOutput{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(off.String(), "nodeKeySigned") || !strings.Contains(off.String(), "enabled: false\n") {
		t.Errorf("lock off:\n%s", off.String())
	}
	signed := true
	var on strings.Builder
	if err := render(&on, tools.LockStatusOutput{Enabled: true, NodeKeySigned: &signed}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(on.String(), "nodeKeySigned: true\n") {
		t.Errorf("lock on:\n%s", on.String())
	}
	// Any other nil scalar is still "unknown": the source did not say.
	type out struct {
		Said    *bool `json:"said"`
		Omitted *bool `json:"omitted" tk:"absentok"`
	}
	var other strings.Builder
	if err := render(&other, out{}); err != nil {
		t.Fatal(err)
	}
	if other.String() != "said: unknown\n" {
		t.Errorf("render = %q", other.String())
	}
}

// The usage names the flags each command takes, --context and --json included.
func TestUsageNamesTheFlagsOfEveryCommand(t *testing.T) {
	var b strings.Builder
	(&Runner{}).usage(&b)
	for _, want := range []string{
		"tailkeeper mcp [--context NAME] [--profile reads|core|full] [--enable-alpha]\n",
		"tailkeeper doctor [--context NAME] [--json] [--probe | --policy --out FILE [--tag TAG] [--admin-group GROUP] [--with-logins]]\n",
		"tailkeeper scopes [--json] [--alpha]\n",
		"tailkeeper audit verify [--json] | audit tail [-n N] [--json] | audit rotate [--json]\n",
		"tailkeeper docs [--scopes] [--check FILE]\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("usage lacks %q:\n%s", want, b.String())
		}
	}
}

type commandRow struct {
	Name   string `json:"name" tk:"col"`
	Answer string `json:"answer" tk:"col"`
}

type commandRows struct {
	Rows    []commandRow `json:"rows" tk:"rows"`
	Message string       `json:"message,omitempty"`
}

// Text from the tailnet can lead a table row or follow a field name; no line of
// the text form starts like a GitHub workflow command or an Azure formatting
// command, and none holds an Azure logging command or a TeamCity service message.
func TestRenderKeepsCILogCommandsOutOfEveryLine(t *testing.T) {
	var b strings.Builder
	out := commandRows{
		Rows: []commandRow{
			{Name: "::error::boom", Answer: "##vso[task.setvariable variable=x]y"},
			{Name: "##[group]x", Answer: "fine"},
			{Name: "ordinary", Answer: "##teamcity[buildProblem description='x']"},
		},
		Message: "see ##vso[task.complete result=Failed;] now",
	}
	if err := render(&b, out); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n") {
		trimmed := strings.TrimLeftFunc(line, unicode.IsSpace)
		if strings.HasPrefix(trimmed, "::") || strings.HasPrefix(trimmed, "##[") ||
			strings.Contains(line, "##vso[") || strings.Contains(line, "##teamcity[") {
			t.Errorf("a line of the text form can act on a CI log: %q", line)
		}
	}
	for _, want := range []string{`error::boom`, `#vso[task.setvariable variable=x]y`, `ordinary`, `message: see `} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("the text form lost %q:\n%s", want, b.String())
		}
	}
}

// The lines a tool prints after its fields, and a document it prints, are guarded
// like the fields.
func TestRenderGuardsDetailLinesAndDocumentLines(t *testing.T) {
	var b strings.Builder
	if err := render(&b, detailedOut{}); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n") {
		if strings.HasPrefix(line, "::") || strings.Contains(line, "##vso[") || strings.Contains(line, "##teamcity[") {
			t.Errorf("a line can act on a CI log: %q", line)
		}
	}
	if !strings.Contains(b.String(), "error::detail") || !strings.Contains(b.String(), "document ") {
		t.Errorf("render lost its lines:\n%s", b.String())
	}
}

type detailedOut struct {
	Text string `json:"text" tk:"multiline"`
	Note string `json:"note" tk:"details"`
}

func (detailedOut) Details() []string {
	return []string{"::error::detail", "x ##vso[task.logissue type=error]y"}
}
func (detailedOut) Block() (int, string) {
	return 1, "document ##teamcity[buildProblem description='x']\n"
}
