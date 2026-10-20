package tools_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

func TestIsLiteralLoginIsTheMaskersDefinitionLessThreeForms(t *testing.T) {
	bs := string(rune(92))
	for s, want := range map[string]bool{
		"amy@example.com":                        true,
		"Amy@Example.COM":                        true,
		"amy" + bs + "u0040example.com":          true,
		"amy%40example.com":                      true,
		"amy@example.com:22":                     true,
		"note: ask amy@example.com":              true,
		"amy@user:*@example.com":                 true,
		"user:*@example.com and amy@example.com": true,
		"a…@example.com [p:abcdefghij]":          false,
		"p:abcdefghij":                           false,
		"[p:abcdefghij]":                         false,
		"user:*@example.com":                     false,
		"localpart:*@example.com":                false,
		"user:*@example.com:22":                  false,
		"logstream@tailscale":                    false,
		"group:engineering@example.com":          false,
		"group:eng":                              false,
		// A pointer that spells a key (the ~1 is a slash) is no login as written, since the
		// masker reads group:~1amy as a group's name; read as a pointer it is group:/amy@..., a login.
		"/group:~1amy@example.com": false,
		"group:/amy@example.com":   true,
		"autogroup:member":         false,
		"tag:prod":                 false,
		"100.64.0.1:22":            false,
		"@handle":                  false,
		"":                         false,
	} {
		if got := tools.IsLiteralLogin(s); got != want {
			t.Errorf("IsLiteralLogin(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestProposalWithoutALoginPasses(t *testing.T) {
	_, _, env := apiEnv(t)
	bs := string(rune(92))
	for name, text := range map[string]string{
		"names, tags, groups and the three forms": `{
	// owner: amy@example.com asked for this
	"groups": {"group:eng": ["a…@example.com [p:abcdefghij]", "p:klmnopqrst"]},
	"tagOwners": {"tag:web": ["group:eng", "group:engineering@example.com"]},
	"acls": [{"action": "accept", "src": ["user:*@example.com", "localpart:*@example.com"], "dst": ["tag:web:443", "100.64.0.1:22"]}],
	"nodeAttrs": [{"target": ["logstream@tailscale"], "attr": ["funnel"]}], /* bob@example.com */
}`,
		"a // inside a string is not a comment": `{"hosts": {"a": "100.64.0.1"}, "note": "see http://example.com/x // not a comment"} // amy@example.com`,
		"a login after a block comment":         `{"a": "x"} /* amy@example.com */`,
		"an escaped quote ends nothing":         `{"a": "he said ` + bs + `"hi` + bs + `" // x", "b": "ok"} // amy@example.com`,
		"an empty object":                       `{}`,
	} {
		if err := tools.CheckProposalSubjects(env, text); err != nil {
			t.Errorf("%s: %v, want nil", name, err)
		}
	}
}

func TestProposalWithALiteralLoginIsRefusedNamingThePointer(t *testing.T) {
	_, _, env := apiEnv(t)
	bs := string(rune(92))
	for name, c := range map[string]struct{ text, pointer string }{
		"a value":                {`{"groups": {"group:a": ["amy@example.com"]}}`, "/groups/group:a/0"},
		"a test source":          {`{"tests": [{"src": "amy@example.com", "accept": ["tag:x:22"]}]}`, "/tests/0/src"},
		"a destination":          {`{"tests": [{"src": "tag:a", "accept": ["amy@example.com:22"]}]}`, "/tests/0/accept/0"},
		"a key":                  {`{"groups": {"amy@example.com": []}}`, "/groups (a key)"},
		"a top-level key":        {`{"amy@example.com": 1}`, "the top level (a key)"},
		"an escaped at sign":     {`{"a": ["amy` + bs + `u0040example.com"]}`, "/a/0"},
		"a percent-encoded one":  {`{"a": ["amy%40example.com"]}`, "/a/0"},
		"upper case":             {`{"a": ["AMY@EXAMPLE.COM"]}`, "/a/0"},
		"inside a longer string": {`{"note": "ask amy@example.com first"}`, "/note"},
		"after a string with //": {`{"url": "http://x//y", "src": ["amy@example.com"]}`, "/src/0"},
		"deep":                   {`{"a": {"b": [[], {"c": "amy@example.com"}]}}`, "/a/b/1/c"},
	} {
		err := tools.CheckProposalSubjects(env, c.text)
		e, ok := tkerr.As(err)
		if !ok || e.Code != tkerr.FilterRefused {
			t.Errorf("%s: %v, want filter_refused", name, err)
			continue
		}
		if !strings.Contains(e.Message, c.pointer) {
			t.Errorf("%s: the message %q does not name %s", name, e.Message, c.pointer)
		}
		if strings.Contains(e.Error(), "amy") || strings.Contains(strings.ToLower(e.Error()), "example.com") {
			t.Errorf("%s: the refusal repeats the login: %v", name, e)
		}
		// This env has no privacy key, so there are no pseudonyms to point to: the hint says so,
		// as the hint of a refused filter does.
		if !strings.Contains(e.Hint, "privacy key") {
			t.Errorf("%s: the hint %q does not name the privacy key", name, e.Hint)
		}
	}
}

// A rule that guards a privacy boundary does not panic on a nil Env: it refuses, as it did
// before the hint followed the key, and the hint is the keyless one.
func TestSubjectRuleWithANilEnvRefusesWithoutPanicking(t *testing.T) {
	checked := 0
	for name, err := range map[string]error{
		"proposal": tools.CheckProposalSubjects(nil, `{"a": "amy@example.com"}`),
		"patch":    tools.CheckPatchSubjects(nil, []byte(`[{"op": "add", "path": "/a", "value": "amy@example.com"}]`)),
	} {
		checked++
		e, ok := tkerr.As(err)
		if !ok || e.Code != tkerr.FilterRefused {
			t.Errorf("%s: %v, want filter_refused", name, err)
			continue
		}
		if !strings.Contains(e.Hint, "privacy key is configured") {
			t.Errorf("%s: the hint %q is not the keyless one", name, e.Hint)
		}
	}
	if checked != 2 {
		t.Fatalf("checked %d, want 2", checked)
	}
}

// Pseudonyms exist only with a privacy key, so the hint of a refusal sends the caller to one
// only then; without a key it names the key, as filterRefused does.
func TestRefusalHintFollowsTheKey(t *testing.T) {
	_, _, env := apiEnv(t)
	kenv, _ := keyed(t, env)
	proposal := `{"groups": {"group:a": ["amy@example.com"]}}`
	patch := `[{"op": "add", "path": "/groups/group:a/-", "value": "amy@example.com"}]`
	checked := 0
	for name, e := range map[string]*registry.Env{"keyless": env, "keyed": kenv} {
		for what, err := range map[string]error{
			"proposal": tools.CheckProposalSubjects(e, proposal),
			"patch":    tools.CheckPatchSubjects(e, []byte(patch)),
		} {
			checked++
			fe, ok := tkerr.As(err)
			if !ok || fe.Code != tkerr.FilterRefused {
				t.Errorf("%s %s: %v, want filter_refused", name, what, err)
				continue
			}
			hasKey := strings.Contains(fe.Hint, "privacy key is configured")
			routes := strings.Contains(fe.Hint, "name the user by the pseudonym a result shows")
			if name == "keyless" && (!hasKey || routes) {
				t.Errorf("%s %s: the hint %q must name the privacy key and send no one to a pseudonym", name, what, fe.Hint)
			}
			if name == "keyed" && (hasKey || !routes) {
				t.Errorf("%s %s: the hint %q must send the caller to the pseudonym a result shows", name, what, fe.Hint)
			}
		}
	}
	if checked != 4 {
		t.Fatalf("checked %d refusals, want 4", checked)
	}
}

func TestProposalRefusalCountsEveryStringAndNamesTheFirstEight(t *testing.T) {
	_, _, env := apiEnv(t)
	var items []string
	for i := range 12 {
		items = append(items, fmt.Sprintf(`"u%d@example.com"`, i))
	}
	text := `{"groups": {"group:a": [` + strings.Join(items, ",") + `], "k@example.com": []}}`
	e, _ := tkerr.As(tools.CheckProposalSubjects(env, text))
	if e == nil || !strings.Contains(e.Message, "13 strings") {
		t.Fatalf("got %v, want a refusal that counts 13 strings", e)
	}
	if n := strings.Count(e.Message, "/groups/group:a/"); n != 8 {
		t.Errorf("the message names %d pointers, want 8: %s", n, e.Message)
	}
	if !strings.Contains(e.Message, "the first 8") {
		t.Errorf("the message does not say it lists only the first 8: %s", e.Message)
	}
	// A key and a value in one string each: two findings.
	e, _ = tkerr.As(tools.CheckProposalSubjects(env, `{"amy@example.com": "bob@example.com"}`))
	if e == nil || !strings.Contains(e.Message, "2 strings") {
		t.Errorf("got %v, want 2 strings", e)
	}
	if e != nil && strings.Contains(e.Message, "the first 8") {
		t.Errorf("a refusal that lists every string says it lists the first 8: %s", e.Message)
	}
}

func TestProposalThatIsNotHuJSONOrNestsTooDeepIsNeverAPass(t *testing.T) {
	_, _, env := apiEnv(t)
	for name, text := range map[string]string{
		"a syntax error":    `{"a": [}`,
		"trailing text":     `{} amy@example.com`,
		"a byte order mark": "\xef\xbb\xbf{}",
		"a NUL":             "{\"a\": \"x\x00\"}",
		"nothing":           ``,
		"an open comment":   `{} /* amy@example.com`,
		"1,001 levels":      strings.Repeat("[", 1001) + strings.Repeat("]", 1001),
		"5,000 open levels": strings.Repeat("[", 5000),
	} {
		err := tools.CheckProposalSubjects(env, text)
		if code(err) != tkerr.ValidationFailed {
			t.Errorf("%s: %v, want validation_failed", name, err)
		}
	}
	if err := tools.CheckProposalSubjects(env, strings.Repeat("[", 1000)+strings.Repeat("]", 1000)); err != nil {
		t.Errorf("1,000 levels: %v, want nil", err)
	}
	e, _ := tkerr.As(tools.CheckProposalSubjects(env, strings.Repeat("[", 1001)+strings.Repeat("]", 1001)))
	if e == nil || !strings.Contains(e.Message, "deeper than 1,000 levels") {
		t.Errorf("1,001 levels: %v, want the depth named", e)
	}
}

func TestProposalRuleDoesNotApplyWhilePersonalDataIsShown(t *testing.T) {
	_, _, env := apiEnv(t)
	for name, e := range map[string]*registry.Env{"masked": env, "shown": show(env)} {
		err := tools.CheckProposalSubjects(e, `{"groups": {"group:a": ["amy@example.com"]}}`)
		if (name == "masked") != (err != nil) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPatchWithoutALoginPasses(t *testing.T) {
	_, _, env := apiEnv(t)
	patch := `[
	// add the web rule; owner amy@example.com
	{"op": "add", "path": "/acls/-", "value": {"action": "accept", "src": ["group:eng", "user:*@example.com"], "dst": ["tag:web:443"]}},
	{"op": "add", "path": "/groups/group:eng/-", "value": "a…@example.com [p:abcdefghij]"}, /* bob@example.com */
	{"op": "remove", "path": "/tests/0"},
	{"op": "test", "path": "/hosts/web", "value": "100.64.0.1"},
	{"op": "copy", "from": "/groups/group:eng", "path": "/groups/group:copy"},
	{"op": "remove", "path": "/groups/a…@example.com [p:abcdefghij]"},
	{"op": "copy", "from": "/groups/a…@example.com [p:abcdefghij]", "path": "/groups/g2"},
	{"op": "add", "path": "/hosts/b", "value": {"addr": "100.64.0.2" /* amy@example.com */}},
]`
	if err := tools.CheckPatchSubjects(env, []byte(patch)); err != nil {
		t.Errorf("a patch with no login: %v, want nil", err)
	}
}

func TestPatchWithALoginAnywhereIsRefusedNamingThePointerInThePatch(t *testing.T) {
	_, _, env := apiEnv(t)
	bs := string(rune(92))
	clean := `{"op": "add", "path": "/hosts/a", "value": "100.64.0.1"}`
	for name, c := range map[string]struct{ patch, pointer string }{
		"the value of an add":          {`[{"op": "add", "path": "/groups/group:a/-", "value": "amy@example.com"}]`, "/0/value"},
		"a rule's source":              {`[{"op": "add", "path": "/acls/-", "value": {"action": "accept", "src": ["amy@example.com"], "dst": ["*:*"]}}]`, "/0/value/src/0"},
		"the value of a replace":       {`[{"op": "replace", "path": "/tests/0/src", "value": "amy@example.com"}]`, "/0/value"},
		"the value of a test":          {`[{"op": "test", "path": "/groups/group:a/0", "value": "amy@example.com"}]`, "/0/value"},
		"a key inside a value":         {`[{"op": "add", "path": "/groups", "value": {"amy@example.com": []}}]`, "/0/value (a key)"},
		"a path":                       {`[{"op": "add", "path": "/hosts/amy@example.com", "value": "100.64.0.1"}]`, "/0/path"},
		"a path with an escaped slash": {`[{"op": "remove", "path": "/groups/x~1amy@example.com"}]`, "/0/path"},
		"a from":                       {`[{"op": "copy", "from": "/groups/amy@example.com", "path": "/groups/g"}]`, "/0/from"},
		"an escaped at sign":           {`[{"op": "add", "path": "/a/-", "value": "amy` + bs + `u0040example.com"}]`, "/0/value"},
		"the second operation":         {`[` + clean + `, {"op": "add", "path": "/groups/g/-", "value": "amy@example.com"}]`, "/1/value"},
		"the last of five":             {`[` + clean + `,` + clean + `,` + clean + `,` + clean + `, {"op": "add", "path": "/a/-", "value": ["x", "amy@example.com"]}]`, "/4/value/1"},
		"after a string with //":       {`[{"op": "add", "path": "/a", "value": "http://x//y"}, {"op": "add", "path": "/b", "value": "amy@example.com"}]`, "/1/value"},
	} {
		err := tools.CheckPatchSubjects(env, []byte(c.patch))
		e, ok := tkerr.As(err)
		if !ok || e.Code != tkerr.FilterRefused {
			t.Errorf("%s: %v, want filter_refused", name, err)
			continue
		}
		if !strings.Contains(e.Message, c.pointer) {
			t.Errorf("%s: the message %q does not name %s", name, e.Message, c.pointer)
		}
		if strings.Contains(strings.ToLower(e.Error()), "amy") {
			t.Errorf("%s: the refusal repeats the login: %v", name, e)
		}
	}
	// Not valid HuJSON is never a pass, and personalData show lifts the rule.
	if code(tools.CheckPatchSubjects(env, []byte(`[{"op": `))) != tkerr.ValidationFailed {
		t.Error("a truncated patch must be validation_failed")
	}
	if err := tools.CheckPatchSubjects(show(env), []byte(`[{"op": "add", "path": "/a", "value": "amy@example.com"}]`)); err != nil {
		t.Errorf("personalData show: %v, want nil", err)
	}
}

// A path or a from is a JSON pointer, and a pointer spells a slash in a key as ~1: the key
// group:/amy@example.com is /groups/group:~1amy@example.com, which the masker reads as a
// group's name and leaves whole. The pointer is read as one too.
func TestPatchPathThatSpellsAKeyAsAPointerIsRefused(t *testing.T) {
	_, _, env := apiEnv(t)
	checked := 0
	for name, c := range map[string]struct{ patch, pointer string }{
		"a path": {`[{"op":"remove","path":"/groups/group:~1amy@example.com"}]`, "/0/path"},
		"a from": {`[{"op":"copy","from":"/groups/group:~1amy@example.com","path":"/groups/g"}]`, "/0/from"},
	} {
		checked++
		e, ok := tkerr.As(tools.CheckPatchSubjects(env, []byte(c.patch)))
		if !ok || e.Code != tkerr.FilterRefused {
			t.Errorf("%s: %v, want filter_refused", name, e)
			continue
		}
		if !strings.Contains(e.Message, c.pointer) {
			t.Errorf("%s: the message %q does not name %s", name, e.Message, c.pointer)
		}
		if strings.Contains(strings.ToLower(e.Error()), "amy") {
			t.Errorf("%s: the refusal repeats the login: %v", name, e)
		}
	}
	if checked != 2 {
		t.Fatalf("checked %d patches, want 2", checked)
	}
}

// Every member of an operation is read, the ones RFC 6902 does not name too, and so is a patch
// that is an object and not an array: hujson.Patch will refuse it later, and the rule does not
// wait for that.
func TestPatchRefusesAnUnknownMemberAndChecksAnObjectPatch(t *testing.T) {
	_, _, env := apiEnv(t)
	checked := 0
	for name, c := range map[string]struct{ patch, pointer string }{
		"an unknown member": {`[{"op": "add", "path": "/a", "value": 1, "comment": "amy@example.com"}]`, "/0/comment"},
		"an object patch":   {`{"op": "add", "path": "/a", "value": "amy@example.com"}`, "/value"},
	} {
		checked++
		e, ok := tkerr.As(tools.CheckPatchSubjects(env, []byte(c.patch)))
		if !ok || e.Code != tkerr.FilterRefused {
			t.Errorf("%s: %v, want filter_refused", name, e)
			continue
		}
		if !strings.Contains(e.Message, c.pointer) {
			t.Errorf("%s: the message %q does not name %s", name, e.Message, c.pointer)
		}
		if strings.Contains(strings.ToLower(e.Error()), "amy") {
			t.Errorf("%s: the refusal repeats the login: %v", name, e)
		}
	}
	if checked != 2 {
		t.Fatalf("checked %d patches, want 2", checked)
	}
}

// hujson recurses once per level, and a Go stack overflow is fatal, so the pre-scan has to
// come first; the test binary cannot prove that in its own process. The parent starts itself
// again with the switch set, and the child sends 5,000,000 levels through both checks.
func TestDeepNestingIsRefusedBeforeAnyParse(t *testing.T) {
	if os.Getenv("TAILKEEPER_TEST_DEEP_NESTING") != "" {
		deep := strings.Repeat("[", 5_000_000)
		env := &registry.Env{}
		for name, err := range map[string]error{
			"CheckProposalSubjects": tools.CheckProposalSubjects(env, deep),
			"CheckPatchSubjects":    tools.CheckPatchSubjects(env, []byte(deep)),
		} {
			e, ok := tkerr.As(err)
			if !ok || e.Code != tkerr.ValidationFailed || !strings.Contains(e.Message, "deeper than 1,000 levels") {
				fmt.Printf("%s: %v\n", name, err)
				os.Exit(3)
			}
		}
		fmt.Println("both refused the depth")
		return
	}
	// os.Args[0] with no slash in it is looked up on PATH: the running binary is asked for.
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("the path of the test binary: %v", err)
	}
	cmd := exec.Command(self, "-test.run=^TestDeepNestingIsRefusedBeforeAnyParse$")
	cmd.Env = append(os.Environ(), "TAILKEEPER_TEST_DEEP_NESTING=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "both refused the depth") {
		head := string(out)
		if len(head) > 400 {
			head = head[:400]
		}
		t.Fatalf("the child did not refuse 5,000,000 levels: %v\n%s", err, head)
	}
}

func TestProposalRefusalNeverEchoesALoginKeyOnThePathOfADeeperValue(t *testing.T) {
	_, _, env := apiEnv(t)
	for name, c := range map[string]struct {
		text, pointer string
		never         []string
	}{
		"a login key above a login value": {`{"amy@example.com": {"x": "bob@example.com"}}`, "/(a login)/x", []string{"amy", "example.com"}},
		"a login key with a tail":         {`{"amy@example.com;rm": {"x": "bob@example.com"}}`, "/(a login)/x", []string{"amy", ";rm"}},
		"a login key in an array":         {`{"groups": {"amy@example.com": ["bob@example.com"]}}`, "/groups/(a login)/0", []string{"amy"}},
	} {
		e, ok := tkerr.As(tools.CheckProposalSubjects(env, c.text))
		if !ok || e.Code != tkerr.FilterRefused {
			t.Errorf("%s: %v, want filter_refused", name, e)
			continue
		}
		if !strings.Contains(e.Message, c.pointer) {
			t.Errorf("%s: the message %q does not contain %s", name, e.Message, c.pointer)
		}
		low := strings.ToLower(e.Error())
		for _, n := range c.never {
			if strings.Contains(low, n) {
				t.Errorf("%s: the refusal repeats %q: %v", name, n, e)
			}
		}
	}
}

func TestProposalRefusalCapsEachPointerSegment(t *testing.T) {
	_, _, env := apiEnv(t)
	bs := string(rune(92))
	long := `{"` + strings.Repeat("k", 10000) + `": "amy@example.com"}`
	e, _ := tkerr.As(tools.CheckProposalSubjects(env, long))
	if e == nil || len(e.Message) >= 400 {
		t.Errorf("a 10,000 byte key: got %v, want a refusal under 400 bytes", e)
	}
	ctl := `{"a` + bs + `u0001b": {"x": "amy@example.com"}}`
	e, _ = tkerr.As(tools.CheckProposalSubjects(env, ctl))
	if e == nil {
		t.Fatalf("a control character in a key: no refusal")
	}
	for i := 0; i < len(e.Message); i++ {
		if e.Message[i] < 0x20 {
			t.Errorf("the message holds the raw byte %#x at %d: %q", e.Message[i], i, e.Message)
		}
	}
}
