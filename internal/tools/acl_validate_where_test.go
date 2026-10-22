package tools_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// A proposal with two keys and two tests, one line each, so that a problem can be told from
// its line.
const placedProposal = "{\n" +
	"\t\"tagOwners\": {\"tag:x\": [\"autogroup:admin\"], \"tag:b\": [\"autogroup:admin\"]},\n" +
	"\t\"acls\": [{\"action\": \"accept\", \"src\": [\"tag:x\"], \"dst\": [\"tag:b:22\"]}],\n" +
	"\t\"tests\": [\n" +
	"\t\t{\"src\": \"tag:x\", \"accept\": [\"tag:b:22\"]},\n" +
	"\t\t{\"src\": \"tag:b\", \"accept\": [\"tag:b:22\"]},\n" +
	"\t],\n" +
	"}\n"

func validateProposal(t *testing.T, answer apitest.Shape, proposal string) tools.ACLValidateOutput {
	t.Helper()
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(answer)
	return validateOnline(t, env, `{"policy":`+jsonString(proposal)+`}`)
}

// Every rejection the live API gave on 20 Oct 2026 is a rejected result, placed in the
// proposal as far as its words allow: a position is one line, a quoted name is every place
// that holds it, labelled, and a message that names nothing has no place.
func TestEveryObservedRejectionIsRejectedWithItsLocation(t *testing.T) {
	t.Run("a syntax error is one line and column of the proposal", func(t *testing.T) {
		out := validateProposal(t, apitest.PolicySyntaxError(3, 5, "invalid literal: foo"), placedProposal)
		if out.Status != "rejected" || len(out.Errors) != 1 {
			t.Fatalf("status %q, errors %+v", out.Status, out.Errors)
		}
		p := out.Errors[0]
		if p.Kind != "server_message" || p.Source != "from" || p.Line != 3 || p.Column != 5 || !p.FromTailscale || !strings.Contains(p.Message, "invalid literal") {
			t.Errorf("problem = %+v", p)
		}
	})
	t.Run("an unknown tag is every place that holds it, never one", func(t *testing.T) {
		out := validateProposal(t, apitest.PolicyTagNotFound("tag:x"), placedProposal)
		if out.Status != "rejected" {
			t.Fatalf("status %q", out.Status)
		}
		var lines []string
		for _, p := range out.Errors {
			lines = append(lines, fmt.Sprintf("%d:%s", p.Line, p.Pointer))
			if p.Source != "from" || p.Kind != "server_message" || !strings.Contains(p.Message, "tag not found") {
				t.Errorf("problem = %+v", p)
			}
		}
		want := "2:/tagOwners/tag:x,3:/acls/0/src/0,5:/tests/0/src"
		if strings.Join(lines, ",") != want {
			t.Errorf("places = %v, want %s", lines, want)
		}
		if len(out.Errors) < 2 {
			t.Fatalf("%d problems, want one for each place", len(out.Errors))
		}
		if !strings.Contains(out.Errors[0].Message, "(the name the message quotes is a key here)") ||
			!strings.Contains(out.Errors[1].Message, "(the name the message quotes is a string here)") {
			t.Errorf("labels: %q, %q", out.Errors[0].Message, out.Errors[1].Message)
		}
	})
	t.Run("an unknown field is placed at the section", func(t *testing.T) {
		out := validateProposal(t, apitest.PolicyUnknownField("nodeAttr"), "{\n\"nodeAttr\": []\n}")
		if out.Status != "rejected" || len(out.Errors) != 1 || out.Errors[0].Line != 2 || out.Errors[0].Pointer != "/nodeAttr" {
			t.Errorf("status %q, errors %+v", out.Status, out.Errors)
		}
	})
	t.Run("a message that names nothing has no place", func(t *testing.T) {
		out := validateProposal(t, apitest.BareMessage200("something is wrong"), placedProposal)
		if out.Status != "rejected" || len(out.Errors) != 1 || out.Errors[0].Line != 0 || out.Errors[0].Source != "" {
			t.Errorf("status %q, errors %+v", out.Status, out.Errors)
		}
	})
	t.Run("a repeated key in a proposal is invalid and nothing is sent", func(t *testing.T) {
		f, _, env := apiEnv(t)
		serveLive(f, liveText, nil, nil)
		f.ServeValidate(apitest.PolicyDuplicateKey(2, 3, 3, 3))
		before := len(f.Requests())
		out := validateOnline(t, env, `{"policy":"{\n\"groups\": {},\n\"groups\": {}\n}"}`)
		if out.Status != "invalid" || out.Errors[0].Kind != "duplicate_key" || len(f.Requests()) != before {
			t.Errorf("status %q, errors %+v, %d requests", out.Status, out.Errors, len(f.Requests())-before)
		}
	})
}

// A message that quotes a name held in more places than are listed shows the first few and
// says how many it left out, on the first.
func TestACandidateListIsCutAndCounted(t *testing.T) {
	var b strings.Builder
	b.WriteString("{\n\"hosts\": {\n")
	for i := 0; i < 12; i++ {
		fmt.Fprintf(&b, "\"h%d\": \"tag:x\",\n", i)
	}
	b.WriteString("}\n}\n")
	out := validateProposal(t, apitest.PolicyTagNotFound("tag:x"), b.String())
	if out.Status != "rejected" || len(out.Errors) != 8 || out.Errors[0].MoreCandidates != 4 {
		t.Fatalf("status %q, %d problems, more %d; want 8 shown and 4 more on the first", out.Status, len(out.Errors), out.Errors[0].MoreCandidates)
	}
	for _, p := range out.Errors[1:] {
		if p.MoreCandidates != 0 {
			t.Errorf("only the first carries the count: %+v", p)
		}
	}
}

// A failure is placed in the proposal by the test it is about: its source, and its
// destination when the line names one.
func TestAssertionFailuresAreLocatedByTheirTest(t *testing.T) {
	line := `[acl test error]: address "tag:b:22": want: Accept, got: Drop`
	out := validateProposal(t, apitest.TestsFailed(apitest.Entry{User: "tag:b", Errors: []string{line}}), placedProposal)
	if out.Status != "fail" || len(out.Errors) != 1 {
		t.Fatalf("status %q, errors %+v", out.Status, out.Errors)
	}
	p := out.Errors[0]
	if p.Kind != "assertion_failed" || p.Source != "from" || p.Line != 6 || p.Pointer != "/tests/1" || p.Message != line {
		t.Errorf("problem = %+v", p)
	}
	// A destination the server wrote another way is every test with that source, labelled.
	other := `[acl test error]: address "192.0.2.9:22": want: Accept, got: Drop`
	out = validateProposal(t, apitest.TestsFailed(apitest.Entry{User: "tag:b", Errors: []string{other}}), placedProposal)
	if len(out.Errors) != 1 || out.Errors[0].Line != 6 || !strings.Contains(out.Errors[0].Message, "(a test with the same source)") {
		t.Errorf("a destination that matches no test: %+v", out.Errors)
	}
	// Validating the live policy places the failure in the live text.
	f, _, env := apiEnv(t)
	liveWithTest := liveText[:len(liveText)-2] + "\t\"tests\": [{\"src\": \"tag:ci\", \"accept\": [\"tag:ci:22\"]}],\n}\n"
	serveLive(f, liveWithTest, nil, nil)
	f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{`[acl test error]: address "tag:ci:22": want: Accept, got: Drop`}}))
	live := validateOnline(t, env, `{}`)
	if live.Status != "fail" || len(live.Errors) != 1 || live.Errors[0].Source != "live" || live.Errors[0].Line != 4 {
		t.Errorf("live: status %q, errors %+v", live.Status, live.Errors)
	}
}

// What Tailscale writes is data. An address in it is masked without a pseudonym, a pseudonym
// marker is unforged, and a terminal escape is escaped, in the message and in the pointer.
func TestAServerMessageIsMaskedWithoutPseudonymsAndUnforged(t *testing.T) {
	f, _, env := apiEnv(t)
	keyedEnv, _ := keyed(t, env)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.BareMessage200("amy@example.com is unknown; also [p:abcdefghij] and \x1b[2J"))
	out := validateOnline(t, keyedEnv, `{}`)
	if out.Status != "rejected" || len(out.Errors) != 1 {
		t.Fatalf("status %q, errors %+v", out.Status, out.Errors)
	}
	m := out.Errors[0].Message
	absent(t, m, "amy@", "[p:abcdefghij]", "\x1b", "[p:")
	if !strings.Contains(m, "a…@example.com is unknown") {
		t.Errorf("the address is not masked as one character and a domain: %q", m)
	}
	if strings.Contains(m, "] ") && strings.Contains(m, "a…@example.com [") {
		t.Errorf("a pseudonym stands beside an echoed address: %q", m)
	}
}

// A rejection that echoes an object key (probe A-14: a login used as a host name) is masked
// like any message.
func TestAnEchoedKeyIsMasked(t *testing.T) {
	f, _, env := apiEnv(t)
	keyedEnv, _ := keyed(t, env)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.PolicyKeyRejected("nobody-aaaaaaaa@example.com"))
	out := validateOnline(t, keyedEnv, `{}`)
	if out.Status != "rejected" || len(out.Errors) != 1 {
		t.Fatalf("status %q, errors %+v", out.Status, out.Errors)
	}
	absent(t, out.Errors[0].Message, "nobody-aaaaaaaa@", "[p:")
	if !strings.Contains(out.Errors[0].Message, "n…@example.com") {
		t.Errorf("message = %q", out.Errors[0].Message)
	}
}

// A 400 whose message speaks of size carries the size hint beside the rejection.
func TestARejectionThatSpeaksOfSizeCarriesTheHint(t *testing.T) {
	out := validateProposal(t, apitest.Rejected400("request entity too large"), placedProposal)
	if out.Status != "rejected" || len(out.Errors) != 1 || len(out.Notices) != 1 || !strings.Contains(out.Notices[0].Message, "policy_too_large") {
		t.Errorf("status %q, errors %+v, notices %+v", out.Status, out.Errors, out.Notices)
	}
}

func TestErrorsLeaveThroughTheResolverAndTheRegistry(t *testing.T) {
	f, _, env := apiEnv(t)
	serveLive(f, liveText, nil, nil)
	f.ServeValidate(apitest.Forbidden403())
	_, err := call(t, newRegistry(t), env, "acl_validate", `{}`)
	if code(err) != tkerr.ScopeMissing {
		t.Errorf("err = %v, want scope_missing", err)
	}
}
