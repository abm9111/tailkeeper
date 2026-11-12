package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// The synthetic estate of these tests: group:example-admins reaches the database on 22 and
// tag:example-web must not. Every name is a reserved one.
const explainPolicy = `{
	"groups": {"group:example-admins": ["alice@example.com"]},
	"tagOwners": {
		"tag:example-db": ["group:example-admins"],
		"tag:example-web": ["group:example-admins"],
	},
	"acls": [
		{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db:22"]},
		{"action": "accept", "src": ["tag:example-web"], "dst": ["tag:example-web:443"]},
	],
	"ssh": [
		{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db"], "users": ["root"]},
	],
}`

// adminIntent is the owner's admin-path invariant: only the admins reach the database on 22, and
// the web tier must not.
const adminIntent = `{
	"tests": [
		{"src": "group:example-admins", "accept": ["tag:example-db:22"]},
		{"src": "tag:example-web", "deny": ["tag:example-db:22"]},
	],
}`

const adminSSHIntent = `{
	"tests": [
		{"src": "tag:example-web", "deny": ["tag:example-db:22"]},
	],
	"sshTests": [
		{"src": "group:example-admins", "dst": ["tag:example-db"], "accept": ["root"]},
	],
}`

func adminModel() *policyModel {
	return &policyModel{allow: map[string]bool{"group:example-admins|tag:example-db:22": true}, sshAllow: map[string]bool{}}
}

func explainEnv(t *testing.T, policy string, m *policyModel) (*apitest.Fake, *registry.Env) {
	t.Helper()
	f, _, env := apiEnv(t)
	serveExplain(f, policy, m)
	return f, env
}

// The owner's admin-path example in its three variants.
func TestExplainAdminPathMetUnmetUnknown(t *testing.T) {
	t.Run("met: complete, exit 0, and one request", func(t *testing.T) {
		m := adminModel()
		f, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, adminIntent)
		if err != nil {
			t.Fatal(err)
		}
		if out.Status != "complete" || out.Counts.Met != 2 || out.ExitCode() != 0 || out.Report().Level != registry.LevelOK {
			t.Fatalf("status %s counts %+v exit %d", out.Status, out.Counts, out.ExitCode())
		}
		for _, row := range out.Expectations {
			for _, c := range row.Cells {
				if !c.Canary || !c.LiveUnchanged || c.Verdict != "met" {
					t.Errorf("%s: %+v, want met, with the canary and the live policy unchanged", row.ID, c)
				}
			}
		}
		if got := posts(f); got != 1 {
			t.Errorf("%d validation requests, want one: only network tests were asked", got)
		}
	})
	t.Run("unmet: the web tier reaches the database, exit 8", func(t *testing.T) {
		m := adminModel()
		m.allow["tag:example-web|tag:example-db:22"] = true
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, adminIntent)
		if err != nil {
			t.Fatal(err)
		}
		if rowOf(out, "network-2").Status != "unmet" || rowOf(out, "network-1").Status != "met" || out.ExitCode() != 8 || out.Status != "incomplete" {
			t.Fatalf("%+v exit %d", out.Counts, out.ExitCode())
		}
		for _, f := range out.Report().Findings {
			if strings.HasPrefix(f.Message, "network-2 · network") && f.Severity != "error" {
				t.Errorf("the finding of an unmet expectation is a %s, not an error", f.Severity)
			}
			if strings.HasPrefix(f.Message, "network-1 · network") && f.Severity != "notice" {
				t.Errorf("the finding of a met expectation is a %s, not a notice", f.Severity)
			}
		}
		web := blastOf(out, "tag:example-web")
		if web == nil || len(web.Reaches) != 1 || web.Reaches[0].Destination != "tag:example-db:22" || web.Heading != "if tag:example-web were compromised, the live policy would let it reach:" {
			t.Errorf("blast = %+v", out.Blast)
		}
		if out.Report().Level != registry.LevelFail || !strings.Contains(reportText(out), "network-2 · network · tag:example-web · unmet") {
			t.Errorf("report:\n%s", reportText(out))
		}
		if !strings.Contains(reportText(out), "network-2 · deny tag:example-db:22 · unmet · the live policy allowed it, which is the other thing") {
			t.Errorf("the pair that is unmet is not listed with its witness:\n%s", reportText(out))
		}
	})
	t.Run("unknown: no canary, exit 1", func(t *testing.T) {
		m := adminModel()
		m.omitCanary = true
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, adminIntent)
		if err != nil {
			t.Fatal(err)
		}
		if out.Counts.Unknown != 2 || out.Counts.Met != 0 || out.ExitCode() != 1 || out.Status != "incomplete" {
			t.Fatalf("%+v exit %d", out.Counts, out.ExitCode())
		}
		for _, row := range out.Expectations {
			if row.Cells[0].Reason != "canary" || row.Cells[0].Canary {
				t.Errorf("%s: %+v", row.ID, row.Cells[0])
			}
		}
	})
}

// A broad rule is a candidate however many narrow rules for others stand beside it, and the
// blast radius names it; the narrow rule of another source is not a candidate.
func TestBroadGrantSurvivesUnrelatedNarrowRule(t *testing.T) {
	policy := `{
	"acls": [
		{"action": "accept", "src": ["tag:example-other"], "dst": ["tag:example-db:22"]},
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
		{"action": "accept", "src": ["tag:example-web"], "dst": ["tag:example-web:443"]},
	],
}`
	intent := `{"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}]}`
	m := &policyModel{allow: map[string]bool{"tag:example-web|tag:example-db:22": true}}
	_, env := explainEnv(t, policy, m)
	out, err := explainOnce(t, env, intent)
	if err != nil {
		t.Fatal(err)
	}
	row := rowOf(out, "network-1")
	if row.Status != "unmet" || out.ExitCode() != 8 {
		t.Fatalf("status %s exit %d", row.Status, out.ExitCode())
	}
	if len(row.Candidates) != 1 || row.Candidates[0].Section != "acls" || row.Candidates[0].Index != 2 || !row.Candidates[0].Broad || row.Candidates[0].Line != 4 {
		t.Errorf("candidates = %+v, want only the broad rule, acls[2] at line 4", row.Candidates)
	}
	blast := blastOf(out, "tag:example-web")
	if blast == nil || len(blast.Broad) != 1 || blast.Broad[0].Index != 2 {
		t.Fatalf("blast = %+v", out.Blast)
	}
	text := reportText(out)
	if !strings.Contains(text, "policy grants this source all destinations (candidate rule at 4:") {
		t.Errorf("the blast radius does not name the broad rule in the fixed words:\n%s", text)
	}
	if strings.Contains(text, "tag:example-other") {
		t.Errorf("the narrow rule of another source was cited:\n%s", text)
	}
	// The candidate is not the cause: the verdict is the same with no rule cited at all.
	if !strings.Contains(text, "candidate rule (a text match, not a verdict)") {
		t.Errorf("a candidate is not labelled as one:\n%s", text)
	}
}

// "policy grants this source all destinations" is said only for a plain network rule whose
// destination is *: a rule with srcPosture, app capabilities or via says less, and an ssh rule is
// about ssh. Those stay candidates, marked as qualified, and the limit says what the qualifier means.
func TestBlastRadiusDoesNotOverclaimForQualifiedOrSSHRules(t *testing.T) {
	policy := `{
	"acls": [
		{"action": "accept", "src": ["tag:example-web"], "dst": ["*:*"], "srcPosture": ["posture:example"]},
	],
	"grants": [
		{"src": ["tag:example-web"], "dst": ["*"], "app": {"example.com/cap": [{"x": 1}]}},
		{"src": ["tag:example-web"], "dst": ["*"], "ip": ["*"], "via": ["tag:example-exit"]},
	],
	"ssh": [
		{"action": "accept", "src": ["tag:example-web"], "dst": ["*"], "users": ["root"]},
	],
	"postures": {"posture:example": ["node:os == 'linux'"]},
}`
	intent := `{"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}]}`
	m := &policyModel{allow: map[string]bool{"tag:example-web|tag:example-db:22": true}}
	_, env := explainEnv(t, policy, m)
	out, err := explainOnce(t, env, intent)
	if err != nil {
		t.Fatal(err)
	}
	text := reportText(out)
	if strings.Contains(text, "policy grants this source all destinations") {
		t.Errorf("the blast radius says the policy grants every destination on the strength of a qualified rule:\n%s", text)
	}
	row := rowOf(out, "network-1")
	if len(row.Candidates) != 3 {
		t.Fatalf("candidates = %+v, want the three qualified rules", row.Candidates)
	}
	for _, c := range row.Candidates {
		if !c.Qualified || !c.Broad {
			t.Errorf("candidate %+v: want broad and qualified", c)
		}
	}
	if !strings.Contains(text, "qualified by srcPosture or defaultSrcPosture, app capabilities or via") {
		t.Errorf("a candidate does not say it is qualified:\n%s", text)
	}
	if blast := blastOf(out, "tag:example-web"); blast == nil || len(blast.Broad) != 0 || len(blast.Reaches) != 1 {
		t.Errorf("blast = %+v, want the witnessed pair and no broad rule", out.Blast)
	}
	// An ssh expectation's broad ssh rule is no network grant either.
	sshIntent := `{"sshTests": [{"src": "tag:example-web", "dst": ["tag:example-db"], "deny": ["root"]}]}`
	m2 := &policyModel{sshAllow: map[string]bool{"tag:example-web|tag:example-db|root": true}}
	_, env2 := explainEnv(t, policy, m2)
	out2, err := explainOnce(t, env2, sshIntent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(reportText(out2), "policy grants this source all destinations") {
		t.Errorf("an ssh rule is said to grant all destinations:\n%s", reportText(out2))
	}
	if c := rowOf(out2, "ssh-1").Candidates; len(c) != 1 || !c[0].Broad || c[0].Qualified {
		t.Errorf("ssh candidates = %+v, want the one broad ssh rule", c)
	}
}

// Owning a tag is not holding its rules: a rule whose source is a tag the user owns is no
// candidate for the user, and the blast radius says the user could apply the tag.
func TestTagOwnershipIsNotUserAccess(t *testing.T) {
	policy := `{
	"groups": {"group:example-admins": ["alice@example.com"]},
	"tagOwners": {"tag:example-x": ["alice@example.com"], "tag:example-y": ["group:example-admins"]},
	"acls": [
		{"action": "accept", "src": ["tag:example-x"], "dst": ["tag:example-db:5432"]},
		{"action": "accept", "src": ["alice@example.com"], "dst": ["tag:example-web:80"]},
		{"action": "accept", "src": ["group:example-admins"], "dst": ["tag:example-db:5432"]},
	],
}`
	t.Run("a user", func(t *testing.T) {
		intent := `{"tests": [{"src": "alice@example.com", "accept": ["tag:example-db:5432"]}]}`
		m := &policyModel{allow: map[string]bool{"alice@example.com|tag:example-db:5432": true}}
		_, env := explainEnv(t, policy, m)
		env.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}} // the login is read as written
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		row := rowOf(out, "network-1")
		for _, c := range row.Candidates {
			if c.Index == 1 || c.Source == "tag:example-x" {
				t.Errorf("a rule of a tag the user owns is a candidate: %+v", c)
			}
		}
		if len(row.Candidates) != 1 || row.Candidates[0].Index != 3 || row.Candidates[0].Source != "group:example-admins" {
			t.Errorf("candidates = %+v, want the group's rule, which lists the user", row.Candidates)
		}
		blast := blastOf(out, "alice@example.com")
		if blast == nil || strings.Join(blast.Tags, ",") != "tag:example-x,tag:example-y" {
			t.Fatalf("blast = %+v, want the tags the user can apply", out.Blast)
		}
		if !strings.Contains(reportText(out), "assumption: can apply tag:example-x (tagOwners), whose rules would then apply") {
			t.Errorf("the ownership assumption is not stated:\n%s", reportText(out))
		}
	})
	t.Run("a tag source takes its own rules", func(t *testing.T) {
		intent := `{"tests": [{"src": "tag:example-x", "accept": ["tag:example-db:5432"]}]}`
		m := &policyModel{allow: map[string]bool{"tag:example-x|tag:example-db:5432": true}}
		_, env := explainEnv(t, policy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		if c := rowOf(out, "network-1").Candidates; len(c) != 1 || c[0].Index != 1 {
			t.Errorf("candidates = %+v", c)
		}
	})
}

// An SSH verdict says nothing of the network, and the reverse: one run holds a network deny that
// is met and an ssh accept that is met, then each the other way round, and no verdict follows
// the other. The candidates of an SSH expectation are rules of ssh, and a network expectation's
// are rules of acls and grants.
func TestSSHAcceptanceIsNotNetworkReachability(t *testing.T) {
	t.Run("ssh accepted while the network denies", func(t *testing.T) {
		m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{"group:example-admins|tag:example-db|root": true}}
		f, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, adminSSHIntent)
		if err != nil {
			t.Fatal(err)
		}
		if rowOf(out, "network-1").Status != "met" || rowOf(out, "ssh-1").Status != "met" || out.ExitCode() != 0 {
			t.Fatalf("%+v", out.Counts)
		}
		if got := posts(f); got != 2 {
			t.Errorf("%d requests, want two: one for the network tests and one for the SSH tests", got)
		}
		if strings.Count(strings.Join(out.Notes, "|"), "SSH and network access are separate questions") != 1 {
			t.Errorf("notes = %q, want the separation said once", out.Notes)
		}
		ssh := rowOf(out, "ssh-1")
		if len(ssh.Candidates) != 1 || ssh.Candidates[0].Section != "ssh" {
			t.Errorf("ssh candidates = %+v, want the ssh rule only", ssh.Candidates)
		}
		if c := rowOf(out, "network-1").Candidates; len(c) != 0 {
			t.Errorf("a network deny of a tag that no rule gives the database has candidates: %+v", c)
		}
	})
	t.Run("the network accepts while ssh is denied: each verdict is its own", func(t *testing.T) {
		intent := `{
	"tests": [{"src": "group:example-admins", "accept": ["tag:example-db:22"]}],
	"sshTests": [{"src": "group:example-admins", "dst": ["tag:example-db"], "deny": ["root"]}],
}`
		m := &policyModel{allow: map[string]bool{"group:example-admins|tag:example-db:22": true}, sshAllow: map[string]bool{}}
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		if rowOf(out, "network-1").Status != "met" || rowOf(out, "ssh-1").Status != "met" {
			t.Fatalf("%+v", out.Counts)
		}
		// The ssh pair is denied and the network pair is allowed: opposite observations, both met.
		if rowOf(out, "network-1").Cells[0].Observed != "allowed" || rowOf(out, "ssh-1").Cells[0].Observed != "denied" {
			t.Errorf("observed: network %+v, ssh %+v", rowOf(out, "network-1").Cells[0], rowOf(out, "ssh-1").Cells[0])
		}
		// The rule that could account for each is of its own section: the ssh rule is not cited
		// for the network question, though its source and destination match.
		if c := rowOf(out, "network-1").Candidates; len(c) != 1 || c[0].Section != "acls" {
			t.Errorf("network candidates = %+v, want the acls rule only", c)
		}
		if c := rowOf(out, "ssh-1").Candidates; len(c) != 1 || c[0].Section != "ssh" {
			t.Errorf("ssh candidates = %+v, want the ssh rule only", c)
		}
	})
	t.Run("an ssh failure does not make the network unmet", func(t *testing.T) {
		m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{}}
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, adminSSHIntent)
		if err != nil {
			t.Fatal(err)
		}
		if rowOf(out, "network-1").Status != "met" || rowOf(out, "ssh-1").Status != "unmet" || out.ExitCode() != 8 {
			t.Errorf("%+v exit %d", out.Counts, out.ExitCode())
		}
	})
}

// Posture, app capabilities and via are not guessed: an expectation that is met while the live
// policy has a rule that carries one (and is not shown to be about other destinations) is met with
// limits, with the fixed sentence, and the run exits 1, never 0. These rules also match the
// expectation as candidates; TestAPostureGrantTheCandidateMatcherCannotSeeIsStillALimit has the ones
// the candidate matcher cannot match, which count the same.
func TestPostureAndAppCapabilitiesAreNotGuessed(t *testing.T) {
	base := func(rule string, extra string) string {
		return `{"acls": [], "grants": [` + rule + `], ` + extra + `}`
	}
	intent := `{"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}]}`
	cases := []struct {
		name, policy string
		limit        string
		sentence     string
	}{
		{"a candidate rule gated on posture",
			`{"acls": [{"action": "accept", "src": ["tag:example-web"], "dst": ["tag:example-db:22"], "srcPosture": ["posture:example"]}], "postures": {"posture:example": ["node:os == 'linux'"]}}`,
			"posture", "depends on device posture"},
		{"a policy with a default posture", `{"acls": [{"action": "accept", "src": ["tag:example-web"], "dst": ["tag:example-web:80"]}], "defaultSrcPosture": ["posture:example"], "postures": {"posture:example": ["node:os == 'linux'"]}}`,
			"posture", "depends on device posture"},
		{"a candidate grant with app capabilities",
			base(`{"src": ["tag:example-web"], "dst": ["tag:example-db"], "app": {"example.com/cap": [{"x": 1}]}}`, `"tagOwners": {}`),
			"app", "app capabilities"},
		{"a candidate grant with via",
			base(`{"src": ["tag:example-web"], "dst": ["tag:example-db"], "ip": ["22"], "via": ["tag:example-exit"]}`, `"tagOwners": {}`),
			"via", "routes through via"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &policyModel{allow: map[string]bool{}}
			_, env := explainEnv(t, c.policy, m)
			out, err := explainOnce(t, env, intent)
			if err != nil {
				t.Fatal(err)
			}
			row := rowOf(out, "network-1")
			if row.Status != "met_with_limits" || len(row.Limits) != 1 || row.Limits[0] != c.limit {
				t.Fatalf("status %s limits %v, want met_with_limits and %s", row.Status, row.Limits, c.limit)
			}
			if out.ExitCode() != 1 || out.Status != "incomplete" || out.Counts.MetWithLimits != 1 {
				t.Errorf("exit %d status %s counts %+v, want exit 1, incomplete", out.ExitCode(), out.Status, out.Counts)
			}
			if !strings.Contains(reportText(out), c.sentence) {
				t.Errorf("the fixed sentence is not stated:\n%s", reportText(out))
			}
		})
	}
	t.Run("the attributes the expectation gives remove the posture limit and travel in the test", func(t *testing.T) {
		policy := `{"acls": [{"action": "accept", "src": ["tag:example-web"], "dst": ["tag:example-db:22"], "srcPosture": ["posture:example"]}], "postures": {"posture:example": ["node:os == 'linux'"]}}`
		withAttrs := `{"tests": [{"src": "tag:example-web", "srcPostureAttrs": {"node:os": "linux"}, "accept": ["tag:example-db:22"]}]}`
		m := &policyModel{allow: map[string]bool{"tag:example-web|tag:example-db:22": true}}
		_, env := explainEnv(t, policy, m)
		out, err := explainOnce(t, env, withAttrs)
		if err != nil {
			t.Fatal(err)
		}
		if row := rowOf(out, "network-1"); row.Status != "met" || len(row.Limits) != 0 || out.ExitCode() != 0 {
			t.Errorf("status %s limits %v exit %d, want met with no limit", row.Status, row.Limits, out.ExitCode())
		}
		sent := m.sentTexts(t)
		if len(sent) != 1 || sent[0].Tests[0].Attrs == nil {
			t.Errorf("the posture attributes did not travel in the test: %+v", sent)
		}
	})
	t.Run("a source the test language cannot name", func(t *testing.T) {
		m := &policyModel{allow: map[string]bool{"autogroup:admin|tag:example-db:22": true}}
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, `{"tests": [{"src": "autogroup:admin", "accept": ["tag:example-db:22"]}]}`)
		if err != nil {
			t.Fatal(err)
		}
		if row := rowOf(out, "network-1"); row.Status != "met_with_limits" || len(row.Limits) != 1 || row.Limits[0] != "source" || out.ExitCode() != 1 {
			t.Errorf("%+v exit %d", row, out.ExitCode())
		}
	})
}

// A rule that the candidate matcher cannot see is still a limit: the limits do not depend on the
// candidate lists. A member's login is denied by the validation (the synthetic device reports no
// posture), and a posture-compliant device of the member would reach the database: the answer is
// not met, and the run is not complete.
func TestAPostureGrantTheCandidateMatcherCannotSeeIsStillALimit(t *testing.T) {
	denyMember := `{"tests": [{"src": "bob@example.com", "deny": ["tag:example-db:22"]}]}`
	cases := []struct {
		name, policy, intent string
		limit                string
	}{
		{"srcPosture on a grant for autogroup:member",
			`{"grants": [{"src": ["autogroup:member"], "srcPosture": ["posture:compliant"], "dst": ["tag:example-db"], "ip": ["*"]}], "postures": {"posture:compliant": ["node:os == 'linux'"]}}`,
			denyMember, "posture"},
		{"app capabilities on a grant for a localpart source",
			`{"grants": [{"src": ["localpart:*@example.com"], "dst": ["tag:example-db"], "app": {"example.com/cap": [{"x": 1}]}}]}`,
			denyMember, "app"},
		{"via on a grant for autogroup:member",
			`{"grants": [{"src": ["autogroup:member"], "dst": ["tag:example-db"], "ip": ["22"], "via": ["tag:example-exit"]}]}`,
			denyMember, "via"},
		{"srcPosture on an acl for another tag at the same port",
			`{"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:example-web:22"], "srcPosture": ["posture:compliant"]}], "postures": {"posture:compliant": ["node:os == 'linux'"]}}`,
			denyMember, "posture"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, env := explainEnv(t, c.policy, &policyModel{allow: map[string]bool{}})
			env.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
			out, err := explainOnce(t, env, c.intent)
			if err != nil {
				t.Fatal(err)
			}
			row := rowOf(out, "network-1")
			if row.Status != "met_with_limits" || len(row.Limits) != 1 || row.Limits[0] != c.limit || len(row.Candidates) != 0 {
				t.Fatalf("status %s limits %v candidates %v, want met_with_limits by %s with no candidate listed", row.Status, row.Limits, row.Candidates, c.limit)
			}
			if out.Counts.Met != 0 || out.ExitCode() != 1 || out.Status != "incomplete" {
				t.Errorf("counts %+v exit %d status %s: not met, and not exit 0", out.Counts, out.ExitCode(), out.Status)
			}
		})
	}
	t.Run("a rule about other destinations is no limit", func(t *testing.T) {
		policy := `{"acls": [
			{"action": "accept", "src": ["autogroup:member"], "dst": ["198.51.100.0/24:22"], "srcPosture": ["posture:compliant"]},
			{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:example-web:443"], "srcPosture": ["posture:compliant"]},
		], "postures": {"posture:compliant": ["node:os == 'linux'"]}}`
		intent := `{"tests": [{"src": "bob@example.com", "deny": ["192.0.2.5:22"]}]}`
		_, env := explainEnv(t, policy, &policyModel{allow: map[string]bool{}})
		env.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		if row := rowOf(out, "network-1"); row.Status != "met" || len(row.Limits) != 0 || out.ExitCode() != 0 {
			t.Errorf("status %s limits %v exit %d, want met: both rules are shown to be about other destinations", row.Status, row.Limits, out.ExitCode())
		}
	})
	t.Run("rules past the cap of the reader cannot be ruled out", func(t *testing.T) {
		var rules strings.Builder
		for i := 0; i < 4097; i++ {
			fmt.Fprintf(&rules, `{"action": "accept", "src": ["tag:example-web"], "dst": ["tag:example-web:%d"]},`, 1+i%60000)
		}
		policy := `{"acls": [` + rules.String() + `]}`
		intent := `{"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}]}`
		_, env := explainEnv(t, policy, &policyModel{allow: map[string]bool{}})
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		if row := rowOf(out, "network-1"); row.Status != "met_with_limits" || len(row.Limits) != 1 || row.Limits[0] != "rules" || out.ExitCode() != 1 {
			t.Errorf("status %s limits %v exit %d, want met_with_limits by rules", row.Status, row.Limits, out.ExitCode())
		}
		if !strings.Contains(reportText(out), "could not be listed or read here") {
			t.Errorf("the fixed sentence of the limit is not stated:\n%s", reportText(out))
		}
	})
	t.Run("a rule that cannot be read cannot be ruled out", func(t *testing.T) {
		policy := `{"acls": [{"action": "accept", "src": ["tag:example-web"], "dst": ["tag:example-web:443"]}, "not a rule"]}`
		intent := `{"tests": [{"src": "tag:example-web", "deny": ["tag:example-db:22"]}]}`
		_, env := explainEnv(t, policy, &policyModel{allow: map[string]bool{}})
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		if row := rowOf(out, "network-1"); row.Status != "met_with_limits" || len(row.Limits) != 1 || row.Limits[0] != "rules" {
			t.Errorf("status %s limits %v, want met_with_limits by rules", row.Status, row.Limits)
		}
	})
}

// A canary that is missing, unevaluable or doubled, a policy that moved while it was checked,
// a line nobody can read, a limit and a cancelled call: each leaves the pair unknown, never met.
func TestAccessUnknownOnMissingCanaryOrChangedPolicy(t *testing.T) {
	cases := []struct {
		name   string
		model  func() *policyModel
		reason string
		mod    func(*testing.T, *apitest.Fake, *liveRoute)
	}{
		{"a missing canary", func() *policyModel { m := adminModel(); m.omitCanary = true; return m }, "canary", nil},
		{"an unevaluable canary", func() *policyModel { m := adminModel(); m.canaryUnevaluable = true; return m }, "canary", nil},
		{"the canary twice", func() *policyModel { m := adminModel(); m.canaryTwice = true; return m }, "canary", nil},
		{"a text Tailscale refuses", func() *policyModel { m := adminModel(); m.refuse = "json: unknown field \"nodeAttr\""; return m }, "refused", nil},
		{"a line nobody can pair", func() *policyModel {
			m := adminModel()
			m.extraLine = func(string) []string { return []string{"[acl test error]: something nobody has seen before"} }
			return m
		}, "unresolved", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, env := explainEnv(t, explainPolicy, c.model())
			out, err := explainOnce(t, env, adminIntent)
			if err != nil {
				t.Fatal(err)
			}
			if out.Counts.Met != 0 || out.ExitCode() != 1 {
				t.Fatalf("%+v exit %d, want nothing met and exit 1", out.Counts, out.ExitCode())
			}
			for _, row := range out.Expectations {
				for _, cell := range row.Cells {
					if cell.Verdict != "unknown" || cell.Reason != c.reason {
						t.Errorf("%s: %+v, want unknown by %s", row.ID, cell, c.reason)
					}
				}
			}
		})
	}
	t.Run("the live policy changed while it was checked", func(t *testing.T) {
		m := adminModel()
		f, _, env := apiEnv(t)
		route := serveExplain(f, explainPolicy, m)
		m.after = func(int) { route.set(explainPolicy + "\n// moved\n") }
		out, err := explainOnce(t, env, adminIntent)
		if err != nil {
			t.Fatal(err)
		}
		if out.Counts.Met != 0 || out.ExitCode() != 1 {
			t.Fatalf("%+v exit %d", out.Counts, out.ExitCode())
		}
		for _, row := range out.Expectations {
			if c := row.Cells[0]; c.Verdict != "unknown" || c.Reason != "live_changed" || c.LiveUnchanged || !c.Canary {
				t.Errorf("%s: %+v", row.ID, c)
			}
		}
		for _, b := range out.Blast {
			if len(b.Reaches) != 0 {
				t.Errorf("blast = %+v: nothing is said to be reachable by a policy that moved", b)
			}
		}
	})
	t.Run("a rate limit", func(t *testing.T) {
		m := adminModel()
		f := apitest.New(t)
		serveExplain(f, explainPolicy, m)
		env := limitedEnv(t, f, 1)
		// A run that asks only network tests takes one token: two runs fit the bucket, whole.
		for i := 0; i < 2; i++ {
			first, err := explainOnce(t, env, adminIntent)
			if err != nil || first.Counts.Met != 2 {
				t.Fatalf("run %d: %+v, %v; the bucket holds two tokens", i+1, first.Counts, err)
			}
		}
		out, err := explainOnce(t, env, adminIntent)
		if err != nil {
			t.Fatalf("a rate limit is an unknown answer, not an error: %v", err)
		}
		if out.Counts.Met != 0 || out.Counts.Unknown != 2 || out.ExitCode() != 1 || rowOf(out, "network-1").Cells[0].Reason != "rate_limited" {
			t.Errorf("%+v exit %d reason %v", out.Counts, out.ExitCode(), cellReasons(rowOf(out, "network-1")))
		}
	})
	t.Run("a cancelled call", func(t *testing.T) {
		m := adminModel()
		f, _, env := apiEnv(t)
		serveExplain(f, explainPolicy, m)
		ctx, cancel := context.WithCancel(context.Background())
		m.after = func(int) { cancel() }
		out, err := explainCtx(ctx, t, env, adminSSHIntent)
		if err != nil {
			t.Fatalf("a cancelled validation is an unknown answer, not an error: %v", err)
		}
		if out.Counts.Met != 0 || out.ExitCode() != 1 {
			t.Errorf("%+v exit %d, want nothing met and exit 1", out.Counts, out.ExitCode())
		}
	})
	t.Run("an unmet expectation beside an unknown one is still 8", func(t *testing.T) {
		// The network request is proven and fails a pair; the SSH request has no SSH canary.
		m := &policyModel{allow: map[string]bool{"tag:example-web|tag:example-db:22": true}, sshAllow: map[string]bool{"group:example-admins|tag:example-db|root": true}, omitSSHCanary: true}
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, adminSSHIntent)
		if err != nil {
			t.Fatal(err)
		}
		if rowOf(out, "network-1").Status != "unmet" || rowOf(out, "ssh-1").Status != "unknown" || rowOf(out, "ssh-1").Cells[0].Reason != "canary" || out.ExitCode() != 8 {
			t.Errorf("%+v exit %d", out.Counts, out.ExitCode())
		}
	})
}

// A large tailnet changes nothing about what is asked: the request carries the expectation's own
// pairs and the canary, the devices and users are never read, and the pairs past the cap are not
// evaluated, counted, and not met.
func TestBoundedTargetsNoAllPairsExpansion(t *testing.T) {
	f := apitest.New(t)
	m := &policyModel{allow: map[string]bool{}}
	serveExplain(f, explainPolicy, m)
	var devs, users []string
	for i := 0; i < 500; i++ {
		devs = append(devs, fmt.Sprintf(`{"nodeId":"nDEV%03dCNTRL","name":"host-%d.example.com"}`, i, i))
		users = append(users, fmt.Sprintf(`{"loginName":"user%d@example.com"}`, i))
	}
	f.JSON("GET", tailnetPath+"/devices", 200, `{"devices":[`+strings.Join(devs, ",")+`]}`)
	f.JSON("GET", tailnetPath+"/users", 200, `{"users":[`+strings.Join(users, ",")+`]}`)
	env := &registry.Env{API: f.Client(t), Now: func() time.Time { return now }}
	var dsts []string
	for i := 0; i < 100; i++ {
		dsts = append(dsts, fmt.Sprintf("%q", fmt.Sprintf("192.0.2.%d:22", i)))
		m.allow[fmt.Sprintf("tag:example-a|192.0.2.%d:22", i)] = true
	}
	// A second expectation, of another source, comes after the 64th pair: it is left out whole.
	intent := `{"tests": [{"src": "tag:example-a", "accept": [` + strings.Join(dsts, ",") + `]}, {"src": "tag:example-b", "accept": ["192.0.2.200:22"]}]}`
	out, err := explainOnce(t, env, intent)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range f.Requests() {
		if strings.HasSuffix(r.Path, "/devices") || strings.HasSuffix(r.Path, "/users") {
			t.Errorf("a request for %s: the explanation named a source or a destination by enumerating the tailnet", r.Path)
		}
	}
	sent := m.sentTexts(t)
	if len(sent) != 1 || len(sent[0].Tests) != 2 {
		t.Fatalf("%d requests, tests %+v; want one request with the expectation's test and the canary", len(sent), sent)
	}
	one := sent[0].Tests[0]
	if one.Src != "tag:example-a" || len(one.Accept) != 64 || len(one.Deny) != 0 {
		t.Fatalf("the test = %+v, want the source and 64 of its destinations", one)
	}
	for i, d := range one.Accept {
		if d != fmt.Sprintf("192.0.2.%d:22", i) {
			t.Fatalf("destination %d is %s: a destination the expectation did not list, or out of order", i, d)
		}
	}
	row := rowOf(out, "network-1")
	if out.PairsJudged != 64 || out.PairsPastCap != 37 || row.PastCap != 36 || row.Status != "not_evaluated" || out.ExitCode() != 1 {
		t.Errorf("judged %d past %d status %s exit %d", out.PairsJudged, out.PairsPastCap, row.Status, out.ExitCode())
	}
	if other := rowOf(out, "network-2"); other.Status != "not_evaluated" || other.PastCap != 1 || len(other.Cells) != 0 {
		t.Errorf("the expectation after the cap: %+v", other)
	}
	if len(row.Cells) != 64 {
		t.Errorf("%d pairs listed, want the 64 judged", len(row.Cells))
	}
	if !strings.Contains(reportText(out), "network-1 · 36 pairs not evaluated") || !strings.Contains(reportText(out), "37 pairs past the limit of 64") {
		t.Errorf("the count past the cap is not said:\n%s", reportText(out))
	}
}

// Two expectations of one source with the same terms share a test; a second set of terms is not
// asked, and its pairs are not evaluated, with the reason.
func TestTheProtocolOfAnExpectationTravelsInItsTest(t *testing.T) {
	intent := `{"tests": [{"src": "tag:example-a", "proto": "tcp", "accept": ["tag:example-db:22"]}]}`
	m := &policyModel{allow: map[string]bool{"tag:example-a|tag:example-db:22": true}}
	_, env := explainEnv(t, explainPolicy, m)
	out, err := explainOnce(t, env, intent)
	if err != nil || out.Counts.Met != 1 {
		t.Fatalf("%+v, %v", out.Counts, err)
	}
	if sent := m.sentTexts(t); len(sent) != 1 || sent[0].Tests[0].Proto != "tcp" {
		t.Errorf("sent = %+v, want the protocol in the test", sent)
	}
}

func TestSameSourceOtherTermsIsNotAsked(t *testing.T) {
	intent := `{"tests": [
		{"src": "tag:example-a", "accept": ["tag:example-db:22"]},
		{"src": "tag:example-a", "accept": ["tag:example-db:443"]},
		{"src": "tag:example-a", "proto": "udp", "accept": ["tag:example-db:53"]},
	]}`
	m := &policyModel{allow: map[string]bool{"tag:example-a|tag:example-db:22": true, "tag:example-a|tag:example-db:443": true}}
	_, env := explainEnv(t, explainPolicy, m)
	out, err := explainOnce(t, env, intent)
	if err != nil {
		t.Fatal(err)
	}
	sent := m.sentTexts(t)
	if len(sent) != 1 || len(sent[0].Tests) != 2 || strings.Join(sent[0].Tests[0].Accept, ",") != "tag:example-db:22,tag:example-db:443" {
		t.Fatalf("sent = %+v, want one test for the source holding both destinations", sent)
	}
	third := rowOf(out, "network-3")
	if rowOf(out, "network-1").Status != "met" || rowOf(out, "network-2").Status != "met" || third.Status != "not_evaluated" || third.Cells[0].Reason != "same_source" || out.ExitCode() != 1 {
		t.Errorf("%+v / %+v", out.Counts, third.Cells)
	}
}

func TestExplainNoIntentSetIsIncomplete(t *testing.T) {
	f, _, env := apiEnv(t)
	out, err := explainOnce(t, env, "")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "incomplete" || out.ExitCode() != 1 || len(out.Notes) != 1 || out.Notes[0] != "no intent set: nothing explained" || out.Intent.Source != "none" || len(out.Expectations) != 0 {
		t.Errorf("%+v", out)
	}
	if got := len(f.Requests()); got != 0 {
		t.Errorf("%d requests: with no intent there is nothing to ask", got)
	}
	if !strings.Contains(out.Report().Verdict, "no intent set: nothing explained") {
		t.Errorf("verdict = %q", out.Report().Verdict)
	}
	t.Run("a file with no test is an empty set, with its own sentence", func(t *testing.T) {
		out, err := explainOnce(t, env, `{"tests": []}`)
		if err != nil || out.ExitCode() != 1 || len(out.Notes) != 1 || !strings.Contains(out.Notes[0], "holds no expectations") {
			t.Errorf("%+v, %v", out, err)
		}
	})
	t.Run("--only with no set is a usage error", func(t *testing.T) {
		_, err := explainOnce(t, env, "", func(in *tools.SecurityExplainInput) { in.Only = []string{"network-1"} })
		if code(err) != tkerr.ValidationFailed || tkerr.ExitCode(err) != 2 {
			t.Errorf("err = %v", err)
		}
	})
}

func TestExplainOnlyUnknownIDIsUsageError(t *testing.T) {
	f, env := explainEnv(t, explainPolicy, adminModel())
	_, err := explainOnce(t, env, adminIntent, func(in *tools.SecurityExplainInput) { in.Only = []string{"network-9"} })
	if code(err) != tkerr.ValidationFailed || tkerr.ExitCode(err) != 2 {
		t.Fatalf("err = %v, want validation_failed and exit 2", err)
	}
	if !strings.Contains(err.Error(), "network-1 to network-2") || strings.Contains(err.Error(), "network-9") {
		t.Errorf("the refusal %q must name the IDs the set holds and not repeat what was typed", err)
	}
	if len(f.Requests()) != 0 {
		t.Errorf("%d requests: a usage error asks nothing", len(f.Requests()))
	}
	for _, bad := range []string{"", "network-0", "net-1", "ssh-", "network-1;ssh-2", "NETWORK-1", "network-1 ", "../x"} {
		if bad == "network-1 " {
			continue // trimmed: a space around an ID is not a different ID
		}
		_, err := explainOnce(t, env, adminIntent, func(in *tools.SecurityExplainInput) { in.Only = []string{bad} })
		if code(err) != tkerr.ValidationFailed || !strings.Contains(err.Error(), "--only takes expectation IDs") {
			t.Errorf("--only %q: err = %v, want validation_failed that says what an ID is", bad, err)
		}
	}
	t.Run("a known ID selects, in the file's order, and comma lists work", func(t *testing.T) {
		m := adminModel()
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, adminIntent, func(in *tools.SecurityExplainInput) { in.Only = []string{"network-2,network-1", "network-2"} })
		if err != nil || out.Counts.Total != 2 {
			t.Fatalf("%+v, %v", out.Counts, err)
		}
		_, env = explainEnv(t, explainPolicy, adminModel())
		out, err = explainOnce(t, env, adminIntent, func(in *tools.SecurityExplainInput) { in.Only = []string{"network-2"} })
		if err != nil || out.Counts.Total != 1 || out.Intent.Selected != 1 || out.Intent.Expectations != 2 || out.Expectations[0].ID != "network-2" {
			t.Fatalf("%+v, %v", out, err)
		}
		if got := len(m.sentTexts(t)[0].Tests); got != 3 {
			t.Errorf("%d tests in the first request", got)
		}
	})
}

func TestExplainConfiguredUnreadableIsConfigInvalid(t *testing.T) {
	f, _, env := apiEnv(t)
	serveExplain(f, explainPolicy, adminModel())
	env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: "/no/such/file.hujson"}}}
	_, err := explainOnce(t, env, "")
	if code(err) != tkerr.ConfigInvalid || tkerr.ExitCode(err) != 6 {
		t.Fatalf("err = %v, want config_invalid and exit 6", err)
	}
	if len(f.Requests()) != 0 {
		t.Errorf("%d requests: a configured file that cannot be read is not no intent", len(f.Requests()))
	}
	t.Run("a configured file that is readable is the intent", func(t *testing.T) {
		f, _, env := apiEnv(t)
		serveExplain(f, explainPolicy, adminModel())
		env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: intentPath(t, adminIntent)}}}
		out, err := explainOnce(t, env, "")
		if err != nil || out.Counts.Met != 2 || out.Intent.Source != "configured" {
			t.Errorf("%+v, %v", out, err)
		}
	})
	t.Run("a file the operator did not name is refused", func(t *testing.T) {
		_, env := explainEnv(t, explainPolicy, adminModel())
		_, err := explainOnce(t, env, adminIntent, func(in *tools.SecurityExplainInput) { in.Operator = false })
		if code(err) != tkerr.ValidationFailed {
			t.Errorf("err = %v", err)
		}
	})
}

// The exit codes of the output, 0, 8 and 1, with 8 over 1.
func TestExplainExitCodes(t *testing.T) {
	out := func(status string, c tools.SecurityExplainCounts) tools.SecurityExplainOutput {
		return tools.SecurityExplainOutput{Status: status, Counts: c}
	}
	cases := []struct {
		name string
		o    tools.SecurityExplainOutput
		want int
	}{
		{"all met", out("complete", tools.SecurityExplainCounts{Total: 3, Met: 3}), 0},
		{"one unknown", out("incomplete", tools.SecurityExplainCounts{Total: 3, Met: 2, Unknown: 1}), 1},
		{"one met with limits", out("incomplete", tools.SecurityExplainCounts{Total: 3, Met: 2, MetWithLimits: 1}), 1},
		{"one not evaluated", out("incomplete", tools.SecurityExplainCounts{Total: 3, Met: 2, NotEvaluated: 1}), 1},
		{"no intent", out("incomplete", tools.SecurityExplainCounts{}), 1},
		{"one unmet", out("incomplete", tools.SecurityExplainCounts{Total: 3, Met: 2, Unmet: 1}), 8},
		{"unmet and unknown: 8 over 1", out("incomplete", tools.SecurityExplainCounts{Total: 3, Unmet: 1, Unknown: 2}), 8},
		{"a status that is not complete is 1", out("", tools.SecurityExplainCounts{Total: 1, Met: 1}), 1},
	}
	for _, c := range cases {
		if got := c.o.ExitCode(); got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
}

// Through the whole path: the same fixtures give 0, 8 and 1.
func TestExplainExitCodesEndToEnd(t *testing.T) {
	for _, c := range []struct {
		name  string
		model func() *policyModel
		want  int
	}{
		{"met", adminModel, 0},
		{"unmet", func() *policyModel { m := adminModel(); m.allow["tag:example-web|tag:example-db:22"] = true; return m }, 8},
		{"unknown", func() *policyModel { m := adminModel(); m.omitCanary = true; return m }, 1},
	} {
		_, env := explainEnv(t, explainPolicy, c.model())
		out, err := explainOnce(t, env, adminIntent)
		if err != nil || out.ExitCode() != c.want {
			t.Errorf("%s: exit %d, %v; want %d", c.name, out.ExitCode(), err, c.want)
		}
	}
}

// What is asked is only what the expectations list: no all-pairs, no widening of a source by a
// group or a tag it belongs to.
func TestExplainAsksOnlyTheListedPairs(t *testing.T) {
	m := adminModel()
	_, env := explainEnv(t, explainPolicy, m)
	if _, err := explainOnce(t, env, adminSSHIntent); err != nil {
		t.Fatal(err)
	}
	texts := m.sentTexts(t)
	if len(texts) != 2 {
		t.Fatalf("%d requests", len(texts))
	}
	net, ssh := texts[0], texts[1]
	if len(net.Tests) != 2 || net.Tests[0].Src != "tag:example-web" || strings.Join(net.Tests[0].Deny, ",") != "tag:example-db:22" || len(net.Tests[0].Accept) != 0 || len(net.SSHTests) != 0 {
		t.Errorf("the network request = %+v", net)
	}
	if len(ssh.Tests) != 1 || len(ssh.SSHTests) != 2 || ssh.SSHTests[0].Src != "group:example-admins" ||
		strings.Join(ssh.SSHTests[0].Dst, ",") != "tag:example-db" || strings.Join(ssh.SSHTests[0].Accept, ",") != "root" {
		t.Errorf("the ssh request = %+v", ssh)
	}
}

// The tool runs at the command line only: it is an owner tool of the registry, not one of
// Register.
func TestExplainIsAnOwnerToolAndNotInTheSharedRegistry(t *testing.T) {
	shared := registry.New()
	tools.Register(shared)
	if _, ok := shared.Get("security_explain"); ok {
		t.Fatal("security_explain is in the registry every surface is built from")
	}
	owner := registry.New()
	tools.RegisterOwnerOnly(owner)
	tl, ok := owner.Get("security_explain")
	if !ok || tl.Meta.Area != "security" || tl.Meta.Verb != "explain" {
		t.Fatalf("the owner registry = %v", ok)
	}
	var schema map[string]any
	b, _ := json.Marshal(tl.InputSchema)
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	props, _ := schema["properties"].(map[string]any)
	if len(props) != 1 || props["only"] == nil {
		t.Errorf("input properties = %v, want only the selection: the file and the operator mark are not in the schema", props)
	}
}

// SSH pairs are read one by one: an accepted user the policy lets in is met, a denied one it lets
// in is unmet, and a check user is never met.
func TestExplainSSHPairs(t *testing.T) {
	intent := `{"sshTests": [{"src": "group:example-admins", "dst": ["tag:example-db"], "accept": ["root"], "deny": ["deploy"], "check": ["ops"]}]}`
	t.Run("a denied user the policy lets in is unmet", func(t *testing.T) {
		m := &policyModel{sshAllow: map[string]bool{"group:example-admins|tag:example-db|root": true, "group:example-admins|tag:example-db|deploy": true}}
		f, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		row := rowOf(out, "ssh-1")
		verdicts := map[string]string{}
		for _, c := range row.Cells {
			verdicts[c.Expect+" "+c.User] = c.Verdict + "/" + c.Reason
		}
		want := map[string]string{"accept root": "met/", "deny deploy": "unmet/", "check ops": "unknown/check_user"}
		if !reflect.DeepEqual(verdicts, want) || row.Status != "unmet" || out.ExitCode() != 8 {
			t.Errorf("verdicts %v status %s exit %d, want %v", verdicts, row.Status, out.ExitCode(), want)
		}
		if got := posts(f); got != 1 {
			t.Errorf("%d requests: only SSH tests were asked", got)
		}
		reach := blastOf(out, "group:example-admins")
		if reach == nil || len(reach.Reaches) != 2 {
			t.Errorf("blast = %+v, want the two users the policy lets in", out.Blast)
		}
	})
	t.Run("a check user keeps the expectation short of met", func(t *testing.T) {
		m := &policyModel{sshAllow: map[string]bool{"group:example-admins|tag:example-db|root": true}}
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		if row := rowOf(out, "ssh-1"); row.Status != "unknown" || out.ExitCode() != 1 {
			t.Errorf("status %s exit %d", row.Status, out.ExitCode())
		}
	})
	t.Run("one entry for each user and list, however many destinations", func(t *testing.T) {
		two := `{"sshTests": [{"src": "tag:example-ci", "dst": ["tag:example-a", "tag:example-b"], "accept": ["deploy"]}]}`
		m := &policyModel{sshAllow: map[string]bool{"tag:example-ci|tag:example-a|deploy": true}}
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, two)
		if err != nil {
			t.Fatal(err)
		}
		verdicts := map[string]string{}
		for _, c := range rowOf(out, "ssh-1").Cells {
			verdicts[c.Destination] = c.Verdict
		}
		if verdicts["tag:example-a"] != "met" || verdicts["tag:example-b"] != "unmet" {
			t.Errorf("verdicts = %v", verdicts)
		}
		sent := m.sentTexts(t)
		if len(sent[0].SSHTests) != 2 || strings.Join(sent[0].SSHTests[0].Dst, ",") != "tag:example-a,tag:example-b" {
			t.Errorf("sent = %+v", sent[0].SSHTests)
		}
	})
}

// A line for a source nobody asked about is not about any pair of the request, and no pair is
// read from a reply that holds one.
func TestAForeignLineLeavesEveryPairUnknown(t *testing.T) {
	m := adminModel()
	m.foreign = []apitest.Entry{{User: "tag:example-stranger", Errors: []string{`[acl test error]: address "tag:example-db:22": want: Drop, got: Accept`}}}
	_, env := explainEnv(t, explainPolicy, m)
	out, err := explainOnce(t, env, adminIntent)
	if err != nil {
		t.Fatal(err)
	}
	if out.Counts.Met != 0 || out.Counts.Unknown != 2 || out.ExitCode() != 1 || rowOf(out, "network-1").Cells[0].Reason != "unpaired_line" {
		t.Errorf("%+v exit %d reason %v", out.Counts, out.ExitCode(), cellReasons(rowOf(out, "network-1")))
	}
	t.Run("a source written another way is not a pair either", func(t *testing.T) {
		m := adminModel()
		m.foreign = []apitest.Entry{{User: "TAG:EXAMPLE-WEB", Errors: []string{`[acl test error]: address "tag:example-db:22": want: Drop, got: Accept`}}}
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, adminIntent)
		if err != nil {
			t.Fatal(err)
		}
		if row := rowOf(out, "network-2"); row.Status == "met" || out.ExitCode() == 0 {
			t.Errorf("network-2 %s, exit %d: a spelling of the source with a line is not silence", row.Status, out.ExitCode())
		}
	})
}

// A new string field of the result has to be decided: the owner's words go in fields the
// framework masks and sanitizes as untrusted, and the rest are the tool's closed words.
func TestExplainOutputStringFieldsAreTaggedOrFixed(t *testing.T) {
	fixed := map[string]bool{
		"SecurityExplainOutput.Status": true, "SecurityExplainOutput.PolicyVersion": true, "SecurityExplainOutput.EvaluatedAt": true,
		"SecurityExplainIntent.Source": true, "SecurityExplainIntent.Digest": true, "SecurityExplainIntent.Revision": true,
		"SecurityExplainRow.ID": true, "SecurityExplainRow.Kind": true, "SecurityExplainRow.Status": true, "SecurityExplainRow.Limits": true, "SecurityExplainOutput.Notes": true,
		"SecurityExplainCell.Expect": true, "SecurityExplainCell.Verdict": true, "SecurityExplainCell.Observed": true, "SecurityExplainCell.Reason": true,
		"SecurityExplainRule.Section": true, "SecurityExplainReach.Kind": true, "SecurityExplainReach.Expectation": true,
	}
	seen := map[string]bool{}
	var walk func(rt reflect.Type)
	walk = func(rt reflect.Type) {
		for rt.Kind() == reflect.Slice || rt.Kind() == reflect.Pointer {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt.Name()] {
			return
		}
		seen[rt.Name()] = true
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			name := rt.Name() + "." + f.Name
			elem := f.Type
			for elem.Kind() == reflect.Slice {
				elem = elem.Elem()
			}
			switch {
			case elem.Kind() == reflect.String:
				untrusted := strings.Contains(f.Tag.Get("tk"), "untrusted")
				if untrusted == fixed[name] {
					t.Errorf("%s: untrusted=%v and in the list of fixed words=%v; it is exactly one of them", name, untrusted, fixed[name])
				}
				delete(fixed, name)
			case elem.Kind() == reflect.Struct:
				walk(elem)
			}
		}
	}
	walk(reflect.TypeFor[tools.SecurityExplainOutput]())
	for name := range fixed {
		t.Errorf("%s is listed as a fixed word and is not a string field of the result", name)
	}
}

// The audit fields are counts and closed words, and each is one the audit log keeps.
func TestExplainAuditFieldsAreClosed(t *testing.T) {
	out := tools.SecurityExplainOutput{Intent: tools.SecurityExplainIntent{Source: "cli", Revision: "0123456789ab"},
		Counts: tools.SecurityExplainCounts{Total: 5, Met: 1, Unmet: 1, Unknown: 1, MetWithLimits: 1, NotEvaluated: 1}}
	got := out.AuditFields()
	want := map[string]any{"intent": "cli", "digest": "0123456789ab", "expectations": 5, "met": 1, "unmet": 1, "unknown": 1, "limited": 1, "not_evaluated": 1}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fields = %v, want %v", got, want)
	}
	out.Intent.Revision = ""
	if _, ok := out.AuditFields()["digest"]; ok {
		t.Error("a digest is recorded when the rule gives none")
	}
}

// A live policy that was read again and could not be, or that changed, is not shown unchanged.
func TestALiveReadThatFailsIsNotUnchanged(t *testing.T) {
	f, _, env := apiEnv(t)
	m := adminModel()
	reads := 0
	serveExplain(f, explainPolicy, m)
	f.Handle("GET", tailnetPath+"/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(explainPolicy, `"e1"`, nil, nil).Write(w)
			return
		}
		reads++
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	})
	out, err := explainOnce(t, env, adminIntent)
	if err != nil {
		t.Fatal(err)
	}
	if reads == 0 || out.Counts.Met != 0 || out.ExitCode() != 1 || rowOf(out, "network-1").Cells[0].Reason != "live_changed" {
		t.Errorf("reads %d, %+v exit %d reasons %v: a live policy that cannot be read again was taken as unchanged", reads, out.Counts, out.ExitCode(), cellReasons(rowOf(out, "network-1")))
	}
}

// A live policy with errors stored with it would be refused as it is, and one this version cannot
// read cannot be built into a text: neither is sent, and every pair is unknown for that reason.
func TestALivePolicyThatCannotBeAskedAboutIsNotSent(t *testing.T) {
	t.Run("errors stored with it", func(t *testing.T) {
		f, _, env := apiEnv(t)
		serveLive(f, explainPolicy, nil, []string{"a stored error"})
		f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
			t.Error("a validation was sent")
			apitest.TestsPassEmptyObject().Write(w)
		})
		out, err := explainOnce(t, env, adminIntent)
		if err != nil || out.ExitCode() != 1 || rowOf(out, "network-1").Cells[0].Reason != "live_policy_errors" || posts(f) != 0 {
			t.Errorf("%+v, %v, exit %d", rowOf(out, "network-1").Cells, err, out.ExitCode())
		}
	})
	t.Run("a policy this version cannot read", func(t *testing.T) {
		f, _, env := apiEnv(t)
		serveLive(f, `[1, 2]`, nil, nil)
		f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
			t.Error("a validation was sent")
			apitest.TestsPassEmptyObject().Write(w)
		})
		out, err := explainOnce(t, env, adminIntent)
		if err != nil || out.ExitCode() != 1 || rowOf(out, "network-1").Cells[0].Reason != "live_policy_unreadable" || posts(f) != 0 {
			t.Fatalf("%+v, %v, exit %d", rowOf(out, "network-1").Cells, err, out.ExitCode())
		}
		if len(rowOf(out, "network-1").Candidates) != 0 || !strings.Contains(strings.Join(out.Notes, "|"), "candidate lists may be short") {
			t.Errorf("candidates %+v notes %q: a policy that cannot be read lists no rule and says the lists are short", rowOf(out, "network-1").Candidates, out.Notes)
		}
	})
}

// The version of the live policy the witnesses are about follows the rule of the other versions.
func TestExplainNamesTheVersionOfThePolicyByTheRuleOfVersions(t *testing.T) {
	f, _, env := apiEnv(t)
	route := serveExplain(f, explainPolicy, adminModel())
	_ = route
	out, err := explainOnce(t, env, adminIntent)
	if err != nil || out.PolicyVersion != "" {
		t.Fatalf("masked with no key: %q, %v; there is none", out.PolicyVersion, err)
	}
	env.Config = &config.Loaded{Config: config.Config{PersonalData: config.PersonalDataShow}}
	out, err = explainOnce(t, env, adminIntent)
	if err != nil || out.PolicyVersion != api.ETagOf([]byte(explainPolicy)) || out.EvaluatedAt != "2026-10-10T12:00:00Z" {
		t.Errorf("shown: %q at %q, %v", out.PolicyVersion, out.EvaluatedAt, err)
	}
}
