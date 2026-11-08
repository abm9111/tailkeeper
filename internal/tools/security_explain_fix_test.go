package tools_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Tests of the follow-up to the first review of `security explain`. Every name is a reserved one.

// sshEntriesOf are the sshTests entries of a posted text that are the explanation's own, the
// canary's left out.
func sshEntriesOf(t testing.TB, m *policyModel) []struct {
	Src    string   `json:"src"`
	Dst    []string `json:"dst"`
	Accept []string `json:"accept"`
	Check  []string `json:"check"`
	Deny   []string `json:"deny"`
} {
	t.Helper()
	var out []struct {
		Src    string   `json:"src"`
		Dst    []string `json:"dst"`
		Accept []string `json:"accept"`
		Check  []string `json:"check"`
		Deny   []string `json:"deny"`
	}
	for _, sent := range m.sentTexts(t) {
		for _, e := range sent.SSHTests {
			if !sshCanaryTagRE.MatchString(e.Src) {
				out = append(out, e)
			}
		}
	}
	return out
}

// Tailscale fails two tests that share a src (design 12.2); no probe shows that sshTests are
// spared. A source has one sshTests entry in the request, and what one entry cannot hold is not
// asked, never widened to fit.
func TestExplainSSHEntriesNeverShareASource(t *testing.T) {
	t.Run("an accept user and a deny user on one destination are one entry", func(t *testing.T) {
		intent := `{"sshTests": [{"src": "group:example-admins", "dst": ["tag:example-db"], "accept": ["root"], "deny": ["deploy"]}]}`
		m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{"group:example-admins|tag:example-db|root": true}}
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		entries := sshEntriesOf(t, m)
		if len(entries) != 1 {
			t.Fatalf("%d sshTests entries for one source, want one: %+v", len(entries), entries)
		}
		if e := entries[0]; !slices.Equal(e.Dst, []string{"tag:example-db"}) || !slices.Equal(e.Accept, []string{"root"}) || !slices.Equal(e.Deny, []string{"deploy"}) {
			t.Errorf("entry = %+v, want the one test the owner wrote", e)
		}
		if row := rowOf(out, "ssh-1"); row.Status != "met" || len(row.Cells) != 2 || out.ExitCode() != 0 {
			t.Errorf("status %s cells %+v exit %d, want both pairs met", row.Status, row.Cells, out.ExitCode())
		}
	})
	t.Run("expectations of one source on the same pairs share it", func(t *testing.T) {
		intent := `{"sshTests": [
			{"src": "group:example-admins", "dst": ["tag:example-db"], "accept": ["root"]},
			{"src": "group:example-admins", "dst": ["tag:example-web"], "accept": ["root"]},
		]}`
		m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{"group:example-admins|tag:example-db|root": true, "group:example-admins|tag:example-web|root": true}}
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		entries := sshEntriesOf(t, m)
		if len(entries) != 1 || !slices.Equal(entries[0].Dst, []string{"tag:example-db", "tag:example-web"}) {
			t.Fatalf("entries = %+v, want one entry holding both destinations (its product is exactly the pairs asked)", entries)
		}
		if out.Counts.Met != 2 || out.ExitCode() != 0 {
			t.Errorf("counts %+v exit %d", out.Counts, out.ExitCode())
		}
	})
	t.Run("pairs one entry cannot hold are not asked, not widened", func(t *testing.T) {
		// root on the database and deploy on the web tier: one entry would also ask root on the web
		// tier and deploy on the database, which nobody asked.
		intent := `{"sshTests": [
			{"src": "group:example-admins", "dst": ["tag:example-db"], "accept": ["root"]},
			{"src": "group:example-admins", "dst": ["tag:example-web"], "accept": ["deploy"]},
		]}`
		m := &policyModel{allow: map[string]bool{}, sshAllow: map[string]bool{"group:example-admins|tag:example-db|root": true, "group:example-admins|tag:example-web|deploy": true}}
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		entries := sshEntriesOf(t, m)
		if len(entries) != 1 || !slices.Equal(entries[0].Dst, []string{"tag:example-db"}) || !slices.Equal(entries[0].Accept, []string{"root"}) {
			t.Fatalf("entries = %+v, want the first pair alone: two entries would share a source", entries)
		}
		second := rowOf(out, "ssh-2")
		if second.Status != "not_evaluated" || len(second.Cells) != 1 || second.Cells[0].Reason != "same_source" || second.Cells[0].Observed != "not_asked" {
			t.Errorf("ssh-2 = %+v, want not_evaluated, not asked, same_source", second)
		}
		if rowOf(out, "ssh-1").Status != "met" || out.ExitCode() != 1 {
			t.Errorf("ssh-1 %s exit %d, want met and exit 1", rowOf(out, "ssh-1").Status, out.ExitCode())
		}
	})
}

// An SSH failure line carries its own source. When it is not the source of the entry of the reply
// it was found in, the line is evidence about one source set under another, and neither is read.
func TestAnSSHFailureLineThatNamesAnotherSourceLeavesTheAffectedPairsUnknown(t *testing.T) {
	intent := `{"sshTests": [
		{"src": "tag:example-a", "dst": ["tag:example-db"], "accept": ["root"]},
		{"src": "tag:example-b", "dst": ["tag:example-db"], "accept": ["root"]},
		{"src": "tag:example-c", "dst": ["tag:example-db"], "accept": ["root"]},
	]}`
	allow := map[string]bool{"tag:example-a|tag:example-db|root": true, "tag:example-b|tag:example-db|root": true, "tag:example-c|tag:example-db|root": true}
	t.Run("a line for another asked source", func(t *testing.T) {
		m := &policyModel{allow: map[string]bool{}, sshAllow: allow}
		m.sshExtra = func(src string) []string {
			if src == "tag:example-a" {
				return []string{sshLine("tag:example-b", "tag:example-db", "root", "accept", "deny")}
			}
			return nil
		}
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"ssh-1", "ssh-2"} {
			if row := rowOf(out, id); row.Status != "unknown" || row.Cells[0].Reason != "unpaired_line" {
				t.Errorf("%s = %s by %s: a line for the other source is under this one, so neither is read", id, row.Status, row.Cells[0].Reason)
			}
		}
		if row := rowOf(out, "ssh-3"); row.Status != "met" {
			t.Errorf("ssh-3 = %s: a source the line does not touch is read as before", row.Status)
		}
		if out.Counts.Unmet != 0 || out.ExitCode() != 1 {
			t.Errorf("counts %+v exit %d: the line is not a failure of the source it sits under", out.Counts, out.ExitCode())
		}
	})
	t.Run("a line for a source nobody asked", func(t *testing.T) {
		m := &policyModel{allow: map[string]bool{}, sshAllow: allow}
		m.sshExtra = func(src string) []string {
			if src == "tag:example-a" {
				return []string{sshLine("tag:example-zz", "tag:example-db", "root", "accept", "deny")}
			}
			return nil
		}
		_, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, intent)
		if err != nil {
			t.Fatal(err)
		}
		if row := rowOf(out, "ssh-1"); row.Status != "unknown" || row.Cells[0].Reason != "unpaired_line" {
			t.Errorf("ssh-1 = %s by %s", row.Status, row.Cells[0].Reason)
		}
		if rowOf(out, "ssh-2").Status != "met" || rowOf(out, "ssh-3").Status != "met" {
			t.Errorf("counts %+v: the other sources are read as before", out.Counts)
		}
	})
}

// "At most two validation requests" is POSTs on the wire. The sends of an explanation do not
// retry: a 500 leaves its pairs unknown and is not sent again.
func TestAnExplanationSendsAtMostTwoPostsWhateverTheEndpointAnswers(t *testing.T) {
	both := `{
	"tests": [{"src": "group:example-admins", "accept": ["tag:example-db:22"]}],
	"sshTests": [{"src": "group:example-admins", "dst": ["tag:example-db"], "accept": ["root"]}],
}`
	model := func() *policyModel {
		return &policyModel{allow: map[string]bool{"group:example-admins|tag:example-db:22": true}, sshAllow: map[string]bool{"group:example-admins|tag:example-db|root": true}}
	}
	t.Run("500 then 200: the first answer is the answer", func(t *testing.T) {
		m := model()
		m.fiveHundred = func(n int) bool { return n%2 == 1 }
		f, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, both)
		if err != nil {
			t.Fatal(err)
		}
		if got := posts(f); got != 2 {
			t.Errorf("%d POSTs, want 2: a retry is a POST", got)
		}
		if row := rowOf(out, "network-1"); row.Status != "unknown" || row.Cells[0].Reason != "request_failed" {
			t.Errorf("network-1 = %s by %s, want unknown by request_failed: the 500 was not retried into an answer", row.Status, row.Cells[0].Reason)
		}
		if out.ExitCode() != 1 || out.Counts.Met > 1 {
			t.Errorf("counts %+v exit %d", out.Counts, out.ExitCode())
		}
	})
	t.Run("500 for everything", func(t *testing.T) {
		m := model()
		m.fiveHundred = func(int) bool { return true }
		f, env := explainEnv(t, explainPolicy, m)
		out, err := explainOnce(t, env, both)
		if err != nil {
			t.Fatal(err)
		}
		if got := posts(f); got != 2 {
			t.Errorf("%d POSTs, want 2", got)
		}
		if out.Counts.Unknown != 2 || out.Counts.Met != 0 || out.ExitCode() != 1 {
			t.Errorf("counts %+v exit %d, want two unknown", out.Counts, out.ExitCode())
		}
	})
}

// A call cancelled while the intent file is read says so in words that are true of this command.
func TestExplainCancelledWhileReadingTheIntentDoesNotSayScan(t *testing.T) {
	_, env := explainEnv(t, explainPolicy, adminModel())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := explainCtx(ctx, t, env, adminIntent)
	if err == nil {
		t.Fatal("a cancelled call returned no error")
	}
	if msg := tkerr.From(err).Message; strings.Contains(msg, "scan") || !strings.Contains(msg, "cancelled") {
		t.Errorf("message = %q", msg)
	}
}

// Each validation request has its own audit records: an attempt before it is sent and an outcome
// after, through the required security audit method. Metadata only.
func TestExplainRecordsEachValidationRequestTwice(t *testing.T) {
	both := `{
	"tests": [{"src": "group:example-admins", "accept": ["tag:example-db:22"]}],
	"sshTests": [{"src": "group:example-admins", "dst": ["tag:example-db"], "accept": ["root"]}],
}`
	m := &policyModel{allow: map[string]bool{"group:example-admins|tag:example-db:22": true}, sshAllow: map[string]bool{"group:example-admins|tag:example-db|root": true}}
	_, env := explainEnv(t, explainPolicy, m)
	log := recorderOf(env)
	var mu sync.Mutex
	var seen []int
	m.onPost = func(int) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, len(log.all()))
	}
	out, err := explainOnce(t, env, both)
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode() != 0 {
		t.Fatalf("counts %+v", out.Counts)
	}
	if !slices.Equal(seen, []int{1, 3}) {
		t.Errorf("the records existing as each request arrived: %v, want 1 then 3: the attempt is written before the request", seen)
	}
	ev := log.all()
	if len(ev) != 4 {
		t.Fatalf("%d events, want an attempt and an outcome for each of two requests: %+v", len(ev), ev)
	}
	want := []struct {
		src   security.CollectionSource
		phase security.CollectionPhase
	}{
		{security.SourceValidateNetwork, security.PhaseAttempt}, {security.SourceValidateNetwork, security.PhaseOutcome},
		{security.SourceValidateSSH, security.PhaseAttempt}, {security.SourceValidateSSH, security.PhaseOutcome},
	}
	for i, w := range want {
		if ev[i].Source != w.src || ev[i].Phase != w.phase || ev[i].Scope != security.ScopeFleet {
			t.Errorf("event %d = %+v, want %s %s in the fleet scope", i, ev[i], w.src, w.phase)
		}
	}
	for _, o := range []security.CollectionEvent{ev[1], ev[3]} {
		if o.Outcome != security.OutcomeOK || o.Code != "" || o.Observed != 1 || o.Dropped != 0 {
			t.Errorf("outcome = %+v, want ok with the one pair counted", o)
		}
	}
}

// A request whose attempt cannot be recorded is not sent; one whose outcome cannot be recorded is
// not relied on. The pairs are unknown, with a reason, and the run exits 1.
func TestExplainWithoutAuditRecordsSendsNothingAndKnowsNothing(t *testing.T) {
	both := `{
	"tests": [{"src": "group:example-admins", "accept": ["tag:example-db:22"]}],
	"sshTests": [{"src": "group:example-admins", "dst": ["tag:example-db"], "accept": ["root"]}],
}`
	model := func() *policyModel {
		return &policyModel{allow: map[string]bool{"group:example-admins|tag:example-db:22": true}, sshAllow: map[string]bool{"group:example-admins|tag:example-db|root": true}}
	}
	refuse := tkerr.New(tkerr.ConfigInvalid, `audit.reads is "none"`, "")
	t.Run("every record refused: nothing is sent", func(t *testing.T) {
		f, env := explainEnv(t, explainPolicy, model())
		recorderOf(env).fail = func(security.CollectionEvent) error { return refuse }
		out, err := explainOnce(t, env, both)
		if err != nil {
			t.Fatal(err)
		}
		if got := posts(f); got != 0 {
			t.Errorf("%d POSTs, want none: the attempt could not be recorded", got)
		}
		if out.Counts.Unknown != 2 || out.Counts.Met != 0 || out.ExitCode() != 1 {
			t.Errorf("counts %+v exit %d", out.Counts, out.ExitCode())
		}
		for _, row := range out.Expectations {
			if row.Cells[0].Reason != "audit_unrecorded" || row.Cells[0].Canary {
				t.Errorf("%s = %+v, want unknown by audit_unrecorded", row.ID, row.Cells[0])
			}
		}
		if !strings.Contains(reportText(out), security.ReasonSentence(security.ReasonNotRecorded)) {
			t.Errorf("the reason is not stated in its sentence:\n%s", reportText(out))
		}
	})
	t.Run("a surface with no audit record at all", func(t *testing.T) {
		f, env := explainEnv(t, explainPolicy, model())
		env.RecordObservation = nil
		withoutRecorder.Store(env, true)
		out, err := explainCtx(context.Background(), t, env, both)
		if err != nil {
			t.Fatal(err)
		}
		if posts(f) != 0 || out.Counts.Unknown != 2 || out.ExitCode() != 1 {
			t.Errorf("%d POSTs, counts %+v exit %d", posts(f), out.Counts, out.ExitCode())
		}
	})
	t.Run("the attempt of the second request refused: only the first is sent", func(t *testing.T) {
		f, env := explainEnv(t, explainPolicy, model())
		recorderOf(env).fail = func(ev security.CollectionEvent) error {
			if ev.Source == security.SourceValidateSSH {
				return refuse
			}
			return nil
		}
		out, err := explainOnce(t, env, both)
		if err != nil {
			t.Fatal(err)
		}
		if posts(f) != 1 || rowOf(out, "network-1").Status != "met" || rowOf(out, "ssh-1").Status != "unknown" || rowOf(out, "ssh-1").Cells[0].Reason != "audit_unrecorded" {
			t.Errorf("%d POSTs, counts %+v: network-1 %s, ssh-1 %s", posts(f), out.Counts, rowOf(out, "network-1").Status, rowOf(out, "ssh-1").Status)
		}
	})
	t.Run("the outcome refused: the answer is not relied on", func(t *testing.T) {
		f, env := explainEnv(t, explainPolicy, model())
		recorderOf(env).fail = func(ev security.CollectionEvent) error {
			if ev.Phase == security.PhaseOutcome {
				return refuse
			}
			return nil
		}
		out, err := explainOnce(t, env, both)
		if err != nil {
			t.Fatal(err)
		}
		if posts(f) != 2 || out.Counts.Met != 0 || out.Counts.Unknown != 2 || out.ExitCode() != 1 {
			t.Errorf("%d POSTs, counts %+v exit %d: the requests were sent and their answers, unrecorded, are not a verdict", posts(f), out.Counts, out.ExitCode())
		}
	})
	t.Run("an error that stops the command stops it, whether or not the outcome can be recorded", func(t *testing.T) {
		for _, refuseOutcome := range []bool{false, true} {
			f, env := explainEnv(t, explainPolicy, model())
			f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
			recorderOf(env).fail = func(ev security.CollectionEvent) error {
				if refuseOutcome && ev.Phase == security.PhaseOutcome {
					return refuse
				}
				return nil
			}
			_, err := explainOnce(t, env, both)
			if err == nil {
				t.Errorf("outcome refused %v: a refused credential produced a report", refuseOutcome)
			} else if code := tkerr.From(err).Code; code == tkerr.ConfigInvalid || code == tkerr.AuditUnavailable {
				t.Errorf("outcome refused %v: the error is %s, the audit's, and not the request's", refuseOutcome, code)
			}
		}
	})
}
