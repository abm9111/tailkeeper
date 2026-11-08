package tools_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// credentialTraces says which pieces of a credential-shaped string are in text, however it is
// cased or punctuated: text is reduced to its lower-case letters first, so that a copy squeezed
// into the shape of a code ("tskeyapiktest...") is found as well as the string itself.
func credentialTraces(text string) []string {
	flat := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		}
		return -1
	}, text)
	var found []string
	for _, piece := range []string{"tskeyapi", "ktestcntrl", "notarealsecret", "upstreamsaid"} {
		if strings.Contains(flat, piece) {
			found = append(found, piece)
		}
	}
	return found
}

// Text a source gives is never put in a record, an explanation or an error: a failure is
// named by the program's own code. A credential could reach three places: a line of the audit
// log, the text of an error the collection returns, and the text of a coverage row (and so of
// a report). The test looks in each, in the form it really has: the log is the file a real App
// writes, the error is one the collection returns while holding the text of two failed
// sources, and the coverage and the snapshot are marshalled. Before it looks, it checks that
// its detector finds the string in the places it would be, and that the places it reads are
// not empty, so a clean answer cannot come from looking at nothing.
func TestSourceErrorTextWithACredentialShapeReachesNothing(t *testing.T) {
	// Assembled at run time so that no credential shape sits in the source.
	canary := "tskey" + "-api-" + "kTEST1CNTRL-" + "notarealsecretvalue"

	// The detector: it finds the string as it is, and squeezed into the shape of a code.
	for _, planted := range []string{canary, "fatal: " + canary, "upstream said " + canary, strings.ToLower(strings.NewReplacer("-", "_", "1", "").Replace(canary))} {
		if got := credentialTraces(planted); len(got) == 0 {
			t.Fatalf("the detector does not find a credential in %q", planted)
		}
	}
	if got := credentialTraces(`{"event":"collect","source":"api_devices","outcome":"error","code":"upstream_unavailable","tailnet":"T1234CNTRL"}`); len(got) != 0 {
		t.Fatalf("the detector reports %v in a clean audit line", got)
	}

	fail := func(r *rig) {
		r.f.JSON("GET", tailnetPath+"/devices", 500, `{"message":"upstream said `+canary+`"}`)
		r.cli.on("status --json --peers=false", 1, "", "fatal: "+canary)
	}

	// 1. The run is complete: the audit log the App wrote, and the result.
	r, path := newAppRig(t)
	withCLI(r)
	fail(r)
	c, err := tools.CollectSecurity(context.Background(), r.env, security.ScopeFleet)
	if err != nil {
		t.Fatal(err)
	}
	requireValid(t, c)
	raw, lines := auditLines(t, path)
	if len(lines) != 6 {
		t.Fatalf("the audit log has %d lines, want 6: an attempt and an outcome for the API and for the status, and a skip for each of the two sources not asked: %v", len(lines), raw)
	}
	codes := map[string]string{}
	for _, l := range lines {
		if l["phase"] == "outcome" {
			codes[fmt.Sprint(l["source"])] = fmt.Sprint(l["code"])
		}
	}
	if codes["api_devices"] != string(tkerr.UpstreamUnavailable) || codes["local_status"] != string(tkerr.LocalCommandFailed) ||
		codes["local_version"] != security.SkipIdentity || codes["local_prefs"] != security.SkipIdentity {
		t.Errorf("the audit log names the failures by code: %v", codes)
	}
	for i, l := range raw {
		if got := credentialTraces(l); len(got) != 0 {
			t.Errorf("audit line %d holds %v of a source's text: %s", i, got, l)
		}
	}
	snap, _ := json.Marshal(c)
	if got := credentialTraces(string(snap)); len(got) != 0 {
		t.Errorf("the result holds %v of a source's text: %s", got, snap)
	}
	for _, rw := range c.Coverage {
		if rw.Explanation == "" || !strings.Contains(rw.Explanation, string(tkerr.UpstreamUnavailable)) {
			t.Errorf("the coverage row names no failure by its code: %+v", rw)
		}
		if got := credentialTraces(rw.Explanation); len(got) != 0 {
			t.Errorf("coverage text holds %v of a source's text: %q", got, rw.Explanation)
		}
	}
	events, _ := json.Marshal(r.got)
	if got := credentialTraces(string(events) + fmt.Sprintf("%+v", r.got)); len(got) != 0 {
		t.Errorf("an event holds %v of a source's text", got)
	}

	// 2. The run ends with an error after both sources failed: the error, its message and
	// everything it wraps are the program's words.
	r, _ = newAppRig(t)
	withCLI(r)
	fail(r)
	r.failAt = 4 // the outcome of the status, after the text of both sources has been seen
	_, err = tools.CollectSecurity(context.Background(), r.env, security.ScopeFleet)
	if tkerr.From(err).Code != tkerr.AuditUnavailable {
		t.Fatalf("the premise: the run ends with the audit error, got %v", err)
	}
	text := fmt.Sprintf("%v | %+v | %#v", err, err, err)
	for e := err; e != nil; e = errors.Unwrap(e) {
		text += " | " + e.Error()
	}
	if got := credentialTraces(text); len(got) != 0 {
		t.Errorf("the returned error holds %v of a source's text: %s", got, text)
	}
}
