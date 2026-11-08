package doctor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/audit"
	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// The local summary of the security assessment: the catalog built into the binary and the
// intent set the configuration names. The clock is the doctor's input, taken from the
// catalog's own dates so that renewing them does not break these tests.

func shippedSummary(t *testing.T) tools.CatalogSummary {
	t.Helper()
	sum, err := tools.ScanCatalogSummary(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

// check returns the one check of the report with that name.
func check(t *testing.T, r Report, name string) Check {
	t.Helper()
	var found []Check
	for _, c := range r.Checks {
		if c.Name == name {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d checks named %q: %+v", len(found), name, r.Checks)
	}
	return found[0]
}

func TestDoctorCatalogSummaryOkWarnFail(t *testing.T) {
	sum := shippedSummary(t)
	day := 24 * time.Hour
	for name, c := range map[string]struct {
		at     time.Time
		status Status
		detail string // a word the detail must hold
		fix    bool   // the fix names the bulletin re-check and the renewal of the dates
	}{
		"far from expiry":       {sum.ExpiresAt.Add(-60 * day), OK, "60 days left", false},
		"15 days left":          {sum.ExpiresAt.Add(-15 * day), OK, "15 days left", false},
		"exactly 14 days left":  {sum.ExpiresAt.Add(-14 * day), Warn, "14 days left", true},
		"13 days left":          {sum.ExpiresAt.Add(-13 * day), Warn, "13 days left", true},
		"1 day left":            {sum.ExpiresAt.Add(-day), Warn, "1 day left", true},
		"the last second":       {sum.ExpiresAt.Add(-time.Second), Warn, "less than 1 day left", true},
		"the instant of expiry": {sum.ExpiresAt, Fail, "expired on " + sum.ExpiresAt.Format("2006-01-02"), true},
		"a day after expiry":    {sum.ExpiresAt.Add(day), Fail, "expired on " + sum.ExpiresAt.Format("2006-01-02"), true},
		"a year after expiry":   {sum.ExpiresAt.Add(365 * day), Fail, "expired on", true},
	} {
		f, a := newApp(t, allReadScopes(t))
		f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","expires":"2099-01-01T00:00:00Z"}`)
		r := Run(context.Background(), Input{App: a, Now: c.at})
		row := check(t, r, "advisory catalog")
		if row.Status != c.status || !strings.Contains(row.Detail, c.detail) {
			t.Errorf("%s: %s %q, want %s with %q", name, row.Status, row.Detail, c.status, c.detail)
		}
		if has := strings.Contains(row.Hint, "bulletins") && strings.Contains(row.Hint, "renew its dates"); has != c.fix {
			t.Errorf("%s: fix %q, names the bulletin re-check and the renewal: %v, want %v", name, row.Hint, has, c.fix)
		}
		// Doctor's exit follows the existing rows: a failing row is 8, a warning is not.
		wantExit := 0
		if c.status == Fail {
			wantExit = 8
		}
		if got := tkerr.ExitCode(r.Err()); got != wantExit {
			t.Errorf("%s: exit %d, want %d (failed %d, warned %d)", name, got, wantExit, r.Failed, r.Warned)
		}
	}
}

// The row states what a person acts on: the revision, the first eight digits of the digest,
// the expiry date and the rules by review state. Nothing else of the catalog.
func TestDoctorCatalogSummaryStatesTheCatalog(t *testing.T) {
	sum := shippedSummary(t)
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 200, `{"id":"test-client-id","keyType":"client","expires":"2099-01-01T00:00:00Z"}`)
	row := check(t, Run(context.Background(), Input{App: a, Now: sum.ExpiresAt.Add(-90 * 24 * time.Hour)}), "advisory catalog")
	for _, want := range []string{
		fmt.Sprintf("revision %d", sum.Revision), "digest " + sum.Digest[:8] + ",", "expires " + sum.ExpiresAt.Format("2006-01-02"),
		fmt.Sprintf("%d rules (%d approved, %d pending, %d withdrawn)", sum.Rules, sum.Approved, sum.Pending, sum.Withdrawn),
	} {
		if !strings.Contains(row.Detail, want) {
			t.Errorf("the row lacks %q: %q", want, row.Detail)
		}
	}
	if strings.Contains(row.Detail, sum.Digest[:9]) {
		t.Errorf("the row shows more than eight digits of the digest: %q", row.Detail)
	}
	if sum.Rules == 0 || sum.Pending == 0 {
		t.Fatalf("the premise: the shipped catalog has rules and some pending: %+v", sum)
	}
}

// The row and a scan speak of one catalog: the doctor reads it by the code the scan does, and
// a scan's result names the same revision, digest, expiry and rule counts.
func TestDoctorCatalogSummaryAgreesWithTheScan(t *testing.T) {
	_, a := newApp(t, allReadScopes(t))
	a.Env.RecordObservation = a.RecordObservation
	var out tools.SecurityScanOutput
	if err := call(context.Background(), a, "security_scan", `{"scope":"local"}`, &out); err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339, out.Catalog.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	var rep Report
	catalogChecks(context.Background(), &rep, a, expires.Add(-90*24*time.Hour))
	row := check(t, rep, "advisory catalog")
	for _, want := range []string{
		fmt.Sprintf("revision %d", out.Catalog.Revision), "digest " + out.Catalog.Digest[:8], "expires " + out.Catalog.ExpiresAt[:10],
		fmt.Sprintf("%d rules (%d approved, %d pending, %d withdrawn)", out.Catalog.Rules, out.Catalog.Approved, out.Catalog.Pending, out.Catalog.Withdrawn),
	} {
		if !strings.Contains(row.Detail, want) {
			t.Errorf("the scan says %+v; the row lacks %q: %q", out.Catalog, want, row.Detail)
		}
	}
}

// The group makes no request: not to the API, which a fake here would record, and not an audit
// line either. It scans nothing.
func TestDoctorCatalogSummaryMakesNoRequest(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	path := filepath.Join(t.TempDir(), "intent.hujson")
	if err := os.WriteFile(path, []byte(`{"tests": [{"src": "tag:one", "accept": ["tag:two:22"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
	linesBefore, err := audit.Verify(a.Audit.Path())
	if err != nil {
		t.Fatal(err)
	}
	var rep Report
	catalogChecks(context.Background(), &rep, a, shippedSummary(t).ExpiresAt.Add(-time.Hour))
	if n := len(f.Requests()); n != 0 {
		t.Errorf("%d API requests from the catalog summary", n)
	}
	if linesAfter, err := audit.Verify(a.Audit.Path()); err != nil || linesAfter != linesBefore {
		t.Errorf("the audit log went from %d to %d lines (%v): the summary records no source", linesBefore, linesAfter, err)
	}
	if len(rep.Checks) != 2 {
		t.Errorf("%d rows, want the catalog and the intent set: %+v", len(rep.Checks), rep.Checks)
	}
}

func TestDoctorIntentSetRow(t *testing.T) {
	const file = `{"tests": [{"src": "zq-canary-owner@example.com", "accept": ["tag:zq-canary-db:5432"]}], "sshTests": [{"src": "tag:zq-canary-ci", "dst": ["tag:zq-canary-ssh"], "accept": ["zqcanaryuser"]}]}`
	needles := []string{"zq-canary", "zqcanary", ":5432"}
	dir := t.TempDir()
	write := func(text string) string {
		path := filepath.Join(dir, fmt.Sprintf("intent-%d.hujson", len(text)))
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	run := func(path string) Check {
		_, a := newApp(t, allReadScopes(t))
		if path != "" {
			a.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
		}
		var rep Report
		catalogChecks(context.Background(), &rep, a, shippedSummary(t).ExpiresAt.Add(-90*24*time.Hour))
		return check(t, rep, "intent set")
	}

	if row := run(""); row.Status != Info || !strings.Contains(row.Detail, "none configured") {
		t.Errorf("no file configured: %+v", row)
	}
	path := write(file)
	row := run(path)
	if row.Status != Info || !strings.Contains(row.Detail, "configured: 2 expectations") || !strings.Contains(row.Detail, "no digest (personal data is masked and no privacy key is loaded)") {
		t.Errorf("a file configured: %+v", row)
	}
	b, _ := json.Marshal(row)
	for _, bad := range append(needles, path, filepath.Base(path), dir) {
		if strings.Contains(string(b), bad) {
			t.Errorf("the row repeats %q: %s", bad, b)
		}
	}
	// The deprecated spellings acl validate takes (user, allow) are taken.
	if row := run(write(`{"tests": [{"user": "zq-canary-a", "allow": ["tag:zq-canary:1"]}]}`)); row.Status != Info || !strings.Contains(row.Detail, "configured: 1 expectation,") {
		t.Errorf("a file in the deprecated spellings: %+v", row)
	}
	// A file that is set and cannot be used is a failure, never "none configured".
	for name, p := range map[string]string{
		"missing":          filepath.Join(dir, "gone.hujson"),
		"a defect":         write(`{"zq-canary-key": []}`),
		"past the engine":  write(`{"tests": [` + strings.Repeat("{},", acl.MaxNodes) + `]}`),
		"a field not kept": write(`{"tests": [{"src": "zq-canary-a", "zz-unmapped": ["tag:zq-canary:1"]}]}`),
	} {
		row := run(p)
		if row.Status != Fail || !strings.HasPrefix(row.Detail, "config_invalid:") {
			t.Errorf("%s: %+v, want a failure with config_invalid", name, row)
		}
		b, _ := json.Marshal(row)
		for _, bad := range needles {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s: the row repeats %q: %s", name, bad, b)
			}
		}
	}
}

// The row also says what the scan says is not fresh besides the expiry: a catalog that is not
// valid yet, and approved rules whose review is not fresh. The facts come from the summary (the
// scan's own predicates); the row is a layout of them, so these cases drive it with summaries.
func TestDoctorCatalogRowStates(t *testing.T) {
	issued := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(90 * 24 * time.Hour)
	day := 24 * time.Hour
	sum := func(state security.CatalogState, stale int) tools.CatalogSummary {
		return tools.CatalogSummary{Revision: 3, Digest: strings.Repeat("ab", 32), IssuedAt: issued, ExpiresAt: expires, Rules: 5, Approved: 2, Pending: 3,
			State: state, StaleReviews: stale}
	}
	for name, c := range map[string]struct {
		sum    tools.CatalogSummary
		at     time.Time
		status Status
		detail []string
		fix    []string // words the fix must hold; none: no fix
	}{
		"fresh":                   {sum(security.CatalogCurrent, 0), issued.Add(10 * day), OK, []string{"revision 3, digest abababab,", "5 rules (2 approved, 3 pending, 0 withdrawn)", "80 days left"}, nil},
		"one stale review":        {sum(security.CatalogCurrent, 1), issued.Add(10 * day), Warn, []string{"1 approved rule has a review that is not fresh"}, []string{"review_expires_at"}},
		"two stale reviews":       {sum(security.CatalogCurrent, 2), issued.Add(10 * day), Warn, []string{"2 approved rules have a review that is not fresh"}, []string{"review_expires_at"}},
		"not yet valid":           {sum(security.CatalogNotYetValid, 0), issued.Add(-day), Warn, []string{"not yet valid", "issued on 2026-11-01", "91 days left"}, []string{"clock", "issued_at"}},
		"not yet valid and stale": {sum(security.CatalogNotYetValid, 1), issued.Add(-day), Warn, []string{"not yet valid", "1 approved rule has a review that is not fresh"}, []string{"clock", "review_expires_at"}},
		"expiring and stale":      {sum(security.CatalogCurrent, 1), expires.Add(-5 * day), Warn, []string{"5 days left", "1 approved rule has a review that is not fresh"}, []string{"bulletins", "renew its dates", "review_expires_at"}},
		"expired":                 {sum(security.CatalogExpired, 0), expires.Add(day), Fail, []string{"expired on 2027-01-30"}, []string{"bulletins", "renew its dates"}},
		"expired and stale":       {sum(security.CatalogExpired, 2), expires.Add(day), Fail, []string{"expired on 2027-01-30", "2 approved rules have a review that is not fresh"}, []string{"bulletins", "review_expires_at"}},
	} {
		st, detail, fix := catalogRow(c.sum, c.at)
		if st != c.status {
			t.Errorf("%s: %s %q, want %s", name, st, detail, c.status)
		}
		for _, w := range c.detail {
			if !strings.Contains(detail, w) {
				t.Errorf("%s: the detail lacks %q: %q", name, w, detail)
			}
		}
		if len(c.fix) == 0 && fix != "" {
			t.Errorf("%s: a fix where there is nothing to fix: %q", name, fix)
		}
		for _, w := range c.fix {
			if !strings.Contains(fix, w) {
				t.Errorf("%s: the fix lacks %q: %q", name, w, fix)
			}
		}
	}
}

// The intent row shows the digest by the rule of the other digests of a policy: a prefix of the
// keyed one while personal data is masked and a key is loaded, a prefix of the plain one with
// personalData show, and none (and the reason) while masked with no key.
func TestDoctorIntentRowFollowsTheDigestRule(t *testing.T) {
	const file = `{"tests": [{"src": "zq-canary-owner@example.com", "accept": ["tag:zq-canary-db:5432"]}]}`
	path := filepath.Join(t.TempDir(), "intent.hujson")
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	keyedHex := strings.TrimPrefix(key.Digest([]byte(file)), "hmac-sha256:")
	sum := sha256.Sum256([]byte(file))
	plainHex := hex.EncodeToString(sum[:])
	for name, c := range map[string]struct {
		key  *privacy.Key
		show bool
		want string
		not  []string
	}{
		"masked, no key":      {nil, false, "no digest", []string{plainHex[:8], keyedHex[:8], "hmac"}},
		"masked, a key":       {key, false, "digest " + keyedHex[:8], []string{plainHex[:8], "hmac", "no digest"}},
		"personal data shown": {nil, true, "digest " + plainHex[:8], []string{keyedHex[:8], "no digest"}},
	} {
		_, a := newApp(t, allReadScopes(t))
		a.Env.Privacy = c.key
		a.Env.Config = &config.Loaded{Config: config.Config{ACL: config.ACL{InvariantsFile: path}}}
		if c.show {
			a.Env.Config.Config.PersonalData = config.PersonalDataShow
		}
		var rep Report
		catalogChecks(context.Background(), &rep, a, shippedSummary(t).ExpiresAt.Add(-90*24*time.Hour))
		row := check(t, rep, "intent set")
		if row.Status != Info || !strings.Contains(row.Detail, "configured: 1 expectation") || !strings.Contains(row.Detail, c.want) {
			t.Errorf("%s: %+v, want an info row with %q", name, row, c.want)
		}
		for _, bad := range c.not {
			if strings.Contains(row.Detail, bad) {
				t.Errorf("%s: the row holds %q: %q", name, bad, row.Detail)
			}
		}
	}
}

// With no configuration loaded the row cannot know what the configuration names, so it says
// it was skipped, as the other rows that need the configuration do; the catalog row, which does
// not, is still there.
func TestDoctorIntentRowIsSkippedWhenNoConfigurationLoaded(t *testing.T) {
	_, a := newApp(t, allReadScopes(t))
	a.Loaded = nil
	a.Env.APIErr = tkerr.New(tkerr.ConfigMissing, "no configuration", "")
	r := Run(context.Background(), Input{App: a, Now: shippedSummary(t).ExpiresAt.Add(-90 * 24 * time.Hour)})
	row := check(t, r, "intent set")
	if row.Status != NA || !strings.Contains(row.Detail, "skipped: no configuration") || strings.Contains(row.Detail, "none configured") {
		t.Errorf("intent set: %+v, want n/a, skipped: no configuration", row)
	}
	if c := check(t, r, "advisory catalog"); c.Status == NA {
		t.Errorf("the catalog row was skipped: %+v", c)
	}
}

// A catalog that does not load is a failure of the row, not a warning: it can only be a bug of
// the build, and it means no scan can run.
func TestDoctorCatalogThatDoesNotLoadFails(t *testing.T) {
	var rep Report
	catalogReport(&rep, tools.CatalogSummary{}, tkerr.New(tkerr.Internal, "the advisory catalog built into this binary does not load", "this is a tailkeeper bug"), time.Now())
	row := check(t, rep, "advisory catalog")
	if row.Status != Fail || !strings.HasPrefix(row.Detail, "internal_error:") || rep.Failed != 1 || tkerr.ExitCode(rep.Err()) != 8 {
		t.Errorf("%+v, failed %d", row, rep.Failed)
	}
}
