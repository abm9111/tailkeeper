//go:build !windows

package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/tools"
)

func TestPublicDemoAdvisoryApplicability(t *testing.T) {
	at := scanAt(t)
	h := scanHarness(t, at, fleet(at)...)
	code := h.run("--json", "security", "scan", "fleet")
	var out tools.SecurityScanOutput
	if err := json.Unmarshal(h.out.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if code != 8 || out.Status != "partial" || out.AtThreshold.Affected != 1 || out.Counts.Unknown != 8 || out.Catalog.Pending != 4 || !strings.Contains(h.err.String(), "findings_present") {
		t.Fatalf("unexpected assessment: exit %d", code)
	}
	affected, pending := 0, 0
	for _, finding := range out.Findings {
		if finding.Rule == "CVE-2022-41925" && finding.Applicability == "affected" {
			affected++
			if finding.EvidenceState != "observed" || finding.Confidence != "reported" || finding.Reason != "" || len(finding.Evidence) != 2 {
				t.Fatal("affected finding lacks its expected observed evidence")
			}
			for _, evidence := range finding.Evidence {
				if evidence.Origin != "api" || evidence.Freshness != "fresh" || evidence.AcquiredAt != at.UTC().Format(time.RFC3339) || evidence.ObservedAt != at.Add(-time.Minute).UTC().Format(time.RFC3339) {
					t.Fatal("affected finding evidence is not fresh API evidence")
				}
			}
		}
		if finding.Reason == "review_pending" && finding.Applicability == "unknown" {
			pending++
		}
	}
	if affected != 1 || pending != 8 {
		t.Fatalf("affected rows %d, pending unknown rows %d", affected, pending)
	}

	fmt.Println("ADVISORY: exit 8; 1 affected at threshold; assessment partial; 4 rules pending; reported version is evidence, not proof of exploitation.")
}

func TestPublicDemoExcessiveAccess(t *testing.T) {
	const policy = `{"acls":[{"action":"accept","src":["tag:example-web"],"dst":["*:*"]}]}`
	const intent = `{"tests":[{"src":"tag:example-web","deny":["tag:example-db:22"]}]}`
	m := &cliModel{allow: map[string]bool{"tag:example-web|tag:example-db:22": true}}
	h := explainHarness(t, policy, m)
	code := h.explain(t, writeIntent(t, intent), "--json")
	var out struct {
		Status string `json:"status"`
		Counts struct {
			Unmet int `json:"unmet"`
		} `json:"counts"`
		PairsJudged int `json:"pairsJudged"`
	}
	if err := json.Unmarshal(h.out.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if code != 8 || out.Status != "incomplete" || out.Counts.Unmet != 1 || out.PairsJudged != 1 || !strings.Contains(h.err.String(), "findings_present") {
		t.Fatalf("unexpected explanation: exit %d: %s %s", code, h.out, h.err)
	}
	for _, s := range []string{`"observed": "allowed"`, `"candidates"`, `"blast"`, `"broad"`, `"heading"`, "if tag:example-web were compromised", "not the rule that grants or denies", "not that a service listens"} {
		if !strings.Contains(h.out.String(), s) {
			t.Fatalf("missing %q in %s", s, h.out)
		}
	}
	fmt.Println("ACCESS: exit 8; 1 unmet deny; pair witnessed allowed; broad rule is a candidate. Blast radius is conditional, not proof of cause, a running service, or exploitation.")
}

func TestPublicDemoCorrectionVerification(t *testing.T) {
	h, f, before, at := verifyFleetFixture(t)
	now := at.Add(3 * time.Minute)
	h.app.Env.Now = func() time.Time { return now }
	correction := verifyCorrectionFile(t, t.TempDir(), versionCorrection(at.Add(time.Minute), "nOLD01CNTRL"))
	for _, tc := range []struct {
		version, verdict, after string
		exit                    int
	}{{"1.102.5-t0123456ab", "fixed", "satisfied", 0}, {"1.28.2-t0123456ab", "not_fixed", "contradicted", 8}} {
		setVerifyFleet(t, f, now, tc.version, true)
		prior := len(f.Requests())
		h.out.Reset()
		h.err.Reset()
		code := h.run("security", "verify", "--before", before, "--correction", correction, "--json")
		var result tools.SecurityVerifyOutput
		if err := json.Unmarshal(h.out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if code != tc.exit || result.Outcome != tc.verdict || len(f.Requests()) <= prior || len(result.Targets) != 1 {
			t.Fatalf("unexpected verification exit %d or target count", code)
		}
		row := result.Targets[0]
		if row.Kind != "version" || row.Name != "client" || row.AtLeast != "1.32.3" || row.Outcome != tc.verdict || row.Before != "contradicted" || row.After != tc.after || row.Reason != "" || row.MatcherReason != "" || len(row.Evidence) != 2 {
			t.Fatalf("unexpected target transition: %+v", row)
		}
		for _, evidence := range row.Evidence {
			if evidence.Class != "api" || evidence.AgeSeconds != int64(time.Minute/time.Second) || !now.Add(-time.Duration(evidence.AgeSeconds)*time.Second).After(at.Add(time.Minute)) {
				t.Fatal("target evidence is not fresh post-action API evidence")
			}
		}
	}
	fmt.Println("CORRECTION: private before-pack exported (exit 0); fresh post-action evidence fixed (exit 0); contradictory old running version not_fixed (exit 8). Paths: <before-pack>, <correction>.")
}
