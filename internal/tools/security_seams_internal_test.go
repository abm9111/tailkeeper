package tools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func TestContextReferencesAreScopeBoundAndKeepAPIErrors(t *testing.T) {
	f := apitest.New(t)
	env := &registry.Env{API: f.Client(t)}
	ref, err := apiContextRef(env)
	if err != nil || ref == security.ContextLocalOnly || ref == "" {
		t.Fatalf("API reference: %q, %v", ref, err)
	}
	if got := securityContextRef(env, security.ScopeFleet); got != ref {
		t.Fatalf("fleet reference %q", got)
	}
	if got := securityContextRef(env, security.ScopeLocal); got != security.ContextLocalOnly {
		t.Fatalf("local reference %q", got)
	}
	classified := tkerr.New(tkerr.CredentialUnavailable, "synthetic", "")
	env.API, env.APIErr = nil, classified
	if _, err := apiContextRef(env); !errors.Is(err, classified) {
		t.Fatalf("API error changed: %v", err)
	}
	if got := securityContextRef(env, security.ScopeFleet); got != security.ContextLocalOnly {
		t.Fatalf("unavailable fleet reference %q", got)
	}
}

func TestTagsOwnedByBudgetIsDeterministicAcrossMapOrders(t *testing.T) {
	want := []string{"tag:example-00", "tag:example-01", "tag:example-02"}
	for shift := 0; shift < 20; shift++ {
		owners := map[string][]string{}
		for i := 0; i < 20; i++ {
			owners[fmt.Sprintf("tag:example-%02d", (i+shift)%20)] = []string{"group:example-owner"}
		}
		m := ruleMatcher{a: &acl.Access{TagOwners: owners}, w: newMatchMeter(context.Background(), 6)}
		if got := m.tagsOwnedBy("group:example-owner"); !reflect.DeepEqual(got, want) || !m.w.spent() {
			t.Fatalf("shift %d: %v spent=%v", shift, got, m.w.spent())
		}
	}
}

func TestRunScanInputsReusesOneCollectionAndItsExactInputs(t *testing.T) {
	catalog, err := advisory.Shipped()
	if err != nil {
		t.Fatal(err)
	}
	at := catalog.IssuedAt.Add(time.Hour)
	var events int
	env := &registry.Env{Now: func() time.Time { return at }, RecordObservation: func(context.Context, security.CollectionEvent) error { events++; return nil }}
	in := SecurityScanInput{Scope: string(security.ScopeLocal)}
	run, err := runScanInputs(context.Background(), env, in, func() (security.Catalog, error) { return catalog, nil })
	if err != nil {
		t.Fatal(err)
	}
	if events != 4 {
		t.Fatalf("events=%d, want one attempt and outcome plus two skipped sources", events)
	}
	again, err := security.Evaluate(context.Background(), run.Input)
	if err != nil || !reflect.DeepEqual(run.Report, again) {
		t.Fatalf("replay differs from original evaluation: %v", err)
	}
	out, err := securityScan(context.Background(), env, in, func() (security.Catalog, error) { return catalog, nil })
	if err != nil || out.Status != string(run.Report.Status) || events != 8 {
		t.Fatalf("scan status=%q events=%d err=%v", out.Status, events, err)
	}
}

func TestCollectAccessInputStartsBeforeFirstRequestAndMatchesExplain(t *testing.T) {
	f := apitest.New(t)
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	clockCalls, requests := 0, 0
	f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/acl", func(w http.ResponseWriter, _ *http.Request) {
		if clockCalls == 0 {
			t.Error("request made before start time was read")
		}
		requests++
		apitest.DetailsOK(`{}`, `"synthetic"`, nil, nil).Write(w)
	})
	env := &registry.Env{API: f.Client(t), Now: func() time.Time { clockCalls++; return at.Add(time.Duration(clockCalls) * time.Second) }}
	selected := security.IntentSet{}
	input, started, err := collectAccessInput(context.Background(), env, selected)
	if err != nil {
		t.Fatal(err)
	}
	if !started.Equal(at.Add(time.Second)) || input.EvaluatedAt.Before(started) || requests != 1 {
		t.Fatalf("started=%v evaluated=%v requests=%d", started, input.EvaluatedAt, requests)
	}
	want, err := security.ExplainAccess(input)
	if err != nil {
		t.Fatal(err)
	}
	clockCalls = 0
	got, err := explainSelected(context.Background(), env, selected)
	if err != nil || !reflect.DeepEqual(got, want) || requests != 2 {
		t.Fatalf("wrapper mismatch or extra requests: %v, requests=%d", err, requests)
	}
}
