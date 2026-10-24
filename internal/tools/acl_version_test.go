package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func TestVersionIdsRoundTripAndABadOneIsValidationFailed(t *testing.T) {
	ref := versionRef{Time: "2026-10-01T00:00:00.5Z", Group: "g1", Ordinal: 2, Side: "new"}
	id := encodeVersionID(ref)
	got, err := decodeVersionID(id)
	if err != nil || got != ref {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	bad := func(name, id, want string) {
		t.Helper()
		_, err := decodeVersionID(id)
		e := tkerr.From(err)
		if e == nil || e.Code != tkerr.ValidationFailed || !strings.Contains(e.Message, want) {
			t.Errorf("%s: %v, want validation_failed containing %q", name, err, want)
		}
	}
	tampered := []byte(id)
	tampered[len(versionPrefix)+2] = '*'
	bad("tampered base64", string(tampered), "version id from acl_history")
	extra, _ := json.Marshal(map[string]any{"t": ref.Time, "g": "g1", "n": 0, "s": "new", "x": 1})
	bad("extra field", versionPrefix+base64.RawURLEncoding.EncodeToString(extra), "version id from acl_history")
	bad("oversize", strings.Repeat("v", maxVersionID+1), "too long")
	bad("retention", encodeVersionID(versionRef{Time: "1990-01-01T00:00:00Z", Group: "g", Side: "old"}), "retention window")
	bad("bad side", encodeVersionID(versionRef{Time: ref.Time, Group: "g", Side: "both"}), "version id from acl_history")
}

func TestReadVersionTextFindsTheEntryByTimeGroupAndOrdinalAndSaysWhenItIsGone(t *testing.T) {
	f := apitest.New(t)
	env := &registry.Env{API: f.Client(t), Now: func() time.Time { return time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC) }}
	const when = "2026-10-08T00:00:00Z"
	f.Serve("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/logging/configuration", apitest.AuditACLUpdates())
	// The shape's second entry is the one at when, group g2. A window of two seconds
	// holds it alone, so its ordinal is 0.
	ctx := context.Background()
	id := encodeVersionID(versionRef{Time: when, Group: "g2", Side: "new"})
	text, err := readVersionText(ctx, env, id)
	if err != nil || string(text.b) != `{"tagOwners":{"tag:a":["amy@example.com"],"tag:b":[]}}` {
		t.Fatalf("new text: %q, %v", text.b, err)
	}
	prev := encodeVersionID(versionRef{Time: when, Group: "g2", Side: "old"})
	old, err := readVersionText(ctx, env, prev)
	if err != nil || string(old.b) != `{"tagOwners":{"tag:a":["amy@example.com"]}}` {
		t.Fatalf("old text: %q, %v", old.b, err)
	}
	gone := encodeVersionID(versionRef{Time: when, Group: "missing", Side: "new"})
	_, err = readVersionText(ctx, env, gone)
	if e := tkerr.From(err); e == nil || e.Code != tkerr.NotFound || !strings.Contains(e.Message, "no longer holds") {
		t.Fatalf("gone: %v, want not_found", err)
	}
	if len(f.Requests()) != 3 {
		t.Fatalf("%d reads, want one per lookup", len(f.Requests()))
	}
	q := f.Requests()[0].Query
	if q.Get("event") != historyEvent || q.Get("start") != "2026-10-07T23:59:59Z" || q.Get("end") != "2026-10-08T00:00:01Z" {
		t.Fatalf("window query = %v", q)
	}
}

func TestAVersionIdNamesTheNewTextAndPreviousNamesTheOldOne(t *testing.T) {
	f := apitest.New(t)
	env := &registry.Env{API: f.Client(t), Now: func() time.Time { return time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC) }}
	f.Serve("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/logging/configuration", apitest.AuditACLUpdates())
	out, err := aclHistory(context.Background(), env, ACLHistoryInput{})
	if err != nil || out.Count != 2 {
		t.Fatalf("list: %+v, %v", out, err)
	}
	got, err := readVersionText(context.Background(), env, out.Versions[1].Version)
	prev, err2 := readVersionText(context.Background(), env, out.Versions[1].Previous)
	if err != nil || err2 != nil {
		t.Fatal(err, err2)
	}
	if string(got.b) != `{"tagOwners":{"tag:a":["amy@example.com"],"tag:b":[]}}` || string(prev.b) != `{"tagOwners":{"tag:a":["amy@example.com"]}}` {
		t.Fatalf("version names %s, previous names %s", got.b, prev.b)
	}
}

func TestRawPolicyTextPrintsAPlaceholderAndHasNoEncodingMethods(t *testing.T) {
	r := rawPolicyText{b: []byte("amy@example.com")}
	if got, want := fmt.Sprintf("%v", r), "raw policy text"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	if got := fmt.Sprintf("%s", r); got != "raw policy text" {
		t.Fatalf("%s printed %q", "%s", got)
	}
	typ := reflect.TypeOf(r)
	for _, name := range []string{"String", "Error", "MarshalJSON", "MarshalText"} {
		if _, ok := typ.MethodByName(name); ok {
			t.Errorf("rawPolicyText has %s", name)
		}
	}
}

func TestAnOverCapTextIsRefusedWithTheCapOnly(t *testing.T) {
	errs := map[int]string{}
	for _, n := range []int{8, 40} {
		login := strings.Repeat("a", n) + "@example.com"
		body := `{"logs":[{"eventTime":"2026-10-08T00:00:00Z","eventGroupID":"g","origin":"ADMIN_CONSOLE","action":"UPDATE","actor":{"id":"u1","type":"user","loginName":"amy@example.com","displayName":"Amy"},"old":"{}","new":` + strconv.Quote(strings.Repeat("x", guard.MaxPolicyBytes)+login) + `}]}`
		f := apitest.New(t)
		env := &registry.Env{API: f.Client(t), Now: func() time.Time { return time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC) }}
		f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/logging/configuration", 200, body)
		id := encodeVersionID(versionRef{Time: "2026-10-08T00:00:00Z", Group: "g", Side: "new"})
		_, err := readVersionText(context.Background(), env, id)
		if err == nil || strings.Contains(err.Error(), login) || strings.Contains(err.Error(), strconv.Itoa(guard.MaxPolicyBytes+len(login))) {
			t.Fatalf("n=%d: %v", n, err)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("over the cap of %d bytes", guard.MaxPolicyBytes)) {
			t.Fatalf("n=%d: %v", n, err)
		}
		errs[n] = err.Error()
	}
	if errs[8] != errs[40] {
		t.Fatalf("the error tells the length:\n%s\n%s", errs[8], errs[40])
	}
}
