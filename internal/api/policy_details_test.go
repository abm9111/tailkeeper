package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// This file feeds raw bodies to the details reader on purpose, to see what it refuses, so
// it is on the allowlist of TestNoHandWrittenValidateJSON.

func TestGetPolicyDetailsReadsTheObservedShape(t *testing.T) {
	policy := "// the owner's comment\r\n{\"acls\": [],}\r\n"
	for _, c := range []struct {
		name             string
		warnings, errors []string
	}{
		{"a clean policy", nil, nil},
		{"warnings and errors", []string{`host alias "p" unused`}, []string{"line 3: tag:p is not defined"}},
	} {
		f := apitest.New(t)
		f.ServeDetails(apitest.DetailsOK(policy, `"e1"`, c.warnings, c.errors))
		cl := f.Client(t)
		d, err := cl.GetPolicyDetails(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if string(d.Text) != policy || d.ETag != `"e1"` || strings.Join(d.Warnings, "|") != strings.Join(c.warnings, "|") || strings.Join(d.Errors, "|") != strings.Join(c.errors, "|") {
			t.Errorf("%s: %+v", c.name, d)
		}
		if (c.warnings == nil) != (d.Warnings == nil) {
			t.Errorf("%s: warnings %#v", c.name, d.Warnings)
		}
		reqs := f.Requests()
		if len(reqs) != 1 || reqs[0].Query.Get("details") != "true" || reqs[0].IfNoneMatch != "" || reqs[0].AcceptSent {
			t.Errorf("%s: requests %+v, want one details read with no If-None-Match (A-8: it is never honoured) and no Accept header (the observed answers)", c.name, reqs)
		}
	}
}

func TestGetPolicyDetailsRefusesWhatItDoesNotKnow(t *testing.T) {
	for _, c := range []struct{ name, body string }{
		{"an extra key", `{"acl":"e30=","extra":1}`},
		{"a key in capitals", `{"ACL":"e30="}`},
		{"a repeated key", `{"acl":"e30=","acl":"e30="}`},
		{"acl not base64", `{"acl":"%%%"}`},
		{"acl in the URL-safe alphabet", `{"acl":"_-_-"}`},
		{"acl absent", `{"warnings":null,"errors":null}`},
		{"acl null", `{"acl":null}`},
		{"acl empty", `{"acl":""}`},
		{"acl a number", `{"acl":5}`},
		{"warnings a string", `{"acl":"e30=","warnings":"x"}`},
		{"warnings holding a number", `{"acl":"e30=","warnings":[1]}`},
		{"warnings holding a null", `{"acl":"e30=","warnings":[null]}`},
		{"warnings holding a string and a null", `{"acl":"e30=","warnings":["w",null]}`},
		{"errors holding a null", `{"acl":"e30=","errors":[null]}`},
		{"errors an object", `{"acl":"e30=","errors":{}}`},
		{"a list", `[]`},
		{"an empty body", ``},
		{"bytes after the object", `{"acl":"e30="} x`},
	} {
		f := apitest.New(t)
		f.JSON("GET", aclPath, 200, c.body)
		cl := f.Client(t)
		d, err := cl.GetPolicyDetails(context.Background())
		e, ok := tkerr.As(err)
		if !ok || e.Code != tkerr.APIError || !strings.Contains(e.Message, "unrecognised response") {
			t.Errorf("%s: err = %v, want the unrecognised-response error", c.name, err)
		}
		if d.Text != nil || d.ETag != "" || d.Warnings != nil || d.Errors != nil {
			t.Errorf("%s: a value came back with the error: %+v", c.name, d)
		}
		if n := len(f.Requests()); n != 1 {
			t.Errorf("%s: %d requests, want 1 (a 200 is not retried)", c.name, n)
		}
	}
}

// 4 MiB decoded is the largest policy; base64 adds a third, which the client's limit must
// allow: 4 MiB * 4/3 = 5.6 MiB is within the 8 MiB an MCP call reads and the 64 MiB of the CLI.
func TestGetPolicyDetailsRefusesAPolicyOverTheCap(t *testing.T) {
	atCap := strings.Repeat("a", guard.MaxPolicyBytes)
	f := apitest.New(t)
	f.ServeDetails(apitest.DetailsOK(atCap, `"e1"`, nil, nil))
	cl := f.Client(t)
	for name, c := range map[string]*api.Client{"the CLI limit": cl, "the MCP limit": cl.WithMaxBody(8 << 20)} {
		d, err := c.GetPolicyDetails(context.Background())
		if err != nil || len(d.Text) != guard.MaxPolicyBytes {
			t.Errorf("exactly the cap, with %s: %d bytes, %v", name, len(d.Text), err)
		}
	}

	over := apitest.New(t)
	over.ServeDetails(apitest.DetailsOK(atCap+"a", `"e1"`, nil, nil))
	d, err := over.Client(t).GetPolicyDetails(context.Background())
	e, ok := tkerr.As(err)
	if !ok || e.Code != tkerr.APIError || !strings.Contains(e.Message, "4194305 bytes") || !strings.Contains(e.Hint, "policy_too_large") || d.Text != nil {
		t.Errorf("one byte over: %v (%+v)", err, d)
	}
}

func TestLiveStampHashesTheBodyAndCarriesTheETag(t *testing.T) {
	policy := "// c\r\n{}\r\n"
	f := apitest.New(t)
	f.ServePolicy(apitest.PolicyText(policy, api.ETagOf([]byte(policy))))
	cl := f.Client(t)
	stamp, err := cl.LiveStamp(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(policy))
	if stamp.SHA256 != hex.EncodeToString(sum[:]) || stamp.ETag != `"`+stamp.SHA256+`"` || stamp.ETag != api.ETagOf([]byte(policy)) {
		t.Errorf("stamp = %+v", stamp)
	}
	if r := f.Requests()[0]; r.Accept != "application/hujson" || r.IfNoneMatch != "" || len(r.Query) != 0 {
		t.Errorf("request = %+v, want a plain read for HuJSON with no If-None-Match", r)
	}
}

func TestLiveStampRefusesAPolicyOverTheCap(t *testing.T) {
	f := apitest.New(t)
	f.ServePolicy(apitest.PolicyText(strings.Repeat("a", guard.MaxPolicyBytes+1), `"e1"`))
	_, err := f.Client(t).LiveStamp(context.Background())
	if e, ok := tkerr.As(err); !ok || e.Code != tkerr.APIError || !strings.Contains(e.Message, "4194305 bytes") {
		t.Errorf("err = %v", err)
	}
}

func TestETagOfIsTheQuotedSHA256(t *testing.T) {
	for in, want := range map[string]string{
		"":    `"e3b0c44298fc1c149afbf4c8996fb924` + `27ae41e4649b934ca495991b7852b855"`,
		"abc": `"ba7816bf8f01cfea414140de5dae2223` + `b00361a396177a9cb410ff61f20015ad"`,
	} {
		if got := api.ETagOf([]byte(in)); got != want {
			t.Errorf("ETagOf(%q) = %s, want %s", in, got, want)
		}
	}
}
