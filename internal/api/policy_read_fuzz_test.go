package api_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
)

// This file feeds raw bodies to the reader on purpose, so it is on the allowlist of
// TestNoHandWrittenValidateJSON, like policy_read_test.go.

// passOracle is an independent statement of what a pass may look like, written without the
// reader's help: an empty body, or an object whose keys are message and data, whose entries
// hold only user, errors and warnings, and none of them an error. It is a necessary
// condition: a bare message passes it and reads as a rejection.
func passOracle(body []byte) bool {
	if len(bytes.TrimSpace(body)) == 0 {
		return true
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil || top == nil {
		return false
	}
	for k := range top {
		if k != "message" && k != "data" {
			return false
		}
	}
	var entries []map[string]json.RawMessage
	if raw, ok := top["data"]; ok && json.Unmarshal(raw, &entries) != nil {
		return false
	}
	for _, e := range entries {
		for k, v := range e {
			if k != "user" && k != "errors" && k != "warnings" {
				return false
			}
			var list []string
			if k == "errors" && (json.Unmarshal(v, &list) != nil || len(list) > 0) {
				return false
			}
		}
	}
	return true
}

// onlyMessage says whether body is an object whose only key is message.
func onlyMessage(body []byte) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return false
	}
	_, ok := top["message"]
	return ok && len(top) == 1
}

// hasErrorEntry says whether body has an entry of data with a non-empty errors list.
func hasErrorEntry(body []byte) bool {
	var top struct {
		Data []struct {
			Errors []string `json:"errors"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &top) != nil {
		return false
	}
	for _, e := range top.Data {
		if len(e.Errors) > 0 {
			return true
		}
	}
	return false
}

// FuzzReadPolicyValidation: whatever the server sends, the reader does not panic, answers
// the same way twice, reads a pass only from HTTP 200 and a shape the oracle allows, reads
// a rejection only from a 200 or a 400 with a lone message, a failure only from an entry
// with an error, and says why when it does not know.
func FuzzReadPolicyValidation(f *testing.F) {
	for _, s := range apitest.AllShapes() {
		f.Add(s.Status, []byte(s.Body))
	}
	for _, body := range []string{
		``, "  \n", `{}`, `[]`, `null`, "\xef\xbb\xbf{}",
		`{"message":"x","data":[{"user":"u","errors":[]}]}`,
		`{"data":[{"user":"a","errors":["e"]}],"data":[]}`,
		`{"Message":"x"}`, `{"message":"x"} trailing`, `{"message":"x" /* c */}`,
		"{\"message\":\"\xff\"}", `{"data":` + strings.Repeat("[", 300),
	} {
		f.Add(200, []byte(body))
		f.Add(400, []byte(body))
	}
	f.Fuzz(func(t *testing.T, status int, body []byte) {
		v := api.ReadPolicyValidation(status, body)
		if again := api.ReadPolicyValidation(status, body); !reflect.DeepEqual(v, again) {
			t.Fatalf("two readings differ: %+v and %+v", v, again)
		}
		if v.HTTP != status {
			t.Fatalf("HTTP = %d, want %d", v.HTTP, status)
		}
		switch v.Status {
		case api.PolicyPass:
			if status != 200 || !passOracle(body) {
				t.Fatalf("read as a pass: HTTP %d %q", status, body)
			}
		case api.PolicyRejected:
			if (status != 200 && status != 400) || !onlyMessage(body) || v.Message == "" {
				t.Fatalf("read as a rejection: HTTP %d %q", status, body)
			}
		case api.PolicyFail:
			if status != 200 || !hasErrorEntry(body) {
				t.Fatalf("read as a failure: HTTP %d %q", status, body)
			}
		case api.PolicyUnknown:
			if v.Why == "" {
				t.Fatalf("unknown without a reason: HTTP %d %q", status, body)
			}
		default:
			t.Fatalf("status %q", v.Status)
		}
	})
}
