package api

import (
	"reflect"
	"testing"

	"golang.org/x/oauth2"
)

// tokens is a token source that hands out the tokens it holds, in order.
type tokens struct{ next []*oauth2.Token }

func (s *tokens) Token() (*oauth2.Token, error) {
	t := s.next[0]
	s.next = s.next[1:]
	return t, nil
}

// The token endpoint reports the granted scopes with each token. A refresh that leaves
// the field out says nothing about them, so what was recorded for the earlier token must
// not be shown as the scopes of the new one.
func TestAFreshTokenWithoutAScopeFieldForgetsTheEarlierScopes(t *testing.T) {
	first := (&oauth2.Token{AccessToken: "first"}).WithExtra(map[string]any{"scope": "devices:core:read users:read"})
	rec := &scopeRecorder{src: &tokens{next: []*oauth2.Token{first, {AccessToken: "second"}}}}
	if _, err := rec.Token(); err != nil {
		t.Fatal(err)
	}
	if got, known := rec.get(); !known || !reflect.DeepEqual(got, []string{"devices:core:read", "users:read"}) {
		t.Fatalf("after the first token: %v, known %v", got, known)
	}
	if _, err := rec.Token(); err != nil {
		t.Fatal(err)
	}
	if got, known := rec.get(); known || len(got) != 0 {
		t.Errorf("after a token without a scope field: %v, known %v; want none, unknown", got, known)
	}
}
