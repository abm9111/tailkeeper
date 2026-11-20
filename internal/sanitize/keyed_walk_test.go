package sanitize

import (
	"testing"

	"github.com/abm9111/tailkeeper/internal/privacy"
)

// TestKeyedMaskWalksStructs covers a struct and a slice of structs. This test adds that a keyed Masker also names
// the values it reaches through a pointer, a slice of strings, an array and the values of a
// map: each is a place where the walk could carry on with a Masker that has no key (as Mask
// does) and mask the text without the pseudonym that a filter reads it by.
func TestKeyedMaskNamesValuesReachedThroughPointersSlicesArraysAndMaps(t *testing.T) {
	m, k := keyedMasker(t)
	amy := "a…@example.com" + privacy.Suffix(k.Pseudonym("amy@example.com"))
	bob := "b…@example.com" + privacy.Suffix(k.Pseudonym("bob@example.com"))
	name := "Amy Lee"
	type row struct {
		Name   *string           `json:"name" tk:"untrusted,personal"`
		Logins []string          `json:"logins" tk:"untrusted,personal"`
		Health []string          `json:"health" tk:"untrusted"`
		Pair   [2]string         `json:"pair" tk:"untrusted"`
		Claims map[string]string `json:"claims" tk:"untrusted"`
		Mail   *string           `json:"mail" tk:"untrusted,emails"`
		Plain  []string          `json:"plain" tk:"untrusted,plain"`
	}
	mail := "ask bob@example.com"
	v := struct {
		Ptr *row `json:"ptr"`
	}{Ptr: &row{
		Name:   &name,
		Logins: []string{"amy@example.com", "bob@example.com"},
		Health: []string{"ping bob@example.com", "ok"},
		Pair:   [2]string{"ping amy@example.com", "ping bob@example.com"},
		Claims: map[string]string{"email@example.com": "amy@example.com"},
		Mail:   &mail,
		Plain:  []string{"amy@example.com"},
	}}
	m.Mask(&v)
	got := v.Ptr
	for label, c := range map[string]struct{ got, want string }{
		"*string, personal":       {*got.Name, "A…" + privacy.Suffix(k.Pseudonym("Amy Lee"))},
		"[]string, personal [0]":  {got.Logins[0], amy},
		"[]string, personal [1]":  {got.Logins[1], bob},
		"[]string, text [0]":      {got.Health[0], "ping " + bob},
		"[]string, text [1]":      {got.Health[1], "ok"},
		"array, text [0]":         {got.Pair[0], "ping " + amy},
		"array, text [1]":         {got.Pair[1], "ping " + bob},
		"map value":               {got.Claims["email@example.com"], amy},
		"*string, emails":         {*got.Mail, "ask " + bob},
		"[]string, plain is kept": {got.Plain[0], "amy@example.com"},
	} {
		if c.got != c.want {
			t.Errorf("%s: %q, want %q", label, c.got, c.want)
		}
	}
	// A map key is not masked: two keys masked alike would collide.
	if _, ok := got.Claims["email@example.com"]; !ok || len(got.Claims) != 1 {
		t.Errorf("claims = %v, want the one key left as it was", got.Claims)
	}
	// The same value masked without a key: the control that the pseudonyms above are the key's.
	plain := row{Logins: []string{"amy@example.com"}, Health: []string{"ping bob@example.com"}, Claims: map[string]string{"k": "amy@example.com"}}
	Mask(&plain)
	if plain.Logins[0] != "a…@example.com" || plain.Health[0] != "ping b…@example.com" || plain.Claims["k"] != "a…@example.com" {
		t.Errorf("unkeyed: %q, %q, %q", plain.Logins[0], plain.Health[0], plain.Claims["k"])
	}
}
