package tools

import (
	"reflect"
	"strings"
	"testing"
)

// The audit_log descriptions say what a URL in a result looks like. They once said "only
// its host" while cutURLs shows the scheme and host and a hash of the path, so a reader
// could not tell the cut URL from the claim. The shown form is built here from cutURLs
// itself, and each description must name its parts and not call it the host alone.
func TestAuditLogDescriptionsSayWhatAURLShowsAs(t *testing.T) {
	got := cutURLs("https://hooks.example.com/services/T0/B0/token")
	if !strings.HasPrefix(got, "https://hooks.example.com/…[path sha256 ") {
		t.Fatalf("cutURLs shows %q: update the descriptions below to say what it shows", got)
	}
	typ := reflect.TypeOf(AuditLogInput{})
	for _, field := range []string{"Target", "IncludeValues"} {
		f, ok := typ.FieldByName(field)
		if !ok {
			t.Fatalf("AuditLogInput has no %s", field)
		}
		desc := f.Tag.Get("jsonschema")
		for _, bad := range []string{"only its host", "only their host"} {
			if strings.Contains(desc, bad) {
				t.Errorf("%s: the description says %q, but a URL shows as its scheme and host and a hash of its path", field, bad)
			}
		}
		for _, want := range []string{"scheme and host", "hash of "} {
			if !strings.Contains(desc, want) {
				t.Errorf("%s: the description does not say %q", field, want)
			}
		}
	}
}
