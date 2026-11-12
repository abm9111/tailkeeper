package app

import (
	"reflect"
	"testing"
)

// Options once had ReadFile, a by-path file reader handed to the credential code, which
// no credential read used any more (VIGIL-SEC-001). The sole reader is the explicit
// checked credential-reader seam, whose production default is config.ReadSecretFile.
func TestOptionsOfferNoFileReader(t *testing.T) {
	reader := reflect.TypeOf(func(string) ([]byte, error) { return nil, nil })
	ot := reflect.TypeFor[Options]()
	if _, ok := ot.FieldByName("ReadFile"); ok {
		t.Error("Options still has the ReadFile field")
	}
	for i := 0; i < ot.NumField(); i++ {
		if f := ot.Field(i); f.Type == reader && f.Name != "ReadSecretFile" {
			t.Errorf("Options.%s is a by-path file reader", f.Name)
		}
	}
}
