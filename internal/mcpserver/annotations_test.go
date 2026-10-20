package mcpserver

import (
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// Every tool the server advertises says it reads only, changes nothing, destroys
// nothing and gives the same answer to the same call.
func TestEveryToolIsAdvertisedReadOnlyIdempotentAndNotDestructive(t *testing.T) {
	reg := registry.New()
	tools.Register(reg)
	for _, tl := range reg.All() {
		d, err := Describe(tl)
		if err != nil {
			t.Fatal(err)
		}
		a := d.Annotations
		if a == nil || !a.ReadOnlyHint || !a.IdempotentHint || a.DestructiveHint == nil || *a.DestructiveHint || a.OpenWorldHint == nil {
			t.Errorf("%s: annotations %+v", tl.Meta.Name, a)
		}
	}
}
