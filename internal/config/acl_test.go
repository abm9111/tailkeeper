package config

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

const oneContext = `"contexts":{"p":{"tailnetId":"T1CNTRL","credentials":{"read":{"provider":"env"}}}}`

// aclConfig is a configuration whose acl block is body.
func aclConfig(body string) []byte { return []byte(`{` + oneContext + `,"acl":` + body + `}`) }

func TestACLKeysDefaultToUnsetAndThirty(t *testing.T) {
	c, err := Parse([]byte(`{` + oneContext + `}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.ACL.InvariantsFile != "" || c.ACL.ValidatePerMinute != nil || c.ACL.ValidateRate() != 30 {
		t.Errorf("defaults: %+v, rate %d", c.ACL, c.ACL.ValidateRate())
	}
	if b, _ := json.Marshal(c); strings.Contains(string(b), `"acl"`) {
		t.Errorf("an unset acl block is written out: %s", b)
	}
}

func TestACLKeysAreRead(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "invariants.hujson")
	body, _ := json.Marshal(map[string]any{"invariantsFile": abs, "validatePerMinute": 120})
	c, err := Parse(aclConfig(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if c.ACL.InvariantsFile != abs || c.ACL.ValidateRate() != 120 {
		t.Errorf("acl = %+v, rate %d", c.ACL, c.ACL.ValidateRate())
	}
	for _, n := range []string{"1", "30", "119"} {
		c, err := Parse(aclConfig(`{"validatePerMinute":` + n + `}`))
		if err != nil || c.ACL.ValidateRate() < 1 {
			t.Errorf("validatePerMinute %s: %v", n, err)
		}
	}
}

func TestACLKeysAreChecked(t *testing.T) {
	for name, c := range map[string]struct{ body, want string }{
		"relative invariantsFile": {`{"invariantsFile":"invariants.hujson"}`, "acl.invariantsFile must be an absolute path"},
		"zero rate":               {`{"validatePerMinute":0}`, "acl.validatePerMinute must be a whole number from 1 to 120"},
		"negative rate":           {`{"validatePerMinute":-5}`, "acl.validatePerMinute must be a whole number from 1 to 120"},
		"rate over the cap":       {`{"validatePerMinute":121}`, "acl.validatePerMinute must be a whole number from 1 to 120"},
		"fractional rate":         {`{"validatePerMinute":1.5}`, "does not match the schema"},
		"string rate":             {`{"validatePerMinute":"30"}`, "does not match the schema"},
		"unknown key":             {`{"invariants":"/x"}`, "acl.invariants is not a configuration key"},
		"wrong case":              {`{"InvariantsFile":"/x"}`, "acl.InvariantsFile is not a configuration key"},
		"duplicate key":           {`{"validatePerMinute":5,"validatePerMinute":6}`, "acl.validatePerMinute appears twice"},
		"not an object":           {`[]`, "does not match the schema"},
	} {
		_, err := Parse(aclConfig(c.body))
		e, ok := tkerr.As(err)
		if !ok || e.Code != tkerr.ConfigInvalid || !strings.Contains(e.Message, c.want) {
			t.Errorf("%s: err = %v, want config_invalid containing %q", name, err, c.want)
		}
	}
}
