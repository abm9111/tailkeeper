package probe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Live is the tailnet's own policy, held in memory for the probes that need a name from
// it (A-7, A-8, A-9, A-10, A-12, A-13). Nothing in it is ever printed or written: the
// probes print booleans and counts computed from it.
type Live struct {
	Text     []byte   // the policy as the server stores it (HuJSON)
	ETag     string   // the ETag header of the details answer
	Warnings []string // the server's warnings for the stored policy
	Errors   []string // the server's errors for the stored policy
	Tags     []string // the tags tagOwners defines, sorted
	Hosts    []string // the host aliases, sorted
	Groups   []string // the group names, sorted
	Logins   []string // the members of groups that are written as an address, sorted
	Services []string // the svc: names the text mentions, sorted
	SSH      []SSHRule
	// StoredTests is how many entries the policy's tests section holds (0 when it has none).
	// A count only: A-12 needs to know whether a stored test could fail, never what it says.
	StoredTests int
	Parsed      bool // the sections above were read; false when the text would not parse as the probe expects
}

// String and GoString keep a stray %v or %+v from printing the policy's names.
func (Live) String() string   { return "<live>" }
func (Live) GoString() string { return "<live>" }

// SSHRule is the part of an ssh rule an sshTests entry can be built from.
type SSHRule struct {
	Src, Dst, Users []string
}

// svcRE finds a service name anywhere in the policy text.
var svcRE = regexp.MustCompile(`"(svc:[a-z0-9-]+)"`)

// Live reads the live policy with GET .../acl?details=true once and keeps it for the rest
// of the run. The request is recorded in the probe that first asks. It sends no Accept
// header: the OpenAPI document says not to send one with details.
func (x *Exec) Live(ctx context.Context) (*Live, error) {
	if x.live != nil || x.liveErr != nil {
		return x.live, x.liveErr
	}
	seen, err := x.GetPolicy(ctx, Step{Label: "live policy (details=true), held in memory for the probes that need it",
		Expect: "200 with acl, warnings, errors and an ETag"}, api.PolicyGet{Details: true})
	if err == nil && x.stopped != nil {
		err = x.stopped // a 429 on the read stops the run; it is not an api_error
	}
	if err != nil {
		x.liveErr = err
		return nil, err
	}
	l, err := parseDetails(seen)
	if err != nil {
		x.liveErr = err
		return nil, err
	}
	x.live = l
	return l, nil
}

// parseDetails reads the details answer into a Live.
func parseDetails(s Seen) (*Live, error) {
	if s.Status != 200 {
		return nil, tkerr.New(tkerr.APIError, "the live policy could not be read with details=true", "")
	}
	var d struct {
		ACL      string   `json:"acl"`
		Warnings []string `json:"warnings"`
		Errors   []string `json:"errors"`
	}
	if json.Unmarshal(s.Body, &d) != nil {
		return nil, tkerr.New(tkerr.APIError, "the details answer is not a JSON object with an acl", "")
	}
	text, err := base64.StdEncoding.DecodeString(d.ACL)
	if err != nil || len(text) == 0 {
		return nil, tkerr.New(tkerr.APIError, "the details answer holds no policy text in base64", "")
	}
	l := &Live{Text: text, ETag: s.ETag, Warnings: d.Warnings, Errors: d.Errors}
	l.read()
	return l, nil
}

// read fills the name lists from the text. The server accepted this text, and its strict
// decoder refuses nesting past 10,000 levels, so hujson cannot be sent into runaway recursion by it.
func (l *Live) read() {
	std, err := hujson.Standardize(append([]byte(nil), l.Text...))
	if err != nil {
		return
	}
	var doc struct {
		TagOwners map[string]json.RawMessage `json:"tagOwners"`
		Hosts     map[string]json.RawMessage `json:"hosts"`
		Groups    map[string]json.RawMessage `json:"groups"`
		Tests     json.RawMessage            `json:"tests"`
		SSH       []struct {
			Src   []string `json:"src"`
			Dst   []string `json:"dst"`
			Users []string `json:"users"`
		} `json:"ssh"`
	}
	if json.Unmarshal(std, &doc) != nil {
		return
	}
	l.Tags, l.Hosts, l.Groups = keys(doc.TagOwners), keys(doc.Hosts), keys(doc.Groups)
	var stored []json.RawMessage
	_ = json.Unmarshal(doc.Tests, &stored) // absent, null or not a list: no stored tests
	l.StoredTests = len(stored)
	seen := map[string]bool{}
	for _, raw := range doc.Groups {
		var members []string
		if json.Unmarshal(raw, &members) != nil {
			continue
		}
		for _, m := range members {
			if strings.Contains(m, "@") && !seen[m] {
				seen[m] = true
				l.Logins = append(l.Logins, m)
			}
		}
	}
	sort.Strings(l.Logins)
	for _, m := range svcRE.FindAllSubmatch(l.Text, -1) {
		if name := string(m[1]); !contains(l.Services, name) {
			l.Services = append(l.Services, name)
		}
	}
	sort.Strings(l.Services)
	for _, r := range doc.SSH {
		l.SSH = append(l.SSH, SSHRule{Src: r.Src, Dst: r.Dst, Users: r.Users})
	}
	l.Parsed = true
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
