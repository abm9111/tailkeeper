package tools

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/acl"
)

// The verdict of the user canary on the canary's destination is set aside whether the destination is
// the literal address or an alias of the live policy's hosts, and, when the policy could not be read,
// whatever is not a literal address, for it may be an alias.
func TestTheSSHCanaryUserIsSetAsideByAliasAndWhenTheHostsAreUnknown(t *testing.T) {
	hosts := map[string]string{"example-canary": "192.0.2.1", "example-other": "192.0.2.2"}
	for _, c := range []struct {
		name, dst, user string
		hosts           map[string]string
		known           bool
		want            bool
	}{
		{"the literal address", "192.0.2.1", "canary", hosts, true, true},
		{"an alias for it", "example-canary", "canary", hosts, true, true},
		{"an alias for another address", "example-other", "canary", hosts, true, false},
		{"a name that is no alias", "example-missing", "canary", hosts, true, false},
		{"a tag", "tag:db", "canary", hosts, true, false},
		{"another user on the alias", "example-canary", "root", hosts, true, false},
		{"a tag, the policy not read", "tag:db", "canary", nil, false, true},
		{"a name, the policy not read", "example-canary", "canary", nil, false, true},
		{"the literal address, the policy not read", "192.0.2.1", "canary", nil, false, true},
		{"another literal address, the policy not read", "192.0.2.2", "canary", nil, false, false},
		{"another literal IPv6 address, the policy not read", "2001:db8::1", "canary", nil, false, false},
		{"another user, the policy not read", "tag:db", "root", nil, false, false},
		{"an alias, no hosts but the policy read", "example-canary", "canary", map[string]string{}, true, false},
	} {
		v := []ACLSSHVerdict{{Dst: c.dst, User: c.user, Expect: "accept", Verdict: verdictAllowed}}
		changed := setAsideSSHCanaryUser(v, c.hosts, c.known)
		if changed != c.want || (v[0].Verdict == verdictUnknown) != c.want || (c.want && v[0].Why != whySSHCanaryUser) || (!c.want && v[0].Verdict != verdictAllowed) {
			t.Errorf("%s: changed %v, verdict %+v, want set aside %v", c.name, changed, v[0], c.want)
		}
	}
}

func TestLiveHostAliasesReadTheHostsSectionOrSayTheyCannot(t *testing.T) {
	hosts, ok := liveHostAliases(context.Background(), []byte(`{"hosts": {"example-canary": "192.0.2.1"}, "acls": []}`))
	if !ok || !reflect.DeepEqual(hosts, map[string]string{"example-canary": "192.0.2.1"}) {
		t.Errorf("hosts = %v, ok %v", hosts, ok)
	}
	if hosts, ok := liveHostAliases(context.Background(), []byte(`{}`)); !ok || len(hosts) != 0 {
		t.Errorf("a policy with no hosts: %v, ok %v, want read and empty", hosts, ok)
	}
	for _, text := range []string{`{"hosts": `, ``, `not a policy`} {
		if hosts, ok := liveHostAliases(context.Background(), []byte(text)); ok || hosts != nil {
			t.Errorf("%q: hosts %v, ok %v, want not read", text, hosts, ok)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := liveHostAliases(ctx, []byte(`{"hosts": {}}`)); ok {
		t.Error("a cancelled call read the hosts")
	}
}

// afterCalls is a context that reports its error from the n-th question on.
type afterCalls struct {
	context.Context
	n, asked int
}

func (c *afterCalls) Err() error {
	c.asked++
	if c.asked >= c.n {
		return context.Canceled
	}
	return nil
}

// A call that ends while the live policy is read, wherever it ends, says the hosts were not read, and
// does not go on with a policy it did not finish reading.
func TestLiveHostAliasesSayTheyWereNotReadWhereverTheCallEnds(t *testing.T) {
	text := []byte(`{"hosts": {"example-canary": "192.0.2.1"}, "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`)
	failed := 0
	for n := 1; n <= 40; n++ {
		hosts, ok := liveHostAliases(&afterCalls{Context: context.Background(), n: n}, text)
		if !ok && hosts != nil {
			t.Fatalf("a call that ended after %d questions gave hosts %v and not ok", n, hosts)
		}
		if !ok {
			failed++
		}
	}
	if failed == 0 || failed == 40 {
		t.Errorf("%d of 40 calls ended unread: the question was not asked while the policy was read, or the policy was never read", failed)
	}
}

// A call that ends after the live policy was parsed, while the rules are read, says the hosts were not
// read: a policy it has not read whole is not a policy with no aliases. The text is long enough for
// the reader to ask the context (every 4,096 steps of work) after the parser is done, and the call
// ends at each question the reader asks.
func TestLiveHostAliasesSayTheyWereNotReadWhenOnlyTheReadingOfTheRulesEnds(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"hosts": {"example-canary": "192.0.2.1"}, "groups": {"group:example-big": [`)
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&b, `"user%d@example.com",`, i)
	}
	b.WriteString(`]}}`)
	text := []byte(b.String())
	parsing := &afterCalls{Context: context.Background(), n: 1 << 30}
	if _, err := acl.Parse(parsing, text); err != nil {
		t.Fatal(err)
	}
	whole := &afterCalls{Context: context.Background(), n: 1 << 30}
	if hosts, ok := liveHostAliases(whole, text); !ok || !reflect.DeepEqual(hosts, map[string]string{"example-canary": "192.0.2.1"}) {
		t.Fatalf("the control: hosts %v, ok %v", hosts, ok)
	}
	if whole.asked <= parsing.asked {
		t.Fatalf("the context was asked %d times in all and %d while parsing: the reading of the rules never asks it", whole.asked, parsing.asked)
	}
	for n := parsing.asked + 1; n <= whole.asked; n++ {
		if hosts, ok := liveHostAliases(&afterCalls{Context: context.Background(), n: n}, text); ok || hosts != nil {
			t.Errorf("a call that ended at question %d, in the reading of the rules, gave hosts %v, ok %v, want not read", n, hosts, ok)
		}
	}
}
