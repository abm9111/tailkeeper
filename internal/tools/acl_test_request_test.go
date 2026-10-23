package tools_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// sentTest is the one test of a tests-mode request body.
type sentTest struct {
	Src    string   `json:"src"`
	Proto  string   `json:"proto"`
	Accept []string `json:"accept"`
	Deny   []string `json:"deny"`
}

func sentTests(t *testing.T, f *apitest.Fake) []sentTest {
	t.Helper()
	var out []sentTest
	if err := json.Unmarshal([]byte(postBody(t, f)), &out); err != nil {
		t.Fatalf("the request body is not a list of tests: %v", err)
	}
	return out
}

// Which destinations go in accept and which in deny is what the whole answer is read
// against. A swap would send every test inverted, and the fake cannot tell.
func TestTheRequestCarriesAcceptInAcceptAndDenyInDeny(t *testing.T) {
	f, reg, env := apiEnv(t)
	servePass(f)
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","proto":"tcp","accept":["tag:web:22","100.64.0.5:443"],"deny":["tag:db:5432","tag:db:5433","[fd7a:115c:a1e0::5]:22"]}`, nil)
	got := sentTests(t, f)
	if len(got) != 1 || got[0].Src != "tag:ci" || got[0].Proto != "tcp" ||
		!slices.Equal(got[0].Accept, []string{"tag:web:22", "100.64.0.5:443"}) ||
		!slices.Equal(got[0].Deny, []string{"tag:db:5432", "tag:db:5433", "[fd7a:115c:a1e0::5]:22"}) {
		t.Fatalf("request = %+v", got)
	}
	// A call with deny alone and one with accept alone put the destinations on their own side.
	for args, want := range map[string]sentTest{
		`{"src":"tag:ci","deny":["tag:db:5432"]}`:  {Src: "tag:ci", Deny: []string{"tag:db:5432"}},
		`{"src":"tag:ci","accept":["tag:web:22"]}`: {Src: "tag:ci", Accept: []string{"tag:web:22"}},
	} {
		f, reg, env := apiEnv(t)
		servePass(f)
		mustCall(t, reg, env, "acl_test", args, nil)
		got := sentTests(t, f)
		if len(got) != 1 || got[0].Src != want.Src || !slices.Equal(got[0].Accept, want.Accept) || !slices.Equal(got[0].Deny, want.Deny) {
			t.Errorf("%s: request = %+v", args, got)
		}
	}
}

// The same when the destinations are pseudonyms: each is split from its port, resolved,
// and joined to its own port again on its own side.
func TestTheRequestKeepsEachResolvedDestinationOnItsOwnSideAndPort(t *testing.T) {
	const amy, bob, carol = "ops/amy@example.com", "bob@example.org", "carol@example.com"
	f, reg, env := apiEnv(t)
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		t.Fatal(err)
	}
	env.Privacy = k
	f.JSON("GET", tailnetPath+"/users", 200, `{"users":[{"id":"u1","loginName":"`+amy+`","type":"member"},{"id":"u2","loginName":"`+bob+`","type":"member"},{"id":"u3","loginName":"`+carol+`","type":"member"}]}`)
	servePass(f)
	args := `{"src":` + jsonString(k.APIPseudonym(amy)) + `,"accept":[` + jsonString(k.APIPseudonym(bob)+":22") + `],"deny":[` + jsonString(k.APIPseudonym(carol)+":443") + `,"tag:db:5432"]}`
	mustCall(t, reg, env, "acl_test", args, nil)
	got := sentTests(t, f)
	if len(got) != 1 || got[0].Src != amy || !slices.Equal(got[0].Accept, []string{bob + ":22"}) || !slices.Equal(got[0].Deny, []string{carol + ":443", "tag:db:5432"}) {
		t.Fatalf("request = %+v", got)
	}
}

// A host alias that the server quotes as its address is read back to the alias through the
// policy's hosts section. With no hosts section the line names nobody, and nothing is allowed.
func TestAHostAliasQuotedAsItsAddressIsReadThroughTheHostsSection(t *testing.T) {
	const line = `[acl test error]: address "192.0.2.10:443" (protocol "tcp"): want: Accept, got: Drop`
	args := `{"src":"tag:ci","proto":"tcp","accept":["web:443"]}`

	f, reg, env := apiEnv(t)
	f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{line}}))
	servePolicy(f, "{\"hosts\": {\"web\": \"192.0.2.10\"}}\n", `"e1"`)
	var out tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", args, &out)
	if out.Status != "fail" || out.ExitCode() != 9 || len(out.Verdicts) != 1 || out.Verdicts[0].Dst != "web:443" ||
		out.Verdicts[0].Verdict != "denied" || out.Verdicts[0].Why != "the server quoted the address of this host alias" || len(out.Unmatched) != 0 {
		t.Fatalf("with hosts: %+v", out)
	}
	if !slices.Contains(out.Caveats, "the server may quote a host alias as its address") {
		t.Errorf("caveats = %q", out.Caveats)
	}

	f, reg, env = apiEnv(t)
	f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{line}}))
	servePolicy(f, "{}\n", `"e1"`)
	var bare tools.ACLTestOutput
	mustCall(t, reg, env, "acl_test", args, &bare)
	if bare.Status != "unknown" || len(bare.Verdicts) != 1 || bare.Verdicts[0].Verdict != "unknown" || len(bare.Unmatched) != 1 {
		t.Fatalf("without hosts: %+v", bare)
	}
}

// Every sentence a result can carry as a caveat is stated by a real call, and a call
// that needs none states none.
func TestEveryCaveatTheResultCanCarryIsStatedByACallThatNeedsIt(t *testing.T) {
	seen := map[string]bool{}
	note := func(label string, out tools.ACLTestOutput, want ...string) {
		t.Helper()
		if !slices.Equal(out.Caveats, want) {
			t.Errorf("%s: caveats %q, want %q", label, out.Caveats, want)
		}
		for _, c := range out.Caveats {
			seen[c] = true
		}
	}
	const (
		protoOmitted = "with proto omitted, a destination that must be denied can yield one line for tcp and one for udp"
		bothLists    = "a destination in accept and in deny is told apart by the line's got word"
		hostAddress  = "the server may quote a host alias as its address"
		groupSource  = "a group: source in an SSH test can be reported denied when the user is in the group (tailscale/tailscale#11790)"
		liveInvalid  = "the live policy does not validate"
		sshRefused   = "your SSH tests were refused"
	)
	var out tools.ACLTestOutput

	f, reg, env := apiEnv(t)
	servePass(f)
	out = tools.ACLTestOutput{}
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","accept":["tag:web:22"]}`, &out)
	note("an accept-only call", out)

	f, reg, env = apiEnv(t)
	servePass(f)
	out = tools.ACLTestOutput{}
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","proto":"tcp","deny":["tag:db:5432"]}`, &out)
	note("a deny call with proto", out)

	f, reg, env = apiEnv(t)
	servePass(f)
	out = tools.ACLTestOutput{}
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","deny":["tag:db:5432"]}`, &out)
	note("a deny call with no proto", out, protoOmitted)

	f, reg, env = apiEnv(t)
	f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{
		`[acl test error]: address "tag:db:22" (protocol "tcp"): want: Accept, got: Drop`}}))
	servePolicy(f, "{}\n", `"e1"`)
	out = tools.ACLTestOutput{}
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","proto":"tcp","accept":["tag:db:22"],"deny":["tag:db:22"]}`, &out)
	note("a destination in both lists", out, bothLists)

	f, reg, env = apiEnv(t)
	f.ServeValidate(apitest.TestsFailed(apitest.Entry{User: "tag:ci", Errors: []string{
		`[acl test error]: address "192.0.2.10:443" (protocol "tcp"): want: Accept, got: Drop`}}))
	servePolicy(f, "{\"hosts\": {\"web\": \"192.0.2.10\"}}\n", `"e1"`)
	out = tools.ACLTestOutput{}
	mustCall(t, reg, env, "acl_test", `{"src":"tag:ci","proto":"tcp","accept":["web:443"]}`, &out)
	note("a host alias quoted as its address", out, hostAddress)

	f, reg, env = apiEnv(t)
	serveSSH(f, "{}\n", func(tag string) apitest.Shape {
		return apitest.TestsFailed(apitest.Entry{User: tag, Errors: []string{canaryLine}})
	})
	out = tools.ACLTestOutput{}
	mustCall(t, reg, env, "acl_test", `{"src":"group:eng","ssh":[{"dst":["tag:db"],"accept":["root"]}]}`, &out)
	note("an SSH test of a group", out, groupSource)

	for label, c := range map[string]struct {
		second apitest.Shape
		want   string
	}{
		"a live policy that does not validate": {apitest.PolicyUnknownField("nodeAttr"), liveInvalid},
		"SSH tests that were refused":          {apitest.TestsPassEmptyObject(), sshRefused},
	} {
		f, reg, env = apiEnv(t)
		servePolicy(f, "{\"acls\":[]}\n", `"e1"`)
		n := 0
		f.Handle("POST", apitest.ValidatePath, func(w http.ResponseWriter, r *http.Request) {
			n++
			if n == 1 {
				apitest.PolicyUnknownField("nodeAttr").Write(w)
				return
			}
			c.second.Write(w)
		})
		out = tools.ACLTestOutput{}
		mustCall(t, reg, env, "acl_test", sshCall("tag:db", "root", "accept"), &out)
		note(label, out, c.want)
	}

	for _, want := range aclClosedLists["ACLTestOutput.Caveats"] {
		if !seen[want] {
			t.Errorf("no call states the caveat %q", want)
		}
	}
}

// The posture names come from the policy, and a policy may name a user. The names go through
// the resolver's mask like any other text of the policy, so two logins of different lengths
// give one list, and what the layout prints of them is behind the untrusted notice.
func TestPostureNamesAreMaskedLikeAnyOtherTextOfThePolicy(t *testing.T) {
	var lists [][]string
	for _, login := range []string{"amy@example.com", "amy-zzzzqqqqmuchlongerlocalpart@example.com"} {
		local, _, _ := strings.Cut(login, "@")
		f, reg, env := apiEnv(t)
		k, err := privacy.Parse(strings.Repeat("5a", 32))
		if err != nil {
			t.Fatal(err)
		}
		env.Privacy = k
		f.JSON("GET", tailnetPath+"/users", 200, `{"users":[{"id":"u1","loginName":"`+login+`","type":"member"}]}`)
		f.ServeValidate(apitest.TestsPass())
		servePolicy(f, `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"],"srcPosture":[`+
			jsonString(local)+`,`+jsonString(login)+`,"::add-mask::"]}]}`+"\n", `"e1"`)
		var out tools.ACLTestOutput
		s := mustCall(t, reg, env, "acl_test", `{"src":`+jsonString(k.APIPseudonym(login))+`,"accept":["tag:web:22"]}`, &out)
		absent(t, s, "amy", "zzzz")
		if out.Posture != "gated" || len(out.PosturesNeeded) != 3 {
			t.Fatalf("posture %q, names %q", out.Posture, out.PosturesNeeded)
		}
		lists = append(lists, out.PosturesNeeded)
		rep := out.Report()
		trusted := append([]string{}, rep.NotChecked...)
		for _, f := range rep.Facts {
			trusted = append(trusted, f.Text)
		}
		for _, n := range trusted {
			if strings.Contains(n, "amy") || strings.Contains(n, "add-mask") || strings.Contains(n, "attributes needed") {
				t.Errorf("a policy string is in the trusted lines of the report: %q", n)
			}
		}
		named := 0
		for _, fnd := range rep.Findings {
			if strings.HasPrefix(fnd.Message, "posture attribute needed: ") {
				named++
				if !fnd.Untrusted {
					t.Errorf("a posture name is a trusted finding: %+v", fnd)
				}
			}
		}
		if named != 3 {
			t.Errorf("%d posture findings, want 3: %+v", named, rep.Findings)
		}
	}
	if !slices.Equal(lists[0], lists[1]) {
		t.Errorf("the two logins give different lists:\n%q\n%q", lists[0], lists[1])
	}
}
