package doctor

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tailscale/hujson"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

func starterPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "invariants.hujson")
}

func serveKey(f *apitest.Fake, body string) {
	f.JSON("GET", keyPath, 200, body)
}

func serveAdmins(f *apitest.Fake, owner, admin string) {
	f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/users", func(w http.ResponseWriter, r *http.Request) {
		var login, role string
		switch r.URL.Query().Get("role") {
		case "owner":
			login, role = owner, "owner"
		case "admin":
			login, role = admin, "admin"
		default:
			w.WriteHeader(404)
			return
		}
		if r.URL.Query().Get("type") != "all" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`{"users":[{"loginName":"` + login + `","role":"` + role + `"}]}`))
	})
}

func TestTheStarterIsHuJSONWithOnlyTestsAndSSHTests(t *testing.T) {
	_, a := newApp(t, allReadScopes(t))
	a.KeyID = ""
	path := starterPath(t)
	res, err := WriteStarter(context.Background(), a, StarterInput{Out: path, Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Tests != 1 || res.SSHTests != 0 || res.Path != path {
		t.Fatalf("result = %+v", res)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acl.Parse(context.Background(), body); err != nil {
		t.Fatalf("parse: %v\n%s", err, body)
	}
	root, err := hujson.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	obj, ok := root.Value.(*hujson.Object)
	if !ok {
		t.Fatalf("root is %T", root.Value)
	}
	var keys []string
	for _, m := range obj.Members {
		lit, ok := m.Name.Value.(hujson.Literal)
		if !ok {
			t.Fatal("member name is not a literal")
		}
		keys = append(keys, lit.String())
	}
	if strings.Join(keys, ",") != "tests,sshTests" {
		t.Errorf("keys = %v", keys)
	}
	if !bytesContain(body, `"sshTests": []`) || !bytesContain(body, sshTestsComment) {
		t.Errorf("sshTests:\n%s", body)
	}
	// The same bytes are the golden the validator test reads.
	golden, err := os.ReadFile(filepath.Join("..", "tools", "testdata", "starter.hujson"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(golden) {
		t.Errorf("starter differs from the golden:\n%s", body)
	}
}

func TestTheStarterNamesTheTagsAndGroupsGivenAndTheCredentialsOwnTags(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	serveKey(f, `{"id":"test-client-id","keyType":"client","tags":["tag:db","tag:web"]}`)
	path := starterPath(t)
	res, err := WriteStarter(context.Background(), a, StarterInput{
		Out: path, Tags: []string{"tag:web", "tag:ci"}, AdminGroups: []string{"group:ops", "group:admins"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.CredTags != credTagsRead || res.Tests != 6 {
		t.Fatalf("result = %+v, want credTags %s and 6 tests (2 groups × 3 tags)", res, credTagsRead)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"src":"group:admins","accept":["tag:ci:22"]`,
		`"src":"group:admins","accept":["tag:db:22"]`,
		`"src":"group:admins","accept":["tag:web:22"]`,
		`"src":"group:ops","accept":["tag:ci:22"]`,
		`"src":"group:ops","accept":["tag:db:22"]`,
		`"src":"group:ops","accept":["tag:web:22"]`,
	} {
		if !bytesContain(body, want) {
			t.Errorf("missing %s\n%s", want, body)
		}
	}
}

func TestWhenTheKeyRecordCannotBeReadTheStarterSaysSoAndNamesTheScopes(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	f.JSON("GET", keyPath, 403, `{"message":"forbidden"}`)
	path := starterPath(t)
	res, err := WriteStarter(context.Background(), a, StarterInput{Out: path, Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.CredTags != credTagsUnreadable || !strings.Contains(res.CredTags, "oauth_keys:read") || !strings.Contains(res.CredTags, "federated_keys:read") {
		t.Fatalf("credTags = %q", res.CredTags)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesContain(body, `"src":"group:admins","accept":["tag:web:22"]`) {
		t.Errorf("the named tag is still written:\n%s", body)
	}
}

func TestWhenTheKeyRecordIsNotFoundTheStarterSaysSoAndDoesNotAskForAScope(t *testing.T) {
	_, a := newApp(t, allReadScopes(t)) // no key route: the record is not found
	res, err := WriteStarter(context.Background(), a, StarterInput{Out: starterPath(t), Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.CredTags != credTagsNotFound || strings.Contains(res.CredTags, "oauth_keys:read") {
		t.Fatalf("credTags = %q", res.CredTags)
	}
}

func TestWithLoginsWithoutUsersReadNamesTheOptionalScope(t *testing.T) {
	f, a := newApp(t, "devices:core:read")
	serveKey(f, `{"id":"test-client-id","keyType":"client","tags":["tag:web"]}`)
	path := starterPath(t)
	_, err := WriteStarter(context.Background(), a, StarterInput{Out: path, Tags: []string{"tag:web"}, WithLogins: true})
	if tkerr.From(err).Code != tkerr.ScopeMissing || !strings.Contains(tkerr.From(err).Message, "users:read") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("file created on a missing scope: %v", statErr)
	}
	for _, req := range f.Requests() {
		if strings.Contains(req.Path, "/users") {
			t.Errorf("users were requested without the scope: %s", req.Path)
		}
	}
}

func TestTheStarterListsWhatInvariantsCannotTest(t *testing.T) {
	_, a := newApp(t, allReadScopes(t))
	a.KeyID = ""
	res, err := WriteStarter(context.Background(), a, StarterInput{Out: starterPath(t), Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Untestable, "\n") != strings.Join(untestableControls, "\n") {
		t.Fatalf("untestable = %v", res.Untestable)
	}
	body, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range untestableControls {
		if !bytesContain(body, "// - "+c) {
			t.Errorf("file omits %q", c)
		}
	}
	if !bytesContain(body, "template the owner edits") {
		t.Errorf("header:\n%s", body)
	}
}

func TestDoctorPolicyWritesNothingToTheAuditLogButItsOwnLine(t *testing.T) {
	const short, long = "o@example.com", "administrator.with.a.longer.login@example.com"
	f, a := newApp(t, allReadScopes(t))
	serveKey(f, `{"id":"test-client-id","keyType":"client","tags":["tag:web"]}`)
	serveAdmins(f, short, long)
	path := starterPath(t)
	if _, err := WriteStarter(context.Background(), a, StarterInput{Out: path, AdminGroups: []string{"group:admins"}, WithLogins: true}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(a.Audit.Path())
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if strings.Contains(text, short) || strings.Contains(text, long) || strings.Contains(text, "group:admins") || strings.Contains(text, `"tests"`) {
		t.Fatalf("audit log holds a login, a group or the file:\n%s", text)
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	got := map[string]int{}
	for _, line := range lines {
		switch {
		case strings.Contains(line, `"tool":"key_get"`):
			got["key_get"]++
		case strings.Contains(line, `"tool":"doctor.users"`):
			got["doctor.users"]++
		case strings.Contains(line, `"tool":"doctor.policy"`):
			got["doctor.policy"]++
		default:
			t.Errorf("unexpected audit line: %s", line)
		}
		if strings.Contains(line, `"tool":"doctor.`) && !strings.Contains(line, `"bytes":0`) {
			t.Errorf("a size computed on tailnet text: %s", line)
		}
	}
	if got["key_get"] != 1 || got["doctor.users"] != 2 || got["doctor.policy"] != 1 || len(lines) != 4 {
		t.Errorf("lines = %v (%d)", got, len(lines))
	}
}

func TestLoginsAreWrittenOnlyWithWithLogins(t *testing.T) {
	const short, long = "o@example.com", "administrator.with.a.longer.login@example.com"
	write := func(with bool) string {
		f, a := newApp(t, allReadScopes(t))
		serveKey(f, `{"id":"test-client-id","keyType":"client"}`)
		serveAdmins(f, short, long)
		path := starterPath(t)
		res, err := WriteStarter(context.Background(), a, StarterInput{Out: path, Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"}, WithLogins: with})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(res.CredTags, "@") || strings.Contains(strings.Join(res.Untestable, " "), "@") {
			t.Fatalf("result carries a login: %+v", res)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	without, with := write(false), write(true)
	if strings.Contains(without, short) || strings.Contains(without, long) || strings.Contains(without, "@") {
		t.Fatalf("logins written without the flag:\n%s", without)
	}
	if !strings.Contains(with, `"src":"`+short+`","accept":["tag:web:22"]`) || !strings.Contains(with, `"src":"`+long+`","accept":["tag:web:22"]`) {
		t.Fatalf("logins missing:\n%s", with)
	}
}

func TestAUsersReadErrorIsMasked(t *testing.T) {
	got := map[int]string{}
	for _, n := range []int{8, 40} {
		login := strings.Repeat("a", n) + "@example.com"
		f, a := newApp(t, allReadScopes(t))
		serveKey(f, `{"id":"test-client-id","keyType":"client"}`)
		f.JSON("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/users", 500, `{"message":"user `+login+` cannot be listed"}`)
		_, err := WriteStarter(context.Background(), a, StarterInput{Out: starterPath(t), Tags: []string{"tag:web"}, AdminGroups: []string{"group:eng"}, WithLogins: true})
		if err == nil || strings.Contains(err.Error(), login) || strings.Contains(err.Error(), "[p:") {
			t.Fatalf("n=%d: %v", n, err)
		}
		got[n] = err.Error()
	}
	if got[8] == "" || got[8] != got[40] {
		t.Fatalf("the error tells the length:\n%s\n%s", got[8], got[40])
	}
}

func bytesContain(b []byte, s string) bool { return strings.Contains(string(b), s) }

func noUsers(f *apitest.Fake) {
	f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"users":[]}`))
	})
}

func TestAStarterThatWouldHoldNoTestIsRefusedAndNoFileIsWritten(t *testing.T) {
	for _, c := range []struct {
		name string
		key  string // the key record; empty means the record is not readable
		in   StarterInput
		want string // a flag the error tells the owner to pass
	}{
		{"no source named", `{"id":"test-client-id","keyType":"client","tags":["tag:web"]}`, StarterInput{Tags: []string{"tag:web"}}, "--admin-group"},
		{"no tag named or on the key", `{"id":"test-client-id","keyType":"client"}`, StarterInput{AdminGroups: []string{"group:admins"}}, "--tag"},
		{"no tag named and the key record unreadable", "", StarterInput{AdminGroups: []string{"group:admins"}}, "--tag"},
		{"logins asked for and none found", `{"id":"test-client-id","keyType":"client","tags":["tag:web"]}`, StarterInput{WithLogins: true}, "--admin-group"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, a := newApp(t, allReadScopes(t))
			if c.key != "" {
				serveKey(f, c.key)
			}
			noUsers(f)
			c.in.Out = starterPath(t)
			_, err := WriteStarter(context.Background(), a, c.in)
			if err == nil {
				t.Errorf("a starter with no test was written")
			} else if e := tkerr.From(err); e.Code != tkerr.Usage || !strings.Contains(e.Hint, c.want) || !strings.Contains(e.Hint, "--tag") {
				t.Errorf("err = %v, hint %q; want a usage error that names %s and --tag", err, e.Hint, c.want)
			}
			if _, statErr := os.Stat(c.in.Out); !os.IsNotExist(statErr) {
				t.Errorf("a file was written for a starter with no test: %v", statErr)
			}
		})
	}
}

func TestAStarterWithNoSourceIsRefusedBeforeAnyRequest(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	serveKey(f, `{"id":"test-client-id","keyType":"client","tags":["tag:web"]}`)
	in := StarterInput{Out: starterPath(t), Tags: []string{"tag:web"}}
	if err := CheckStarterInput(in); err == nil || tkerr.From(err).Code != tkerr.Usage || !strings.Contains(tkerr.From(err).Hint, "--admin-group") {
		t.Fatalf("CheckStarterInput = %v", err)
	}
	if _, err := WriteStarter(context.Background(), a, in); err == nil {
		t.Fatal("a starter with no source was written")
	}
	if n := len(f.Requests()) + f.TokenRequests(); n != 0 {
		t.Errorf("%d requests were made for a starter with no source", n)
	}
}

func TestAnExistingFileOrDirectoryIsRefusedBeforeAnyRequest(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	dir := t.TempDir()
	file := filepath.Join(dir, "invariants.hujson")
	if err := os.WriteFile(file, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{file: "already exists", dir: "directory"} {
		in := StarterInput{Out: path, Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"}}
		if err := CheckStarterInput(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckStarterInput(%s) = %v, want %q", filepath.Base(path), err, want)
		}
		if _, err := WriteStarter(context.Background(), a, in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("WriteStarter(%s) = %v, want %q", filepath.Base(path), err, want)
		}
	}
	if n := len(f.Requests()) + f.TokenRequests(); n != 0 {
		t.Errorf("%d requests were made for a path the starter refuses", n)
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "{}\n" {
		t.Fatalf("the existing file was changed: %q %v", b, err)
	}
}

// A users list that ignores the role filter must not put a member in the starter: the
// starter accepts owners and admins only, so a login of any other role is refused.
func TestAUserOfAnotherRoleIsNeverWrittenIntoTheStarter(t *testing.T) {
	for _, role := range []string{"member", "admin", "owner", ""} {
		for _, asked := range []string{"owner", "admin"} {
			if role == asked {
				continue
			}
			t.Run(asked+" list holding "+role, func(t *testing.T) {
				f, a := newApp(t, allReadScopes(t))
				serveKey(f, `{"id":"test-client-id","keyType":"client"}`)
				f.Handle("GET", "/api/v2/tailnet/"+apitest.Tailnet+"/users", func(w http.ResponseWriter, r *http.Request) {
					r2 := role
					body := `{"users":[{"loginName":"o@example.com","role":"` + r2 + `"}]}`
					if r.URL.Query().Get("role") != asked {
						body = `{"users":[]}`
					}
					_, _ = w.Write([]byte(body))
				})
				path := starterPath(t)
				_, err := WriteStarter(context.Background(), a, StarterInput{Out: path, Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"}, WithLogins: true})
				if err == nil || !strings.Contains(err.Error(), "cannot write") {
					t.Fatalf("a %q login in the %s list: %v", role, asked, err)
				}
				if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
					t.Errorf("a file was written: %v", statErr)
				}
			})
		}
	}
}

// A login that carries a pseudonym is the masked form of a login, not a login: writing it
// would put a name no policy knows into a test.
func TestAMaskedLoginIsNeverWrittenIntoTheStarter(t *testing.T) {
	for _, login := range []string{"a…@example.com[p:k7x2m9qd4a]", "a…[p:k7x2m9qd4a]@example.com"} {
		t.Run(login, func(t *testing.T) {
			f, a := newApp(t, allReadScopes(t))
			serveKey(f, `{"id":"test-client-id","keyType":"client"}`)
			serveAdmins(f, login, "admin@example.com")
			path := starterPath(t)
			_, err := WriteStarter(context.Background(), a, StarterInput{Out: path, Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"}, WithLogins: true})
			if err == nil || !strings.Contains(err.Error(), "cannot write") {
				t.Fatalf("err = %v, want the users list refused", err)
			}
			if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
				t.Errorf("a file was written: %v", statErr)
			}
		})
	}
}

// The creation refuses a path that appeared after the early check, whatever it is: the
// check and the creation are two steps, so the open itself must fail on an existing file and
// must not follow a link planted there.
func TestTheStarterIsOpenedOnlyAsANewFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.hujson")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{"an existing file": target}
	// A link needs a privilege on some systems; where it cannot be made the file case still runs.
	link := filepath.Join(dir, "link.hujson")
	dangling := filepath.Join(dir, "dangling.hujson")
	if os.Symlink(target, link) == nil && os.Symlink(filepath.Join(dir, "never-created.hujson"), dangling) == nil {
		paths["a link to a file"], paths["a link to nothing"] = link, dangling
	}
	for name, path := range paths {
		f, err := openNew(path)
		if err == nil {
			_ = f.Close()
			t.Errorf("%s: the open succeeded", name)
			continue
		}
		if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("%s: %v, want it to say the path already exists", name, err)
		}
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "keep\n" {
		t.Errorf("the file a path led to was changed: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "never-created.hujson")); !os.IsNotExist(err) {
		t.Errorf("a file was created through a dangling link: %v", err)
	}
}
