package tools

import (
	"context"
	"fmt"
	"io"
	"net/url"

	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// loginPlaceholder is what a Login shows wherever it is printed or encoded.
const loginPlaceholder = "[login]"

// Login is the login name of one user, resolved from a pseudonym. It exists to be sent to
// Tailscale in a request and to go nowhere else while personal data is masked: it
// prints as [login] under every fmt verb, encodes as "[login]" in JSON and text, and keeps
// the name in a function, as privacy.Key keeps its bytes, so that fmt cannot reach it through
// a struct field. Reveal is the one way to read it; its call site is the line that builds the
// request, and a line that puts it anywhere else is the bug.
type Login struct{ reveal func() string }

func newLogin(name string) Login { return Login{reveal: func() string { return name }} }

// Reveal returns the login. Use it only to build the request that goes to Tailscale.
func (l Login) Reveal() string {
	if l.reveal == nil {
		return ""
	}
	return l.reveal()
}

// String is what a Login is called as text.
func (Login) String() string { return loginPlaceholder }

// GoString is what %#v prints.
func (Login) GoString() string { return loginPlaceholder }

// Format keeps the login out of every format verb: fmt calls it before any other way of
// printing, so even the numeric verbs print the placeholder.
func (Login) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, loginPlaceholder) }

// MarshalJSON encodes the placeholder.
func (Login) MarshalJSON() ([]byte, error) { return []byte(`"` + loginPlaceholder + `"`), nil }

// MarshalText encodes the placeholder.
func (Login) MarshalText() ([]byte, error) { return []byte(loginPlaceholder), nil }

// SubjectResolver turns the pseudonym of a user, as a result shows it, into the user's login.
// It is built for one tool call and dropped with it: it reads the tailnet's users
// on first use, holds them for the call, and is never kept or shared, since a long-lived
// process holding every login is the leak this design avoids. The logins it hands out are
// remembered, so that Hide can mask them where Tailscale's reply repeats them. The logins sit
// behind a pointer and Format, so that no fmt verb, and no struct holding a resolver, prints them.
// It is not safe for concurrent use.
type SubjectResolver struct {
	env  *registry.Env
	name func(login string) string // how a login is named; nil means the privacy key's APIPseudonym
	s    *resolverState
}

// resolverState is what a resolver learns. It is a separate type behind a pointer because fmt
// prints a nested pointer as an address. The logins sit one pointer deeper still: a verb that
// does not fit a pointer field (%s, %q) makes fmt print what the pointer points to, and that
// would be the state itself.
type resolverState struct {
	listed bool
	err    error // the failure of the users call, kept so that it is made once
	users  *userLists
}

// userLists holds the tailnet's logins and the ones the resolver handed out.
type userLists struct {
	logins   []string
	resolved []string
}

func newResolverState() *resolverState { return &resolverState{users: &userLists{}} }

// Format keeps every login out of every format verb: fmt calls it before any other way of
// printing, so even the numeric verbs print "subject resolver". The receiver is a value, so
// both a SubjectResolver and a pointer to one print it.
func (SubjectResolver) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "subject resolver") }

// state returns the resolver's state, making it when the resolver was not built by
// NewSubjectResolver.
func (r *SubjectResolver) state() *resolverState {
	if r.s == nil {
		r.s = newResolverState()
	}
	return r.s
}

// NewSubjectResolver returns a resolver for one call.
func NewSubjectResolver(env *registry.Env) *SubjectResolver {
	return &SubjectResolver{env: env, s: newResolverState()}
}

// Resolve returns the login of the one user that ref names. ref is a pseudonym (p:…), the
// bracketed form, or a masked value ending in it. It is an error, validation_failed, when
// ref is none of these, when no user has the pseudonym (the user left, or the privacy key was
// replaced since the pseudonym was shown), or when several do. No message repeats ref.
func (r *SubjectResolver) Resolve(ctx context.Context, ref string) (Login, error) {
	p, ok := privacy.Ref(ref)
	if !ok {
		return Login{}, tkerr.New(tkerr.ValidationFailed, "a user is named by a pseudonym (p:…), or by a masked value that ends in one",
			"take it from a result, for example users_list, as shown there: p: and ten lower-case characters; a login or a masked value with no pseudonym names no one")
	}
	key, err := r.env.RequirePrivacy()
	if err != nil {
		return Login{}, err
	}
	if err := r.load(ctx); err != nil {
		return Login{}, err
	}
	name := r.name
	if name == nil {
		name = key.APIPseudonym
	}
	var match []string
	for _, l := range r.state().users.logins {
		if name(l) == p {
			match = append(match, l)
		}
	}
	switch len(match) {
	case 1:
		st := r.state()
		st.users.resolved = append(st.users.resolved, match[0])
		return newLogin(match[0]), nil
	case 0:
		return Login{}, tkerr.New(tkerr.ValidationFailed, "no user has that pseudonym: the user may have left the tailnet, or the privacy key was replaced since the pseudonym was shown",
			"read the pseudonym again from users_list")
	}
	return Login{}, tkerr.New(tkerr.ValidationFailed, "more than one user has that pseudonym, so it names no one in particular",
		"report this: two logins share a pseudonym under this privacy key")
}

// load reads the tailnet's users once: members and shared users, suspended ones included
// (listUsers has no paging, and a user's status is an attribute, not a filter). A login
// listed twice is one user; logins that differ in case are different users, and if their
// pseudonyms collide Resolve reports more than one. A failed call is remembered for the call.
func (r *SubjectResolver) load(ctx context.Context) error {
	st := r.state()
	if st.listed {
		return nil
	}
	if st.err != nil {
		return st.err
	}
	path, err := tailnetPath(r.env, "/users")
	if err != nil {
		st.err = err
		return err
	}
	var resp struct {
		Users []struct {
			LoginName string `json:"loginName"`
		} `json:"users"`
	}
	if err := get(ctx, r.env, path, url.Values{"type": {"all"}, "role": {"all"}}, &resp); err != nil {
		st.err = usersError(err)
		return st.err
	}
	seen := map[string]bool{}
	for _, u := range resp.Users {
		if u.LoginName == "" || seen[u.LoginName] {
			continue
		}
		seen[u.LoginName] = true
		st.users.logins = append(st.users.logins, u.LoginName)
	}
	st.listed = true
	return nil
}

// usersError names the scope the users call needs when it is refused: the API answers 403,
// or 404 ("the user does not have access to read users"), without users:read.
func usersError(err error) error {
	e, ok := tkerr.As(err)
	if !ok || (e.Code != tkerr.ScopeMissing && e.Status != 404) {
		return err
	}
	return tkerr.New(tkerr.ScopeMissing, "resolving a pseudonym reads the tailnet's users, and the read credential lacks the users:read scope",
		"users:read is optional and used only to resolve a pseudonym: grant it to the read credential, or have the owner set personalData to show")
}
