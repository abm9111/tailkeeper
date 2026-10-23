package tools

import (
	"context"
	"regexp"
	"strings"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// syncedGroupSubjectRE is a whole test subject that is one synced group: group:,
// then a name that may hold spaces, then one @ and a domain. MaskEmails cannot see
// the space form as a group (a space ends the local part), so the subject check
// recognises the whole field itself.
var syncedGroupSubjectRE = regexp.MustCompile(`^group:(?:[^\s@]+(?:\s+[^\s@]+)*)@[^\s@]+$`)

// testSubjects is a source and its destinations after pseudonym carriers have been
// replaced by the logins they name. Shown maps each substituted string, as it will
// be sent, back to the text the caller wrote. A caller strips ports before calling
// resolveTestSubjects; screenTestSubjects reads a destination's host itself.
type testSubjects struct {
	Src   string
	Dsts  []string
	Shown map[string]string
}

// screenTestSubjects refuses a literal login in src, or in a destination's host,
// while masking is on. A pseudonym carrier, a synced group and a subject that is
// not a login pass. personalData show passes everything.
func screenTestSubjects(env *registry.Env, src string, dsts []string) error {
	if err := refuseCredentialShape("src", src); err != nil {
		return err
	}
	for _, d := range dsts {
		if err := refuseCredentialShape("a destination", d); err != nil {
			return err
		}
	}
	if env != nil && env.ShowPersonalData() {
		return nil
	}
	if err := refuseLiteralSubject(env, "src", src); err != nil {
		return err
	}
	for _, d := range dsts {
		// The whole destination is screened, a carrier host included: text after a carrier
		// (a comma, a space, a second login) is not a port, and a login with a port behind it
		// is a login to the scan that masks.
		if err := refuseLiteralSubject(env, "a destination", d); err != nil {
			return err
		}
	}
	return nil
}

func refuseLiteralSubject(env *registry.Env, name, value string) error {
	if !literalTestSubject(value) {
		return nil
	}
	return filterRefused(env, name, false)
}

// literalTestSubject reports whether value is a user login the masker would hide.
// A carrier and a whole-field synced group are not.
func literalTestSubject(value string) bool {
	if value == "" {
		return false
	}
	if _, carrier, _ := carrierRef(value); carrier {
		return false
	}
	if syncedGroupSubjectRE.MatchString(value) {
		return false
	}
	return IsLiteralLogin(value)
}

// subjectHost is the host of a destination. A destination whose port is not one
// number still yields the text before its last colon, so a login is not hidden
// behind a port range.
func subjectHost(d string) string {
	if h, _, err := splitDestination(d); err == nil {
		return h
	}
	if strings.HasPrefix(d, "[") {
		if end := strings.Index(d, "]:"); end > 0 {
			return d[:end+1]
		}
	}
	if i := strings.LastIndexByte(d, ':'); i > 0 {
		return d[:i]
	}
	return d
}

// resolveTestSubjects replaces each pseudonym carrier in src and dsts with the
// login it names and leaves every other string unchanged. dsts are hosts: the
// caller strips ports first. Shown maps a substituted login back to the carrier
// the caller wrote. One resolver serves every carrier, so the users list is read
// once. A string that holds a marker and is not a carrier is validation_failed.
func resolveTestSubjects(ctx context.Context, res *SubjectResolver, src string, dsts []string) (testSubjects, error) {
	out := testSubjects{Shown: map[string]string{}}
	sent, written, err := resolveOneSubject(ctx, res, src)
	if err != nil {
		return testSubjects{}, err
	}
	out.Src = sent
	if written != "" {
		out.Shown[sent] = written
	}
	out.Dsts = make([]string, len(dsts))
	for i, d := range dsts {
		sent, written, err = resolveOneSubject(ctx, res, d)
		if err != nil {
			return testSubjects{}, err
		}
		out.Dsts[i] = sent
		if written != "" {
			out.Shown[sent] = written
		}
	}
	return out, nil
}

func resolveOneSubject(ctx context.Context, res *SubjectResolver, value string) (sent, written string, err error) {
	ref, carrier, holds := carrierRef(value)
	if holds {
		return "", "", tkerr.New(tkerr.ValidationFailed,
			"a test subject holds a pseudonym marker without being a pseudonym",
			"write a user as a result shows them, alone: p:…, [p:…], or the masked address followed by [p:…]")
	}
	if !carrier {
		return value, "", nil
	}
	login, err := res.Resolve(ctx, ref)
	if err != nil {
		return "", "", err
	}
	return login.Reveal(), value, nil
}
