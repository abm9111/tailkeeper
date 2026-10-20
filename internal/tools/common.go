// Package tools defines tailkeeper's tools. M1 contains the read tools for the
// Tailscale API and the node's local CLI (spec §6, §18).
package tools

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Register adds every M1 tool to r.
func Register(r *registry.Registry) {
	r.MustAdd(deviceTools()...)
	r.MustAdd(settingsTools()...)
	r.MustAdd(dnsTools()...)
	r.MustAdd(keyTools()...)
	r.MustAdd(userTools()...)
	r.MustAdd(inviteTools()...)
	r.MustAdd(logTools()...)
	r.MustAdd(integrationTools()...)
	r.MustAdd(localTools()...)
	r.MustAdd(aclTools()...)
}

func readMeta(name, area, verb, summary string, scopes ...string) registry.Meta {
	return registry.Meta{
		Name: name, Area: area, Verb: verb, Summary: summary,
		Tier: registry.TierRead, Stage: registry.StageGA, Credential: registry.CredRead, Scopes: scopes,
	}
}

// withOps declares the API operations a tool calls (spec §20).
func withOps(m registry.Meta, ops ...string) registry.Meta {
	m.Operations = ops
	return m
}

func get(ctx context.Context, env *registry.Env, path string, q url.Values, out any) error {
	c, err := env.RequireAPI()
	if err != nil {
		return err
	}
	return c.Get(ctx, path, q, out)
}

func tailnetPath(env *registry.Env, suffix string) (string, error) {
	c, err := env.RequireAPI()
	if err != nil {
		return "", err
	}
	return c.TailnetPath(suffix), nil
}

var (
	nodeIDRE   = regexp.MustCompile(`^n[A-Za-z0-9]{3,}CNTRL$`)
	legacyIDRE = regexp.MustCompile(`^[0-9]{3,}$`)
	plainIDRE  = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
)

// requireID validates an opaque identifier taken from a caller before it goes into
// a URL path. Path segments are also escaped, so this is defence in depth.
func requireID(field, v string) error {
	if !plainIDRE.MatchString(v) {
		return tkerr.New(tkerr.ValidationFailed, field+" must be 1-128 characters of letters, digits, '.', '_', ':' or '-'", "")
	}
	return nil
}

// keylessHint is what a refusal says when there is no privacy key: pseudonyms exist only with
// one, so no refusal may send the caller to a pseudonym.
const keylessHint = "masked values carry pseudonyms only when a privacy key is configured (README, Privacy key); the owner can also set personalData to show"

// keyless reports whether no privacy key is loaded. A nil Env has none.
func keyless(env *registry.Env) bool { return env == nil || env.Privacy == nil }

// filterRefused refuses a literal filter that would confirm a guessed personal
// value while masking is on (spec Appendix C): a match would tell the caller the
// guess was right. takesIDs says the filter also takes exact IDs. The message
// names the filter and never what the caller typed: an echo of a guess is an
// oracle.
func filterRefused(env *registry.Env, name string, takesIDs bool) error {
	takes := "a pseudonym (p:…)"
	if takesIDs {
		takes = "an exact ID or a pseudonym (p:…)"
	}
	hint := "pass the pseudonym shown after a masked value, or the masked value itself; the owner can set personalData to show"
	if keyless(env) {
		hint = keylessHint
	}
	if takesIDs {
		hint = "pass an exact ID; or " + hint
	}
	return tkerr.New(tkerr.FilterRefused,
		"while personal data is masked, "+name+" takes "+takes+", not a name or an address: a match would confirm a guess", hint)
}

func validationf(msg string) error { return tkerr.New(tkerr.ValidationFailed, msg, "") }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// parseWindow resolves an RFC 3339 start/end pair with defaults and a maximum span.
func parseWindow(now time.Time, start, end string, defaultSpan, maxSpan time.Duration) (time.Time, time.Time, error) {
	e := now
	if end != "" {
		t, err := time.Parse(time.RFC3339Nano, end)
		if err != nil {
			return time.Time{}, time.Time{}, validationf("end must be an RFC 3339 time")
		}
		e = t
	}
	s := e.Add(-defaultSpan)
	if start != "" {
		t, err := time.Parse(time.RFC3339Nano, start)
		if err != nil {
			return time.Time{}, time.Time{}, validationf("start must be an RFC 3339 time")
		}
		s = t
	}
	if !s.Before(e) {
		return time.Time{}, time.Time{}, validationf("start must be before end")
	}
	if e.Sub(s) > maxSpan {
		return time.Time{}, time.Time{}, validationf("the window may span at most " + maxSpan.String())
	}
	return s, e, nil
}

func lower(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(s)
	}
	return out
}
