package doctor

import (
	"context"
	"encoding/json"
	"regexp"

	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/tools"
	"github.com/tailscale/hujson"
)

// probeKinds are the destination kinds a test can read. The destination of a tag
// and of a host alias comes from the live policy; the others are documentation
// addresses. ICMP uses port 0. Kinds Tailscale refuses are not in this list.
var probeKinds = []struct {
	Name, Proto, Dst string
}{
	{"tag", "", ""},
	{"host alias", "", ""},
	{"IPv4 address", "", "192.0.2.10:22"},
	{"IPv6 address", "", "[2001:db8::1]:22"},
	{"ICMP, port 0", "icmp", "192.0.2.10:0"},
}

// policyProbeNames are the probe rows a run with no credential skips, so a missing
// row is never read as a pass.
var policyProbeNames = []string{
	"probe policy rejection",
	"probe details keys",
	"probe invariants canary",
	"probe ssh tests",
	"probe tag",
	"probe host alias",
	"probe IPv4 address",
	"probe IPv6 address",
	"probe ICMP, port 0",
	"probe kinds refused",
}

// svcSelectors finds each svc: selector written as its own JSON string, whatever follows
// the prefix; svcNameRE is the name a kind probe may send, the rule of a tag. Anything else,
// a comment or a longer token, is a service this probe does not name, and the row says so.
var (
	svcSelectors = regexp.MustCompile(`"(svc:[^"]*)"`)
	svcNameRE    = regexp.MustCompile(`^svc:[A-Za-z0-9][A-Za-z0-9-]{0,99}$`)
)

// canaryTagRE and hostAliasRE are the names a kind probe may send: letters, digits and the
// separators a name is written with, short enough to reach Tailscale whole. A name the
// summary cut, or one that holds something the masker would rewrite, is not sent, because
// the answer would be about a different name.
var (
	hostAliasRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	kindsRefused = "CIDR and autogroup:internet are not probed: Tailscale does not evaluate them, so a result for one would not be evidence"
)

// firstNamed is the first of names that re matches, or "".
func firstNamed(names []string, re *regexp.Regexp) string {
	for _, n := range names {
		if re.MatchString(n) {
			return n
		}
	}
	return ""
}

// kindProbes asks acl_test one question per destination kind the live policy can
// source, the same destination accepted and denied. The verdict is the line's got
// word. A kind with no source, or a host alias when the policy defines none, is
// n/a. A service is probed only when the live text names one.
func kindProbes(ctx context.Context, r *Report, a *app.App) {
	var page tools.ACLGetOutput
	err := call(ctx, a, "acl_get", `{"view":"summary"}`, &page)
	if err != nil || page.Summary == nil {
		for _, k := range probeKinds {
			if err != nil {
				r.addReadErr("probe "+k.Name, err)
			} else {
				r.add("probe "+k.Name, Warn, "the summary was absent, so this kind was not probed", "")
			}
		}
		r.add("probe kinds refused", Info, "svc, "+kindsRefused, "")
		return
	}
	src, host := firstNamed(page.Summary.TagOwners, canaryTagRE), firstNamed(page.Summary.Hosts, hostAliasRE)
	svc, svcSeen := "", false
	if a.Env != nil && a.Env.API != nil {
		d, derr := a.Env.API.GetPolicyDetails(ctx)
		noteDirect(ctx, a, "doctor.probe kind source", derr)
		if derr == nil {
			text := d.Text
			if std, serr := hujson.Standardize(d.Text); serr == nil {
				text = std
			}
			var named []string
			for _, m := range svcSelectors.FindAllSubmatch(text, -1) {
				named = append(named, string(m[1]))
			}
			svc, svcSeen = firstNamed(named, svcNameRE), len(named) > 0
		}
	}
	for _, k := range probeKinds {
		name := "probe " + k.Name
		switch {
		case src == "":
			r.add(name, NA, "the live policy defines no tag with a name this probe can send, so this kind was not probed", "")
			continue
		case k.Name == "host alias" && host == "":
			r.add(name, NA, "the live policy defines no host alias with a name this probe can send, so this kind was not probed", "")
			continue
		}
		dst := k.Dst
		if k.Name == "tag" {
			dst = src + ":22"
		}
		if k.Name == "host alias" {
			dst = host + ":22"
		}
		addKind(ctx, r, a, name, src, dst, k.Proto)
	}
	if svc != "" && src != "" {
		addKind(ctx, r, a, "probe svc", src, svc+":22", "")
	}
	if svc == "" && svcSeen {
		r.add("probe svc", NA, "the live policy names a service, but no name this probe can send (letters, digits and hyphens, at most 100 characters), so this kind was not probed", "")
	}
	refused := kindsRefused
	if svc == "" {
		refused = "svc, " + kindsRefused
	}
	r.add("probe kinds refused", Info, refused, "")
}

func addKind(ctx context.Context, r *Report, a *app.App, name, src, dst, proto string) {
	var out tools.ACLTestOutput
	if err := call(ctx, a, "acl_test", kindArgs(src, dst, proto), &out); err != nil {
		r.addReadErr(name, err)
		return
	}
	verdicts := make([]string, len(out.Verdicts))
	for i, v := range out.Verdicts {
		verdicts[i] = v.Verdict
	}
	st, detail, fix := tools.ClassifyKind(out.Status, verdicts)
	r.add(name, Status(st), detail, fix)
}

func kindArgs(src, dst, proto string) string {
	in := map[string]any{"src": src, "accept": []string{dst}, "deny": []string{dst}}
	if proto != "" {
		in["proto"] = proto
	}
	b, err := json.Marshal(in)
	if err != nil {
		return `{"src":""}`
	}
	return string(b)
}
