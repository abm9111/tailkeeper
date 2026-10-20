package acl

import "github.com/tailscale/hujson"

// Tailscale edits the policy file on the owner's behalf for some features, so a comparison
// of the file in git with the live policy shows them as drift for ever. They are listed
// here, with where the list comes from and when it was made, and a diff classifies a change
// to one of them apart from the rest so a drift job can ignore it. The output carries the
// date, so a reader knows how old the list is.
//
// Source: docs/design.md section 12.6 and Tailscale's documentation of the three features.
// Review this list when a feature of the admin console starts writing to the policy.
const (
	TailscaleWrittenAsOf   = "2026-10-17"
	TailscaleWrittenSource = "design.md 12.6: Funnel node attribute, private log streaming accept rule, app connector presets"
)

const (
	// funnelAttr is the node attribute the admin console adds when Funnel is turned on.
	funnelAttr = "funnel"
	// logStreamSource is the source of the accept rule written for private log streaming.
	logStreamSource = "logstream@tailscale"
	// appConnectors is the capability an app connector entry sits under.
	appConnectors = "tailscale.com/app-connectors"
	// presetKey is the key of an app connector entry that names a preset.
	presetKey = "presetAppID"
)

// atomWritten reports whether an access atom is the rule Tailscale writes for private log
// streaming (design 12.6): an accept rule written in acls, whose sources are that source and
// no other, with no protocol, posture, via, app or other field, and not all ports or a
// wildcard destination, which no log sink needs. Anything else from that source is somebody's
// own rule, and a drift job must not ignore it. The destination and port of the real rule are
// the owner's, so they are not pinned; a change to them (an edit of the rule) is not a
// removal or an addition of the rule, and Diff classes it as an ordinary change.
func atomWritten(a *atom) bool {
	return a.src.written && a.origin == originACLs && a.act == "" && a.proto == "" &&
		a.posture == "" && a.via == "" && a.app == "" && a.extra == "" &&
		a.pkey != "*" && wideBit(a.dst) == 0
}

// presetAllowed are the fields of an app connector entry that Tailscale writes for a preset;
// an entry with others (domains, routes) has been written by hand.
var presetAllowed = map[string]bool{"name": true, "presetAppID": true, "connectors": true}

// appIsPreset reports whether an app field holds what Tailscale writes for app connector
// presets: the app-connectors capability and no other, a list of entries each of which names
// a preset as a string and has no field a preset does not. It reads the tree of the last
// layer (a later app replaces an earlier one), and pays for every member it visits.
func appIsPreset(m *meter, layers []*hujson.Value) (bool, error) {
	obj, ok := layers[len(layers)-1].Value.(*hujson.Object)
	if !ok || len(obj.Members) != 1 || nameOf(&obj.Members[0].Name) != appConnectors {
		return false, nil
	}
	list, ok := obj.Members[0].Value.Value.(*hujson.Array)
	if !ok || len(list.Elements) == 0 {
		return false, nil
	}
	for i := range list.Elements {
		entry, ok := list.Elements[i].Value.(*hujson.Object)
		if !ok {
			return false, nil
		}
		if err := m.tick(len(entry.Members) + 1); err != nil {
			return false, err
		}
		named := false
		for j := range entry.Members {
			name := nameOf(&entry.Members[j].Name)
			if !presetAllowed[name] {
				return false, nil
			}
			if name == presetKey {
				lit, isLit := entry.Members[j].Value.Value.(hujson.Literal)
				if !isLit || lit.Kind() != '"' {
					return false, nil
				}
				named = true
			}
		}
		if !named {
			return false, nil
		}
	}
	return true, nil
}

// attrWritten reports whether a node attribute atom is Funnel's, or belongs to an entry that
// is an app connector preset. Funnel counts only in the one shape the admin console writes
// (bare): the funnel attribute and a target, with no other attribute, no app, no ipPool and
// no field the engine does not model. An entry that carries more is somebody's own change
// and a drift job must see it, as with the log-stream rule and the preset. Within that shape
// a change to the targets that have Funnel is Tailscale-written, by design.
func attrWritten(attr string, preset, bare bool) bool { return preset || (attr == funnelAttr && bare) }
