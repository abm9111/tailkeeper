package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"

	"github.com/abm9111/tailkeeper/internal/acl"
	"github.com/abm9111/tailkeeper/internal/api"
)

// Posture is none, gated or unknown. unknown means the live policy could not be
// read, which is not the same as a policy that gates on nothing.
const (
	postureNone    = "none"
	postureGated   = "gated"
	postureUnknown = "unknown"
)

// The sentences PostureNote can hold. The live policy could not be read, or it names
// more posture attributes than the result lists. A result that read the policy and
// found none leaves the note empty, and posture is none.
const (
	postureNoteUnread = "the live policy could not be read, so whether it is posture-sensitive was not checked"
	postureNoteMore   = "the policy names more posture attributes than this result lists"
	postureUnproved   = "an unknown posture leaves unproved whether a posture-gated rule matched"
)

// maxPosturesListed is how many posture attribute names one result lists.
const maxPosturesListed = 64

// postureNeeds reads the live policy once and reports whether it gates on posture,
// the attribute names it uses, and the hosts section a verdict matches an address
// through. A failure of the read, of the guard or of the decode is posture unknown,
// never "not sensitive": hosts is nil and the note says the policy was not checked.
// The test's own status is left to the caller. The read is the same GET the tool declares.
func postureNeeds(ctx context.Context, c *api.Client) (hosts map[string]string, posture string, postures []string, note string) {
	d, err := c.GetPolicyDetails(ctx)
	if err != nil {
		return nil, postureUnknown, nil, postureNoteUnread
	}
	std, err := acl.Standardize(ctx, d.Text)
	if err != nil {
		return nil, postureUnknown, nil, postureNoteUnread
	}
	hosts, postures, err = posturesOf(std)
	if err != nil {
		return nil, postureUnknown, nil, postureNoteUnread
	}
	if len(postures) > maxPosturesListed {
		postures = postures[:maxPosturesListed]
		return hosts, postureGated, postures, postureNoteMore
	}
	if len(postures) == 0 {
		return hosts, postureNone, nil, ""
	}
	return hosts, postureGated, postures, ""
}

// posturesOf reads defaultSrcPosture and the srcPosture of acls, grants and ssh, and
// the hosts section. Section names match without regard to case. A value that is not
// the array of strings or the map of strings the section holds is an error, so a
// policy this cannot read is not reported as having no posture.
func posturesOf(text []byte) (map[string]string, []string, error) {
	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return nil, nil, err
	}
	folded := make(map[string]json.RawMessage, len(top))
	for k, v := range top {
		folded[strings.ToLower(k)] = v
	}
	var names []string
	if raw, ok := folded["defaultsrcposture"]; ok {
		got, err := postureNames(raw)
		if err != nil {
			return nil, nil, err
		}
		names = append(names, got...)
	}
	for _, sec := range []string{"acls", "grants", "ssh"} {
		raw, ok := folded[sec]
		if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		var rules []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &rules); err != nil {
			return nil, nil, err
		}
		for _, rule := range rules {
			for k, v := range rule {
				if !strings.EqualFold(k, "srcPosture") {
					continue
				}
				got, err := postureNames(v)
				if err != nil {
					return nil, nil, err
				}
				names = append(names, got...)
			}
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) == 0 {
		names = nil
	}
	var hosts map[string]string
	if raw, ok := folded["hosts"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, nil, err
		}
		for k, v := range m {
			var s string
			if json.Unmarshal(v, &s) != nil {
				continue
			}
			if hosts == nil {
				hosts = map[string]string{}
			}
			hosts[k] = s
		}
	}
	return hosts, names, nil
}

func postureNames(raw json.RawMessage) ([]string, error) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var names []string
	if err := json.Unmarshal(raw, &names); err != nil {
		return nil, err
	}
	return names, nil
}
