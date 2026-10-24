package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// ACLHistoryInput selects policy versions from the configuration audit log.
// The log has no pagination: tailkeeper reads the window in slices and pages
// over what came back.
type ACLHistoryInput struct {
	Start  string `json:"start,omitempty" tk:"short" jsonschema:"RFC 3339 start (default end minus 30 days); the window may span at most 90 days"`
	End    string `json:"end,omitempty" tk:"short" jsonschema:"RFC 3339 end (default now)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"page size, 1-200 (default 50)"`
	Cursor string `json:"cursor,omitempty" tk:"short" jsonschema:"nextCursor of the previous page; it fixes the window, so omit start and end"`
}

// ACLVersion is one policy the log recorded. The text itself is not here: a
// version id is how acl_diff asks for it. policyVersion and policySha256 describe
// the text as acl_get would show it, so neither is a hash of a login.
type ACLVersion struct {
	Version       string     `json:"version" tk:"col"`
	Previous      string     `json:"previous,omitempty" tk:"col"`
	EventTime     string     `json:"eventTime" tk:"col"`
	Origin        string     `json:"origin" tk:"col,untrusted"`
	Actor         AuditActor `json:"actor"`
	Bytes         int        `json:"bytes" tk:"col"`
	Digest        string     `json:"digest,omitempty"`
	PolicyVersion string     `json:"policyVersion,omitempty"`
	PolicySHA256  string     `json:"policySha256"`
}

// ACLHistoryOutput is one page of policy versions, oldest first.
type ACLHistoryOutput struct {
	Versions    []ACLVersion `json:"versions" tk:"rows"`
	Count       int          `json:"count"`
	WindowStart string       `json:"windowStart"`
	WindowEnd   string       `json:"windowEnd"`
	NextCursor  string       `json:"nextCursor,omitempty"`
	Skipped     int          `json:"skipped,omitempty"`
	Note        string       `json:"note"`
}

// historyNote is the sentence every result's note holds; historyNoteCut and the
// sentence of actorTagsNote follow it when they apply.
const historyNote = "Policy versions come from the configuration audit log, oldest first. An entry can be deferred, with no documented maximum delay, and the log keeps a finite history. This result has no policy text: a version id is how a later comparison reads one, and the text is masked as acl_get shows a policy."

const historyNoteCut = " This page ended before its size because of the size of the versions it holds: continue with nextCursor."

// historyPageBudget is the most characters, as JSON text, that the versions of one page take,
// counted as the registry will show them. A page of 200 ordinary versions is about 160,000;
// the tool declares 200,000 for the page and its note.
const historyPageBudget = 190000

const (
	historyMaxSpan      = 90 * 24 * time.Hour
	historyDefaultSpan  = 30 * 24 * time.Hour
	historyDefaultLimit = 50
	historyMaxLimit     = 200
	historyEvent        = "TAILNET.UPDATE.ACL"
)

// Check refuses a limit out of range, a cursor given with a window or that no
// page issued, and a window longer than 90 days, before anything is sent.
func (in ACLHistoryInput) Check() error {
	if in.Limit != 0 && (in.Limit < 1 || in.Limit > historyMaxLimit) {
		return validationf("limit must be between 1 and 200")
	}
	if in.Cursor != "" && (in.Start != "" || in.End != "") {
		return validationf("a cursor fixes the window: omit start and end")
	}
	if in.Cursor == "" {
		return checkWindow(in.Start, in.End, historyMaxSpan)
	}
	_, _, _, _, err := decodeAuditCursor(in.Cursor, historyMaxSpan)
	return err
}

type historyItem struct {
	t       time.Time
	order   string
	group   string
	ordinal int
	oldText string
	newText string
	version ACLVersion
}

func aclHistory(ctx context.Context, env *registry.Env, in ACLHistoryInput) (ACLHistoryOutput, error) {
	limit := in.Limit
	if limit == 0 {
		limit = historyDefaultLimit
	}
	filters := historyFilters(env, limit)
	var (
		start, end, after time.Time
		cur               *auditCursor
	)
	if in.Cursor != "" {
		c, s, e, a, err := decodeAuditCursor(in.Cursor, historyMaxSpan)
		if err != nil {
			return ACLHistoryOutput{}, err
		}
		if c.Filters != filters {
			return ACLHistoryOutput{}, validationf("the cursor is not from acl_history with this page size and privacy setting; start again without a cursor")
		}
		start, end, after, cur = s, e, a, &c
	} else {
		var err error
		if start, end, err = parseWindow(env.Clock(), in.Start, in.End, historyDefaultSpan, historyMaxSpan); err != nil {
			return ACLHistoryOutput{}, err
		}
	}
	items, skipped, err := readHistory(ctx, env, start, end)
	if err != nil {
		return ACLHistoryOutput{}, err
	}
	kept := items[:0]
	for _, it := range items {
		// The cap is read on the raw text: an entry is left out of the listing by its size as
		// the log holds it, not as it would show, so a login's length can decide whether the
		// entry is listed at all. Its id still names it, for ordering.
		if len(it.newText) > guard.MaxPolicyBytes || len(it.oldText) > guard.MaxPolicyBytes {
			skipped++
			continue
		}
		kept = append(kept, it)
	}
	items = kept
	if cur != nil {
		i, seen := 0, 0
		for i < len(items) && items[i].t.Before(after) {
			i++
		}
		for i < len(items) && items[i].t.Equal(after) && seen < cur.Skip {
			i, seen = i+1, seen+1
		}
		items = items[i:]
	}
	out := ACLHistoryOutput{
		WindowStart: start.UTC().Format(time.RFC3339Nano),
		WindowEnd:   end.UTC().Format(time.RFC3339Nano),
		Note:        historyNote,
		Versions:    []ACLVersion{},
		Skipped:     skipped,
	}
	// A page ends at the limit or when the next version would take it past the budget, and
	// holds at least one version: a version is bounded, so one fits.
	n, spent := 0, 0
	for n < min(limit, len(items)) {
		cost := shownJSONLen(env, items[n].version)
		if n > 0 && spent+cost > historyPageBudget {
			break
		}
		n, spent = n+1, spent+cost
	}
	if len(items) > n {
		last := items[n-1].t
		next := auditCursor{Start: out.WindowStart, End: out.WindowEnd, After: last.UTC().Format(time.RFC3339Nano), Filters: filters}
		for _, it := range items[:n] {
			if it.t.Equal(last) {
				next.Skip++
			}
		}
		if cur != nil && last.Equal(after) {
			next.Skip += cur.Skip
		}
		out.NextCursor = next.encode()
		if n < limit {
			out.Note += historyNoteCut
		}
		items = items[:n]
	}
	for _, it := range items {
		out.Versions = append(out.Versions, it.version)
		if actorTagsCut(it.version.Actor) && !strings.Contains(out.Note, actorTagsNote) {
			out.Note += actorTagsNote
		}
	}
	out.Count = len(out.Versions)
	return out, nil
}

// historyFilters fingerprints the page a cursor was issued for. The tool name is
// part of it, so an audit_log cursor does not open this tool.
func historyFilters(env *registry.Env, limit int) string {
	mode := "show"
	if !env.ShowPersonalData() {
		mode = "masked"
		if env.Privacy != nil {
			mode += ":" + env.Privacy.Digest([]byte("acl_history cursor"))
		}
	}
	b, _ := json.Marshal([]any{"acl_history", limit, mode})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// readHistory reads every ACL update in [start, end], in slices of at most 31
// days, and returns them oldest first. An entry whose old or new is not a JSON
// string is counted in skipped and dropped. A string over the policy cap is kept
// for ordering, so a version id still names it, and left out of the page.
func readHistory(ctx context.Context, env *registry.Env, start, end time.Time) ([]historyItem, int, error) {
	var (
		all     []historyItem
		skipped int
		seen    = map[string]bool{}
	)
	for _, sl := range historySlices(start, end) {
		items, skip, err := readHistorySlice(ctx, env, sl[0], sl[1])
		if err != nil {
			return nil, 0, err
		}
		skipped += skip
		for _, it := range items {
			// Two requests return an entry that sits on the end point they share, so one
			// entry is kept once. The key holds the digest of the text as shown, so two
			// entries of one group and one time whose texts differ only in what masking
			// removes are one entry here: the second is dropped and not counted.
			key := it.version.EventTime + "\n" + it.group + "\n" + it.order
			if seen[key] {
				continue
			}
			seen[key] = true
			all = append(all, it)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].t.Equal(all[j].t) {
			return all[i].t.Before(all[j].t)
		}
		return all[i].order < all[j].order
	})
	// The ordinal numbers the entries that share a time, in the order of historyOrder, which
	// holds the digest of the text as shown. It therefore depends on the privacy setting: an
	// id issued with personalData show can name another entry of the same time when it is
	// used with masking on. Ids are for the call that listed them.
	ord := 0
	for i := range all {
		if i > 0 && all[i].t.Equal(all[i-1].t) {
			ord++
		} else {
			ord = 0
		}
		all[i].ordinal = ord
		ref := versionRef{Time: all[i].version.EventTime, Group: all[i].group, Ordinal: ord}
		ref.Side = "new"
		all[i].version.Version = encodeVersionID(ref)
		ref.Side = "old"
		all[i].version.Previous = encodeVersionID(ref)
	}
	return all, skipped, nil
}

func historySlices(start, end time.Time) [][2]time.Time {
	var out [][2]time.Time
	cur := start
	for cur.Before(end) {
		next := cur.Add(auditMaxSpan)
		if !next.Before(end) {
			next = end
		}
		out = append(out, [2]time.Time{cur, next})
		cur = next
	}
	return out
}

type historyLog struct {
	EventTime    string          `json:"eventTime"`
	EventGroupID string          `json:"eventGroupID"`
	Origin       string          `json:"origin"`
	Actor        AuditActor      `json:"actor"`
	Old          json.RawMessage `json:"old"`
	New          json.RawMessage `json:"new"`
}

func readHistorySlice(ctx context.Context, env *registry.Env, start, end time.Time) ([]historyItem, int, error) {
	path, err := tailnetPath(env, "/logging/configuration")
	if err != nil {
		return nil, 0, err
	}
	q := url.Values{
		"start": {start.UTC().Format(time.RFC3339Nano)},
		"end":   {end.UTC().Format(time.RFC3339Nano)},
		"event": {historyEvent},
	}
	// The server's event filter is trusted: an entry it returns is taken for an ACL update,
	// and its own type is not read again.
	var r struct {
		Logs []historyLog `json:"logs"`
	}
	if err := get(ctx, env, path, q, &r); err != nil {
		return nil, 0, err
	}
	var (
		items   []historyItem
		skipped int
	)
	for _, l := range r.Logs {
		oldText, oldOK := jsonStringValue(l.Old)
		newText, newOK := jsonStringValue(l.New)
		if !oldOK || !newOK {
			skipped++
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, l.EventTime)
		if err != nil {
			return nil, 0, tkerr.New(tkerr.APIError, "an audit entry has an unparsable eventTime, so the log cannot be paged", "")
		}
		shown, size, sha := shownPolicy(env, newText)
		group := versionGroup(l.EventGroupID)
		item := historyItem{
			t: t, order: historyOrder(group, sha), group: group,
			oldText: oldText, newText: newText,
			version: ACLVersion{
				EventTime:     versionEventTime(l.EventTime, t),
				Origin:        l.Origin,
				Actor:         boundActor(env, l.Actor),
				Bytes:         size,
				Digest:        historyDigest(env, newText, shown),
				PolicyVersion: historyPolicyVersion(env, newText, sha),
				PolicySHA256:  sha,
			},
		}
		items = append(items, item)
	}
	return items, skipped, nil
}

func jsonStringValue(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// historyOrder orders entries that share a timestamp. It is a hash of the event
// group and of the digest of the text as shown, never of the text itself, and
// nothing prints it.
func historyOrder(group, sha string) string {
	sum := sha256.Sum256([]byte(group + "\n" + sha))
	return hex.EncodeToString(sum[:])
}

// historyDigest is audit_log's digest rule applied to the text as shown while
// masking is on (a digest of the raw text would differ for two logins that show
// as one form). With personalData show it is the unkeyed digest of the raw JSON
// string. With masking on and no key it is absent.
func historyDigest(env *registry.Env, raw, shown string) string {
	switch {
	case env.ShowPersonalData():
		b, _ := json.Marshal(raw)
		sum := sha256.Sum256(b)
		return "sha256:" + hex.EncodeToString(sum[:])
	case env != nil && env.Privacy != nil:
		b, _ := json.Marshal(shown)
		return env.Privacy.Digest(b)
	default:
		return ""
	}
}

// historyPolicyVersion is acl_get's version token for a text that has no ETag.
// With a privacy key it is a keyed digest of the hex SHA-256 of the text as
// shown. With personalData show it is that SHA-256 of the raw text. Otherwise
// there is none: an unkeyed token of the raw text would confirm a guessed address.
func historyPolicyVersion(env *registry.Env, raw, shownSHA string) string {
	switch {
	case env.ShowPersonalData():
		sum := sha256.Sum256([]byte(raw))
		return hex.EncodeToString(sum[:])
	case env != nil && env.Privacy != nil:
		return env.Privacy.Digest([]byte(shownSHA))
	default:
		return ""
	}
}
