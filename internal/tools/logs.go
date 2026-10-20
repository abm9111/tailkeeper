package tools

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// AuditLogInput selects configuration audit-log entries. The API has no pagination:
// it returns the whole window, and tailkeeper pages over that response.
type AuditLogInput struct {
	Start         string   `json:"start,omitempty" jsonschema:"RFC 3339 start (default end minus 24h)"`
	End           string   `json:"end,omitempty" jsonschema:"RFC 3339 end (default now); the window may span at most 31 days"`
	Actor         []string `json:"actor,omitempty" jsonschema:"exact actor IDs, or ~search on login or display name (server-side); a pseudonym (p:…) matches client-side; while personal data is masked, ~search and addresses are refused, and with masking off they cannot share a list with a pseudonym"`
	Target        []string `json:"target,omitempty" jsonschema:"substring, in any case, of the target's ID, name, type or property as the result shows it (client-side: a URL in them shows as its scheme and host and a hash of its path and query when it has either, so a substring of its path matches nothing); a pseudonym (p:…) matches client-side; while personal data is masked, only exact target IDs and pseudonyms; with masking off a substring cannot share a list with a pseudonym"`
	Event         []string `json:"event,omitempty" jsonschema:"event names such as TAILNET.UPDATE.ACL (server-side)"`
	Origin        []string `json:"origin,omitempty" jsonschema:"origins such as ADMIN_CONSOLE or CONFIG_API (client-side)"`
	IncludeValues bool     `json:"includeValues,omitempty" jsonschema:"also return previews of old and new values, up to 256 bytes each (a cut one ends in ...[truncated]): http and https URLs show as their scheme and host and a hash of their path and query when they have either (https://host/…[path sha256 …]), values under credential-named keys are removed (true, false and null stay), and email and public addresses are masked unless the owner turned masking off; they can still hold user names"`
	Limit         int      `json:"limit,omitempty" jsonschema:"page size, 1-5000 (default 500)"`
	Cursor        string   `json:"cursor,omitempty" jsonschema:"nextCursor from the previous page; it fixes the window, so omit start and end and repeat the same filters, limit and includeValues"`
}

// AuditActor is who made a change.
type AuditActor struct {
	ID          string   `json:"id,omitempty"`
	Type        string   `json:"type,omitempty"`
	LoginName   string   `json:"loginName,omitempty" tk:"untrusted,personal"`
	DisplayName string   `json:"displayName,omitempty" tk:"untrusted,personal"`
	Tags        []string `json:"tags,omitempty" tk:"untrusted"`
}

// AuditTarget is what changed.
type AuditTarget struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty" tk:"untrusted"`
	Type        string `json:"type,omitempty"`
	IsEphemeral bool   `json:"isEphemeral,omitempty"`
	Property    string `json:"property,omitempty" tk:"untrusted"`
}

// AuditEntry is one configuration audit-log entry. old/new can hold whole policy
// files and personal data, so they are returned as a digest and, only on request
// (includeValues), a short untrusted preview.
type AuditEntry struct {
	EventTime     string      `json:"eventTime" tk:"col"`
	DeferredAt    string      `json:"deferredAt,omitempty"`
	EventGroupID  string      `json:"eventGroupId,omitempty"`
	Origin        string      `json:"origin" tk:"col"`
	Action        string      `json:"action" tk:"col"`
	Actor         AuditActor  `json:"actor"`
	Target        AuditTarget `json:"target"`
	OldDigest     string      `json:"oldDigest,omitempty" jsonschema:"a digest of the old value's JSON as the API sent it: hmac-sha256: under the privacy key while personal data is masked, sha256: when it is not; absent while masked with no key"`
	NewDigest     string      `json:"newDigest,omitempty" jsonschema:"as oldDigest"`
	OldPreview    string      `json:"oldPreview,omitempty" tk:"untrusted,premasked"`
	NewPreview    string      `json:"newPreview,omitempty" tk:"untrusted,premasked"`
	ActionDetails string      `json:"actionDetails,omitempty" tk:"untrusted"`
	Error         string      `json:"error,omitempty" tk:"untrusted"`
}

// AuditLogOutput is one page of entries, oldest first.
type AuditLogOutput struct {
	Entries     []AuditEntry `json:"entries" tk:"rows"`
	Count       int          `json:"count"`
	WindowStart string       `json:"windowStart"`
	WindowEnd   string       `json:"windowEnd"`
	NextCursor  string       `json:"nextCursor,omitempty"`
	Note        string       `json:"note"`
}

const auditNote = "Entries can be deferred with no documented maximum delay; reads, support-initiated changes and the cascade of a user suspension are not logged."

// digestsWithheld is appended to the note while masking is on and no privacy key
// is loaded: an unkeyed digest would confirm a guessed value. digestsWithheldBadKey
// is its form when a key is set but malformed or unreadable, which is not the
// same thing to fix.
const (
	digestsWithheld       = " Digests of old and new values are left out: personal data is masked and no privacy key is loaded, and an unkeyed digest would confirm a guessed value."
	digestsWithheldBadKey = " Digests of old and new values are left out: personal data is masked and the privacy key is malformed or unreadable (`tailkeeper doctor` says why), and an unkeyed digest would confirm a guessed value."
)

// FlowLogsInput selects a short window of network flow logs.
type FlowLogsInput struct {
	Start      string `json:"start,omitempty" jsonschema:"RFC 3339 start (default end minus 15m)"`
	End        string `json:"end,omitempty" jsonschema:"RFC 3339 end (default now); the window may span at most 1h"`
	Node       string `json:"node,omitempty" jsonschema:"only records logged by this node ID (client-side)"`
	MaxRecords int    `json:"maxRecords,omitempty" jsonschema:"1-10000 (default 1000)"`
}

// Flow is one traffic counter in a flow-log record.
type Flow struct {
	Kind    string `json:"kind" jsonschema:"virtual, subnet, exit or physical"`
	Proto   string `json:"proto" tk:"untrusted"`
	Src     string `json:"src" tk:"untrusted"`
	Dst     string `json:"dst" tk:"untrusted"`
	TxPkts  int64  `json:"txPkts"`
	TxBytes int64  `json:"txBytes"`
	RxPkts  int64  `json:"rxPkts"`
	RxBytes int64  `json:"rxBytes"`
}

// FlowRecord is one node's 5-second window.
type FlowRecord struct {
	NodeID string `json:"nodeId"`
	Logged string `json:"logged"`
	Start  string `json:"start" tk:"untrusted"`
	End    string `json:"end" tk:"untrusted"`
	Flows  []Flow `json:"flows"`
}

// FlowLogsOutput reports flow records or why there are none.
type FlowLogsOutput struct {
	Status          string       `json:"status" jsonschema:"ok, not_enabled (flow logging is off) or not_available (not on this plan)"`
	LoggingEnabled  string       `json:"loggingEnabled" jsonschema:"true, false or unknown (settings unreadable): with unknown, zero records may mean logging is off"`
	Records         []FlowRecord `json:"records"`
	Count           int          `json:"count"`
	Truncated       bool         `json:"truncated"`
	AsOf            string       `json:"asOf"`
	MayBeIncomplete bool         `json:"mayBeIncomplete"`
	Note            string       `json:"note"`
}

// LogStreamInput names a log type.
type LogStreamInput struct {
	LogType string `json:"logType" jsonschema:"configuration or network"`
}

// LogStreamConfig is a destination without its secrets (token, S3 secret key and
// GCS credentials are never returned).
type LogStreamConfig struct {
	DestinationType      string   `json:"destinationType,omitempty"`
	URL                  string   `json:"url,omitempty" tk:"untrusted,plain" jsonschema:"scheme and host only"`
	URLPathHash          string   `json:"urlPathSha256,omitempty" jsonschema:"SHA-256 of the URL's path and query, which can carry a collector token"`
	User                 string   `json:"user,omitempty" tk:"untrusted,personal"`
	UploadPeriodMinutes  int      `json:"uploadPeriodMinutes,omitempty"`
	CompressionFormat    string   `json:"compressionFormat,omitempty"`
	S3Bucket             string   `json:"s3Bucket,omitempty" tk:"untrusted"`
	S3Region             string   `json:"s3Region,omitempty" tk:"untrusted"`
	S3KeyPrefix          string   `json:"s3KeyPrefix,omitempty" tk:"untrusted"`
	S3AuthenticationType string   `json:"s3AuthenticationType,omitempty"`
	S3AccessKeyID        string   `json:"s3AccessKeyId,omitempty" tk:"untrusted"`
	S3RoleARN            string   `json:"s3RoleArn,omitempty" tk:"untrusted"`
	S3ExternalID         string   `json:"s3ExternalId,omitempty" tk:"untrusted"`
	GCSBucket            string   `json:"gcsBucket,omitempty" tk:"untrusted"`
	GCSKeyPrefix         string   `json:"gcsKeyPrefix,omitempty" tk:"untrusted"`
	GCSScopes            []string `json:"gcsScopes,omitempty" tk:"untrusted"`
}

// LogStreamStatus is delivery health.
type LogStreamStatus struct {
	LastActivity       string  `json:"lastActivity,omitempty"`
	LastError          string  `json:"lastError,omitempty" tk:"untrusted"`
	NumBytesSent       int64   `json:"numBytesSent"`
	NumEntriesSent     int64   `json:"numEntriesSent"`
	NumSpoofedEntries  int64   `json:"numSpoofedEntries"`
	NumTotalRequests   int64   `json:"numTotalRequests"`
	NumFailedRequests  int64   `json:"numFailedRequests"`
	RateFailedRequests float64 `json:"rateFailedRequests"`
}

// LogStreamOutput describes one log stream.
type LogStreamOutput struct {
	LogType       string           `json:"logType"`
	Status        string           `json:"status" jsonschema:"configured or not_configured"`
	Configuration *LogStreamConfig `json:"configuration,omitempty"`
	Health        *LogStreamStatus `json:"health,omitempty"`
	HealthError   string           `json:"healthError,omitempty" jsonschema:"error code when delivery health could not be read"`
	Findings      []string         `json:"findings"`
}

func logTools() []registry.Tool {
	audit := withOps(readMeta("audit_log", "logs", "audit", "Read the configuration audit log for a time window (paged client-side).", "logs:configuration:read"),
		"GET /tailnet/{tailnet}/logging/configuration")
	flows := withOps(readMeta("network_flow_logs", "logs", "network", "Read network flow logs for a short window.", "logs:network:read"),
		"GET /tailnet/{tailnet}/settings", "GET /tailnet/{tailnet}/logging/network")
	flows.PlanGate = "Premium, Enterprise"
	stream := withOps(readMeta("log_streaming_get", "logs", "streaming", "Show a log stream's destination (without secrets) and delivery health.", "log_streaming:read"),
		"GET /tailnet/{tailnet}/logging/{logType}/stream", "GET /tailnet/{tailnet}/logging/{logType}/stream/status")
	stream.PlanGate = "Premium, Enterprise"
	return []registry.Tool{
		registry.Define(audit, auditLog),
		registry.Define(flows, networkFlowLogs),
		registry.Define(stream, logStreamingGet),
	}
}

// auditCursor is the opaque nextCursor. It fixes the window and the filters, and
// records how many entries at exactly After were already returned, so entries that
// share a timestamp are neither repeated nor skipped across a page boundary.
type auditCursor struct {
	Start   string `json:"s"`
	End     string `json:"e"`
	After   string `json:"t"`
	Skip    int    `json:"n"`
	Filters string `json:"f"`
}

func (c auditCursor) encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeAuditCursor(s string) (auditCursor, time.Time, time.Time, time.Time, error) {
	var c auditCursor
	bad := validationf("cursor must be the nextCursor of a previous page")
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || json.Unmarshal(b, &c) != nil || c.Skip < 1 {
		return c, time.Time{}, time.Time{}, time.Time{}, bad
	}
	start, err1 := time.Parse(time.RFC3339Nano, c.Start)
	end, err2 := time.Parse(time.RFC3339Nano, c.End)
	after, err3 := time.Parse(time.RFC3339Nano, c.After)
	// The cursor is not signed, so its window gets the same checks as a new one.
	if err1 != nil || err2 != nil || err3 != nil || !start.Before(end) || end.Sub(start) > auditMaxSpan ||
		after.Before(start) || after.After(end) {
		return c, time.Time{}, time.Time{}, time.Time{}, bad
	}
	return c, start, end, after, nil
}

// auditMaxSpan is the longest window audit_log reads.
const auditMaxSpan = 31 * 24 * time.Hour

// flowMaxSpan is the longest window network_flow_logs reads.
const flowMaxSpan = time.Hour

// auditFilters fingerprints what a cursor was issued for: the filters, the page
// size, whether previews are shown, and how entries are displayed. The last
// decides the order of entries that share a timestamp (see displayKey), so under
// another setting, or another privacy key, the cursor's position inside such a
// run would mean something else. The key enters only as a keyed hash of a
// constant, itself hashed.
func auditFilters(env *registry.Env, in AuditLogInput, limit int) string {
	mode := "show"
	if !env.ShowPersonalData() {
		mode = "masked"
		if env.Privacy != nil {
			mode += ":" + env.Privacy.Digest([]byte("audit_log cursor"))
		}
	}
	b, _ := json.Marshal([]any{in.Actor, in.Target, in.Event, lower(in.Origin), limit, in.IncludeValues, mode})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// displayKey orders entries that share a timestamp: a hash of the entry as a
// caller sees it, masked and capped like the result. It reads no raw value, so an
// unkeyed hash of it confirms nothing the caller does not already have; entries
// that display alike are indistinguishable, so their relative order cannot matter.
// The entry is copied through JSON first because displaying rewrites slices in
// place.
func displayKey(env *registry.Env, e AuditEntry) string {
	b, _ := json.Marshal(e)
	var shown AuditEntry
	_ = json.Unmarshal(b, &shown)
	env.Display(&shown)
	b, _ = json.Marshal(shown)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type timedEntry struct {
	t time.Time
	k string // orders entries that share a timestamp, whatever order the API used
	e AuditEntry
}

// auditMatch is a client-side audit-log filter: exact IDs and pseudonyms, or with
// masking off the substrings of a target filter. A zero auditMatch keeps
// everything.
type auditMatch struct {
	on   bool
	ids  map[string]bool
	refs map[string]bool
	// subs are substrings, lower case, read against the text an entry shows
	// (keepShown). They are the literals of a substring filter while masking is
	// off, which is never sent to the server: the server matches the raw target.
	subs []string
}

// splitAuditFilter sorts a filter's values into what may go to the server and
// what must be matched here. literalOK says whether a literal value is a plain
// ID, which is all that may be matched here while masking is on; idsExact says
// whether the server also reads such a value as an exact ID, as it does for an
// actor, rather than as a substring, as it does for a target.
//
// While masking is on, the server's match is always narrowed here to exact IDs
// and pseudonyms, since it is wider than either. A pseudonym moves the whole
// filter here, so with masking off a value only the server could read (a ~search,
// a substring) cannot be mixed with one: it would match nothing here.
//
// With masking off, a substring (idsExact false: a target) is matched here and
// not sent. The server would match it against the raw target, where the result
// shows a URL cut to its host, so whether an entry came back would confirm a guess
// at the path: a filter reads a value as the result shows it (keepShown).
func splitAuditFilter(env *registry.Env, name string, values []string, literalOK func(string) bool, idsExact bool) ([]string, auditMatch, error) {
	m := auditMatch{ids: map[string]bool{}, refs: map[string]bool{}}
	var literals []string
	for _, v := range values {
		if p, ok := privacy.Ref(v); ok {
			if _, err := env.RequirePrivacy(); err != nil {
				return nil, m, err
			}
			m.refs[p] = true
			continue
		}
		if !env.ShowPersonalData() && !literalOK(v) {
			return nil, m, filterRefused(env, name, true)
		}
		m.ids[v] = true
		literals = append(literals, v)
	}
	if len(values) == 0 {
		return nil, m, nil
	}
	if len(m.refs) > 0 {
		if env.ShowPersonalData() {
			for _, v := range literals {
				if !idsExact || !literalOK(v) {
					return nil, m, validationf("the " + name + " filter mixes a pseudonym with " + strconv.Quote(v) +
						", which only the server can match (a ~search, a substring or an address), so the filter would drop it: filter by pseudonyms or by literals, not both")
				}
			}
		}
		// The server cannot match a pseudonym, and narrowing by the other values
		// would drop the entries the pseudonyms match: everything is matched here.
		m.on = true
		return nil, m, nil
	}
	m.on = !env.ShowPersonalData()
	if env.ShowPersonalData() && !idsExact {
		for _, v := range values {
			m.subs = append(m.subs, strings.ToLower(v))
		}
		return nil, m, nil
	}
	return values, m, nil
}

// keep reports whether an entry passes: its ID is one of the exact IDs asked for,
// or one of the pseudonyms asked for is among shown, which must list the
// pseudonyms the entry's display names for this field and no others. A pseudonym
// the display does not show must not match, or asking for it would confirm a
// guess at the hidden value; one it does show must, or the filter drops entries
// it names.
func (m auditMatch) keep(id string, shown func() []string) bool {
	if !m.on || m.ids[id] {
		return true
	}
	if len(m.refs) == 0 {
		return false
	}
	for _, p := range shown() {
		if m.refs[p] {
			return true
		}
	}
	return false
}

// keepShown reports whether an entry passes a substring filter: one of the
// literals asked for, in any case, is in one of the texts fields returns, which
// must be those the result shows and no others, so that a match never confirms
// what the result hides. Without substrings it keeps everything.
func (m auditMatch) keepShown(fields func() []string) bool {
	if len(m.subs) == 0 {
		return true
	}
	for _, f := range fields() {
		f = strings.ToLower(f)
		for _, sub := range m.subs {
			if strings.Contains(f, sub) {
				return true
			}
		}
	}
	return false
}

// shownTarget returns the text fields of a target as the result shows them.
func shownTarget(env *registry.Env, t AuditTarget) []string {
	env.Display(&t) // t is a copy
	return []string{t.ID, t.Name, t.Type, t.Property}
}

// wholeRefs are the pseudonyms a result shows for values masked whole: while
// masking is on, those the display carries, which is none for a value masking
// leaves as it is (an empty one, tagged devices) and none for one whose pseudonym
// the length cap cuts off. With masking off nothing is hidden, so every
// non-empty value keeps its pseudonym as a convenient name.
func wholeRefs(env *registry.Env, values ...string) []string {
	var out []string
	for _, v := range values {
		switch {
		case v == "":
		case env.ShowPersonalData():
			out = append(out, env.Privacy.APIPseudonym(v))
		default:
			out = append(out, env.PersonalRefs(v)...)
		}
	}
	return out
}

// Check refuses a limit out of range, a cursor given with a window or that no page
// issued, and a window that is malformed or too long, before anything is sent. What
// depends on the filters or the privacy setting waits for the run. Zero means the
// default limit.
func (in AuditLogInput) Check() error {
	if in.Limit != 0 && (in.Limit < 1 || in.Limit > 5000) {
		return validationf("limit must be between 1 and 5000")
	}
	if in.Cursor != "" && (in.Start != "" || in.End != "") {
		return validationf("a cursor fixes the window: omit start and end")
	}
	if in.Cursor == "" {
		return checkWindow(in.Start, in.End, auditMaxSpan)
	}
	_, _, _, _, err := decodeAuditCursor(in.Cursor)
	return err
}

func auditLog(ctx context.Context, env *registry.Env, in AuditLogInput) (AuditLogOutput, error) {
	limit := in.Limit
	if limit == 0 {
		limit = 500
	}
	filters := auditFilters(env, in, limit)
	var (
		start, end, after time.Time
		cur               *auditCursor
	)
	if in.Cursor != "" {
		c, s, e, a, err := decodeAuditCursor(in.Cursor)
		if err != nil {
			return AuditLogOutput{}, err
		}
		if c.Filters != filters {
			return AuditLogOutput{}, validationf("the filters, includeValues, the privacy setting or the privacy key differ from the page that issued this cursor; repeat them, or start again without a cursor")
		}
		start, end, after, cur = s, e, a, &c
	} else {
		var err error
		if start, end, err = parseWindow(env.Clock(), in.Start, in.End, 24*time.Hour, auditMaxSpan); err != nil {
			return AuditLogOutput{}, err
		}
	}
	q := url.Values{"start": {start.UTC().Format(time.RFC3339Nano)}, "end": {end.UTC().Format(time.RFC3339Nano)}}
	actors, actorMatch, err := splitAuditFilter(env, "actor", in.Actor, func(v string) bool {
		return !strings.HasPrefix(v, "~") && !strings.Contains(v, "@")
	}, true)
	if err != nil {
		return AuditLogOutput{}, err
	}
	targets, targetMatch, err := splitAuditFilter(env, "target", in.Target, plainIDRE.MatchString, false)
	if err != nil {
		return AuditLogOutput{}, err
	}
	for _, a := range actors {
		q.Add("actor", a)
	}
	for _, t := range targets {
		q.Add("target", t)
	}
	for _, e := range in.Event {
		q.Add("event", e)
	}
	path, err := tailnetPath(env, "/logging/configuration")
	if err != nil {
		return AuditLogOutput{}, err
	}
	var r struct {
		Logs []struct {
			EventTime     string          `json:"eventTime"`
			DeferredAt    string          `json:"deferredAt"`
			EventGroupID  string          `json:"eventGroupID"`
			Origin        string          `json:"origin"`
			Action        string          `json:"action"`
			Actor         AuditActor      `json:"actor"`
			Target        AuditTarget     `json:"target"`
			Old           json.RawMessage `json:"old"`
			New           json.RawMessage `json:"new"`
			ActionDetails string          `json:"actionDetails"`
			Error         string          `json:"error"`
		} `json:"logs"`
	}
	if err := get(ctx, env, path, q, &r); err != nil {
		return AuditLogOutput{}, err
	}
	origins := map[string]bool{}
	for _, o := range in.Origin {
		origins[strings.ToUpper(o)] = true
	}
	var all []timedEntry
	for _, l := range r.Logs {
		// Webhook and log-stream endpoints carry their token in the URL path, and
		// the audit log names them (spec Appendix C): cut every URL in every
		// free-text field to its host before anything filters, shows or orders the
		// entry. Secrets are not personal data, so this holds with personalData
		// set to show, too.
		l.Target.Name, l.Target.Property = cutURLs(l.Target.Name), cutURLs(l.Target.Property)
		l.ActionDetails, l.Error = cutURLs(l.ActionDetails), cutURLs(l.Error)
		if len(origins) > 0 && !origins[l.Origin] {
			continue
		}
		// A login and a display name are personal fields, masked whole, so each
		// is named by the pseudonym of the whole value. A target name and property
		// are untrusted text: each address inside them is named, and the text as a
		// whole is not.
		if !actorMatch.keep(l.Actor.ID, func() []string { return wholeRefs(env, l.Actor.LoginName, l.Actor.DisplayName) }) ||
			!targetMatch.keep(l.Target.ID, func() []string {
				return append(env.UntrustedRefs(l.Target.Name), env.UntrustedRefs(l.Target.Property)...)
			}) ||
			!targetMatch.keepShown(func() []string { return shownTarget(env, l.Target) }) {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, l.EventTime)
		if err != nil {
			return AuditLogOutput{}, tkerr.New(tkerr.APIError, "an audit entry has an unparsable eventTime, so the log cannot be paged", "")
		}
		e := AuditEntry{
			EventTime: l.EventTime, DeferredAt: l.DeferredAt, EventGroupID: l.EventGroupID, Origin: l.Origin,
			Action: l.Action, Actor: l.Actor, Target: l.Target, ActionDetails: l.ActionDetails, Error: l.Error,
		}
		e.OldDigest, e.OldPreview = digestPreview(l.Old, env, in.IncludeValues)
		e.NewDigest, e.NewPreview = digestPreview(l.New, env, in.IncludeValues)
		all = append(all, timedEntry{t, displayKey(env, e), e})
	}
	// RFC 3339 strings with different fractional precision do not sort as text.
	// Equal times sort by content, so a cursor's skip count does not depend on the
	// order the API returned them in.
	sort.Slice(all, func(i, j int) bool {
		if !all[i].t.Equal(all[j].t) {
			return all[i].t.Before(all[j].t)
		}
		return all[i].k < all[j].k
	})
	if cur != nil {
		i, seen := 0, 0
		for i < len(all) && all[i].t.Before(after) {
			i++
		}
		for i < len(all) && all[i].t.Equal(after) && seen < cur.Skip {
			i, seen = i+1, seen+1
		}
		all = all[i:]
	}
	out := AuditLogOutput{WindowStart: start.UTC().Format(time.RFC3339Nano), WindowEnd: end.UTC().Format(time.RFC3339Nano),
		Note: auditNote, Entries: []AuditEntry{}}
	if len(all) > limit {
		last := all[limit-1].t
		next := auditCursor{Start: out.WindowStart, End: out.WindowEnd, After: last.UTC().Format(time.RFC3339Nano), Filters: filters}
		for _, te := range all[:limit] {
			if te.t.Equal(last) {
				next.Skip++
			}
		}
		if cur != nil && last.Equal(after) {
			next.Skip += cur.Skip
		}
		out.NextCursor = next.encode()
		all = all[:limit]
	}
	for _, te := range all {
		out.Entries = append(out.Entries, te.e)
	}
	out.Count = len(out.Entries)
	if !env.ShowPersonalData() && env.Privacy == nil {
		if env.PrivacyErr != nil {
			out.Note += digestsWithheldBadKey
		} else {
			out.Note += digestsWithheld
		}
	}
	return out, nil
}

// digestPreview returns a digest of a raw JSON value and a short preview of it
// (spec Appendix C). The digest is over the raw value; the preview is not: values
// under credential-named keys are removed from it and every URL is cut to its host,
// both before anything else, since the cap below could cut a token in half and
// leave a piece of it. While masking is on, the digest is keyed, or left out when
// no key is loaded, since an unkeyed hash confirms a guessed value; and the preview
// is masked before it is capped, which would otherwise leave an address too short
// to recognise.
func digestPreview(raw json.RawMessage, env *registry.Env, wantPreview bool) (string, string) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", ""
	}
	digest := ""
	if env.ShowPersonalData() {
		sum := sha256.Sum256(raw)
		digest = "sha256:" + hex.EncodeToString(sum[:])
	} else if env.Privacy != nil {
		digest = env.Privacy.Digest(raw)
	}
	if !wantPreview {
		return digest, ""
	}
	preview := cutURLs(previewText(raw))
	if !env.ShowPersonalData() {
		preview = env.Masker().Text(preview)
	}
	return digest, sanitize.String(preview, 256)
}

// previewText is a value as text: a string is its content, with credential-named
// values removed if the content is itself a JSON object or array, or HuJSON, as a
// policy file is; anything else is its JSON with those removed.
func previewText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		text, _ := redactJSONText(s)
		return text
	}
	return string(redactSecrets(raw))
}

// Check refuses a window that is malformed or too long and a maxRecords out of
// range, before anything is sent. Zero means the default.
func (in FlowLogsInput) Check() error {
	if err := checkWindow(in.Start, in.End, flowMaxSpan); err != nil {
		return err
	}
	if in.MaxRecords != 0 && (in.MaxRecords < 1 || in.MaxRecords > 10000) {
		return validationf("maxRecords must be between 1 and 10000")
	}
	return nil
}

func networkFlowLogs(ctx context.Context, env *registry.Env, in FlowLogsInput) (FlowLogsOutput, error) {
	now := env.Clock()
	start, end, err := parseWindow(now, in.Start, in.End, 15*time.Minute, flowMaxSpan)
	if err != nil {
		return FlowLogsOutput{}, err
	}
	maxRecords := in.MaxRecords
	if maxRecords == 0 {
		maxRecords = 1000
	}
	out := FlowLogsOutput{Records: []FlowRecord{}, AsOf: now.UTC().Format(time.RFC3339), MayBeIncomplete: true, LoggingEnabled: "unknown",
		Note: "Node-reported times and traffic are not verified by Tailscale; only successful connections are logged; repeated queries may differ."}
	// An empty answer must never read as "no traffic" when logging is off.
	settingsPath, err := tailnetPath(env, "/settings")
	if err != nil {
		return FlowLogsOutput{}, err
	}
	var s Settings
	if err := get(ctx, env, settingsPath, nil, &s); err == nil && s.NetworkFlowLoggingOn != nil {
		out.LoggingEnabled = "false"
		if !*s.NetworkFlowLoggingOn {
			out.Status = "not_enabled"
			return out, nil
		}
		out.LoggingEnabled = "true"
	}
	path, err := tailnetPath(env, "/logging/network")
	if err != nil {
		return FlowLogsOutput{}, err
	}
	type counter struct {
		Proto   flowProto `json:"proto"`
		Src     string    `json:"src"`
		Dst     string    `json:"dst"`
		TxPkts  int64     `json:"txPkts"`
		TxBytes int64     `json:"txBytes"`
		RxPkts  int64     `json:"rxPkts"`
		RxBytes int64     `json:"rxBytes"`
	}
	var r struct {
		Logs []struct {
			Logged   string    `json:"logged"`
			NodeID   string    `json:"nodeId"`
			Start    string    `json:"start"`
			End      string    `json:"end"`
			Virtual  []counter `json:"virtualTraffic"`
			Subnet   []counter `json:"subnetTraffic"`
			Exit     []counter `json:"exitTraffic"`
			Physical []counter `json:"physicalTraffic"`
		} `json:"logs"`
	}
	q := url.Values{"start": {start.UTC().Format(time.RFC3339Nano)}, "end": {end.UTC().Format(time.RFC3339Nano)}}
	if err := get(ctx, env, path, q, &r); err != nil {
		if e, ok := tkerr.As(err); ok && e.Code == tkerr.NotFound {
			out.Status = "not_available"
			return out, nil
		}
		return FlowLogsOutput{}, err
	}
	out.Status = "ok"
	for _, l := range r.Logs {
		if in.Node != "" && l.NodeID != in.Node {
			continue
		}
		if len(out.Records) == maxRecords {
			out.Truncated = true
			break
		}
		rec := FlowRecord{NodeID: l.NodeID, Logged: l.Logged, Start: l.Start, End: l.End, Flows: []Flow{}}
		for _, k := range []struct {
			kind string
			list []counter
		}{{"virtual", l.Virtual}, {"subnet", l.Subnet}, {"exit", l.Exit}, {"physical", l.Physical}} {
			for _, c := range k.list {
				rec.Flows = append(rec.Flows, Flow{Kind: k.kind, Proto: string(c.Proto), Src: c.Src, Dst: c.Dst,
					TxPkts: c.TxPkts, TxBytes: c.TxBytes, RxPkts: c.RxPkts, RxBytes: c.RxBytes})
			}
		}
		out.Records = append(out.Records, rec)
	}
	out.Count = len(out.Records)
	return out, nil
}

// flowProto accepts the protocol as a JSON number (the documented flow-log format
// and Tailscale's own encoding) or as a name (the OpenAPI document), and holds a
// name when one is known.
type flowProto string

var protoNames = map[int]string{1: "icmp", 2: "igmp", 4: "ipv4", 6: "tcp", 8: "egp", 9: "igp", 17: "udp",
	33: "dccp", 47: "gre", 50: "esp", 51: "ah", 58: "ipv6-icmp", 132: "sctp"}

func (p *flowProto) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*p = ""
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		if name, ok := protoNames[n]; ok {
			*p = flowProto(name)
		} else {
			*p = flowProto(strconv.Itoa(n))
		}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*p = flowProto(s)
	return nil
}

// Check refuses a log type Tailscale does not have, before anything is sent.
func (in LogStreamInput) Check() error {
	if !slices.Contains([]string{"configuration", "network"}, in.LogType) {
		return validationf("logType must be configuration or network")
	}
	return nil
}

func logStreamingGet(ctx context.Context, env *registry.Env, in LogStreamInput) (LogStreamOutput, error) {
	out := LogStreamOutput{LogType: in.LogType, Findings: []string{}}
	path, err := tailnetPath(env, "/logging/"+in.LogType+"/stream")
	if err != nil {
		return LogStreamOutput{}, err
	}
	var cfg LogStreamConfig
	if err := get(ctx, env, path, nil, &cfg); err != nil {
		if e, ok := tkerr.As(err); ok && e.Code == tkerr.NotFound {
			out.Status = "not_configured"
			return out, nil
		}
		return LogStreamOutput{}, err
	}
	cfg.URL, cfg.URLPathHash = shownEndpoint(cfg.URL)
	out.Status, out.Configuration = "configured", &cfg
	var st LogStreamStatus
	if err := get(ctx, env, path+"/status", nil, &st); err != nil {
		out.HealthError = string(tkerr.From(err).Code)
	} else {
		// A delivery error quotes the collector's URL, which carries its token.
		st.LastError = cutURLs(st.LastError)
		out.Health = &st
		if st.LastError != "" {
			out.Findings = append(out.Findings, "last_error")
		}
		if st.NumSpoofedEntries > 0 {
			out.Findings = append(out.Findings, "spoofed_entries")
		}
		if st.NumTotalRequests > 0 && st.NumFailedRequests*10 > st.NumTotalRequests {
			out.Findings = append(out.Findings, "high_failure_ratio")
		}
		if staleActivity(st.LastActivity, cfg.UploadPeriodMinutes, env.Clock()) {
			out.Findings = append(out.Findings, "stale_activity")
		}
	}
	return out, nil
}

// staleActivity reports a stream with no delivery for three upload periods, and at
// least an hour. A missing or unparsable lastActivity counts as stale: nothing shows
// that delivery works. The period is capped at a day, so an absurd value cannot
// hide a dead stream.
func staleActivity(last string, periodMinutes int, now time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, last)
	if err != nil {
		return true
	}
	period := time.Duration(min(max(periodMinutes, 0), 24*60)) * time.Minute
	return now.Sub(t) > max(3*period, time.Hour)
}
