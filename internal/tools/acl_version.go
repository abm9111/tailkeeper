package tools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

const (
	versionPrefix = "v1."
	maxVersionID  = 512
	// versionWindow is how far either side of an id's time readVersionText asks for.
	// The two sides together are the two-second window.
	versionWindow = time.Second
)

// A version id names a moment the log can still be asked for. Times outside this
// range are not a cursor into that log.
var (
	versionEarliest = time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)
	versionLatest   = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

// versionRef is the content of a version id: the entry's time, its event group,
// its place among entries with that time, and which side of the entry the text is.
type versionRef struct {
	Time    string `json:"t"`
	Group   string `json:"g"`
	Ordinal int    `json:"n"`
	Side    string `json:"s"` // "new" or "old"
}

// versionGroupMax and versionTimeMax are the most bytes of an event group and of an entry's
// time that an id carries. With the most digits an ordinal can have, an id of the longest group
// and time is under half of maxVersionID, so an id acl_history writes is one acl_diff accepts.
const (
	versionGroupMax = 160
	versionTimeMax  = 64
)

// versionGroup is the event group an id carries: the log's own id when its JSON text is short,
// and otherwise a digest of it, which names the same entries.
func versionGroup(group string) string {
	if b, err := json.Marshal(group); err == nil && len(b) <= versionGroupMax {
		return group
	}
	sum := sha256.Sum256([]byte(group))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// versionEventTime is the time an entry shows and an id carries: the log's own text of it, or,
// for a text longer than any time is written, the time in its canonical form.
func versionEventTime(raw string, t time.Time) string {
	if len(raw) <= versionTimeMax {
		return raw
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func encodeVersionID(r versionRef) string {
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return versionPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func decodeVersionID(s string) (versionRef, error) {
	bad := validationf("version must be a version id from acl_history")
	if len(s) > maxVersionID {
		return versionRef{}, validationf("version id is too long")
	}
	rest, ok := strings.CutPrefix(s, versionPrefix)
	if !ok || rest == "" {
		return versionRef{}, bad
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return versionRef{}, bad
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r versionRef
	if err := dec.Decode(&r); err != nil {
		return versionRef{}, bad
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return versionRef{}, bad
	}
	if (r.Side != "new" && r.Side != "old") || r.Ordinal < 0 {
		return versionRef{}, bad
	}
	t, err := time.Parse(time.RFC3339Nano, r.Time)
	if err != nil || t.Before(versionEarliest) || !t.Before(versionLatest) {
		return versionRef{}, validationf("the version time is outside the retention window")
	}
	return r, nil
}

// readVersionText reads the policy text a version id names. It asks for the two
// seconds around the id's time, keeps only ACL updates, and returns the side the
// id names. The text is the log's own; the caller masks it on the way out.
func readVersionText(ctx context.Context, env *registry.Env, id string) (rawPolicyText, error) {
	ref, err := decodeVersionID(id)
	if err != nil {
		return rawPolicyText{}, err
	}
	when, err := time.Parse(time.RFC3339Nano, ref.Time)
	if err != nil {
		return rawPolicyText{}, validationf("the version time is outside the retention window")
	}
	items, _, err := readHistory(ctx, env, when.Add(-versionWindow), when.Add(versionWindow))
	if err != nil {
		return rawPolicyText{}, err
	}
	matched := -1
	for i := range items {
		if items[i].ordinal == ref.Ordinal && items[i].group == ref.Group && items[i].t.Equal(when) {
			matched = i
			break
		}
	}
	if matched < 0 {
		return rawPolicyText{}, versionGone()
	}
	text := items[matched].newText
	if ref.Side == "old" {
		text = items[matched].oldText
	}
	if len(text) > guard.MaxPolicyBytes {
		return rawPolicyText{}, validationf(fmt.Sprintf("the policy is over the cap of %d bytes", guard.MaxPolicyBytes))
	}
	return rawPolicyText{b: []byte(text)}, nil
}

// rawPolicyText is the log's policy bytes. It has no String, Error, MarshalJSON
// or MarshalText method. Formatting it prints a fixed placeholder. The bytes are
// unexported; a caller masks them before they leave the package.
type rawPolicyText struct {
	b []byte
}

func (rawPolicyText) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "raw policy text")
}

func versionGone() error {
	return tkerr.New(tkerr.NotFound, "the log no longer holds this version",
		"list the versions again with acl history; an entry can be deferred, and the log keeps a finite history")
}
