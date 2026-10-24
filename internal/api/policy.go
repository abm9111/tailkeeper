package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	hujsonguard "github.com/abm9111/tailkeeper/internal/guard"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// RawResponse is one answer of the API, whatever its status: the HTTP status, the
// ETag header verbatim (quotes included; "" when the API sent none) and the body
// unparsed. The low-level calls below return a non-2xx answer as data, not as an
// error, because the probes exist to see what the API says to a request
// that fails. A later, strict reader decides what each status means.
type RawResponse struct {
	Status int
	ETag   string
	Body   []byte
}

// ValidatePolicy sends body to POST .../acl/validate with the given Content-Type
// and returns the answer. The endpoint chooses its mode from the body: a JSON array
// is a set of tests run against the live policy (send application/json), a JSON
// object is a policy to validate (send application/hujson, the policy's exact
// bytes). The call changes nothing on the tailnet. It makes one attempt: no retry on
// a 429 or a 5xx, and no check that the body suits the content type (the probes send
// mismatches on purpose). A transport failure, and a body over the client's limit,
// are errors.
func (c *Client) ValidatePolicy(ctx context.Context, body []byte, contentType string) (RawResponse, error) {
	h := http.Header{}
	h.Set("Accept", "application/json")
	h.Set("Content-Type", contentType)
	return c.once(ctx, http.MethodPost, c.base.String()+c.TailnetPath("/acl/validate"), body, h)
}

// PolicyGet selects how GetPolicy asks for the live policy.
type PolicyGet struct {
	Details     bool   // adds ?details=true: a JSON object with the policy, its warnings and errors
	Accept      string // "" sends no Accept header
	IfNoneMatch string // "" sends no If-None-Match header; otherwise the value, verbatim
}

// GetPolicy performs GET .../acl as g says and returns the answer: the status, the
// ETag and the body unparsed. One attempt, like ValidatePolicy.
func (c *Client) GetPolicy(ctx context.Context, g PolicyGet) (RawResponse, error) {
	rawURL := c.base.String() + c.TailnetPath("/acl")
	if g.Details {
		rawURL += "?details=true"
	}
	h := http.Header{}
	if g.Accept != "" {
		h.Set("Accept", g.Accept)
	}
	if g.IfNoneMatch != "" {
		h.Set("If-None-Match", g.IfNoneMatch)
	}
	return c.once(ctx, http.MethodGet, rawURL, nil, h)
}

// GetOnce performs a GET of path (already escaped, see TailnetPath) with the query q and
// returns the answer, whatever its status: one attempt, no retry on a 429 or a 5xx, no
// Accept header. Get and GetRaw retry; the probes must not, because a second attempt is a
// request they did not plan.
func (c *Client) GetOnce(ctx context.Context, path string, q url.Values) (RawResponse, error) {
	if err := checkPath(path); err != nil {
		return RawResponse{}, err
	}
	full := c.base.String() + path
	if len(q) > 0 {
		full += "?" + q.Encode()
	}
	return c.once(ctx, http.MethodGet, full, nil, http.Header{})
}

// PolicyDetails is the live policy as GET .../acl?details=true answers it.
type PolicyDetails struct {
	Text     []byte   // the policy as HuJSON, decoded from the base64 acl field; at most guard.MaxPolicyBytes
	ETag     string   // the header verbatim, quotes included; "" when none
	Warnings []string // the server's own warnings for the stored policy: the baseline
	Errors   []string // the stored policy's errors: it no longer parses or resolves
}

// GetPolicyDetails reads the live policy with its warnings and errors in one request:
// GET .../acl?details=true, retried like any read. The answer is read strictly: the acl
// field is required and standard base64, warnings and errors are null or lists of strings,
// and any other shape is an error, never a zero-value success. A decoded policy over
// guard.MaxPolicyBytes is refused with its size. Text is not parsed here: what it holds,
// an array say, is for acl.Parse to refuse.
func (c *Client) GetPolicyDetails(ctx context.Context) (PolicyDetails, error) {
	var d PolicyDetails
	err := c.retry(ctx, func() error {
		// No Accept header. The OpenAPI document says not to send one with details, and
		// the observed answers are for none and for application/hujson; a live read on
		// 24 Oct 2026 that sent application/json got an acl field that is not base64.
		return c.do(ctx, http.MethodGet, c.base.String()+c.TailnetPath("/acl")+"?details=true", nil, "", "", false, func(r io.Reader, resp *http.Response) error {
			b, err := c.readAll(r)
			if err != nil {
				return err
			}
			if d, err = readDetails(b); err != nil {
				return err
			}
			d.ETag = resp.Header.Get("ETag")
			return nil
		})
	})
	return d, err
}

// readDetails reads the body of a details=true answer.
func readDetails(b []byte) (PolicyDetails, error) {
	top, err := fields(b, "acl", "warnings", "errors")
	if err != nil {
		return PolicyDetails{}, unrecognisedPolicy("it " + err.Error())
	}
	var encoded string
	raw, ok := top["acl"]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &encoded) != nil || encoded == "" {
		return PolicyDetails{}, unrecognisedPolicy("it has no acl field holding the policy as a string")
	}
	text, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return PolicyDetails{}, unrecognisedPolicy("its acl field is not standard base64")
	}
	if len(text) > hujsonguard.MaxPolicyBytes {
		return PolicyDetails{}, policyTooLarge(len(text))
	}
	d := PolicyDetails{Text: text}
	if stringList(top, "warnings", &d.Warnings) != nil || stringList(top, "errors", &d.Errors) != nil {
		return PolicyDetails{}, unrecognisedPolicy("its warnings or errors are not lists of strings")
	}
	return d, nil
}

// stringList decodes the field k of an object that fields split into out: absent or null
// leaves out nil, and anything but a list of strings is an error. A null element is one:
// decoding straight into a list of strings would turn it into an empty string.
func stringList(f map[string]json.RawMessage, k string, out *[]string) error {
	var items []*string
	if err := field(f, k, &items); err != nil {
		return err
	}
	if items == nil {
		return nil
	}
	list := make([]string, len(items))
	for i, item := range items {
		if item == nil {
			return fmt.Errorf("element %d of %s is null", i, k)
		}
		list[i] = *item
	}
	*out = list
	return nil
}

func unrecognisedPolicy(why string) error {
	return tkerr.New(tkerr.APIError, "the policy read answered with an unrecognised response: "+why,
		"the API may have changed; run `tailkeeper doctor --probe`")
}

// policyOverCapHint is the hint of tailkeeper's own refusal of a live policy over the cap:
// Tailscale refused nothing, so it does not say so (policyTooLargeHint is for its refusals).
const policyOverCapHint = "tailkeeper reads and checks policies up to 4 MiB (policy_too_large): the policy has to lose sections or comments, in the admin console, before tailkeeper can read it"

// policyTooLarge is the error for a live policy over guard.MaxPolicyBytes.
func policyTooLarge(n int) error {
	return tkerr.New(tkerr.APIError, fmt.Sprintf("the live policy is %d bytes, more than the 4 MiB tailkeeper reads", n), policyOverCapHint)
}

// PolicyStamp identifies the live policy without carrying it.
type PolicyStamp struct {
	ETag   string // the header verbatim, quotes included; "" when none
	SHA256 string // lower-case hex of the plain body's bytes
}

// LiveStamp reads the live policy once more, as the plain text, and returns its ETag and
// the SHA-256 of its bytes. It is the re-check after a validation: the API never answered
// 304 to If-None-Match (probe A-8), so nothing sends that header, and the whole body is
// read again. A policy over guard.MaxPolicyBytes is refused with its size.
func (c *Client) LiveStamp(ctx context.Context) (PolicyStamp, error) {
	raw, err := c.GetRaw(ctx, c.TailnetPath("/acl"), "application/hujson")
	if err != nil {
		return PolicyStamp{}, err
	}
	if len(raw.Body) > hujsonguard.MaxPolicyBytes {
		return PolicyStamp{}, policyTooLarge(len(raw.Body))
	}
	sum := sha256.Sum256(raw.Body)
	return PolicyStamp{ETag: raw.ETag, SHA256: hex.EncodeToString(sum[:])}, nil
}

// ETagOf is the ETag the API gives a policy whose plain body is body: the SHA-256 of the
// bytes as lower-case hex, in quotes (probe A-13). A text that is not the body as the API
// sent it has another ETag.
func ETagOf(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// maxValidateReply bounds the reply tailkeeper reads to a policy-mode validation.
const maxValidateReply = 1 << 20

// validatePolicy sends a policy to the validate endpoint in policy mode (Content-Type
// application/hujson, the exact bytes) and reads the answer strictly. It is unmetered:
// the callers outside this package go through ValidateCall, which takes the bucket's
// tokens. body must be a top-level object, once white space and comments are skipped: an
// array there would run in tests mode and read as a pass for a policy never validated.
// It is retried like a read, except that a 500 is retried once: after the second one the
// error is policy_rejected_or_server_error, which never repeats the server's body. A 400
// whose bare message speaks of size stays a rejection and carries policyTooLargeHint in
// its Hint, for the tool that shows it.
func (c *Client) validatePolicy(ctx context.Context, body []byte) (PolicyValidation, error) {
	if !startsAnObject(body) {
		return PolicyValidation{}, tkerr.New(tkerr.Internal, "a policy-mode body must be a top-level object", "this is a tailkeeper bug; report it")
	}
	var v PolicyValidation
	fiveHundreds := 0
	err := c.retryWith(ctx, func() error {
		return c.do(ctx, http.MethodPost, c.base.String()+c.TailnetPath("/acl/validate"), body, "application/hujson", "application/json", true, func(r io.Reader, resp *http.Response) error {
			b, err := io.ReadAll(io.LimitReader(r, maxValidateReply+1))
			if err != nil {
				return err
			}
			if len(b) > maxValidateReply {
				return tkerr.New(tkerr.APIError, "the validate reply is longer than 1 MiB", "the API may have changed; run `tailkeeper doctor --probe`")
			}
			v = ReadPolicyValidation(resp.StatusCode, b)
			if v.Status == PolicyRejected && refusedForSize(resp, v.Message) {
				v.Hint = policyTooLargeHint
			}
			return nil
		})
	}, func(err error, retried int) bool {
		if e, ok := tkerr.As(err); ok && e.Status == http.StatusInternalServerError {
			fiveHundreds++
			return fiveHundreds < 2 && retried < c.retries
		}
		return retried < c.retries
	})
	if e, ok := tkerr.As(err); ok && e.Status == http.StatusInternalServerError {
		return PolicyValidation{}, serverErrorTwice(fiveHundreds)
	}
	return v, err
}

// serverErrorTwice is the error for a policy that got HTTP 500 on its last attempt.
func serverErrorTwice(n int) error {
	msg := "Tailscale answered HTTP 500 to this policy"
	if n > 1 {
		msg = "Tailscale answered HTTP 500 twice to this policy"
	}
	e := tkerr.New(tkerr.PolicyRejectedOrServerError, msg,
		"remove sections until the policy passes: the hosted service answers 500 for some policies it cannot evaluate, and a nodeAttrs entry that targets autogroup:self is one that fails on every send; running the same call again is safe, but it fails the same way until sections are removed")
	e.Status = http.StatusInternalServerError
	return e
}

// startsAnObject reports whether the first token of a HuJSON text is "{". White space and
// comments before it are skipped; a byte order mark is not, and an empty text has no token.
func startsAnObject(b []byte) bool {
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			end := bytes.Index(b[i+2:], []byte("*/"))
			if end < 0 {
				return false
			}
			i += 2 + end + 1
		default:
			return c == '{'
		}
	}
	return false
}

// once sends one request and returns whatever status comes back. The request goes
// through the same transports as every other, so the guard still refuses anything
// but GET and the validate POST.
func (c *Client) once(ctx context.Context, method, rawURL string, body []byte, hdr http.Header) (RawResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var rb io.Reader
	if len(body) > 0 {
		rb = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rb)
	if err != nil {
		return RawResponse{}, tkerr.Wrap(tkerr.Internal, err, "cannot build request", "")
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	resp, err := c.http.Do(req)
	if r := (*refusal)(nil); errors.As(err, &r) {
		return RawResponse{}, tkerr.New(tkerr.Internal, r.Error(), "this is a tailkeeper bug; report it")
	}
	if err != nil {
		return RawResponse{}, transportError(err)
	}
	defer func() { _ = resp.Body.Close() }() // read only
	b, err := c.readAll(&io.LimitedReader{R: resp.Body, N: c.maxBody + 1})
	switch {
	case errors.Is(err, errTooLarge):
		return RawResponse{}, tkerr.New(tkerr.APIError, fmt.Sprintf("response exceeded %d bytes", c.maxBody), "")
	case err != nil:
		return RawResponse{}, transportError(err)
	}
	return RawResponse{Status: resp.StatusCode, ETag: resp.Header.Get("ETag"), Body: b}, nil
}
