package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

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
