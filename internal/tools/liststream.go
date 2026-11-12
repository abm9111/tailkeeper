package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// maxListRows is the most rows a list tool keeps from one response. An 8 MiB body of
// empty objects is millions of rows; decoding them all into structs took gigabytes.
const maxListRows = 512

func getRead(ctx context.Context, env *registry.Env, path string, q url.Values, read func(io.Reader) error) error {
	c, err := env.RequireAPI()
	if err != nil {
		return err
	}
	return c.GetRead(ctx, path, q, read)
}

// readRows reads the array named field from one JSON object, one element at a time.
// row sees each element and must copy anything it keeps: the buffer is reused.
// Rows after maxListRows are still read, so the body is consumed, and tooMany is set.
func readRows(body io.Reader, field string, row func(json.RawMessage) error) (n int, tooMany bool, err error) {
	dec := json.NewDecoder(body)
	tok, err := dec.Token()
	if err != nil {
		return 0, false, err
	}
	if tok != json.Delim('{') {
		return 0, false, errors.New("the API response is not a JSON object")
	}
	found := false
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return n, tooMany, err
		}
		name, _ := key.(string)
		if !strings.EqualFold(name, field) {
			if err := skipJSON(dec); err != nil {
				return n, tooMany, err
			}
			continue
		}
		if found {
			return n, tooMany, fmt.Errorf("the API response has two %s arrays", field)
		}
		found = true
		if err := readOneArray(dec, func(raw json.RawMessage) error {
			n++
			if n > maxListRows {
				tooMany = true
			}
			return row(raw)
		}); err != nil {
			return n, tooMany, err
		}
	}
	if err := wantEnd(dec, '}'); err != nil {
		return n, tooMany, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return n, tooMany, errors.New("the API response has more data after its JSON value")
	}
	return n, tooMany, nil
}

func readOneArray(dec *json.Decoder, row func(json.RawMessage) error) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return errors.New("the list is not an array")
	}
	var raw json.RawMessage
	for dec.More() {
		raw = raw[:0]
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		if err := row(raw); err != nil {
			return err
		}
	}
	return wantEnd(dec, ']')
}

func wantEnd(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != d {
		return fmt.Errorf("expected %q", d)
	}
	return nil
}

func skipJSON(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); ok {
		if d == '{' || d == '[' {
			for dec.More() {
				if d == '{' {
					if _, err := dec.Token(); err != nil {
						return err
					}
				}
				if err := skipJSON(dec); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
	}
	return nil
}

// readTopRows reads a body whose one JSON value is an array, one element at a time.
func readTopRows(body io.Reader, row func(json.RawMessage) error) (n int, tooMany bool, err error) {
	dec := json.NewDecoder(body)
	if err := readOneArray(dec, func(raw json.RawMessage) error {
		n++
		if n > maxListRows {
			tooMany = true
		}
		return row(raw)
	}); err != nil {
		return n, tooMany, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return n, tooMany, errors.New("the API response has more data after its JSON value")
	}
	return n, tooMany, nil
}

// collectField reads the named array of an object into at most maxListRows values.
func collectField[T any](ctx context.Context, env *registry.Env, path string, q url.Values, field, what string) ([]T, error) {
	var out []T
	_, tooMany, err := readRowsKept(ctx, env, path, q, field, func(raw json.RawMessage) error {
		if len(out) >= maxListRows {
			return nil
		}
		var row T
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}
		out = append(out, row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if tooMany {
		return nil, tooManyRows(what)
	}
	if out == nil {
		out = []T{}
	}
	return out, nil
}

// collectArray reads a body that is itself an array.
func collectArray[T any](ctx context.Context, env *registry.Env, path, what string) ([]T, error) {
	var out []T
	var n int
	var tooMany bool
	err := getRead(ctx, env, path, nil, func(body io.Reader) error {
		var err error
		n, tooMany, err = readTopRows(body, func(raw json.RawMessage) error {
			if len(out) >= maxListRows {
				return nil
			}
			var row T
			if err := json.Unmarshal(raw, &row); err != nil {
				return err
			}
			out = append(out, row)
			return nil
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	if tooMany || n > maxListRows {
		return nil, tooManyRows(what)
	}
	if out == nil {
		out = []T{}
	}
	return out, nil
}

func tooManyRows(what string) error {
	return tkerr.New(tkerr.APIError,
		fmt.Sprintf("the %s list has more than %d rows", what, maxListRows),
		"narrow the request if it has filters")
}
