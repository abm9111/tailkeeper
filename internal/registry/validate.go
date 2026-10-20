package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// Checker is implemented by an input type that can refuse a value from the input
// alone: no API, no clock, no configuration. Validate runs it after the strict
// decode, so the CLI refuses a bad argument before it loads the configuration or
// starts the credential wrapper (a secret-manager unlock). A check that needs
// anything else belongs in the tool's run function.
//
// On the command line, Check runs before the binder fills the fields that are read
// from a file or from standard input, so a rule over loaded text lives in the run
// function. Such a field must be omitempty (optional in the schema), because
// Validate runs before it is set.
type Checker interface{ Check() error }

// Given says which CLI input flags a command line set, by flag name without the
// dashes ("from", "against", "patch", "invariants", "no-invariants", "offline").
// A flag whose value names the live policy ("--against live") counts as not set.
// MCP calls have no flags: Given only serves the CLI's decision whether to start
// the credential wrapper.
type Given map[string]bool

// OfflineInput is implemented by the input type of a tool whose Credential is
// CredOptional. RunsOffline says, from the flags the command line set, that the
// call will not touch the API.
type OfflineInput interface{ RunsOffline(g Given) bool }

// Prepared is an input that passed Validate, ready to run.
type Prepared struct {
	tool Tool
	in   reflect.Value // a pointer to the tool's input type
}

// Tool returns the tool the input was validated for.
func (p *Prepared) Tool() Tool { return p.tool }

// Input returns a pointer to the decoded input struct. The CLI sets the fields
// that are not part of the JSON arguments (file contents, flags that exist only
// on the command line) through it, between Validate and Run.
func (p *Prepared) Input() any { return p.in.Interface() }

// NeedsCredential says whether running the tool needs the read credential, which
// for the exec provider means starting its wrapper. g names the CLI flags that
// were set.
func (p *Prepared) NeedsCredential(g Given) bool {
	switch p.tool.Meta.Credential {
	case CredRead:
		return true
	case CredOptional:
		if o, ok := p.in.Interface().(OfflineInput); ok {
			return !o.RunsOffline(g)
		}
		return true
	}
	return false
}

// Validate decodes raw JSON arguments against the input schema, strictly, and runs
// the input's Check method. It touches nothing else, so a caller can run it before
// it loads the configuration or unlocks a credential. Its errors are scrubbed like
// the errors of Call, but masked as if masking were on: the owner's setting is not
// loaded yet, and an error echoes what the caller typed.
func (t Tool) Validate(raw json.RawMessage) (*Prepared, error) { return t.validate(nil, raw) }

func (t Tool) validate(env *Env, raw json.RawMessage) (p *Prepared, err error) {
	defer func() {
		if r := recover(); r != nil {
			p, err = nil, scrub(tkerr.New(tkerr.Internal, "unexpected internal error in "+t.Meta.Name, "report this with `tailkeeper version` output"), t.Meta, env)
		}
	}()
	in, err := t.decode(raw)
	if err != nil {
		return nil, scrub(err, t.Meta, env)
	}
	return &Prepared{tool: t, in: in}, nil
}

func (t Tool) decode(raw json.RawMessage) (reflect.Value, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		raw = json.RawMessage("{}")
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return reflect.Value{}, tkerr.New(tkerr.ValidationFailed, "arguments are not valid JSON", "")
	}
	if err := t.resolved.Validate(generic); err != nil {
		return reflect.Value{}, tkerr.New(tkerr.ValidationFailed, "invalid arguments: "+err.Error(), "")
	}
	in := reflect.New(t.InputType)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(in.Interface()); err != nil {
		return reflect.Value{}, tkerr.New(tkerr.ValidationFailed, "invalid arguments: "+err.Error(), "")
	}
	if c, ok := in.Interface().(Checker); ok {
		if err := c.Check(); err != nil {
			return reflect.Value{}, err
		}
	}
	return in, nil
}

// Run runs the tool on the validated input. Errors leave it the way results do,
// sanitized and then scanned by the secret tripwire, and a panic in the tool
// becomes internal_error without its value.
func (p *Prepared) Run(ctx context.Context, env *Env) (out any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = tkerr.New(tkerr.Internal, "unexpected internal error in "+p.tool.Meta.Name, "report this with `tailkeeper version` output")
		}
		if err != nil {
			out, err = nil, scrub(err, p.tool.Meta, env)
		}
	}()
	return p.tool.run(ctx, env, p.in.Elem().Interface())
}

// Call validates raw JSON arguments and runs the tool: Validate, then Run.
func (t Tool) Call(ctx context.Context, env *Env, raw json.RawMessage) (any, error) {
	p, err := t.validate(env, raw)
	if err != nil {
		return nil, err
	}
	return p.Run(ctx, env)
}
