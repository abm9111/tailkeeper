package tools

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/sanitize"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// ProbeStatus is what one policy-mode probe established. A reading tailkeeper did
// not establish is a warning or a failure, never ok.
type ProbeStatus string

const (
	ProbeOK   ProbeStatus = "ok"
	ProbeWarn ProbeStatus = "warn"
	ProbeFail ProbeStatus = "fail"
	ProbeNA   ProbeStatus = "n/a"
)

// PolicyProbe is one row of the policy-mode probes doctor runs. Called is true when
// the probe made a request, or tried to; a probe that stopped before it asked
// anything (the canary with no live policy to build on, or a send tailkeeper's own
// validation limit refused) is not a call. Code is the
// code of the error the call returned, empty when it returned none. Only the code
// leaves the probe: the error's text is tailnet text and stays out of this struct.
type PolicyProbe struct {
	Name   string
	Status ProbeStatus
	Detail string
	Fix    string
	Called bool
	Code   tkerr.Code
}

const (
	probeRejection = "probe policy rejection"
	probeDetails   = "probe details keys"
	probeCanary    = "probe invariants canary"
	probeSSH       = "probe ssh tests"

	// rejectionDocument is the one-line document the rejection probe sends. The server
	// refuses nodeAttr (singular); a pass means that refusal is no longer what this
	// document proves.
	rejectionDocument = `{"nodeAttr": []}`

	kindUnread = "the reading of this destination kind did not map to a verdict: acl_test results for it are not evidence"
	kindPassed = "a test no policy can pass came back as passed: acl_test results for this kind cannot be trusted"
	reportIt   = "report this with `tailkeeper version`"
)

// sshProbeDocument is a policy that exists only for the probe: one tag, one ssh rule
// and one sshTests entry that accepts and denies the same user, so exactly one of the
// two fails in the SSH form if sshTests runs. Nothing in it comes from the tailnet.
var sshProbeDocument = func() []byte {
	b, err := json.Marshal(map[string]any{
		"tagOwners": map[string][]string{"tag:tailkeeper-probe": {}},
		"ssh": []map[string]any{{
			"action": "accept",
			"src":    []string{"tag:tailkeeper-probe"},
			"dst":    []string{"tag:tailkeeper-probe"},
			"users":  []string{"canary"},
		}},
		"sshTests": []map[string]any{{
			"src":    "tag:tailkeeper-probe",
			"dst":    []string{"192.0.2.1"},
			"accept": []string{"canary"},
			"deny":   []string{"canary"},
		}},
	})
	if err != nil {
		panic(err) // fixed strings always encode
	}
	return b
}()

// ProbePolicyMode runs the four policy-mode probes, in order: a document the server
// rejects, the details reader, the in-band canary on the live policy, and one synthetic
// SSH document. Each send takes one token of the validation bucket. The details read
// takes none.
func ProbePolicyMode(ctx context.Context, env *registry.Env) []PolicyProbe {
	c, err := env.RequireAPI()
	if err != nil {
		rows := []PolicyProbe{
			probeErr(probeRejection, err),
			probeErr(probeDetails, err),
			probeErr(probeCanary, err),
			probeErr(probeSSH, err),
		}
		for i := range rows {
			rows[i].Called = false
		}
		return rows
	}
	out := make([]PolicyProbe, 0, 4)
	out = append(out, probePolicyRejection(ctx, c))
	text, row := probeDetailsKeys(ctx, c)
	out = append(out, row)
	out = append(out, probeInvariantsCanary(ctx, c, text, row.Status == ProbeOK))
	out = append(out, probeSSHTests(ctx, c))
	return out
}

// ClassifyKind is the row for one destination kind. ok only when the test failed and
// a verdict is allowed or denied. unknown, unresolved and a pass are not that.
func ClassifyKind(status string, verdicts []string) (st ProbeStatus, detail, fix string) {
	switch status {
	case statusPass:
		return ProbeFail, kindPassed, reportIt
	case statusFail:
		if len(verdicts) == 0 {
			return ProbeWarn, kindUnread, reportIt
		}
		for _, v := range verdicts {
			if v != verdictAllowed && v != verdictDenied {
				return ProbeWarn, kindUnread, reportIt
			}
		}
		return ProbeOK, "the destination was read as " + verdicts[0], ""
	default:
		return ProbeWarn, kindUnread, reportIt
	}
}

func probePolicyRejection(ctx context.Context, c *api.Client) PolicyProbe {
	pv, err := postPolicy(ctx, c, []byte(rejectionDocument))
	if err != nil {
		return probeErr(probeRejection, err)
	}
	switch pv.Status {
	case api.PolicyRejected:
		msg := strings.ToLower(pv.Message)
		if strings.Contains(msg, "unknown field") && strings.Contains(pv.Message, "nodeAttr") {
			return PolicyProbe{Name: probeRejection, Status: ProbeOK, Called: true, Detail: "a document with an unknown field is read as rejected"}
		}
		return PolicyProbe{Name: probeRejection, Status: ProbeWarn, Called: true,
			Detail: "the answer was a bare message that did not name the unknown field, so a rejection was not shown",
			Fix:    reportIt}
	case api.PolicyPass:
		// The server accepted the field. That is not a misread of a rejection, and it
		// is not proof that a rejection is read as one.
		return PolicyProbe{Name: probeRejection, Status: ProbeWarn, Called: true,
			Detail: "the server accepted a document with an unknown field, so this probe no longer proves that a rejection is read as one",
			Fix:    reportIt}
	default:
		return PolicyProbe{Name: probeRejection, Status: ProbeWarn, Called: true,
			Detail: "the answer was not a rejection, so how a rejection is read was not established",
			Fix:    reportIt}
	}
}

func probeDetailsKeys(ctx context.Context, c *api.Client) ([]byte, PolicyProbe) {
	d, err := c.GetPolicyDetails(ctx)
	if err != nil {
		e := tkerr.From(err)
		if strings.Contains(e.Message, "unrecognised") {
			return nil, PolicyProbe{Name: probeDetails, Status: ProbeWarn, Called: true, Code: e.Code,
				Detail: "the details reader refused the answer: acl_get, acl_validate and acl_diff fail until tailkeeper is updated",
				Fix:    reportIt}
		}
		return nil, probeErr(probeDetails, err)
	}
	return d.Text, PolicyProbe{Name: probeDetails, Status: ProbeOK, Called: true, Detail: "the details reader accepted the answer"}
}

func probeInvariantsCanary(ctx context.Context, c *api.Client, text []byte, detailsOK bool) PolicyProbe {
	if !detailsOK {
		return PolicyProbe{Name: probeCanary, Status: ProbeWarn,
			Detail: "the live policy could not be read, so the canary was not sent",
			Fix:    reportIt}
	}
	built, err := buildInvariantsText(ctx, text, &invariantSet{}, randomHex8)
	if err != nil {
		// Nothing was sent: the canary could not be built.
		row := probeErr(probeCanary, err)
		row.Called, row.Code = false, ""
		return row
	}
	pv, err := postPolicy(ctx, c, built.Text)
	if err != nil {
		return probeErr(probeCanary, err)
	}
	if pv.Status == api.PolicyPass {
		return PolicyProbe{Name: probeCanary, Status: ProbeFail, Called: true,
			Detail: "Tailscale did not fail the canary, so there is no sign that tests ran: this is not a pass",
			Fix:    reportIt}
	}
	rest, ok := takeCanary(pv, built.Canary, accessStateOf(ctx, built.Text))
	if !ok || rest.Status != api.PolicyPass {
		return PolicyProbe{Name: probeCanary, Status: ProbeWarn, Called: true,
			Detail: "the canary did not come back once, in the grammar, so how a failure is read was not established",
			Fix:    reportIt}
	}
	return PolicyProbe{Name: probeCanary, Status: ProbeOK, Called: true, Detail: "the canary failed once, in the grammar"}
}

func probeSSHTests(ctx context.Context, c *api.Client) PolicyProbe {
	pv, err := postPolicy(ctx, c, sshProbeDocument)
	if err != nil {
		return probeErr(probeSSH, err)
	}
	if pv.Status == api.PolicyPass {
		return PolicyProbe{Name: probeSSH, Status: ProbeFail, Called: true,
			Detail: "sshTests were not evaluated: a passing answer is not evidence they ran",
			Fix:    reportIt}
	}
	if sshProbeOnce(pv) {
		return PolicyProbe{Name: probeSSH, Status: ProbeOK, Called: true, Detail: "a failing sshTests entry came back once, in the SSH form"}
	}
	return PolicyProbe{Name: probeSSH, Status: ProbeWarn, Called: true,
		Detail: "the SSH failure did not come back once in the SSH form, so sshTests were not shown to run",
		Fix:    reportIt}
}

// sshProbeOnce is the known positive: exactly one error, and it is an SSH assertion.
func sshProbeOnce(pv api.PolicyValidation) bool {
	if pv.Status != api.PolicyFail || len(pv.Results) != 1 || len(pv.Results[0].Errors) != 1 {
		return false
	}
	f := ParseFailureLine(pv.Results[0].Errors[0])
	return f.Kind == AssertionFailed && f.SSH
}

func postPolicy(ctx context.Context, c *api.Client, body []byte) (api.PolicyValidation, error) {
	call, err := c.BeginValidate(ctx, 1)
	if err != nil {
		return api.PolicyValidation{}, err
	}
	defer call.End()
	return call.Send(body)
}

func probeErr(name string, err error) PolicyProbe {
	e := tkerr.From(err)
	if e == nil {
		e = tkerr.New(tkerr.Internal, "unexpected internal error", "")
	}
	msg := sanitize.String(sanitize.MaskText(e.Message), sanitize.DefaultMax)
	hint := sanitize.String(sanitize.MaskText(e.Hint), sanitize.DefaultMax)
	row := PolicyProbe{Name: name, Status: ProbeWarn, Detail: string(e.Code) + ": " + msg, Fix: hint, Called: true, Code: e.Code}
	if e.Code == tkerr.ValidateRateLimited {
		// tailkeeper's own limit refused the send before any request: it is not a call.
		row.Called, row.Code = false, ""
	}
	return row
}
