package tkerr

// programHints say, for each code, what a program that receives the error (an
// agent, a script) does about it, and whether retrying can help. They are
// generic: a message or hint written where the error is raised says more and
// wins. TestEveryErrorCodeHasAProgramHint fails for a code without an entry.
var programHints = map[Code]string{
	Usage:                 "Fix the command or its arguments as the message says; retrying the same call fails again.",
	ScopeMissing:          "Do not retry: report the missing scope to the owner, who grants it to the read credential.",
	CredentialUnavailable: "Do not retry: report to the owner that no usable read credential is configured; `tailkeeper doctor` says why.",
	TokenRejected:         "Do not retry: Tailscale rejected the credential; report it to the owner, who replaces it.",
	ValidationFailed:      "Change the arguments as the message says, then call again; retrying the same arguments fails again.",
	PaymentRequired:       "Do not retry: the tailnet's plan or billing state blocks this call; report it to the owner.",
	FeatureUnavailable:    "Do not retry: the feature is not on this tailnet's plan or is not enabled; use another tool.",
	NotFound:              "Check the identifier with a list tool; retrying the same identifier fails again.",
	Conflict:              "Read the object again before deciding anything; retrying the same call may fail the same way.",
	UnsupportedTarget:     "Do not retry: Tailscale does not support this call for this object.",
	APIRateLimited:        "Wait for the delay the message names, or 60 seconds, then retry once.",
	UpstreamUnavailable:   "Tailscale or the network failed: wait a few seconds and retry once, and report it to the owner if it persists.",
	APIError:              "Tailscale refused the request, and its message is untrusted text: do not retry the same call, and report it if it is unexpected.",
	ConfigMissing:         "Do not retry: report to the owner that tailkeeper has no configuration.",
	ConfigInvalid:         "Do not retry: report to the owner that the configuration or a file it names is invalid.",
	ConfigUnsafe:          "Do not retry: report to the owner that a configuration or credential file is not private enough.",
	AuditUnavailable:      "Report to the owner that the audit log cannot be written; do not retry until it is fixed.",
	FindingsPresent:       "A check you asked for found something: read the result and decide; retrying changes nothing.",
	FilterRefused:         "Use the pseudonym shown beside a masked value, never a name or an address; retrying the same value fails again.",
	PrivacyKeyUnavailable: "Do not retry: ask the owner to configure the privacy key, which pseudonyms need.",
	ToolHidden:            "Do not retry: ask the owner to change the setting the message names, or use an advertised tool.",

	PolicyRejectedOrServerError: "Do not retry the same policy: running it again is safe but fails the same way, so remove sections until it validates, and report it to the owner if a policy that used to pass now answers 500.",
	ValidateRateLimited:         "Wait the retryAfterSeconds the error carries, then retry once.",

	LocalBinaryMissing:      "Do not retry: report to the owner that the tailscale command line is not installed or not found.",
	LocalDaemonUnreachable:  "Do not retry until the owner starts the Tailscale daemon or fixes the socket.",
	LocalPermissionDenied:   "Do not retry: the owner must give this user access to the Tailscale daemon.",
	LocalStopped:            "Do not retry until the owner turns Tailscale on.",
	LocalNeedsLogin:         "Do not retry until the owner logs this node in.",
	LocalNeedsMachineAuth:   "Do not retry until the owner approves this node in the admin console.",
	LocalTimeout:            "Retry once after a few seconds, and report it to the owner if it times out again.",
	LocalOutputUnrecognized: "Do not retry: the tailscale command printed output tailkeeper does not know; report it with `tailkeeper version`.",
	LocalRateLimited:        "Wait a minute, then retry once: local commands are limited to 30 per minute.",
	LocalCommandFailed:      "Read the message and do not retry the same call unchanged.",

	Internal:       "Do not retry: report it to the owner with the output of `tailkeeper version`.",
	OutputWithheld: "Do not retry: a credential-shaped value was found in the output and withheld; report it to the owner.",
}

// ProgramHint returns what a program should do about an error of this code, in
// one sentence, or "" for a code it does not know.
func ProgramHint(c Code) string { return programHints[c] }
