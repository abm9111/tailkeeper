package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/registry"
)

// Webhook is a webhook endpoint. The secret is never returned, and the endpoint
// URL is reduced to scheme and host plus a hash of the path, because chat-provider
// webhook URLs carry a bearer token in the path.
type Webhook struct {
	EndpointID       string   `json:"endpointId" tk:"col"`
	EndpointHost     string   `json:"endpointHost" tk:"untrusted,col,plain"`
	EndpointPathHash string   `json:"endpointPathSha256,omitempty"`
	ProviderType     string   `json:"providerType,omitempty" tk:"col"`
	CreatorLoginName string   `json:"creatorLoginName,omitempty" tk:"untrusted,personal"`
	Created          string   `json:"created,omitempty"`
	LastModified     string   `json:"lastModified,omitempty"`
	Subscriptions    []string `json:"subscriptions"`
}

type apiWebhook struct {
	EndpointID       string   `json:"endpointId"`
	EndpointURL      string   `json:"endpointUrl"`
	ProviderType     string   `json:"providerType"`
	CreatorLoginName string   `json:"creatorLoginName"`
	Created          string   `json:"created"`
	LastModified     string   `json:"lastModified"`
	Subscriptions    []string `json:"subscriptions"`
}

func toWebhook(a apiWebhook) Webhook {
	w := Webhook{EndpointID: a.EndpointID, ProviderType: a.ProviderType, CreatorLoginName: a.CreatorLoginName,
		Created: a.Created, LastModified: a.LastModified, Subscriptions: nonNil(a.Subscriptions)}
	w.EndpointHost, w.EndpointPathHash = shownEndpoint(a.EndpointURL)
	return w
}

// shownEndpoint is endpoint for a result: a URL that is set and cannot be read (no
// scheme, no host) shows as one that could not be read, not as an empty host, which
// would read as a destination that is not set. Nothing of the URL is shown.
func shownEndpoint(raw string) (host, pathHash string) {
	host, pathHash = endpoint(raw)
	if host == "" && raw != "" {
		return unreadableURL, ""
	}
	return host, pathHash
}

// endpoint reduces a URL to scheme and host, plus a SHA-256 of its path and query
// when it has either: user info is dropped, and paths and queries can carry tokens
// (chat-provider webhooks, HTTP log collectors).
func endpoint(raw string) (host, pathHash string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", ""
	}
	if p := strings.TrimPrefix(u.EscapedPath(), "/"); p != "" || u.RawQuery != "" {
		sum := sha256.Sum256([]byte(u.EscapedPath() + "?" + u.RawQuery))
		pathHash = hex.EncodeToString(sum[:])
	}
	return u.Scheme + "://" + u.Host, pathHash
}

// WebhooksOutput lists webhooks.
type WebhooksOutput struct {
	Webhooks []Webhook `json:"webhooks" tk:"rows"`
	Count    int       `json:"count"`
}

// WebhookRef names one webhook.
type WebhookRef struct {
	ID string `json:"id" jsonschema:"webhook endpoint ID"`
}

// Check refuses an ID that cannot be one, before anything is sent.
func (in WebhookRef) Check() error { return requireID("id", in.ID) }

// PostureIntegration is an EDR/MDM integration without its client secret.
type PostureIntegration struct {
	ID            string         `json:"id" tk:"col"`
	Provider      string         `json:"provider" tk:"col"`
	CloudID       string         `json:"cloudId,omitempty" tk:"untrusted"`
	ClientID      string         `json:"clientId,omitempty" tk:"untrusted"`
	TenantID      string         `json:"tenantId,omitempty" tk:"untrusted"`
	ConfigUpdated string         `json:"configUpdated,omitempty"`
	Status        *PostureStatus `json:"status,omitempty"`
}

// PostureStatus is the integration's sync health.
type PostureStatus struct {
	LastSync             string `json:"lastSync,omitempty"`
	Error                string `json:"error,omitempty" tk:"untrusted"`
	ProviderHostCount    int    `json:"providerHostCount"`
	MatchedCount         int    `json:"matchedCount"`
	PossibleMatchedCount int    `json:"possibleMatchedCount"`
}

// PostureIntegrationsOutput lists integrations.
type PostureIntegrationsOutput struct {
	Integrations []PostureIntegration `json:"integrations" tk:"rows"`
	Count        int                  `json:"count"`
}

// IDRef names an object by ID.
type IDRef struct {
	ID string `json:"id" jsonschema:"object ID"`
}

// Check refuses an ID that cannot be one, before anything is sent.
func (in IDRef) Check() error { return requireID("id", in.ID) }

// Service is a Tailscale Service.
type Service struct {
	Name        string   `json:"name" tk:"untrusted,col"`
	DisplayName string   `json:"displayName,omitempty" tk:"untrusted"`
	Addrs       []string `json:"addrs,omitempty" tk:"col"`
	Comment     string   `json:"comment,omitempty" tk:"untrusted"`
	Ports       []string `json:"ports,omitempty" tk:"untrusted,col"`
	Tags        []string `json:"tags,omitempty" tk:"untrusted"`
}

// ServicesOutput lists services.
type ServicesOutput struct {
	Services []Service `json:"services" tk:"rows"`
	Count    int       `json:"count"`
}

// ServiceRef names one service.
type ServiceRef struct {
	Name string `json:"name" jsonschema:"service name, for example svc:web"`
}

// Check refuses a name that cannot be one, before anything is sent.
func (in ServiceRef) Check() error { return requireID("name", in.Name) }

// OAuthApp is an OAuth app without its client secret.
type OAuthApp struct {
	ID                    string   `json:"id" tk:"col"`
	Name                  string   `json:"name" tk:"untrusted,col"`
	Description           string   `json:"description,omitempty" tk:"untrusted"`
	RedirectURIs          []string `json:"redirectURIs,omitempty" tk:"untrusted,plain"`
	Scopes                []string `json:"scopes,omitempty" tk:"col"`
	AllowedNodeAttributes []string `json:"allowedNodeAttributes,omitempty" tk:"untrusted"`
	Created               string   `json:"created,omitempty"`
	Updated               string   `json:"updated,omitempty"`
}

// OAuthAppsOutput lists OAuth apps.
type OAuthAppsOutput struct {
	Apps  []OAuthApp `json:"apps" tk:"rows"`
	Count int        `json:"count"`
}

func integrationTools() []registry.Tool {
	posture := withOps(readMeta("posture_integrations_list", "posture", "list", "List device-posture integrations and their sync health.", "feature_settings:read"),
		"GET /tailnet/{tailnet}/posture/integrations")
	posture.PlanGate = "Standard, Premium, Enterprise"
	postureGet := withOps(readMeta("posture_integration_get", "posture", "get", "Get one device-posture integration.", "feature_settings:read"),
		"GET /posture/integrations/{id}")
	postureGet.PlanGate = posture.PlanGate
	apps := withOps(readMeta("oauth_apps_list", "oauth-apps", "list", "List OAuth apps (alpha; secrets never shown).", "oauth_apps:read"),
		"GET /tailnet/{tailnet}/oauth-apps")
	apps.Stage = registry.StageAlpha
	app := withOps(readMeta("oauth_app_get", "oauth-apps", "get", "Get one OAuth app (alpha; secret never shown).", "oauth_apps:read"),
		"GET /tailnet/{tailnet}/oauth-apps/{appId}")
	app.Stage = registry.StageAlpha
	return []registry.Tool{
		registry.Define(withOps(readMeta("webhooks_list", "webhooks", "list", "List webhook endpoints (secrets never shown; URLs reduced to host and path hash).", "webhooks:read"),
			"GET /tailnet/{tailnet}/webhooks"), webhooksList),
		registry.Define(withOps(readMeta("webhook_get", "webhooks", "get", "Get one webhook endpoint.", "webhooks:read"),
			"GET /webhooks/{endpointId}"), webhookGet),
		registry.Define(posture, postureList),
		registry.Define(postureGet, postureGetOne),
		registry.Define(withOps(readMeta("services_list", "services", "list", "List Tailscale Services.", "services:read"),
			"GET /tailnet/{tailnet}/services"), servicesList),
		registry.Define(withOps(readMeta("service_get", "services", "get", "Get one Tailscale Service.", "services:read"),
			"GET /tailnet/{tailnet}/services/{serviceName}"), serviceGet),
		registry.Define(apps, oauthAppsList),
		registry.Define(app, oauthAppGet),
	}
}

func webhooksList(ctx context.Context, env *registry.Env, _ NoInput) (WebhooksOutput, error) {
	path, err := tailnetPath(env, "/webhooks")
	if err != nil {
		return WebhooksOutput{}, err
	}
	var r struct {
		Webhooks []apiWebhook `json:"webhooks"`
	}
	if err := get(ctx, env, path, nil, &r); err != nil {
		return WebhooksOutput{}, err
	}
	out := WebhooksOutput{Webhooks: []Webhook{}}
	for _, w := range r.Webhooks {
		out.Webhooks = append(out.Webhooks, toWebhook(w))
	}
	out.Count = len(out.Webhooks)
	return out, nil
}

func webhookGet(ctx context.Context, env *registry.Env, in WebhookRef) (Webhook, error) {
	var w apiWebhook
	if err := get(ctx, env, api.Path("webhooks/%s", in.ID), nil, &w); err != nil {
		return Webhook{}, err
	}
	return toWebhook(w), nil
}

func postureList(ctx context.Context, env *registry.Env, _ NoInput) (PostureIntegrationsOutput, error) {
	path, err := tailnetPath(env, "/posture/integrations")
	if err != nil {
		return PostureIntegrationsOutput{}, err
	}
	var r struct {
		Integrations []PostureIntegration `json:"integrations"`
	}
	if err := get(ctx, env, path, nil, &r); err != nil {
		return PostureIntegrationsOutput{}, err
	}
	return PostureIntegrationsOutput{Integrations: nonNil(r.Integrations), Count: len(r.Integrations)}, nil
}

func postureGetOne(ctx context.Context, env *registry.Env, in IDRef) (PostureIntegration, error) {
	var p PostureIntegration
	if err := get(ctx, env, api.Path("posture/integrations/%s", in.ID), nil, &p); err != nil {
		return PostureIntegration{}, err
	}
	return p, nil
}

func servicesList(ctx context.Context, env *registry.Env, _ NoInput) (ServicesOutput, error) {
	path, err := tailnetPath(env, "/services")
	if err != nil {
		return ServicesOutput{}, err
	}
	var r struct {
		VIPServices []Service `json:"vipServices"`
	}
	if err := get(ctx, env, path, nil, &r); err != nil {
		return ServicesOutput{}, err
	}
	return ServicesOutput{Services: nonNil(r.VIPServices), Count: len(r.VIPServices)}, nil
}

func serviceGet(ctx context.Context, env *registry.Env, in ServiceRef) (Service, error) {
	path, err := tailnetPath(env, "/services/"+url.PathEscape(in.Name))
	if err != nil {
		return Service{}, err
	}
	var s Service
	if err := get(ctx, env, path, nil, &s); err != nil {
		return Service{}, err
	}
	return s, nil
}

func oauthAppsList(ctx context.Context, env *registry.Env, _ NoInput) (OAuthAppsOutput, error) {
	path, err := tailnetPath(env, "/oauth-apps")
	if err != nil {
		return OAuthAppsOutput{}, err
	}
	var r struct {
		OAuthApps []OAuthApp `json:"oauthApps"`
	}
	if err := get(ctx, env, path, nil, &r); err != nil {
		return OAuthAppsOutput{}, err
	}
	return OAuthAppsOutput{Apps: nonNil(r.OAuthApps), Count: len(r.OAuthApps)}, nil
}

func oauthAppGet(ctx context.Context, env *registry.Env, in IDRef) (OAuthApp, error) {
	path, err := tailnetPath(env, "/oauth-apps/"+url.PathEscape(in.ID))
	if err != nil {
		return OAuthApp{}, err
	}
	var a OAuthApp
	if err := get(ctx, env, path, nil, &a); err != nil {
		return OAuthApp{}, err
	}
	return a, nil
}
