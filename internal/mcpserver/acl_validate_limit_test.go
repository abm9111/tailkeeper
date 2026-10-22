package mcpserver

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/creds"
)

// An empty validation bucket is the error validate_rate_limited over MCP too, and the text
// a host shows the model names the seconds to wait: the message and the hint are what the
// text content carries, not the field.
func TestTheValidateBucketIsExhaustedOverMCP(t *testing.T) {
	f := apitest.New(t)
	const live = "{}\n"
	f.Handle("GET", "/api/v2/tailnet/T1234CNTRL/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(live, api.ETagOf([]byte(live)), nil, nil).Write(w)
			return
		}
		apitest.PolicyText(live, api.ETagOf([]byte(live))).Write(w)
	})
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/settings", 200, `{"aclsExternallyManagedOn":false}`)
	f.ServeValidate(apitest.TestsPassEmptyObject())
	a := newApp(t, f)
	fixed := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	c, err := api.New(context.Background(), apitest.Tailnet,
		creds.Read{Kind: creds.KindOAuth, ClientID: apitest.ClientID, ClientSecret: creds.NewSecret(apitest.ClientSecret), Provider: "env"},
		api.Options{BaseURL: f.URL(), ValidatePerMinute: 1, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	a.Env.API = c
	cs := connect(t, a, Options{Profile: "reads"})
	for i := 1; i <= 2; i++ {
		if res := callTool(t, cs, "acl_validate", map[string]any{}); res.IsError {
			t.Fatalf("call %d: %s", i, text(res, 0))
		}
	}
	res := callTool(t, cs, "acl_validate", map[string]any{})
	if !res.IsError || !strings.HasPrefix(text(res, 0), "validate_rate_limited: ") || !strings.Contains(text(res, 0), "try again in 60 s") {
		t.Errorf("third call: isError %v, text %q; want validate_rate_limited naming the seconds", res.IsError, text(res, 0))
	}
}
