package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// benchEnv is apiEnv for benchmarks, with a privacy key: the default masking
// path plus pseudonyms, which is what a configured install runs.
func benchEnv(b *testing.B) (*apitest.Fake, *registry.Registry, *registry.Env) {
	b.Helper()
	f := apitest.New(b)
	reg := registry.New()
	tools.Register(reg)
	k, err := privacy.Parse(strings.Repeat("5a", 32))
	if err != nil {
		b.Fatal(err)
	}
	return f, reg, &registry.Env{API: f.Client(b), Privacy: k, Now: func() time.Time { return now }}
}

func benchCall(b *testing.B, reg *registry.Registry, env *registry.Env, name, args string) {
	b.Helper()
	tool, ok := reg.Get(name)
	if !ok {
		b.Fatalf("tool %s is not registered", name)
	}
	for b.Loop() {
		if _, err := tool.Call(context.Background(), env, json.RawMessage(args)); err != nil {
			b.Fatalf("%s: %v", name, err)
		}
	}
}

func BenchmarkDevicesList1000(b *testing.B) {
	f, reg, env := benchEnv(b)
	var d []string
	for i := range 1000 {
		d = append(d, fmt.Sprintf(`{"addresses":["100.64.%d.%d"],"id":"%d","nodeId":"n%04dCNTRL","user":"user%d@example.com",`+
			`"name":"host-%d.example.ts.net","hostname":"host-%d","os":"linux","lastSeen":"2026-10-10T11:59:00Z","authorized":true,"tags":["tag:web"]}`,
			i/256, i%256, i, i, i, i, i))
	}
	f.JSON("GET", tailnetPath+"/devices", 200, `{"devices":[`+strings.Join(d, ",")+`]}`)
	benchCall(b, reg, env, "devices_list", `{}`)
}

func BenchmarkAuditLog1000(b *testing.B) {
	f, reg, env := benchEnv(b)
	var e []string
	for i := range 1000 {
		e = append(e, fmt.Sprintf(`{"eventTime":"2026-10-10T%02d:%02d:%02dZ","origin":"ADMIN_CONSOLE","action":"UPDATE",`+
			`"actor":{"id":"u%d","loginName":"user%d@example.com","displayName":"User %d"},"target":{"id":"t%d","name":"key for user%d@example.com"},`+
			`"old":{"acls":[{"action":"accept"}]},"new":{"acls":[{"action":"accept","src":["user%d@example.com"]}]}}`,
			i/3600, i/60%60, i%60, i, i, i, i, i, i))
	}
	f.JSON("GET", tailnetPath+"/logging/configuration", 200, `{"logs":[`+strings.Join(e, ",")+`]}`)
	benchCall(b, reg, env, "audit_log", `{"limit":1000,"includeValues":true}`)
}
