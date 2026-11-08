package mcpserver

import (
	"os"
	"strings"
	"testing"
)

// The description of tailkeeper_info says that MCP calls are audited, as the CLI form is not.
func TestSelfInfoCallsAreAuditedOverMCP(t *testing.T) {
	a := newApp(t, nil)
	cs := connect(t, a, Options{Profile: "reads"})
	if res := callTool(t, cs, "tailkeeper_info", map[string]any{}); res.IsError {
		t.Fatalf("tailkeeper_info: %s", text(res, 0))
	}
	data, err := os.ReadFile(a.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	if line := string(data); !strings.Contains(line, `"tool":"tailkeeper_info"`) || !strings.Contains(line, `"status":"ok"`) {
		t.Errorf("audit log = %s", line)
	}
}
