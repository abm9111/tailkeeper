package tools_test

import (
	"fmt"
	"testing"

	"github.com/abm9111/tailkeeper/internal/tools"
)

func TestDevicesListPages(t *testing.T) {
	f, reg, env := apiEnv(t)
	var b string
	b = `{"devices":[`
	for i := 1; i <= 5; i++ {
		if i > 1 {
			b += ","
		}
		b += fmt.Sprintf(`{"id":"%d","nodeId":"n%dCNTRL","name":"n-%d","hostname":"h-%d","os":"linux"}`, i, i, i, i)
	}
	b += `]}`
	f.JSON("GET", devicesPath, 200, b)
	var out tools.DevicesListOutput
	mustCall(t, reg, env, "devices_list", `{"limit":2,"offset":1}`, &out)
	if out.Count != 2 || out.Total != 5 || !out.Truncated || out.Offset != 1 || out.Limit != 2 {
		t.Fatalf("page = %+v", out)
	}
	if out.Devices[0].NodeID != "n2CNTRL" || out.Devices[1].NodeID != "n3CNTRL" {
		t.Fatalf("devices = %+v", out.Devices)
	}
}
