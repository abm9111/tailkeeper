package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/audit"
)

// The rotation reports the whole path of the archive it made, in JSON and in text.
func TestAuditRotateNamesTheWholeArchivePath(t *testing.T) {
	if !audit.RotateSupported() {
		t.Skip("audit rotate needs the file lock, which this platform does not have yet")
	}
	h := newDNSHarness(t)
	h.run("dns", "get")
	h.out.Reset()
	if code := h.run("--json", "audit", "rotate"); code != 0 {
		t.Fatalf("audit rotate: exit %d, %s", code, h.err)
	}
	archive := onlyArchive(t, h)
	var rot struct{ Log, Archive string }
	if err := json.Unmarshal(h.out.Bytes(), &rot); err != nil || rot.Log != h.app.AuditPath || rot.Archive != archive {
		t.Errorf("audit rotate JSON = %q (%v), want log %q and archive %q", h.out, err, h.app.AuditPath, archive)
	}
	h.run("dns", "get")
	h.out.Reset()
	if code := h.run("audit", "rotate"); code != 0 || !strings.Contains(h.out.String(), h.app.AuditPath+": started a new log; the old one is kept as ") {
		t.Errorf("text: exit %d, %q", code, h.out)
	}
}

// A verify that cannot print every line of its answer is exit 1, whichever line
// the write fails on.
func TestAuditVerifyReturnsAWriteErrorOnAnyLine(t *testing.T) {
	if !audit.RotateSupported() {
		t.Skip("audit rotate needs the file lock, which this platform does not have yet")
	}
	h := newDNSHarness(t)
	h.run("dns", "get")
	if code := h.run("audit", "rotate"); code != 0 {
		t.Fatalf("rotate: exit %d, %s", code, h.err)
	}
	h.run("dns", "get")
	for at := 1; at <= 2; at++ {
		w := &failingWriter{at: at}
		h.r.Stdout = w
		h.err.Reset()
		if code := h.run("audit", "verify"); code != 1 || !w.tripped {
			t.Errorf("write %d failing: exit %d, tripped %v, stderr %q", at, code, w.tripped, h.err)
		}
	}
}
