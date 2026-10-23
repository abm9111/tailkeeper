package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/abm9111/tailkeeper/internal/api"
	"github.com/abm9111/tailkeeper/internal/api/apitest"
	"github.com/abm9111/tailkeeper/internal/app"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// A result that does not fit in one JSON-RPC frame breaks the connection of the host that asked
// for it: the SDK reads a frame of at most mcp.DefaultMaxLineLength bytes (16 MiB) and closes the
// session on a longer one. What the host receives for a tool call is the whole CallToolResult in
// one frame: the structured content (the result as JSON), the text content (the same JSON once
// more, as a JSON string, which doubles every quote and backslash again), a summary line and the
// list of untrusted fields. These tests do not compute that size, they send the result through a
// real connection whose reader has the SDK's own limit, and measure the longest frame it read.
// They hold the policy tools' largest results, whatever the policy and Tailscale's replies hold,
// under the limit with the headroom frameHeadroom; devices_list, whose rows have no such bound,
// is not covered, and the issue about it stays open.
const frameHeadroom = 2 << 20

// frameMeter wraps what a client reads and records the longest frame: the longest run of bytes
// between two line feeds.
type frameMeter struct {
	io.ReadCloser
	run     int
	longest atomic.Int64
}

func (m *frameMeter) Read(p []byte) (int, error) {
	n, err := m.ReadCloser.Read(p)
	for _, b := range p[:n] {
		if b == '\n' {
			m.run = 0
			continue
		}
		if m.run++; int64(m.run) > m.longest.Load() {
			m.longest.Store(int64(m.run))
		}
	}
	return n, err
}

// overPipes serves a over a pair of pipes, the way a host runs the server over standard
// input and output, and returns a client whose reader refuses a frame over maxLine (0 is the
// SDK's default, which is the limit a host has) with the meter on what it reads.
func overPipes(t *testing.T, a *app.App, maxLine int) (*mcp.ClientSession, *frameMeter) {
	t.Helper()
	srv, err := New(a, Options{Profile: "reads"})
	if err != nil {
		t.Fatal(err)
	}
	toClientR, toClientW := io.Pipe()
	toServerR, toServerW := io.Pipe()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, &mcp.IOTransport{Reader: toServerR, Writer: toClientW}, nil)
	if err != nil {
		t.Fatal(err)
	}
	meter := &frameMeter{ReadCloser: toClientR}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "frame-test", Version: "1"}, nil).
		Connect(ctx, &mcp.IOTransport{Reader: meter, Writer: toServerW, MaxLineLength: maxLine}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Close() })
	return cs, meter
}

// serveACL answers both reads of the policy, the details and the settings.
func serveACL(f *apitest.Fake, text string, warnings, stored []string) {
	f.Handle("GET", "/api/v2/tailnet/T1234CNTRL/acl", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") == "true" {
			apitest.DetailsOK(text, api.ETagOf([]byte(text)), warnings, stored).Write(w)
			return
		}
		apitest.PolicyText(text, api.ETagOf([]byte(text))).Write(w)
	})
	f.JSON("GET", "/api/v2/tailnet/T1234CNTRL/settings", 200, `{"aclsExternallyManagedOn":false}`)
}

// repeatedLines is a policy of lines of the same character, size bytes of it: a quote is two
// bytes as JSON and four bytes encoded again, and nothing else costs more for each byte.
func repeatedLines(char string, size int) string {
	line := strings.Repeat(char, 60) + "\n"
	return strings.Repeat(line, size/len(line))
}

// unknownKeys is a text of n sections this version does not know.
func unknownKeys(n int) string {
	var b strings.Builder
	b.WriteString("{\n")
	for i := range n {
		fmt.Fprintf(&b, "\"k%05d\": 0,\n", i)
	}
	b.WriteString("}\n")
	return b.String()
}

// frameCase is one call whose frame is measured.
type frameCase struct {
	name  string
	setup func(f *apitest.Fake)
	tool  string
	args  map[string]any
	floor int // the frame is at least this long: the call reached what it was written to reach
	cap   int // and at most this long, when the case is a small one
}

func frameCases() []frameCase {
	var cases []frameCase
	// The largest page of acl_get, 4 MiB of text, for the character that costs the most (a
	// quote doubles again in the second encoding, and so does a backslash), the one whose first
	// encoding costs the most (an angle bracket is six bytes as JSON) and one that costs nothing
	// extra, with the warnings and the stored errors at their longest in the same result (64 of
	// each, cut to 1 KiB by the tool). The body of a response is read up to 8 MiB over MCP, so
	// the policy is a little under 4 MiB.
	for _, c := range []struct {
		name, char string
		floor      int
	}{
		{"quotes", `"`, 12 << 20}, {"angle brackets", "<", 8 << 20}, {"letters", "a", 8 << 20},
	} {
		var warnings, stored []string
		for range 64 {
			warnings = append(warnings, strings.Repeat(`"`, 1500))
			stored = append(stored, strings.Repeat(`\`, 1500))
		}
		text := repeatedLines(c.char, 4<<20-8192)
		cases = append(cases, frameCase{
			name:  "acl_get, the largest page of " + c.name,
			setup: func(f *apitest.Fake) { serveACL(f, text, warnings, stored) },
			tool:  "acl_get", args: map[string]any{"maxBytes": 4194304}, floor: c.floor,
		})
	}
	// acl_validate with the largest reply the client reads (64 entries of 64 messages, each
	// quoting what it can), the live policy's own warnings and stored errors, and a proposal.
	var warnings, stored []string
	for range 64 {
		warnings = append(warnings, strings.Repeat(`"`, 1500))
		stored = append(stored, strings.Repeat(`\`, 1500))
	}
	var entries []apitest.Entry
	for i := range 64 {
		e := apitest.Entry{User: fmt.Sprintf("tag:t%02d", i)}
		for range 64 {
			e.Errors = append(e.Errors, "[acl test error]: "+strings.Repeat(`"`, 110))
		}
		entries = append(entries, e)
	}
	const live = "{\n\t\"tagOwners\": {\"tag:ci\": [\"autogroup:admin\"]},\n}\n"
	cases = append(cases, frameCase{
		name: "acl_validate, the largest reply",
		setup: func(f *apitest.Fake) {
			serveACL(f, live, warnings, stored)
			f.ServeValidate(apitest.TestsFailed(entries...))
		},
		tool: "acl_validate", args: map[string]any{"policy": live + "// proposed\n"}, floor: 400 << 10,
	})
	// A proposal of as many unknown sections as an argument can hold (1 MiB): every one is a
	// notice, and a result carries 64 problems whatever the text holds. The same two texts
	// compared by acl_diff, where a side lists 64 findings.
	many := unknownKeys(60000)
	cases = append(cases, frameCase{
		name:  "acl_validate, a proposal of 60,000 unknown sections",
		setup: func(f *apitest.Fake) { serveACL(f, live, nil, nil); f.ServeValidate(apitest.TestsPassEmptyObject()) },
		tool:  "acl_validate", args: map[string]any{"policy": many}, floor: 8 << 10, cap: 256 << 10,
	})
	// The same, with an error in the text: the result takes the early return of an invalid
	// text, which cuts the notices to the room the error leaves.
	invalid := "{\n\"groups\": {},\n\"groups\": {},\n" + strings.TrimPrefix(many, "{\n")
	cases = append(cases, frameCase{
		name:  "acl_validate, an invalid proposal of 60,000 unknown sections",
		setup: func(f *apitest.Fake) { serveACL(f, live, nil, nil) },
		tool:  "acl_validate", args: map[string]any{"policy": invalid}, floor: 8 << 10, cap: 256 << 10,
	})
	cases = append(cases, frameCase{
		name:  "acl_diff, a new side of 60,000 unknown sections",
		setup: func(f *apitest.Fake) { serveACL(f, live, nil, nil) },
		tool:  "acl_diff", args: map[string]any{"policy": many}, floor: 8 << 10, cap: 256 << 10,
	})
	// acl_test with the widest SSH call the input bounds allow: 8 tests of 32 destinations and 16
	// users, 4,096 verdicts. A reply with no canary leaves every verdict unknown with its reason,
	// which is the longest each can be; the result lists 256 of them and counts the rest.
	var wide []map[string]any
	for i := range 8 {
		var dst, users []string
		for d := range 32 {
			dst = append(dst, fmt.Sprintf("tag:t%d-d%02d", i, d))
		}
		for u := range 16 {
			users = append(users, fmt.Sprintf("user%02d", u))
		}
		wide = append(wide, map[string]any{"dst": dst, "accept": users})
	}
	cases = append(cases, frameCase{
		name:  "acl_test, the widest SSH call",
		setup: func(f *apitest.Fake) { serveACL(f, live, nil, nil); f.ServeValidate(apitest.TestsPass()) },
		tool:  "acl_test", args: map[string]any{"src": "tag:ci", "ssh": wide}, floor: 16 << 10, cap: 512 << 10,
	})
	// acl_test in tests mode with a reply of 64 entries of 64 lines of 900 characters, 4 MB under
	// the 8 MiB an MCP call reads, in the characters that cost the most as JSON text. The entries are those of other sources
	// (the policy's stored tests) in one case and of the posted source in the other, and the
	// lines are not in the verdict grammar. The result shows a bounded part of them and counts
	// the rest.
	for _, c := range []struct {
		name string
		user func(i int) string
	}{
		{"entries of other sources", func(i int) string { return fmt.Sprintf("tag:t%02d", i) }},
		{"entries of the posted source", func(int) string { return "tag:ci" }},
	} {
		var flood []apitest.Entry
		for i := range 64 {
			e := apitest.Entry{User: c.user(i)}
			for range 64 {
				e.Errors = append(e.Errors, "[acl test error]: "+strings.Repeat(`"`, 900))
			}
			flood = append(flood, e)
		}
		cases = append(cases, frameCase{
			name:  "acl_test, the largest tests-mode reply, " + c.name,
			setup: func(f *apitest.Fake) { serveACL(f, live, nil, nil); f.ServeValidate(apitest.TestsFailed(flood...)) },
			tool:  "acl_test", args: map[string]any{"src": "tag:ci", "accept": []string{"tag:web:22"}}, floor: 16 << 10, cap: 256 << 10,
		})
	}
	return cases
}

// The policy tools' largest results reach the host: each goes through a connection whose
// reader has the SDK's own limit and arrives, and the longest frame it read leaves the stated
// headroom.
func TestTheLargestACLResultsStayUnderTheFrameLimit(t *testing.T) {
	for _, c := range frameCases() {
		t.Run(c.name, func(t *testing.T) {
			f := apitest.New(t)
			c.setup(f)
			cs, meter := overPipes(t, newApp(t, f), 0)
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: c.tool, Arguments: c.args})
			if err != nil {
				t.Fatalf("%s: the connection broke: %v (longest frame read: %d bytes)", c.tool, err, meter.longest.Load())
			}
			if res.IsError {
				t.Fatalf("%s: %s", c.tool, text(res, 0))
			}
			frame := int(meter.longest.Load())
			if frame < c.floor {
				t.Errorf("the frame is %d bytes, under %d: the call no longer reaches the largest result", frame, c.floor)
			}
			if c.cap > 0 && frame > c.cap {
				t.Errorf("the frame is %d bytes, over %d: the result is no longer bounded by its caps", frame, c.cap)
			}
			if limit := mcp.DefaultMaxLineLength - frameHeadroom; frame > limit {
				t.Errorf("the frame is %d bytes: the SDK reads %d, and the test keeps %d of headroom (%d)", frame, mcp.DefaultMaxLineLength, frameHeadroom, limit)
			}
		})
	}
}

// The oracle can fail: the largest reply of acl_validate read by a client whose limit is one
// byte under the frame is refused by the SDK, so the test above measures what a host would meet.
// (A small result: that the SDK refuses a frame over its limit does not depend on the size.)
func TestTheFrameLimitOfTheTestsIsTheSDKsAndItBites(t *testing.T) {
	var c frameCase
	for _, candidate := range frameCases() {
		if candidate.name == "acl_validate, the largest reply" {
			c = candidate
		}
	}
	if c.setup == nil {
		t.Fatal("the case of the largest validate reply is gone")
	}
	f := apitest.New(t)
	c.setup(f)
	cs, meter := overPipes(t, newApp(t, f), 0)
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: c.tool, Arguments: c.args}); err != nil {
		t.Fatal(err)
	}
	frame := int(meter.longest.Load())
	f2 := apitest.New(t)
	c.setup(f2)
	cs2, _ := overPipes(t, newApp(t, f2), frame-1)
	res, err := cs2.CallTool(context.Background(), &mcp.CallToolParams{Name: c.tool, Arguments: c.args})
	switch {
	case err == nil:
		t.Errorf("a client that reads %d bytes a frame was sent a frame of %d: isError %v", frame-1, frame, res.IsError)
	case !strings.Contains(err.Error(), "maximum line length"):
		// Any other failure (a setup that broke) would end the call the same way.
		t.Errorf("the call failed, but not because the frame is over the limit: %v", err)
	}
	// And the frame itself fits a limit of exactly its length: the meter counts the bytes
	// between line feeds, as the SDK's limit does.
	f3 := apitest.New(t)
	c.setup(f3)
	cs3, _ := overPipes(t, newApp(t, f3), frame)
	if _, err := cs3.CallTool(context.Background(), &mcp.CallToolParams{Name: c.tool, Arguments: c.args}); err != nil {
		t.Errorf("a client that reads %d bytes a frame was refused a frame of %d: %v", frame, frame, err)
	}
}

// The offline check cannot be asked for over MCP (the switch exists on the command line
// only), so no frame of it is read. Its result still carries what a frame would: the
// structured content and the same JSON once more as text. The two copies of the largest
// result, an offline text of 60,000 unknown sections with and without an error, stay under
// the cap of the other paths.
func TestTheOfflineResultsOfAValidateAreBoundedLikeTheOthers(t *testing.T) {
	many := unknownKeys(60000)
	for name, text := range map[string]string{
		"a valid text":   many,
		"an invalid one": "{\n\"groups\": {},\n\"groups\": {},\n" + strings.TrimPrefix(many, "{\n"),
	} {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, nil)
			tool, ok := a.Registry.Get("acl_validate")
			if !ok {
				t.Fatal("acl_validate is not registered")
			}
			p, err := tool.Validate([]byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			in := p.Input().(*tools.ACLValidateInput)
			in.Policy, in.Offline = text, true
			out, err := p.Run(context.Background(), a.Env)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			if size := 2 * len(raw); size < 8<<10 || size > 256<<10 {
				t.Errorf("two copies of the result are %d bytes, want between %d and %d", size, 8<<10, 256<<10)
			}
		})
	}
}
