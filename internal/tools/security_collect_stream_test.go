package tools_test

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/tkerr"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// heapPeak samples the heap while a function runs and reports the most it held in use (a
// floor on the true peak) and the bytes allocated in all.
func heapPeak(fn func()) (peak, allocated uint64) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var mu sync.Mutex
	stop, done := make(chan struct{}), make(chan struct{})
	peak = before.HeapInuse
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
			runtime.ReadMemStats(&m)
			mu.Lock()
			peak = max(peak, m.HeapInuse)
			mu.Unlock()
		}
	}()
	fn()
	close(stop)
	<-done
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	mu.Lock()
	defer mu.Unlock()
	return max(peak, after.HeapInuse), after.TotalAlloc - before.TotalAlloc
}

// A device list is read as a stream: the memory a collection spends on it follows the body, not
// a hundred times the body. A body of 8 MiB (the most an MCP call reads) of empty entries took
// 864 MiB of heap in use, and 1,668 MiB of allocation, when the whole array was decoded into
// structs before any bound applied; read as a stream it takes about 35 MiB in use (the
// decoder's copy of the body and the garbage waiting for a collection), and 24 MiB allocated
// (260 MiB under the race detector, which makes the decoder allocate for each row). The bounds
// sit between: 20 times the body in use, which the old cost passes by 5 times, and 100 times
// the body allocated. The heap is sampled, so its peak can only be read too low, never too
// high: a failure of the first bound is real, and the allocation, which cannot be missed,
// catches what the sampler does not.
func TestAnEightMiBDeviceListOfEmptyEntriesIsReadInBoundedMemory(t *testing.T) {
	const size = 8 << 20
	entries := (size - len(`{"devices":[]}`) + 1) / 3
	body := `{"devices":[` + strings.Repeat("{},", entries-1) + `{}]}`
	if len(body) < size-3 || len(body) > size {
		t.Fatalf("the body is %d bytes, want 8 MiB", len(body))
	}
	r := newRig(t)
	r.f.JSON("GET", tailnetPath+"/devices", 200, body)
	var c tools.SecurityCollection
	peak, allocated := heapPeak(func() { c = r.collect(security.ScopeFleet) })
	t.Logf("%d entries in %d bytes: peak heap in use %d MiB, %d MiB allocated in all", entries, len(body), peak>>20, allocated>>20)
	if peak > 20*size || allocated > 100*size {
		t.Errorf("a %d MiB body took %d MiB of heap in use and %d MiB of allocation: the list is not read as a stream", size>>20, peak>>20, allocated>>20)
	}
	// The cap stays counted and reported: no entry gave a fact, every one is not observed, and
	// the record's count stops at what an event takes.
	ev := r.apiOutcome()
	if ev.Outcome != security.OutcomeTruncated || ev.Observed != 0 || ev.Dropped != security.SaturateCount(entries) {
		t.Errorf("outcome %+v, want truncated with %d dropped", ev, security.SaturateCount(entries))
	}
	requireGap(t, c, fmt.Sprintf("%d of %d items not observed", entries, entries))
}

// Rows are read whole while the snapshot has room for their facts, and as a node ID alone after
// that. Either way every row is counted, kept devices come out in node ID order whatever the
// list's order, and what is not kept is dropped. A row with fewer facts that comes after one
// that did not fit still fits.
func TestADeviceListIsReadWholeWhileThereIsRoomAndCountedAfterward(t *testing.T) {
	full := func(id string) string {
		return `{"nodeId":"` + id + `","clientVersion":"1.104.5","os":"linux","connectedToControl":true,"sshEnabled":true}`
	}
	list := `{"devices":[` + strings.Join([]string{
		full("nC"), full("nA"), `{"nodeId":"nBARE"}`, full("nB"), `{"nodeId":"nONLYCONN","connectedToControl":true}`, `{}`, `{"nodeId":"\u0007"}`,
	}, ",") + `]}`
	// Room for 6 facts: nC (4), then nA does not fit (needs 4, 2 left), nBARE (1 placeholder)
	// fits, nB does not, nONLYCONN (1) fits, and nothing more.
	got, err := tools.ReadSecurityDeviceList([]byte(list), 6)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"nBARE", "nC", "nONLYCONN"}; !slices.Equal(got.Kept(), want) {
		t.Errorf("kept %v, want %v", got.Kept(), want)
	}
	if got.Rows() != 7 || got.Dropped() != 4 || len(got.Kept())+got.Dropped() != got.Rows() {
		t.Errorf("rows %d, dropped %d, kept %d", got.Rows(), got.Dropped(), len(got.Kept()))
	}
	// The rows that were only counted still tell that their node is in the list.
	for _, id := range []string{"nA", "nB", "nC", "nBARE", "nONLYCONN"} {
		if !got.Has(id) {
			t.Errorf("the list gave %s and the read does not know it", id)
		}
	}
	if got.Has("nZ") || got.Has("") {
		t.Error("the read knows a node the list did not give")
	}
	// Order of the list does not change what is kept.
	rev := `{"devices":[` + strings.Join([]string{full("nC"), `{"nodeId":"nBARE"}`, `{"nodeId":"nONLYCONN","connectedToControl":true}`}, ",") + `]}`
	again, err := tools.ReadSecurityDeviceList([]byte(rev), 100)
	if err != nil || !slices.IsSorted(again.Kept()) {
		t.Errorf("kept %v (%v)", again.Kept(), err)
	}
}

// A node ID the list gives twice is not believed on any row, wherever its rows are: the second
// may come after the room has run out, or the first may be the one that did not fit.
func TestARepeatedNodeIDIsFoundWhereverItsRowsAre(t *testing.T) {
	full := func(id string) string {
		return `{"nodeId":"` + id + `","clientVersion":"1.104.5","os":"linux","connectedToControl":true,"sshEnabled":true}`
	}
	bare := func(id string) string { return `{"nodeId":"` + id + `"}` }
	for name, tc := range map[string]struct {
		rows []string
		room int
		kept []string
	}{
		"both kept":                         {[]string{full("nA"), bare("nB"), full("nA")}, 100, []string{"nB"}},
		"the second is past the room":       {[]string{full("nA"), bare("nB"), full("nA")}, 5, []string{"nB"}},
		"the first did not fit":             {[]string{full("nA"), bare("nB"), bare("nA")}, 3, []string{"nB"}},
		"three rows":                        {[]string{bare("nA"), bare("nA"), bare("nA"), bare("nB")}, 100, []string{"nB"}},
		"unusable rows between":             {[]string{bare("nA"), `{}`, bare("nA")}, 100, nil},
		"the repeat is read as an ID alone": {[]string{full("nA"), full("nB"), full("nC"), `{"nodeId":"nA"}`}, 12, []string{"nB", "nC"}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := tools.ReadSecurityDeviceList([]byte(`{"devices":[`+strings.Join(tc.rows, ",")+`]}`), tc.room)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got.Kept(), tc.kept) || got.Rows() != len(tc.rows) || len(got.Kept())+got.Dropped() != got.Rows() {
				t.Errorf("kept %v, dropped %d of %d rows", got.Kept(), got.Dropped(), got.Rows())
			}
			if !got.Has("nA") {
				t.Error("a repeated node is still in the list")
			}
		})
	}
}

// A list that is cut short, or is not well formed, is an error and never a list that ended:
// the reader does not take the end of its input for the end of the array.
func TestAStreamedDeviceListCutShortIsNeverTakenForWhole(t *testing.T) {
	row := `{"nodeId":"nA1CNTRL","clientVersion":"1.104.5"}`
	for name, body := range map[string]string{
		"empty":                       ``,
		"cut after the opening brace": `{`,
		"cut in the key":              `{"dev`,
		"cut after the key":           `{"devices"`,
		"cut after the colon":         `{"devices":`,
		"cut after the bracket":       `{"devices":[`,
		"cut after a row":             `{"devices":[` + row,
		"cut after a comma":           `{"devices":[` + row + `,`,
		"cut in a row":                `{"devices":[` + row + `,{"nodeId":"nB1`,
		"array not closed":            `{"devices":[` + row + `}`,
		"object not closed":           `{"devices":[` + row + `]`,
		"trailing comma":              `{"devices":[` + row + `,]}`,
		"two arrays":                  `{"devices":[` + row + `],"devices":[]}`,
		"data after the object":       `{"devices":[` + row + `]} {}`,
		"garbage after the object":    `{"devices":[` + row + `]}x`,
		"not an object":               `[` + row + `]`,
		"devices is an object":        `{"devices":{"a":1}}`,
		"devices is a string":         `{"devices":"nA1CNTRL"}`,
		"a row of the wrong type":     `{"devices":[` + row + `,5]}`,
		"a node ID of the wrong type": `{"devices":[{"nodeId":5}]}`,
		"an unknown value cut short":  `{"extra":{"a":[1,2,{"b":null}`,
		"no devices":                  `{}`,
		"null devices":                `{"devices":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			// With room, and with none: the tail is read in the other mode.
			for _, room := range []int{100, 0} {
				if got, err := tools.ReadSecurityDeviceList([]byte(body), room); err == nil {
					t.Errorf("room %d: read as a list that ended: kept %v, %d rows", room, got.Kept(), got.Rows())
				}
			}
		})
	}
	// The control: the same shapes, whole, are read, with keys the reader does not know skipped
	// wherever they are.
	for name, body := range map[string]string{
		"plain":       `{"devices":[` + row + `]}`,
		"empty array": `{"devices":[]}`,
		"keys before": `{"extra":{"a":[1,2,{"b":null}],"c":"]}"},"devices":[` + row + `]}`,
		"keys after":  `{"devices":[` + row + `],"extra":[[],{}],"more":1.5e3}`,
		"white space": " {\n \"devices\" : [ " + row + " ,\n" + row[:len(row)-1] + ",\"extra\":[1]} ] }\n",
	} {
		if _, err := tools.ReadSecurityDeviceList([]byte(body), 100); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A row's node ID is remembered, for the questions of a repeat and of membership, up to a bound.
// Past it a new ID is not remembered and its row is not kept, so that nothing is kept that a
// later row might repeat unseen, and the node is not shown to be in the list: the answer is
// never "yes" for a node the list did not give.
func TestTheNodeIDsARemembersAreBounded(t *testing.T) {
	limit := tools.SecurityMaxListedIDs()
	var b strings.Builder
	b.WriteString(`{"devices":[`)
	rows := limit + 5
	for i := 0; i < rows; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"nodeId":"n%d"}`, i)
	}
	b.WriteString(`]}`)
	got, err := tools.ReadSecurityDeviceList([]byte(b.String()), 100)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IDsFull() || got.Rows() != rows || len(got.Kept())+got.Dropped() != rows {
		t.Errorf("full %v, rows %d, kept %d, dropped %d", got.IDsFull(), got.Rows(), len(got.Kept()), got.Dropped())
	}
	if !got.Has("n0") || got.Has(fmt.Sprintf("n%d", rows-1)) {
		t.Error("the first ID should be remembered and the last, past the bound, should not")
	}
}

// A truncated body from the API is a gap in the coverage with no facts, as a body that is not a
// list is.
func TestATruncatedDeviceListIsAGapWithNoFacts(t *testing.T) {
	r := newRig(t)
	r.f.JSON("GET", tailnetPath+"/devices", 200, `{"devices":[{"nodeId":"nA1CNTRL","clientVersion":"1.104.5"},{"nodeId":"nB1`)
	c := r.collect(security.ScopeFleet)
	if ev := r.apiOutcome(); ev.Outcome != security.OutcomeError || ev.Code != string(tkerr.APIError) || ev.Observed != 0 {
		t.Errorf("outcome %+v", ev)
	}
	requireGap(t, c, string(tkerr.APIError))
	if len(assets(c.Snapshot)) != 0 {
		t.Errorf("facts from a list that was cut short: %v", assets(c.Snapshot))
	}
}

// Past the bound of the snapshot the devices kept are the first the API listed, and they are
// put in node ID order; the rest are counted. A list in any order has the same size of cut.
func TestAnOverlongListIsCutInTheAPIsOrderAndKeptInNodeIDOrder(t *testing.T) {
	r := newRig(t)
	devs := make([]map[string]any, 10001)
	for i := range devs {
		devs[i] = dev(fmt.Sprintf("nT%06dCNTRL", 10000-i), map[string]any{"sshEnabled": true})
	}
	r.devices(devs...)
	c := r.collect(security.ScopeFleet)
	ev := r.apiOutcome()
	got := assets(c.Snapshot)
	if ev.Outcome != security.OutcomeTruncated || ev.Observed+ev.Dropped != 10001 || ev.Observed != len(got) || ev.Observed*4 > security.MaxObservations-8 {
		t.Fatalf("outcome %+v with %d devices", ev, len(got))
	}
	if !slices.IsSorted(got) || got[len(got)-1] != "nT010000CNTRL" {
		t.Errorf("the devices kept are not the first listed, in node ID order: %s .. %s", got[0], got[len(got)-1])
	}
}

// This node is in the list although the room for devices ran out before its row: its facts
// join all the same, since the list gave its ID.
func TestANodeListedBeyondTheRoomStillJoinsItsLocalFacts(t *testing.T) {
	r := newCLIRig(t)
	serveLocal(r, "true")
	devs := make([]map[string]any, 0, 10002)
	for i := 0; i < 10001; i++ {
		devs = append(devs, dev(fmt.Sprintf("nT%06dCNTRL", i), map[string]any{"sshEnabled": true}))
	}
	devs = append(devs, dev(selfID, nil))
	r.devices(devs...)
	c, err := tools.CollectSecurity(context.Background(), r.env, security.ScopeFleet)
	if err != nil {
		t.Fatal(err)
	}
	if ev := r.apiOutcome(); ev.Outcome != security.OutcomeTruncated {
		t.Fatalf("the premise: the list is cut: %+v", ev)
	}
	if len(feature2(c.Snapshot, selfID)) != 1 || len(versionsOf(c.Snapshot, selfID)) != 2 {
		t.Errorf("this node's facts: %d feature, %d versions", len(feature2(c.Snapshot, selfID)), len(versionsOf(c.Snapshot, selfID)))
	}
	for _, v := range versionsOf(c.Snapshot, selfID) {
		if v.Evidence.Origin != security.OriginLocal {
			t.Errorf("an API fact for a row that was past the room: %+v", v)
		}
	}
	if ev := r.event(security.SourceLocalStatus, security.PhaseOutcome).ev; ev.Outcome != security.OutcomeOK {
		t.Errorf("status: %+v", ev)
	}
}

// feature2 lists the tailscale_ssh facts of a device.
func feature2(s security.Snapshot, asset string) []security.FeatureFact {
	var out []security.FeatureFact
	for _, f := range s.Features {
		if f.Evidence.Asset == asset && f.Name == security.FeatureTailscaleSSH {
			out = append(out, f)
		}
	}
	return out
}
