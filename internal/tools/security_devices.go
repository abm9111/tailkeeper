package tools

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// This file reads the API's device list as a stream. A collection must not hold more of a
// list than it can use: decoding a whole array into structs costs about a hundred times the
// size of the body (an 8 MiB body of empty entries took 873 MiB), and the body is the
// vendor's, over TLS, but not for that reason trusted to be small or well formed. The reader
// decodes a row into a device only while the snapshot has room for its facts; after that it
// reads a row's node ID alone. It never stops early: the rest of the list is still read, so
// that the rows are counted, a repeated node ID is found wherever its rows are, and a body
// that is cut short or is not well formed is an error and never a list that ended.

// maxListedIDs bounds the node IDs a read remembers. They answer two questions: has a node ID
// been seen before (a repeated one is believed on none of its rows), and is a node in the
// list (its facts may join the tailnet's). Past the bound a new ID is not remembered, its row
// is not kept, and a node whose ID was not remembered is not shown to be in the list.
const maxListedIDs = 1 << 16

// errNoDevices is the error of a body with no devices array.
var errNoDevices = tkerr.New(tkerr.APIError, "the device list has no devices array", "the API may have changed; run `tailkeeper doctor --probe`")

// deviceList is what a read of the device list kept: the rows that give facts, a count of
// the rows that do not, and the node IDs it saw.
type deviceList struct {
	kept     []observedDevice // in node ID order once the read is finished
	dropped  int              // rows that give no fact: no usable ID, no room, or a repeated ID
	rows     int              // rows in the list
	ids      map[string]int   // every node ID seen: its index in kept while it is kept, else -1
	repeated map[string]bool  // node IDs the list gives more than once
	doubled  map[string]bool  // node IDs with a row that gives a decision field twice
	idsFull  bool             // an ID was not remembered, for want of room in ids
}

// has says whether the list gave node ID id. A list too long to remember its IDs may have
// given an ID it does not know of: has is then false for it, never true for an ID that was
// not there.
func (l *deviceList) has(id string) bool {
	_, ok := l.ids[id]
	return ok
}

// deviceFeed is the value a device list is decoded into: the decoder gives the reader the
// body, whole and checked to be one JSON value, and the reader builds a deviceList from it.
type deviceFeed struct {
	room int // facts the snapshot can still take
	list *deviceList
}

func (f *deviceFeed) UnmarshalJSON(data []byte) error {
	l, err := readDeviceList(bytes.NewReader(data), f.room)
	if err != nil {
		return err
	}
	f.list = l
	return nil
}

// readDeviceList reads {"devices":[...]} from body. room is the number of facts the
// snapshot can take for the devices in it.
func readDeviceList(body io.Reader, room int) (*deviceList, error) {
	dec := json.NewDecoder(body)
	if err := wantDelim(dec, '{'); err != nil {
		return nil, err
	}
	l := &deviceList{ids: map[string]int{}, repeated: map[string]bool{}, doubled: map[string]bool{}}
	found := false
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, endOfInput(err)
		}
		// encoding/json, which the other list tools decode with, takes any spelling equal to
		// "devices" under case folding for the field: so does the reader, and a second such
		// spelling is a second devices array.
		if name, _ := key.(string); !strings.EqualFold(name, "devices") {
			if err := skipValue(dec); err != nil {
				return nil, err
			}
			continue
		}
		if found {
			return nil, errors.New("the device list has two devices arrays")
		}
		found = true
		if err := l.readArray(dec, room); err != nil {
			return nil, err
		}
	}
	if err := wantDelim(dec, '}'); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the device list is followed by more data")
	}
	if !found {
		return nil, errNoDevices
	}
	l.finish()
	return l, nil
}

// readArray reads the devices array: a row at a time, into a device while there is room for
// the facts of one, and as a node ID alone after that.
func (l *deviceList) readArray(dec *json.Decoder, room int) error {
	tok, err := dec.Token()
	if err != nil {
		return endOfInput(err)
	}
	if tok == nil {
		return errNoDevices
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return errors.New("the devices of the device list are not an array")
	}
	left := room
	// One row, one node ID and one buffer are reused for every row: a row that is kept is
	// copied out, and the others leave nothing for the collector to free.
	var (
		raw json.RawMessage
		d   observedDevice
		id  struct {
			NodeID string `json:"nodeId"`
		}
	)
	for dec.More() {
		l.rows++
		raw = raw[:0]
		if err := dec.Decode(&raw); err != nil {
			return endOfInput(err)
		}
		// A row that gives its node ID twice names no one device; one that gives another
		// decision field twice names the device but says two things of it. encoding/json
		// would keep the last of each, and which comes last is not evidence.
		twice := repeatedKeys(raw)
		if twice.nodeID {
			l.dropped++
			continue
		}
		if left > 0 {
			d = observedDevice{}
			if err := json.Unmarshal(raw, &d); err != nil {
				return err
			}
			if twice.other {
				l.addDoubled(d.NodeID)
				continue
			}
			left -= l.add(d, left)
			continue
		}
		id.NodeID = ""
		if err := json.Unmarshal(raw, &id); err != nil {
			return err
		}
		l.add(observedDevice{NodeID: id.NodeID}, 0)
	}
	return wantDelim(dec, ']')
}

// decisionKeys are the fields of a row the collector reads. encoding/json matches a key to a
// field without regard to case, so a key is one of these if it is equal to it under case
// folding.
var decisionKeys = [...]string{"nodeId", "clientVersion", "os", "lastSeen", "connectedToControl", "authorized", "blocksIncomingConnections", "sshEnabled"}

// rowKeys says which decision fields a row gives more than once: its node ID, or another.
type rowKeys struct{ nodeID, other bool }

// repeatedKeys reads the keys of the row raw, a JSON value the decoder has already checked,
// and says which decision fields it gives twice. A row that is not an object gives none. It
// scans the bytes rather than decoding them, so that a row costs no allocation; only a key
// written with an escape is decoded, as encoding/json would decode it before matching.
func repeatedKeys(raw []byte) rowKeys {
	var k rowKeys
	if len(raw) == 0 || raw[0] != '{' {
		return k
	}
	var seen [len(decisionKeys)]bool
	depth := 0
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case '"':
			end := stringEnd(raw, i)
			if end < 0 {
				return k
			}
			if depth == 1 && followedByColon(raw, end) {
				if f := decisionKey(raw[i:end]); f >= 0 {
					if seen[f] {
						if f == 0 {
							k.nodeID = true
						} else {
							k.other = true
						}
					}
					seen[f] = true
				}
			}
			i = end - 1
		}
	}
	return k
}

// followedByColon says whether the first byte at or after i that is not white space is a
// colon: the string before it is a key.
func followedByColon(raw []byte, i int) bool {
	for ; i < len(raw); i++ {
		switch raw[i] {
		case ' ', '\t', '\n', '\r':
		default:
			return raw[i] == ':'
		}
	}
	return false
}

// decisionKey is the index in decisionKeys of the field the quoted key names, or -1.
func decisionKey(quoted []byte) int {
	name := quoted[1 : len(quoted)-1]
	if bytes.IndexByte(name, '\\') >= 0 {
		var s string
		if json.Unmarshal(quoted, &s) != nil {
			return -1
		}
		name = []byte(s)
	}
	for i, f := range decisionKeys {
		if bytes.EqualFold(name, []byte(f)) {
			return i
		}
	}
	return -1
}

// addDoubled files a row that gives a decision field twice. The device is in the list, but
// none of its rows is believed: like a node ID listed twice, it is named only by a fact that
// says why it cannot be judged.
func (l *deviceList) addDoubled(id string) {
	l.dropped++
	if !assetOK(id) {
		return
	}
	if _, seen := l.ids[id]; seen {
		// A node ID listed before: it is now listed twice, and finish drops (and counts) a
		// row of it kept earlier.
		l.repeated[id] = true
		return
	}
	if len(l.ids) >= maxListedIDs {
		l.idsFull = true
		return
	}
	l.ids[id] = -1
	l.doubled[id] = true
}

// add files one row and returns the facts it takes from the snapshot's room. A row is kept
// only if its node ID is usable, new, remembered and its facts fit. A repeated ID is
// recorded wherever its second row is, and finish drops the first.
func (l *deviceList) add(d observedDevice, left int) int {
	id := d.NodeID
	if !assetOK(id) {
		l.dropped++
		return 0
	}
	if _, seen := l.ids[id]; seen {
		l.repeated[id] = true
		l.dropped++
		return 0
	}
	if len(l.ids) >= maxListedIDs {
		l.idsFull = true
		l.dropped++
		return 0
	}
	if n := d.facts(); n <= left {
		l.ids[id] = len(l.kept)
		l.kept = append(l.kept, d)
		return n
	}
	l.ids[id] = -1
	l.dropped++
	return 0
}

// finish drops every row of a node ID the list gave more than once, counting it, and puts
// what is kept in node ID order, so that the snapshot does not depend on the order of the
// list.
func (l *deviceList) finish() {
	for id := range l.repeated {
		if i := l.ids[id]; i >= 0 {
			l.kept[i].NodeID = ""
			l.dropped++
		}
	}
	l.kept = slices.DeleteFunc(l.kept, func(d observedDevice) bool { return d.NodeID == "" })
	slices.SortFunc(l.kept, func(a, b observedDevice) int { return strings.Compare(a.NodeID, b.NodeID) })
}

// wantDelim reads the next token and requires it to be the delimiter d.
func wantDelim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return endOfInput(err)
	}
	if got, ok := tok.(json.Delim); !ok || got != d {
		return errors.New("the device list is not shaped as expected: wanted " + d.String())
	}
	return nil
}

// skipValue reads one JSON value of any shape and discards it.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return endOfInput(err)
		}
		if d, ok := tok.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

// endOfInput turns the end of the input where a value was still due into an error: a list
// that stops in the middle is not a list that ended.
func endOfInput(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
