package acl

import "strconv"

// pointerOf is the JSON Pointer (RFC 6901) of something a normal form kept a ref to, cut at
// 1 KiB. Pointers are made only for what a result names, never for every node, and each
// part is read only as far as the cut can show it: a name of a megabyte costs about what a
// name of a kilobyte does.
func (d *Doc) pointerOf(r ref) string {
	if r.val == nil || r.top < 0 || r.top >= len(d.top) {
		return ""
	}
	b := make([]byte, 0, 128)
	b = append(b, '/')
	b = append(b, escapePointer(nameHead(d.top[r.top].key, maxPointer+1))...)
	if len(b) <= maxPointer {
		switch {
		case r.tail != "":
			b = append(b, r.tail[:min(len(r.tail), maxPointer+4)]...)
		case r.idx >= 0:
			b = append(b, '/')
			b = strconv.AppendInt(b, int64(r.idx), 10)
		case r.named:
			b = append(b, '/')
			b = append(b, escapePointer(nameHead(r.val, maxPointer+1))...)
		}
	}
	return capText(string(b))
}

// lineOf is the line and column of the start of what a ref points at, or 0 and 0.
func (d *Doc) lineOf(r ref) (line, col int) {
	if r.val == nil {
		return 0, 0
	}
	return d.Position(r.val.StartOffset)
}
