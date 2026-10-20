package acl

import (
	"bytes"
	"sort"
	"sync"
)

// lineIndex finds the line of a byte offset by binary search in a table of the offsets of
// every line feed, built once on first use. The HuJSON tree carries the byte offset of every
// value (Parse sets StartOffset and EndOffset), so no walk over the tree is needed to
// place a node, and no node is ever packed to find its offset, which would be quadratic.
type lineIndex struct {
	once sync.Once
	nl   []int
}

func (l *lineIndex) build(src []byte) {
	l.once.Do(func() {
		// Sized before it is filled: growing it by appending allocates about five times what
		// it holds, and a text of nothing but line ends would make that 190 MB.
		l.nl = make([]int, 0, bytes.Count(src, []byte{'\n'}))
		for i := 0; ; {
			j := bytes.IndexByte(src[i:], '\n')
			if j < 0 {
				return
			}
			l.nl = append(l.nl, i+j)
			i += j + 1
		}
	})
}

// Position is the line and column of a byte offset in the text Parse read, counted as the
// HuJSON parser and the server count: lines end at "\n", columns are bytes from 1, a lone
// carriage return is whitespace.
func (d *Doc) Position(off int) (line, col int) {
	d.lines.build(d.src)
	off = min(max(off, 0), len(d.src))
	n := sort.SearchInts(d.lines.nl, off) // line feeds before off
	start := 0
	if n > 0 {
		start = d.lines.nl[n-1] + 1
	}
	return n + 1, off - start + 1
}

// Lines is the number of lines in the text: one more than its line feeds.
func (d *Doc) Lines() int {
	d.lines.build(d.src)
	return len(d.lines.nl) + 1
}

// Len is the size of the text in bytes.
func (d *Doc) Len() int { return len(d.src) }

// Nodes is the number of values in the tree (names, values, elements and the root).
func (d *Doc) Nodes() int { return d.nodes }
