package tools

// CutAt is the text as a read of limit bytes leaves it: cut at a rune boundary, with nothing
// of a login that starts before the cut left in it. It is not masked.
func (r *SubjectResolver) CutAt(text string, limit int) string {
	return cutForHideAt(text, r.state().users().resolved, limit)
}

// HideRead is Hide with the number of bytes of the text it read to make the result.
func (r *SubjectResolver) HideRead(text string) (string, int) {
	out, read := r.read(text, hideNeed, false, hideMaxRead)
	return head(out, hideNeed), read
}
