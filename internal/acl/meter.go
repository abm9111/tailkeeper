package acl

import "context"

// MaxWork is the work one call may spend, in the engine's own units (a value visited, an
// atom built, a comparison made). Real policies use a small fraction of it; text built to
// be slow runs into it and gets a too_complex error. It counts operations, not time, so
// the same input reads the same on every machine.
const MaxWork = 1 << 26

// maxWork is MaxWork; a test lowers it.
var maxWork int64 = MaxWork

// meter counts the work of one call and checks the caller's context as it goes.
type meter struct {
	ctx  context.Context
	used int64
}

func newMeter(ctx context.Context) *meter { return &meter{ctx: ctx} }

// tick adds n units of work. It fails when the budget is spent, and, every 4,096 units,
// when the context is done.
func (m *meter) tick(n int) error {
	before := m.used
	m.used += int64(n)
	if m.used > maxWork {
		return tooComplex("the policy needs more work to read than the limit of %d steps allows", maxWork)
	}
	if m.used>>12 != before>>12 {
		return m.ctx.Err()
	}
	return nil
}
