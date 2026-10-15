package tools

import "time"

// SetSettingsWait shortens acl_get's settings deadline for one test and returns
// the function that restores it.
func SetSettingsWait(d time.Duration) (restore func()) {
	old := settingsWait
	settingsWait = d
	return func() { settingsWait = old }
}
