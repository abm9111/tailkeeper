#!/bin/sh
# Judges one `make live` run from the captured output of
#   go test -v -run '^TestLive' ./cmd/tailkeeper
# and the exit status go test returned: live-check.sh LOG STATUS.
#
# It prints the test framework's own lines and the lines the live tests log
# (live_test.go), which hold tool names, outcomes, error codes, sizes and counts
# and nothing from the tailnet. Everything else in the log (a panic, a stack
# trace) is withheld, because it could quote a value the tests never meant to show.
#
# It fails unless both live tests ran to the end and passed. A skipped live test
# checked nothing, so a skip is a failure here, not a pass.
#
# -u but not -e: grep exits 1 when it finds nothing, and every one of those exits is
# judged below, so none may end the script early.
set -u

log="${1:-}"
status="${2:-}"
[ -f "$log" ] || { echo "live: there is no log to check"; exit 1; }
case "$status" in
'' | *[!0-9]*) echo "live: the go test status is not a number"; exit 1 ;;
esac

grep -E '^(=== RUN|--- |ok|FAIL)|live_test\.go' "$log"

if grep -q -e '--- SKIP' "$log"; then
	echo "live: a live test skipped, so it checked nothing"
	exit 1
fi
for name in TestLiveReads TestLiveMCP; do
	passes="$(grep -c -e "^--- PASS: $name " "$log")"
	if [ "$passes" != 1 ]; then
		echo "live: $name did not pass ($passes pass lines for it); the full log is withheld because it may hold tailnet values"
		exit 1
	fi
done
# Each test logs a closing line when it reaches the end: a test that returned early
# would pass without one.
grep -q -e 'live_test\.go:[0-9]*: summary: [0-9]* tools: ' "$log" || { echo "live: TestLiveReads logged no summary line"; exit 1; }
grep -q -e 'live_test\.go:[0-9]*: mcp: devices_list: [0-9]* bytes, checks passed' "$log" || { echo "live: TestLiveMCP logged no closing line"; exit 1; }
exit "$status"
