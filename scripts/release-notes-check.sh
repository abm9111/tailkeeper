#!/bin/sh
# Judges a GoReleaser run made with --verbose and --release-notes FIXTURE:
#   release-notes-check.sh FIXTURE LOG
#
# FIXTURE is the notes file the run was given and LOG is what the run printed. GoReleaser
# reads that file in its changelog stage and nowhere else, and the stage does not run when
# the configuration disables it (v0.5.0 was published with only the release footer for
# that reason). A snapshot leaves the stage out, and with --release-notes the stage never
# writes dist/CHANGELOG.md, so the stage leaves one trace: its step line, "generating
# changelog" (a skipped stage prints "skipped generating changelog" instead), and a debug
# line saying how many bytes it read from which file. It fails, and says why, when
#   - the fixture or the log is missing, or the fixture is empty (a size of 0 would match
#     a stage that read nothing);
#   - the log shows the stage skipped, or shows no stage step at all;
#   - the log does not say the stage read exactly the fixture's size from the fixture's
#     path (the whole value of file=, not a path that begins with it), which is how it
#     shows that it read this file and not another.
#
# It uses sh, grep and wc only. The log is read as text (grep -a): a verbose run prints
# the tag's annotation through git, and that output holds NUL bytes, which make grep
# print "Binary file matches" in place of the lines. -u but not -e: grep exits 1 when it
# finds nothing, and every one of those exits is judged below.
set -u

fixture="${1:-}"
log="${2:-}"
if [ -z "$fixture" ] || [ ! -f "$fixture" ]; then echo "release-notes-check: there is no fixture at \"$fixture\""; exit 1; fi
if [ -z "$log" ] || [ ! -f "$log" ]; then echo "release-notes-check: there is no GoReleaser log at \"$log\""; exit 1; fi

size="$(wc -c < "$fixture" | tr -d '[:space:]')"
if [ -z "$size" ] || [ "$size" -eq 0 ]; then echo "release-notes-check: the fixture \"$fixture\" is empty"; exit 1; fi

if grep -a -q -e 'skipped generating changelog' "$log"; then
	echo "release-notes-check: GoReleaser skipped its changelog stage, so it never read the release notes (is changelog.disable set?)"
	exit 1
fi
if ! grep -a -q -e 'generating changelog' "$log"; then
	echo "release-notes-check: the log shows no changelog stage, so GoReleaser never read the release notes"
	exit 1
fi
# The value of file= on a line that says "read <size> bytes" must be the fixture's whole
# path, alone or followed by a space and another field, not a path that only begins with it.
found="$(grep -a -F -e "read $size bytes" "$log" | sed -n 's/^.*file=//p' | while IFS= read -r value; do
	case "$value" in
	("$fixture" | "$fixture "*)
		echo yes
		break
		;;
	esac
done)"
if [ "$found" != "yes" ]; then
	echo "release-notes-check: the changelog stage ran but did not report reading $size bytes from \"$fixture\""
	exit 1
fi
echo "release-notes-check: GoReleaser's changelog stage read the $size bytes of $fixture"
