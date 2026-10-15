#!/bin/sh
# Judges the tests that skipped in the Windows CI job: windows-skips.sh TEST_LOG DOC.
#
# TEST_LOG is the output of `go test -v ./...` on Windows and DOC is docs/windows.md.
# The tests that report SKIP in the log must be exactly the ones the document lists
# between its windows-skipped markers (a list line starts with the test's name in
# backticks). It fails, and says why, when
#   - the log is missing or holds no test result (a run that never reached go test must
#     not read as "no tests skipped");
#   - the document lacks the markers, or lists nothing between them (a list that matched
#     nothing must not read as "all of them listed");
#   - a test skipped that the document does not list, or the document lists a test that
#     did not skip (it ran, failed or is gone).
#
# It uses sh and awk only. Under Git Bash on Windows a Windows program of the same name
# (sort.exe, find.exe) can come first on PATH, so nothing here depends on one, and the
# patterns avoid GNU extensions (\s) that other awks and greps lack.
#
# -u but not -e: every exit status is judged below.
set -u

log="${1:-}"
doc="${2:-}"
if [ -z "$log" ] || [ ! -f "$log" ]; then echo "windows-skips: there is no test log at \"$log\""; exit 1; fi
if [ -z "$doc" ] || [ ! -f "$doc" ]; then echo "windows-skips: there is no document at \"$doc\""; exit 1; fi

# The document comes first, then the log. A Windows log has CRLF line ends.
awk -v doc="$doc" '
	function sorted(set, out,    n, name, i, j, t) {
		n = 0
		for (name in set) { out[++n] = name }
		for (i = 2; i <= n; i++) {
			t = out[i]
			for (j = i - 1; j >= 1 && out[j] > t; j--) { out[j + 1] = out[j] }
			out[j + 1] = t
		}
		return n
	}
	{ sub(/\r$/, "") }
	FILENAME == doc {
		if ($0 == "<!-- windows-skipped:begin -->") { begins++; inlist = 1; next }
		if ($0 == "<!-- windows-skipped:end -->") { ends++; inlist = 0; next }
		if (inlist && $0 ~ /^- `[^`]+`/) {
			name = $0
			sub(/^- `/, "", name)
			sub(/`.*$/, "", name)
			if (!(name in listed)) { listed[name] = 1; nlisted++ }
		}
		next
	}
	{
		if ($0 ~ /^[ \t]*--- (PASS|FAIL|SKIP): /) { results++ }
		if ($0 ~ /^[ \t]*--- SKIP: /) {
			name = $0
			sub(/^[ \t]*--- SKIP: /, "", name)
			sub(/ .*$/, "", name)
			if (!(name in skipped)) { skipped[name] = 1; nskipped++ }
		}
	}
	END {
		bad = 0
		if (begins != 1 || ends != 1) {
			printf "windows-skips: %s must have exactly one windows-skipped:begin and one windows-skipped:end marker (found %d and %d)\n", doc, begins, ends
			bad = 1
		}
		if (nlisted == 0) {
			printf "windows-skips: %s lists no skipped test between its markers\n", doc
			bad = 1
		}
		if (results == 0) {
			print "windows-skips: the test log holds no test result (no --- PASS, --- FAIL or --- SKIP line)"
			bad = 1
		}
		if (bad) { exit 1 }
		for (name in skipped) { if (!(name in listed)) { extra[name] = 1 } }
		for (name in listed) { if (!(name in skipped)) { missing[name] = 1 } }
		n = sorted(extra, names)
		for (i = 1; i <= n; i++) { printf "windows-skips: %s skipped and %s does not list it\n", names[i], doc; bad = 1 }
		delete names
		n = sorted(missing, names)
		for (i = 1; i <= n; i++) { printf "windows-skips: %s lists %s, which did not skip (it ran, failed or is gone)\n", doc, names[i]; bad = 1 }
		if (bad) { exit 1 }
		printf "windows-skips: %d tests skipped, exactly the %d that %s lists (%d test results read)\n", nskipped, nlisted, doc, results
	}
' "$doc" "$log"
