#!/bin/sh
# Judges the tests that skipped in the Windows CI job: windows-skips.sh TEST_LOG DOC.
#
# TEST_LOG is the output of `go test -v ./...` on Windows and DOC is docs/windows.md.
# The tests that report SKIP in the log must be exactly the ones the document lists
# between its windows-skipped markers (a list line is "- `Test` (`package`): reason."),
# each in the package the document names. A test is known by its package and its name:
# the same name skipping in two packages is two tests. The log says which package a skip
# belongs to only on the "ok" or "FAIL" line that ends that package's output, so a skip
# is attributed to the next such line; the package there is a full import path
# (github.com/abm9111/tailkeeper/internal/x) and the document gives the tail of it
# (internal/x). It fails, and says why, when
#   - the log is missing or holds no test result (a run that never reached go test must
#     not read as "no tests skipped");
#   - the document lacks the markers, or lists nothing between them (a list that matched
#     nothing must not read as "all of them listed");
#   - a skip is not followed by the "ok" or "FAIL" line of a package (a truncated log
#     cannot say where it came from);
#   - a test skipped in a package that the document does not list it for, or the
#     document lists a test for a package in which it did not skip (it ran, failed, is
#     gone, or moved).
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
			pkg = $0
			if (pkg ~ /^- `[^`]+` \(`[^`]+`\)/) {
				sub(/^- `[^`]+` \(`/, "", pkg)
				sub(/`.*$/, "", pkg)
			} else {
				pkg = "(no package)"
			}
			if (!((pkg SUBSEP name) in listed)) { listed[pkg SUBSEP name] = 1; nlisted++ }
		}
		next
	}
	{
		if ($0 ~ /^[ \t]*--- (PASS|FAIL|SKIP): /) { results++ }
		if ($0 ~ /^[ \t]*--- SKIP: /) {
			name = $0
			sub(/^[ \t]*--- SKIP: /, "", name)
			sub(/ .*$/, "", name)
			pending[++np] = name
		}
		# The end of a package: "ok  <tab>path<tab>time" or "FAIL<tab>path<tab>time".
		if ($0 ~ /^(ok|FAIL)[ \t]+[^ \t]+/) {
			path = $0
			sub(/^(ok|FAIL)[ \t]+/, "", path)
			sub(/[ \t].*$/, "", path)
			for (i = 1; i <= np; i++) {
				if (!((path SUBSEP pending[i]) in seen)) {
					seen[path SUBSEP pending[i]] = 1
					skpath[++ns] = path
					skname[ns] = pending[i]
				}
			}
			np = 0
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
		for (i = 1; i <= np; i++) { nopkg[pending[i]] = 1 }
		# Match each skip with a listed (package, name): the document names the tail of the
		# import path, so try the whole path, then what follows each slash.
		for (i = 1; i <= ns; i++) {
			s = skpath[i]
			found = 0
			for (;;) {
				if ((s SUBSEP skname[i]) in listed) { found = 1; matched[s SUBSEP skname[i]] = 1; break }
				k = index(s, "/")
				if (k == 0) { break }
				s = substr(s, k + 1)
			}
			if (!found) { extra[skpath[i] "." skname[i]] = 1 }
		}
		for (key in listed) {
			if (!(key in matched)) {
				split(key, parts, SUBSEP)
				missing[parts[1] "." parts[2]] = 1
			}
		}
		n = sorted(nopkg, names)
		for (i = 1; i <= n; i++) { printf "windows-skips: %s skipped and no package result line (ok or FAIL) follows it, so its package is unknown\n", names[i]; bad = 1 }
		delete names
		n = sorted(extra, names)
		for (i = 1; i <= n; i++) { printf "windows-skips: %s skipped and %s does not list it\n", names[i], doc; bad = 1 }
		delete names
		n = sorted(missing, names)
		for (i = 1; i <= n; i++) { printf "windows-skips: %s lists %s, which did not skip (it ran, failed or is gone)\n", doc, names[i]; bad = 1 }
		if (bad) { exit 1 }
		printf "windows-skips: %d tests skipped, exactly the %d that %s lists (%d test results read)\n", ns, nlisted, doc, results
	}
' "$doc" "$log"
