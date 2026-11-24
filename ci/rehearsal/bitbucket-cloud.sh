#!/usr/bin/env sh
# Rehearse the Code Insights recipe on a real Bitbucket Cloud workspace, and print a checklist of what passed.
#
# THIS SCRIPT HAS NOT BEEN RUN against Bitbucket Cloud. Its first run is the rehearsal that issue "Rehearse the CI recipe on
# real Bitbucket Cloud" asks for. It uses a fixture report with three findings, so it needs no model key.
#
#   BITBUCKET_TOKEN      repository access token that can write Code Insights reports
#   REHEARSAL_REPO       workspace/repo of a test repository
#   REHEARSAL_COMMIT     the 40-character head commit of a test pull request in that repository
#   REHEARSAL_REPORT_ID  report id to use (default: 0-rehearsal)
#   --dry-run            print what would run and send nothing
#
# After the script passes, open the pull request in Bitbucket and tick the manual items it prints.
set -eu

dry=0
[ "${1:-}" = "--dry-run" ] && dry=1
here="$(cd "$(dirname "$0")" && pwd)"
api="https://api.bitbucket.org/2.0"
report="${REHEARSAL_REPORT_ID:-0-rehearsal}"
pass=0
failed=0

say() { printf '%s\n' "$*"; }
ok() { pass=$((pass + 1)); say "  [pass] $*"; }
bad() { failed=$((failed + 1)); say "  [FAIL] $*"; }

say "Bitbucket Cloud rehearsal (not yet run against a live workspace)"
[ -n "${BITBUCKET_TOKEN:-}" ] || { say "Set BITBUCKET_TOKEN."; exit 2; }
repo="${REHEARSAL_REPO:-}"
case "$repo" in */*) ;; *) say "Set REHEARSAL_REPO to workspace/repo."; exit 2 ;; esac
commit="${REHEARSAL_COMMIT:-}"
case "$commit" in *[!0-9a-f]*|'') say "Set REHEARSAL_COMMIT to a 40-character commit hash."; exit 2 ;; esac
[ "${#commit}" -eq 40 ] || { say "Set REHEARSAL_COMMIT to a 40-character commit hash."; exit 2; }
case "$report" in *[!A-Za-z0-9._-]*) say "REHEARSAL_REPORT_ID has characters Bitbucket ids should not have."; exit 2 ;; esac

upload() { 0security findings upload "$here/fixture-scan.json" --to bitbucket-cloud --repo "$repo" --commit "$commit" --report-id "$report"; }
# The token goes to curl on standard input, so it never appears in a process list.
get() { printf 'header = "Authorization: Bearer %s"\n' "$BITBUCKET_TOKEN" | curl -fsS --config - "$api/repositories/$repo/commit/$commit/reports/$report$1"; }

if [ "$dry" -eq 1 ]; then
  say "Would upload $here/fixture-scan.json as report $report on $repo at $commit,"
  say "read the report and its annotations back, upload again, and check nothing was duplicated."
  exit 0
fi

say "1. Upload the fixture report"
if upload; then ok "findings upload finished"; else bad "findings upload failed"; fi

say "2. Read the report back"
body="$(get "" 2>/dev/null || true)"
case "$body" in *'"FAILED"'*) ok "report result is FAILED (it holds findings)" ;; *) bad "report not found or result is not FAILED" ;; esac
case "$body" in *'"SECURITY"'*) ok "report type is SECURITY" ;; *) bad "report type is not SECURITY" ;; esac

say "3. Count the annotations"
count_of() { printf '%s' "$1" | grep -o '"external_id"' | wc -l | tr -d ' '; }
annotations="$(get "/annotations?pagelen=100" 2>/dev/null || true)"
[ "$(count_of "$annotations")" -eq 3 ] && ok "3 annotations are on the report" || bad "expected 3 annotations, found $(count_of "$annotations")"

say "4. Upload again and check nothing is duplicated"
if upload; then
  annotations="$(get "/annotations?pagelen=100" 2>/dev/null || true)"
  [ "$(count_of "$annotations")" -eq 3 ] && ok "still 3 annotations after the second upload" || bad "found $(count_of "$annotations") annotations after the second upload"
else bad "second upload failed"; fi

say ""
say "Manual checks in Bitbucket (open the test pull request):"
say "  [ ] The Code Insights report \"0 security scan\" shows on the pull request with a FAILED result and 3 findings."
say "  [ ] README.md lines 1 to 3 show the annotations, with severity, rule and CWE in the text."
say "  [ ] Deleting the report in the API removes the annotations (curl -X DELETE on the report URL)."
say "  [ ] Record the date, the Bitbucket plan and the 0security version in the issue."
say ""
say "Automatic checks: $pass passed, $failed failed."
[ "$failed" -eq 0 ]
