#!/usr/bin/env sh
# Send a finished scan to Bitbucket Code Insights, then exit with the scan's result.
#
# Run it outside the checkout, in a step that holds BITBUCKET_TOKEN and never runs the pull request's code. It reads only
# the three files 0-ci-scan.sh wrote (scan.json, scan.exit, scan.commit) from ZEROCI_OUT_DIR.
#
#   ZEROCI_OUT_DIR      folder with the files (default: the current folder)
#   ZEROCI_UPLOAD_TO    bitbucket-cloud (default) or bitbucket-dc
#   ZEROCI_REPO         workspace/repo on Cloud, PROJECT/repo on Data Center. Cloud reads BITBUCKET_WORKSPACE and
#                     BITBUCKET_REPO_SLUG in Pipelines when this is empty.
#   BITBUCKET_URL     Data Center server, for example https://bitbucket.example.com
#   BITBUCKET_TOKEN   token that can write Code Insights reports. Without it nothing is sent and the scan's result is kept.
set -eu

fail() { printf '%s\n' "0-ci-publish: $*" >&2; exit 2; }

dir="${ZEROCI_OUT_DIR:-.}"
[ -f "$dir/scan.exit" ] || fail "no scan.exit in $dir; run 0-ci-scan.sh first"
code="$(cat "$dir/scan.exit")"
case "$code" in 0|1|2|3) ;; *) fail "scan.exit holds an unexpected value" ;; esac
commit="$(cat "$dir/scan.commit" 2>/dev/null || true)"
case "$commit" in *[!0-9a-f]*|'') fail "scan.commit is missing or is not a 40-character hash" ;; esac
[ "${#commit}" -eq 40 ] || fail "scan.commit is missing or is not a 40-character hash"
target="${ZEROCI_UPLOAD_TO:-bitbucket-cloud}"
case "$target" in bitbucket-cloud|bitbucket-dc) ;; *) fail "ZEROCI_UPLOAD_TO must be bitbucket-cloud or bitbucket-dc" ;; esac

if [ "$code" -ne 2 ] && [ -f "$dir/scan.json" ]; then
  if [ -n "${BITBUCKET_TOKEN:-}" ]; then
    set -- findings upload "$dir/scan.json" --to "$target" --commit "$commit"
    [ -z "${ZEROCI_REPO:-}" ] || set -- "$@" --repo "$ZEROCI_REPO"
    [ "$target" != "bitbucket-dc" ] || [ -z "${BITBUCKET_URL:-}" ] || set -- "$@" --url "$BITBUCKET_URL"
    0security "$@"
  else
    printf '%s\n' "0-ci-publish: BITBUCKET_TOKEN is not set, so nothing was sent." >&2
  fi
fi

if [ "$code" -eq 3 ]; then printf '%s\n' "The scan stopped at its budget; the findings are partial." >&2; code=0; fi
exit "$code"
