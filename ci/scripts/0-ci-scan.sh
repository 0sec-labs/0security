#!/usr/bin/env sh
# Scan the change a pull request makes and keep the result for a later publish step.
#
# Run it inside the checkout, with 0security on the PATH. It writes three files to ZEROCI_OUT_DIR:
#   scan.json    the report (agent verdict, rationale and fix guidance)
#   scan.exit    the exit code of the scan: 0 done, 1 finding at the fail level or scan failed, 2 usage error, 3 stopped early
#   scan.commit  the commit the results belong to (all 40 characters)
#
# Settings come from environment variables, never from the repository:
#   ZEROCI_BASE_BRANCH   required. The branch the pull request merges into.
#   ZEROCI_OUT_DIR       where the files go (default: the current folder)
#   ZEROCI_TARGET        folder to scan (default: .)
#   ZEROCI_FAIL_ON       critical, high, medium, low or info (default: high)
#   ZEROCI_BUDGET        spend limit in USD (default: 3)
#   ZEROCI_COMMIT        the pull request's source commit. Default: the second parent when HEAD is a merge commit, else HEAD.
#   ZEROCI_EXIT_WITH_RESULT=1  exit with the scan's code (3 becomes 0) instead of always exiting 0.
set -eu

fail() { printf '%s\n' "0-ci-scan: $*" >&2; exit 2; }

base="${ZEROCI_BASE_BRANCH:-}"
[ -n "$base" ] || fail "set ZEROCI_BASE_BRANCH to the pull request's target branch"
case "$base" in -*|*..*|*[!A-Za-z0-9._/-]*) fail "ZEROCI_BASE_BRANCH has characters a branch name should not have" ;; esac
fail_on="${ZEROCI_FAIL_ON:-high}"
case "$fail_on" in critical|high|medium|low|info) ;; *) fail "ZEROCI_FAIL_ON must be critical, high, medium, low or info" ;; esac
budget="${ZEROCI_BUDGET:-3}"
case "$budget" in ''|*[!0-9.]*) fail "ZEROCI_BUDGET must be a number" ;; esac
target="${ZEROCI_TARGET:-.}"
case "$target" in -*|/*|*..*) fail "ZEROCI_TARGET must be a folder inside the checkout" ;; esac
out="${ZEROCI_OUT_DIR:-.}"
mkdir -p "$out"

commit="${ZEROCI_COMMIT:-}"
if [ -z "$commit" ]; then
  if git rev-parse --verify --quiet "HEAD^2" >/dev/null 2>&1; then commit="$(git rev-parse HEAD^2)"; else commit="$(git rev-parse HEAD)"; fi
fi
case "$commit" in *[!0-9a-f]*|'') fail "the commit is not a 40-character hash" ;; esac
[ "${#commit}" -eq 40 ] || fail "the commit is not a 40-character hash"

git fetch --no-tags --depth=1 origin "+refs/heads/${base}:refs/remotes/origin/${base}"

code=0
0security scan "$target" --diff "origin/${base}" --format json -o "$out/scan.json" --fail-on "$fail_on" --budget "$budget" || code=$?
printf '%s\n' "$code" > "$out/scan.exit"
printf '%s\n' "$commit" > "$out/scan.commit"

if [ "${ZEROCI_EXIT_WITH_RESULT:-}" = "1" ]; then
  if [ "$code" -eq 3 ]; then printf '%s\n' "The scan stopped at its budget; the findings are partial." >&2; code=0; fi
  exit "$code"
fi
exit 0
