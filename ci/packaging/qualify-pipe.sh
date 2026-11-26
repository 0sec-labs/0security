#!/bin/sh
# A real binary/scanner scan in the built image against a synthetic local PR. No public writes.
# Requires Docker. Default is scanner-only, with no model request. Add --model only with an approved spend cap.
set -eu
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || { echo 'usage: qualify-pipe.sh IMAGE [--model]' >&2; exit 2; }
image="$1"
[ -z "${QUALIFICATION_ARTIFACTS:-}" ] || [ ! -e "$QUALIFICATION_ARTIFACTS" ] || { echo 'QUALIFICATION_ARTIFACTS already exists' >&2; exit 2; }
prepass=1
if [ "${2:-}" = --model ]; then
  [ -n "${OPENAI_API_KEY:-}" ] || { echo 'set OPENAI_API_KEY for the actual model scan' >&2; exit 2; }
  prepass=0
elif [ -n "${2:-}" ]; then echo 'unknown qualification option' >&2; exit 2; fi
root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
mkdir -p "$root/tmp"
temp="$(mktemp -d "$root/tmp/0-pipe-qualification.XXXXXX")"
trap 'rm -rf "$temp"' EXIT HUP INT TERM
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=Qualification GIT_AUTHOR_EMAIL=qualification@example.invalid
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
git init -q --bare "$temp/origin"
git clone -q "$temp/origin" "$temp/work"
cd "$temp/work"
git config remote.origin.url ../origin
git checkout -q -b main
printf '%s\n' 'Synthetic qualification repository; no application code is executed.' > README.md
git add README.md && git -c commit.gpgsign=false commit -q -m base
git push -q origin main
git checkout -q -b security-qualification
printf '%s\n' "const http = require('http');" "http.createServer((req,res) => { const expression = new URL(req.url, 'http://localhost').searchParams.get('expression'); res.end(String(eval(expression))); }).listen(3000);" > server.js
git add server.js && git -c commit.gpgsign=false commit -q -m 'synthetic unsafe expression evaluation'
if [ "$prepass" -eq 1 ]; then
  docker run --rm -v "$temp:/workspace" -e BITBUCKET_CLONE_DIR=/workspace/work \
    -e ZEROCI_PREPASS_ONLY=1 -e ZEROCI_BASE_BRANCH=main "$image"
else
  docker run --rm -v "$temp:/workspace" -e BITBUCKET_CLONE_DIR=/workspace/work \
    -e OPENAI_API_KEY -e ZEROCI_BASE_BRANCH=main -e ZEROCI_BUDGET=1 "$image"
fi
[ -s .zero-ci/scan.json ] && [ -s .zero-ci/scan.commit ] && [ -s .zero-ci/scan.exit ]
# Publish mode without a token exercises isolation and recorded exit propagation, without contacting Bitbucket.
code=0
docker run --rm -v "$temp:/workspace" -e BITBUCKET_CLONE_DIR=/workspace/work -e MODE=publish "$image" || code=$?
case "$code" in 0|1) ;; *) echo "publisher exited $code" >&2; exit "$code" ;; esac
if [ -n "${QUALIFICATION_ARTIFACTS:-}" ]; then
  mkdir -p "$QUALIFICATION_ARTIFACTS"
  cp .zero-ci/scan.json .zero-ci/scan.exit .zero-ci/scan.commit "$QUALIFICATION_ARTIFACTS/"
fi
printf '%s\n' 'Image scan and isolated publish execution completed. Live Code Insights qualification remains separate.'
