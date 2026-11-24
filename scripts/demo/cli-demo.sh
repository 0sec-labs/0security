#!/usr/bin/env bash
# Terminal demo: scan a small vulnerable app, list findings, fix one on a branch.
# Run from the demo app directory (see cli-demo-setup.sh) with 0security on PATH and a HOME whose state dir already holds the telemetry-notice flag file.
# Record with: asciinema rec --idle-time-limit 1.5 -c 'bash scripts/demo/cli-demo.sh' (or run scripts/demo/record.sh)
set -euo pipefail
export GIT_PAGER=cat

type_cmd() {
  printf '$ '
  local s="$1" i
  for ((i = 0; i < ${#s}; i++)); do
    printf '%s' "${s:i:1}"
    sleep 0.04
  done
  sleep 0.4
  printf '\n'
}

run() {
  type_cmd "$*"
  "$@"
  sleep 1.2
}

run 0security --version
run 0security scan . --budget 1
run 0security findings list

id=$(0security findings list --format json | jq -r '[.findings[] | select(.category == "sql-injection")][0].id')
[[ -n "$id" && "$id" != null ]] || { echo "no sql-injection finding to fix" >&2; exit 1; }
type_cmd "0security findings fix $id --test \"node --test\" --no-pr"
0security findings fix "$id" --test "node --test" --no-pr
sleep 1.2

br=$(git branch --list '0/fix-*' --format '%(refname:short)' | sed -n 1p)
run git checkout -q "$br"
run node --test
run git log --oneline -3
run git show --stat HEAD
