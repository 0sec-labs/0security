#!/usr/bin/env bash
# Terminal demo: scan a small vulnerable app, list findings, fix one on a branch.
# Run from the demo app directory (see cli-demo-setup.sh) with 0security on PATH.
# Record with: asciinema rec --idle-time-limit 1.5 -c scripts/demo/cli-demo.sh
set -u
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
type_cmd "0security findings fix $id --test \"node --test\" --no-pr"
0security findings fix "$id" --test "node --test" --no-pr
sleep 1.2

br=$(git branch --list '0/fix-*' --format '%(refname:short)' | head -1)
run git log --oneline -3 "$br"
run git diff "main..$br" --stat
run git show --patch "$br" -- server.js
