#!/usr/bin/env bash
# Records one take. Usage: record.sh <out.cast>
# Needs OPENAI_API_KEY in the environment, asciinema, jq. Uses a fresh HOME.
set -euo pipefail
out="${1:?usage: record.sh <out.cast>}"
here="$(cd "$(dirname "$0")" && pwd)"
root=/tmp/clidemo
mkdir -p "$root/old"; for d in home app; do [ -e "$root/$d" ] && mv "$root/$d" "$root/old/$d-$$-$RANDOM"; done; mkdir -p "$root/home/.0"
touch "$root/home/.0/telemetry-notice"
HOME="$root/home" bash "$here/cli-demo-setup.sh" "$root/app"
cd "$root/app"
# asciinema needs a controlling terminal for a real pty, so the CLI renders for a terminal; with-pty.py supplies one from a non-interactive shell.
HOME="$root/home" PATH="$root/bin:$PATH" python3 "$here/with-pty.py" asciinema rec --overwrite --idle-time-limit 1.5 --window-size 100x28 -c "bash $here/cli-demo.sh" "$out"
