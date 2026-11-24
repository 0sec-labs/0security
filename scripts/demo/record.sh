#!/usr/bin/env bash
# Records one take. Usage: record.sh <out.cast>
# Needs OPENAI_API_KEY in the environment, asciinema, python3, jq and a built CLI (packages/cli/dist).
# Everything runs in a fresh private work directory made with mktemp -d (mode 0700); it is kept for inspection.
set -euo pipefail
umask 077

[[ $# -eq 1 && -n "$1" ]] || { echo "usage: record.sh <out.cast>" >&2; exit 2; }
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cli="$(cd -- "$here/../.." && pwd -P)/packages/cli/dist/index.js"
[[ -f "$cli" ]] || { echo "build the CLI first: $cli is missing" >&2; exit 1; }
out_dir="$(cd -- "$(dirname -- "$1")" && pwd -P)"
out="$out_dir/$(basename -- "$1")"
[[ ! -L "$out" ]] || { echo "refusing to write through a symlink: $out" >&2; exit 1; }

root="$(mktemp -d "${TMPDIR:-/tmp}/clidemo.XXXXXXXX")"
[[ -d "$root" && ! -L "$root" && -O "$root" ]] || { echo "unsafe work directory: $root" >&2; exit 1; }
mkdir -- "$root/home" "$root/home/.0" "$root/bin"
: > "$root/home/.0/telemetry-notice"
printf '#!/bin/sh\nexec node "$ZERO_DEMO_CLI" "$@"\n' > "$root/bin/0security"
chmod 700 "$root/bin/0security"

HOME="$root/home" bash "$here/cli-demo-setup.sh" "$root/app"
cd -- "$root/app"

# asciinema needs a controlling terminal for a real pty, so the CLI renders for a terminal;
# with-pty.py supplies one from a non-interactive shell. The paths travel in the environment, not in a shell string.
export ZERO_DEMO_CLI="$cli" ZERO_DEMO_SCRIPT="$here/cli-demo.sh"
HOME="$root/home" PATH="$root/bin:$PATH" python3 -I "$here/with-pty.py" \
  asciinema rec --overwrite --idle-time-limit 1.5 --window-size 100x28 -c 'bash "$ZERO_DEMO_SCRIPT"' -- "$out"
echo "recorded $out (work directory: $root)" >&2
