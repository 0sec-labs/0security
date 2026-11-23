#!/usr/bin/env bash
# Stage the release binaries and write checksums.txt.
#
# Usage: scripts/stage-release-assets.sh <dir>
#
# <dir> holds the built binaries named 0-<platform>. Each one is copied, not
# rebuilt, to 0security-<platform> so both names carry identical bytes. The old
# 0-<platform> names stay published because installed copies update through them.
# checksums.txt covers every name in both sets. Fails if a binary is missing.
set -euo pipefail

dir="${1:?usage: stage-release-assets.sh <dir>}"
PLATFORMS="darwin-arm64 linux-x64 linux-arm64 windows-x64.exe"

if command -v sha256sum >/dev/null 2>&1; then
  sum() { sha256sum "$@"; }
else
  sum() { shasum -a 256 "$@"; }
fi

cd "$dir"
old=() new=()
for p in $PLATFORMS; do
  [ -f "0-$p" ] || { echo "stage-release-assets: missing 0-$p in $dir" >&2; exit 1; }
  cp -f "0-$p" "0security-$p"
  old+=("0-$p")
  new+=("0security-$p")
done
sum "${old[@]}" "${new[@]}" > checksums.txt
