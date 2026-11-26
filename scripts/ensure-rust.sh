#!/usr/bin/env bash
# Install the Rust toolchain pinned in rust-toolchain.toml (the single source of
# truth for the Foxguard build) and report it. Installs rustup first when the
# runner has none. Usage: scripts/ensure-rust.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
channel="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$root/rust-toolchain.toml")"
[ -n "$channel" ] || { echo "ensure-rust: no channel in rust-toolchain.toml" >&2; exit 1; }
case "$channel" in [0-9]*.[0-9]*.[0-9]*) ;; *) echo "ensure-rust: rust-toolchain.toml must pin an exact version, found ${channel}" >&2; exit 1 ;; esac

export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
fi
rustup toolchain install "$channel" --profile minimal --component rustfmt --component clippy
if [ -n "${GITHUB_PATH:-}" ]; then echo "${CARGO_HOME:-$HOME/.cargo}/bin" >> "$GITHUB_PATH"; fi
(cd "$root" && cargo --version && rustc --version)
