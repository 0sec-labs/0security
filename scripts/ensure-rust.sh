#!/usr/bin/env bash
# Install the Rust toolchain pinned in rust-toolchain.toml (the single source of
# truth for the Foxguard build) and report it. Installs rustup first when the
# runner has none (a pinned, checksum-verified rustup-init). Usage: scripts/ensure-rust.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
channel="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$root/rust-toolchain.toml")"
[ -n "$channel" ] || { echo "ensure-rust: no channel in rust-toolchain.toml" >&2; exit 1; }
case "$channel" in [0-9]*.[0-9]*.[0-9]*) ;; *) echo "ensure-rust: rust-toolchain.toml must pin an exact version, found ${channel}" >&2; exit 1 ;; esac

export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
if ! command -v rustup >/dev/null 2>&1; then
  # rustup-init is pinned by version and checked against a SHA-256 kept here, so a changed download fails the build.
  rustup_version="1.29.3"
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) rustup_target="x86_64-unknown-linux-gnu"; rustup_sha256="b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55" ;;
    Linux-aarch64|Linux-arm64) rustup_target="aarch64-unknown-linux-gnu"; rustup_sha256="9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282" ;;
    Darwin-arm64) rustup_target="aarch64-apple-darwin"; rustup_sha256="63752a1919a3a4793173ec70f8f212621a7ce38ba6a246095984482f4de20f9f" ;;
    Darwin-x86_64) rustup_target="x86_64-apple-darwin"; rustup_sha256="bc107f1fb0228de7fa32413c89c1b305cea9cd256e94b01150cd054128145429" ;;
    *) echo "ensure-rust: no pinned rustup-init for $(uname -s)-$(uname -m); install rustup yourself and run again" >&2; exit 1 ;;
  esac
  tmp="$(mktemp -d)"
  trap 'rm -f "$tmp/rustup-init"; rmdir "$tmp" 2>/dev/null || true' EXIT
  curl --proto '=https' --tlsv1.2 -sSfo "$tmp/rustup-init" "https://static.rust-lang.org/rustup/archive/${rustup_version}/${rustup_target}/rustup-init"
  if command -v sha256sum >/dev/null 2>&1; then actual="$(sha256sum "$tmp/rustup-init" | cut -d' ' -f1)"; else actual="$(shasum -a 256 "$tmp/rustup-init" | cut -d' ' -f1)"; fi
  [ "$actual" = "$rustup_sha256" ] || { echo "ensure-rust: rustup-init ${rustup_version} for ${rustup_target} has SHA-256 ${actual}, expected ${rustup_sha256}" >&2; exit 1; }
  chmod +x "$tmp/rustup-init"
  "$tmp/rustup-init" -y --profile minimal --default-toolchain none
fi
rustup toolchain install "$channel" --profile minimal --component rustfmt --component clippy
if [ -n "${GITHUB_PATH:-}" ]; then echo "${CARGO_HOME:-$HOME/.cargo}/bin" >> "$GITHUB_PATH"; fi
(cd "$root" && cargo --version && rustc --version)
