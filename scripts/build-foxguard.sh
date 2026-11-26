#!/usr/bin/env bash
# Build the Foxguard scanner from crates/foxguard and install it as
# <dir>/foxguard. This replaces downloading a pinned prebuilt companion: the
# scanner is part of this repository and is built with the toolchain pinned in
# rust-toolchain.toml.
#
# Usage:
#   INSTALL_DIR=/path/to/bin bash scripts/build-foxguard.sh   # default: ./target/foxguard-bin
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="${INSTALL_DIR:-$root/target/foxguard-bin}"

bash "$root/scripts/ensure-rust.sh" >&2
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
(cd "$root" && cargo build --release --locked -p foxguard --bin foxguard) >&2

mkdir -p "$dir"
cp -f "$root/target/release/foxguard" "$dir/foxguard.$$"
chmod 755 "$dir/foxguard.$$"
mv -f "$dir/foxguard.$$" "$dir/foxguard"
echo "Built Foxguard at $dir/foxguard" >&2
