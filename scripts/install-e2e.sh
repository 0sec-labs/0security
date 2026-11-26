#!/usr/bin/env bash
# Exercise every supported public installation path in a fresh container.
#
# Usage:
#   bash scripts/install-e2e.sh [binary|source|container|all]
set -euo pipefail

readonly REPOSITORY="0sec-labs/0security"
# The image keeps its original package name until ghcr.io/0sec-labs/0security is published.
readonly IMAGE="ghcr.io/0sec-labs/0security:latest"
readonly METHOD="${1:-all}"

require_docker() {
  command -v docker >/dev/null 2>&1 || {
    echo "docker is required to run installation E2E checks" >&2
    exit 2
  }
  docker info >/dev/null 2>&1 || {
    echo "an accessible Docker daemon is required to run installation E2E checks" >&2
    exit 2
  }
}

check_binary_install() {
  docker run --rm --pull=always ubuntu:24.04 bash -ceu '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl
    rm -rf /var/lib/apt/lists/*

    export HOME=/tmp/0-home
    export SHELL=/bin/bash
    curl -fsSL https://raw.githubusercontent.com/0sec-labs/0security/main/install.sh | bash
    # Use the saved shell configuration, rather than hiding PATH regressions
    # behind a test-only export.
    . "$HOME/.profile"
    0 --version
    0 --help >/dev/null
    # Foxguard is installed only from a release that lists it (the installer reads the same checksums.txt). A
    # release published before Foxguard was bundled has no such asset, so the check applies only when it is listed.
    case "$(uname -m)" in x86_64|amd64) platform=linux-x64 ;; aarch64|arm64) platform=linux-arm64 ;; *) platform="" ;; esac
    checksums="$(curl -fsSL https://github.com/0sec-labs/0security/releases/latest/download/checksums.txt)"
    if printf "%s\n" "$checksums" | awk -v asset="foxguard-$platform" "\$2 == asset || \$2 == (\"*\" asset) { found = 1 } END { exit !found }"; then
      foxguard --version
    else
      echo "the latest release lists no foxguard-$platform; skipping the Foxguard check" >&2
    fi
    ! command -v node
  '
}

check_source_install() {
  docker run --rm --pull=always node:24-bookworm bash -ceu '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates git
    rm -rf /var/lib/apt/lists/*

    git clone --depth 1 https://github.com/0sec-labs/0security.git /work/0
    cd /work/0
    corepack enable
    pnpm install --frozen-lockfile
    pnpm build
    node packages/cli/dist/index.js --help >/dev/null
  '
}

check_container_install() {
  docker run --rm --pull=always "$IMAGE" --help >/dev/null
}

require_docker
case "$METHOD" in
  binary) check_binary_install ;;
  source) check_source_install ;;
  container) check_container_install ;;
  all)
    check_binary_install
    check_source_install
    check_container_install
    ;;
  *)
    echo "usage: $0 [binary|source|container|all]" >&2
    exit 2
    ;;
esac
