#!/usr/bin/env sh
# Provision the pinned FoxGuard binary for this host architecture.
#
# Downloads the verified release asset from 0sec-labs/foxguard to a configurable
# install directory (default: /usr/local/bin). The pinned version is the same
# FOXGUARD_PINNED_TAG used by the 0 runtime (v0.14.2).
#
# Usage:
#   bash scripts/provision-foxguard.sh                    # install to /usr/local/bin
#   INSTALL_DIR=/opt/bin bash scripts/provision-foxguard.sh
set -eu

FOXGUARD_REPO="0sec-labs/foxguard"
FOXGUARD_TAG="${FOXGUARD_TAG:-v0.14.2}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# ── v0.14.2 checksums (cross-checked against the release's checksums.txt) ──
# Update the pin and its checksums together when upgrading.
FOXGUARD_SHA256_LINUX_X64="6996b73f5bd60eaa173908e585808a4df63595e09be34b1d7a5a70457a0ebec8"
FOXGUARD_SHA256_LINUX_ARM64="db6df4e455740488efef3be01df2217f825e0878ff1e4288e945db2133cabb7c"
FOXGUARD_SHA256_MACOS_ARM64="d81086ad96f46e07c863f33b64be1c5e14013d92f8e3344c6f17a23d8f34772f"
FOXGUARD_SHA256_MACOS_X64="9ca2576794fdf9bcdece6c034e4bc8f83d84eef6a66f53ed0ef1d108a9bf4104"
FOXGUARD_SHA256_WIN_X64="83b1512b6e22463055cf45d16620578ac41f02a090f912069d9d4223ae517949"

fail() {
  printf '%s\n' "foxguard provisioner: $*" >&2
  exit 1
}

[ "$FOXGUARD_TAG" = "v0.14.2" ] || fail "update the pinned checksums before selecting another release"

# Resolve platform → asset name + expected sha256
case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64)
        ASSET="foxguard-macos-aarch64"
        EXPECTED_SHA256="$FOXGUARD_SHA256_MACOS_ARM64"
        ;;
      x86_64)
        ASSET="foxguard-macos-x86_64"
        EXPECTED_SHA256="$FOXGUARD_SHA256_MACOS_X64"
        ;;
      *) fail "unsupported macOS architecture: $(uname -m)" ;;
    esac
    ;;
  Linux)
    case "$(uname -m)" in
      x86_64|amd64)
        ASSET="foxguard-linux-x86_64"
        EXPECTED_SHA256="$FOXGUARD_SHA256_LINUX_X64"
        ;;
      aarch64|arm64)
        ASSET="foxguard-linux-aarch64"
        EXPECTED_SHA256="$FOXGUARD_SHA256_LINUX_ARM64"
        ;;
      *) fail "unsupported Linux architecture: $(uname -m)" ;;
    esac
    ;;
  MINGW*|MSYS*)
    case "$(uname -m)" in
      x86_64)
        ASSET="foxguard-windows-x86_64.exe"
        EXPECTED_SHA256="$FOXGUARD_SHA256_WIN_X64"
        ;;
      *) fail "unsupported Windows architecture: $(uname -m)" ;;
    esac
    ;;
  *)
    fail "unsupported operating system: $(uname -s)"
    ;;
esac

command -v curl >/dev/null 2>&1 || fail "curl is required"
if command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  fail "sha256sum or shasum is required to verify the download"
fi

DOWNLOAD_URL="https://github.com/${FOXGUARD_REPO}/releases/download/${FOXGUARD_TAG}/${ASSET}"
INSTALL_PATH="${INSTALL_DIR}/foxguard"

# Skip if already installed and matching
if [ -f "$INSTALL_PATH" ] && [ ! -L "$INSTALL_PATH" ]; then
  actual="$(sha256_file "$INSTALL_PATH")"
  if [ "$actual" = "$EXPECTED_SHA256" ]; then
    chmod 755 "$INSTALL_PATH"
    printf '%s\n' "foxguard already verified at ${INSTALL_PATH}" >&2
    exit 0
  fi
  printf '%s\n' "foxguard at ${INSTALL_PATH} has mismatched checksum; re-downloading..." >&2
fi

mkdir -p "$INSTALL_DIR"
tmpdir="$(mktemp -d "${INSTALL_DIR}/.foxguard-install.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

downloaded="${tmpdir}/${ASSET}"
printf '%s\n' "Downloading ${ASSET} from ${FOXGUARD_TAG}..." >&2
curl --fail --location --silent --show-error --retry 3 --retry-delay 2 \
  "$DOWNLOAD_URL" -o "$downloaded"

actual="$(sha256_file "$downloaded")"
if [ "$actual" != "$EXPECTED_SHA256" ]; then
  fail "checksum mismatch for ${ASSET} (expected ${EXPECTED_SHA256}, got ${actual})"
fi

chmod 755 "$downloaded"
mv -f "$downloaded" "$INSTALL_PATH"

printf '%s\n' "Installed foxguard ${FOXGUARD_TAG} (${ASSET}) to ${INSTALL_PATH}" >&2