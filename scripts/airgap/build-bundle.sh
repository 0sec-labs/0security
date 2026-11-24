#!/usr/bin/env sh
# Build an offline install bundle for 0. Run it on a connected machine, then carry the
# resulting archive into the isolated network.
#
#   scripts/airgap/build-bundle.sh --version 0.44.0 --out ./bundle [--platform linux-x64] [--image] [--chart]
#
# The bundle holds the release binary, its checksums and signature bundles, optionally the
# container image and the Helm chart, a MANIFEST.sha256 over every file, and install-bundle.sh.
# The release signature is verified here, on the connected side, before anything is packed.
set -eu

REPO="0sec-labs/0security"
VERSION=""
OUT=""
PLATFORM="linux-x64"
WITH_IMAGE=0
WITH_CHART=0
ALLOW_UNSIGNED=0
RELEASE_BASE_URL="${RELEASE_BASE_URL:-}"
IMAGE_NAME="${IMAGE_NAME:-ghcr.io/${REPO}}"

fail() { printf '%s\n' "build-bundle: $*" >&2; exit 1; }
usage() {
  printf '%s\n' "usage: build-bundle.sh --version X.Y.Z --out DIR [--platform linux-x64|linux-arm64|darwin-arm64] [--image] [--chart] [--allow-unsigned]" >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --platform) PLATFORM="${2:-}"; shift 2 ;;
    --image) WITH_IMAGE=1; shift ;;
    --chart) WITH_CHART=1; shift ;;
    --allow-unsigned) ALLOW_UNSIGNED=1; shift ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done
[ -n "$VERSION" ] && [ -n "$OUT" ] || usage
case "$VERSION" in [0-9]*.[0-9]*.[0-9]*) ;; *) fail "--version must look like 0.44.0" ;; esac
case "$PLATFORM" in linux-x64|linux-arm64|darwin-arm64) ;; *) fail "unsupported --platform $PLATFORM" ;; esac
[ -n "$RELEASE_BASE_URL" ] || RELEASE_BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}"

command -v curl >/dev/null 2>&1 || fail "curl is required"
if command -v sha256sum >/dev/null 2>&1; then sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else fail "sha256sum or shasum is required"; fi

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
NAME="0security-${PLATFORM}"
mkdir -p "$OUT"
[ -z "$(ls -A "$OUT")" ] || fail "$OUT is not empty; choose a new folder"

fetch() { curl --fail --location --silent --show-error --retry 3 "${RELEASE_BASE_URL}/$1" -o "$OUT/$1"; }

printf '%s\n' "Downloading ${NAME} and checksums..." >&2
fetch "$NAME"
fetch checksums.txt

expected="$(awk -v asset="$NAME" '$2 == asset || $2 == ("*" asset) { print $1; exit }' "$OUT/checksums.txt")"
[ -n "$expected" ] || fail "checksums.txt has no entry for ${NAME}"
[ "$expected" = "$(sha256_file "$OUT/$NAME")" ] || fail "checksum mismatch for ${NAME}"
printf '%s\n' "Checksum verified." >&2

IDENTITY="^https://github\\.com/${REPO}/\\.github/workflows/release\\.yml@refs/(tags/v[0-9].*|heads/main)\$"
ISSUER="https://token.actions.githubusercontent.com"
if [ "$ALLOW_UNSIGNED" = 1 ]; then
  printf '%s\n' "Skipping the signature check (--allow-unsigned)." >&2
else
  command -v cosign >/dev/null 2>&1 || fail "cosign is required to verify the signature (or pass --allow-unsigned)"
  fetch checksums.txt.sigstore.json || fail "this release has no signature bundle (or pass --allow-unsigned)"
  cosign verify-blob --bundle "$OUT/checksums.txt.sigstore.json" \
    --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$OUT/checksums.txt" >/dev/null 2>&1 \
    || fail "the checksums.txt signature did not verify"
  printf '%s\n' "Signature verified." >&2
fi

if [ "$WITH_IMAGE" = 1 ]; then
  command -v docker >/dev/null 2>&1 || fail "docker is required for --image"
  IMAGE="${IMAGE_NAME}:v${VERSION}"
  if [ "$ALLOW_UNSIGNED" != 1 ]; then
    cosign verify "$IMAGE" \
      --certificate-identity-regexp "^https://github\\.com/${REPO}/\\.github/workflows/docker-publish\\.yml@refs/heads/main\$" \
      --certificate-oidc-issuer "$ISSUER" >/dev/null 2>&1 || fail "the image signature did not verify"
    printf '%s\n' "Image signature verified." >&2
  fi
  docker pull --platform linux/amd64 "$IMAGE" >&2
  docker save "$IMAGE" | gzip > "$OUT/image.tar.gz"
  printf '%s\n' "$IMAGE" > "$OUT/image.ref"
fi

if [ "$WITH_CHART" = 1 ]; then
  [ -d "$ROOT/deploy/helm/zero" ] || fail "deploy/helm/zero not found next to this script"
  tar czf "$OUT/zero-chart.tgz" -C "$ROOT/deploy/helm" zero
fi

cp "$HERE/install-bundle.sh" "$OUT/install-bundle.sh"
printf '%s\n' "$VERSION" > "$OUT/VERSION"
printf '%s\n' "$NAME" > "$OUT/BINARY"

# One manifest over every file except itself. install-bundle.sh checks it before it installs.
# shellcheck disable=SC2094  # MANIFEST.sha256 is skipped inside the loop
( cd "$OUT" && for f in *; do
    [ "$f" = MANIFEST.sha256 ] && continue
    printf '%s  %s\n' "$(sha256_file "$f")" "$f"
  done > MANIFEST.sha256 )

printf '%s\n' "Bundle ready in $OUT. Archive it, record the SHA-256 of the archive, and carry it in." >&2
