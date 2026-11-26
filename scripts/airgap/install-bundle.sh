#!/usr/bin/env sh
# Install 0 from an offline bundle. Needs no network: it checks the bundle against its
# MANIFEST.sha256, installs the binary and loads the container image if one is included.
#
#   sh install-bundle.sh [--no-image]
#
# Compare the SHA-256 of the whole archive with the value you recorded when you built it.
# The manifest only proves the files match each other.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.0/bin}"
LOAD_IMAGE=1

fail() { printf '%s\n' "install-bundle: $*" >&2; exit 1; }
for arg in "$@"; do
  case "$arg" in
    --no-image) LOAD_IMAGE=0 ;;
    *) fail "unknown option $arg" ;;
  esac
done

if command -v sha256sum >/dev/null 2>&1; then sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else fail "sha256sum or shasum is required"; fi

[ -f "$HERE/MANIFEST.sha256" ] || fail "MANIFEST.sha256 is missing"
[ -f "$HERE/BINARY" ] || fail "BINARY is missing"
BINARY="$(cat "$HERE/BINARY")"
case "$BINARY" in 0security-*) ;; *) fail "BINARY holds an unexpected name" ;; esac

printf '%s\n' "Checking the bundle..." >&2
listed=0
while read -r digest name; do
  [ -n "$name" ] || continue
  case "$name" in */*|..*) fail "manifest names a path outside the bundle: $name" ;; esac
  [ -f "$HERE/$name" ] || fail "missing file $name"
  [ "$digest" = "$(sha256_file "$HERE/$name")" ] || fail "checksum mismatch for $name; refusing to install"
  listed=$((listed + 1))
done < "$HERE/MANIFEST.sha256"
[ "$listed" -gt 0 ] || fail "the manifest is empty"
for f in "$HERE"/*; do
  base="$(basename "$f")"
  [ "$base" = "MANIFEST.sha256" ] && continue
  grep -q "  ${base}\$" "$HERE/MANIFEST.sha256" || fail "$base is not in the manifest"
done
printf '%s\n' "All ${listed} files match the manifest." >&2

mkdir -p "$INSTALL_DIR"
tmp="$(mktemp "${INSTALL_DIR}/.${BINARY}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT HUP INT TERM
cp "$HERE/$BINARY" "$tmp"
chmod 755 "$tmp"
mv -f "$tmp" "${INSTALL_DIR}/0security"
ln -sf 0security "${INSTALL_DIR}/0"
printf '%s\n' "Installed ${INSTALL_DIR}/0security (and the 0 alias)." >&2

if [ "$LOAD_IMAGE" = 1 ] && [ -f "$HERE/image.tar.gz" ]; then
  runtime=""
  for candidate in docker podman; do command -v "$candidate" >/dev/null 2>&1 && { runtime="$candidate"; break; }; done
  if [ -n "$runtime" ]; then
    gzip -dc "$HERE/image.tar.gz" | "$runtime" load >&2
    printf '%s\n' "Loaded the image $(cat "$HERE/image.ref" 2>/dev/null || echo "") with $runtime." >&2
  else
    printf '%s\n' "No docker or podman found. Load image.tar.gz into your registry or runtime yourself." >&2
  fi
fi

printf '%s\n' "Next: export ZERO_ENTERPRISE=1 DO_NOT_TRACK=1 and point 0 at your in-network model endpoint." >&2
