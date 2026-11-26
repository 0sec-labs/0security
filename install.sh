#!/usr/bin/env sh
# Install the latest verified standalone binary for this host as `0security`, with `0` as a symlink alias.
set -eu

REPO="0sec-labs/0security"
RELEASE_BASE_URL="${RELEASE_BASE_URL:-https://github.com/${REPO}/releases/latest/download}"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.0/bin}"

fail() {
  printf '%s\n' "0 installer: $*" >&2
  exit 1
}

case "$(uname -s)" in
  Darwin)
    case "$(uname -m)" in
      arm64) ASSET="0-darwin-arm64" ;;
      *) fail "unsupported macOS architecture; download a matching release asset manually" ;;
    esac
    ;;
  Linux)
    case "$(uname -m)" in
      x86_64|amd64) ASSET="0-linux-x64" ;;
      aarch64|arm64) ASSET="0-linux-arm64" ;;
      *) fail "unsupported Linux architecture; download a matching release asset manually" ;;
    esac
    ;;
  *)
    fail "unsupported operating system; download the matching GitHub Release asset manually"
    ;;
esac

# Releases publish each binary as `0security-<platform>` and, so installed older
# copies can still update, as `0-<platform>`. Prefer the new name and fall back to
# the old one when a release or mirror has only that.
NEW_ASSET="0security-${ASSET#0-}"
# Foxguard ships beside `0` under the same platform suffix.
FG_ASSET="foxguard-${ASSET#0-}"

command -v curl >/dev/null 2>&1 || fail "curl is required"
if command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  fail "sha256sum or shasum is required to verify the download"
fi

mkdir -p "$INSTALL_DIR"
manifest="$(mktemp "${TMPDIR:-/tmp}/0-checksums.XXXXXX")"
binary="$(mktemp "${INSTALL_DIR}/.${ASSET}.XXXXXX")"
fg_binary=""
alias_link=""
cleanup() {
  rm -f "$manifest" "$binary" "$fg_binary" "$alias_link"
}
trap cleanup EXIT HUP INT TERM

download() {
  task_download_url="$1"
  task_download_path="$2"
  shift 2
  if [ -t 2 ] && [ "${TERM:-}" != "dumb" ]; then
    curl --fail --location --progress-bar --show-error --retry 3 --retry-delay 1 "$@" "$task_download_url" -o "$task_download_path"
  else
    curl --fail --location --silent --show-error --retry 3 --retry-delay 1 "$@" "$task_download_url" -o "$task_download_path"
  fi
}
printf '%s\n' "Fetching release checksums…" >&2
curl --fail --location --silent --show-error --retry 3 --retry-delay 1 \
  "${RELEASE_BASE_URL}/checksums.txt" -o "$manifest"

# Provenance: checksums.txt is attested at release time (GitHub build-provenance
# attestation). When an authenticated `gh` is available, verify that attestation
# so the checksums come from this repository's release workflow and not only from
# whoever served the download. INSTALL_ATTESTATION=auto (default) verifies when
# possible and otherwise falls back to the checksums.txt integrity check below;
# `require` fails if it cannot verify; `0` skips (offline mirrors, air gaps).
INSTALL_ATTESTATION="${INSTALL_ATTESTATION:-auto}"
case "$INSTALL_ATTESTATION" in auto|require|0) ;; *) fail "INSTALL_ATTESTATION must be auto, require or 0" ;; esac
# Usage: attestation_verify <file> <owner/repo>; returns 0 only on a verified attestation.
attestation_verify() {
  gh attestation verify "$1" --repo "$2" >/dev/null 2>&1
}
# gh older than 2.49 has no `attestation` subcommand; treat it like a missing gh.
attestation_usable() {
  command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1 \
    && gh attestation --help >/dev/null 2>&1
}
if [ "$INSTALL_ATTESTATION" = "0" ]; then
  printf '%s\n' "Skipping attestation check (INSTALL_ATTESTATION=0); relying on checksums.txt only." >&2
elif attestation_usable; then
  printf '%s\n' "Verifying checksums.txt attestation with gh…" >&2
  if attestation_output="$(gh attestation verify "$manifest" --repo "$REPO" 2>&1)"; then
    printf '%s\n' "checksums.txt attestation verified for ${REPO}." >&2
  else
    printf '%s\n' "$attestation_output" >&2
    fail "could not verify the checksums.txt attestation for ${REPO}; refusing to install (set INSTALL_ATTESTATION=0 to skip when offline or using a mirror)"
  fi
elif [ "$INSTALL_ATTESTATION" = "require" ]; then
  fail "INSTALL_ATTESTATION=require needs an authenticated GitHub CLI (gh auth login)"
else
  printf '%s\n' "Note: gh is not installed, not logged in, or too old for \`gh attestation\` (needs 2.49+), so the release attestation was not verified; falling back to the checksums.txt integrity check. See https://docs.0.security/self-hosting/#verify-a-release to verify manually." >&2
fi

# Signature: releases also publish checksums.txt.sigstore.json, a keyless Sigstore
# bundle made by this repository's release workflow. When `cosign` is installed,
# verify it so the checksums come from that workflow without needing a GitHub
# login. INSTALL_SIGNATURE=auto (default) verifies when cosign and a bundle exist
# and fails on a bad signature; `require` also fails when either is missing; `0`
# skips (offline mirrors, air gaps).
INSTALL_SIGNATURE="${INSTALL_SIGNATURE:-auto}"
case "$INSTALL_SIGNATURE" in auto|require|0) ;; *) fail "INSTALL_SIGNATURE must be auto, require or 0" ;; esac
SIGNATURE_IDENTITY="^https://github\.com/${REPO}/\.github/workflows/release\.yml@refs/(tags/v[0-9].*|heads/main)\$"
SIGNATURE_ISSUER="https://token.actions.githubusercontent.com"
signature_bundle="$(mktemp "${TMPDIR:-/tmp}/0-checksums-sig.XXXXXX")"
trap 'rm -f "$manifest" "$binary" "$fg_binary" "$alias_link" "$signature_bundle"' EXIT HUP INT TERM
if [ "$INSTALL_SIGNATURE" = "0" ]; then
  printf '%s\n' "Skipping signature check (INSTALL_SIGNATURE=0)." >&2
elif ! command -v cosign >/dev/null 2>&1; then
  [ "$INSTALL_SIGNATURE" != "require" ] || fail "INSTALL_SIGNATURE=require needs cosign (https://docs.sigstore.dev/cosign/system_config/installation/)"
  printf '%s\n' "Note: cosign is not installed, so the release signature was not verified. Install cosign to verify it." >&2
elif ! curl --fail --location --silent --show-error --retry 3 --retry-delay 1 \
    "${RELEASE_BASE_URL}/checksums.txt.sigstore.json" -o "$signature_bundle" 2>/dev/null; then
  [ "$INSTALL_SIGNATURE" != "require" ] || fail "this release has no checksums.txt.sigstore.json signature bundle"
  printf '%s\n' "Note: this release has no signature bundle, so the signature was not verified." >&2
else
  printf '%s\n' "Verifying checksums.txt signature with cosign…" >&2
  if signature_output="$(cosign verify-blob --bundle "$signature_bundle" \
      --certificate-identity-regexp "$SIGNATURE_IDENTITY" \
      --certificate-oidc-issuer "$SIGNATURE_ISSUER" "$manifest" 2>&1)"; then
    printf '%s\n' "checksums.txt signature verified for ${REPO}." >&2
  else
    printf '%s\n' "$signature_output" >&2
    fail "could not verify the checksums.txt signature for ${REPO}; refusing to install (set INSTALL_SIGNATURE=0 to skip when offline or using a mirror)"
  fi
fi

printf '%s\n' "Downloading ${NEW_ASSET}…" >&2
if download "${RELEASE_BASE_URL}/${NEW_ASSET}" "$binary" 2>/dev/null; then
  ASSET="$NEW_ASSET"
else
  printf '%s\n' "${NEW_ASSET} is not available in this release; downloading ${ASSET}…" >&2
  download "${RELEASE_BASE_URL}/${ASSET}" "$binary"
fi

printf '%s\n' "Verifying ${ASSET}…" >&2
expected="$(awk -v asset="$ASSET" '$2 == asset || $2 == ("*" asset) { print $1; exit }' "$manifest")"
[ -n "$expected" ] || fail "checksums.txt has no entry for ${ASSET}"
actual="$(sha256_file "$binary")"
[ "$expected" = "$actual" ] || fail "checksum mismatch for ${ASSET}; refusing to install"

printf '%s\n' "Installing 0security…" >&2
chmod 755 "$binary"
mv -f "$binary" "${INSTALL_DIR}/0security"
binary=""
# `0` is a relative symlink to `0security`. The link is built under a temporary
# name and renamed over `0`, so an older plain `0` file is replaced in one step
# and the folder always holds a working `0`.
alias_link="${INSTALL_DIR}/.0.link.$$"
rm -f "$alias_link"
if ln -sf 0security "$alias_link" && mv -f "$alias_link" "${INSTALL_DIR}/0"; then
  alias_link=""
  printf '%s\n' "Installed verified 0security to ${INSTALL_DIR}/0security (also available as ${INSTALL_DIR}/0)" >&2
else
  printf '%s\n' "0 installer: could not link ${INSTALL_DIR}/0 to 0security; the 0 command was left as it was" >&2
  printf '%s\n' "Installed verified 0security to ${INSTALL_DIR}/0security" >&2
fi

# Install the default static analyzer (Foxguard) next to `0`, so source reviews
# do not require Node/npm. It is built from this repository's crates/foxguard by
# the same release workflow as `0`, published as foxguard-<platform>, and listed
# in the same checksums.txt, so the attestation and signature checks above cover
# it. INSTALL_FOXGUARD=0 opts out for pre-provisioned hosts. A release or mirror
# that has no foxguard asset leaves 0security installed without it.
if [ "${INSTALL_FOXGUARD:-1}" != "0" ]; then
  fg_expected="$(awk -v asset="$FG_ASSET" '$2 == asset || $2 == ("*" asset) { print $1; exit }' "$manifest")"
  if [ -z "$fg_expected" ]; then
    printf '%s\n' "0 installer: this release lists no ${FG_ASSET}; keeping 0security installed without Foxguard" >&2
  else
    fg_binary="$(mktemp "${INSTALL_DIR}/.${FG_ASSET}.XXXXXX")"
    printf '%s\n' "Downloading ${FG_ASSET}…" >&2
    if download "${RELEASE_BASE_URL}/${FG_ASSET}" "$fg_binary" \
      --connect-timeout 10 --max-time 60 --retry 1 --retry-delay 1 --retry-max-time 65; then
      if [ "$fg_expected" = "$(sha256_file "$fg_binary")" ]; then
        chmod 755 "$fg_binary"
        mv -f "$fg_binary" "${INSTALL_DIR}/foxguard"
        fg_binary=""
        printf '%s\n' "Installed verified Foxguard to ${INSTALL_DIR}/foxguard" >&2
      else
        printf '%s\n' "0 installer: ${FG_ASSET} checksum mismatch; keeping 0security installed without Foxguard" >&2
      fi
    else
      printf '%s\n' "0 installer: ${FG_ASSET} download failed; keeping 0security installed without Foxguard" >&2
    fi
  fi
fi

# A piped installer cannot change its parent shell. Persist the path for future
# shells and print the exact command for the terminal that launched it.
quoted_dir="$(printf '%s' "$INSTALL_DIR" | sed "s/'/'\\\\''/g")"
path_line="export PATH='${quoted_dir}':\"\$PATH\""
add_path() {
  profile="$1"
  if ! grep -Fqx "$path_line" "$profile" 2>/dev/null; then
    if printf '\n# 0.security CLI\n%s\n' "$path_line" >> "$profile"; then
      printf '%s\n' "Added 0security to PATH in ${profile}" >&2
    else
      printf '%s\n' "Could not update ${profile}; add 0security to PATH manually" >&2
    fi
  fi
}
add_path "${HOME}/.profile"
case "${SHELL:-/bin/bash}" in
  */zsh) add_path "${ZDOTDIR:-${HOME}}/.zshrc" ;;
  */bash)
    add_path "${HOME}/.bashrc"
    if [ -f "${HOME}/.bash_profile" ]; then add_path "${HOME}/.bash_profile"
    elif [ -f "${HOME}/.bash_login" ]; then add_path "${HOME}/.bash_login"
    fi
    ;;
esac
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) printf '\n%s\n%s\n' "To use 0security in this terminal, run:" "$path_line" >&2 ;;
esac
