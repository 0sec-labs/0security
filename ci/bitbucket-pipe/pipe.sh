#!/bin/sh
# The pipe is installed from trusted source in its image; no script is loaded from the clone.
set -eu
fail() { printf '%s\n' "0security pipe: $*" >&2; exit 2; }
trusted="$(CDPATH= cd -- "$(dirname -- "$0")/../scripts" && pwd)"
PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"
export PATH
mode="${MODE:-scan}"
clone="${BITBUCKET_CLONE_DIR:-$(pwd)}"
[ -d "$clone" ] || fail "BITBUCKET_CLONE_DIR is not a directory"
clone="$(CDPATH= cd -- "$clone" && pwd)"
case "${ZEROCI_OUT_DIR:-.zero-ci}" in /*|*..*|-*|*[!A-Za-z0-9._/-]*) fail "ZEROCI_OUT_DIR must be a relative folder inside the clone" ;; esac
out="$clone/${ZEROCI_OUT_DIR:-.zero-ci}"
# Reject symlink directory components as well as symlink files.
walk="$clone"
saved_ifs="$IFS"; IFS=/; set -f
for component in ${ZEROCI_OUT_DIR:-.zero-ci}; do
  walk="$walk/$component"
  [ ! -L "$walk" ] || fail "artifact directory must not contain symbolic links"
done
set +f; IFS="$saved_ifs"
case "$mode" in
  scan)
    [ -z "${BITBUCKET_TOKEN:-}" ] || fail "Do not pass BITBUCKET_TOKEN to the scan step; keep it in a separate publish deployment"
    cd "$clone"
    # The model sees only the scan's credentials and settings, never publisher credentials.
    # Model provider settings are passed when set: API keys, the provider pin and model, and the AWS settings Amazon Bedrock reads.
    set --
    for name in OPENAI_API_KEY OPENAI_BASE_URL ANTHROPIC_API_KEY GOOGLE_API_KEY ZERO_SELECTED_PROVIDER ZERO_MODEL ZERO_BEDROCK_MODEL BEDROCK_BASE_URL \
      AWS_REGION AWS_DEFAULT_REGION AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_BEARER_TOKEN_BEDROCK AWS_ROLE_ARN AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_SESSION_NAME; do
      eval "value=\"\${$name:-}\""
      [ -z "$value" ] || set -- "$@" "$name=$value"
    done
    exec env -i PATH="$PATH" HOME="${HOME:-/tmp}" \
      GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$clone" \
      SSL_CERT_FILE="${SSL_CERT_FILE:-}" SSL_CERT_DIR="${SSL_CERT_DIR:-}" "$@" \
      ZERO_NO_EGRESS="${ZERO_NO_EGRESS:-}" ZERO_ENTERPRISE="${ZERO_ENTERPRISE:-}" DO_NOT_TRACK=1 \
      ZEROCI_BASE_BRANCH="${ZEROCI_BASE_BRANCH:-${BITBUCKET_PR_DESTINATION_BRANCH:-}}" \
      ZEROCI_COMMIT="${ZEROCI_COMMIT:-${BITBUCKET_COMMIT:-}}" ZEROCI_OUT_DIR="$out" \
      ZEROCI_PREPASS_ONLY="${ZEROCI_PREPASS_ONLY:-0}" ZEROCI_TARGET="${ZEROCI_TARGET:-.}" ZEROCI_FAIL_ON="${ZEROCI_FAIL_ON:-high}" ZEROCI_BUDGET="${ZEROCI_BUDGET:-3}" \
      sh "$trusted/0-ci-scan.sh"
    ;;
  publish)
    isolated="$(mktemp -d)"
    trap 'rm -rf "$isolated"' EXIT HUP INT TERM
    # No checkout scripts/configuration, symlinks or unexpected artifact names reach the publisher.
    for name in scan.json scan.exit scan.commit; do
      [ -f "$out/$name" ] && [ ! -L "$out/$name" ] || fail "missing or symbolic-link artifact: $name"
      [ "$(wc -c < "$out/$name")" -le 20971520 ] || fail "$name exceeds 20 MB"
      cp "$out/$name" "$isolated/$name"
    done
    cd "$isolated"
    code=0
    env -i PATH="$PATH" HOME="$isolated" DO_NOT_TRACK=1 \
      SSL_CERT_FILE="${SSL_CERT_FILE:-}" SSL_CERT_DIR="${SSL_CERT_DIR:-}" \
      BITBUCKET_TOKEN="${BITBUCKET_TOKEN:-}" BITBUCKET_URL="${BITBUCKET_URL:-}" \
      ZERO_NO_EGRESS="${ZERO_NO_EGRESS:-}" ZERO_ENTERPRISE="${ZERO_ENTERPRISE:-}" ZERO_BITBUCKET_URL="${ZERO_BITBUCKET_URL:-}" \
      BITBUCKET_WORKSPACE="${BITBUCKET_WORKSPACE:-}" BITBUCKET_REPO_SLUG="${BITBUCKET_REPO_SLUG:-}" \
      ZEROCI_OUT_DIR="$isolated" ZEROCI_UPLOAD_TO="${ZEROCI_UPLOAD_TO:-bitbucket-cloud}" ZEROCI_REPO="${ZEROCI_REPO:-}" \
      sh "$trusted/0-ci-publish.sh" || code=$?
    exit "$code"
    ;;
  *) fail "MODE must be scan or publish" ;;
esac
