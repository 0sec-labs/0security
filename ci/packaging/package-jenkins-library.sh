#!/bin/sh
# Export a standard Jenkins Shared Library without maintaining copied shell resources.
# Usage: sh ci/packaging/package-jenkins-library.sh /absolute/new-output-directory
set -eu
root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
[ "$#" -eq 1 ] || { echo 'usage: package-jenkins-library.sh NEW_OUTPUT_DIRECTORY' >&2; exit 2; }
[ ! -e "$1" ] && [ ! -e "$1.tar.gz" ] && [ ! -e "$1.tar.gz.sha256" ] || { echo 'output directory already exists; choose a new directory' >&2; exit 2; }
mkdir -p "$1/vars" "$1/resources/0security"
cp "$root/ci/jenkins-library/vars/zeroSecurity.groovy" "$1/vars/"
cp "$root/install.sh" "$1/resources/0security/install.sh"
cp "$root/ci/scripts/0-ci-scan.sh" "$root/ci/scripts/0-ci-publish.sh" "$1/resources/0security/"
# package.json is trusted source, not evaluated as code.
version="$(sed -n 's/^  "version": "\([0-9][0-9.]*\)",$/\1/p' "$root/packages/cli/package.json")"
printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo 'invalid CLI version' >&2; exit 2; }
printf '%s\n' "$version" > "$1/resources/0security/VERSION"
printf '%s\n' 'Exported Jenkins Shared Library. Configure as a trusted, pinned SCM library; see https://docs.0.security/ci/.' > "$1/README.md"

tar -czf "$1.tar.gz" -C "$1" .
artifact_dir="$(CDPATH= cd -- "$(dirname -- "$1.tar.gz")" && pwd)"
artifact_name="$(basename -- "$1.tar.gz")"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$artifact_dir" && sha256sum "$artifact_name") > "$1.tar.gz.sha256"
else
  (cd "$artifact_dir" && shasum -a 256 "$artifact_name") > "$1.tar.gz.sha256"
fi
