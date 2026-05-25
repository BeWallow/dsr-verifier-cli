#!/usr/bin/env bash
# download/update.sh — Substitutes real version + SHA-256 values into index.html.
#
# Called by the release CI pipeline after SHA256SUMS is generated:
#
#   bash download/update.sh v1.0.1 dist/SHA256SUMS
#
# The resulting index.html is then deployed to verify.deja.dev/download.

set -euo pipefail

VERSION="${1:?usage: $0 <version> <SHA256SUMS>}"
SHA256SUMS="${2:?usage: $0 <version> <SHA256SUMS>}"

# Validate the checksum file exists and has the expected entries.
for suffix in darwin-arm64.tar.gz darwin-amd64.tar.gz linux-amd64.tar.gz linux-arm64.tar.gz windows-amd64.zip; do
  if ! grep -q "${suffix}" "${SHA256SUMS}"; then
    echo "ERROR: ${SHA256SUMS} does not contain an entry for ${suffix}" >&2
    exit 1
  fi
done

SHA256_DARWIN_ARM64=$(grep "darwin-arm64.tar.gz"  "${SHA256SUMS}" | awk '{print $1}')
SHA256_DARWIN_AMD64=$(grep "darwin-amd64.tar.gz"  "${SHA256SUMS}" | awk '{print $1}')
SHA256_LINUX_AMD64=$( grep "linux-amd64.tar.gz"   "${SHA256SUMS}" | awk '{print $1}')
SHA256_LINUX_ARM64=$( grep "linux-arm64.tar.gz"   "${SHA256SUMS}" | awk '{print $1}')
SHA256_WINDOWS_AMD64=$(grep "windows-amd64.zip"   "${SHA256SUMS}" | awk '{print $1}')

SEMVER="${VERSION#v}"      # strip leading 'v' for display
DIR="$(cd "$(dirname "$0")" && pwd)"

# Work on a copy to avoid partial writes.
TMPFILE=$(mktemp)
cp "${DIR}/index.html" "${TMPFILE}"

sed -i \
  -e "s|v1\.0\.0|${VERSION}|g" \
  -e "s|1\.0\.0|${SEMVER}|g" \
  -e "s|REPLACE_SHA256_DARWIN_ARM64|${SHA256_DARWIN_ARM64}|g" \
  -e "s|REPLACE_SHA256_DARWIN_AMD64|${SHA256_DARWIN_AMD64}|g" \
  -e "s|REPLACE_SHA256_LINUX_AMD64|${SHA256_LINUX_AMD64}|g" \
  -e "s|REPLACE_SHA256_LINUX_ARM64|${SHA256_LINUX_ARM64}|g" \
  -e "s|REPLACE_SHA256_WINDOWS_AMD64|${SHA256_WINDOWS_AMD64}|g" \
  -e "s|Last updated for version: .*|Last updated for version: ${VERSION}|" \
  "${TMPFILE}"

cp "${TMPFILE}" "${DIR}/index.html"
rm "${TMPFILE}"

echo "download/index.html updated for ${VERSION}"
