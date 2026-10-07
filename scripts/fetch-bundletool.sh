#!/usr/bin/env bash
set -euo pipefail

VERSION="1.18.3"
SHA256="a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"
DESTINATION="${1:-build/tools/bundletool-all-${VERSION}.jar}"
URL="https://github.com/google/bundletool/releases/download/${VERSION}/bundletool-all-${VERSION}.jar"

mkdir -p "$(dirname "$DESTINATION")"

if [[ -f "$DESTINATION" ]]; then
  current="$(sha256sum "$DESTINATION" | awk '{print $1}')"
  if [[ "$current" == "$SHA256" ]]; then
    printf '%s\n' "$DESTINATION"
    exit 0
  fi
  rm -f "$DESTINATION"
fi

curl --fail --location --proto '=https' --tlsv1.2 --output "$DESTINATION.tmp" "$URL"
actual="$(sha256sum "$DESTINATION.tmp" | awk '{print $1}')"
if [[ "$actual" != "$SHA256" ]]; then
  rm -f "$DESTINATION.tmp"
  echo "bundletool SHA-256 mismatch: expected $SHA256, got $actual" >&2
  exit 1
fi

mv "$DESTINATION.tmp" "$DESTINATION"
printf '%s\n' "$DESTINATION"
