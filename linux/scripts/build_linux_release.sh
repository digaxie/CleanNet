#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
VERSION="$(tr -d '\357\273\277[:space:]' < "$ROOT/VERSION")"
DIST="$ROOT/dist"
STAGE="$DIST/cleannet-linux-$VERSION"
ARCHIVE="$DIST/cleannet-linux-$VERSION.tar.gz"

cd "$ROOT"
./run_tests.sh

rm -rf "$STAGE" "$ARCHIVE"
mkdir -p "$STAGE" "$DIST"

cp -a cleannet assets scripts "$STAGE/"
cp -a cleannet-launcher.sh run_tests.sh requirements.txt README.md PRIVACY.md SECURITY.md SECURITY_HARDENING.md LICENSE VERSION CHANGELOG.md RELEASE.md "$STAGE/"

find "$STAGE" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "$STAGE" -type f \( -name "*.pyc" -o -name "*.pyo" -o -name "*.ps1" -o -name "*.bat" -o -name "*.iss" -o -name "*.exe" -o -name "CleanNet.spec" \) -delete

tar -czf "$ARCHIVE" -C "$DIST" "cleannet-linux-$VERSION"
sha256sum "$ARCHIVE" > "$DIST/SHA256SUMS.txt"
rm -rf "$STAGE"

echo "[OK] Linux release: $ARCHIVE"
