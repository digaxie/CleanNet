#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
VERSION="$(tr -d '\357\273\277[:space:]' < "$ROOT/VERSION")"
DIST="$ROOT/dist"
STAGE="$DIST/cleannet-linux-$VERSION"
ARCHIVE="$DIST/cleannet-linux-$VERSION.tar.gz"

# Modules only the Windows build uses; the platform facades never import them on Linux.
WINDOWS_ONLY_MODULES=(windows_integration.py network_monitor_windows.py tray_windows.py)

cd "$ROOT"
./run_tests.sh

rm -rf "$STAGE" "$ARCHIVE"
mkdir -p "$STAGE" "$DIST"

cp -a cleannet assets scripts "$STAGE/"
cp -a cleannet-launcher.sh run_tests.sh requirements.txt LICENSE VERSION CHANGELOG.md "$STAGE/"
cp -a docs/LINUX.md "$STAGE/README.md"

for module in "${WINDOWS_ONLY_MODULES[@]}"; do
    rm -f "$STAGE/cleannet/$module"
done
find "$STAGE" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "$STAGE" -type f \( -name "*.pyc" -o -name "*.pyo" -o -name "*.ps1" -o -name "*.bat" -o -name "*.iss" -o -name "*.exe" -o -name "*.ico" -o -name "CleanNet.spec" \) -delete

tar -czf "$ARCHIVE" -C "$DIST" "cleannet-linux-$VERSION"
# Relative file name, so users can run `sha256sum -c SHA256SUMS.txt` next to the download.
(cd "$DIST" && sha256sum "$(basename "$ARCHIVE")" > SHA256SUMS.txt)
rm -rf "$STAGE"

echo "[OK] Linux release: $ARCHIVE"
