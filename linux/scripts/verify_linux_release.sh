#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
VERSION="$(tr -d '\357\273\277[:space:]' < "$ROOT/VERSION")"
ARCHIVE="$ROOT/dist/cleannet-linux-$VERSION.tar.gz"

cd "$ROOT"

python3 -m compileall -q cleannet tests
python3 -m unittest discover -s tests -v
bash -n cleannet-launcher.sh run_tests.sh scripts/build_linux_release.sh scripts/verify_linux_release.sh

if grep -r "windows_integration" cleannet/ tests/; then
    echo "FAIL: Windows import found" >&2
    exit 1
else
    echo "OK: no windows_integration imports"
fi

scripts/build_linux_release.sh

if [ ! -f "$ARCHIVE" ]; then
    echo "FAIL: missing archive $ARCHIVE" >&2
    exit 1
fi

entries="$(tar -tzf "$ARCHIVE")"
for required in cleannet assets cleannet-launcher.sh run_tests.sh requirements.txt README.md VERSION; do
    if ! grep -q "cleannet-linux-$VERSION/$required" <<<"$entries"; then
        echo "FAIL: missing tar entry $required" >&2
        exit 1
    fi
done

if grep -E '(__pycache__|\.pyc$|\.pyo$|\.venv/|/build/|\.ps1$|\.bat$|\.iss$|\.exe$|CleanNet\.spec|windows_integration\.py|test_windows_integration\.py|bypass\.log|proxy_state\.json|linux_proxy_state\.json|strategy_cache\.json|ai_strategy\.json|stats\.json)' <<<"$entries"; then
    echo "FAIL: archive contains forbidden runtime or Windows files" >&2
    exit 1
fi

echo "[OK] Linux release verification passed"
