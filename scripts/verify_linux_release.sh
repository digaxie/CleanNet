#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
VERSION="$(tr -d '\357\273\277[:space:]' < "$ROOT/VERSION")"
ARCHIVE="$ROOT/dist/cleannet-linux-$VERSION.tar.gz"

cd "$ROOT"

python3 -m compileall -q cleannet tests
python3 -m unittest discover -s tests -v
bash -n cleannet-launcher.sh run_tests.sh scripts/build_linux_release.sh scripts/verify_linux_release.sh

scripts/build_linux_release.sh

if [ ! -f "$ARCHIVE" ]; then
    echo "FAIL: missing archive $ARCHIVE" >&2
    exit 1
fi

entries="$(tar -tzf "$ARCHIVE")"
for required in cleannet/__main__.py cleannet/linux_integration.py assets/dashboard.html cleannet-launcher.sh run_tests.sh requirements.txt README.md VERSION; do
    if ! grep -q "cleannet-linux-$VERSION/$required" <<<"$entries"; then
        echo "FAIL: missing tar entry $required" >&2
        exit 1
    fi
done

if grep -E '(__pycache__|\.pyc$|\.pyo$|\.venv/|/build/|\.ps1$|\.bat$|\.iss$|\.exe$|CleanNet\.spec|windows_integration\.py|network_monitor_windows\.py|tray_windows\.py|bypass\.log|proxy_state\.json|strategy_cache\.json|ai_strategy\.json|stats\.json)' <<<"$entries"; then
    echo "FAIL: archive contains forbidden runtime or Windows files" >&2
    exit 1
fi

# The archive has no Windows modules: make sure the package still imports and builds
# its runtime from the extracted tree alone.
CHECK_DIR="$(mktemp -d)"
trap 'rm -rf "$CHECK_DIR"' EXIT
tar -xzf "$ARCHIVE" -C "$CHECK_DIR"
(
    cd "$CHECK_DIR/cleannet-linux-$VERSION"
    CLEANNET_DATA_DIR="$CHECK_DIR/data" DPI_BYPASS_NO_DISK_LOG=1 python3 - <<'PY'
from cleannet.bootstrap import create_app
app = create_app("cleannet/__main__.py", install_handlers=False)
assert "const PLATFORM='linux';" in app.runtime.dashboard_html
print("OK: extracted archive builds the Linux runtime")
PY
)

echo "[OK] Linux release verification passed"
