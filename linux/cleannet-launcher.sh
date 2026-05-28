#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

cd "$SCRIPT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 was not found. Install Python 3.10+ and try again." >&2
    exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating CleanNet virtual environment..."
    if ! python3 -m venv "$VENV_DIR"; then
        echo "Could not create a virtual environment." >&2
        echo "On Debian/Ubuntu, install it with: sudo apt install python3-venv" >&2
        exit 1
    fi
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip >/dev/null
python -m pip install -r "$SCRIPT_DIR/requirements.txt" --quiet

echo "Launching CleanNet..."
exec python -m cleannet "$@"
