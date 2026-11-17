#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

python3 -m compileall -q cleannet tests
python3 -m unittest discover -s tests -v
