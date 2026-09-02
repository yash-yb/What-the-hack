#!/usr/bin/env bash
# Run the Python test suites from the repository root.
# Usage: ./deployment/scripts/run_tests.sh [pytest args]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PY="backend/.venv/bin/python"
[ -x "$PY" ] || PY="python3"
"$PY" -m pip install -q pytest jsonschema pandas >/dev/null 2>&1 || true
"$PY" -m pytest "$@"
