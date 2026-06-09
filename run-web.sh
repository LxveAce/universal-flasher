#!/usr/bin/env bash
# Launch the browser UI at http://localhost:5000. Pass-through args: --port /dev/ttyUSB0, --mock, etc.
cd "$(dirname "$0")" || exit 1
[ -d .venv ] && source .venv/bin/activate
exec python3 web/app.py "$@"
