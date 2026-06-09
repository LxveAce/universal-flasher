#!/usr/bin/env bash
# Launch the native desktop GUI. Pass-through args: --port /dev/ttyUSB0, --mock, etc.
cd "$(dirname "$0")" || exit 1
[ -d .venv ] && source .venv/bin/activate
exec python3 gui/app.py "$@"
