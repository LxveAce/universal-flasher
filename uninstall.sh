#!/usr/bin/env bash
# Remove the launchers + menu entry (leaves the repo folder and .venv in place).
set -euo pipefail
APP="headless-marauder"
rm -f "$HOME/.local/bin/$APP" "$HOME/.local/bin/${APP}-tui" "$HOME/.local/bin/${APP}-web"
rm -f "$HOME/.local/share/applications/$APP.desktop"
rm -f "$HOME/.local/share/icons/$APP.svg"
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
echo "[✓] Removed launchers + menu entry."
echo "    The project folder and its .venv are untouched — delete them manually to fully remove."
