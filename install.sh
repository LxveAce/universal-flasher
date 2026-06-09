#!/usr/bin/env bash
#
# Install Headless Marauder as a real Kali/Linux application:
#   * sets up a venv in this folder (with deps)
#   * adds `headless-marauder` and `headless-marauder-tui` commands (~/.local/bin)
#   * adds an entry to your application menu (.desktop)
#   * the in-app "Check for Updates" then pulls from this git clone
#
# Run from inside a git clone:   ./install.sh
set -euo pipefail

APP="headless-marauder"
NAME="Headless Marauder"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Installing $NAME from: $HERE"

# 1. system packages (best effort — venv tooling, Tkinter, Qt)
if command -v apt-get >/dev/null 2>&1; then
  echo "[*] apt: python3-venv python3-tk python3-pyqt5 (sudo)"
  sudo apt-get update -y || true
  sudo apt-get install -y python3-venv python3-tk python3-pyqt5 || true
fi

# 2. venv — --system-site-packages so apt's PyQt5/Tk are visible inside it
if [ ! -d "$HERE/.venv" ]; then
  echo "[*] creating venv"
  python3 -m venv --system-site-packages "$HERE/.venv"
fi
"$HERE/.venv/bin/pip" install -q --upgrade pip || true
"$HERE/.venv/bin/pip" install -q -r "$HERE/requirements.txt"

# PyQt5 fallback (only if the system package isn't visible)
if ! "$HERE/.venv/bin/python" -c "import PyQt5" 2>/dev/null; then
  echo "[*] PyQt5 not present — pip installing into venv"
  "$HERE/.venv/bin/pip" install -q PyQt5 || \
    echo "[!] PyQt5 install failed — the Qt GUI won't run, but the TUI/Tkinter apps still will."
fi

# 3. launchers
mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/$APP" <<EOF
#!/usr/bin/env bash
cd "$HERE"
exec "$HERE/.venv/bin/python" "$HERE/gui_qt/app.py" "\$@"
EOF
cat > "$HOME/.local/bin/${APP}-tui" <<EOF
#!/usr/bin/env bash
cd "$HERE"
exec "$HERE/.venv/bin/python" "$HERE/tui/app.py" "\$@"
EOF
cat > "$HOME/.local/bin/${APP}-web" <<EOF
#!/usr/bin/env bash
cd "$HERE"
exec "$HERE/.venv/bin/python" "$HERE/web/app.py" "\$@"
EOF
chmod +x "$HOME/.local/bin/$APP" "$HOME/.local/bin/${APP}-tui" "$HOME/.local/bin/${APP}-web"

# 4. icon + menu entry
mkdir -p "$HOME/.local/share/icons" "$HOME/.local/share/applications"
cp "$HERE/assets/icon.svg" "$HOME/.local/share/icons/$APP.svg" 2>/dev/null || true
cat > "$HOME/.local/share/applications/$APP.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$NAME
Comment=Control and flash a headless ESP32 Marauder
Exec=$HOME/.local/bin/$APP
Icon=$HOME/.local/share/icons/$APP.svg
Terminal=false
Categories=Network;Security;Utility;
Keywords=marauder;esp32;wifi;bluetooth;security;
EOF
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true

echo
echo "[✓] Installed $NAME"
echo "    • App menu:  search for \"$NAME\""
echo "    • Terminal:  $APP        (Qt GUI)"
echo "                 ${APP}-tui  (terminal UI)"
echo "                 ${APP}-web  (browser UI at localhost:5000)"
echo "    • Update:    in-app  Help → Check for Updates"
if ! printf '%s' "$PATH" | grep -q "$HOME/.local/bin"; then
  echo
  echo "[!] ~/.local/bin isn't in your PATH. Add to ~/.bashrc then re-open the terminal:"
  echo '    export PATH="$HOME/.local/bin:$PATH"'
fi
