# Changelog

## [1.3.0] — 2026-06-09

Multi-firmware flasher, Suicide-build support, standalone builds, and security hardening.

**New stuff:**
- Multi-firmware flasher — profile-based flashing for ESP32Marauder, Evil Portal, Wi-Fi Nugget, and custom firmware. Each profile defines its own partition layout and support files.
- Suicide-build flash path — dedicated `flash_suicide` flow for pre-provisioned Suicide-Marauder bundles with manifest validation and SHA256 integrity checks.
- Standalone executables — PyInstaller-based Windows `.exe`, Linux x64, and Linux ARM64 binaries on the Releases page. No Python needed. Built automatically via GitHub Actions CI on each release.
- `build.py` for local PyInstaller builds (`python build.py --onefile`)
- Hover tooltips across all desktop UIs — shared `uihelp.py` module with a `GLOSSARY` of plain-language term explanations
- Web UI flash panel — full feature parity with desktop GUIs (multi-firmware + Suicide-build + tooltips)
- ARM64 Linux builds for Raspberry Pi and ARM SBCs

**Security:**
- Path-traversal guard on bundle extraction — rejects entries that resolve outside the target directory
- SHA256 integrity verification for all files in Suicide-Marauder bundles (strict mode: missing/empty hash = hard fail)
- Red-team round 2 fixes: corrected path-traversal check + stricter bundle schema validation

**Changed:**
- Flasher window expanded with firmware profile selector and Suicide-build tab in all desktop UIs
- GUIDE.md updated with multi-firmware and Suicide-build documentation
- README updated with standalone binary download links and ARM64 instructions
- Docs cleanup (SECURITY.md, DISCLAIMER.md, CONTRIBUTING.md trimmed)

## [1.2.0] — 2026-06-08

Added a browser-based UI, standalone executables, and project policies.

**New stuff:**
- Browser UI — Flask + SocketIO at `localhost:5000`. Full command sidebar, live console over WebSocket, AP/Station tables, parameter forms, raw command input with history, auto-list, logging, keyboard shortcuts (Ctrl+L/K/.), dark theme, `--mock` and `--host 0.0.0.0` support.
- `headless-marauder-web` launcher for Linux and Windows
- `run-web.sh` / `run-web.bat` dev scripts
- SECURITY.md, DISCLAIMER.md, CONTRIBUTING.md, this changelog
- Standalone executables (Windows .exe, Linux x64/ARM64 binaries) on the Releases page — no Python needed
- `build.py` for local PyInstaller builds
- GitHub Actions CI to auto-build on each release

**Fixed:**
- Web UI: `flasher.detect_chip()` crash from missing callback argument
- Web UI: XSS through malicious SSIDs in the AP/Station tables
- Web UI: autolist timer stacking when toggled rapidly
- Web UI: keyboard shortcuts not working when the command input was focused

**Changed:**
- requirements.txt and pyproject.toml updated for Flask/SocketIO deps
- Installers now include the web UI launcher
- README updated with browser UI docs

## [1.1.0] — 2026-06-08

Cross-platform release — Windows support, pip install.

- Windows installer (`install.bat`) with venv, PATH, Start Menu shortcut
- `pip install git+....[all]` for cross-platform installs
- `pyproject.toml` with optional dep groups (`[qt]`, `[tui]`, `[all]`)
- Updated `install.sh` / `uninstall.sh` with TUI launcher

## [1.0.1] — 2026-06-08

- In-app Guide tab with full tool reference
- `GUIDE.md` — attack chaining walkthrough and integration guide for other tools
- Hover tooltips on all command buttons

## [1.0.0] — 2026-06-08

Initial release.

- PyQt5 GUI with live AP/Station tables, target picker, firmware flasher, logging
- Tkinter GUI (lightweight alternative)
- Textual TUI for terminal/SSH use
- `marauder_core` shared library — serial controller, 70+ command catalog, stream parser, firmware flasher (ESP32 + S3), capture logger, self-updater
- Linux installer with app menu entry and PATH launchers
- Auto-detect serial port at 115200 baud
- `--mock` mode for dev/demo without hardware
- MIT License

[1.3.0]: https://github.com/LxveAce/headless-marauder-gui/releases/tag/v1.3.0
[1.2.0]: https://github.com/LxveAce/headless-marauder-gui/releases/tag/v1.2.0
[1.1.0]: https://github.com/LxveAce/headless-marauder-gui/releases/tag/v1.1.0
[1.0.1]: https://github.com/LxveAce/headless-marauder-gui/releases/tag/v1.0.1
[1.0.0]: https://github.com/LxveAce/headless-marauder-gui/releases/tag/v1.0.0
