# Changelog

> **Git tags / GitHub releases:** only **v1.1.0**, **v1.1.1**, and **v1.4.0** are tagged.
> The version headings below without a `[bracketed]` link (1.0.0, 1.0.1, 1.2.0, 1.3.0, 1.3.1)
> record development milestones that were folded into those tagged releases — they were never
> cut as standalone git tags. Retro-tagging any of them is an owner decision.

## [1.4.0] — 2026-06-27

Software-OS flashing — flash whole operating systems to USB, alongside firmware.

**Added:**
- **Software OS tab + `--list-os` / `--flash-os` CLI** — write verified bootable **Kali, Tails, and
  Arch** images to a removable USB, separate from board firmware. The latest version is auto-resolved
  from the official source (Kali `SHA256SUMS`, Arch releng JSON feed, Tails feed); the bundled catalog
  works fully **offline**; every image is integrity-verified (SHA-256 + OpenPGP signature) before write,
  reusing the hardened removable-only raw-image writer.
- A weekly CI job (`update-os-catalog.yml`) that opens a PR refreshing the bundled OS versions/checksums.
- Tooltips on the new controls; the Field Guide now documents the Software-OS flow.
- Test suite added (`tests/`): OS catalog (12) + Software-OS tab smoke (1).

## 1.3.1 — 2026-06-27 (development milestone — never git-tagged)

Frozen-binary flashing fix + version reconciliation.

**Fixed:**
- Standalone binaries could not flash ESP32. esptool was invoked as `sys.executable -m esptool`,
  which under a PyInstaller build is the app itself (not Python), and esptool's package data
  (targets/stub_flasher JSON) was never bundled. The binary now acts as a multi-call esptool
  runner (re-execs itself, dispatches to `esptool.main()`) and bundles esptool fully
  (`--collect-all esptool`). Source / `pip install` runs were unaffected.
- Version drift: `uf_core.__version__`, `pyproject.toml`, and this CHANGELOG now agree (1.3.1);
  the UIs read the version from `uf_core.__version__`, so binaries no longer show a stale "v1.0.0".
- build.py: removed a dead ICON variable.

## 1.3.0 — 2026-06-09 (development milestone — never git-tagged)

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

## 1.2.0 — 2026-06-08 (development milestone — never git-tagged)

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

## [1.1.1] — 2026-06-10

Vendored Suicide-Marauder sync + provisioner hardening (red-team round 3).

**Changed:**
- Synced the vendored Suicide-Marauder bundle to its canonical upstream.

**Security:**
- Red-team round 3 hardening of the provisioning / integrity-verify path: encryption-aware
  verification, resume convergence, factory/scratch coverage, and RAM scrub.

## [1.1.0] — 2026-06-08

Cross-platform release — Windows support, pip install.

- Windows installer (`install.bat`) with venv, PATH, Start Menu shortcut
- `pip install git+....[all]` for cross-platform installs
- `pyproject.toml` with optional dep groups (`[qt]`, `[tui]`, `[all]`)
- Updated `install.sh` / `uninstall.sh` with TUI launcher

## 1.0.1 — 2026-06-08 (development milestone — never git-tagged)

- In-app Guide tab with full tool reference
- `GUIDE.md` — attack chaining walkthrough and integration guide for other tools
- Hover tooltips on all command buttons

## 1.0.0 — 2026-06-08 (development milestone — never git-tagged)

Initial release.

- PyQt5 GUI with live AP/Station tables, target picker, firmware flasher, logging
- Tkinter GUI (lightweight alternative)
- Textual TUI for terminal/SSH use
- `marauder_core` shared library — serial controller, 70+ command catalog, stream parser, firmware flasher (ESP32 + S3), capture logger, self-updater
- Linux installer with app menu entry and PATH launchers
- Auto-detect serial port at 115200 baud
- `--mock` mode for dev/demo without hardware
- MIT License

<!-- Only the three git-tagged releases are linked; the other headings above are
     never-tagged development milestones (see the note at the top of this file). -->
[1.4.0]: https://github.com/LxveAce/universal-flasher/releases/tag/v1.4.0
[1.1.1]: https://github.com/LxveAce/universal-flasher/releases/tag/v1.1.1
[1.1.0]: https://github.com/LxveAce/universal-flasher/releases/tag/v1.1.0
