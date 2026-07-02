# Universal Flasher

> ⚠️ **Authorized, lawful use only.** A security-research tool — use it only on systems you own or have explicit permission to test. Provided as-is, no warranty; you assume all risk. See [DISCLAIMER.md](DISCLAIMER.md).

Multi-firmware flasher and device manager for ESP32, Raspberry Pi, Flipper Zero, and ADB-based security hardware. One app flashes, controls, and manages every device in your cyberdeck, or any standalone security build.

**Built on the [Headless Marauder GUI](https://github.com/LxveAce/headless-marauder-gui) scaffold.**

> **Project status:** actively released, Beta. Universal Flasher is the standalone, device-agnostic flasher in this ecosystem: firmware plus Software-OS flashing (Kali/Tails/Arch to USB), shipped in v1.4.0. Broader all-in-one device control (controller, logger, wardriving, access gate) lives in the flagship successor, **[cyber-controller](https://github.com/LxveAce/cyber-controller)** (v1.4.0). This repo stays focused on the flashing/provisioning side and works fine on its own.

<!-- STATUS-ROADMAP:START -->
## Status & Roadmap

**Status:** Beta, actively shipping (latest release v1.4.0); source builds and the CI release pipeline are healthy and all four front-ends run on Python 3.13.

**Shipped (v1.4.0):**
- **Software-OS flashing** — flash full operating systems to USB: Kali Linux, Tails OS, and Arch Linux, each integrity-verified (SHA256 / signature) before writing, alongside the existing ESP32 firmware flasher. Available from the Qt front end's CLI: `universal-flasher-qt --list-os` / `--flash-os`.
- **Auto-updating OS catalog** — a weekly CI job keeps the bundled OS catalog current; latest versions auto-resolve, and everything works fully **offline** from a cached catalog and previously downloaded images.

**In progress / known issues:**
- A final on-hardware ESP32 flash test of the *prebuilt standalone binaries* is still pending (owner/hardware-gated). The frozen-binary flash path is fixed (multi-call esptool dispatch + bundled esptool data, v1.3.1) and source/pip installs are flash-verified — this is the last on-device confirmation of the packaged build.

**Roadmap:**

- Continued responsible hardening of the web UI controls (download allowlist, redirect handling, path-traversal guard, WebSocket auth token).
- In-app tooltips on every control and a thorough How-To / tutorial tab.
- Flasher consolidation — share one canonical flash engine with cyber-controller (drop-a-JSON firmware growth).

> **Scope:** Universal Flasher is strictly the flasher (Firmware + Software flashing) — no controller, logger, or wardriving. All-in-one control — combining flashing, logging, pentest tooling, lawful, owner-authorized wardriving (GPS-tagged Wi-Fi capture exported to WiGLE CSV), and an in-app Access-Gate setup (admin password / physical USB key, salted-scrypt + encrypted vault) — plus the main cyberdeck GUI ship in the separate flagship **[cyber-controller](https://github.com/LxveAce/cyber-controller)** project (latest release v1.5.0), not here.
<!-- STATUS-ROADMAP:END -->

---

## What This Does

Replaces several separate tools (esptool CLI, Arduino IDE, PlatformIO, Meshtastic Web Flasher, qFlipper, Raspberry Pi Imager, ADB manual commands) with a single application.

Select your device from a dropdown, pick the firmware, click FLASH. As of v1.4.0 it also flashes full operating systems to USB — Kali Linux, Tails OS, and Arch Linux — with an auto-updating, offline-capable catalog (`universal-flasher-qt --list-os` / `--flash-os`).

## Supported Firmware

The flasher ships with profiles for the firmware below. Each profile knows its target boards, image layout (merged blob vs. multi-file with bootloader/partitions), flash offsets, and how to fetch the latest release from its upstream GitHub repo.

### ESP32-Based (esptool)

| Firmware | Repo | Image Type |
|----------|------|------------|
| **ESP32 Marauder** | justcallmekoko/ESP32Marauder | Multi-file |
| **GhostESP** | GhostESP-Revival/GhostESP | Merged |
| **Bruce** | pr3y/Bruce | Merged |
| **HaleHound-CYD** | JesseCHale/HaleHound-CYD | Merged |
| **Meshtastic** | meshtastic/firmware | Merged (factory) |
| **ESP32-DIV** | cifertech/ESP32-DIV | Multi-file |
| **Flock-You** | colonelpanichacks/flock-you | Merged |
| **OUI-Spy Unified Blue** | colonelpanichacks/oui-spy-unified-blue | Merged |
| **Sky-Spy (Drone RemoteID)** | colonelpanichacks/Sky-Spy | Merged |
| **ESP32 AirTag Scanner** | MatthewKuKanich/ESP32-AirTag-Scanner | Merged |
| **Chasing Your Tail NG** | ArgeliusLabs/Chasing-Your-Tail-NG | Merged |
| **MinigotchiV3** | dj1ch/minigotchi-V3 | Merged |
| **Custom / local .bin** | — | Local file |

Chip detection is automatic across the ESP32 family (ESP32, S2, S3, C3, C5, C6, H2), and each profile selects the right release asset for the detected chip.

### Raspberry Pi (SD Image Writer)

| Firmware | Repo | Board |
|----------|------|-------|
| **Pwnagotchi** | jayofelony/pwnagotchi | Pi Zero 2W |
| **RaspyJack** | 7h30th3r0n3/Raspyjack | Pi Zero 2W |
| **Kali Linux ARM64** | kali.org | Pi 5, Pi Zero 2W |

### ADB-Based

| Firmware | Repo | Device |
|----------|------|--------|
| **RayHunter** (IMSI-catcher detector) | EFForg/rayhunter | Orbic RC400L |

### Flipper Zero (qFlipper)

| Firmware | Repo |
|----------|------|
| **Momentum** | Next-Flip/Momentum-Firmware |
| **Unleashed** | DarkFlippers/unleashed-firmware |

Flipper firmware is downloaded by the matching profile and handed off to qFlipper for the actual install.

### Community Plugins

Drop a `.json` profile into `~/.universal-flasher/plugins/` (or `%LOCALAPPDATA%\universal-flasher\plugins\` on Windows) to add any firmware without touching the source. Plugins are schema-validated on load and rejected with a clear error if malformed.

```json
{
  "id": "my-firmware",
  "label": "My Custom Firmware",
  "repo": "owner/repo",
  "flash_method": "esptool",
  "image_model": "merged",
  "supported_chips": ["esp32", "esp32s3"],
  "release_asset_pattern": ".*\\.bin$"
}
```

`flash_method` accepts `esptool`, `qflipper`, `dfu`, or `uf2`; `image_model` is `merged` or `multi`. The required fields are `id`, `label`, `repo`, `flash_method`, and `supported_chips`.

## Four Native UIs

| UI | Launch | Best For |
|----|--------|----------|
| **PyQt5** (desktop) | `python gui_qt/app.py` | Full GUI with flasher, serial console, AP/station tables |
| **Tkinter** (desktop) | `python gui/app.py` | Lightweight GUI, works on Kali without extra deps |
| **Textual** (terminal) | `python tui/app.py` | SSH sessions, headless Kali, no X11 needed |
| **Flask** (browser) | `python web/app.py` | Remote access at `http://localhost:5000` |

All four UIs share the same `uf_core` library and support the full firmware profile list. (Software-OS flashing — the Kali / Tails / Arch-to-USB feature — is currently wired only into the Qt CLI: `universal-flasher-qt --list-os` / `--flash-os`.) After a `pip install`, the same entry points are available as console scripts: `universal-flasher-qt`, `universal-flasher-tk`, `universal-flasher-tui`, and `universal-flasher-web`.

## Flash Backends

| Backend | Devices | How |
|---------|---------|-----|
| **esptool** | All ESP32 variants | Write firmware bins at chip-appropriate offsets with chip auto-detection |
| **SD Image Writer** | Pwnagotchi, RaspyJack, Kali | Download `.img.xz`/`.img.gz`, decompress, block-write to SD card |
| **ADB** | RayHunter (Orbic RC400L) | ADB push + shell install, port forwarding, status check |
| **qFlipper** | Flipper Zero | Launch qFlipper externally with the downloaded firmware package |

## Features

### Core Flashing
- **Profile-driven flashing** with automatic chip detection and compatible-firmware selection
- **Auto chip detection** — ESP32, S2, S3, C3, C5, C6, H2
- **Full flash or app-only** — blank-board setup or firmware update
- **Suicide build support** — SHA256-verified anti-forensic Marauder bundles with TOCTOU defense (see [`suicide/docs/SAFETY.md`](suicide/docs/SAFETY.md))
- **Custom local .bin** — flash any local firmware file with chip-appropriate offsets

### Device Management
- **USB VID/PID identification** — automatically detect connected device type
- **Firmware version detection** — query the running firmware version over serial (single- or multi-baud probe)
- **Port scanner** — enumerate all serial ports and identify what's on each one
- **Cyberdeck manifest** — generate a JSON snapshot of all connected devices

### Serial Controllers
- **Marauder** — full command catalog (70+ commands: WiFi scan, BLE scan, GPS, deauth, beacon spam)
- **HaleHound** — IoT recon, WiFi/BLE scan, evil portal, packet monitor
- **GhostESP** — AP/station scan, beacon, deauth, probe, BLE scan
- **Bruce** — WiFi, BLE, IR, RFID, NFC, BadUSB, GPS
- **Meshtastic** — node listing, message send, region config
- **Generic** — raw serial for any firmware

### Batch Flash
- **Sequential or parallel** — flash multiple ESP32 boards in one operation
- **Cyberdeck flash plan** — a pre-built plan that assigns firmware across a multi-board deck
- **Per-device result tracking** — success/fail/duration for each flash

### Firmware Backup & Restore
- **Full flash dump** — read the entire flash before flashing (esptool `read_flash`)
- **Restore from backup** — write a backup image back to the device with verify
- **Backup metadata** — chip, port, timestamp, and SHA256 stored alongside each backup

### Post-Flash Health Check
- **Boot signature detection** — verify firmware started correctly after flash
- **Crash detection** — catch guru meditation, assert failures, panics, and backtraces
- **Version confirmation** — parse the firmware version from serial boot output

### Offline Firmware Cache
- **Pre-download all firmware** — cache every profile's latest release for field deployment
- **Organized storage** — `~/.universal-flasher/cache/<profile>/<tag>/<asset>`
- **No internet needed** — flash from cache when disconnected

### Flash History
- **Persistent log** — every flash operation recorded with timestamp, version, and result
- **Per-device history** — what was last flashed to each port
- **Auto-prune** — keeps the most recent entries

### Update Checker
- **Cross-profile update scan** — check all firmware for new releases in one call
- **Rate-limited** — API responses cached to avoid hammering GitHub
- **Background checking** — threaded update checks with a callback

### Plugin System
- **Community firmware profiles** — add new firmware via JSON files
- **Schema validation** — rejects malformed plugins with clear error messages
- **Install/uninstall** — manage plugins from code or the UI

## Security

- **HTTPS-only downloads** — all firmware fetched over TLS
- **Host allowlist** — downloads restricted to known release/raw infrastructure (GitHub, `kali.download`)
- **Redirect hardening** — HTTP redirects validated against the same allowlist *before* they are followed, with a redirect-loop cap
- **Path traversal protection** — all downloaded filenames validated as safe basenames; bundle extraction rejects entries that resolve outside the target directory
- **SHA256 integrity** — suicide builds verified before flashing; backups hashed
- **TOCTOU defense** — verified firmware staged to a private tempdir before esptool runs
- **SD card safety** — block writes only to removable drives under a size cap, with explicit confirmation
- **Web UI hardening** — localhost-only CORS and a WebSocket auth token generated on startup

## Installation

```bash
git clone https://github.com/LxveAce/universal-flasher.git
cd universal-flasher
pip install -e ".[all]"
```

Or install specific UI dependencies:

```bash
pip install -e ".[qt]"    # PyQt5 desktop GUI
pip install -e ".[tui]"   # Textual terminal UI
pip install -e ".[web]"   # Flask browser UI
```

### System Dependencies

- **Python 3.9+**
- **Tkinter** (ships with Python; on Debian/Kali: `sudo apt install python3-tk`)
- **ADB** (for RayHunter): `sudo apt install android-tools-adb`
- **qFlipper** (for Flipper Zero): [flipperzero.one/update](https://flipperzero.one/update)

## Standalone Executables

Prebuilt binaries are published on the [Releases](https://github.com/LxveAce/universal-flasher/releases) page — no Python install required: **Windows x64**, **macOS arm64 (Apple Silicon)**, **Linux x64**, and **Linux arm64**.

To build locally:

```bash
pip install pyinstaller
python build.py              # onedir build
python build.py --onefile    # single executable
```

## Quick Start

```bash
# Full desktop GUI
python gui_qt/app.py

# Flash from the terminal (no GUI)
python tui/app.py

# Flash via browser
python web/app.py
# Open http://localhost:5000

# Command-line chip detection
python -c "from uf_core.flasher import detect_chip; print(detect_chip('COM3', print))"
```

Convenience launchers are included for both platforms: `run-qt`, `run-gui`, `run-tui`, and `run-web` (`.sh` / `.bat`).

## Architecture

```
universal-flasher/
├── uf_core/                    # Core library
│   ├── flasher.py              # FirmwareProfile classes + esptool/qFlipper plumbing
│   ├── controller.py           # Marauder serial controller
│   ├── controllers.py          # HaleHound, Meshtastic, GhostESP, Bruce controllers
│   ├── device_detect.py        # USB VID/PID identification, firmware version probe
│   ├── sd_backend.py           # SD card imaging for Pi devices
│   ├── adb_backend.py          # ADB-based RayHunter installation
│   ├── batch.py                # Batch flash (sequential/parallel) + deck flash plan
│   ├── backup.py               # Firmware backup/restore (esptool read_flash)
│   ├── health.py               # Post-flash boot verification
│   ├── cache.py                # Offline firmware cache
│   ├── history.py              # Persistent flash log
│   ├── update_checker.py       # Cross-profile firmware update checker
│   ├── plugins.py              # Community firmware plugin system
│   ├── commands.py             # Marauder command catalog
│   ├── parsing.py              # Serial output parser (AP/Station tables)
│   ├── capture.py              # Capture logger (CSV/JSON export)
│   ├── updater.py              # Self-update checker
│   └── uihelp.py               # UI helpers (tooltips, glossary)
├── gui_qt/                     # PyQt5 desktop GUI
├── gui/                        # Tkinter desktop GUI + flasher window
├── tui/                        # Textual terminal UI
├── web/                        # Flask browser UI
├── suicide/                    # Suicide-Marauder provisioner + firmware sources
├── build.py                    # PyInstaller build script
├── pyproject.toml              # Package metadata + dependencies
└── requirements.txt            # Flat dependency list
```

## Relationship to Headless Marauder GUI

This project is a superset of [Headless Marauder GUI](https://github.com/LxveAce/headless-marauder-gui). The original repo stays focused on Marauder-only control and flashing. Universal Flasher extends the same codebase to cover every device in the cyberdeck ecosystem.

| Feature | Headless Marauder | Universal Flasher |
|---------|-------------------|-------------------|
| Marauder flash/control | Yes | Yes |
| ESP32-DIV, Bruce | Yes | Yes |
| GhostESP, HaleHound, Meshtastic | No | Yes |
| Flock-You, OUI-Spy, Sky-Spy | No | Yes |
| AirTag Scanner, CYT-NG, MinigotchiV3 | No | Yes |
| SD card imaging (Pi) | No | Yes |
| ADB install (RayHunter) | No | Yes |
| Flipper Zero (qFlipper) | No | Yes |
| Batch flash | No | Yes |
| Firmware backup/restore | No | Yes |
| Device auto-detection | No | Yes |
| Offline cache | No | Yes |
| Flash history | No | Yes |
| Update checker | No | Yes |
| Plugin system | No | Yes |
| Health check | No | Yes |

## Legal

This tool is a firmware flasher — it writes official, unmodified firmware images to hardware devices. It does not add, enable, or modify any offensive capability. All firmware is downloaded directly from its respective upstream repositories. It does not verify firmware signatures, so always check what you are flashing.

**For authorized security testing, research, and educational purposes only.**

The user is solely responsible for ensuring compliance with all applicable laws and regulations when using this tool and the firmware it installs. See [`DISCLAIMER.md`](DISCLAIMER.md) and, for anti-forensic suicide builds, [`suicide/docs/SAFETY.md`](suicide/docs/SAFETY.md).

## License

MIT — see [LICENSE](LICENSE).

## Connect

- **Discord:** [discord.gg/lxveace](https://discord.gg/lxveace) — questions, help, or to talk through this project
- **GitHub:** [@LxveAce](https://github.com/LxveAce)
- **Website:** [lxveace.com](https://lxveace.com)
- **Project site:** [esp32marauder.com](https://esp32marauder.com)
