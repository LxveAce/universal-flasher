# Universal Flasher

Multi-firmware flasher and device manager for ESP32, Raspberry Pi, Flipper Zero, and ADB-based security hardware. One app flashes, controls, and manages every device in your cyberdeck — or any standalone security build.

**Built on the [Headless Marauder GUI](https://github.com/LxveAce/headless-marauder-gui) scaffold.**

---

## What This Does

Replaces 8+ separate tools (esptool CLI, Arduino IDE, PlatformIO, Meshtastic Web Flasher, qFlipper, Raspberry Pi Imager, ADB manual commands, ESP Terminator) with a single desktop application.

Select your device from a dropdown, pick the firmware, click FLASH.

## Supported Firmware (14+ Profiles)

### ESP32-Based (esptool)

| Firmware | Repo | Boards | Image Type |
|----------|------|--------|------------|
| **ESP32 Marauder** | justcallmekoko/ESP32Marauder | Gold, CYD, C5, WROOM, Cardputer | Multi-file |
| **GhostESP** | GhostESP-Revival/GhostESP | S3, C5, C6, XIAO, DevKitC | Merged |
| **Bruce** | pr3y/Bruce | 30+ boards (S3, CYD, C5, C6, Cardputer) | Merged |
| **HaleHound-CYD** | JesseCHale/HaleHound-CYD | CYD 2.8" (ESP32-2432S028R) | Merged |
| **Meshtastic** | meshtastic/firmware | Heltec V3, T-Beam, XIAO, T-Deck | Merged (factory) |
| **ESP32-DIV** | cifertech/ESP32-DIV | ESP32-S3 + CC1101/NRF24 | Multi-file |
| **Flock-You** | colonelpanichacks/flock-you | ESP32, XIAO S3 | Merged |
| **OUI-Spy Unified Blue** | colonelpanichacks/oui-spy-unified-blue | T-Display S3, XIAO S3 | Merged |
| **Sky-Spy** | colonelpanichacks/Sky-Spy | ESP32-S3, WROOM-32 | Merged |
| **AirTag Scanner** | MatthewKuKanich/ESP32-AirTag-Scanner | ESP32, ESP32-S3 | Merged |
| **Chasing Your Tail NG** | ArgeliusLabs/Chasing-Your-Tail-NG | ESP32 | Merged |

### Raspberry Pi (SD Image Writer)

| Firmware | Repo | Board |
|----------|------|-------|
| **Pwnagotchi** | jayofelony/pwnagotchi | Pi Zero 2W |
| **RaspyJack** | 7h30th3r0n3/Raspyjack | Pi Zero 2W |
| **Kali Linux ARM** | kali.org | Pi 5, Pi Zero 2W |

### ADB-Based

| Firmware | Repo | Device |
|----------|------|--------|
| **RayHunter** | EFForg/rayhunter | Orbic RC400L |

### Flipper Zero (qFlipper)

| Firmware | Repo |
|----------|------|
| **Momentum** | Next-Flip/Momentum-Firmware |
| **Unleashed** | DarkFlippers/unleashed-firmware |

### Community Plugins

Drop a `.json` profile into `~/.universal-flasher/plugins/` to add any ESP32 firmware:

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

## Four Native UIs

| UI | Launch | Best For |
|----|--------|----------|
| **PyQt5** (desktop) | `python gui_qt/app.py` | Full GUI with flasher, serial console, AP/station tables |
| **Tkinter** (desktop) | `python gui/app.py` | Lightweight GUI, works on Kali without extra deps |
| **Textual** (terminal) | `python tui/app.py` | SSH sessions, headless Kali, no X11 needed |
| **Flask** (browser) | `python web/app.py` | Remote access at `http://localhost:5000` |

All four UIs share the same core and support the full firmware profile list.

## Flash Backends

| Backend | Devices | How |
|---------|---------|-----|
| **esptool** | All ESP32 variants | Write firmware bins at specific offsets with chip auto-detection |
| **SD Image Writer** | Pwnagotchi, RaspyJack, Kali | Download `.img.xz`, decompress, block-write to SD card |
| **ADB** | RayHunter (Orbic RC400L) | ADB push + shell install, port forwarding, status check |
| **qFlipper** | Flipper Zero | Launch qFlipper externally with downloaded firmware package |

## Features

### Core Flashing
- **14+ firmware profiles** with auto-detection of chip type and compatible firmware
- **Auto chip detection** — ESP32, S2, S3, C3, C5, C6, H2
- **Full flash or app-only** — blank board setup or firmware update
- **Suicide build support** — SHA256-verified anti-forensic Marauder bundles with TOCTOU defense
- **Custom local .bin** — flash any local firmware file with chip-appropriate offsets

### Device Management
- **USB VID/PID identification** — automatically detect connected device type
- **Firmware version detection** — query running firmware version over serial
- **Port scanner** — enumerate all serial ports and identify what's on each one
- **Cyberdeck manifest** — generate a JSON manifest of all connected devices

### Serial Controllers
- **Marauder** — 70+ commands (WiFi scan, BLE scan, GPS, deauth, beacon spam)
- **HaleHound** — IoT recon, WiFi/BLE scan, evil portal, packet monitor
- **GhostESP** — AP/station scan, beacon, deauth, probe, BLE scan
- **Bruce** — WiFi, BLE, IR, RFID, NFC, BadUSB, GPS
- **Meshtastic** — node listing, message send, region config
- **Generic** — raw serial for any firmware

### Batch Flash
- **Sequential or parallel** — flash multiple ESP32 boards in one operation
- **Cyberdeck flash plan** — pre-configured plan for all 14 cyberdeck devices
- **Per-device result tracking** — success/fail/duration for each flash

### Firmware Backup & Restore
- **Full flash dump** — read entire flash contents before flashing (esptool read_flash)
- **Restore from backup** — write a backup image back to the device with verify
- **Backup metadata** — chip, port, timestamp, SHA256 stored alongside each backup

### Post-Flash Health Check
- **Boot signature detection** — verify firmware started correctly after flash
- **Crash detection** — catch guru meditation, assert failures, panics, backtrace
- **Version confirmation** — parse firmware version from serial boot output

### Offline Firmware Cache
- **Pre-download all firmware** — cache every profile's latest release for field deployment
- **Organized storage** — `~/.universal-flasher/cache/<profile>/<tag>/<asset>`
- **No internet needed** — flash from cache when disconnected

### Flash History
- **Persistent log** — every flash operation recorded with timestamp, version, result
- **Per-device history** — what was last flashed to each port
- **Auto-prune** — keeps last 1000 entries

### Update Checker
- **Cross-profile update scan** — check all firmware for new releases in one call
- **Rate-limited** — 5-minute API cache to avoid GitHub API abuse
- **Background checking** — threaded update checks with callback

### Plugin System
- **Community firmware profiles** — add new firmware via JSON files
- **Schema validation** — rejects malformed plugins with clear error messages
- **Install/uninstall** — manage plugins from code or the UI

## Security

- **HTTPS-only downloads** — all firmware fetched over TLS
- **Host allowlist** — downloads restricted to GitHub's release/raw infrastructure
- **Redirect hardening** — HTTP redirects validated against the same allowlist
- **Path traversal protection** — all downloaded filenames validated as safe basenames
- **SHA256 integrity** — suicide builds verified before flashing, backups hashed
- **TOCTOU defense** — verified firmware staged to a private tempdir before esptool runs
- **SD card safety** — block writes only to removable drives under 256GB with explicit confirmation

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

```bash
pip install pyinstaller
python build.py              # onedir build
python build.py --onefile    # single .exe
```

Builds for Windows (x64), Linux (x64, ARM64), and macOS.

## Quick Start

```bash
# Flash Marauder to an ESP32-S3 Gold board
python gui_qt/app.py

# Flash from the terminal (no GUI)
python tui/app.py

# Flash via browser
python web/app.py
# Open http://localhost:5000

# Command-line chip detection
python -c "from uf_core.flasher import detect_chip; print(detect_chip('COM3', print))"
```

## Architecture

```
universal-flasher/
├── uf_core/                    # Core library
│   ├── flasher.py              # 14+ FirmwareProfile subclasses + esptool plumbing
│   ├── controller.py           # Marauder serial controller
│   ├── controllers.py          # HaleHound, Meshtastic, GhostESP, Bruce controllers
│   ├── device_detect.py        # USB VID/PID identification, firmware version detection
│   ├── sd_backend.py           # SD card imaging for Pi devices
│   ├── adb_backend.py          # ADB-based RayHunter installation
│   ├── batch.py                # Batch flash (sequential/parallel)
│   ├── backup.py               # Firmware backup/restore (esptool read_flash)
│   ├── health.py               # Post-flash boot verification
│   ├── cache.py                # Offline firmware cache
│   ├── history.py              # Persistent flash log
│   ├── update_checker.py       # Cross-profile firmware update checker
│   ├── plugins.py              # Community firmware plugin system
│   ├── commands.py             # Marauder command catalog (70+)
│   ├── parsing.py              # Serial output parser (AP/Station tables)
│   ├── capture.py              # Capture logger (CSV/JSON export)
│   ├── updater.py              # Self-update checker
│   └── uihelp.py               # UI helpers (tooltips, glossary)
├── gui_qt/                     # PyQt5 desktop GUI
├── gui/                        # Tkinter desktop GUI + flasher window
├── tui/                        # Textual terminal UI
├── web/                        # Flask browser UI
├── suicide/                    # Suicide-Marauder provisioner
├── build.py                    # PyInstaller build script
├── pyproject.toml              # Package metadata + dependencies
└── requirements.txt            # Flat dependency list
```

## Relationship to Headless Marauder GUI

This project is a superset of [Headless Marauder GUI](https://github.com/LxveAce/headless-marauder-gui). The original repo remains focused on Marauder-only control and flashing. Universal Flasher extends the same codebase to support every device in the cyberdeck ecosystem.

| Feature | Headless Marauder | Universal Flasher |
|---------|-------------------|-------------------|
| Marauder flash/control | Yes | Yes |
| ESP32-DIV, Bruce | Yes | Yes |
| GhostESP, HaleHound, Meshtastic | No | Yes |
| Flock-You, OUI-Spy, Sky-Spy | No | Yes |
| AirTag Scanner, CYT-NG | No | Yes |
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

This tool is a firmware flasher — it writes official, unmodified firmware images to hardware devices. It does not add, enable, or modify any offensive capability. All firmware is downloaded directly from their respective GitHub repositories.

**For authorized security testing, research, and educational purposes only.**

The user is solely responsible for ensuring compliance with all applicable laws and regulations when using this tool and the firmware it installs.

## License

MIT — see [LICENSE](LICENSE).
