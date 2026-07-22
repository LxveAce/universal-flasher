<div align="center">

<img src="assets/icon.svg" alt="Universal Flasher" width="120" />

# Universal Flasher

### One app to flash security hardware: firmware and full operating systems.

Flash ESP32, Flipper Zero, and ADB gear from one screen, then write a bootable Kali/Tails/Arch USB from the same tool.

[![Release](https://img.shields.io/github/v/release/LxveAce/universal-flasher?style=for-the-badge)](https://github.com/LxveAce/universal-flasher/releases)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-2ea44f?style=for-the-badge)](https://github.com/LxveAce/universal-flasher/releases)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue?style=for-the-badge)](https://www.python.org/)
[![License](https://img.shields.io/github/license/LxveAce/universal-flasher?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/LxveAce/universal-flasher?style=for-the-badge)](https://github.com/LxveAce/universal-flasher/stargazers)

**[Download](https://github.com/LxveAce/universal-flasher/releases)** · **[Field Guide](GUIDE.md)** · **[Changelog](CHANGELOG.md)** · **[Security](SECURITY.md)** · **[Discord](https://discord.gg/lxvelabs)**

</div>

---

> ⚠️ **Authorized, lawful use only.** This is a security-research tool. Use it only on devices you own or have explicit permission to test. Provided as-is, no warranty, you assume all risk. See [DISCLAIMER.md](DISCLAIMER.md).

Every board in a cyberdeck seems to need its own flashing ritual: esptool on the command line for one, the Arduino IDE for another, Raspberry Pi Imager for the SD cards, qFlipper for the Flipper, ADB commands for the hotspot. Universal Flasher folds all of that into a single app: pick the device, pick the firmware, hit flash. As of v1.4.0 it does the same thing for whole operating systems, writing verified Kali, Tails, and Arch images to a USB stick.

It's the standalone flasher in this lineage. The full all-in-one cyberdeck controller (live device control, capture logging, lawful wardriving, and an access gate) lives in the flagship **[cyber-controller](https://github.com/LxveAce/cyber-controller)**. Universal Flasher keeps the console and AP/station tables it inherited from its Headless Marauder GUI roots so you can open a board and confirm it came up right after a flash, and it leaves the heavy control tooling to cyber-controller. This repo stays focused on flashing and provisioning, and it runs fine on its own.

<!-- STATUS-ROADMAP:START -->
## Status & roadmap

**Latest release:** v1.4.0 (see the badge above; it tracks the real tag). Beta, actively shipping. The four front-ends run on Python 3.9+, and both CI pipelines (test + build-release) are green.

**Shipped in v1.4.0:**
- **Software-OS flashing.** Write full, bootable operating systems to USB: Kali, Tails, and Arch. Each image is integrity-checked (SHA-256 + OpenPGP signature) before a single byte is written, reusing the same removable-only writer the SD-card path uses. Available from the Qt front end as a tab and on the CLI: `universal-flasher-qt --list-os` / `--flash-os`.
- **Auto-updating OS catalog.** A weekly CI job refreshes the bundled versions and checksums. The latest release auto-resolves from the official source, and everything still works fully offline from the cached catalog and any images you've already pulled.

**Open items:**
- A final on-hardware ESP32 flash test of the *prebuilt binaries* is still pending (owner/hardware-gated). The frozen-binary flash path is already fixed (multi-call esptool dispatch plus bundled esptool data since v1.3.1), and source / `pip install` runs are flash-verified. This is the last on-device confirmation of the packaged build.
- Flasher consolidation: share one canonical flash engine with cyber-controller so new firmware is a drop-in JSON on both sides.
- Keep hardening the web UI and download paths as new firmware sources get added (the allowlist / redirect / path-traversal / WebSocket-token controls already ship; see [Security](#security)).
<!-- STATUS-ROADMAP:END -->

---

## Two sides: firmware and OS

| Side | What it writes | How |
|------|----------------|-----|
| **Firmware** | ESP32 / Pi / Flipper / ADB security firmware | Profile-driven: pick a device, pick a build, flash |
| **Software (OS)** | Kali, Tails, Arch to a USB stick | Verified whole-disk image writer, removable drives only |

## Supported firmware

Each profile knows its target boards, image layout (a merged blob vs. a multi-file bootloader/partitions/app set), flash offsets, and how to pull the latest release from its upstream GitHub repo.

### ESP32 (esptool)

| Firmware | Repo | Image type |
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

Chip detection is automatic across the ESP32 family (ESP32, S2, S3, C3, C5, C6, H2), and each profile picks the right release asset for the chip it finds.

### Raspberry Pi (SD image writer): planned, not yet wired

These image profiles live in the backend (`uf_core/sd_backend.py`) but aren't reachable from any UI yet.
The working SD/USB image path today is the verified **OS images** below (Kali / Tails / Arch → USB); wiring
these Pi targets to a front-end is on the roadmap.

| Firmware | Repo | Board |
|----------|------|-------|
| **Pwnagotchi** | jayofelony/pwnagotchi | Pi Zero 2W |
| **RaspyJack** | 7h30th3r0n3/Raspyjack | Pi Zero 2W |
| **Kali Linux ARM64** | kali.org | Pi 5, Pi Zero 2W |

### ADB

| Firmware | Repo | Device |
|----------|------|--------|
| **RayHunter** (IMSI-catcher detector) | EFForg/rayhunter | Orbic RC400L |

### Flipper Zero (qFlipper)

| Firmware | Repo |
|----------|------|
| **Momentum** | Next-Flip/Momentum-Firmware |
| **Unleashed** | DarkFlippers/unleashed-firmware |

Flipper firmware is downloaded by its profile and handed off to qFlipper for the actual install.

### Bring your own (plugins)

Drop a `.json` profile into `~/.universal-flasher/plugins/` (or `%LOCALAPPDATA%\universal-flasher\plugins\` on Windows) to add any firmware without touching the source. Plugins are schema-validated on load and rejected with a clear error if they're malformed.

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

`flash_method` currently has to be `esptool`; qflipper/dfu/uf2 plugin dispatch isn't wired yet, so a plugin declaring one of those is rejected with a clear message instead of being silently flashed with esptool. `image_model` is `merged` or `multi`. Required fields: `id`, `label`, `repo`, `flash_method`, `supported_chips`.

## Supported OS images

| OS | Source | Verified before write |
|----|--------|-----------------------|
| **Kali Linux** | cdimage.kali.org | SHA-256 + OpenPGP (`SHA256SUMS.gpg`) |
| **Tails** | tails.net installer feed | SHA-256 + detached OpenPGP `.sig` |
| **Arch Linux** | archlinux.org releng feed | SHA-256 + detached OpenPGP `.sig` |

The latest version auto-resolves from the official source, the bundled catalog works offline, and writes only go to removable drives under a size cap with an explicit confirmation.

## Four native UIs

| UI | Launch | Best for |
|----|--------|----------|
| **PyQt5** (desktop) | `python gui_qt/app.py` | Full GUI: flasher, Software-OS tab, serial console, AP/station tables |
| **Tkinter** (desktop) | `python gui/app.py` | Lightweight GUI, runs on Kali with no extra deps |
| **Textual** (terminal) | `python tui/app.py` | SSH sessions, headless Kali, no X11 |
| **Flask** (browser) | `python web/app.py` | Local access at `http://localhost:5000` |

All four share the same `uf_core` library and the full firmware profile list. The Software-OS flow (Kali/Tails/Arch to USB) is wired into the Qt front end: the tab plus `universal-flasher-qt --list-os` / `--flash-os`. After a `pip install` the entry points are also available as console scripts: `universal-flasher-qt`, `universal-flasher-tk`, `universal-flasher-tui`, `universal-flasher-web`.

## Flash backends

| Backend | Devices | How |
|---------|---------|-----|
| **esptool** | Every ESP32 variant | Writes firmware bins at chip-appropriate offsets, with chip auto-detection |
| **SD image writer** | OS images (Kali / Tails / Arch → USB) | Downloads the image, decompresses if needed, block-writes it to a removable drive. (Pi image profiles are scaffolded but not yet UI-wired; see above.) |
| **ADB** | RayHunter (Orbic RC400L) | ADB push + shell install, port forward, status check |
| **qFlipper** | Flipper Zero | Launches qFlipper with the downloaded firmware package |

## What else it does

Beyond the raw flash, the flasher covers the surrounding grind:

- **Know what's plugged in**: USB VID/PID identification, a serial version probe (single- or multi-baud), a port scanner that tells you what's on each port, and a JSON manifest of every connected device.
- **Full flash or app-only**: blank-board setup or a firmware update, whichever you need.
- **Backup and restore**: dump the whole flash before you write (esptool `read_flash`), and restore it later with verify. Each backup stores its chip, port, timestamp, and SHA-256.
- **Post-flash health check**: watches the serial boot for a good boot signature, and catches guru-meditation, asserts, panics, and backtraces so you know if a board came up wrong.
- **Batch flash**: sequential or parallel, with a pre-built cyberdeck plan that assigns firmware across a multi-board deck and per-device pass/fail/duration tracking.
- **Offline cache**: pre-download every profile's latest release to `~/.universal-flasher/cache/<profile>/<tag>/<asset>` for field work with no internet.
- **Flash history**: a persistent log of every flash (timestamp, version, result) and what was last written to each port, auto-pruned.
- **Update checker**: one call scans every profile for new upstream releases, rate-limited and cached so it doesn't hammer GitHub.
- **Suicide-build support**: flash pre-provisioned, SHA256-verified anti-forensic Marauder bundles, with a TOCTOU defense that stages verified files to a private tempdir before esptool runs. See [`suicide/docs/SAFETY.md`](suicide/docs/SAFETY.md).

The desktop UIs also carry a serial console and live AP/station tables for checking a board after you flash it. That's a leftover from the Headless Marauder GUI lineage, not the point of the app. Reach for [cyber-controller](https://github.com/LxveAce/cyber-controller) when you want the full controller, logger, and wardriving suite.

## Security

- **HTTPS-only downloads**: everything is fetched over TLS.
- **Host allowlist**: downloads are restricted to known release/raw infrastructure (GitHub, `kali.download`, and the OS sources above).
- **Redirect hardening**: HTTP redirects are checked against the same allowlist *before* they're followed, with a redirect-loop cap.
- **Path-traversal protection**: every downloaded filename is validated as a safe basename, and bundle extraction rejects any entry that resolves outside the target directory.
- **SHA-256 integrity**: suicide bundles and OS images are verified before flashing; backups are hashed.
- **TOCTOU defense**: verified firmware is staged to a private tempdir before esptool touches it.
- **SD-card safety**: block writes go only to removable drives under a size cap, with an explicit confirmation.
- **Web UI hardening**: the browser UI binds to loopback only, with CORS locked to `127.0.0.1:5000` and a WebSocket auth token minted at startup.

Found a security bug? Please report it privately: see [SECURITY.md](SECURITY.md), not a public issue.

## Install

```bash
git clone https://github.com/LxveAce/universal-flasher.git
cd universal-flasher
pip install -e ".[all]"
```

Or install just the UI you want:

```bash
pip install -e ".[qt]"    # PyQt5 desktop GUI
pip install -e ".[tui]"   # Textual terminal UI
pip install -e ".[web]"   # Flask browser UI
```

**System deps**

- **Python 3.9+**
- **Tkinter** (ships with Python; on Debian/Kali: `sudo apt install python3-tk`)
- **ADB** for RayHunter: `sudo apt install android-tools-adb`
- **qFlipper** for Flipper Zero: [flipperzero.one/update](https://flipperzero.one/update)

### Prebuilt binaries

No-Python-required builds are on the [Releases](https://github.com/LxveAce/universal-flasher/releases) page for **Windows x64**, **macOS arm64 (Apple Silicon)**, **Linux x64**, and **Linux arm64**. They're unsigned, so Windows SmartScreen and macOS Gatekeeper will warn on first run. That's expected for an unsigned build; allow it through if you trust the source.

To build one locally:

```bash
pip install pyinstaller
python build.py              # onedir build
python build.py --onefile    # single executable
```

## Quick start

```bash
# Full desktop GUI
python gui_qt/app.py

# Flash from the terminal (no GUI)
python tui/app.py

# Flash via browser
python web/app.py     # then open http://localhost:5000

# List / flash an OS image to USB
universal-flasher-qt --list-os
universal-flasher-qt --flash-os
```

Convenience launchers are included for both platforms: `run-qt`, `run-gui`, `run-tui`, `run-web` (`.sh` / `.bat`). Pass `--mock` to any UI to poke around without hardware.

## Learn more

| If you want to… | Go to |
|-----------------|-------|
| Read the full walkthrough | [GUIDE.md](GUIDE.md) |
| See what changed | [CHANGELOG.md](CHANGELOG.md) |
| Report a security bug | [SECURITY.md](SECURITY.md) |
| Understand the legal line | [DISCLAIMER.md](DISCLAIMER.md) |
| Add firmware or fix a bug | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Ask a question | [Discord](https://discord.gg/lxvelabs) |

## Ecosystem

| Project | What it is |
|---------|------------|
| **[cyber-controller](https://github.com/LxveAce/cyber-controller)** | The flagship. Flash + control + coordinate: the full cyberdeck controller with live device control, capture logging, lawful wardriving, and an access gate. Universal Flasher is its flashing half, spun out to run standalone. |
| **[headless-marauder-gui](https://github.com/LxveAce/headless-marauder-gui)** | The Marauder-only controller + flasher this project grew out of. It stays focused on Marauder; Universal Flasher generalized the flasher to every device. |

## Architecture

```
universal-flasher/
├── uf_core/                # Core library
│   ├── flasher.py          # FirmwareProfile classes + esptool/qFlipper plumbing
│   ├── sd_backend.py       # SD-card imaging for Pi devices
│   ├── adb_backend.py      # ADB install for RayHunter
│   ├── os_catalog.py       # Software-OS catalog (Kali/Tails/Arch) + verify
│   ├── device_detect.py    # USB VID/PID identification, version probe
│   ├── batch.py            # Batch flash (sequential/parallel) + deck plan
│   ├── backup.py           # Firmware backup/restore (esptool read_flash)
│   ├── health.py           # Post-flash boot verification
│   ├── cache.py            # Offline firmware cache
│   ├── history.py          # Persistent flash log
│   ├── update_checker.py   # Cross-profile update checker
│   ├── plugins.py          # Community firmware plugin system
│   ├── controller.py       # Marauder serial controller (console)
│   ├── controllers.py      # HaleHound / Meshtastic / GhostESP / Bruce consoles
│   ├── commands.py         # Serial command catalog
│   ├── parsing.py          # AP/station table parser
│   └── capture.py          # Serial capture logger
├── gui_qt/                 # PyQt5 desktop GUI (+ Software-OS tab)
├── gui/                    # Tkinter desktop GUI
├── tui/                    # Textual terminal UI
├── web/                    # Flask browser UI
├── suicide/                # Suicide-Marauder provisioner + firmware sources
├── build.py                # PyInstaller build script
└── pyproject.toml          # Package metadata + dependencies
```

## Contributing

PRs and issues are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). The short version: branch off `main`, run with `--mock` to develop without hardware, and if you touch `uf_core/`, keep it working across all four UIs.

There's a hardware-free test suite (`tests/`) that CI runs on every push: flash offsets, security guards, the SD/ADB/OS backends, and headless-import safety. Run it with:

```bash
pip install -e ".[test]"
pytest
```

## Credits

All firmware is downloaded straight from its upstream repositories (linked in the tables above) and written unmodified. Nothing is vendored or rebuilt here. Flashing rides on [esptool](https://github.com/espressif/esptool) for ESP32 and [qFlipper](https://flipperzero.one/update) for the Flipper. The vendored Suicide-Marauder bundle is pinned and SHA-256 verified before it's ever flashed. Thanks to every firmware author who makes their work open.

## Legal

Universal Flasher is a flasher. It writes official, unmodified firmware and OS images to hardware. It doesn't add, enable, or modify any offensive capability, and it doesn't verify firmware *signatures*, so always check what you're flashing. You're solely responsible for complying with the laws that apply to you and to the firmware you install. See [DISCLAIMER.md](DISCLAIMER.md) and, for anti-forensic suicide builds, [`suicide/docs/SAFETY.md`](suicide/docs/SAFETY.md).

**For authorized security testing, research, and education only.**

## License

MIT. See [LICENSE](LICENSE).

## 📫 Connect

**Discord:** [discord.gg/lxvelabs](https://discord.gg/lxvelabs) · **GitHub:** [@LxveAce](https://github.com/LxveAce) · **Email:** LxveLabs@proton.me (business) · lxveace@proton.me (direct) · **Sites:** [lxvelabs.com](https://lxvelabs.com) · [esp32marauder.com](https://esp32marauder.com)

---

Built by LxveAce · a LxveLabs project
