# Headless Marauder — Field Guide

What every tool does, how to use the app, and how to chain scans + attacks together and feed the output into other software. For authorized testing only (see [Legal](#legal)).

---

## 1. How it works

The ESP32 runs Marauder firmware. This app is just a remote control over USB serial — every button sends a text command and shows what the board prints back. The workflow is always:

```
        ┌─────────── recon ───────────┐         ┌──── act ────┐
  scan  →  list  →  (tables fill)  →  select  →  attack / sniff / capture  →  STOP
```

1. **Scan** to find things (APs, stations, BLE devices).
2. **List** to pull indexed results (the app does this automatically — tables fill themselves).
3. **Select** your target(s) from the picker.
4. **Act** — deauth, sniff a handshake, evil portal, whatever.
5. **STOP** — scans and attacks run until you stop them.

> Hover any command button for a description. *Help → Command Reference* lists everything.

---

## 2. Using the app

- **Connect** — auto-detects the board (115200 baud). Green = connected.
- **Scan APs** → Access Points tab fills automatically (auto-list is on by default).
- **STOP** → ends the scan.
- **Select APs / Select Stations** → tick targets in the picker (builds the right `select -a 0,2,5`).
- Run an action (e.g. **Deauth (selected APs)**).
- **● Log** → records everything to a folder (see [§5](#5-data--logging)).
- **⚡ Flash Firmware** → detect chip, fetch firmware, flash.
- **Raw box** (bottom) → type any command the buttons don't cover.

Keyboard: `Ctrl+L` clear · `F5` refresh ports · `Ctrl+K` command box · `Ctrl+.` STOP · `Ctrl+U` update.

---

## 3. Command reference

All commands from the Marauder CLI. "runs until STOP" means it keeps going until you stop it. "attack" means offensive — rendered in red, confirmed before sending.

### WiFi · Scan

| Command | Sends | What it does |
|---|---|---|
| Scan APs | `scanap` | Find nearby access points. _(runs until STOP)_ |
| Scan Stations | `scansta` | Find client devices (run scanap first). _(runs until STOP)_ |
| Scan All | `scanall` | APs and stations together. _(runs until STOP)_ |
| Signal Monitor | `sigmon` | Live signal strength for a target. _(runs until STOP)_ |
| Packet Count | `packetcount` | Packets-per-second counter. _(runs until STOP)_ |
| MAC Track | `mactrack` | Track signal strength of a MAC — proximity/hot-cold. _(runs until STOP)_ |
| Wardrive | `wardrive` | GPS-tagged AP logging to SD card (WiGLE CSV format). _(runs until STOP)_ |

### WiFi · Sniff

| Command | Sends | What it does |
|---|---|---|
| Sniff Raw | `sniffraw` | Capture raw 802.11 frames to PCAP. _(runs until STOP)_ |
| Sniff Beacons | `sniffbeacon` | Capture beacon frames. _(runs until STOP)_ |
| Sniff Probes | `sniffprobe` | Capture probe requests (what devices are looking for). _(runs until STOP)_ |
| Sniff Deauth | `sniffdeauth` | Detect deauth frames — useful defensively. _(runs until STOP)_ |
| Sniff ESP | `sniffesp` | Detect ESP-based devices nearby. _(runs until STOP)_ |
| Sniff Pwnagotchi | `sniffpwn` | Detect Pwnagotchi units. _(runs until STOP)_ |
| Sniff PMKID | `sniffpmkid` | Capture PMKID/EAPOL handshakes to PCAP (crackable). _(runs until STOP)_ |

### WiFi · Attack

| Command | Sends | What it does |
|---|---|---|
| Deauth (selected APs) | `attack -t deauth` | Kick all clients off selected AP(s). _(attack)_ |
| Deauth (selected clients) | `attack -t deauth -c` | Kick specific clients only. _(attack)_ |
| Beacon Spam (list) | `attack -t beacon -l` | Broadcast SSIDs from your list. _(attack)_ |
| Beacon Spam (random) | `attack -t beacon -r` | Broadcast random SSIDs. _(attack)_ |
| Beacon Spam (clone APs) | `attack -t beacon -a` | Clone scanned AP names. _(attack)_ |
| Probe Flood | `attack -t probe` | Flood probe requests. _(attack)_ |
| Rickroll Beacon | `attack -t rickroll` | Beacon-spam Rick Astley lyrics as SSIDs. _(attack)_ |
| Bad Msg (clients) | `attack -t badmsg -c` | Malformed frames at selected clients. _(attack)_ |
| Evil Portal | `evilportal -c start` | Captive portal credential harvester (needs HTML on SD). _(attack)_ |
| Karma | `karma` | Answer a device's probe to lure it onto your AP. _(attack)_ |

### Bluetooth

| Command | Sends | What it does |
|---|---|---|
| Sniff Bluetooth | `sniffbt` | Scan BLE devices; filter `airtag`/`flipper`/`flock`. _(runs until STOP)_ |
| BT Wardrive | `btwardrive` | GPS-tagged Bluetooth logging. _(runs until STOP)_ |
| Detect Skimmers | `sniffskim` | Scan for card-skimmer BLE signatures. _(runs until STOP)_ |
| BLE Spam | `blespam -t <type>` | Spam BLE pairing pop-ups (sourapple/applejuice/google/samsung/windows/flipper/all). _(attack)_ |
| Spoof AirTag | `spoofat` | Broadcast a cloned AirTag. _(attack)_ |
| Sour Apple / Swiftpair / Samsung / Spam All | `sourapple` … | Targeted BLE spam. _(attack)_ |

### Everything else

`list -a/-c/-s/-t` (show lists) · `select -a/-c/-s/-f` (pick targets) · `clearlist` · `info` ·
`ssid -a/-r` (manage SSID list) · `channel [-s n]` · `gpsdata`/`nmea`/`gps -g` ·
`ls`/`save`/`load` (SD card) · `settings -s <name> enable/disable` (e.g. SavePCAP) · `led` · `reboot` · `stopscan`.

> Full list with every flag is in *Help → Command Reference* and in
> [`marauder_core/commands.py`](marauder_core/commands.py).

---

## 4. Attack chains

This is where it gets interesting — recon feeds targeting, targeting feeds attacks, and the captures feed into other tools.

### A. Capture a WPA handshake and crack it

The classic chain. Deauth forces clients to re-handshake, you capture it, crack offline.

1. `settings -s SavePCAP enable` (once) and insert a FAT32 SD card.
2. **Scan APs** → **Select APs** (pick your target).
3. **Sniff PMKID** (`sniffpmkid`) — or `sniffpmkid -d` to deauth while sniffing so clients reconnect faster.
4. **STOP**. The `.pcap` is on the SD card.
5. On your PC:
   ```bash
   hcxpcapngtool -o hash.hc22000 capture.pcap     # convert
   hashcat -m 22000 hash.hc22000 wordlist.txt     # crack
   # or: aircrack-ng -w wordlist.txt capture.pcap
   ```

### B. Targeted deauth (surgical)

1. **Scan All** (`scanall`) to map APs and their clients at the same time.
2. **Select Stations** → pick a specific device.
3. **Deauth (selected clients)** — drops just that one device instead of blasting everyone.

### C. Evil Portal credential capture

1. Put your `index.html` (and optional `ap.config.txt`) on the SD card.
2. **Scan APs** → **Select APs** (the AP to impersonate).
3. **Evil Portal** (`evilportal -c start`) — enable EPDeauth in settings to deauth the real AP so
   clients land on yours. Captured credentials are written to the SD card.

### D. Wardriving → map it on WiGLE
1. Plug in a GPS module (NMEA over serial, or shared via `gpsd`).
2. **Wardrive** (`wardrive`) while moving — writes a **WiGLE-format CSV** (`wardrive_*.csv`) to SD.
3. Upload that CSV to **wigle.net** (counts toward your stats / builds a coverage map).

### E. Find who's following you (BLE)
1. **Sniff Bluetooth** `sniffbt -t airtag` to surface trackers; `-t flock` for Flock cameras.
2. **MAC Track** a suspicious MAC to gauge proximity as you move.
3. Correlate sightings over time/location with a tool like **Chasing Your Tail NG**.

### F. Probe-sniff → Karma lure
1. **Sniff Probes** to learn which SSIDs nearby devices are searching for.
2. **Scan APs** → **Select APs** (the AP you're impersonating).
3. **Evil Portal** (`evilportal -c start`) — turn on EPDeauth in settings to knock clients off the real AP so they land on yours. Creds get saved to SD.

### D. Wardriving

1. Plug in GPS (the deck can share one GPS via `gpsd`).
2. **Wardrive** (`wardrive`) while moving — writes a WiGLE-format CSV to SD.
3. Upload that CSV to [wigle.net](https://wigle.net) for mapping.

### E. Tracker detection (BLE)

1. **Sniff Bluetooth** `sniffbt -t airtag` to find trackers; `-t flock` for Flock cameras.
2. **MAC Track** a suspicious MAC to see if it follows you.

### F. Probe-sniff into Karma

1. **Sniff Probes** to see what SSIDs nearby devices are searching for.
2. Add those to your SSID list (`ssid -a -n <name>`).
3. **Karma** to answer those probes and get devices to connect.

---

## 5. Data & logging

Turn on **● Log** (or pass `--log [dir]`, defaults to `~/marauder-logs`). It writes in real-time:

| File | Format | Good for |
|---|---|---|
| `serial-<ts>.log` | Raw text | `tail -f` from another terminal; grep; replay |
| `latest.json` | JSON | Poll from a script for current APs + stations + status |
| `aps.csv` / `stations.csv` | CSV | Import into a spreadsheet, pandas, whatever |

Files are atomic and append-only, so another process can read them while the app is running:

```bash
tail -f ~/marauder-logs/serial-*.log                 # live stream
watch -n1 'jq ".ap_count,.station_count" ~/marauder-logs/latest.json'
```

PCAP, evil portal captures, and wardrive CSVs live on the board's SD card (use `ls` / `save` to manage).

---

## 6. Works with

- **Your own dashboard** — `marauder_core` is importable; build a dashboard on it to show Marauder
  beside other tools (Kismet/Meshtastic/GPS).
- **Kismet** — run Kismet on the Pi for deep WiFi mapping while Marauder does active attacks; both
  can share the **same GPS** via `gpsd` (`localhost:2947`).
- **Wireshark / hashcat / aircrack-ng / hcxtools** — for PCAP analysis and cracking (chain A).
- **WiGLE** — wardrive CSVs (chain D).
- **Flipper Zero** — pair sub-GHz/RFID/NFC/IR work (Flipper) with WiFi/BLE (this) for full coverage.
- **The cyberdeck** — `marauder_core` is importable; the deck's dashboard reuses it alongside Kismet, Meshtastic, and GPS.
- **Kismet** — run it on the Pi for passive WiFi mapping while Marauder handles active attacks. Both can share GPS via `gpsd`.
- **Wireshark / hashcat / aircrack-ng / hcxtools** — for PCAP analysis and cracking.
- **WiGLE** — for wardrive map uploads.
- **Flipper Zero** — pair sub-GHz/RFID/NFC/IR work with WiFi/BLE from this.

---

## 7. Flashing

⚡ **Flash Firmware** → pick the **Firmware** → **Detect chip** → **Load release list** → pick a variant →
**Update app only** (existing board) or **Full flash** (blank board). Uses `esptool` with
`--flash_size detect`. Classic ESP32 Gold → a non-S3 variant (e.g. *old_hardware*); S3 → *MultiBoard S3*.
⚡ **Flash Firmware** → **Detect chip** → **Load release list** → pick a variant → **Update app only** or **Full flash**. Uses `esptool` with `--flash_size detect`. Classic ESP32 (Gold) → a non-S3 variant (usually *old_hardware*); S3 → *MultiBoard S3*.

### Firmware types (the Firmware selector)

The flasher reuses one esptool pipeline for several firmwares. Pick from the **Firmware** dropdown:

| Firmware | What it is | How it flashes | Suicide build? |
|---|---|---|---|
| **ESP32 Marauder** *(default)* | The full native control app this tool is built around — live tables, target picker, every command (everything in §1–§6 above). | Pulls the right variant from the official Marauder GitHub release and flashes at the correct offsets. | **Yes — Marauder only** (§8). |
| **ESP32-DIV** ([cifertech/esp32-div](https://github.com/cifertech/esp32-div)) | A separate standalone ESP32 firmware. **Flash-only here** — once it's on the board it runs on its own; this app has no native control panel for it. | Fetches the official ESP32-DIV image and its boot chain and flashes them byte-for-byte. | No. |
| **Custom / local `.bin`** | Any other ESP32 firmware you have a `.bin` for. | You point the flasher at a local `.bin`; it flashes with chip-appropriate default offsets. Nothing is downloaded. | No. |

> **ESP32-DIV jamming features are illegal to operate and are NOT part of this tool.** ESP32-DIV
> ships RF-jamming functionality that is illegal to use in most jurisdictions (e.g. FCC rules).
> This tool only **flashes** the official ESP32-DIV image — it adds, enables, and controls **none**
> of that. What the firmware does after it's flashed is entirely your responsibility (see [Legal](#legal)).

> The **Firmware** selector is purely additive: leave it on **ESP32 Marauder** (the default) and the
> entire app — control panel, tables, attacks, logging, and the Suicide path — behaves exactly as
> documented in this guide.

> **Tooltips:** every flasher control — including the **Firmware** selector, the **Suicide** checkbox
> and its bundle-dir field — has a hover tooltip explaining what it does.

---

## 8. Suicide build & flashing it (anti-forensic, opt-in)

This is an **optional, owner-only, defensive** layer that **applies to the ESP32 Marauder firmware
only** — it has no meaning for ESP32-DIV or Custom firmware. With the **Firmware** selector on
ESP32 Marauder (the default), plain Marauder is still the default; the suicide path is gated behind
a single **Suicide** checkbox and changes nothing unless you tick it.

### What it is
A hardened Marauder variant that can **wipe its own secrets** so a lost or seized board protects
the data on it. The provisioned bundle bakes in:
- a **boot password** gate (the board won't come up without it),
- a **2-fail wipe** (too many wrong password attempts triggers the configured wipe),
- a **GPIO dead-man** trigger (a pin/check-in the owner controls; if it's tripped/stops, the
  protective action runs).

This app does **not** build, configure, hash, or arm any of that. It only **flashes** an image
that was already provisioned elsewhere.

### Where it's built: the Suicide-Marauder repo
You build and provision the bundle in the **separate private repo
[LxveAce/Suicide-Marauder](https://github.com/LxveAce/Suicide-Marauder)** (its `host/` provisioner).
That repo does all the sensitive work — password hashing, guard configuration, and any eFuse /
flash-encryption (T2) burning. The provisioner emits a **bundle**: a directory holding a
`bundle.json` manifest plus the firmware `.bin` images and their flash offsets.

> Read the Suicide-Marauder repo's **SAFETY.md** first, and don't let this guide contradict it —
> the provisioning repo is the source of truth for how the protections behave and how to arm them.

### Flashing the bundle from here
1. Build + provision the bundle in the Suicide-Marauder repo (follow its README/SAFETY.md).
2. In the flasher, tick the **Suicide** checkbox and point its field at the **bundle directory**
   (the folder containing `bundle.json` and the `.bin` files).
3. **Detect chip** — the manifest names the chip it was built for; the flasher warns if it
   disagrees with the detected chip (a mismatch will likely fail or brick the board).
4. **FLASH** — it writes every offset/image pair from the manifest in one
   `write_flash -z --flash_size detect`. No eFuses are burned here; no T2 is performed here.

### Safety
- **Test `SUICIDE_SAFE_MODE` first.** Provision and run the bundle in the Suicide-Marauder repo's
  safe mode before any live build, so you can confirm the password gate and triggers behave as
  expected **without** performing a destructive wipe. Validate the whole flow in safe mode, then
  graduate to the real build.
- **T2 / flash encryption is irreversible.** If the bundle was provisioned to burn T2
  (flash-encryption eFuses), that is a **one-way, permanent** change to the chip — it cannot be
  undone. Be certain before flashing such a bundle.
- This is for **your own** hardware only, as a duress/loss/seizure safeguard — not an attack tool.

---

## Legal

For **authorized security testing only** — networks/devices you own or have **written permission**
to test. Deauth, evil-portal, beacon/BLE spam, and karma can be illegal against others (US CFAA,
FCC rules, and equivalents). Many modern networks ignore deauth (802.11w/PMF). You are responsible
for your use. See the firmware's own [legal notes](https://github.com/justcallmekoko/ESP32Marauder).

**ESP32-DIV (optional flash target):** its RF-**jamming** features are **illegal to operate** in
most jurisdictions (e.g. FCC rules) and are **NOT part of this tool** — this app only *flashes* the
official ESP32-DIV image and neither enables nor controls any such feature. What that firmware does
once it's on the board is entirely your responsibility.
**Authorized testing only** — networks and devices you own or have written permission to test. Deauth, evil portals, beacon/BLE spam, and karma can be illegal against other people's stuff. Many modern networks ignore deauth anyway (802.11w/PMF). You are responsible for what you do. See the firmware's own [legal notes](https://github.com/justcallmekoko/ESP32Marauder).
