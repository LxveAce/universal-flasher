# LxveAce/universal-flasher - Forward Plan

> Status: beta, shipping — latest release **v1.4.0**. The version's unified across `uf_core`, `pyproject`, and
> the CHANGELOG, and the ESP32-C5 bootloader-offset fix is in. Health: green. Last revised 2026-07-01. The old
> P0s further down (esptool bundling, four-way version drift, cutting a clean release) are all done — kept for
> history. Current direction: this repo is the shared, UI-free flash **engine**; active planning lives in command-center.

> **⭐ MAJOR DIRECTION (2026-06-29): this repo is becoming the home of a single, UI-free flashing ENGINE
> (firmware + OS catalogs, backends, parsers, per-board offsets) plus a light standalone UI. Cyber
> Controller will consume that engine as a dependency rather than carrying its own copy, ending the
> two-codebase drift. The engine is seeded from Cyber Controller's flash core (the more complete base).
> Goal: adding a new firmware/OS/board = drop one data file. The "cross-repo de-dup" dig-deeper item
> below is folded into this effort. Staged, test-gated, with a real-hardware flash before any release.**

Public repo. Frame all security work as responsible hardening; do NOT publish step-by-step exploit/evasion recipes. Commit as LxveAce, no Claude co-author, no PII.

## Progress — 2026-06-27 (this session)

- **P0-1 DONE + build-verified:** frozen binaries can flash ESP32 again. Root cause was deeper than
  "missing data": esptool ran via `sys.executable -m esptool`, which is the app (not Python) when
  frozen. `flasher.esptool_argv()` is now frozen-aware (re-execs the app as a multi-call esptool
  runner; `gui_qt/app.py` dispatches `--__uf-esptool__` -> `esptool.main()`), and `build.py` uses
  `--collect-all esptool`. Verified on a real build: `universal-flasher.exe --__uf-esptool__ version`
  -> `esptool v5.3.0`; 24 stub_flasher JSON bundled. (commit `d8ec823`)
- **P0-2 DONE:** version unified to **1.3.1** (`uf_core/__init__` + `pyproject.toml` + CHANGELOG); UIs
  read `uf_core.__version__`; added the CHANGELOG entry; fixed 5 CHANGELOG link refs that wrongly
  pointed at the headless-marauder-gui repo. Removed the dead `build.py` ICON variable.
- **P0-3 (cut release) PREPARED, not cut:** everything is ready for **v1.3.1**, but per the plan the
  binaries must be hardware-flash-verified on a real ESP32 before re-publishing — left for the owner
  to `gh release create v1.3.1` after that check.
- **Feature directives (Tails flashing, physical-key gate): FLAGGED for the consolidation decision.**
  Canonical, tested implementations already live in **cyber-controller** (the convergence flagship
  that supersedes this repo). Per the agreed approach, not duplicating ~800 lines into the superseded
  4-frontend structure until you decide: port here vs. point users to cyber-controller. (`uf_core`
  already has `sd_backend` for the Tails writer; an access gate would need a `win_acl` port + wiring
  all four front-end `main()`s.)

## Where this stands

**What it is:** A Python multi-firmware flasher and device manager for ESP32 (Marauder, GhostESP, Bruce, HaleHound, Meshtastic, and more), Raspberry Pi (SD-image: Pwnagotchi, RaspyJack, Kali ARM), Flipper Zero (via qFlipper hand-off), and ADB-based security hardware (Orbic RC400L / RayHunter). A shared core library `uf_core/` (flasher, controllers, device_detect, sd_backend, adb_backend, cache, history, plugins, batch, backup, health, updater) is consumed by four interchangeable front-ends: PyQt5 desktop (`gui_qt/app.py`), Tkinter desktop (`gui/app.py`), Textual TUI (`tui/app.py`), and Flask+SocketIO web UI (`web/app.py`). Flashing is profile-driven — one `FirmwareProfile` subclass per ESP32 firmware (GitHub-release asset discovery + esptool chip auto-detect), with Pi/USB images handled separately by `sd_backend.py`. A vendored `suicide/` tree holds anti-forensic firmware sources + a provisioner.

**Lineage (per cross-repo recon):** headless-marauder-gui -> **universal-flasher (this repo)** + universal-flasher-ui (alpha v0.1.0, now superseded) -> cyber-controller (current flagship convergence, merges all three + built-in Dead Man's Switch). This repo is the **focused, standalone flasher** in that lineage — not the convergence point. NOTE: the orchestration premise that universal-flasher-ui is the planned successor is stale; cyber-controller is the real successor.

**How to build/run:**
- Install: `pip install -e .[all]` (extras: `[qt]`/`[tui]`/`[web]`/`[all]`). Console scripts: `universal-flasher-{qt,tk,tui,web}` -> `{gui_qt,gui,tui,web}.app:main`.
- Standalone binaries: `python build.py --onefile` (PyInstaller). CI builds all 4 platforms on each GitHub release via `.github/workflows/build-release.yml`.

**Current state:** `import uf_core` compiles on 3.13 and the release workflow ships all four platform assets. Version is unified at **1.4.0** everywhere, and the two defects that used to gate confidence are both fixed: the binaries now bundle esptool's runtime data (`build.py` uses `--collect-all esptool`, so a frozen build actually flashes ESP32), and the version metadata is consistent. No open issues. The repo is healthy, and its role now is the shared, UI-free flash engine (see the direction note up top).

## P0 — DONE (historical, kept for provenance)

> All three P0s below shipped by **v1.4.0**: esptool data is bundled (`build.py` → `--collect-all esptool`),
> the version is unified to 1.4.0 in all four places, and a clean release was cut. Left here so the history reads straight.

1. **Fix esptool data bundling in the release binaries (the headline feature is probably broken).** `build.py` bundles esptool via `--hidden-import esptool` only (build.py:44) and its `DATA_FILES` (build.py:53-57) never collects esptool's package data (flasher-stub / targets JSON). `--hidden-import` pulls the module but NOT its data files — the documented PyInstaller+esptool pitfall. Since esptool is the flash backend for every ESP32 firmware, all 4 prebuilt binaries likely fail ESP32 flashing with a missing-stub/targets error. Fix with PyInstaller `--collect-data esptool` (or `--collect-all esptool`, or a runtime hook). **Then VERIFY**: build a binary and confirm it actually detects + flashes a real ESP32 before re-publishing. (Source/pip installs are unaffected — they use the system esptool with data intact.)
2. **Unify the four-way version.** `uf_core/__init__.py:5` says `1.0.0` (this is what the Qt About dialog gui_qt/app.py:1158 and web/app.py:106 show users), `pyproject.toml` says `1.1.0`, the published release is `v1.1.1`, and `CHANGELOG.md` top header is `[1.3.0]`. Pick ONE next number, set it in all four places, add the missing CHANGELOG entry for the already-published v1.1.1, and resolve the orphaned 1.3.0 header (drop or promote). Today users on v1.1.1 see "v1.0.0" in the UI.
3. **Cut a fresh, correct release.** v1.1.1 is 7 commits behind main and omits real fixes (notably the 4MB guardcfg NVS fix "0x2000 -> 0x3000, gate now activates", and an HW-validated suicide build). After (1) and (2), tag + publish so shipped source AND binaries carry those fixes and a working esptool bundle.

> The orchestration note about an .exe/installer issue belongs to **cyber-controller** (the convergence/flagship that ships the installer), not this repo. For universal-flasher the equivalent P0 is the esptool-binary breakage above. Confirm cyber-controller's installer state separately — no recon report verified it.

## Surface bugs found

| Title | Location | Severity | Note |
|---|---|---|---|
| Release binaries likely cannot flash ESP32 (esptool package data not bundled) | build.py:44 + build.py:53-57; shipped by build-release.yml | P1 | `--hidden-import` includes module not data (stub/targets JSON). Pip/source installs unaffected. Inferred from code + known pitfall; not runtime-proven. |
| Four-way version mismatch (1.0.0 / 1.1.0 / v1.1.1 / 1.3.0) | uf_core/__init__.py:5; pyproject.toml; CHANGELOG.md:3; surfaced gui_qt/app.py:1158, web/app.py:106 | P2 | Users on v1.1.1 binary see "v1.0.0"; no CHANGELOG entry for v1.1.1; unreleased 1.3.0 header. |
| Latest release 7 commits behind main, omits functional fixes | v1.1.1...main ahead_by 7 (e.g. 73ed8d30, fd6ad03a) | P2 | Shipped binaries lack the guardcfg NVS fix and an HW-validated build. |
| pip wheel won't bundle suicide/ non-Python resources | pyproject.toml package-data (only *.md/*.svg/*.json); suicide/{docs,firmware,partitions,scripts} lack __init__.py | P2 | Wheel omits *.csv/*.cpp/*.h/*.ino.patch/*.ps1/*.sh/*.template. May be by design (binaries-only) — confirm intent. |
| build.py computes ICON path but never uses it | build.py:19 | P3 | Dead variable; no custom icon. PyInstaller --icon needs .ico/.icns, not the shipped .svg anyway. |

## Features to add

**USER DIRECTIVE 1 (verbatim): add Tails OS as a flashable target in the flasher.**
- Tails is a hybrid image written block-level to a USB stick — it maps onto the existing image writer in `uf_core/sd_backend.py`, NOT the esptool flasher. Add a `tails` entry to `PI_IMAGE_PROFILES` (sd_backend.py:98) or a parallel `USB_IMAGE_PROFILES` registry, and surface it through all four front-ends via `list_pi_profiles()`/`get_pi_profile()` (or new `list_usb_profiles()`).
- Required deviations from the Pi profiles: (a) Tails is **x86 USB media, not an ARM SD card** — relabel UI strings and reconsider the "SD card" wording and the `<256 GB` ceiling (`_MAX_SD_BYTES`, sd_backend.py:39) for USB sticks; (b) downloads come from **tails.net / tails.boum.org**, which are NOT on the current `_ALLOWED_HOSTS` allowlist (sd_backend.py:45-52) — extend it narrowly; (c) **integrity verification is mandatory** for Tails — verify the published sha256 (ideally OpenPGP signature) before writing, reusing the existing hashlib verification in sd_backend.py.
- Keep the removable-only + size-sanity safety invariants intact (never target a fixed/system disk).

**USER DIRECTIVE 2 (verbatim): "create physical key" access gate - admin password AND/OR physical USB key present to access the software.**
- Add a new `uf_core/access_gate.py` that runs BEFORE any front-end `main()` (gui_qt/gui/tui/web `app:main`) grants access. Logic: allow if **(admin password verifies) AND/OR (a recognized physical USB key is present)**.
- Detect the USB key via the existing removable-drive/volume enumeration already in `sd_backend.py`, plus a key-file or volume-serial fingerprint. Store only a **salted password hash** (never plaintext), config under `~/.universal-flasher/`.
- **Port/adapt cyber-controller's `src/core/deadman_auth.py`** (CTX recon) rather than reinventing.
- For the **web UI**, integrate with the existing WebSocket auth-token flow. Provide a documented **headless/CI bypass** so the release build and automation are not locked out. Document clearly that this is a **usability gate, not a cryptographic boundary**, and define the lost-key recovery story.

**Supporting features:**
- Reconcile CHANGELOG (add v1.1.1 entry; resolve [1.3.0] header) as part of the version unification.
- Add lightweight CI beyond the release-only workflow: a compile/import smoke job (`python -m compileall` + `import uf_core`), and ideally a packaged-binary smoke test asserting esptool data is present — to auto-catch the P0-1 class of bug.

## Red-team / hardening

- **Audit the README-claimed web controls** (NOT independently verified in recon): HTTPS-only / host allowlist, redirect hardening, path-traversal guard on bundle extraction, TOCTOU staging, WebSocket auth token. Confirm each line-by-line; modules exist but correctness is unproven.
- **Access gate (directive 2):** salted+hashed password only; present it honestly as a UI gate, not crypto protection; document its threat model; ship an explicit, documented headless/CI bypass that an unprivileged user cannot trivially toggle at runtime.
- **Tails (directive 1):** enforce sha256 (ideally OpenPGP) verification BEFORE writing (high-value tampering target); extend the SSRF allowlist to the exact tails hosts only, not a broad loosening; keep removable-only + size guards so the writer can never hit a system disk.
- **Keep the two download allowlists consistent:** flasher.py and sd_backend.py each maintain their own; update the right one and audit both as a unit when adding a host.
- **Profile/confidentiality rules (PUBLIC repo):** commit as LxveAce, no Claude co-author, no PII. Recon flagged real-name/EMR-license PII in the PRIVATE session-context repo — never leak it here. Keep all anti-forensic/suicide and gate docs at the responsible-hardening level.

## Dig deeper (next dedicated session)

1. **Run the prebuilt binaries (all 4 platforms)** and confirm whether ESP32 flashing fails with a missing esptool stub/targets error — convert P0-1 from inferred to runtime-proven; re-test after the build.py fix.
2. **Determine esptool invocation style** in uf_core/flasher.py (imported module vs subprocess) — changes how the missing-data bug manifests and how to bundle the fix.
3. **Hardware-in-the-loop pass:** real ESP32 flash (incl. the ESP32-C5 0x2000 bootloader gotcha), SD/USB image writes, ADB (RayHunter/Orbic), qFlipper hand-off — none testable in static recon.
4. **Web security line-by-line audit** of the README-claimed controls (allowlist, redirect hardening, path-traversal guard, TOCTOU, WebSocket auth).
5. **Cross-repo de-dup study:** diff uf_core/ vs cyber-controller src/core (backends, protocols, deadman_auth.py) and universal-flasher-ui src/core to decide PORT vs reinvent for both directives. Recon could not confirm whether cyber-controller's flash core is shared, vendored, or rewritten.
6. **Confirm suicide/ packaging intent** (wheel vs binaries-only); if shipping, add MANIFEST.in / package-data globs and/or build.py DATA_FILES.
7. **Verify dep availability:** esptool `>=4.7,<6` upper bound and `esp-idf-nvs-partition-gen==0.2.0` pin against upstream; confirm the pinned esptool's exact data-file layout when fixing build.py.
8. **Hunt for the branch behind the orphaned [1.3.0] CHANGELOG header** before deleting it (local clone is a single squashed commit; no branches inspected beyond HEAD).

## Dependencies & cross-repo context

- **Runtime (requirements.txt):** pyserial, textual, esptool>=4.7,<6, flask, flask-socketio, requests, psutil, esp-idf-nvs-partition-gen==0.2.0.
- **Packaging (pyproject.toml):** setuptools; extras [qt]/[tui]/[web]/[all]; console scripts `universal-flasher-{qt,tk,tui,web}` -> `{gui_qt,gui,tui,web}.app:main` (all define main()).
- **Build/release:** build.py (PyInstaller --onefile); build-release.yml builds Windows x64 / macOS arm64 / Linux x64 / Linux arm64 per release.
- **Lineage:** headless-marauder-gui -> universal-flasher (this repo) + universal-flasher-ui (superseded) -> cyber-controller (flagship convergence + built-in Dead Man's Switch). Reuse from cyber-controller: `src/core/deadman_auth.py` (directive 2), backends/protocols/21 profiles (avoid re-duplicating).
- **External services:** GitHub Releases API (firmware discovery); kali.download (already allowlisted); **tails.net/tails.boum.org (NEW, needed for directive 1)**.
- **Public hubs:** esp32marauder.com (homepage), cybercontroller.org, lxveace.com, Discord discord.gg/lxvelabs.

## Open questions

- Is universal-flasher still getting NEW features, or maintenance-only while cyber-controller absorbs new work? READMEs say "recommended for day-to-day flashing" but state no feature freeze; the two directives imply ongoing work — confirm before large investments.
- Does flasher.py call esptool as an imported module or a subprocess?
- Which single version should the line converge on — 1.1.x or 1.3.0? Is there an unpushed branch explaining the 1.3.0 header?
- Are suicide/ non-Python resources meant to ship in the pip wheel, or is distribution binaries-only?
- Directive 1: ride sd_backend.py's writer (recommended) or a dedicated USB-image backend? sha256 only, or full OpenPGP chain?
- Directive 2: usability gate or real security boundary? Lost-key recovery/bypass story? Web + headless/CI handling?
- Is cyber-controller's flash core shared code, a vendored copy, or a rewrite of this repo's?
- cyber-controller is the installer-shipping flagship per the orchestration note, but no recon verified its current release/installer state — confirm before assuming it is release-ready.


## Owner feature directives — unified flashing + auto-update + offline + UX (2026-06-27)

Committed roadmap for the flasher line. **cyber-controller and universal-flasher implement the
FLASHING parts CONSISTENTLY (shared engine + catalog); their ROLES differ (see below).** These are
to be kept in sync across both repos.

### 1. Flash more, all in one — firmware vs software, in separate tabs
- Make flashing all-in-one, split into clearly separated tabs so the two audiences never collide:
  - **Firmware tab (hardware projects):** the existing ESP32 firmwares (Marauder, GhostESP, Bruce,
    HaleHound, Meshtastic, ...) + Pi/SBC SD-image firmwares. Add as many more as feasible.
  - **NEW Software tab (PC / USB operating systems):** bootable OS images written to a USB stick —
    **Kali Linux, Tails OS, Arch Linux**, and as many others as feasible (Ubuntu/Debian/Parrot, and a
    Ventoy-style multiboot stretch goal). Reuses the hardened **removable-only raw-image writer +
    mandatory integrity verification** (sha256 / signature) already used for Tails.

### 2. Auto-updating catalog + app, with FULL offline utility
- **Catalog auto-update:** keep the flashable firmware/OS definitions as current as possible
  automatically — resolve each upstream's latest version (GitHub Releases API for ESP32 firmwares;
  official version/checksum/signature feeds for Kali / Tails / Arch / etc.) and refresh the bundled
  profiles. Do it two ways: (a) a **scheduled CI job** (GitHub Action) that updates the profile JSON +
  pinned checksums in the repo so the shipped catalog never goes stale, and (b) an **in-app
  "check for catalog updates"** that pulls the latest profile manifest.
- **App auto-update:** keep the existing self-update path; every project in this line ships auto-update.
- **Offline utility (mandatory, non-negotiable):** everything must work with NO internet — a cached
  catalog + already-downloaded images flash fully offline. Auto-update is an enhancement, never a
  requirement to use the tool in the field.

### 3. UX — discoverability everywhere
- **Hover tooltips on EVERY control** explaining what it does (extend the existing tooltip/glossary
  pattern to 100% coverage).
- **A thorough "How To" / tutorial tab** that walks through every feature, tab, and button with
  step-by-step usage — first-run friendly, offline, and kept in sync as features land.

### Role: universal-flasher = STRICTLY a flasher
universal-flasher stays focused: the unified firmware + software flashing above, auto-updating
catalog, offline utility, tooltips, and How-To tab — and nothing else. **No controller / logger /
wardriving** (those live in cyber-controller). The flashing engine + catalog manifest should be the
shared, consistent core between the two repos so a firmware/OS added in one is trivially available in
the other.

