# FORK Integration Guide — wiring the boot-gate into ESP32 Marauder

> Owner-only, **defensive** anti-forensic ("duress") layer for a Marauder *you own*. Not for
> evading lawful process. Read [`SAFETY.md`](../../docs/SAFETY.md) and
> [`THREAT-MODEL.md`](../../docs/THREAT-MODEL.md) first. Canonical contract:
> [`docs/SPEC.md`](../../docs/SPEC.md).

This document covers the **FORK** variant (SPEC §1, the default for all flash sizes incl. 4 MB):
the gate is compiled *into* a fork of ESP32Marauder and called once from `setup()`, reusing
Marauder's own display / keyboard / SD drivers. GUARDIAN (SPEC §1, 8 MB+) is templated by
`../partitions/suicide_guardian_16MB.csv` but is **not** the path described step-by-step here.

**Always build and test `SUICIDE_SAFE_MODE` first** (SPEC §5). In SAFE mode the entire
detect → arm → trigger → erase chain runs against a scratch partition + dummy key and only
**logs** the simulated destruction; nothing is erased. Only after the full flow is observed in
SAFE mode should you consider a live (non-SAFE) build, and only T1 first.

---

## 0. What you are adding

Five headers + their `.cpp` implementations live in [`../bootgate/`](../bootgate/):

| File | Role |
|------|------|
| `GateConfig.h/.cpp` | load `guardcfg` NVS (namespaces `sgate`, `sgate_rt`) into `GateConfig` |
| `BootGate.h/.cpp`   | the state machine — `suicide::BootGate::run()` |
| `ArmingSwitch.h`    | read the hardware dead-man / arming GPIO |
| `GateCrypto.h/.cpp` | PBKDF2-HMAC-SHA256 verify (mbedtls), constant-time compare |
| `SelfDestruct.h`    | best-effort secure erase (SAFE-mode gated) |
| `GateInput.h` + `GateInput_<class>.cpp` | board-agnostic password entry (exactly one adapter) |

The integration is **two edits to one file** plus build configuration:

1. `#include "esp_system.h"` (for `esp_restart`) and `#include "bootgate/BootGate.h"` near
   Marauder's other includes.
2. A single **fail-closed** gate call inserted **after** `display_obj.RunSetup()` and **before**
   `settings_obj.begin()` (SPEC §1, §6):

   ```cpp
   if (suicide::BootGate::run() != suicide::GATE_PASS) { esp_restart(); }
   ```

   The return value is **checked**, not discarded: only `GATE_PASS` is allowed to continue into
   Marauder. Any other result reboots (see §2 for why this matters).

Everything else is build flags, a partition CSV, and a flashed `guardcfg` image. The exact patch
is in [`esp32marauder.ino.patch`](esp32marauder.ino.patch); the PlatformIO env templates are in
[`platformio.ini.example`](platformio.ini.example).

---

## 1. Add `firmware/bootgate` to the build

The bootgate sources must compile alongside Marauder's `.ino`/`.cpp` files in the
`esp32_marauder/` sketch folder (the Arduino sketch directory the upstream repo calls
`esp32_marauder`).

### Option A — arduino-cli / Arduino IDE (sketch-relative)
Arduino compiles every `.cpp`/`.h` it finds in the sketch folder and in a `src/` subfolder. Copy
or symlink the gate sources into the sketch tree:

```
esp32_marauder/
├── esp32_marauder.ino          # upstream, patched (see §3)
├── configs.h ...               # upstream
└── bootgate/                   # <-- add this folder (the include path used by the patch)
    ├── BootGate.h   BootGate.cpp
    ├── GateConfig.h GateConfig.cpp
    ├── GateCrypto.h GateCrypto.cpp
    ├── ArmingSwitch.h
    ├── SelfDestruct.h          (+ SelfDestruct.cpp when present)
    ├── GateInput.h
    └── GateInput_serial.cpp    (+ the other GateInput_<class>.cpp adapters)
```

> The patch uses `#include "bootgate/BootGate.h"`. If you instead drop the files flat into
> `esp32_marauder/`, change the include to `#include "BootGate.h"`. Keeping them in a `bootgate/`
> subfolder keeps the GPL fork diff small and obvious.

On Windows, prefer a real copy over a symlink (Arduino's file walker is inconsistent with
junctions). A `robocopy ..\bootgate esp32_marauder\bootgate` in CI is reliable.

### Option B — PlatformIO (out-of-tree, preferred for CI)
PlatformIO can pull the gate in without copying, via `build_src_filter` / `lib_extra_dirs` or a
`+<...>` include. See [`platformio.ini.example`](platformio.ini.example): each env adds

```ini
build_flags = ... -I${PROJECT_DIR}/../bootgate
build_src_filter = +<*> +<../bootgate/>
```

so `../bootgate/*.cpp` is compiled and `../bootgate` is on the include path. This keeps the
upstream Marauder tree pristine except for the single patched `.ino`.

---

## 2. The insertion point (real anchors, not line numbers)

Inspected source: `esp32_marauder/esp32_marauder.ino` from
`github.com/justcallmekoko/ESP32Marauder` (shallow clone, current `master`). Do **not** rely on
absolute line numbers — upstream re-numbers this region every release. Anchor on the surrounding
code instead.

**Include anchor.** Marauder's last core include before the global object declarations is:

```cpp
#include "settings.h"
#include "CommandLine.h"
#include "lang_var.h"
```

Add both `#include "esp_system.h"` (for `esp_restart()`, used by the fail-closed hook) and
`#include "bootgate/BootGate.h"` immediately after `#include "lang_var.h"`.

**Call anchor.** Inside `void setup()`, the display comes up here (guarded by `HAS_SCREEN`):

```cpp
  #ifdef HAS_SCREEN
    display_obj.RunSetup();
    display_obj.tft.setTextColor(TFT_WHITE, TFT_BLACK);
  #endif
```

and settings/SD/SPIFFS initialization begins at:

```cpp
  settings_obj.begin();
```

Between those two there is brightness init, the splash-screen `drawCentreString` calls,
`backlightOn();`, and the `HAS_BUTTONS` stealth-mode check. **Insert the gate call on the line
immediately before `settings_obj.begin();`** — i.e. after the display + backlight are fully up
(so the touch / mini-kb / Cardputer password UI can draw) but before any persistent settings,
SPIFFS, or SD work. This matches SPEC §1 ("after `display_obj.RunSetup()`, before
`settings_obj.begin()`") and SPEC §6 ("called once, early in `setup()`").

```cpp
  // === Suicide Marauder boot-gate (FORK). Owner-only defensive duress layer. SPEC §1, §6. ===
  // Unprovisioned OR master-disarmed -> GATE_PASS (behaves like plain Marauder, cannot wipe).
  // FAIL-CLOSED: only GATE_PASS continues into Marauder; anything else reboots.
  if (suicide::BootGate::run() != suicide::GATE_PASS) { esp_restart(); }
  // A real (non-SAFE) trigger never returns. In SUICIDE_SAFE_MODE it logs and returns GATE_PASS.

  settings_obj.begin();
```

**Why the result is checked, not discarded (fail-closed).** Calling `suicide::BootGate::run();` and
throwing away the return value means the *only* thing that can stop a boot is a SelfDestruct that
**never returns**. But self-destruct is best-effort (SPEC §8): with `brick=0` (T1) the wipe returns,
a partial/failed erase returns, and any future code path that returns `GATE_TRIGGERED` instead of
looping forever would silently fall through into the **un-gated** Marauder UI — exactly the bypass we
are closing. Checking `!= suicide::GATE_PASS` and calling `esp_restart()` makes the hook fail
*toward* not-booting: only an explicit `GATE_PASS` (unprovisioned, master-disarmed, or correct
password) is allowed past. `esp_restart()` re-enters `setup()`, so the gate re-evaluates from a clean
state on the next pass (e.g. `att_ct` already at `max_att` ⇒ it triggers again), rather than handing
control to Marauder. This preserves every safe-default invariant — unprovisioned, master-disarmed,
and correct-password all return `GATE_PASS` and boot normally; SAFE_MODE still returns `GATE_PASS`
and performs zero real erases.

Why here and not the very first line of `setup()`:
- The display/backlight must be initialized for the touch / mini-kb / Cardputer adapters to render
  the prompt. Serial-only builds would tolerate an earlier call, but a single insertion point that
  works for **every** `GATE_INPUT_*` class is the design goal.
- It is still **before** `settings_obj.begin()`, `SPIFFS`, `sd_obj.initSD()`, `wifi_scan_obj`,
  and `cli_obj` — so no Marauder subsystem, persisted setting, or SD mount happens before the gate
  has either passed or wiped.

> The patch quotes these exact surrounding lines so a fuzzy/`patch -F3` apply still lands even if
> upstream shifts the region. See [`esp32marauder.ino.patch`](esp32marauder.ino.patch).

---

## 3. Apply the patch

From the upstream sketch root (the folder containing `esp32_marauder/`):

```bash
# anchor-based, line-number-tolerant
patch -p1 --fuzz=3 < firmware/integration/esp32marauder.ino.patch
# or, if applying from inside esp32_marauder/:
patch -p0 --fuzz=3 < ../firmware/integration/esp32marauder.ino.patch
```

If `patch` reports an offset (e.g. "Hunk #2 succeeded at 351 (offset 3 lines)") that is expected
and fine — the hunks are anchored on the quoted `display_obj.RunSetup()` /
`#include "lang_var.h"` / `settings_obj.begin();` context, not on absolute positions. If a hunk
*rejects*, open the `.rej`, find the two anchors by hand (§2), and insert the two lines manually.

---

## 4. Per-board build flags

Exactly **one** `GATE_INPUT_*` per build (SPEC §5). The input class should mirror the Marauder
hardware define already selected in `configs.h` for that board (`HAS_TOUCH` / `HAS_MINI_KB` /
`MARAUDER_CARDPUTER` / `HAS_BUTTONS`). Verified against upstream `configs.h` and the input
drivers: `keyboardInput(char*, size_t, const char*)` in `TouchKeyboard.cpp`,
`MenuFunctions::miniKeyboard(Menu*, bool do_pass)` in `MenuFunctions.cpp`.

| Board class | Marauder define | `GATE_INPUT_*` | Default `arm_pin` (SPEC §7) | `HAS_TOUCH` etc. | Min flash |
|-------------|-----------------|----------------|------------------------------|------------------|-----------|
| Classic ESP32 dev / Lonely Binary Gold | (none / `HAS_SCREEN`) | `GATE_INPUT_SERIAL` (or `_TOUCH` if TFT) | **GPIO27** (INPUT_PULLDOWN) | — | 4 MB |
| CYD 2.8" / 3.5" (`MARAUDER_CYD_*`) | `HAS_TOUCH` | `GATE_INPUT_TOUCH` | GPIO27 or a CN1/P3 broken-out pin | `HAS_TOUCH` | 4 MB |
| Marauder Mini / v3 (`MARAUDER_MINI*`) | `HAS_MINI_KB` | `GATE_INPUT_MINI_KB` | Grove **G2** (S3) | `HAS_MINI_KB` | 4–8 MB |
| M5Cardputer / ADV (`MARAUDER_CARDPUTER*`) | `HAS_MINI_KB` (QWERTY) | `GATE_INPUT_CARDPUTER` | Grove **G2** | `HAS_MINI_KB` | 8 MB |
| M5StickC / Plus / Plus2 (`MARAUDER_M5STICKC*`) | `HAS_BUTTONS`, `HAS_MINI_KB` | `GATE_INPUT_BUTTONS` (weak — prefer host-assisted serial) | Grove **G2** | `HAS_BUTTONS` | 4–8 MB |
| ESP32-C3 | — | `GATE_INPUT_SERIAL` | GPIO10 (avoid 2/8/9) | — | 4 MB |

Forbidden arm pins (strapping/boot, SPEC §7): classic `0,2,12,15`; S3 `0,3,45,46`; C3 `2,8,9`.
`GPIO34–39` are input-only → external 10 kΩ pulldown required, `arm_pull` is a HW no-op there
(`ArmingSwitch::pinIsInputOnly()` reports this; the host provisioner warns).

Arming-pin compile-time fallbacks (used only if `guardcfg` NVS is unset — real values live in NVS):

```
-DARMING_PIN=27 -DARMING_ACTIVE_LEVEL=1 -DARMING_PULL=2   # 0=none 1=pullup 2=pulldown
```

Common gate flags (SPEC §5):

| Flag | Meaning |
|------|---------|
| `-DSUICIDE_FORK` | select FORK variant (this guide). Mutually exclusive with `-DSUICIDE_GUARDIAN`. |
| `-DSUICIDE_SAFE_MODE` | **simulate only** — scratch partition + dummy key, logs, never destroys. Build this first. |
| `-DSUICIDE_TIER_T2` | expect Secure Boot v2 + Flash Encryption; flips `brick` + NVS-encryption defaults on. |
| `-DGATE_INPUT_<CLASS>` | exactly one of `SERIAL` / `TOUCH` / `MINI_KB` / `CARDPUTER` / `BUTTONS`. Omitting all defaults to `SERIAL` (see `GateInput.h` guard). |

---

## 5. Partition scheme / custom CSV selection

The gate needs the `guardcfg` (subtype `nvs`) partition. Names/subtype are canonical — host and
firmware both key off `guardcfg` (SPEC §3). Pick the CSV for your flash size:

| Flash | CSV | Notes |
|-------|-----|-------|
| 4 MB (classic ESP32 / CYD) | [`../partitions/suicide_4MB.csv`](../partitions/suicide_4MB.csv) | single app slot; Marauder SD-OTA self-update disabled (documented trade, SPEC §3.1) |
| 8 MB | [`../partitions/suicide_8MB.csv`](../partitions/suicide_8MB.csv) | dual app slot + roomier guardcfg |
| 16 MB | [`../partitions/suicide_16MB.csv`](../partitions/suicide_16MB.csv) | dual app slot, large spiffs, 64 KB guardcfg (SPEC §3.2) |
| 16 MB GUARDIAN | [`../partitions/suicide_guardian_16MB.csv`](../partitions/suicide_guardian_16MB.csv) | factory(Guardian)+ota_0(Marauder); not this guide's flow |

- **arduino-cli / IDE:** copy the chosen CSV to `partitions.csv` in the sketch folder and select a
  matching custom partition scheme, **or** pass `--build-property
  build.partitions=suicide_4MB --build-property
  build.custom_partitions=suicide_4MB` with the CSV on the boards' partitions search path. The
  simplest portable approach is to name the file `partitions.csv` in the sketch dir and choose the
  board's "custom" partition option.
- **PlatformIO:** `board_build.partitions = ../partitions/suicide_4MB.csv` (per env — see
  [`platformio.ini.example`](platformio.ini.example)). PlatformIO runs `gen_esp32part.py` itself.
- Never hardcode `otadata`/`nvs` offsets in tooling — read them from the chosen CSV (SPEC §2). App
  partitions must be 64 KB (`0x10000`) aligned or `gen_esp32part.py` errors.
- Bootloader offset branches by chip: **0x1000** classic ESP32 / S2, **0x0** on S3 / C3 / C6 / H2
  (SPEC §2). The build system handles this; the *flasher* must honor it.

After building you flash the gate config separately. `host/provision.py` (SPEC §10) produces
`guardcfg.bin` (sized to the `guardcfg` partition, built via `nvs_partition_gen`) plus a
`bundle.json` manifest of `{file, offset}` pairs. The flasher writes `guardcfg.bin` at the
`guardcfg` offset read from the CSV. A board with no `guardcfg` written is **unprovisioned** and
can never wipe (SPEC §6 step 2) — this is the safe default.

---

## 6. Build order: SAFE_MODE first, then T1, then (optionally) T2

This ordering is non-negotiable (SPEC §5, §8, §13).

### 6.1 SAFE_MODE (mandatory first)
Add `-DSUICIDE_SAFE_MODE`. The detect → arm → trigger → erase chain runs against a scratch
partition + dummy key and **only logs**. Provision a test `guardcfg` (a throwaway password),
verify on serial that:
- unprovisioned board passes through untouched;
- master-disarmed (`armed=0`) board passes through untouched;
- armed board with the dead-man line **not** in armed position logs `REASON_DEADMAN` and
  "(SAFE) would wipe …" without erasing;
- wrong password ×`max_att` logs `REASON_ATTEMPTS` and the simulated wipe order
  (SD → ota_0 → spiffs → nvs → coredump → guardcfg last);
- the **correct** password always boots and resets `att_ct`.

### 6.2 T1 (real wipe, reflashable — `brick=0`)
Remove `-DSUICIDE_SAFE_MODE`. Do **not** set `-DSUICIDE_TIER_T2`. `brick` defaults to 0, so a real
trigger bulk-erases data partitions + SD but leaves a re-flashable (data-wiped) board. **Test on a
sacrificial board only.** This is the dev/demo tier (SPEC §1, §8).

### 6.3 T2 (unrecoverable — `brick=1` + eFuse)
Add `-DSUICIDE_TIER_T2` **and** enable Secure Boot v2 + Flash Encryption (release mode) in the IDF
config. `brick` defaults to 1. The Stage-3 boot-chain self-erase is the one **UNVERIFIED**
primitive (SPEC §8, §13) — it is implemented behind `SUICIDE_SAFE_MODE` and documented in
[`docs/SPIKE-PLAN.md`](../../docs/SPIKE-PLAN.md); it requires
`CONFIG_SPI_FLASH_DANGEROUS_WRITE_ALLOWED=y`. Enabling eFuse Secure Boot/FE is **IRREVERSIBLE**.
Do this only after the spike succeeds on a sacrificial board. Optionally enable NVS encryption with
an `nvs_keys` partition if `arm_pin`/`arm_level` must be hidden too (SPEC §4).

> **Flash Encryption alone is NOT T2 — UART download mode must be disabled too.** Flash Encryption
> protects data *at rest*, but if the **UART download (ROM serial) bootloader is still enabled**, an
> attacker with the board can simply re-flash the gate away (or, on hardware that supports it, read
> back plaintext via the download stub). A board with Flash Encryption but a live download mode is
> **still reflashable past the gate** — that is at most T1-plus, not T2. A real T2 posture also burns
> the download-disable eFuse — on classic ESP32 `DISABLE_DL_ENCRYPT` / `DISABLE_DL_DECRYPT` /
> `DISABLE_DL_CACHE` (and, where supported, `UART_DOWNLOAD_DIS`); on S3/C3 `DIS_DOWNLOAD_MODE` (plus
> `DIS_DIRECT_BOOT` / `DIS_USB_JTAG` as applicable). FE+SB in *release* mode normally sets these, but
> a **Development**-mode FE flash does **not**, so this must be verified, not assumed.
>
> **A T2 claim MUST read back eFuses and refuse to declare a board hardened otherwise.** Run
> `espefuse.py --port <PORT> summary` (or `idf.py efuse-summary`) and confirm, at minimum, that
> `FLASH_CRYPT_CNT`/`SPI_BOOT_CRYPT_CNT` is burned (FE enabled, in *release* not development mode),
> `ABS_DONE_*` / `SECURE_BOOT_EN` is set (Secure Boot v2 enabled), and the UART-download-disable
> eFuse above is burned. Do **not** mark a board "T2 / hardened" on the basis of a build flag or an
> `idf.py` log line — those describe *intent*, not the burned state. Only the read-back eFuse summary
> proves the gate is no longer reflashable. The flasher's T2 path (SPEC §11) should surface this
> read-back and block the "hardened" label until the summary confirms it.

> **GUARDIAN variant — `otadata`-rewrite bypass.** In the GUARDIAN flow (§10) the gate is the
> `factory` app and Marauder lives in `ota_0`. Boot selection is driven by the `otadata` partition.
> Without Secure Boot, an attacker who can write flash (UART download, or even Marauder's own SD-OTA
> path — see the §10/SPEC §1 collision) can **write `otadata` to point boot at `ota_0` directly and
> SKIP the factory Guardian entirely** — the gate never runs, no password is ever asked, and nothing
> wipes. Flash Encryption does not stop this on its own (the attacker is rewriting the boot selector,
> not reading secrets). Closing it requires **(a) Secure Boot v2** so a re-flashed/forged image and
> bootloader are rejected, **and (b) a correct rollback / anti-skip posture**:
> `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` so an `ota_0` Marauder that never marks itself valid
> auto-reverts to the Guardian, and `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` (with a monotonic
> `secure_version`) so a forced downgrade/skip is rejected by the bootloader. The Guardian must also
> re-assert `factory` (erase `otadata` or `esp_ota_set_boot_partition(factory)`) on its own boot so a
> stale `ota_0` selection does not persist. Until Secure Boot + this rollback posture is enforced, a
> GUARDIAN board is **not** T2 regardless of Flash Encryption.

---

## 7. arduino-cli invocations

Replace `<FQBN>` with your board's fully-qualified board name and adjust the CSV. Example below is
a classic ESP32, 4 MB, SAFE mode, serial input.

```bash
# 0) one-time: install the esp32 core the Marauder build targets
arduino-cli core update-index --additional-urls \
  https://espressif.github.io/arduino-esp32/package_esp32_index.json
arduino-cli core install esp32:esp32

# 1) place the partition CSV as partitions.csv in the sketch dir, and bootgate/ alongside the .ino
cp firmware/partitions/suicide_4MB.csv esp32_marauder/partitions.csv

# 2) SAFE_MODE build (build first!)
arduino-cli compile \
  --fqbn esp32:esp32:esp32:PartitionScheme=custom,FlashSize=4M \
  --build-property "compiler.cpp.extra_flags=-DSUICIDE_FORK -DSUICIDE_SAFE_MODE -DGATE_INPUT_SERIAL -DARMING_PIN=27 -DARMING_ACTIVE_LEVEL=1 -DARMING_PULL=2" \
  esp32_marauder

# 3) flash the app (gate config guardcfg.bin is flashed separately by the host flasher, SPEC §11)
arduino-cli upload -p <PORT> \
  --fqbn esp32:esp32:esp32:PartitionScheme=custom,FlashSize=4M \
  esp32_marauder
```

T1 build: drop `-DSUICIDE_SAFE_MODE`. T2 build: add `-DSUICIDE_TIER_T2` and configure Secure
Boot/FE in the IDF/menuconfig sidecar (arduino-cli surfaces these via board menu options or a
`sdkconfig` only on the IDF-component path; for pure Arduino, T2 eFuse steps are done with
`espefuse.py`/`idf.py` separately — see SPEC §11 and the flasher's T2 warning).

A touch board (CYD) swaps the input flag and partition only:
`-DGATE_INPUT_TOUCH` with the same `suicide_4MB.csv`.

---

## 8. PlatformIO invocations

Use [`platformio.ini.example`](platformio.ini.example) as the basis (copy it to `platformio.ini`
in the patched Marauder tree, or merge its envs). Envs are named `<board>_safe`, `<board>_t1`,
`<board>_t2`.

```bash
# SAFE_MODE first
pio run -e esp32dev_serial_safe

# upload app
pio run -e esp32dev_serial_safe -t upload

# T1 (real wipe, reflashable) — sacrificial board only
pio run -e esp32dev_serial_t1 -t upload

# CYD touch SAFE build
pio run -e cyd_touch_safe -t upload
```

PlatformIO reads `board_build.partitions` and runs `gen_esp32part.py` automatically; it also picks
the correct bootloader offset per chip. The `build_src_filter = +<*> +<../bootgate/>` line is what
pulls the gate `.cpp` files in without copying them into the sketch tree.

---

## 9. Verification checklist (every build)

- [ ] Built `-DSUICIDE_SAFE_MODE` and exercised all four state-machine outcomes on serial.
- [ ] Confirmed an **unprovisioned** board boots straight into Marauder (no prompt, no wipe).
- [ ] Confirmed `armed=0` (master-disarmed) board boots straight through.
- [ ] Confirmed the **correct** password always boots and resets `att_ct` (even with the switch
      not armed, except the dead-man pre-check).
- [ ] Confirmed `att_ct` is power-cycle-safe (counter survives a yank mid-attempt).
- [ ] The plaintext password is **never** echoed on serial, never logged, never a CLI arg
      (SPEC §4, §10; enforced by `GateInput` adapters).
- [ ] Chose a non-strapping `arm_pin`; if GPIO34–39, wired an external 10 kΩ pulldown.
- [ ] Only moved past SAFE_MODE on a **sacrificial** board; T2 eFuse steps understood as
      IRREVERSIBLE.

---

## 10. GUARDIAN note (not this flow)

If you need the cleaner GPL boundary / cleaner brick (SPEC §1, §3.3) on 8 MB+, the gate lives in a
separate `factory` app that hands off to an unmodified Marauder in `ota_0` via
`esp_ota_set_boot_partition(ota_0)` + `esp_restart()`. **Collision to handle (verified,
`SDInterface.cpp` ~219–221):** Marauder's own SD updater calls
`esp_ota_get_next_update_partition(NULL)` then `esp_ota_set_boot_partition(next)`. In GUARDIAN the
Guardian must re-assert by selecting **factory** explicitly (erase `otadata` or
`set_boot_partition(factory)`) and enable `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE` so a Marauder
that never marks itself valid auto-reverts to the Guardian. Partition template:
[`../partitions/suicide_guardian_16MB.csv`](../partitions/suicide_guardian_16MB.csv). This guide
otherwise documents FORK only.
