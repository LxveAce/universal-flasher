# PROVISIONING — flash a Suicide build end-to-end

> Operator guide. This is the **owner-only, defensive** anti-forensic layer (see
> [`SAFETY.md`](SAFETY.md), [`THREAT-MODEL.md`](THREAT-MODEL.md)). Everything here conforms to the
> canonical contract in [`SPEC.md`](SPEC.md) — the NVS keys, offsets, and flags below are copied from
> it, not invented here. If they ever disagree, **SPEC.md wins**; fix it there first.

This document walks one device from a blank chip to an armed, tested Suicide Marauder. The hard rule
running through all of it: **build and verify `SUICIDE_SAFE_MODE` behavior first, and never arm a
board holding data you have not backed up.** Recovery from a real (T1) wipe is *re-flashing a blank
device*; a T2 brick has **no** recovery.

The default and recommended target is the **FORK** variant (gate compiled into a Marauder fork).
GUARDIAN is an 8 MB+ hardening option and is called out where it differs.

---

## 0. Prerequisites

| Need | Why | Notes |
|------|-----|-------|
| Python 3.8+ | runs `provision.py` and the flasher | stdlib `hashlib.pbkdf2_hmac` is enough for the KDF — no native deps required |
| `esptool` (`pip install esptool`) | writes the bundle to flash | the existing `headless-marauder-gui` already depends on this |
| `esp-idf-nvs-partition-gen` (`pip install esp-idf-nvs-partition-gen`, Apache-2.0) | builds `guardcfg.bin` from the generated CSV | **NOT** bundled with `esptool` (verified) — install it or vendor the wheel. See [`LICENSING.md`](LICENSING.md). |
| A Suicide build `.bin` set for the target board | the app/bootloader/partition images | from the Suicide-Marauder per-board CI releases, or a local build |
| The matching partition CSV | offsets are read from it, never hardcoded | `firmware/partitions/suicide_4MB.csv` (4 MB) or `suicide_16MB.csv` |
| A **sacrificial** twin board | required before `brick=1` ships | see [`SPIKE-PLAN.md`](SPIKE-PLAN.md) |

> **The plaintext password is never a CLI argument, never logged, never written to disk.**
> `provision.py` reads it via `getpass`/stdin, hashes it in-process, zeroizes the buffer, and emits
> only `{salt, pwhash, kdf_iter, kdf_dklen}` into the NVS image. If any tool would echo the password
> to a console or argv, that is a bug — stop and report it.

---

## 1. The password / KDF contract (host ↔ device must agree exactly)

Host (`provision.py`) and device (`GateCrypto`) MUST use identical `{salt, kdf_iter, kdf_dklen}` or
no correct password will ever verify. From [`SPEC.md`](SPEC.md) §9 and the `sgate` schema (§4):

| Field | Value | Stored as (NVS, namespace `sgate`) |
|-------|-------|-------------------------------------|
| algorithm | PBKDF2-HMAC-SHA256 (mbedtls on device, `hashlib` on host) | implicit — not a stored field |
| `salt` | `os.urandom(16)`, fresh per device | `salt` — `blob[16]` |
| `pwhash` | `pbkdf2_hmac('sha256', pw, salt, kdf_iter, kdf_dklen)` | `pwhash` — `blob[32]` |
| `kdf_iter` | default **10000** (matches `provision.py` `DEFAULT_KDF_ITER` and SPEC §9; ~1 s verify on classic ESP32 — `150000` measured ≈16.7 s, far too slow); tune for boot-gate UX | `kdf_iter` — `u32` |
| `kdf_dklen` | **32** | `kdf_dklen` — `u8` |
| `cfg_ver` | **1** | `cfg_ver` — `u8` |

Why PBKDF2 and not Argon2id: OWASP's Argon2id minimum (19 MiB) exceeds usable ESP32 RAM, so Argon2id
is infeasible on-device (SPEC §9). PBKDF2-HMAC-SHA256 is the deliberate low-memory choice.

The salted hash is **safe in plaintext NVS** — a raw flash dump does not reveal the passphrase. If
you also need to hide `arm_pin`/`arm_level`/wipe flags from a chip-reader, that requires NVS
encryption + an `nvs_keys` partition (a T2 option, SPEC §4 note) — out of scope for a T1 provision.

---

## 2. `guardcfg` NVS — what `provision.py` bakes in

`provision.py` collects the parameters below (password via `getpass`; everything else via flags or
prompts), generates an `nvs_config.csv` in NVS-partition-generator format (`key,type,encoding,value`,
namespace row `sgate,namespace,,` then `sgate_rt,namespace,,`), and runs `nvs_partition_gen generate`
to produce **`guardcfg.bin`** sized to the `guardcfg` partition (0x2000 on 4 MB).

Canonical `sgate` keys (defaults from SPEC §4 — change deliberately, per device):

| Key | Type | Meaning | Default |
|-----|------|---------|---------|
| `cfg_ver` | u8 | schema version | `1` |
| `salt` | blob[16] | PBKDF2 salt | generated |
| `pwhash` | blob[32] | PBKDF2 hash of your password | derived |
| `kdf_iter` | u32 | PBKDF2 iterations | `10000` |
| `kdf_dklen` | u8 | derived-key length | `32` |
| `armed` | u8 | **master arm** (0=DISARMED, 1=ARMED) | **`0`** |
| `arm_pin` | u8 | dead-man GPIO number | per board (SPEC §7; classic ESP32 = 27) |
| `arm_level` | u8 | logic level meaning "armed" | `1` (HIGH) |
| `arm_pull` | u8 | 0=none,1=pullup,2=pulldown | `2` |
| `deadman` | u8 | 1=cut/disarmed line wipes; 0=line only keeps locked | `1` |
| `max_att` | u8 | wrong-password attempts before wipe | `2` |
| `wipe_ota` | u8 | erase Marauder app slot | `1` |
| `wipe_nvs` | u8 | erase Marauder NVS | `1` |
| `wipe_spiffs` | u8 | erase SPIFFS | `1` |
| `wipe_sd` | u8 | overwrite + erase SD | `1` |
| `brick` | u8 | erase boot chain last (true brick) | `0` (T1) / `1` (T2) |
| `sd_passes` | u8 | SD overwrite passes | `1` |

`sgate_rt` (`att_ct`, `lock_until`) is left at defaults; the firmware manages it at runtime. Keeping
config and counter in separate namespaces means re-provisioning config does not reset the attempt
counter (SPEC §4).

> **Choosing `arm_pin`:** never a strapping pin. Classic ESP32 / Lonely Binary Gold → GPIO27; S3
> (Cardputer/Mini) → Grove **G2**; C3 → GPIO10 (SPEC §7). GPIO34–39 are **input-only** and need an
> external 10 kΩ pull-down — `arm_pull` is a no-op there in hardware. `provision.py` should warn if
> you pick an input-only pin (mirrors `ArmingSwitch::pinIsInputOnly`).

### `provision.py` outputs (into a build/bundle dir)

Per SPEC §10:

- **`guardcfg.bin`** — the NVS image (above), sized to the `guardcfg` partition.
- **`otadata_blank.bin`** — `0x2000` of `0xFF`. Forces first boot into factory/Guardian; the FORK
  variant ignores it (no factory slot) but it is written for layout uniformity and GUARDIAN reuse.
- **`bundle.json`** — manifest of `{file, offset}` pairs, with **offsets read from the partition
  CSV**, not hardcoded. The flasher consumes this.

Example (password is prompted, never on argv):

```
python host/provision.py \
  --board esp32_classic \
  --partitions firmware/partitions/suicide_4MB.csv \
  --arm-pin 27 --arm-level 1 --arm-pull 2 \
  --deadman 1 --max-attempts 2 \
  --armed 0 \
  --brick 0 \
  --kdf-iter 10000 \
  --out build/esp32_classic_suicide/
# -> prompts: "Set gate password:" (hidden), "Confirm:"
# -> writes guardcfg.bin, otadata_blank.bin, bundle.json
```

---

## 3. Flashing the bundle

The flasher builds **one** `esptool write_flash` pair list (SPEC §11). Offsets come from
`bundle.json`; the chip determines the bootloader offset (**0x1000** classic ESP32/S2, **0x0** on
S3/C3/C6/H2 — SPEC §2):

```
bootloader.bin       @ 0x0  or 0x1000   (per chip)
partitions.bin       @ 0x8000
boot_app0.bin        @ <real offset from CSV>
app (Marauder fork)  @ 0x10000
guardcfg.bin         @ <nvs/guardcfg offset from CSV>   # 0x1F0000 on the 4 MB layout
otadata_blank.bin    @ <otadata offset from CSV>        # 0xe000 on the 4 MB layout
```

Two ways to run it:

- **GUI** (`headless-marauder-gui` → `FlasherDialog`): tick the single **"Suicide"** checkbox, fill
  the sub-panel (password, arm pin/level, dead-man toggle), pick the suicide build for the detected
  chip, flash. Hashing happens host-side in the GUI process (it reuses `provision.py`). The flash
  encryption + Secure Boot (T2) checkbox is **separate** and carries a blocking warning — leave it
  off for a normal T1 provision.
- **CLI**: `flash_suicide(port, chip, bundle_dir, ...)` from `marauder_core/flasher.py`, reusing the
  existing `--flash_size detect` / `-z` / `_run_stream` plumbing.

Keep `--flash_size detect`. Do **not** hand-edit offsets — if the CSV and `bundle.json` disagree,
fix the CSV.

> **Never** pass the password to `esptool` or `nvs_partition_gen` on the command line, and never let
> it appear in the streamed console log. Hashing is in-process only; the tools only ever see
> `guardcfg.bin`.

---

## 4. Verify `SAFE_MODE` behavior FIRST (mandatory)

Before you ever provision `armed=1`, flash a **`SUICIDE_SAFE_MODE`** build and exercise the whole
chain. In SAFE_MODE every destructive step is redirected at a scratch partition + dummy key and only
**logs** what it would have destroyed — nothing real is touched (SPEC §5, `SelfDestruct.h`). In this
mode `BootGate::run()` returns `GATE_TRIGGERED` instead of actually wiping.

Watch the serial console (the default `GATE_INPUT_SERIAL` build accepts `unlock <pw>` / `wipe`) and
confirm each invariant from SPEC §6:

1. **Unprovisioned board** → `GATE_PASS` immediately, no prompt, no simulated wipe. (Flash the app
   *without* `guardcfg.bin` to test this, or before provisioning.)
2. **Provisioned but `armed=0`** → `GATE_PASS`; destruct logic never runs even on wrong passwords.
3. **`armed=1`, correct password** → `GATE_PASS`; `att_ct` resets to 0.
4. **`armed=1`, wrong password ×`max_att`** → logs `SelfDestruct::trigger(... REASON_ATTEMPTS)` and
   returns `GATE_TRIGGERED` (real build would wipe). Confirm `att_ct` persisted across a power-cycle
   mid-sequence (monotonic counter, SPEC §6).
5. **`armed=1`, `deadman=1`, arming line NOT in armed position** → logs
   `SelfDestruct::trigger(... REASON_DEADMAN)` *before* any password prompt.

Only once you have **seen the simulated-wipe logs** for the exact config you intend to deploy should
you move to a real build. This is the same discipline SAFETY.md makes non-negotiable.

---

## 5. Arming a device (going live)

After SAFE_MODE has validated your config, provision a real (non-SAFE) build:

1. **Back up everything** on the board and any SD card you will leave inserted. A real wipe is final.
2. Re-run `provision.py` **without** `SUICIDE_SAFE_MODE` in the build and with `--armed 1` (or flip
   `armed` to `1` in the GUI sub-panel). Master-arm is the deliberate "go live" step; default is `0`.
3. Decide and set the **dead-man policy** consciously (next section).
4. Wire the arming switch per SPEC §7: the switch in its **armed position drives the pin to
   `arm_level`** (default HIGH); the pin idles to the opposite via `arm_pull`, so a **cut / unplugged
   / floating** wire reads NOT-ARMED.
5. Flash, power-cycle, and confirm the device prompts and unlocks with the correct password.

Invariants that protect you even when armed (SPEC §6): a **correct password always boots and never
wipes** (except the dead-man pre-check), and a **brownout/undervoltage boot SUPPRESSES destruction
(never wipes) but the CORRECT PASSWORD IS STILL REQUIRED to boot** (SPEC §13) — a low battery cannot
spuriously trip the line, but it also does not open the device (no bypass).

---

## 6. Choosing `deadman` 0 vs 1

This is a per-device decision the operator must make on purpose (SAFETY.md pre-arm checklist).

| `deadman` | Behavior when `armed=1` and the arming line is **not** in armed position | Use when |
|-----------|--------------------------------------------------------------------------|----------|
| **`1`** (default) | The board wipes **before the password is even asked** (`REASON_DEADMAN`). A cut/unplugged/floating wire = trigger. | You want tamper/removal (case-open, snatch, cable cut) to be terminal — the BusKill/dead-man posture. |
| **`0`** | The board does **not** wipe; the line being not-armed just keeps the device locked, and the correct password unlocks it. | You do not want a loose or disconnected wire to destroy data; the switch is a lock, not a trip. |

If you provision `deadman=1`, understand that **a wiring fault is indistinguishable from tampering**
to the gate — that is the point, and it is why the wire and switch must be reliable. If in doubt for
a bench or development unit, use `deadman=0` (and keep `armed=0` until truly deployed).

---

## 7. Recovery

There is **no "undo"** for a fired trigger. Recovery means re-provisioning a blank device:

- **T1 (`brick=0`)** — the board is reflashable but data-wiped. Recovery = re-flash a clean Marauder
  (or a fresh Suicide bundle) over UART with `esptool write_flash`, exactly as you would recover any
  ESP32. The previously stored data is gone by design; you are restoring a *working* board, not the
  data.
- **T2 (`brick=1` + Secure Boot/Flash Encryption)** — **no recovery.** The boot chain is erased and
  (in Release mode) UART download is disabled, so the board cannot be reflashed past the gate. The
  ciphertext is gone with the key still locked in unreadable eFuse. This is intentional and
  irreversible; do **not** enable it until the [`SPIKE-PLAN.md`](SPIKE-PLAN.md) test has passed on a
  sacrificial twin and you accept the one-way consequence (SAFETY.md).

To **de-provision** a board you simply want to retire safely: re-flash a stock/blank image so no
`guardcfg` (with a `pwhash`) remains. An app image flashed without a populated `guardcfg` is
unprovisioned and **cannot wipe** (SPEC §6 step 2). If you only want to disarm, re-provision with
`--armed 0`; if you want it fully inert, reflash blank.

---

## 8. Quick reference — order of operations

```
1. Install esptool + esp-idf-nvs-partition-gen.
2. Build/obtain the SUICIDE_SAFE_MODE app for the board.
3. provision.py (armed=0, your config) -> bundle -> flash SAFE_MODE build.
4. Exercise all SPEC §6 invariants over serial; SEE the simulated-wipe logs.   <-- gate
5. Back up all data on the board + SD.
6. provision.py (real build, armed=1, chosen deadman) -> flash.
7. Wire + test the arming switch; confirm correct-password unlock.
8. (brick=1 only) ONLY after SPIKE-PLAN passes on a sacrificial twin.
Recovery: T1 = reflash blank; T2 = none.
```
