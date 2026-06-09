# Suicide Marauder — Canonical Interface Contract (SPEC)

> **This file is the single source of truth.** Every firmware module, host script, partition
> table, and flasher change MUST conform to the names, offsets, NVS keys, build flags, and the
> state machine defined here. If something needs to change, change it *here first*, then update
> the code. Evidence basis: [`RESEARCH-DIGEST.md`](RESEARCH-DIGEST.md).

Suicide Marauder is an **owner-only, defensive anti-forensic ("duress") layer** for an ESP32
Marauder that the operator owns. It is NOT for evading lawful process. See
[`SAFETY.md`](SAFETY.md) and [`THREAT-MODEL.md`](THREAT-MODEL.md).

---

## 0. Glossary

| Term | Meaning |
|------|---------|
| **Gate** | The boot-time check (`BootGate`) that runs before Marauder's UI loads. |
| **Provisioned** | NVS contains a password hash + config. A non-provisioned board behaves like plain Marauder and **can never wipe**. |
| **Armed (master)** | The provisioned `armed` flag is `1`. Default is `0` (DISARMED). Destruct is *physically impossible* unless armed. |
| **Dead-man line** | The hardware arming GPIO. "Armed position" drives it to `ARM_LEVEL`; a cut/floating/unpowered wire reads the opposite (fail-toward-locked or fail-toward-wipe per `deadman` policy). |
| **Trigger** | A condition that starts `SelfDestruct`: (a) wrong-password count reaches `max_att`, or (b) dead-man line not in armed position while in dead-man mode. |
| **Wipe / self-destruct** | Best-effort secure erase of internal flash partitions + connected SD + (optional) the boot chain ("brick"). |
| **T1 / T2** | Anti-forensic tier. **T1** = no Secure Boot/Flash-Encryption (reflashable; *dev/demo*). **T2** = Secure Boot v2 + Flash Encryption release mode (gate cannot be reflashed past; brick is unrecoverable). |
| **SAFE_MODE** | Build flag that routes the entire detect→arm→trigger→erase chain at a **scratch partition + dummy key** and only **logs** the simulated destruction. Mandatory for testing. |

---

## 1. Two build variants

### Variant FORK *(default — all flash sizes, incl. 4 MB)*
The gate is compiled **into** a fork of ESP32Marauder, called from `setup()`. It reuses
Marauder's own display/keyboard/SD drivers, so the password prompt works on every hardware
class with almost no new UI code. Self-destruct = the running app erases every other partition,
the SD, and finally its own boot chain.

- Hook: in `ESP32Marauder.ino`, insert `BootGate::run()` **after** `display_obj.RunSetup()` and
  **before** `settings_obj.begin()`. (Anchor strings, not line numbers — see
  `firmware/integration/INTEGRATION.md`. Reference region: lines 312–348 of the inspected source.)
- Partition table = Marauder's normal layout **plus** a `guardcfg` NVS partition.

### Variant GUARDIAN *(optional hardening — 8 MB+ only)*
A separate tiny **factory** app gates, then `esp_ota_set_boot_partition(ota_0)` + `esp_restart()`
into an **unmodified** Marauder in `ota_0`. Cleaner GPL boundary and cleaner brick (the gate is
not erasing its own running region until the very end, and can re-assert via factory fallback).
Does **not** fit in 4 MB (two ~1.875 MB app slots + filesystems overflow 4 MB → 8 MB minimum,
16 MB preferred).

> **Collision (verified, `SDInterface.cpp` ~217–223):** Marauder's own SD updater already calls
> `esp_ota_get_next_update_partition` + `esp_ota_set_boot_partition`. In GUARDIAN variant the
> Guardian must select the **factory** partition explicitly and re-arm by erasing `otadata` (or
> `set_boot_partition(factory)`), and should enable `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE` so a
> Marauder that never marks itself valid auto-reverts to Guardian.

**Default scaffold targets FORK.** GUARDIAN is documented and partition-templated for 16 MB.

---

## 2. Chip / flash facts the toolchain MUST branch on

| Fact | Classic ESP32 / S2 | S3 / C3 / C6 / H2 |
|------|--------------------|-------------------|
| 2nd-stage bootloader offset | **0x1000** | **0x0** |
| Partition table offset | 0x8000 | 0x8000 |
| App alignment | 0x10000 (64 KB) | 0x10000 |

- Never hardcode the `otadata`/`nvs` offsets — **read them from the build's partition table**.
  (Stock IDF default otadata is `0xd000`; Marauder's is `0xe000` because it enlarges `nvs`.)
- App partitions must be 64 KB aligned or `gen_esp32part.py` errors out.

---

## 3. Partition layout

Partition names are canonical. Data partition `guardcfg` (subtype `nvs`) holds the gate config.

### 3.1 FORK on 4 MB (classic ESP32 / CYD) — `firmware/partitions/suicide_4MB.csv`
Derived from Marauder's `min_spiffs`, carving an 8 KB `guardcfg` out of spiffs. On 4 MB the second
app slot is dropped (Marauder's SD-OTA-self-update is disabled on this build — documented trade).

```
# Name,    Type, SubType, Offset,   Size,     Flags
nvs,       data, nvs,     0x9000,   0x5000,
otadata,   data, ota,     0xe000,   0x2000,
app0,      app,  ota_0,   0x10000,  0x1E0000,
guardcfg,  data, nvs,     0x1F0000, 0x2000,
spiffs,    data, spiffs,  0x1F2000, 0xC000,
coredump,  data, coredump,0x1FE000, 0x2000,
scratch,   data, 0x40,    0x200000, 0x10000,
```

> **`scratch` is mandatory and load-bearing for SAFE_MODE** (§5/§8). It is a dedicated erase
> target so a safe-mode dry run never touches `guardcfg`/`ota_0`/`nvs`/`spiffs`/the running app.
> If a build defines `SUICIDE_SAFE_MODE` but the partition table has **no** `scratch` partition,
> the firmware MUST refuse to simulate (log an error and perform **zero** erases) — it must NEVER
> fall back to any live partition. Every partition CSV (4/8/16 MB + guardian) carries a `scratch`.

### 3.2 FORK on 16 MB — `firmware/partitions/suicide_16MB.csv`
Roomy; full spiffs + larger guardcfg + coredump.

### 3.3 GUARDIAN on 16 MB — `firmware/partitions/suicide_guardian_16MB.csv`
`factory`(Guardian) + `ota_0`(Marauder) + `otadata` + Marauder `nvs` + `guardcfg` + `spiffs`.

> The 4 MB CSV here is the *committed reference*; the fan-out fills 16 MB + GUARDIAN with exact
> sizes. **Do not** change `guardcfg`'s name or subtype — host + firmware both key off it.

---

## 4. `guardcfg` NVS schema (canonical)

Namespace **`sgate`** (config) and **`sgate_rt`** (runtime counter, kept separate so config can be
rewritten without resetting the attempt counter).

### Namespace `sgate`
| Key | Type | Meaning | Default |
|-----|------|---------|---------|
| `cfg_ver` | u8 | schema version | `1` |
| `salt` | blob[16] | PBKDF2 salt (`os.urandom`) | — |
| `pwhash` | blob[32] | PBKDF2-HMAC-SHA256(password, salt, iter) | — |
| `kdf_iter` | u32 | PBKDF2 iteration count | `10000` |
| `kdf_dklen` | u8 | derived-key length | `32` |
| `armed` | u8 | **master arm** (0=DISARMED safe, 1=ARMED) | `0` |
| `arm_pin` | u8 | dead-man GPIO number | per board (`§7`) |
| `arm_level` | u8 | logic level meaning "armed" (1=HIGH) | `1` |
| `arm_pull` | u8 | 0=none,1=pullup,2=pulldown | `2` (pulldown) |
| `deadman` | u8 | 1=cut/disarmed line wipes; 0=line just keeps device locked | `1` |
| `max_att` | u8 | wrong-password attempts before wipe | `2` |
| `wipe_ota` | u8 | erase Marauder app slot | `1` |
| `wipe_nvs` | u8 | erase Marauder NVS | `1` |
| `wipe_spiffs` | u8 | erase SPIFFS | `1` |
| `wipe_sd` | u8 | best-effort SD file + free-space overwrite (no guaranteed format — see §8) | `1` |
| `brick` | u8 | erase boot chain last (true brick) | `0` (T1) / `1` (T2) |
| `sd_passes`| u8 | SD overwrite passes | `1` |

### Namespace `sgate_rt`
| Key | Type | Meaning |
|-----|------|---------|
| `att_ct` | u8 | monotonic wrong-attempt counter; **commit before responding** so a power-cycle mid-attempt does not reset it. Reset to 0 only on a correct password. |
| `lock_until` | u32 | epoch/uptime gate for exponential backoff (disarmed mode). |

> **`kdf_iter` default is `10000` everywhere** (this table, §9, `GateConfig.h` `SUICIDE_KDF_ITER`,
> and `provision.py` `DEFAULT_KDF_ITER` all agree). On **T1** the iteration count is **moot for
> offline cracking** — the salted hash is dumpable from plaintext NVS, and PBKDF2 is GPU-cheap, so
> a higher count buys no meaningful offline resistance. Real protection is **T2 (Flash Encryption
> hides the hash) + a strong passphrase**; tune `kdf_iter` purely for boot-gate UX (~1 s verify).

> **The plaintext password is never stored, never logged, never a CLI argument.** Only
> `{salt, pwhash, kdf_iter, kdf_dklen}` exist on device. Host zeroizes the password buffer after
> hashing. NVS is **not** covered by Flash Encryption's app/partition scope automatically — the
> salted hash is safe in plaintext NVS; if `arm_pin`/`arm_level` must be hidden too, enable NVS
> encryption with an `nvs_keys` partition (T2 option).

### 4.1 Safety clamps (fail-closed — added after security review)

These are invariants the firmware AND host must both enforce. A corrupt/hostile NVS value must
never be able to *increase* destructiveness.

- **`max_att` ≥ 1, always.** Host `provision.py` rejects `max_att < 1`. Firmware `GateConfig::load`
  treats a stored `max_att == 0` as the safe default (`SUICIDE_MAX_ATTEMPTS`). `armedFlow` MUST
  NOT trigger when `att_ct == 0` (no failed attempt ⇒ no wipe), regardless of `max_att`.
- **Attempt counter fails CLOSED.** If `GateRuntime::commitAttempts()` cannot persist `att_ct`
  (NVS read-only / full / encrypted-misconfig), the gate MUST NOT keep accepting guesses. Bound the
  *in-RAM* attempt count to `max_att` and trigger (or hard-halt the gate) anyway — never degrade to
  unlimited guesses. `ESP_LOGE` the condition.
- **`cfg_ver` is read and validated.** `GateConfig::load` reads `cfg_ver`; an unexpected version is
  treated as **not provisioned** (fail-safe: a schema it doesn't understand can't drive a wipe).
- **`ensureNvsReady` is scoped to `guardcfg`.** The gate must NOT `nvs_flash_erase()` the *default*
  `nvs` partition (that would destroy Marauder's own config on every boot). Use
  `nvs_flash_init_partition("guardcfg")` and leave the default partition to Marauder's own startup.
- **`deadman == 0` semantics (clarified).** With `deadman == 0` the arming line is **ignored
  entirely** — the password alone gates boot, and the line can never cause a wipe. The arming line
  only has any effect when `deadman == 1`. (SAFETY.md is corrected to match.)
- **RAM hygiene.** On `GATE_PASS`, scrub `cfg.pwhash`/`cfg.salt` from the stack copy before
  Marauder continues (defense-in-depth; the salted hash is low-sensitivity but the posture is
  "never retained").
- **Fail-safe pull/level pair (host-validated).** A non-fail-safe arming combo — where the pin
  *idles toward ARMED* so a cut wire reads ARMED and defeats the dead-man — MUST be rejected/warned
  by `provision.py`: reject `arm_level==1 & arm_pull==pullup(1)` and `arm_level==0 &
  arm_pull==pulldown(2)`. The fail-safe pairs are `level=1 + pulldown` and `level=0 + pullup`.

---

## 5. Build flags (compile-time `-D`)

| Flag | Effect |
|------|--------|
| `SUICIDE_FORK` / `SUICIDE_GUARDIAN` | select variant (exactly one) |
| `SUICIDE_SAFE_MODE` | **simulate**: chain runs against scratch partition + dummy key, logs only, never destroys. |
| `SUICIDE_TIER_T2` | expect Secure Boot v2 + Flash Encryption; enable `brick` + NVS encryption defaults. |
| `GATE_INPUT_SERIAL` | headless: password over USB serial (`unlock <pw>` / `wipe`). **default** |
| `GATE_INPUT_TOUCH` | on-screen PIN keypad (reuse Marauder `keyboardInput`). |
| `GATE_INPUT_MINI_KB` | Marauder Mini joystick (`miniKeyboard(... do_pass=true)`). |
| `GATE_INPUT_CARDPUTER` | M5Cardputer native QWERTY. |
| `GATE_INPUT_BUTTONS` | M5StickC button-combo (weak; prefer host-assisted). |
| `ARMING_PIN` / `ARMING_ACTIVE_LEVEL` / `ARMING_PULL` | compile-time fallback if NVS unset. |

Exactly one `GATE_INPUT_*` per build. Input class mirrors Marauder's own `HAS_TOUCH` /
`HAS_MINI_KB` / `MARAUDER_CARDPUTER` / `HAS_BUTTONS` defines.

---

## 6. Boot-gate state machine — `BootGate::run()`

Returns `GateResult { GATE_PASS, GATE_TRIGGERED }`. Called once, early in `setup()`.

```
1.  cfg = GateConfig::load()                       // from sgate NVS
2.  if (!cfg.provisioned) return GATE_PASS;         // FAIL-SAFE: unprovisioned never wipes
3.  armedLine = ArmingSwitch::read(cfg)             // 8 samples, 10ms settle, unanimous
4.  if (cfg.armed == 0):                            // master DISARMED (dev/bench/default)
        // never destruct. Optionally still prompt (cosmetic). 
        return GATE_PASS;
5.  // ---- MASTER ARMED from here ----
6.  if (cfg.deadman == 1 && armedLine == NOT_ARMED):
        SelfDestruct::trigger(cfg, REASON_DEADMAN);  // user requirement: no-switch boot = wipe
        return GATE_TRIGGERED;                        // (does not return in practice)
7.  // password loop (board input driver)
    loop:
        pw = Input::getPassword()                    // serial / touch / joystick / kb / buttons
        if (GateCrypto::verify(pw, cfg)):
            rt.att_ct = 0; rt.commit();              // correct ALWAYS wins
            zeroize(pw); return GATE_PASS;
        rt.att_ct += 1; rt.commit();                 // persist BEFORE responding
        zeroize(pw);
        if (rt.att_ct >= cfg.max_att):
            SelfDestruct::trigger(cfg, REASON_ATTEMPTS);
            return GATE_TRIGGERED;
        backoff();                                    // re-prompt (armed: hard, no host reset)
```

**Authenticated host-wipe (`REASON_HOST_WIPE`).** On a headless (`GATE_INPUT_SERIAL`) build the
owner may panic-wipe over USB, but it MUST be authenticated and deliberate: the `wipe` command
prompts for the password and triggers `SelfDestruct` **only on a correct password** (a wrong one
counts as a failed attempt). An unauthenticated/accidental `wipe\n` (terminal paste, serial noise)
can therefore never destroy data. Only available when master-armed.

Invariants:
- **Correct password always boots and never wipes**, regardless of switch (except dead-man pre-check).
- **Unprovisioned or master-disarmed → physically cannot wipe.**
- Counter is monotonic and power-cycle-safe, and **fails closed** (§4.1).
- In dead-man mode the switch is checked *before* the password (a missing switch is terminal).
- `att_ct == 0` never triggers; `max_att` is clamped ≥ 1 (§4.1).
- Host-wipe requires a correct password (above). No other unauthenticated destruct trigger exists.

---

## 7. Per-board arming pin map (defaults; never a strapping pin)

Forbidden (strapping/boot): classic `0,2,12,15` (+5 on some); S3 `0,3,45,46`; C3 `2,8,9`.
GPIO34–39 are input-only → need an external 10 kΩ pull-down (`arm_pull` ignored in HW).

| Board class | Default `arm_pin` | Notes |
|-------------|-------------------|-------|
| Classic ESP32 dev / Lonely Binary Gold | **GPIO27** | free; INPUT_PULLDOWN |
| CYD 2.8"/3.5" | GPIO27 or CN1/P3 broken-out pin | many pins consumed by TFT/SD/touch |
| ESP32-S3 (Cardputer/Mini/MultiBoard) | Grove **G2** | avoid 0/3/45/46 |
| C3 | GPIO10 | avoid 2/8/9 |

Wiring: switch in **armed position drives the pin to `arm_level`** (default HIGH via the intact
switch); pin idles at the opposite via `arm_pull` so a **cut/unplugged/floating** wire reads
NOT-ARMED. This makes tamper/removal a dead-man trigger **when armed**.

---

## 8. Self-destruct ordering — `SelfDestruct::trigger()`

There is **no runtime crypto-erase on ESP32** (AES key eFuse is HW read+write-protected). Wipe is
bulk erase + overwrite. Non-abortable once started. Under `SUICIDE_SAFE_MODE`, every step targets a
scratch partition / logs only.

1. **SD** (if `wipe_sd` & card present): the stock-SD path (`SelfDestruct.cpp` `wipeSDImpl`) does a
   **best-effort file-level overwrite only** — recursively overwrite every file's contents with
   `esp_fill_random` (`sd_passes` passes) and delete it, then a **single** pass over remaining free
   space (fill one big random temp file until the card is full, then delete it). **There is NO
   guaranteed card erase / FAT reformat / full-LBA secure-erase on this path** — `SD.end()` only
   drops our open handles. A true full-LBA erase + reformat needs a **raw-sector backend (SdFat)**
   supplied via the weak `wipeSDImpl` board override → **TODO** (RESEARCH-DIGEST.md). Even the
   file+free-space overwrite is **best-effort**: FTL wear-leveling / over-provisioning means
   remapped or spare cells may survive; this is documented, not hidden. At-rest SD encryption (T2)
   is the only real guarantee.
2. **Internal data**: `esp_partition_erase_range` over `ota_0` (Marauder app, if `wipe_ota`),
   `spiffs` (if `wipe_spiffs`), Marauder `nvs` (if `wipe_nvs`), coredump, then `guardcfg` **last of
   the data** (after config is already in RAM).
3. **Brick** (if `brick`): from an `IRAM_ATTR` routine that does not return to flash — raw-erase the
   partition table (0x8000), the bootloader (0x1000 classic / 0x0 S3-C3), and the running app/factory
   region. **This self-erase-of-the-running-app is the one UNVERIFIED primitive** → see
   `docs/SPIKE-PLAN.md`; requires `CONFIG_SPI_FLASH_DANGEROUS_WRITE_ALLOWED=y`.

T1 (`brick=0`) leaves a re-flashable but data-wiped board. T2 (`brick=1` + Secure Boot/FE) leaves an
unrecoverable board whose ciphertext is gone.

---

## 9. Cryptography — `GateCrypto`

- **PBKDF2-HMAC-SHA256** via mbedtls (bundled with Arduino-ESP32). Argon2id is impossible (OWASP
  19 MiB min > ESP32 RAM).
- Host and device MUST agree on `{iter, dklen, salt}`. **Default `iter=10000`** (≈1 s verify on a
  classic ESP32-D0WD @240 MHz — **`150000` measured ≈16.7 s on hardware, far too slow** for a boot
  gate), `dklen=32`. Record the chosen value in `guardcfg.kdf_iter`.
  > **Why a low iteration count is correct here (measured).** The gate wipes after `max_att`
  > (default 2) wrong tries, so *online* brute-force is impossible regardless of KDF cost. PBKDF2 is
  > GPU-cheap, so a high count does **not** meaningfully protect the salted hash against an *offline*
  > attacker who has dumped the flash — that protection is **T2 (Flash Encryption hides the hash) + a
  > strong passphrase**, not iteration count. Tune `iter` purely for UX (~1 s).
- `verify()` uses a **constant-time** compare (`mbedtls_ct`/manual) against `pwhash`.
- Host: `hashlib.pbkdf2_hmac('sha256', pw, salt, iter, 32)`; `salt=os.urandom(16)`; zeroize `pw`.

---

## 10. Host provisioning — `host/provision.py`

Inputs (password via getpass/stdin, **never argv**): `password, arm_pin, arm_level, arm_pull,
max_attempts, deadman, armed, wipe_* , brick, kdf_iter`.

Outputs (into a build/bundle dir):
- `guardcfg.bin` — NVS partition image sized to the `guardcfg` partition, built from a generated
  `nvs_config.csv` via **`nvs_partition_gen`** (Apache-2.0; vendored or `pip install
  esp-idf-nvs-partition-gen` — **confirmed NOT bundled with esptool**).
- `otadata_blank.bin` — `0x2000` of `0xFF` (forces first boot into factory/Guardian). **GUARDIAN
  only.**
- A manifest **`bundle.json`** that is the *complete* flash list the flasher consumes: a `files`
  array of `{file, offset}` for **every** image to write — `bootloader.bin`@(`0x0`|`0x1000` per
  chip), `partitions.bin`@`0x8000`, the otadata seed (see below), `app.bin`@`0x10000`,
  `guardcfg.bin`@`<guardcfg offset>`. Offsets for `guardcfg`/`otadata` are **read from the chosen
  partition CSV** (never hardcoded `0xe000`); `partitions`/`app` are fixed; bootloader is
  chip-derived. The flasher writes exactly this list, in one `write_flash` pass.
  - **otadata seed, one only (no collision):** **FORK** → `boot_app0.bin` at the otadata offset
    (normal seed → boots `app0`); **GUARDIAN** → `otadata_blank.bin` at the otadata offset (`0xFF`
    → boots `factory`/Guardian). The manifest includes exactly one of the two; never both at the
    same offset.
  - `bootloader.bin`/`partitions.bin`/`boot_app0.bin`/`app.bin` come from the build (CI bundle or
    the local build dir); `provision.py` adds them to the manifest with their offsets so the flasher
    has a single authoritative list.

Never log the password or hash. Zeroize the password bytearray after use.

---

## 11. Flasher integration — `headless-marauder-gui`

Additive only; plain Marauder stays the core/default.

- `marauder_core/flasher.py`: add `suicide_bundle_files(chip, bundle_dir)` and
  `flash_suicide(port, chip, bundle, on_line, baud)` building **one** `write_flash` pair list:
  `bootloader@(0x0|0x1000)`, `partitions@0x8000`, `boot_app0@<real>`, `app@0x10000`,
  `guardcfg@<nvs off>`, `otadata_blank@<otadata off>` — offsets from the bundle manifest, reusing
  the existing `_run_stream` / `--flash_size detect` / `-z` plumbing.
- `gui_qt/app.py` `FlasherDialog`: a single **"Suicide"** checkbox. Unchecked → today's behavior.
  Checked → reveal a minimal sub-panel: **password**, **arm pin/level**, **dead-man** toggle; the
  variant list now offers the suicide build for the detected chip. A **separate** "Flash Encryption
  + Secure Boot (T2 — IRREVERSIBLE eFuse)" checkbox carries a blocking warning.
- Password hashing happens **host-side in the GUI process** (reuse `provision.py`), before flashing.
- Suicide build `.bin`s come from the Suicide-Marauder repo's per-board CI releases (downloaded like
  the normal release) or a chosen local bundle dir.

---

## 12. Tooltips-everywhere (whole app)

Every interactive widget across **all three** front-ends gets hover help:
- **Qt** (`gui_qt/app.py`): `setToolTip()` on every button/checkbox/radio/combo/lineedit/menu action
  /table header — extend the existing `_cmd_tooltip()` pattern with a central `TIPS` dict.
- **Tk** (`gui/*.py`): add a small `Tooltip` helper (Tk has no native tooltip) and attach it.
- **Textual TUI** (`tui/app.py`): set the `tooltip=` property on widgets.

Tooltip copy lives in one place per front-end so it stays consistent and is easy to audit.

---

## 13. Status of risky/unresolved items (carried from research)

| Item | Status | Where handled |
|------|--------|---------------|
| Self-erase of running app | **UNVERIFIED** — needs sacrificial-board spike | `docs/SPIKE-PLAN.md`, gated by SAFE_MODE |
| T1 vs T2 (Secure Boot/FE) | decision: build both, T1 default, T2 opt-in | `§8`, flasher `§11` |
| GPL/LGPL distribution (ESPAsyncWebServer LGPL static link) | needs legal note before redistributing binaries | `docs/LICENSING.md` |
| SD remanence (FTL) | documented best-effort, not guaranteed | `§8`, `SAFETY.md` |
| Low-battery boot policy | **brownout/undervoltage boot SUPPRESSES destruction (never wipes), but the CORRECT PASSWORD IS STILL REQUIRED to boot** (no bypass) — reliability-first *without* a free gate skip | `BootGate` / `GateConfig`, `THREAT-MODEL.md` (brownout weaponization) |
| KDF iteration tuning | default 10000, tune on target for ~1 s UX | `§9` |
| Supply chain (flash-time trust + tool pinning) | flash host is trusted at flash time; firmware/tools pinned toward known-good versions | `§14`, `THREAT-MODEL.md` |

---

## 14. Supply chain — flash-time trust and tool pinning

The provisioning/flash host is part of the **trusted computing base at flash time**: it types and
hashes the password, runs `provision.py`/`nvs_partition_gen`/`esptool`, and writes the bundle. A
compromised host at flash time can substitute firmware, weaken the config, or capture the password
**before** any on-device protection exists — no on-device control can defend against a hostile
flasher. So flash only from a host you trust, over a known-good toolchain.

To shrink that window, the host tools and firmware images should be **pinned toward exact/known-good
versions** rather than floating: `esptool`, `esp-idf-nvs-partition-gen`, `pyserial`, and the suicide
build `.bin`s. `host/requirements.txt` (provisioner) and `headless-marauder-gui/requirements.txt`
(flasher) pin toward known-good versions today; the **next hardening step** is to add wheel hashes
(`pip install --require-hashes`) and pin firmware bundles by signed tag / out-of-band digest. This
complements the bundle integrity note in `THREAT-MODEL.md`: a `sha256` co-located in the same
`bundle.json` guards against corruption/accident, not a determined attacker — real integrity needs an
**out-of-band/signed manifest**.
