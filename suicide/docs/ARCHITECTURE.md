# Suicide Marauder — Architecture

> This document describes the **end-to-end design**: the two build variants and why **FORK** is the
> default, the boot flow, the partition layout, the boot-gate state machine, the wipe pipeline, the
> T1/T2 anti-forensic tiers, and how the whole thing plugs into the headless flasher.
>
> It is a **reference** layered on top of the canonical contract. Where this file and
> [`SPEC.md`](SPEC.md) appear to disagree, **`SPEC.md` wins** — it is the single source of truth for
> names, NVS keys, offsets, build flags, and the state machine. Everything here is grounded in
> [`RESEARCH-DIGEST.md`](RESEARCH-DIGEST.md); citations point there. Framing and limits live in
> [`SAFETY.md`](SAFETY.md) and [`THREAT-MODEL.md`](THREAT-MODEL.md).

Suicide Marauder is an **owner-only, defensive anti-forensic ("duress") layer** for an ESP32
Marauder that the operator owns — the embedded-hardware analogue of Kali's LUKS Nuke, GrapheneOS's
duress PIN, and BusKill. It is **not** a tool for evading lawful process (`THREAT-MODEL.md`,
RESEARCH-DIGEST "Duress/panic" finding *LEGAL/ETHICAL framing is mandatory*).

---

## 1. Design goals and the safety spine

Every architectural choice traces back to one converged lesson from the duress-systems literature:
**fear of accidental destruction**. BusKill ships only non-destructive triggers by default and adds
friction to destructive ones; GrapheneOS is criticized precisely because it has no confirmation/undo
path (RESEARCH-DIGEST: *FAIL-SAFE DEFAULT = least-destructive action*; *Lack of a confirmation/undo
path is the #1 documented failure mode*). So the architecture is built around a **layered safety
model** in which a wipe is physically impossible unless **all** of these hold at once (`SPEC.md` §6,
`SAFETY.md`):

1. **Provisioned** — a password hash exists in `guardcfg` NVS. A non-provisioned board behaves like
   plain Marauder and `BootGate::run()` returns `GATE_PASS` immediately.
2. **Master-armed** — the `armed` flag in NVS is `1`. **Default `0` (DISARMED).**
3. **A trigger fires** — wrong-password count reaches `max_att`, **or** the dead-man line is not in
   the armed position while in dead-man mode.

This is the "explicit two-factor to destroy" requirement (RESEARCH-DIGEST REQ-3): neither arming
alone nor a stray trigger alone may destroy data. The **correct password always wins** and never
wipes (REQ-4; `SPEC.md` §6 invariants). All "are you sure?" friction lives at **provisioning time**
in `host/provision.py`; once a trigger legitimately fires, the wipe is fast and non-abortable so a
coercer cannot interrupt it (REQ-10). Per the user's standing directive, **reliability beats
power**: a brownout/undervoltage boot **suppresses destruction (never wipes) but still REQUIRES the
correct password to boot** — no gate bypass (`SPEC.md` §13, `THREAT-MODEL.md` "Brownout
weaponization"), and any ambiguous arming read is treated as NOT-ARMED.

---

## 2. Two build variants — FORK (default) vs GUARDIAN

The gate has to run **before** Marauder's UI loads, on every supported hardware class, without
forcing the owner onto a larger flash chip. Two strategies satisfy that; the digest's integration
research recommends the first ("ESP32Marauder integration: A vs B" → *RECOMMEND Strategy A*).

### 2.1 FORK *(default — all flash sizes, including 4 MB)*

The gate is compiled **into** a fork of ESP32Marauder and called from `setup()`. It reuses
Marauder's own display, keyboard, touch, and SD drivers, so the password prompt works on every
input class with almost no new UI code (RESEARCH-DIGEST: Marauder already ships `miniKeyboard(...,
do_pass=true)`, `keyboardInput(...)`, and the Cardputer QWERTY matrix — "boot-password … UX
feasibility" findings). Self-destruct is the running app erasing every **other** partition, then the
SD, then — optionally — its own boot chain.

- **Hook point** (`SPEC.md` §1, `firmware/integration/INTEGRATION.md`): insert `BootGate::run()` in
  `ESP32Marauder.ino` **after** `display_obj.RunSetup()` and **before** `settings_obj.begin()`. The
  digest confirms this region against the real source: `setup()` at ~L227, `display_obj.RunSetup()`
  at ~L312, `settings_obj.begin()` at ~L348 (RESEARCH-DIGEST: *setup in esp32_marauder.ino* —
  CONFIRMED). Anchor on the **strings**, not line numbers, because Marauder revisions move them.
- **Partition table** = Marauder's normal `min_spiffs` layout **plus** a dedicated `guardcfg` NVS
  partition (§4 below).
- **Licensing note**: Marauder is MIT, so a fork carries no copyleft obligation for Marauder itself;
  only the bundled LGPL-3.0 `ESPAsyncWebServer` has relink/notice duties if binaries are
  redistributed (RESEARCH-DIGEST: *License is MIT, not GPL*; see `docs/LICENSING.md`).

### 2.2 GUARDIAN *(optional hardening — 8 MB+ only)*

A separate tiny **factory** app gates first, then hands off into an **unmodified** Marauder in
`ota_0` via `esp_ota_set_boot_partition(ota_0)` + `esp_restart()` — the documented factory→OTA
transition (RESEARCH-DIGEST: *A factory app CAN validate, then set boot to an OTA partition and
reboot into it* — CONFIRMED). Advantages: a cleaner GPL/licensing boundary (Marauder ships
untouched), and a cleaner brick (the gate is not erasing its own running region until the very last
moment, and can re-assert via factory fallback).

It does **not** fit in 4 MB. Two ~1.875 MB app slots (`0x1E0000` each) plus filesystems overflow a
4 MB part; you need **8 MB minimum, 16 MB preferred** (RESEARCH-DIGEST: *Two ~1.9 MB apps … do NOT
fit in 4 MB* — CONFIRMED, with verified arithmetic).

> **Collision to respect (verified, `SDInterface.cpp` ~L217–223):** Marauder's own SD updater already
> calls `esp_ota_get_next_update_partition` + `esp_ota_set_boot_partition`, so a Guardian that also
> manipulates `otadata` will collide (RESEARCH-DIGEST: *Marauder already chainloads OTA with both
> slots* — CONFIRMED). The Guardian must therefore select the **factory** partition explicitly and
> re-arm by erasing `otadata` (passing the factory partition object to `set_boot_partition` does
> exactly this — *if set boot partition to factory bin, just format ota info partition*), and should
> enable `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE` so a Marauder that never marks itself valid
> auto-reverts to the Guardian on the next reset.

### 2.3 Why FORK is the default

| Axis | FORK (default) | GUARDIAN |
|------|----------------|----------|
| Flash size | works on **4 MB** through 16 MB | **8 MB minimum**, 16 MB preferred |
| UI code | reuses Marauder's drivers (near-zero new UI) | must reimplement display/touch/keyboard/SD |
| OTA collision | none (single app slot; SD-OTA-self-update disabled on 4 MB build) | must avoid Marauder's `otadata` writes |
| Brick cleanliness | app erases its **own** running region last (the UNVERIFIED primitive) | gate is not the running app at brick time → cleaner |
| Licensing surface | fork of MIT Marauder (only LGPL `ESPAsyncWebServer` relink concern) | Marauder binary untouched → cleanest boundary |

FORK wins on the two things the user actually has in the field: it runs on the common **4 MB**
classic-ESP32 / CYD boards, and it reuses the input drivers instead of duplicating them
(RESEARCH-DIGEST integration verdict: *RECOMMEND Strategy A; keeps stock min_spiffs, headroom,
reuses drivers*). GUARDIAN is documented and partition-templated for 16 MB as an opt-in hardening
path for boards that have the flash and want the cleaner brick + GPL boundary.

**The default scaffold targets FORK.** Variant selection is compile-time: exactly one of
`SUICIDE_FORK` / `SUICIDE_GUARDIAN` (`SPEC.md` §5).

---

## 3. Boot flow (end to end)

The ESP32 boot chain is fixed by the ROM: **ROM 1st-stage bootloader → 2nd-stage bootloader in
flash → partition table @ `0x8000` → `otadata` → selected app** (RESEARCH-DIGEST: *ESP32 boot is a
multi-stage chain* — CONFIRMED). The gate inserts itself at the **top of the app**, not in the
bootloader, which is exactly why the arming pin can be a normal GPIO read at leisure in `setup()`
rather than a fragile reset-window strapping read (see `HARDWARE.md`).

```
power-on / reset
   |
   v
ROM bootloader  ->  2nd-stage bootloader (0x1000 classic / 0x0 S3,C3,C6,H2)
   |
   v
partition table @ 0x8000  ->  otadata
   |
   +-- FORK:     boots app0 (forked Marauder, gate compiled in)
   |                 setup(): ... display_obj.RunSetup()
   |                          >>> BootGate::run()   <<<  (gate runs here)
   |                          settings_obj.begin() ... Marauder UI
   |
   +-- GUARDIAN: blank/erased otadata -> boots factory (Guardian)
                     Guardian::gate() == GATE_PASS
                          -> esp_ota_set_boot_partition(ota_0) + esp_restart()
                          -> ota_0 = unmodified Marauder
```

The **chip-dependent bootloader offset** (`0x1000` on classic ESP32 / S2; `0x0` on S3 / C3 / C6 /
H2) is the single most dangerous thing to hardcode in the flasher; get it wrong and the board won't
boot (RESEARCH-DIGEST: *2nd-stage bootloader flash offset is CHIP-DEPENDENT* — CONFIRMED; note the
caveat that P4/C5/H4 use `0x2000`, so the flasher should resolve the offset per target rather than a
hard binary branch). Never hardcode the `otadata`/`nvs` offsets either — read them from the build's
partition table (`SPEC.md` §2; stock IDF `otadata` is `0xd000`, Marauder's is `0xe000` because it
enlarges `nvs`).

---

## 4. Partition layout

Partition names are canonical (`SPEC.md` §3). The gate's config lives in a dedicated data partition
named **`guardcfg`** (subtype `nvs`), kept **separate** from Marauder's own `nvs`/`spiffs` so a
Marauder factory-reset or SPIFFS format cannot wipe the gate state (RESEARCH-DIGEST: *Add a dedicated
small data,nvs partition for Guardian config … kept separate*). Host and firmware both key off the
name `guardcfg`; **do not rename it or change its subtype.**

### 4.1 FORK on 4 MB (classic ESP32 / CYD) — `firmware/partitions/suicide_4MB.csv`

Derived from Marauder's `min_spiffs`, carving an 8 KB `guardcfg` out of spiffs. On 4 MB the second
app slot is dropped, so Marauder's SD-OTA self-update is disabled on this build (a documented trade;
this is also what removes the `otadata` collision risk for FORK).

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

App partitions must stay 64 KB (`0x10000`) aligned or `gen_esp32part.py` errors out
(RESEARCH-DIGEST: *Partition table … App partitions MUST be aligned to 0x10000*).

> **`scratch` is mandatory and load-bearing for SAFE_MODE** (`SPEC.md` §3, §5). It is a dedicated
> erase target so a `SUICIDE_SAFE_MODE` dry run never touches `guardcfg` / `ota_0` / `nvs` / `spiffs`
> / the running app. If a build defines `SUICIDE_SAFE_MODE` but the partition table has **no**
> `scratch` partition, the firmware **must refuse to simulate** — log an error and perform **zero**
> erases; it must **never** fall back to a live partition. Every partition CSV (4 / 8 / 16 MB +
> guardian) carries a `scratch`.

### 4.2 FORK on 16 MB — `firmware/partitions/suicide_16MB.csv`

Roomy: full `min_spiffs`-style spiffs, a larger `guardcfg`, and coredump, with no pressure on any
region.

### 4.3 GUARDIAN on 16 MB — `firmware/partitions/suicide_guardian_16MB.csv`

`factory` (Guardian) + `ota_0` (Marauder) + `otadata` + Marauder `nvs` + `guardcfg` + `spiffs`. This
is the textbook "factory gates OTA" structure: a blank `otadata` boots `factory`, and
`set_boot_partition(ota_0)` makes the next boot land in Marauder (RESEARCH-DIGEST: *When factory +
ota_0 both exist, the bootloader boots factory until otadata points to ota_0*).

---

## 5. Boot-gate state machine — `BootGate::run()`

Returns `GateResult { GATE_PASS, GATE_TRIGGERED }`, called once early in `setup()` (`SPEC.md` §6;
`BootGate.h`). `GATE_TRIGGERED` is only ever *returned* under `SUICIDE_SAFE_MODE`; a real trigger
does not return (the wipe runs and the device bricks or halts).

```
                       +-------------------------------+
   power-on ---------> | cfg = GateConfig::load()       |
                       +---------------+----------------+
                                       |
                          !cfg.provisioned?  --YES--> GATE_PASS   (fail-safe: never wipes)
                                       | NO
                                       v
                          cfg.armed == 0 ?   --YES--> GATE_PASS   (master DISARMED, default)
                                       | NO            (may still prompt cosmetically)
                                       v
                       +-------------------------------+
                       | armedLine = ArmingSwitch::read |  (8 samples, 10ms settle, unanimous)
                       +---------------+----------------+
                                       |
            cfg.deadman==1 && armedLine==NOT_ARMED ? --YES--> SelfDestruct(REASON_DEADMAN)
                                       | NO                    -> GATE_TRIGGERED (no return)
                                       v
              +------------------- password loop --------------------+
              |  pw = Input::getPassword()  (serial/touch/kb/...)    |
              |  GateCrypto::verify(pw,cfg) ? --YES--> att_ct=0;     |
              |                                        commit;       |
              |                                        zeroize(pw);  |
              |                                        GATE_PASS     |
              |  NO: att_ct += 1; commit();  zeroize(pw);            |
              |      att_ct >= max_att ? --YES--> SelfDestruct(      |
              |                                   REASON_ATTEMPTS)   |
              |                                   -> GATE_TRIGGERED  |
              |      NO: backoff(); re-prompt -----------------------+
              +------------------------------------------------------+
```

**Invariants** (load-bearing — `SPEC.md` §6, `BootGate.h`):

- **Correct password always boots and never wipes**, regardless of switch state (after the dead-man
  pre-check). This is the GrapheneOS "legit credential wins on collision" rule (RESEARCH-DIGEST
  REQ-4).
- **Unprovisioned or master-disarmed → physically cannot wipe.**
- The attempt counter is **monotonic and power-cycle-safe**: `att_ct` is committed to `sgate_rt` NVS
  **before** the gate responds to a wrong attempt, so power-cycling mid-attempt cannot reset it
  (RESEARCH-DIGEST: *a wrong-attempt counter … must be tamper-resistant/monotonic*; `GateConfig.h`
  `GateRuntime::commitAttempts()`). It resets to `0` only on a correct password.
- In dead-man mode the switch is checked **before** the password — a missing switch is terminal
  (user requirement: a no-switch boot, when armed, is a wipe).

Two trigger reasons reach `SelfDestruct` from the gate (`BootGate.h`): `REASON_DEADMAN` and
`REASON_ATTEMPTS`. A third, `REASON_HOST_WIPE`, exists for an explicit `wipe` command over serial in
the host-assisted (headless) input mode.

#### 5.0.1 Authenticated host-wipe (`REASON_HOST_WIPE`)

On a `GATE_INPUT_SERIAL` build the owner can panic-wipe over USB, but the command is
**authenticated and deliberate**, not a bare trigger (`SPEC.md` §6). Typing `wipe` does **not**
destroy anything by itself: the gate then **prompts for the password** and only calls
`SelfDestruct::trigger(cfg, REASON_HOST_WIPE)` on a **correct** password — a wrong one counts as a
normal failed attempt (`att_ct += 1`, committed, subject to `max_att`). This means an
unauthenticated or accidental `wipe\n` — a terminal paste, serial-line noise, a reconnect banner —
**can never destroy data**; there is no unauthenticated destruct path. The command is only available
when the board is **master-armed** (a disarmed/unprovisioned board ignores it and boots, per the
layered safety model). It is the deliberate, owner-initiated analogue of the duress trigger, gated by
the same credential the boot prompt uses.

### 5.1 Input classes

Exactly one `GATE_INPUT_*` per build (`SPEC.md` §5), mirroring Marauder's own input defines:

- `GATE_INPUT_SERIAL` *(default)* — headless boards; password as `unlock <pw>` over USB serial.
- `GATE_INPUT_TOUCH` — on-screen PIN keypad (reuses Marauder `keyboardInput`).
- `GATE_INPUT_MINI_KB` — Marauder Mini joystick (`miniKeyboard(..., do_pass=true)`).
- `GATE_INPUT_CARDPUTER` — M5Cardputer native QWERTY (strongest entropy).
- `GATE_INPUT_BUTTONS` — M5StickC button-combo (weak; prefer host-assisted).

Feasibility per class is grounded in the digest's UX matrix: full on-device gate on touch / Mini /
Cardputer; weak button-combo on StickC; serial/host-assisted on truly headless boards
(RESEARCH-DIGEST: *boot-password + arming-switch + secure-wipe UX feasibility* findings).

---

## 6. Wipe pipeline — `SelfDestruct::trigger()`

**Hard reality first** (`SPEC.md` §8, `SelfDestruct.h`): there is **no runtime crypto-erase on
ESP32**. The flash-encryption AES key lives in a hardware **read- AND write-protected** eFuse, so
software can neither read it nor overwrite it — the magnetic-media "destroy the key, leave the
ciphertext" model does **not** map to ESP32 (RESEARCH-DIGEST: *A true instant CRYPTO-ERASE … is NOT
available at runtime* — CONFIRMED). Therefore the wipe is **bulk erase + overwrite**, and real
unrecoverability comes from **T2** (Secure Boot v2 + Flash Encryption), where the erased ciphertext
is meaningless and the gate cannot be reflashed past. Because NOR flash has no magnetic remanence, a
single erase pass is forensically sufficient; multi-pass is theater, though one optional
`esp_fill_random` overwrite pass defends against read-before-erase residue (RESEARCH-DIGEST:
*Single-pass overwrite is sufficient for NOR flash*).

The sequence is **non-abortable once started** and ordered so the boot chain dies **last** — doing
the data wipes first guarantees they actually complete before the CPU loses the ground under its
feet (RESEARCH-DIGEST: *Safe destruction ORDER … wipe all OTHER regions first, then self-immolate the
boot chain last* — CONFIRMED). Under `SUICIDE_SAFE_MODE` **every** step is redirected at the
dedicated **`scratch`** partition (§4.1) / dummy key and only logged — nothing real is destroyed
(`SPEC.md` §5; mandatory for testing; RESEARCH-DIGEST REQ-5). The `scratch` partition is therefore
**required** for SAFE_MODE: if it is absent, the firmware refuses to simulate and performs **zero**
erases rather than fall back to any live partition (`SPEC.md` §3).

```
SelfDestruct::trigger(cfg, reason)          [non-abortable]
  |
  |  Stage 1: wipeSD(cfg)            (if wipe_sd && card present)
  |     overwrite every file + free space with esp_fill_random  x sd_passes
  |     then card erase / format
  |     * best-effort: FTL wear-leveling / over-provisioning may retain remapped
  |       cells (documented, not hidden). At-rest SD encryption (T2) is the only
  |       real guarantee.  [SPEC §8.1; SAFETY.md SD remanence]
  |
  |  Stage 2: wipeInternal(cfg)      esp_partition_erase_range over:
  |     ota_0 / Marauder app  (if wipe_ota)
  |     spiffs                (if wipe_spiffs)
  |     Marauder nvs          (if wipe_nvs)
  |     coredump
  |     guardcfg  <-- LAST of the data (config is already in RAM)
  |     * these run fine from normal flash-resident code.
  |
  |  Stage 3: brickBootChain(cfg)    (if brick)   [IRAM-resident, noreturn]
  |     raw-erase the partition table (0x8000),
  |     the bootloader (0x1000 classic / 0x0 S3-C3),
  |     and the running app/factory region.
  v
  (real, non-SAFE brick: does not return)
```

### 6.1 The one UNVERIFIED primitive — Stage 3 self-erase

Stage 3 is the **single unverified part of the whole system** (`SPEC.md` §13; tracked in
`docs/SPIKE-PLAN.md`). A partition **cannot reliably erase itself while the CPU is executing code
XIP from it**, because flash erase forces the instruction/data cache **off**; the routine and every
symbol it touches must therefore live in **IRAM/DRAM** with interrupts and the scheduler disabled
(RESEARCH-DIGEST: *A partition cannot reliably erase itself while … executing code XIP from it* —
CONFIRMED). `SelfDestruct::brickBootChain()` is declared `IRAM_ATTR` + `__attribute__((noreturn))`
(`SelfDestruct.h`) for exactly this reason. It additionally requires building with
`CONFIG_SPI_FLASH_DANGEROUS_WRITE_ALLOWED=y`, because IDF by default `abort()`s any
write/erase overlapping the bootloader, partition table, or the running app's partition
(RESEARCH-DIGEST: *By DEFAULT, IDF forbids firmware from erasing/writing the bootloader …* —
CONFIRMED). Until a sacrificial-board spike validates it, this path is **kept behind
`SUICIDE_SAFE_MODE`** and the risk is commented in the code; T1 builds default `brick=0` and never
exercise it.

---

## 7. Anti-forensic tiers — T1 / T2

| | **T1** (default, dev/demo) | **T2** (opt-in, IRREVERSIBLE) |
|---|---|---|
| Secure Boot v2 | off | **on** |
| Flash Encryption | off | **on** (release mode) |
| `brick` default | `0` (reflashable after wipe) | `1` (boot chain erased last) |
| NVS encryption | off (salted hash is safe in plaintext NVS) | optional `nvs_keys` partition to hide `arm_pin`/`arm_level` |
| Result of a wipe | data-wiped but **re-flashable** board | **unrecoverable** board; erased ciphertext is meaningless |
| eFuse change | none | one-way, irreversible (burns Secure Boot / FE eFuses) |

Both tiers are built; **T1 is the default**, T2 is opt-in (`SPEC.md` §13). The salted PBKDF2 hash is
safe in **plaintext** NVS even on T1 — Flash Encryption's scope does not automatically cover NVS, and
the hash reveals nothing useful (`SPEC.md` §4). T2 exists because, given that runtime key-destroy is
impossible on ESP32, the *only* way to make a wiped board's residue truly worthless is to have stored
ciphertext in the first place and then erase it (RESEARCH-DIGEST: *Crypto-erase does NOT require
Secure Boot — but neither feature gives you a runtime key-destroy primitive*; *your security comes
from actually erasing the ciphertext*). T2's eFuse burns are one-way and can brick the board if
mishandled, so the flasher gates T2 behind a separate, blocking warning (§9).

---

## 8. Cryptography (summary; canonical detail in `SPEC.md` §9)

Password verification is **PBKDF2-HMAC-SHA256** via mbedtls (bundled with Arduino-ESP32). Argon2id
is infeasible — OWASP's 19 MiB minimum exceeds ESP32 RAM (`GateCrypto.h`). Host and device must
agree on `{salt, iter, dklen}`; defaults `iter=10000`, `dklen=32`, tuned so a verify takes ~1 s on the
target chip (`150000` measured ≈16.7 s on a classic ESP32 — far too slow for a boot gate) and recorded
in `guardcfg.kdf_iter`. The low count is correct here: the gate wipes after `max_att` wrong tries so
online brute-force is moot, and PBKDF2 is GPU-cheap so a high count buys no offline protection for the
(dumpable on T1) hash — real protection is T2 + a strong passphrase, not iteration count (`SPEC.md` §9). `verify()` uses a **constant-time**
compare (`GateCrypto::ctEqual`). The **plaintext password is never stored, never logged, never a CLI
argument**; only `{salt, pwhash, kdf_iter, kdf_dklen}` exist on device, and both host and firmware
zeroize the password buffer immediately after hashing (`SPEC.md` §4, §9, §10).

---

## 9. How it plugs into the headless flasher — `headless-marauder-gui`

Integration is **additive only**; plain Marauder stays the core default (`SPEC.md` §11).

- **`marauder_core/flasher.py`** gains `suicide_bundle_files(chip, bundle_dir)` and
  `flash_suicide(port, chip, bundle, on_line, baud)`, building **one** `write_flash` pair list from
  the bundle manifest: `bootloader@(0x0|0x1000)`, `partitions@0x8000`, `boot_app0@<real>`,
  `app@0x10000`, `guardcfg@<nvs off>`, `otadata_blank@<otadata off>` — reusing the existing
  `_run_stream` / `--flash_size detect` / `-z` plumbing. Offsets come from the bundle manifest, not
  hardcoded, honoring the chip-dependent bootloader offset rule (§3).
- **`gui_qt/app.py` `FlasherDialog`** gets a single **"Suicide"** checkbox. Unchecked = today's
  behavior. Checked reveals a minimal sub-panel — **password**, **arm pin/level**, **dead-man**
  toggle — and the variant list offers the suicide build for the detected chip. A **separate**
  "Flash Encryption + Secure Boot (T2 — IRREVERSIBLE eFuse)" checkbox carries a blocking warning.
- **Password hashing happens host-side in the GUI process** (reusing `host/provision.py`) **before**
  flashing — the plaintext never reaches the device or a log.
- The provisioner (`host/provision.py`, `SPEC.md` §10) emits `guardcfg.bin` (via
  `nvs_partition_gen`, confirmed *not* bundled with esptool), `otadata_blank.bin` (`0x2000` of
  `0xFF`, which forces first boot into factory/Guardian — **GUARDIAN only**), and a `bundle.json`
  manifest of `{file, offset}` pairs.
- Every interactive widget across all three front-ends (Qt / Tk / Textual) gets hover help from a
  single `TIPS` source per front-end (`SPEC.md` §12).

### 9.1 The `bundle.json` manifest is the complete flash list

The manifest is **authoritative**: its `files` array lists **every** image the flasher writes, each
as a `{file, offset}` pair, written in **one** `write_flash` pass (`SPEC.md` §10). The flasher does
not invent offsets — it consumes exactly this list (`flash_suicide` builds its `write_flash` pairs
straight from the manifest). The full list:

| Image | Offset | Source / notes |
|-------|--------|----------------|
| `bootloader.bin` | `0x0` (S3/C3/C6/H2) or `0x1000` (classic / S2) | **chip-derived** offset (§3); from the build |
| `partitions.bin` | `0x8000` | fixed; from the build |
| otadata seed | `<otadata off>` from the chosen CSV | **exactly one** of the two below (no collision) |
| `app.bin` | `0x10000` | fixed (64 KB-aligned); from the build |
| `guardcfg.bin` | `<guardcfg off>` from the chosen CSV | from `provision.py` (`nvs_partition_gen`) |

- **otadata seed — one only, variant-dependent:** **FORK** writes `boot_app0.bin` at the otadata
  offset (a normal seed → boots `app0`); **GUARDIAN** writes `otadata_blank.bin` (`0xFF`) there
  (→ boots `factory`/Guardian). The manifest contains **exactly one** of them at that offset, never
  both — this is what avoids the otadata collision (`SPEC.md` §10, §11).
- **Offsets for `guardcfg` and `otadata` are read from the chosen partition CSV**, never hardcoded
  (`0xe000` is Marauder-specific and not assumed); `partitions`/`app` are fixed and the bootloader is
  chip-derived (§3). `provision.py` adds `bootloader.bin` / `partitions.bin` / `boot_app0.bin` /
  `app.bin` (from the CI bundle or local build dir) to the manifest with their offsets so the flasher
  has a single source of truth.

---

## 10. Open / risky items (carried from `SPEC.md` §13)

| Item | Status | Where handled |
|------|--------|---------------|
| Stage-3 self-erase of running app | **UNVERIFIED** — sacrificial-board spike needed | `docs/SPIKE-PLAN.md`, gated by SAFE_MODE |
| T1 vs T2 | build both; T1 default, T2 opt-in | §7, flasher §9 |
| LGPL `ESPAsyncWebServer` static-link distribution | legal note before redistributing binaries | `docs/LICENSING.md` |
| SD remanence (FTL) | documented best-effort, not guaranteed | §6, `SAFETY.md` |
| Low-battery boot policy | brownout/undervoltage boot SUPPRESSES destruction (never wipes) but the CORRECT PASSWORD IS STILL REQUIRED to boot — no bypass (reliability-first) | `BootGate` / `GateConfig`, `THREAT-MODEL.md` |
| KDF iteration tuning | default 10000, tune on target for ~1 s UX | §8, `SPEC.md` §9 |
</content>
</invoke>
