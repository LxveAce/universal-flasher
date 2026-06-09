# Suicide Marauder — Hardware Support & Arming-Switch Wiring

> Per-board support matrix, the arming-switch wiring (armed = drive the pin to `arm_level`; floating
> = NOT-ARMED), the **forbidden strapping pins** per chip, and recommended physical switches.
>
> This is a **reference**; the canonical pin defaults, NVS keys, and flags live in
> [`SPEC.md`](SPEC.md) §7 and the headers. Where this disagrees with `SPEC.md`, **`SPEC.md` wins**.
> All hardware facts here are grounded in [`RESEARCH-DIGEST.md`](RESEARCH-DIGEST.md) and carry the
> verification tags from its adversarial-verification sections. Framing/limits:
> [`SAFETY.md`](SAFETY.md), [`THREAT-MODEL.md`](THREAT-MODEL.md).

This is an **owner-only, defensive** anti-forensic layer for an ESP32 Marauder you own. Nothing here
enables wiping unless the board is provisioned **and** master-armed **and** a trigger fires
(`ARCHITECTURE.md` §1).

---

## 1. The one rule that drives every pin choice

An arming line read at boot must **never** live on a strapping/boot pin. The same logic level you
read for "armed" can silently divert the chip into UART/USB download mode, lock the part into 1.8 V
flash mode and brown it out, or be overridden by the chip's own internal pull at reset — every one
of which defeats the security goal, and some of which **fail silently without ever running the wipe**
(RESEARCH-DIGEST: *An arming switch read at boot must NOT live on a strapping/boot pin*). Because the
gate runs in `setup()` at the **top of the app**, not in the bootloader, the pin is read well after
the reset/strapping window — so a **non-strapping** GPIO is read at leisure with debounce, avoiding
the timing hazard entirely (`ARCHITECTURE.md` §3; RESEARCH-DIGEST: *Read at boot in setup() … not in
the reset/strapping window*).

---

## 2. Forbidden strapping pins per chip (never an arming pin)

All entries below are **CONFIRMED** against Espressif primary datasheets / esptool boot-mode docs in
RESEARCH-DIGEST's adversarial verifications.

| Chip | Forbidden strapping/boot pins | Why (the dangerous ones) |
|------|-------------------------------|--------------------------|
| **Classic ESP32 / S2** | `GPIO0, GPIO2, GPIO5, GPIO12 (MTDI), GPIO15 (MTDO)` | `GPIO0` LOW = UART download; **`GPIO12` HIGH = 1.8 V VDD_SDIO → 3.3 V-flash brownout, fails to boot/flash**; `GPIO2` must be LOW/floating for download; `GPIO15` LOW silences ROM msgs; `GPIO5` defaults HIGH (SDIO timing) |
| **ESP32-S3** | `GPIO0, GPIO3, GPIO45, GPIO46` | `GPIO0` LOW = download; `GPIO46` must be floating/LOW for bootloader; **`GPIO45` sets VDD_SPI flash voltage (the S3 analog of classic `GPIO12`)**; `GPIO3` is JTAG-source select with **no internal pull** (floats unpredictably) |
| **ESP32-C3** | `GPIO2, GPIO8, GPIO9` | `GPIO9` (internal pull-up) LOW = download; `GPIO8` must be HIGH for reliable bootloader entry; **`GPIO8=0 AND GPIO9=0` is INVALID → undefined behavior**; do not hang high-value caps on `GPIO9` (can force download mode) |

**Also off-limits regardless of chip:** the SPI-flash / PSRAM pins — classic `GPIO6–11`; S3
~`GPIO26–37` (octal-PSRAM N16R8 consumes `GPIO33–37`); C3 `GPIO12–17`. Touching these breaks
flash/PSRAM access (RESEARCH-DIGEST: *Never use flash/PSRAM pins*).

**Input-only pins need an external pull-down.** Classic ESP32 `GPIO34–39` (and CYD `GPIO35`, StickC
`G36`) are **input-only with NO internal pull resistors** — `INPUT_PULLDOWN` silently does nothing,
leaving a floating, indeterminate boot read. They are fine as a **read-only** arming input *only* if
you fit an **external 10 kΩ pull-down**; `arm_pull` is a no-op in hardware there. `ArmingSwitch.h`
exposes `pinIsInputOnly(pin)` so the firmware/host can warn (RESEARCH-DIGEST: *GPIO34–39 are
INPUT-ONLY and have NO internal pull-up or pull-down resistors* — CONFIRMED; `SPEC.md` §7).

---

## 3. Fail-safe arming-switch wiring (load-bearing)

The safe default for a tamper/dead-man line is **"no confirmed-armed signal = NOT-ARMED."** Use an
internal **pull-down** (`arm_pull = 2`) — or an **external 10 kΩ pull-down** on input-only pins — and
wire the switch so that the **intact, sealed, ARMED position is the only thing that drives the pin to
`arm_level` (default HIGH, 3.3 V).** Then a **cut, unplugged, corroded, removed, or floating** wire
collapses to LOW = NOT-ARMED (RESEARCH-DIGEST: *FAIL-SAFE DESIGN … no confirmed-armed signal =
DISARMED = wipe* — CONFIRMED). This is the inverse of the conventional `INPUT_PULLUP` + active-LOW
button: with a pull-up, snipping the harness would read HIGH = "safe" and an attacker defeats the
dead-man by simply cutting the wire.

Combined with the master `armed` flag this gives **two-factor safety**: a fresh/disarmed board
cannot wipe at all, but an **armed** board treats switch removal as a dead-man trip
(`ARCHITECTURE.md` §1; `ArmingSwitch.h`).

```
            3.3V
             |
             o   <-- "ARMED" throw  (intact switch in armed position drives pin HIGH = arm_level)
              \
               \   SPDT / keyswitch / reed / tilt / case-open
                \
   arm_pin <-----o  (switch common)
      |
      +---[ internal 45k pull-down  OR  external 10k pull-down ]---+
      |    (arm_pull = 2; MANDATORY external on input-only 34-39)  |
     GPIO                                                         GND

  ARMED      = switch closed to the 3.3V throw  -> pin reads arm_level (HIGH)   = ARMED
  NOT-ARMED  = switch open / cut / unplugged / floating -> pull-down -> LOW     = NOT-ARMED
               (when master-armed + deadman=1, this triggers SelfDestruct)
```

**Boot read recipe** (matches `ArmingSwitch.h` constants): configure the pin per `cfg`
(`INPUT_PULLDOWN` for active-HIGH; account for input-only pins), settle ~10 ms, sample **8 times**
~2 ms apart, and return `ARMED` **only if every sample equals `arm_level`** — any ambiguity or a
single NOT-ARMED read is treated as NOT-ARMED. Reed/hall switches can bounce up to ~100 ms; for those
widen the sampling window (RESEARCH-DIGEST: *Reading reliably AT BOOT … sample multiple times … treat
any non-confirmed-armed result as disarmed*). The default values are `arm_level=1` (HIGH),
`arm_pull=2` (pulldown), `deadman=1` (`SPEC.md` §4).

**Brown-out / undervoltage caveat:** a low-battery boot (common on StickC / Cardputer) **SUPPRESSES
destruction (never wipes) but the CORRECT PASSWORD IS STILL REQUIRED to boot** — no gate bypass
(reliability-first; `SPEC.md` §13, `ARCHITECTURE.md` §1, `THREAT-MODEL.md` "Brownout weaponization").
The sagging rail's arming line is not read and the wipe cannot fire, but the device does not open: the
gate still demands the password.

**Optional hardening (the obvious bypass).** A determined attacker who opens the case could short the
pin straight to 3.3 V to hold it "armed." To resist that, replace the bare switch with a
**resistor-coded loop read on an ADC pin**, so the armed state is a specific voltage *window* and
**both** a short-to-GND **and** a short-to-VCC fall out of band = NOT-ARMED; optionally pair with a
signed/eFuse token (RESEARCH-DIGEST: *Harden against the obvious bypass*). This is out of scope for
the default build but documented for high-threat owners.

---

## 4. Per-board support matrix

`arm_pin` defaults follow `SPEC.md` §7. "Can self-destruct standalone?" = can the board wipe its own
internal flash with **no host attached** (the wipe is pure firmware on internal flash, so this is YES
on every class; only the removable SD is an evidence gap, and only while inserted — RESEARCH-DIGEST:
*Standalone self-destruct is feasible on EVERY class*). "Password ENTRY standalone?" is the separate
question of whether a typed password can be verified without a host.

| Board class | Chip | Flash | Bootloader offset | SD interface | Input class (`GATE_INPUT_*`) | Default `arm_pin` | Free-GPIO note | Self-destruct standalone? | Password entry standalone? |
|---|---|---|---|---|---|---|---|---|---|
| Classic ESP32 dev / **Lonely Binary Gold** / bare WROOM | ESP32 | 4 MB (typ.) | **0x1000** | SD over SPI (varies) / often none | `SERIAL` (default) | **GPIO27** | many free pins; arming GPIO trivial | **YES** | **NO** — host/serial `unlock <pw>` |
| **CYD 2.8"/3.5"** (ESP32-2432S028R) | ESP32 | 4 MB | **0x1000** | VSPI shared w/ touch: `IO5/18/19/23` | `TOUCH` | **GPIO27** (CN1) | only `IO22`, `IO27` (full I/O) + `IO35` (input-only, ext 10k) free; rest = TFT/SD/touch | **YES** | **YES** — on-screen touch PIN/keypad |
| **Marauder Mini** (joystick) | ESP32 | 4 MB | **0x1000** | SD over SPI | `MINI_KB` | **GPIO27** (verify variant) | joystick eats `13/34/35/36/39`; use a Grove/free pin | **YES** | **YES** — `miniKeyboard(do_pass=true)` |
| **M5Cardputer** | ESP32-S3 | 8 MB | **0x0** | microSD: `G12/14/39/40` | `CARDPUTER` | Grove **G2** (`G1`/`G2`) | Grove HY2.0 `G1/G2` are the free, non-strapping pins | **YES** | **YES** — native QWERTY (strongest) |
| **Marauder Mini / MultiBoard (S3)** | ESP32-S3 | 8–16 MB | **0x0** | SD over SPI | `MINI_KB` / `SERIAL` | Grove **G2** | avoid `0/3/45/46` and flash/PSRAM `26–37` | **YES** | depends on screen/input present |
| **M5StickC Plus2** | ESP32-PICO (classic core) | 4 MB | **0x1000** | none (no SD) | `BUTTONS` (weak) | **G32** (or G33) | Grove exposes `G32/G33`; `G36` input-only (ext 10k); avoid `G0` | **YES** | **WEAK** — 2–3 button combo only |
| **ESP32-C3 dev** | ESP32-C3 | 4 MB (typ.) | **0x0** | SD over SPI (varies) | `SERIAL` | **GPIO10** | avoid `2/8/9` and flash `12–17`; `GPIO3-7/10` safe | **YES** | **NO** — host/serial |

Notes:
- **Bootloader offset** is `0x1000` on classic ESP32 / S2 and `0x0` on S3 / C3 / C6 / H2 — the
  flasher must branch on this (`ARCHITECTURE.md` §3; RESEARCH-DIGEST CONFIRMED). P4 / C5 / H4 use
  `0x2000`, so resolve the offset per target rather than a hard binary branch.
- **GUARDIAN** variant requires **8 MB+** (16 MB preferred), so it is only applicable to the S3 rows
  with sufficient flash; the 4 MB classic/CYD/Mini rows are **FORK-only** (`ARCHITECTURE.md` §2).
- The CYD and all-in-one boards are pin-starved: almost every GPIO is consumed by display + touch +
  SD + keyboard matrix, and the survivors are often input-only — fine for a read-only arming switch,
  little else (RESEARCH-DIGEST: *Arming-switch GPIO placement is the real bottleneck*). **Verify the
  exact variant's schematic before committing a pin** — Marauder hardware varies (CC1101 / NRF / SD
  options differ), and `GPIO12` is even used as SD_CS on some classic Marauder builds.

---

## 5. Per-board free-pin detail (for choosing a landing spot)

- **Classic ESP32 / Lonely Binary Gold / headless:** full bidirectional pins safe for an arming
  switch include `GPIO4, 13, 16, 17, 18, 19, 21, 22, 23, 25, 26, 27, 32, 33`. Prefer an RTC-capable
  non-strapping pin (e.g. `32`/`33`) if you ever want a deep-sleep tamper wake. Default **GPIO27**.
- **CYD (ESP32-2432S028R):** consumed — display `IO2/12/13/14/15` + backlight `IO21`; touch
  `IO25/32/33/36/39`; SD `IO5/18/19/23`; RGB LED `IO4/16/17`; speaker `IO26`; LDR `IO34`; boot
  button `IO0`. **Free:** `IO22` and `IO27` on CN1 (full I/O; `IO27` has pull-up R18) and input-only
  `IO35` (needs external 10k pull-down). Default **GPIO27**; avoid `IO22` if you want I2C free.
- **M5Cardputer (StampS3):** display `G33–38`; SD `G12/14/39/40`; keyboard matrix via 74HC138 on
  `G3–11/13/15`; mic/speaker/IR on `G41–46`; boot on `G0`. **Free:** Grove HY2.0 `G1`/`G2` — use one
  for arming (default **G2**). If both Grove pins are needed for I2C you have no spare without
  sacrificing a peripheral.
- **M5StickC Plus2:** display `13/15/5/14/12`; buttons `A=37,B=39,power=35`; mic `34`; IR `19`;
  buzzer `2`; I2C `21/22`; power-hold `G4`. Exposed header/Grove: `G0, G25, G26, G32, G33, G36`.
  **Avoid `G0` (strapping).** Default **G32** or **G33**; `G36` is input-only (external 10k).
- **ESP32-C3 dev:** safe free pins `GPIO3, 4, 5, 6, 7, 10` (default **GPIO10**); avoid `2/8/9`,
  `11`(VDD_SPI), and flash `12–17`.

---

## 6. Recommended physical switches

The arming control should be a **hardware** switch/jumper, not a software-only flag a coercer's
forensic tool could flip — sever the circuit, don't politely ask (RESEARCH-DIGEST: *Hardware (hard)
kill switches beat software switches for assurance*). In every option below, wire the **intact /
sealed / armed** state to drive `arm_pin` to `arm_level` (HIGH), so disturbing it releases to the
pull-down = NOT-ARMED (§3).

| Switch type | How to wire as the dead-man / arming line | Best for |
|---|---|---|
| **SPDT toggle** | common → `arm_pin`; "armed" throw → 3.3 V; (optional other throw → GND for explicit disarm). Pull-down still defines the floating default. | bench / deliberate arm-disarm by the owner |
| **Keyswitch** (keyed lock) | same as SPDT; key-in-armed drives HIGH. Removing the key (open) = NOT-ARMED. | physical-key custody; "armed only while keyed" |
| **Reed switch + magnet** | normally-open reed closed by an attached magnet drives the pin HIGH; magnet removed (case opened / device separated) = NOT-ARMED. Widen debounce (~100 ms reed bounce). | case-open / separation detection |
| **Tilt switch** | armed orientation closes the contact to 3.3 V; moving/inverting the device opens it = NOT-ARMED. | "moved from its spot" tamper |
| **Case-open (lid) switch** | sealed lid holds the contact to 3.3 V; opening the case releases to NOT-ARMED. | enclosure-intrusion detection |

Tune any physical trigger against accidental activation and require a deliberate, sustained
condition — the BusKill lesson of a breakaway "strong enough not to come undone unexpectedly but weak
enough that a hard yank triggers it" (RESEARCH-DIGEST: *Trigger-source robustness matters*). Add a
small series resistor (~1 kΩ) for ESD/noise on the safe GPIO, but **avoid large capacitors** on any
strapping-adjacent line (C3 `GPIO9` caps can force download mode). Surface arming state with an LED
where the board allows it, so the owner always knows whether the device is hot (RESEARCH-DIGEST
REQ-11).
</content>
