# Hardware test log — SAFE_MODE gate on a classic ESP32

First real-silicon validation of the boot gate. **SAFE_MODE only — nothing was ever erased.**

## Device under test
| | |
|---|---|
| Board | Lonely Binary ESP32 "Gold" (headless, CH340K USB) |
| Chip | ESP32-D0WD-V3 rev v3.1, dual-core @240 MHz |
| Flash | 4 MB → `firmware/partitions/suicide_4MB.csv` |
| Port | USB serial @115200 |
| Toolchain | PlatformIO (`espressif32`, `board = esp32dev`, framework `arduino`) |

## Build
- A throwaway **SAFE_MODE serial harness** that links the real `firmware/bootgate/*` units
  (`GateConfig`, `GateCrypto`, `ArmingSwitch`, `SelfDestruct`, `BootGate`, `GateInput_serial`) plus a
  stub for "Marauder", built with `-DSUICIDE_SAFE_MODE -DGATE_INPUT_SERIAL -DARMING_PIN=27`.
- **Compiled clean on the first try** — no invented APIs; the agent-written `.cpp` matched the
  headers and the arduino-esp32 / esp-idf / mbedtls surface. App ≈ 296 KB (15 % of the slot).

## Provision + flash (the real product path)
- `host/provision.py` produced `guardcfg.bin` + a full `bundle.json` (PBKDF2-HMAC-SHA256, random
  salt, only `{salt, hash, params}` written — never the plaintext). Test config: a throwaway
  password, `armed=1`, `deadman=0` (no physical switch wired on the Gold), `max_att=2`, `brick=0`.
- Flashed with the headless flasher's new **`flasher.flash_suicide()`** in one `write_flash` pass:
  `bootloader@0x1000`, `partitions@0x8000`, `boot_app0@0xe000`, `app@0x10000`, `guardcfg@0x1f0000`
  — all 5 images hash-verified. (Validates `provision.py` → `bundle.json` → `flash_suicide` end to end.)

## Results — all PASS
| Behavior | Observed | Verdict |
|---|---|---|
| Config loads from NVS | `provisioned=1 armed=1 deadman=0 max_att=2 arm_pin=27 …` | ✅ `GateConfig::load` reads the provisioned NVS |
| **Correct password** | `RESULT: GATE_PASS` | ✅ verifies and boots; never wipes |
| **Wrong ×2** (`max_att=2`) | `wrong. attempts left: 1` → `locked for 0s.` → `RESULT: GATE_TRIGGERED` | ✅ 2nd wrong triggers the SAFE simulated wipe |
| **SAFE_MODE did zero erases** | after the trigger, the board rebooted with `provisioned=1` (config intact) | ✅ **decisive**: a real wipe would have cleared `guardcfg` → `provisioned=0` |
| **Recover** | reset + correct password → `GATE_PASS` (counter reset) | ✅ monotonic counter + recovery |

## Finding — PBKDF2 iteration count was far too high
- `kdf_iter=150000` → **verify took ≈16.7 s** on this ESP32 (measured). Unusable for a boot gate.
- Re-provisioned at `kdf_iter=10000` → **≈1 s** verify. All behaviors above were captured at 10k.
- **Decision:** default lowered to `10000` (SPEC §9, `GateConfig.h`, `provision.py`). This is *safe*:
  the 2-attempt wipe makes online brute-force impossible regardless of KDF cost, and PBKDF2 is
  GPU-cheap so a high count does not protect the salted hash offline anyway — offline resistance is
  **T2 flash-encryption + a strong passphrase**, not iteration count.

## Still UNVERIFIED (out of scope for a SAFE_MODE bench)
- The **real** (non-SAFE) `esp_partition_erase_range` wipe of `ota_0`/`nvs`/`spiffs`/`guardcfg`.
- The **boot-chain self-erase ("brick")** — still requires the sacrificial-board spike in
  [`SPIKE-PLAN.md`](SPIKE-PLAN.md) before `brick=1` ships.
- SD-card overwrite (no SD was attached).
- The hardware **arming switch** path (`deadman=1`) — tested only logically (`deadman=0` on the Gold,
  which has no switch wired); needs a jumper on GPIO27 to exercise `REASON_DEADMAN`.

> Reproduce: build a SAFE_MODE harness linking `firmware/bootgate/*` with `GATE_INPUT_SERIAL`,
> provision a `guardcfg`, flash via `flash_suicide`, and drive the gate over serial @115200.
