# SPIKE-PLAN — settle the UNVERIFIED self-erase before `brick=1` ships

> **STATUS: REQUIRED before any device is provisioned with `brick=1`.** This plan exists to settle the
> one primitive the research could not confirm from documentation: a running ESP32 app erasing its
> **own** boot chain (partition table + bootloader + the app region it is executing from). Until this
> spike passes on a **sacrificial** board of the same chip + flash size as the target,
> `brick=1` must not be enabled on any device you care about (see [`SAFETY.md`](SAFETY.md),
> [`SPEC.md`](SPEC.md) §8, §13).

This is a sacrificial-board test plan, not production code. Run it on a board you are willing to
permanently destroy.

---

## 1. Why a spike is needed (what is and isn't verified)

From [`RESEARCH-DIGEST.md`](RESEARCH-DIGEST.md) (self-wipe section), against ESP-IDF primary sources:

**CONFIRMED:**
- By default IDF forbids firmware from erasing/writing the bootloader, the partition table, **and**
  the partition holding the running app. You **must** build with
  `CONFIG_SPI_FLASH_DANGEROUS_WRITE_ALLOWED=y` to touch those regions.
- During a flash erase the CPU instruction/data **cache is disabled**; any code/constant fetched from
  flash mid-erase crashes (illegal instruction) or returns garbage. So the final routine and
  everything it touches must be in **IRAM/DRAM** (`IRAM_ATTR`, no flash-resident strings/constants).
- Wipe-others-first, **boot chain last** is the correct order: each erase is blocking, and once the
  table/bootloader/app are `0xFF` the CPU can no longer fetch flash-resident code. After the
  partition table is gone, `esp_partition_*` is invalid — use raw `esp_flash_erase_region`.
- Bootloader offset is **chip-dependent**: `0x1000` classic ESP32/S2, `0x0` on S3/C3/C6/H2. Partition
  table at `0x8000`. Resolve per chip; do not hardcode `0x1000`.
- A single NOR erase to `0xFF` is forensically sufficient (no magnetic remanence); multi-pass is
  theater. Wear-leveled partitions (NVS/SPIFFS/FAT) must be erased over their **entire range**.

**UNVERIFIED (the reason for this spike):**
- **No primary source documents or guarantees erasing the flash region that holds the
  currently-executing application image.** The digest's adversarial check rated the "erase your own
  running app from an `IRAM_ATTR` routine" maneuver **UNCERTAIN**: the high-level *order* is sound, but
  self-erase-of-running-app is an undocumented edge case, and the exact "manually disable
  scheduler/interrupts + run from IRAM" mechanism is partly Espressif-driver behavior, not a
  documented caller contract. We must learn empirically whether it (a) completes the wipe before the
  CPU loses its footing, (b) crashes mid-wipe leaving a partially-recoverable device, or (c) is
  unnecessary because erasing only the table + bootloader already produces an unbootable board.

This spike answers exactly that, on hardware, with flash dumps as evidence.

---

## 2. Equipment

- A **sacrificial** ESP32 board, **same chip family and flash size** as the production target (run
  the spike separately per target class — classic ESP32 4 MB, S3 16 MB, etc.; the bootloader offset
  and self-erase timing differ by chip).
- `esptool` on the host (for `read_flash`, `image_info`, `write_flash`).
- Serial console capture (to timestamp the last log line before the CPU dies).
- A second identical sacrificial board recommended (for the A/B arm in §5).

---

## 3. Build under test

Build the FORK app with the **real** (non-SAFE) `SelfDestruct::brickBootChain` path enabled:

- `-DSUICIDE_FORK`
- **NOT** `-DSUICIDE_SAFE_MODE` (SAFE_MODE never performs the real brick — it only logs).
- `sdkconfig`/build with `CONFIG_SPI_FLASH_DANGEROUS_WRITE_ALLOWED=y` (without it the erase of the
  table/bootloader/own-app `abort()`s instantly — that is the central gate).
- Provision a `guardcfg` with `armed=1`, `brick=1`, and the data-wipe flags as the production config
  will use (so the spike exercises the real ordering: SD → internal data → guardcfg last → brick).
- Trigger via the fastest deterministic path: `max_att` wrong passwords over serial, or the
  `wipe` host-assisted command (`REASON_HOST_WIPE`). Do **not** rely on the dead-man line for the
  spike (you want a repeatable trigger).

Confirm `brickBootChain` is `IRAM_ATTR`, marked `noreturn`, and references no flash-resident
constants/strings (per `SelfDestruct.h` and §1).

---

## 4. Procedure with before/after `read_flash` dumps

For each chip class:

### 4.1 Capture the BEFORE image
```
esptool --chip <chip> --port <PORT> read_flash 0x0 ALL before_full.bin
# Targeted ranges (offsets per SPEC §2/§3 for this chip + CSV):
esptool --chip <chip> --port <PORT> read_flash 0x0    0x10000  before_bootchain.bin   # bootloader+table (classic: bl@0x1000, table@0x8000)
esptool --chip <chip> --port <PORT> read_flash 0x10000 0x1E0000 before_app.bin        # app0 / running app (4MB layout)
esptool --chip <chip> --port <PORT> read_flash 0x1F0000 0x2000  before_guardcfg.bin   # guardcfg (4MB layout)
```
Record sizes/SHA256 (`esptool image_info before_app.bin`) so the AFTER comparison is exact. Pull the
real offsets from the board's partition CSV — do not assume.

### 4.2 Fire the trigger
Power the board, trigger the wipe (§3), and **capture the serial log with timestamps.** Note the last
line printed before output stops (e.g. the `panicIndicate` signal and the last stage entered). A real
brick should stop logging when the boot chain goes — that loss of output is itself a data point.

### 4.3 Capture the AFTER image
Re-enter ROM serial download mode (the mask-ROM downloader survives the erase on a T1/no-encryption
part — it is the documented reflash path) and dump the same ranges:
```
esptool --chip <chip> --port <PORT> read_flash 0x0    0x10000  after_bootchain.bin
esptool --chip <chip> --port <PORT> read_flash 0x10000 0x1E0000 after_app.bin
esptool --chip <chip> --port <PORT> read_flash 0x1F0000 0x2000  after_guardcfg.bin
esptool --chip <chip> --port <PORT> read_flash 0x0 ALL after_full.bin
```

### 4.4 Verify each target range is `0xFF`
For every range that was supposed to be erased, confirm it is **all `0xFF`** (NOR-erased state). A
quick host check (any of these is fine):
```
python -c "d=open('after_bootchain.bin','rb').read(); print('bootchain all-FF:', d==b'\xff'*len(d))"
python -c "d=open('after_app.bin','rb').read();       print('app all-FF:',       d==b'\xff'*len(d))"
python -c "d=open('after_guardcfg.bin','rb').read();  print('guardcfg all-FF:',  d==b'\xff'*len(d))"
```
Any non-`0xFF` byte inside a range that was supposed to be erased is a **partial-wipe** result and a
FAIL for that range. Pay special attention to `before_app.bin` vs `after_app.bin`: the app region is
the one the CPU was *executing from*, so an incomplete erase there is exactly the UNVERIFIED risk.

---

## 5. A/B test — is `esp_partition_erase_range` complete on this NOR part?

The data-partition wipe (Stage 2, SPEC §8) uses `esp_partition_erase_range` over `ota_0`, `spiffs`,
`nvs`, `coredump`, then `guardcfg` last. We must confirm that call erases the **entire** partition
range on the actual NOR chip, with no residual stale sectors (wear-leveled FS layers keep spare
copies — the digest flags this).

**Arm A — full-range erase (the design):** call `esp_partition_erase_range(p, 0, p->size)` for each
data partition. Dump each partition's full range with `read_flash` afterward; assert **all `0xFF`**.

**Arm B — logical delete only (the wrong way, as a control):** on a second sacrificial board, only
`nvs_flash_erase` / SPIFFS-format / delete keys-and-files instead of full-range erase. Dump the same
ranges.

**Expected:** Arm A → ranges fully `0xFF`. Arm B → **residual non-`0xFF` data survives** in spare
sectors (proving logical delete is insufficient and the full-range erase in SPEC §8 is required).
This A/B both validates the chosen primitive and documents *why* logical delete is rejected.

If Arm A ever shows residual non-`0xFF` bytes, investigate alignment (offset+size must be 4 KB
aligned) and whether the partition size read from the table matches the dump length before concluding
the primitive is incomplete.

---

## 6. Success criteria (ALL must hold to clear `brick=1`)

1. **Device fails to boot** after the trigger: on power-cycle the ROM bootloader finds no valid
   image (invalid table/bootloader magic) and does not run the app. (Reaching ROM serial download
   mode is **expected and fine** on a T1 part — that is the reflash recovery path, not a failure.)
2. **Every targeted range reads `0xFF`** in the AFTER dump — bootloader, partition table, the running
   app region, and the data partitions selected by the wipe flags (incl. `guardcfg` last). No
   residual plaintext in any range that was supposed to be erased.
3. **No mid-wipe crash that leaves a partially-recoverable device.** The serial log must show the
   wipe progressed through Stage 1 → Stage 2 → Stage 3 in order; the only acceptable "stop" is output
   ceasing when the boot chain itself is erased at the very end. A crash/`abort()`/reboot-loop that
   stops Stage 2 early (leaving `ota_0`/`spiffs`/`nvs` partly intact) is a **FAIL** — that is the
   IRAM/cache hazard from §1 manifesting.
4. **A/B (§5) confirms** `esp_partition_erase_range` full-range erase is complete (Arm A all-`0xFF`),
   and logical delete (Arm B) is demonstrably insufficient.
5. **Repeatable:** the result reproduces on at least two sacrificial boards of the same class (or two
   trigger runs if only one board is available and it survives re-flash between runs).

---

## 7. What to conclude / how to record it

Write the outcome back into the repo (a short results note next to this plan, plus flip the relevant
"UNVERIFIED" lines in SPEC §13 and SAFETY.md once cleared — coordinate that edit; do not silently
change the contract):

- **PASS (all of §6):** `brick=1` is cleared for that specific chip + flash-size class. Record the
  exact build flags, `sdkconfig` (`CONFIG_SPI_FLASH_DANGEROUS_WRITE_ALLOWED=y`), offsets, and dump
  hashes that produced the pass. The clearance is **per chip class** — a pass on classic ESP32 4 MB
  does **not** clear S3 16 MB.
- **PARTIAL (boots dead but app range not fully `0xFF`, or Stage 2 incomplete):** do **not** ship
  `brick=1`. The device is "looks bricked but forensically partial" — the worst outcome for an
  anti-forensic tool. Fix the IRAM-residency / ordering / cache-disable handling and re-spike. Until
  fixed, T1 (`brick=0`, data-wiped + reflashable) remains the only supported posture.
- **CRASH mid-wipe:** treat as PARTIAL. The most likely cause is a flash-resident symbol/constant
  touched after the cache went off; audit `brickBootChain` for non-IRAM references and retry.

Until a documented PASS exists for the target chip class, **`brick=1` must not be enabled on any
non-sacrificial board.** T2 (Secure Boot + Flash Encryption) additionally burns irreversible eFuses
and must not be combined with `brick=1` in production until this spike has passed *and* the T2 eFuse
flow has its own separate sign-off (SAFETY.md).

---

## 8. Stage 3 verification guide (step-by-step)

This section provides a concrete, repeatable procedure for verifying that Stage 3 (boot-chain
brick) works correctly on a given chip class. **Use a SACRIFICIAL board you are willing to
permanently destroy.**

### 8.1 What Stage 3 does

Stage 3 (`SelfDestruct::brickBootChain`) is an `IRAM_ATTR`, non-returning function that raw-erases:

1. **The partition table** at `0x8000` (1 sector, 4 KB) -- after this, the ROM bootloader cannot
   locate any app image.
2. **The bootloader** at `0x1000` (classic ESP32/S2) or `0x0` (S3/C3/C6/H2) -- after this, the
   2nd-stage bootloader is gone and the chip has nothing to execute.
3. **The running app region** (the OTA slot currently executing from) -- this is the UNVERIFIED
   primitive. The CPU is executing from this region, so erasing it while running is the untested
   edge case.

The erase uses `esp_flash_erase_region` with raw offsets (not the partition API, which is invalid
after the partition table is gone). Each erase writes the region to `0xFF` (NOR-erased state).

### 8.2 Why a sacrificial board is required

- Stage 3 is **PERMANENT and IRREVERSIBLE** at the software level. The chip itself is not damaged
  (the silicon and mask ROM survive), but the flash contents are destroyed.
- The boot chain (bootloader + partition table + app) is what makes the board functional. Without
  it, the board is a paperweight until re-flashed.
- On a T2 build (Secure Boot v2 + Flash Encryption), the eFuse burns are additionally irreversible
  at the **hardware** level -- the chip can never be repurposed. Do NOT test T2 on a non-sacrificial
  board.

### 8.3 Step-by-step test procedure

**Prerequisites:**
- A sacrificial ESP32 board (same chip family + flash size as your target)
- `esptool` installed on the host
- Serial console capture tool (PuTTY, miniterm, screen, etc.)
- The Suicide Marauder firmware built with `brick=1` and **NOT** `SUICIDE_SAFE_MODE`
- `CONFIG_SPI_FLASH_DANGEROUS_WRITE_ALLOWED=y` in sdkconfig

**Step 1: Flash Marauder + Suicide Marauder to the sacrificial board.**
```sh
# Flash the complete suicide bundle (bootloader + partitions + app + guardcfg)
esptool --chip <chip> --port <PORT> write_flash \
  <bootloader_offset> bootloader.bin \
  0x8000 partitions.bin \
  0x10000 app.bin \
  <guardcfg_offset> guardcfg.bin \
  <otadata_offset> <otadata_seed>
```

**Step 2: Provision the device with `armed=1`, `brick=1`.**
```sh
python host/provision.py \
  --partitions firmware/partitions/suicide_4MB.csv \
  --armed 1 --brick 1 --max-att 2
```

**Step 3: Capture the BEFORE flash dump.**
```sh
esptool --chip <chip> --port <PORT> read_flash 0x0 ALL before_full.bin
```

**Step 4: Arm the device and trigger the wipe.**
Open a serial console at 115200 baud and trigger via one of:
- Enter the wrong password `max_att` times (e.g. 2 wrong passwords).
- Type `wipe`, then enter the correct password to authenticate.
- Pull the GPIO arming pin (if wired) to trigger REASON_DEADMAN.

**Capture the serial output.** The last lines should show the wipe stages progressing. Output will
cease when the boot chain is erased (the CPU can no longer fetch instructions from flash).

**Step 5: Verify the board does not boot.**
Power-cycle the board. Expected behavior:
- Serial output should be **silent** (no bootloader messages, no app output) or show only the
  mask-ROM bootloader failing to find a valid image.
- The board should NOT run Marauder or any application.

**Step 6: Verify via esptool.**
```sh
# Enter ROM download mode (hold BOOT/GPIO0 during reset, or the board may already be in it)
esptool --chip <chip> --port <PORT> read_flash 0x0 ALL after_full.bin

# Verify the boot chain regions are all 0xFF:
python -c "
d = open('after_full.bin', 'rb').read()
bl_off = 0x1000  # or 0x0 for S3/C3
print('bootloader (0x%X-0x8000) all-FF:' % bl_off, d[bl_off:0x8000] == b'\xff' * (0x8000 - bl_off))
print('partition table (0x8000-0x9000) all-FF:', d[0x8000:0x9000] == b'\xff' * 0x1000)
# App region — check the first 1 MB after 0x10000 (adjust for your partition size):
print('app region first 64K all-FF:', d[0x10000:0x20000] == b'\xff' * 0x10000)
"
```

**Step 7: Verify recovery is possible (the chip is not dead).**
```sh
# Re-flash a fresh Marauder image to prove the chip still works:
esptool --chip <chip> --port <PORT> write_flash \
  <bootloader_offset> bootloader.bin \
  0x8000 partitions.bin \
  0x10000 app.bin

# The board should boot normally after re-flash. If it does, the chip's mask ROM and flash
# hardware survived — only the software was destroyed, which is the designed behavior.
```

### 8.4 Expected results

| Check | Expected | Meaning |
|-------|----------|---------|
| Board boots after wipe? | **NO** | Boot chain successfully destroyed |
| esptool can communicate? | **YES** (ROM download mode) | Mask ROM survived (expected for T1) |
| Bootloader region all 0xFF? | **YES** | Stage 3 erased the bootloader |
| Partition table all 0xFF? | **YES** | Stage 3 erased the partition table |
| App region all 0xFF? | **YES** (ideally) or **partially** | Self-erase of running app -- the UNVERIFIED primitive |
| Re-flash succeeds? | **YES** | Chip hardware undamaged |

**App region partially erased** is an acceptable result for T1: the partition table + bootloader
are already gone, so the device is non-bootable regardless. The running-app self-erase is a
defense-in-depth measure; its partial completion does not reduce the security posture because
the boot chain is the load-bearing target.

### 8.5 Recovery procedure

If you need to recover a board after Stage 3 verification (or an accidental brick):

1. Hold BOOT/GPIO0 LOW during reset to enter ROM serial download mode.
2. Flash a complete image (bootloader + partition table + app):
   ```sh
   esptool --chip <chip> --port <PORT> write_flash \
     <bootloader_offset> bootloader.bin \
     0x8000 partitions.bin \
     0x10000 app.bin
   ```
3. The board should boot normally. The guardcfg partition will be empty (unprovisioned), so the
   gate will return GATE_PASS.
4. For T2 boards with Secure Boot v2 eFuses burned: **recovery is NOT possible.** The chip will
   only boot images signed with the burned key. This is by design -- T2 is irreversible.
