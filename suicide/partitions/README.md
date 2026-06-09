# Partition tables — Suicide Marauder

These CSVs are the flash layouts for the two build variants (docs/SPEC.md §1, §3). They are
consumed by `gen_esp32part.py` (Arduino/IDF) to produce `partitions.bin`, and the **same offsets**
are read back by the host provisioner (`host/provision.py`) and the flasher
(`headless-marauder-gui`) so that `guardcfg`, `otadata`, and the app land at the right addresses.

> Owner-only, defensive anti-forensic layer. The partition table only carves storage; the wipe
> policy and the unprovisioned/disarmed fail-safes live in firmware (see `firmware/bootgate/`).

## Canonical rules (do not break)

- The `guardcfg` partition's **name** (`guardcfg`) and **subtype** (`nvs`) are canonical — host
  and firmware both key off them. Never rename or change the subtype (docs/SPEC.md §3, §4).
- **App partitions MUST be 64 KB (0x10000) aligned** or `gen_esp32part.py` errors out. Data
  partitions need only 4 KB (0x1000) sector alignment.
- Fixed offsets: 2nd-stage bootloader @ `0x1000` (classic ESP32 / S2) or `0x0` (S3/C3/C6/H2);
  partition table @ `0x8000`. Those are set by the build, **not** by these CSVs.
- Never hardcode the `otadata`/`nvs` offsets in code — read them from the active table. Marauder's
  `otadata` is at `0xe000` (not the stock IDF `0xd000`) because it enlarges `nvs` to `0x5000`.
- `nvs` here is **Marauder's own** NVS. The gate's state lives in the **separate** `guardcfg`
  partition (namespaces `sgate` / `sgate_rt`) so a Marauder factory-reset or SPIFFS format cannot
  erase the gate config or the monotonic attempt counter.
- **Every table carries a `scratch` data partition (subtype `0x40`).** It is the dedicated dry-run
  target for `SUICIDE_SAFE_MODE` (docs/SPEC.md §3/§5/§8) and is **load-bearing**: when
  `SUICIDE_SAFE_MODE` is built, the firmware (`firmware/bootgate/SelfDestruct.cpp`,
  `findScratchPartition()`) locates a partition **labelled `scratch`** and, if it is absent (or if a
  "scratch"-labelled partition resolves to a live `guardcfg`/`ota_0`/`app0`/`nvs`/`spiffs` subtype
  or the running partition), **refuses to simulate** — it performs **zero** `esp_partition_erase_range`
  and never falls back to a live partition. Do not remove `scratch` from a SAFE_MODE build, and do
  not reuse its label/subtype for anything else. (Non-SAFE release builds ignore `scratch`; it is
  simply unused storage there.)

## Which board uses which table

| File | Variant | Flash | Boards (typical) |
|------|---------|-------|------------------|
| `suicide_4MB.csv` | FORK | 4 MB | classic ESP32 WROOM dev, Lonely Binary Gold, many CYD 2.8"/3.5" |
| `suicide_8MB.csv` | FORK | 8 MB | ESP32-S3 (Cardputer ESP32-S3FN8, Marauder Mini), 8 MB CYD |
| `suicide_16MB.csv` | FORK | 16 MB | 16 MB S3 boards, MultiBoard, roomy installs |
| `suicide_guardian_16MB.csv` | GUARDIAN | 16 MB | S3 16 MB where the cleaner factory→ota_0 brick boundary is wanted |

**FORK is the default.** GUARDIAN is the optional hardening variant and is only templated for
16 MB (it needs two app slots — a Guardian factory app + an unmodified Marauder in `ota_0` — plus
filesystems, which do not fit in 4 MB; 8 MB is the bare minimum, 16 MB is preferred).

## Offset / size math

All sizes/offsets below are hex bytes. `K`=1024, `M`=1024*1024. Each row's `offset = previous
offset + previous size` unless a gap is intentional.

### `suicide_4MB.csv` — FORK, 4 MB (committed reference, docs/SPEC.md §3.1)

```
nvs       0x009000 0x005000   -> ends 0x00E000   Marauder NVS (20 KB)
otadata   0x00E000 0x002000   -> ends 0x010000   OTA-select (8 KB)
app0      0x010000 0x1E0000   -> ends 0x1F0000   Marauder app, ota_0 (1.875 MB)
guardcfg  0x1F0000 0x002000   -> ends 0x1F2000   gate config NVS (8 KB)
spiffs    0x1F2000 0x00C000   -> ends 0x1FE000   filesystem (48 KB)
coredump  0x1FE000 0x002000   -> ends 0x200000   crash dump (8 KB)
scratch   0x200000 0x010000   -> ends 0x210000   SAFE_MODE dry-run target (64 KB, subtype 0x40)
```

This table is derived from arduino-esp32 `min_spiffs.csv` (which has `app0`=`app1`=`0x1E0000` and
ends at `0x400000`). Here the **second app slot `ota_1` is dropped** and `guardcfg` + a small
`spiffs` + `coredump` are placed in the `0x1F0000`–`0x200000` window where `ota_1` used to begin.

Trade-off — **"no second app slot" on 4 MB:** with only one app partition (`ota_0`), Marauder's
SD-card OTA self-update path (`SDInterface.cpp`, which calls `esp_ota_get_next_update_partition`
+ `esp_ota_set_boot_partition`) has nowhere to write the new image, so it is **disabled** on the
4 MB build. You reflash over USB to update. The committed reference now allocates a 64 KB `scratch`
partition at `0x200000`–`0x210000` (SPEC §3.1) for SAFE_MODE dry runs; everything above `0x210000`
in a 4 MB part remains unallocated/reserved on this layout — match it exactly; do not "reclaim" the
remaining upper region without changing the reference in SPEC §3.1 first.

### `suicide_8MB.csv` — FORK, 8 MB

```
nvs       0x009000 0x005000   -> ends 0x00E000   Marauder NVS (20 KB)
otadata   0x00E000 0x002000   -> ends 0x010000   OTA-select (8 KB)
app0      0x010000 0x1E0000   -> ends 0x1F0000   Marauder app, ota_0 (1.875 MB)
app1      0x1F0000 0x1E0000   -> ends 0x3D0000   Marauder app, ota_1 (1.875 MB)
guardcfg  0x3D0000 0x004000   -> ends 0x3D4000   gate config NVS (16 KB)
spiffs    0x3D4000 0x40C000   -> ends 0x7E0000   filesystem (~4.0 MB; shrunk 64 KB for scratch)
scratch   0x7E0000 0x010000   -> ends 0x7F0000   SAFE_MODE dry-run target (64 KB, subtype 0x40)
coredump  0x7F0000 0x010000   -> ends 0x800000   crash dump (64 KB)
```

8 MB has room to keep **both** app slots, so Marauder's SD-OTA self-update keeps working. SPIFFS is
shrunk by 64 KB to host the `scratch` SAFE_MODE target. Fills 8 MB exactly.

### `suicide_16MB.csv` — FORK, 16 MB

```
nvs       0x009000 0x005000   -> ends 0x00E000    Marauder NVS (20 KB)
otadata   0x00E000 0x002000   -> ends 0x010000    OTA-select (8 KB)
app0      0x010000 0x1E0000   -> ends 0x1F0000    Marauder app, ota_0 (1.875 MB)
app1      0x1F0000 0x1E0000   -> ends 0x3D0000    Marauder app, ota_1 (1.875 MB)
guardcfg  0x3D0000 0x010000   -> ends 0x3E0000    gate config NVS (64 KB)
spiffs    0x3E0000 0xC00000   -> ends 0xFE0000    filesystem (~12.0 MB; shrunk 64 KB for scratch)
scratch   0xFE0000 0x010000   -> ends 0xFF0000    SAFE_MODE dry-run target (64 KB, subtype 0x40)
coredump  0xFF0000 0x010000   -> ends 0x1000000   crash dump (64 KB)
```

Roomy. Both app slots, a generous 64 KB `guardcfg` (headroom for an optional T2 `nvs_keys` /
NVS-encryption story), and a large SPIFFS (shrunk 64 KB to host the `scratch` SAFE_MODE target).
Fills 16 MB exactly.

### `suicide_guardian_16MB.csv` — GUARDIAN, 16 MB

```
nvs       0x009000 0x005000   -> ends 0x00E000    Marauder NVS (20 KB)
otadata   0x00E000 0x002000   -> ends 0x010000    OTA-select (8 KB)
factory   0x010000 0x100000   -> ends 0x110000    Guardian gate app (1 MB)
ota_0     0x110000 0x200000   -> ends 0x310000    unmodified Marauder (2 MB)
guardcfg  0x310000 0x010000   -> ends 0x320000    gate config NVS (64 KB)
spiffs    0x320000 0xCC0000   -> ends 0xFE0000    filesystem (~12.75 MB; shrunk 64 KB for scratch)
scratch   0xFE0000 0x010000   -> ends 0xFF0000    SAFE_MODE dry-run target (64 KB, subtype 0x40)
coredump  0xFF0000 0x010000   -> ends 0x1000000   crash dump (64 KB)
```

Boot/handoff: a blank `otadata` (all `0xFF`) makes the 2nd-stage bootloader run the `factory`
Guardian first. The Guardian gates, then `esp_ota_set_boot_partition(ota_0)` + `esp_restart()`
into Marauder. To re-assert the gate, the Guardian erases `otadata` (or calls
`set_boot_partition(factory)`, which itself just formats `otadata`). Build with
`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE` so a Marauder that never marks itself valid auto-reverts
to the Guardian. The `factory` slot is generously sized at 1 MB (the gate is small); `ota_0` gets
2 MB (≥ Marauder's ~1.875 MB min_spiffs slot). Fills 16 MB exactly.

## Flashing offsets (host bundle manifest)

The flasher builds one `write_flash` list from the active table + the bundle. Per docs/SPEC.md
§10–§11 the host reads these offsets straight from the chosen CSV:

| Image | Offset | Source |
|-------|--------|--------|
| bootloader | `0x1000` (classic/S2) or `0x0` (S3/C3/C6/H2) | chip family |
| partition table | `0x8000` | fixed |
| `boot_app0` (otadata seed) | `otadata` offset (`0xe000` here) | CSV |
| app | `0x10000` (FORK) / `factory@0x10000` + Marauder`@0x110000` (GUARDIAN) | CSV |
| `guardcfg.bin` | `guardcfg` offset | CSV |
| `otadata_blank.bin` | `otadata` offset | CSV (forces first boot into factory/Guardian; FORK ignores) |

`guardcfg.bin` is generated by `nvs_partition_gen` sized to the `guardcfg` partition. Never flash
a plaintext password anywhere — only `{salt, pwhash, kdf_iter, kdf_dklen}` plus the policy bytes
go into `guardcfg` (docs/SPEC.md §4, §9, §10).

## Validation

Before committing a change, confirm with the IDF tool:

```
python gen_esp32part.py suicide_8MB.csv /dev/null
```

It enforces 64 KB app alignment and flags overlaps/oversize. (All four tables here pass: app
slots are 64 KB aligned, data partitions — including `scratch` — are 4 KB aligned, no ranges
overlap, and 8/16 MB fill their part exactly while 4 MB matches the committed SPEC §3.1 reference
plus its `scratch` partition at `0x200000`.)

> **SAFE_MODE dependency.** Each table's `scratch` (data, subtype `0x40`) is mandatory for
> `SUICIDE_SAFE_MODE` builds. `SelfDestruct::trigger()` checks for it at SAFE-mode entry and refuses
> to simulate (logs an error, performs zero erases) if it is missing — it will **never** redirect a
> simulated wipe onto `guardcfg`/`ota_0`/`nvs`/`spiffs`/the running app. Keep the label `scratch`
> and subtype `0x40` intact.
