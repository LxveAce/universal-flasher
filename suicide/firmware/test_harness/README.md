# SAFE_MODE gate test harness

A throwaway PlatformIO sketch that builds the **real** `firmware/bootgate/*` units with a stub
"Marauder" so you can exercise the boot gate on actual hardware **without ever erasing anything**
(`-DSUICIDE_SAFE_MODE` → every destructive call is a logged no-op against the `scratch` partition).

This is the harness behind [`docs/HARDWARE-TEST.md`](../../docs/HARDWARE-TEST.md), where it was
validated on a classic ESP32-D0WD (4 MB): unprovisioned→PASS, correct→PASS, wrong×`max_att`→SAFE
simulated wipe→TRIGGERED, with the config left intact (proving zero real erases).

## Build & run

The `bootgate` sources are not duplicated here — a script copies them in (kept `.gitignore`d so
there is one canonical copy under `firmware/bootgate/`).

```bash
# from the repo root:
scripts/build_test_harness.sh          # or: powershell scripts\build_test_harness.ps1
# then flash + monitor (classic ESP32 on <PORT>):
cd firmware/test_harness
pio run -e gold -t upload --upload-port <PORT>
pio device monitor -b 115200 -p <PORT>
```

Provision a `guardcfg` first (so the gate has something to enforce):

```bash
python host/provision.py --partitions firmware/partitions/suicide_4MB.csv \
  --out build/bundle --chip esp32 --variant fork --armed 1 --deadman 0 --max-att 2 --brick 0
# flash guardcfg.bin to its offset (0x1F0000 on the 4 MB table), or flash the whole bundle.
```

Then type the password over serial: `unlock <password>` (or just the password). Wrong ×`max_att`
prints the SAFE simulated-wipe and `GATE_TRIGGERED`; a correct password resets the counter and
`GATE_PASS`es. **Requires `SUICIDE_SAFE_MODE` — never build this harness without it.**

`pio` comes from `pip install platformio`. The `s3` env is a starting point for ESP32-S3 boards
(adjust `board`, partitions, and `ARMING_PIN`).
