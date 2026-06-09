#!/usr/bin/env bash
# Assemble + build the SAFE_MODE gate test harness (docs/HARDWARE-TEST.md).
# Copies the canonical firmware/bootgate sources into firmware/test_harness/src, then runs PlatformIO.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
bg="$root/firmware/bootgate"
dst="$root/firmware/test_harness/src"
for f in GateConfig.h GateConfig.cpp GateCrypto.h GateCrypto.cpp ArmingSwitch.h ArmingSwitch.cpp \
         SelfDestruct.h SelfDestruct.cpp BootGate.h BootGate.cpp GateInput.h GateInput_serial.cpp; do
  cp "$bg/$f" "$dst/$f"
done
cd "$root/firmware/test_harness"
if command -v pio >/dev/null 2>&1; then pio run "$@"; else python -m platformio run "$@"; fi
