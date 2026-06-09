# Assemble + build the SAFE_MODE gate test harness (docs/HARDWARE-TEST.md).
# Copies the canonical firmware/bootgate sources into firmware/test_harness/src, then runs PlatformIO.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$bg   = Join-Path $root "firmware\bootgate"
$dst  = Join-Path $root "firmware\test_harness\src"
$files = @("GateConfig.h","GateConfig.cpp","GateCrypto.h","GateCrypto.cpp","ArmingSwitch.h",
           "ArmingSwitch.cpp","SelfDestruct.h","SelfDestruct.cpp","BootGate.h","BootGate.cpp",
           "GateInput.h","GateInput_serial.cpp")
foreach ($f in $files) { Copy-Item (Join-Path $bg $f) (Join-Path $dst $f) -Force }
Push-Location (Join-Path $root "firmware\test_harness")
try {
    if (Get-Command pio -ErrorAction SilentlyContinue) { pio run @args }
    else { python -m platformio run @args }   # falls back to the module if `pio` isn't on PATH
} finally { Pop-Location }
