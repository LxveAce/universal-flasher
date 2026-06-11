<#
.SYNOPSIS
  build.ps1 — build a Suicide Marauder firmware image (Windows / PowerShell).

.DESCRIPTION
  Owner-only DEFENSIVE anti-forensic layer. See docs/SPEC.md (canonical contract), docs/SAFETY.md,
  docs/THREAT-MODEL.md. The Stage-3 self-erase brick primitive is UNVERIFIED (docs/SPIKE-PLAN.md);
  this script defaults to SUICIDE_SAFE_MODE so the destruct chain only simulates + logs. A live
  destruct build requires -NoSafeMode, and a live BRICK build additionally requires -AllowLiveBrick.
  CI never produces a live-brick build.

  Build backend: arduino-cli by default (ESP32Marauder is MIT and arduino-cli-built per
  docs/RESEARCH-DIGEST.md). PlatformIO is supported via -Backend pio.

  Output: an esptool-ready bundle dir with app.bin + partitions.bin + bootloader.bin +
  boot_app0.bin. guardcfg.bin / otadata come from host/provision.py at provision time.

.EXAMPLE
  ./scripts/build.ps1 -Board esp32 -Variant fork -Tier T1 -SafeMode
#>
[CmdletBinding()]
param(
  [ValidateSet('esp32','esp32s2','esp32s3','esp32c3','esp32c6')] [string] $Board = 'esp32',
  [ValidateSet('fork','guardian')]                              [string] $Variant = 'fork',
  [ValidateSet('T1','T2')]                                      [string] $Tier = 'T1',
  [ValidateSet('serial','touch','mini_kb','cardputer','buttons')] [string] $Input = 'serial',
  [ValidateSet('arduino-cli','pio')]                            [string] $Backend = 'arduino-cli',
  [switch] $SafeMode,
  [switch] $NoSafeMode,
  [switch] $AllowLiveBrick,
  [string] $Sketch = $env:MARAUDER_SKETCH,
  [string] $Out = '',
  [string] $Fqbn = ''
)

$ErrorActionPreference = 'Stop'

function Die([string]$msg) { Write-Error "error: $msg"; exit 1 }

$RepoRoot      = Split-Path -Parent $PSScriptRoot
$PartitionsDir = Join-Path $RepoRoot 'firmware\partitions'

# ---- SAFE_MODE resolution: defaults ON; -NoSafeMode turns it off; -SafeMode forces on ----
$Safe = $true
if ($NoSafeMode) { $Safe = $false }
if ($SafeMode)   { $Safe = $true }   # explicit -SafeMode always wins (safe-by-default)

if ([string]::IsNullOrWhiteSpace($Out)) {
  $Out = Join-Path $RepoRoot ("build\{0}_{1}_{2}" -f $Board, $Variant, $Tier)
}
New-Item -ItemType Directory -Force -Path $Out | Out-Null

# ---- brick default: T1=0, T2=1 (SPEC §8) ----
$BrickDefault = if ($Tier -eq 'T2') { 1 } else { 0 }

# ---- assemble -D defines ----
$Defs = New-Object System.Collections.Generic.List[string]
if ($Variant -eq 'fork') { $Defs.Add('-DSUICIDE_FORK') } else { $Defs.Add('-DSUICIDE_GUARDIAN') }
if ($Tier -eq 'T2')      { $Defs.Add('-DSUICIDE_TIER_T2') }

if ($Safe) {
  $Defs.Add('-DSUICIDE_SAFE_MODE')
} else {
  if ($BrickDefault -eq 1 -and -not $AllowLiveBrick) {
    Die "refusing to build a LIVE brick image: pass -AllowLiveBrick to acknowledge the UNVERIFIED self-erase primitive (docs/SPIKE-PLAN.md), or keep SAFE_MODE."
  }
}

switch ($Input) {
  'serial'    { $Defs.Add('-DGATE_INPUT_SERIAL') }
  # touch reuses Marauder's real touch_keyboard_obj (TouchKeyboard.h); GateInput_touch.cpp #errors
  # without SUICIDE_HAVE_TOUCH_KEYBOARD_OBJ. Correct here because this builds the FORK against the
  # Marauder source. (If your Marauder revision renames the instance, override the shim per
  # firmware/integration/INTEGRATION.md rather than dropping the define.)
  'touch'     { $Defs.Add('-DGATE_INPUT_TOUCH'); $Defs.Add('-DSUICIDE_HAVE_TOUCH_KEYBOARD_OBJ') }
  'mini_kb'   { $Defs.Add('-DGATE_INPUT_MINI_KB') }
  'cardputer' { $Defs.Add('-DGATE_INPUT_CARDPUTER') }
  'buttons'   { $Defs.Add('-DGATE_INPUT_BUTTONS') }
}

# ---- partition CSV selection ----
if ($Variant -eq 'guardian') {
  $PartCsv = Join-Path $PartitionsDir 'suicide_guardian_16MB.csv'
} elseif ($Board -in @('esp32','esp32s2','esp32c3')) {
  $PartCsv = Join-Path $PartitionsDir 'suicide_4MB.csv'
} else {
  $PartCsv = Join-Path $PartitionsDir 'suicide_16MB.csv'
}
if (-not (Test-Path $PartCsv)) {
  Die "partition CSV not found: $PartCsv (the partitions/*.csv are filled by another scaffold task)"
}

# ---- FQBN default ----
if ([string]::IsNullOrWhiteSpace($Fqbn)) {
  $Fqbn = switch ($Board) {
    'esp32'   { 'esp32:esp32:esp32' }
    'esp32s2' { 'esp32:esp32:esp32s2' }
    'esp32s3' { 'esp32:esp32:esp32s3' }
    'esp32c3' { 'esp32:esp32:esp32c3' }
    'esp32c6' { 'esp32:esp32:esp32c6' }
    default   { Die "no default FQBN for board $Board — pass -Fqbn" }
  }
}

$DefsStr = ($Defs -join ' ')
Write-Host "=============================================================="
Write-Host " Suicide Marauder build"
Write-Host "   board     : $Board   (fqbn: $Fqbn)"
Write-Host "   variant   : $Variant"
Write-Host "   tier      : $Tier   (brick default = $BrickDefault)"
Write-Host "   input     : $Input"
$safeNote = if ($Safe) { '(simulate only — nothing is destroyed)' } else { '(REAL DESTRUCT CHAIN)' }
Write-Host "   SAFE_MODE : $Safe  $safeNote"
Write-Host "   backend   : $Backend"
Write-Host "   partitions: $(Split-Path -Leaf $PartCsv)"
Write-Host "   defines   : $DefsStr"
Write-Host "   out       : $Out"
Write-Host "=============================================================="

# ---- backend: pio ----
if ($Backend -eq 'pio') {
  if (-not (Get-Command pio -ErrorAction SilentlyContinue)) { Die 'pio not found on PATH (pip install platformio)' }
  $env:SUICIDE_BUILD_FLAGS = $DefsStr
  $env:SUICIDE_PARTITIONS  = $PartCsv
  Write-Host "[pio] SUICIDE_BUILD_FLAGS=$($env:SUICIDE_BUILD_FLAGS)"
  pio run -e $Board
  if ($LASTEXITCODE -ne 0) { Die "pio run failed ($LASTEXITCODE)" }
  $PioDir = ".pio\build\$Board"
  foreach ($f in @('partitions.bin','bootloader.bin')) {
    if (Test-Path (Join-Path $PioDir $f)) { Copy-Item (Join-Path $PioDir $f) $Out -Force }
  }
  if (Test-Path (Join-Path $PioDir 'firmware.bin')) { Copy-Item (Join-Path $PioDir 'firmware.bin') (Join-Path $Out 'app.bin') -Force }
  Write-Host "[pio] artifacts -> $Out"
  exit 0
}

# ---- backend: arduino-cli ----
if (-not (Get-Command arduino-cli -ErrorAction SilentlyContinue)) { Die 'arduino-cli not found on PATH' }
if ($Variant -eq 'fork' -and [string]::IsNullOrWhiteSpace($Sketch)) {
  Die 'FORK build needs the ESP32Marauder sketch path: -Sketch <dir> or env MARAUDER_SKETCH (with firmware/bootgate hooked in per firmware/integration/INTEGRATION.md)'
}
$SketchDir = if ([string]::IsNullOrWhiteSpace($Sketch)) { Join-Path $RepoRoot 'firmware\guardian' } else { $Sketch }
if (-not (Test-Path $SketchDir)) { Die "sketch dir not found: $SketchDir" }

$BuildProps = @(
  '--build-property', 'build.partitions=suicide',
  '--build-property', "build.custom_partitions=$PartCsv",
  '--build-property', "compiler.cpp.extra_flags=$DefsStr",
  '--build-property', "compiler.c.extra_flags=$DefsStr"
)

Write-Host "[arduino-cli] compiling $SketchDir ..."
arduino-cli compile --fqbn $Fqbn --export-binaries --output-dir $Out @BuildProps $SketchDir
if ($LASTEXITCODE -ne 0) { Die "arduino-cli compile failed ($LASTEXITCODE)" }

# ---- normalize the bundle to canonical names the flasher expects ----
Get-ChildItem -Path $Out -Filter '*.ino.bin'            | ForEach-Object { Copy-Item $_.FullName (Join-Path $Out 'app.bin') -Force }
Get-ChildItem -Path $Out -Filter '*.ino.bootloader.bin' | ForEach-Object { Copy-Item $_.FullName (Join-Path $Out 'bootloader.bin') -Force }
Get-ChildItem -Path $Out -Filter '*.ino.partitions.bin' | ForEach-Object { Copy-Item $_.FullName (Join-Path $Out 'partitions.bin') -Force }

# boot_app0.bin: fixed core artifact (not chip-specific).
$pkgRoot = Join-Path $env:LOCALAPPDATA 'Arduino15\packages\esp32'
$bootApp0 = $null
if (Test-Path $pkgRoot) {
  $bootApp0 = Get-ChildItem -Path $pkgRoot -Filter 'boot_app0.bin' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
}
if ($bootApp0) {
  Copy-Item $bootApp0.FullName (Join-Path $Out 'boot_app0.bin') -Force
} else {
  Write-Host '[warn] boot_app0.bin not found in the installed core; the flasher will fetch it from FlashFiles/.'
}

Write-Host "=============================================================="
Write-Host " bundle ready: $Out"
Get-ChildItem -Path $Out -Include 'app.bin','partitions.bin','bootloader.bin','boot_app0.bin' -ErrorAction SilentlyContinue | Select-Object Name, Length | Format-Table -AutoSize
Write-Host ' next: host/provision.py to mint guardcfg.bin + otadata + bundle.json into this dir,'
Write-Host '       then flash via headless-marauder-gui (flasher-integration/PLAN.md).'
if ($Safe) { Write-Host ' NOTE: SAFE_MODE build — the destruct chain only simulates + logs.' }
Write-Host "=============================================================="
