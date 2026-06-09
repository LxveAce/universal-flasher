// SelfDestruct.h — best-effort secure erase. Non-abortable once started. docs/SPEC.md §8.
//
// IMPORTANT REALITY (verified): there is NO runtime crypto-erase on ESP32 — the flash-encryption
// AES key lives in a hardware read- AND write-protected eFuse, so software cannot destroy it.
// Wipe is therefore BULK ERASE + OVERWRITE, not key-destruction. Real unrecoverability requires
// T2 (Secure Boot v2 + Flash Encryption) so the erased ciphertext is meaningless and the board
// can't be reflashed past the gate.
//
// SAFE MODE: when SUICIDE_SAFE_MODE is defined, every destructive call is redirected at a scratch
// partition / dummy key and only logs the simulated action — nothing real is destroyed. Build and
// test in SAFE MODE first. The live Stage-3 boot-chain self-erase is UNVERIFIED — see
// docs/SPIKE-PLAN.md; it requires CONFIG_SPI_FLASH_DANGEROUS_WRITE_ALLOWED=y.
#pragma once

#include "GateConfig.h"
#include "BootGate.h"   // TriggerReason

namespace suicide {

class SelfDestruct {
 public:
  // Full sequence per cfg flags. Does not return on a real (non-SAFE) brick.
  // Order: SD overwrite+erase -> internal data partitions (guardcfg LAST) -> boot chain (if brick).
  static void trigger(const GateConfig& cfg, TriggerReason reason);

  // --- individual stages (each a no-op-but-log under SAFE_MODE) ---

  // Stage 1: overwrite SD files + free space with esp_fill_random (cfg.sd_passes), then erase/format.
  // Best-effort: FTL wear-leveling/over-provisioning may retain remapped cells (documented).
  static bool wipeSD(const GateConfig& cfg);

  // Stage 2: esp_partition_erase_range over ota_0/spiffs/nvs/coredump, then guardcfg LAST.
  static bool wipeInternal(const GateConfig& cfg);

  // Stage 3 (brick): IRAM-resident, non-returning. Raw-erase partition table (0x8000), bootloader
  // (0x1000 classic / 0x0 S3-C3), and the running app/factory region. UNVERIFIED — spike first.
  static void brickBootChain(const GateConfig& cfg) __attribute__((noreturn));

 private:
  static void panicIndicate(TriggerReason reason);  // optional LED/serial signal; never blocks long
};

} // namespace suicide
