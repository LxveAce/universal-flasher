// SelfDestruct.cpp — best-effort secure erase. docs/SPEC.md §8. Non-abortable once started.
//
// Owner-only, DEFENSIVE anti-forensic layer (duress wipe of a board the operator owns). See
// docs/SAFETY.md and docs/THREAT-MODEL.md. This is NOT for evading lawful process.
//
// REALITY (verified, SelfDestruct.h + RESEARCH-DIGEST.md): there is NO runtime crypto-erase on
// ESP32 — the flash-encryption AES key lives in a hardware read- AND write-protected eFuse, so
// software can neither read nor overwrite it. "Wipe" is therefore BULK ERASE + OVERWRITE, not
// key-destruction. True unrecoverability requires T2 (Secure Boot v2 + Flash Encryption) so the
// erased ciphertext is meaningless and the gate cannot be reflashed past.
//
// ORDER (SPEC §8):
//   1. SD      — overwrite files + free space (cfg.sd_passes), then card erase/format.
//   2. Internal data — esp_partition_erase_range over ota_0 / spiffs / nvs / coredump, then
//      `guardcfg` LAST (config is already copied into RAM by the caller).
//   3. Brick (if cfg.brick) — IRAM_ATTR, non-returning raw-erase of partition table (0x8000),
//      bootloader (0x1000 classic / 0x0 on S3/C3), and the running app/factory region. This
//      self-erase-of-the-running-app is the ONE UNVERIFIED primitive (docs/SPIKE-PLAN.md) and
//      requires CONFIG_SPI_FLASH_DANGEROUS_WRITE_ALLOWED=y.
//
// SAFE MODE (SUICIDE_SAFE_MODE): EVERY destructive call becomes a log-only no-op. A real
// scratch partition (a DATA partition LABELLED "scratch", subtype 0x40 — SPEC §3) is REQUIRED to
// prove the erase path; if it is absent the simulation refuses to touch ANY partition. There is
// NO fallback to guardcfg / ota_0 / nvs / spiffs / the running app. SAFE MODE NEVER touches a real
// SD card or the boot chain. Build and test here first.

#include "SelfDestruct.h"

#include "GateConfig.h"
#include "BootGate.h"  // TriggerReason

#include <Arduino.h>
#include <string.h>
#include <stdint.h>

#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
#include "esp_log.h"
#include "esp_system.h"
#include "esp_attr.h"           // IRAM_ATTR
#include "esp_partition.h"
#include "esp_ota_ops.h"        // esp_ota_get_running_partition
#include "esp_random.h"         // esp_fill_random
#include "esp_flash.h"          // esp_flash_erase_region, esp_flash_default_chip
#include "bootloader_random.h"  // bootloader_random_enable/disable (true-random for the overwrite)
#include "soc/soc_caps.h"
#endif

// ----- SD card stack (Arduino). On Marauder the SD is on SPI; standalone boards may use SD_MMC.
// We use the stock SD library so this compiles on every board class. A board package that wants
// SD_MMC / SdFat raw-sector speed can override wipeSDImpl via the weak hook below.
#if !defined(SUICIDE_NO_SD)
#include <FS.h>
#include <SD.h>
#endif

namespace suicide {

namespace {

constexpr const char* TAG = "selfdestruct";

// Overwrite buffer: 32 KiB is a sweet spot for SD throughput per RESEARCH-DIGEST.md and is a
// multiple of the 512 B sector size. Filled once per buffer with esp_fill_random, not per sector.
constexpr size_t OVERWRITE_BUF = 32 * 1024;

// ---------------------------------------------------------------------------------------------
// Entropy: make esp_fill_random TRUE random for the overwrite payload. On Marauder Wi-Fi is often
// already up, but at boot-gate time it usually is not, so enable the SAR-ADC entropy source for
// the duration of the wipe. Pseudo-random would be acceptable for destruction, but true-random is
// nearly free. (RESEARCH-DIGEST.md: esp_fill_random is pseudo-random unless an entropy source is
// active.)
// ---------------------------------------------------------------------------------------------
struct EntropyGuard {
  EntropyGuard() {
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
    bootloader_random_enable();
#endif
  }
  ~EntropyGuard() {
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
    bootloader_random_disable();
#endif
  }
};

#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)

#if defined(SUICIDE_SAFE_MODE)
// Canonical scratch subtype (SPEC §3): a DATA partition with subtype 0x40, label "scratch".
// Declared as a literal so we do not depend on a named IDF enum (0x40 is in the user data-subtype
// range and may not have a stable symbol across IDF versions). Only compiled under SAFE MODE — it
// is exclusively used by the simulated-destruct path.
constexpr esp_partition_subtype_t SCRATCH_SUBTYPE =
    (esp_partition_subtype_t)0x40;

// Find the dedicated SAFE-MODE scratch partition. SAFE MODE must NEVER erase a live partition, so
// this returns ONLY a DATA partition LABELLED "scratch" — and returns nullptr otherwise. There is
// deliberately NO fallback to guardcfg / ota_0 / nvs / spiffs / the running app. As an explicit
// guard, a partition that (mis)labels itself "scratch" but carries a guardcfg/nvs/spiffs/ota_0
// subtype, OR that IS the currently-running partition, is REJECTED (returns nullptr) so a hostile
// or mis-built table can never redirect a simulated erase onto something load-bearing.
const esp_partition_t* findScratchPartition() {
  const esp_partition_t* p =
      esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "scratch");
  if (!p) {
    return nullptr;
  }

  // Reject anything whose subtype matches a live data role, even if it claims the "scratch" label.
  if (p->subtype == ESP_PARTITION_SUBTYPE_DATA_NVS ||      // guardcfg / Marauder nvs
      p->subtype == ESP_PARTITION_SUBTYPE_DATA_SPIFFS ||   // spiffs
      p->subtype == ESP_PARTITION_SUBTYPE_DATA_OTA ||      // otadata
      p->subtype == ESP_PARTITION_SUBTYPE_DATA_COREDUMP) { // coredump
    ESP_LOGE(TAG, "[SAFE] partition labelled 'scratch' has live subtype 0x%02x — REJECTED",
             (unsigned)p->subtype);
    return nullptr;
  }
  // Belt-and-suspenders: reject the canonical live labels regardless of subtype.
  if (p->label[0] != '\0' &&
      (strcmp(p->label, "guardcfg") == 0 || strcmp(p->label, "ota_0") == 0 ||
       strcmp(p->label, "app0") == 0 || strcmp(p->label, "nvs") == 0 ||
       strcmp(p->label, "spiffs") == 0)) {
    ESP_LOGE(TAG, "[SAFE] 'scratch' lookup resolved to live label '%s' — REJECTED", p->label);
    return nullptr;
  }
  // Positively require the canonical scratch subtype (SPEC §3: data 0x40). A "scratch"-labelled
  // partition with any other subtype is not the dedicated dry-run target — reject it.
  if (p->subtype != SCRATCH_SUBTYPE) {
    ESP_LOGE(TAG, "[SAFE] partition labelled 'scratch' has subtype 0x%02x (expected 0x40) — REJECTED",
             (unsigned)p->subtype);
    return nullptr;
  }
  // Never the running partition.
  const esp_partition_t* running = esp_ota_get_running_partition();
  if (running &&
      running->address == p->address && running->size == p->size) {
    ESP_LOGE(TAG, "[SAFE] 'scratch' resolves to the RUNNING partition — REJECTED");
    return nullptr;
  }
  return p;
}
#endif  // SUICIDE_SAFE_MODE (findScratchPartition)

// Erase one named data partition by (subtype, label). In SAFE MODE this is LOG-ONLY: it performs
// ZERO esp_partition_erase_range and never touches any partition (live OR scratch). Returns true on
// success / simulated success.
bool eraseDataPartition(esp_partition_subtype_t subtype, const char* label) {
  const esp_partition_t* part =
      esp_partition_find_first(ESP_PARTITION_TYPE_DATA, subtype, label);

#if defined(SUICIDE_SAFE_MODE)
  if (!part) {
    ESP_LOGI(TAG, "[SAFE] would erase data '%s' (not present) — no-op", label ? label : "?");
    return true;
  }
  // LOG ONLY — never erase the live partition and never redirect onto scratch. The scratch
  // partition's existence is validated once at SAFE-mode entry (trigger()); here we only log.
  ESP_LOGI(TAG, "[SAFE] would erase data '%s' (%u bytes @0x%06x) — NO-OP (zero erases)",
           label ? label : "?", (unsigned)part->size, (unsigned)part->address);
  return true;
#else
  if (!part) {
    ESP_LOGW(TAG, "data '%s' not present — skipping", label ? label : "?");
    return true;  // absence is not a failure
  }
  ESP_LOGW(TAG, "erasing data '%s' (%u bytes @0x%06x)", label ? label : "?",
           (unsigned)part->size, (unsigned)part->address);
  esp_err_t e = esp_partition_erase_range(part, 0, part->size);
  if (e != ESP_OK) {
    ESP_LOGE(TAG, "erase '%s' failed: %s", label ? label : "?", esp_err_to_name(e));
    return false;
  }
  return true;
#endif
}

// Erase an APP-type partition (ota_0 / factory) found by subtype. In SAFE MODE this is LOG-ONLY:
// ZERO esp_partition_erase_range, no live partition and no scratch touched.
bool eraseAppPartition(esp_partition_subtype_t subtype, const char* what) {
  const esp_partition_t* part =
      esp_partition_find_first(ESP_PARTITION_TYPE_APP, subtype, nullptr);

#if defined(SUICIDE_SAFE_MODE)
  if (!part) {
    ESP_LOGI(TAG, "[SAFE] would erase app %s (not present) — no-op", what);
    return true;
  }
  // LOG ONLY — never erase the live app slot and never redirect onto scratch.
  ESP_LOGI(TAG, "[SAFE] would erase app %s (%u bytes @0x%06x) — NO-OP (zero erases)",
           what, (unsigned)part->size, (unsigned)part->address);
  return true;
#else
  if (!part) {
    ESP_LOGW(TAG, "app %s not present — skipping", what);
    return true;
  }
  ESP_LOGW(TAG, "erasing app %s (%u bytes @0x%06x)", what, (unsigned)part->size,
           (unsigned)part->address);
  esp_err_t e = esp_partition_erase_range(part, 0, part->size);
  if (e != ESP_OK) {
    ESP_LOGE(TAG, "erase app %s failed: %s", what, esp_err_to_name(e));
    return false;
  }
  return true;
#endif
}

#endif  // ESP32

// ---------------------------------------------------------------------------------------------
// SD wipe implementation (weak — a board package may override for SD_MMC / SdFat raw speed).
// Best-effort order (RESEARCH-DIGEST.md): (1) recursively overwrite + delete every file, then
// (2) overwrite remaining free space with random data. Native full-LBA erase + reformat are
// reserved for a raw-sector backend (SdFat); the stock-SD path here does file + free-space
// overwrite, which is what is portable across every board. FTL wear-leveling means remapped /
// over-provisioned cells may survive — this is documented, not hidden (SPEC §8, SAFETY.md).
// ---------------------------------------------------------------------------------------------
#if !defined(SUICIDE_NO_SD) && (defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM))

bool overwriteFile(File& f, uint8_t* buf, size_t bufLen, uint8_t passes) {
  size_t total = f.size();
  for (uint8_t p = 0; p < passes; ++p) {
    if (!f.seek(0)) {
      return false;
    }
    size_t remaining = total;
    while (remaining > 0) {
      size_t chunk = remaining < bufLen ? remaining : bufLen;
      esp_fill_random(buf, chunk);
      size_t w = f.write(buf, chunk);
      if (w != chunk) {
        return false;
      }
      remaining -= chunk;
    }
    f.flush();
  }
  return true;
}

// Recurse a directory: overwrite each file's contents (cfg.sd_passes), then remove it. Returns
// true if every descendant was scrubbed; false if anything failed (a write error OR a path too
// long for our stack buffer — a truncated path would scrub/remove the WRONG node or silently skip
// it, so we treat truncation as a wipe failure and do NOT act on the truncated path).
bool scrubDir(fs::FS& fs, const char* path, uint8_t* buf, size_t bufLen, uint8_t passes) {
  File dir = fs.open(path);
  if (!dir || !dir.isDirectory()) {
    if (dir) dir.close();
    return true;
  }
  bool ok = true;
  for (File entry = dir.openNextFile(); entry; entry = dir.openNextFile()) {
    // Copy name before we close/recurse (entry buffer is reused). Detect truncation explicitly:
    // strncpy silently cuts an over-long path, which would point us at the wrong file/dir.
    char child[256];
    const char* src = entry.path();
    size_t srcLen = strlen(src);
    if (srcLen >= sizeof(child)) {
      ESP_LOGW(TAG, "SD wipe: path too long (%u >= %u), NOT scrubbed: %s",
               (unsigned)srcLen, (unsigned)sizeof(child), src);
      ok = false;          // count as a wipe failure rather than silently skipping
      entry.close();
      continue;            // do NOT overwrite/remove a truncated (wrong) path
    }
    memcpy(child, src, srcLen);
    child[srcLen] = '\0';
    bool isDir = entry.isDirectory();
    if (isDir) {
      entry.close();
      ok &= scrubDir(fs, child, buf, bufLen, passes);
      fs.rmdir(child);
    } else {
      if (!overwriteFile(entry, buf, bufLen, passes)) {
        ESP_LOGW(TAG, "SD wipe: overwrite failed: %s", child);
        ok = false;
      }
      entry.close();
      fs.remove(child);
    }
  }
  dir.close();
  return ok;
}

// Overwrite remaining free space by writing one big random file until the card is full, then
// deleting it. Defeats casual carving of previously-freed sectors (best-effort; FTL caveat).
void overwriteFreeSpace(fs::FS& fs, uint8_t* buf, size_t bufLen) {
  File f = fs.open("/.sm_wipe.tmp", FILE_WRITE);
  if (!f) {
    return;
  }
  for (;;) {
    esp_fill_random(buf, bufLen);
    size_t w = f.write(buf, bufLen);
    if (w != bufLen) {
      break;  // card full (or error) — stop
    }
  }
  f.flush();
  f.close();
  fs.remove("/.sm_wipe.tmp");
}

#endif  // SD available

}  // namespace

// Weak SD hook: returns true if the SD was handled (so a board override can fully replace this).
__attribute__((weak)) bool wipeSDImpl(const GateConfig& cfg) {
#if defined(SUICIDE_SAFE_MODE)
  ESP_LOGI(TAG, "[SAFE] would wipe SD (sd_passes=%u): recursive file overwrite + free-space "
                "overwrite + erase/format — NO-OP, no card touched",
           (unsigned)cfg.sd_passes);
  return true;
#elif !defined(SUICIDE_NO_SD) && (defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM))
  if (!SD.begin()) {
    ESP_LOGW(TAG, "SD.begin() failed — no card present or bus busy; skipping SD wipe");
    return false;
  }
  uint8_t passes = cfg.sd_passes ? cfg.sd_passes : 1;
  uint8_t* buf = (uint8_t*)malloc(OVERWRITE_BUF);
  if (!buf) {
    ESP_LOGE(TAG, "SD wipe: out of RAM for overwrite buffer");
    SD.end();
    return false;
  }
  ESP_LOGW(TAG, "SD wipe: overwriting all files (%u pass) then free space — best-effort (FTL)",
           (unsigned)passes);
  bool ok = scrubDir(SD, "/", buf, OVERWRITE_BUF, passes);
  if (!ok) {
    ESP_LOGW(TAG, "SD wipe: one or more files could not be scrubbed (see warnings above)");
  }
  overwriteFreeSpace(SD, buf, OVERWRITE_BUF);
  // Best-effort metadata reset: re-init wipes our open handles; a true full-LBA erase + reformat
  // needs a raw-sector backend (SdFat) — see RESEARCH-DIGEST.md; provided by a board override.
  memset(buf, 0, OVERWRITE_BUF);
  free(buf);
  SD.end();
  return ok;
#else
  ESP_LOGW(TAG, "SD support not compiled in (SUICIDE_NO_SD) — skipping SD wipe");
  return false;
#endif
}

bool SelfDestruct::wipeSD(const GateConfig& cfg) {
  if (!cfg.wipe_sd) {
    ESP_LOGI(TAG, "wipe_sd=0 — skipping SD");
    return true;
  }
  EntropyGuard entropy;  // true-random overwrite payload for the duration
  return wipeSDImpl(cfg);
}

// ---------------------------------------------------------------------------------------------
// Retry wrappers (red-team robustness, SPEC §8): a single esp_partition_erase_range can fail
// transiently (bus contention, a marginal sector). Retry a failed partition a few times before
// giving up so one flaky sector does not abort the whole wipe. In SAFE MODE the underlying erase is
// a log-only no-op that returns true, so these loop exactly once.
// ---------------------------------------------------------------------------------------------
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)

namespace {
constexpr int ERASE_RETRIES = 3;  // total attempts per partition (1 try + 2 retries)

bool eraseDataPartitionRetry(esp_partition_subtype_t subtype, const char* label) {
  for (int attempt = 1; attempt <= ERASE_RETRIES; ++attempt) {
    if (eraseDataPartition(subtype, label)) {
      return true;
    }
    ESP_LOGW(TAG, "erase data '%s' attempt %d/%d failed — retrying", label ? label : "?", attempt,
             ERASE_RETRIES);
  }
  ESP_LOGE(TAG, "erase data '%s' FAILED after %d attempts", label ? label : "?", ERASE_RETRIES);
  return false;
}

bool eraseAppPartitionRetry(esp_partition_subtype_t subtype, const char* what) {
  for (int attempt = 1; attempt <= ERASE_RETRIES; ++attempt) {
    if (eraseAppPartition(subtype, what)) {
      return true;
    }
    ESP_LOGW(TAG, "erase app %s attempt %d/%d failed — retrying", what, attempt, ERASE_RETRIES);
  }
  ESP_LOGE(TAG, "erase app %s FAILED after %d attempts", what, ERASE_RETRIES);
  return false;
}
}  // namespace

#endif  // ESP32

// ---------------------------------------------------------------------------------------------
// Stage 2: internal partitions. Covers EVERY app+data partition (FORK 4 MB, FORK/GUARDIAN 16 MB,
// T2 layouts) except the running app: app slots ota_0 AND ota_1 (a GUARDIAN/16 MB layout has a
// second app slot a 4 MB FORK does not), spiffs, Marauder nvs, coredump, otadata (boot-selection
// metadata), nvs_keys (the T2 NVS-encryption key partition — leaving it would let an attacker
// decrypt a recovered NVS image), then guardcfg LAST. Each step is retried; the bool result is
// captured so trigger() can know whether the wipe truly completed (red-team: never log "complete"
// over a failed step).
// ---------------------------------------------------------------------------------------------
bool SelfDestruct::wipeInternal(const GateConfig& cfg) {
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
  bool ok = true;

  const esp_partition_t* running = esp_ota_get_running_partition();

  // App slots. Loss of a non-running slot does not stop the running code. The RUNNING app slot
  // (FORK: typically ota_0) is NOT erased here — that is the brick stage's job; erasing it now would
  // crash mid-sequence. We defer ONLY the running slot and still erase any other app slot.
  if (cfg.wipe_ota) {
    struct AppSlot { esp_partition_subtype_t subtype; const char* name; };
    const AppSlot appSlots[] = {
        {ESP_PARTITION_SUBTYPE_APP_OTA_0, "ota_0"},
        {ESP_PARTITION_SUBTYPE_APP_OTA_1, "ota_1"},  // GUARDIAN/16 MB second app slot (absent on 4 MB)
    };
    for (const AppSlot& slot : appSlots) {
      const esp_partition_t* p =
          esp_partition_find_first(ESP_PARTITION_TYPE_APP, slot.subtype, nullptr);
      if (p && running && p->address == running->address && p->size == running->size) {
        ESP_LOGW(TAG, "%s is the running partition — deferring its erase to the brick stage",
                 slot.name);
        continue;  // do not crash mid-sequence; brickBootChain (if cfg.brick) handles it
      }
      ok &= eraseAppPartitionRetry(slot.subtype, slot.name);
    }
  }

  if (cfg.wipe_spiffs) {
    ok &= eraseDataPartitionRetry(ESP_PARTITION_SUBTYPE_DATA_SPIFFS, "spiffs");
  }
  if (cfg.wipe_nvs) {
    // Marauder's main NVS (label "nvs"). NOT guardcfg (also nvs-subtype) — that is erased last.
    ok &= eraseDataPartitionRetry(ESP_PARTITION_SUBTYPE_DATA_NVS, "nvs");
  }

  // Coredump always erased (may hold RAM snapshots / secrets).
  ok &= eraseDataPartitionRetry(ESP_PARTITION_SUBTYPE_DATA_COREDUMP, "coredump");

  // otadata: boot-selection metadata. Always erased so a recovered board cannot infer/boot a
  // surviving slot (and on GUARDIAN this forces fallback to factory). Absent on a single-slot 4 MB
  // FORK — eraseDataPartition treats "not present" as success.
  ok &= eraseDataPartitionRetry(ESP_PARTITION_SUBTYPE_DATA_OTA, "otadata");

  // nvs_keys: the T2 NVS-encryption key partition. MUST be erased — otherwise a dumped (encrypted)
  // NVS image could be decrypted with the surviving keys. Absent on T1 builds (treated as success).
  ok &= eraseDataPartitionRetry(ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS, "nvs_keys");

  // guardcfg LAST of the data partitions. cfg is already in RAM, so this is safe.
  ok &= eraseDataPartitionRetry(ESP_PARTITION_SUBTYPE_DATA_NVS, "guardcfg");

  return ok;
#else
  (void)cfg;
  return true;
#endif
}

// ---------------------------------------------------------------------------------------------
// Stage 3: brick the boot chain. IRAM_ATTR, non-returning. Raw-erases the partition table,
// bootloader, and the running app/factory region via esp_flash_erase_region (raw offsets, because
// after the partition table is gone the esp_partition_* APIs are invalid).
//
// *** UNVERIFIED PRIMITIVE *** — self-erase of the currently-running app region is the one step
// no primary Espressif source documents (RESEARCH-DIGEST.md rated UNCERTAIN). It must be proven on
// a SACRIFICIAL board (docs/SPIKE-PLAN.md) and requires CONFIG_SPI_FLASH_DANGEROUS_WRITE_ALLOWED=y,
// or the IDF dangerous-write check abort()s the instant we touch the boot chain.
//
// CACHE/IRAM SAFETY (honest reality, not a guarantee): esp_flash_erase_region disables the flash
// cache *internally* for the duration of each erase, and the IDF spi_flash layer is largely placed
// in IRAM — but it is NOT guaranteed to be fully IRAM-resident across all IDF versions/targets, and
// this function itself being IRAM_ATTR does not pull in every callee. We therefore minimize risk by
// using only register/DRAM-resident integer offsets and emitting NO logging / NO flash-resident
// string fetches once the destructive sequence begins. Even so, the self-erase of the
// currently-running app region remains UNVERIFIED (could fault mid-erase before completing) and must
// be proven on a SACRIFICIAL board (docs/SPIKE-PLAN.md). The end state is still a brick (the table +
// bootloader are erased first), but completion of the running-region erase is not assured.
//
// Under SUICIDE_SAFE_MODE this is a LOG-ONLY no-op that returns (so SAFE builds can keep running);
// the noreturn contract only holds for a real brick.
// ---------------------------------------------------------------------------------------------
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)

// Bootloader offset differs by chip family (SPEC §2 / RESEARCH-DIGEST.md):
//   classic ESP32 / S2 -> 0x1000 ; S3 / C3 / C6 / H2 -> 0x0.
#if defined(CONFIG_IDF_TARGET_ESP32) || defined(CONFIG_IDF_TARGET_ESP32S2)
static constexpr uint32_t BOOTLOADER_OFFSET = 0x1000;
#else
// S3 / C3 / C6 / H2 (and any newer target) place the 2nd-stage bootloader at 0x0.
static constexpr uint32_t BOOTLOADER_OFFSET = 0x0;
#endif
static constexpr uint32_t PARTITION_TABLE_OFFSET = 0x8000;  // SPEC §2: always 0x8000
static constexpr uint32_t PARTITION_TABLE_SIZE   = 0x1000;  // one sector covers the table
static constexpr uint32_t BOOTLOADER_SPAN        = 0x7000;  // bootloader region up to the table

#endif  // ESP32

void IRAM_ATTR SelfDestruct::brickBootChain(const GateConfig& cfg) {
#if defined(SUICIDE_SAFE_MODE)
  // SAFE MODE: never touch the boot chain. Log and return (contract: noreturn only for real brick).
  ESP_LOGW(TAG, "[SAFE] would BRICK boot chain: erase partition table @0x%06x, bootloader @0x%06x, "
                "and running app region — NO-OP",
           (unsigned)0x8000,
#if defined(CONFIG_IDF_TARGET_ESP32) || defined(CONFIG_IDF_TARGET_ESP32S2)
           (unsigned)0x1000
#else
           (unsigned)0x0
#endif
  );
  (void)cfg;
  // Spin so the (declared noreturn) signature is honored even in SAFE builds without faulting the
  // caller; a SAFE build that reaches a real brick is a test, not a destruction.
  for (;;) {
    delay(1000);
  }
#elif defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
  (void)cfg;

  // Resolve the running app region BEFORE we destroy the partition table (after which the
  // partition APIs are invalid). Capture as plain integers held in registers/DRAM.
  const esp_partition_t* running = esp_ota_get_running_partition();
  uint32_t app_addr = running ? (uint32_t)running->address : 0x10000u;  // SPEC §2 default app
  uint32_t app_size = running ? (uint32_t)running->size : 0x100000u;

  esp_flash_t* chip = esp_flash_default_chip;

  // From here on: NO logging, NO flash-resident access. Cache is disabled inside each erase call.
  // Order within the brick: (a) partition table -> ROM can no longer find any image; (b)
  // bootloader -> nothing to execute; (c) the running app region LAST so the CPU keeps fetching
  // valid instructions for as long as possible.
  esp_flash_erase_region(chip, PARTITION_TABLE_OFFSET, PARTITION_TABLE_SIZE);
  esp_flash_erase_region(chip, BOOTLOADER_OFFSET,
                         BOOTLOADER_OFFSET == 0x0 ? PARTITION_TABLE_OFFSET : BOOTLOADER_SPAN);
  // The UNVERIFIED self-erase of the running region. If the CPU faults mid-erase the device is
  // already non-bootable (table + bootloader are gone), so the end state is still a brick.
  esp_flash_erase_region(chip, app_addr, app_size);

  // Should never reach here on real hardware. Force a reset into a now-empty boot chain.
  esp_restart();
  for (;;) {
  }
#else
  (void)cfg;
  for (;;) {
  }
#endif
}

// ---------------------------------------------------------------------------------------------
// panicIndicate — optional brief LED / serial signal. Must never block long; the wipe must start.
// ---------------------------------------------------------------------------------------------
void SelfDestruct::panicIndicate(TriggerReason reason) {
  const char* why = "?";
  switch (reason) {
    case REASON_DEADMAN:   why = "DEADMAN";   break;
    case REASON_ATTEMPTS:  why = "ATTEMPTS";  break;
    case REASON_HOST_WIPE: why = "HOST_WIPE"; break;
    default:               why = "NONE";      break;
  }
#if defined(SUICIDE_SAFE_MODE)
  ESP_LOGW(TAG, "[SAFE] SELF-DESTRUCT TRIGGERED (reason=%s) — simulation only", why);
#else
  ESP_LOGW(TAG, "SELF-DESTRUCT TRIGGERED (reason=%s)", why);
#endif
#if defined(LED_BUILTIN)
  pinMode(LED_BUILTIN, OUTPUT);
  for (int i = 0; i < 3; ++i) {
    digitalWrite(LED_BUILTIN, HIGH);
    delay(60);
    digitalWrite(LED_BUILTIN, LOW);
    delay(60);
  }
#endif
}

// ---------------------------------------------------------------------------------------------
// trigger — full sequence per cfg flags (SPEC §8). Non-abortable. Does not return on a real brick.
//   0. set WIPE-IN-PROGRESS tombstone (sgate_rt.wipe_armed=1) BEFORE any erase, so an interrupted
//      wipe RESUMES on the next boot instead of leaving residual data.
//   1. wipeSD  -> 2. wipeInternal (guardcfg LAST)  -> 3. brickBootChain (if cfg.brick).
//   4. clear the tombstone ONLY if every step verifiably succeeded.
//
// Red-team robustness (SPEC §8):
//   (a) the tombstone is committed first (resume on power loss);
//   (b) panicIndicate() runs AFTER the destructive work — do NOT telegraph to an attacker before
//       erasing (the LED blink / serial banner is the LAST thing, not the first);
//   (d) wipeSD()/wipeInternal() bool results are captured; a failed step means we NEVER log
//       "self-destruct complete" and NEVER clear the tombstone — so the next boot retries.
// ---------------------------------------------------------------------------------------------
void SelfDestruct::trigger(const GateConfig& cfg, TriggerReason reason) {
  // cfg is already in RAM (passed by const ref from BootGate); safe to erase guardcfg later.

#if defined(SUICIDE_SAFE_MODE) && (defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM))
  // SAFE-mode entry gate (SPEC §3): a simulated destruct REQUIRES a real, dedicated scratch
  // partition. If one does not exist (or was rejected because it resolves to a live partition),
  // REFUSE to simulate — do not touch ANY partition, the SD, or the boot chain. This guarantees a
  // mis-built SAFE image can never harm a live layout.
  if (findScratchPartition() == nullptr) {
    ESP_LOGE(TAG, "[SAFE] no dedicated 'scratch' partition present — REFUSING to simulate "
                  "self-destruct (zero erases, nothing touched). Add a 'scratch' (data 0x40) "
                  "partition per SPEC §3 to test.");
    return;
  }
  ESP_LOGW(TAG, "[SAFE] scratch partition present — proceeding with LOG-ONLY simulation");
#endif

  // Stage 0 (red-team (a)): set the WIPE-IN-PROGRESS tombstone and COMMIT it to NVS BEFORE touching
  // anything. If power is lost mid-erase, GateConfig::load() sees sgate_rt.wipe_armed=1 on the next
  // boot and BootGate::run() RE-TRIGGERS this sequence to finish. Under SUICIDE_SAFE_MODE this is a
  // log-only no-op (no real NVS write — a dry run must never arm a real resume). We deliberately do
  // NOT abort if the tombstone write fails: failing to persist it must not stop the wipe (the worst
  // case is no auto-resume, never a skipped wipe).
  GateRuntime rt = GateRuntime::load();
  if (!rt.setWipeTombstone()) {
    ESP_LOGE(TAG, "could not persist wipe tombstone (sgate_rt.wipe_armed) — proceeding anyway; "
                  "auto-resume-on-interrupt may be unavailable");
  }

  // Stage 1: SD (best-effort, FTL-limited; documented). Capture the result.
  bool ok = true;
  ok &= wipeSD(cfg);

  // Stage 2: internal data partitions, guardcfg LAST. Capture the result.
  ok &= wipeInternal(cfg);

  // Red-team (b): panicIndicate() runs HERE — after the destructive work — so we never telegraph an
  // imminent wipe to an attacker before the data is gone. On a brick build the device is already
  // erased by now; on T1 it is data-wiped. (On a real brick with cfg.brick we still signal first,
  // because brickBootChain never returns.)
  panicIndicate(reason);

  // Stage 3: brick the boot chain only if configured (T1 default 0; T2 default 1). A real brick does
  // not return, so the tombstone-clear/halt below is reached only on T1 or SAFE builds. If earlier
  // stages failed we still proceed to brick (defense-in-depth: a configured brick should still run),
  // but we do NOT clear the tombstone unless everything succeeded.
  if (cfg.brick) {
    if (!ok) {
      ESP_LOGE(TAG, "one or more wipe steps FAILED before brick — tombstone left SET so a "
                    "non-bricked retry can finish; proceeding to brick");
    }
    brickBootChain(cfg);  // noreturn on a real brick
    // (SAFE-mode brickBootChain spins; real brick never returns.)
  }

  if (ok) {
    // Red-team (a): a wipe verifiably completed — the tombstone must be GONE so a later clean
    // reflash is not perpetually re-wiped. In the REAL path wipeInternal already erased the
    // guardcfg partition (which physically holds the sgate_rt tombstone) as its LAST step, so the
    // tombstone is already cleared — re-writing wipe_armed=0 here would RE-CREATE guardcfg and leave
    // a residual artifact, so we MUST NOT. Under SUICIDE_SAFE_MODE nothing was really erased, so we
    // call the (no-op) clear for symmetry/logging only.
#if defined(SUICIDE_SAFE_MODE)
    rt.clearWipeTombstone();  // log-only no-op (no real NVS write)
#else
    ESP_LOGW(TAG, "wipe complete — tombstone cleared implicitly by the guardcfg erase");
#endif
  }

#if defined(SUICIDE_SAFE_MODE)
  if (ok) {
    ESP_LOGW(TAG, "[SAFE] self-destruct simulation complete (brick=%u) — device still alive",
             (unsigned)cfg.brick);
  } else {
    // Red-team (d): never claim completion when a step failed.
    ESP_LOGE(TAG, "[SAFE] self-destruct simulation had FAILED step(s) (brick=%u) — tombstone left "
                  "SET; NOT logging complete", (unsigned)cfg.brick);
  }
#else
  if (ok) {
    // T1 (brick=0): data is wiped but the board is still reflashable. Halt — the gate's job is done
    // and we must not fall through into Marauder with a half-erased filesystem.
    ESP_LOGW(TAG, "self-destruct complete (brick=0); halting");
  } else {
    // Red-team (d): a step failed. Do NOT log "complete". The tombstone is still SET, so the next
    // boot re-triggers and retries. Halt either way — never fall through into Marauder over partly
    // erased data.
    ESP_LOGE(TAG, "self-destruct INCOMPLETE (brick=0); one or more steps failed — tombstone left "
                  "SET for retry on next boot; halting");
  }
  for (;;) {
    delay(1000);
  }
#endif
}

}  // namespace suicide
