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
// Raw-sector (full-LBA) wipe uses the SDMMC host driver when available for forensic-grade erasure.
#if !defined(SUICIDE_NO_SD)
#include <FS.h>
#include <SD.h>
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
#include "driver/sdmmc_host.h"
#include "sdmmc_cmd.h"
#endif
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

// ---------------------------------------------------------------------------------------------
// OVERWRITE-THEN-ERASE + RAW VERIFY ("write over all deleted items" — SPEC §8).
//
// HONEST NOR reality (RESEARCH-DIGEST): a single sector erase to 0xFF is FORENSICALLY SUFFICIENT on
// NOR flash — no magnetic remanence, and erase removes the floating-gate charge. The random
// overwrite pass(es) are DEFENSE-IN-DEPTH only and ADD power-loss exposure, so g_flash_passes
// defaults to 1 and the RESUME / fast_wipe paths force 0 (the final erase is the load-bearing step).
// On flash-encrypted (T2) partitions the stored data is already AES-XTS ciphertext, so the "scramble
// the original signature" argument does not really apply there — the final erase is what matters.
//
// These run on internal-flash data + non-running app partitions ONLY (never the running app). Both
// use a small STACK buffer so they can never silently degrade under heap pressure.
// Module-scope knobs are set once by wipeInternal() from GateConfig. Anonymous-ns => file linkage.
static uint8_t g_flash_passes = 1;    // random overwrite passes before the final clean erase
static bool    g_verify_wipe  = true; // raw read-back + confirm all-0xFF after erase
static bool    g_resume_fast  = false; // set by trigger() on a RESUME — force erase-only (no
                                       // overwrite) so a resumed wipe converges within the bounded
                                       // resume budget instead of re-doing minutes of overwrite

constexpr size_t SCRUB_BUF = 512;     // stack scrub/verify buffer (16-aligned for encrypted writes)

// RAM-residue defense (red-team ANGLE 2): volatile-zero the sensitive fields of the in-RAM
// GateConfig (salt + pwhash). cfg is a const ref to BootGate's stack object, which is NOT actually
// const, so const_cast to scrub the real bytes is well-defined; `volatile` defeats dead-store
// elimination. trigger() never returns (halt/brick), so it must scrub here — otherwise the salted
// hash + salt stay readable in powered SRAM via JTAG / cold-boot during the post-wipe halt.
void scrubConfigRam(const GateConfig& cfg) {
  volatile uint8_t* s = const_cast<volatile uint8_t*>(&cfg.salt[0]);
  for (size_t i = 0; i < sizeof(cfg.salt); ++i) s[i] = 0;
  volatile uint8_t* h = const_cast<volatile uint8_t*>(&cfg.pwhash[0]);
  for (size_t i = 0; i < sizeof(cfg.pwhash); ++i) h[i] = 0;
}

// Overwrite (g_flash_passes random passes) then a final clean erase. Returns true iff the region is
// left fully erased. esp_partition_erase_range requires a 4096-multiple size, so a non-sector-aligned
// partition is rejected up front (it would fail the erase anyway). SAFE MODE never reaches here.
bool overwriteThenErase(const esp_partition_t* part) {
  if (part->size % 4096u != 0u) {
    ESP_LOGE(TAG, "'%s' size 0x%x not a 4096 multiple — refusing unsafe erase", part->label,
             (unsigned)part->size);
    return false;
  }
  if (g_flash_passes == 0) {
    return esp_partition_erase_range(part, 0, part->size) == ESP_OK;
  }
  uint8_t buf[SCRUB_BUF];   // stack — never OOMs (the old malloc could silently degrade the wipe)
  bool ok = true;
  for (uint8_t pass = 0; pass < g_flash_passes && ok; ++pass) {
    if (esp_partition_erase_range(part, 0, part->size) != ESP_OK) { ok = false; break; }
    for (size_t off = 0; off < part->size; off += SCRUB_BUF) {
      size_t chunk = (part->size - off) < SCRUB_BUF ? (part->size - off) : SCRUB_BUF;
      esp_fill_random(buf, chunk);                       // true-random (EntropyGuard active)
      if (esp_partition_write(part, off, buf, chunk) != ESP_OK) { ok = false; break; }
    }
  }
  // Final clean erase ALWAYS — never leave the random overwrite pattern on the chip.
  if (esp_partition_erase_range(part, 0, part->size) != ESP_OK) ok = false;
  memset(buf, 0, SCRUB_BUF);  // don't leave random on the stack frame
  return ok;
}

// Confirm the partition is truly erased. Reads RAW flash via esp_flash_read (NOT esp_partition_read)
// so the check is correct on flash-encrypted (T2) partitions: an erased NOR sector is 0xFF at the
// raw/ciphertext level, but esp_partition_read would TRANSPARENTLY DECRYPT it into non-0xFF plaintext
// and the check would always (wrongly) fail — re-triggering the wipe until GATE_HALTED on the exact
// tier meant to be unrecoverable. Raw read sees the true 0xFF. Stack buffer (no OOM); a read error
// returns false (treated as not-verified so the tombstone stays set).
bool verifyErased(const esp_partition_t* part) {
  uint8_t buf[SCRUB_BUF];
  esp_flash_t* chip = esp_flash_default_chip;
  for (size_t off = 0; off < part->size; off += SCRUB_BUF) {
    size_t chunk = (part->size - off) < SCRUB_BUF ? (part->size - off) : SCRUB_BUF;
    if (esp_flash_read(chip, buf, (uint32_t)part->address + off, chunk) != ESP_OK) {
      return false;
    }
    for (size_t i = 0; i < chunk; ++i) {
      if (buf[i] != 0xFF) return false;
    }
  }
  return true;
}

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
  ESP_LOGW(TAG, "scrubbing data '%s' (%u bytes @0x%06x; %u overwrite pass + erase)",
           label ? label : "?", (unsigned)part->size, (unsigned)part->address,
           (unsigned)g_flash_passes);
  if (!overwriteThenErase(part)) {
    ESP_LOGE(TAG, "overwrite/erase data '%s' failed", label ? label : "?");
    return false;
  }
  if (g_verify_wipe && !verifyErased(part)) {
    ESP_LOGE(TAG, "post-erase verify data '%s' FAILED (not all 0xFF)", label ? label : "?");
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
  ESP_LOGW(TAG, "scrubbing app %s (%u bytes @0x%06x; %u overwrite pass + erase)", what,
           (unsigned)part->size, (unsigned)part->address, (unsigned)g_flash_passes);
  if (!overwriteThenErase(part)) {
    ESP_LOGE(TAG, "overwrite/erase app %s failed", what);
    return false;
  }
  if (g_verify_wipe && !verifyErased(part)) {
    ESP_LOGE(TAG, "post-erase verify app %s FAILED (not all 0xFF)", what);
    return false;
  }
  return true;
#endif
}

#endif  // ESP32

// ---------------------------------------------------------------------------------------------
// SD wipe implementation (weak — a board package may override for SD_MMC / SdFat raw speed).
//
// PRIMARY: full-LBA raw-sector wipe (forensic-grade). Uses the SDMMC host driver to write zeros
// (or random+zeros for secure-erase) to every sector from LBA 0 through the last sector, bypassing
// the filesystem entirely. Progress is logged every 1024 sectors.
//
// FALLBACK: file-level overwrite + free-space fill. Used when raw sector access is unavailable
// (e.g. SPI-only SD without SDMMC, or driver init failure). Portable across every board but
// FTL wear-leveling means remapped / over-provisioned cells may survive — documented, not hidden
// (SPEC section 8, SAFETY.md).
// ---------------------------------------------------------------------------------------------
#if !defined(SUICIDE_NO_SD) && (defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM))

// ---- Raw-sector (full-LBA) wipe ----
// Attempts SDMMC raw access for forensic-grade erasure. Returns true if the card was fully wiped
// at the raw sector level. Returns false if raw access is unavailable (caller should fall back to
// file-level wipe).
bool rawSectorWipe(uint8_t* buf, size_t bufLen, uint8_t passes) {
  // The SDMMC host driver requires SD_MMC mode (4-bit or 1-bit). On boards that wire the SD via
  // SPI (most Marauder boards), this will fail to init — that is the expected fallback signal.
#if defined(SOC_SDMMC_HOST_SUPPORTED)
  sdmmc_host_t host = SDMMC_HOST_DEFAULT();
  host.max_freq_khz = SDMMC_FREQ_HIGHSPEED;
  sdmmc_slot_config_t slot = SDMMC_SLOT_CONFIG_DEFAULT();
  // Try 1-bit mode first (wider compatibility); if the slot supports 4-bit, SDMMC_HOST_DEFAULT
  // already sets width=4, but many Marauder boards only wire 1 data line.
  slot.width = 1;

  sdmmc_card_t card;
  memset(&card, 0, sizeof(card));
  esp_err_t err = sdmmc_card_init(&host, &card);
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "SD raw-sector: SDMMC init failed (%s) — will fall back to file-level wipe",
             esp_err_to_name(err));
    return false;
  }

  // Total sector count from the card's CSD register.
  uint32_t totalSectors = (uint32_t)(card.csd.capacity);
  if (totalSectors == 0) {
    ESP_LOGW(TAG, "SD raw-sector: card reports 0 sectors — falling back");
    return false;
  }

  uint32_t sectorsPerBuf = (uint32_t)(bufLen / 512);
  if (sectorsPerBuf == 0) sectorsPerBuf = 1;

  ESP_LOGW(TAG, "SD raw-sector: full-LBA wipe starting — %u total sectors, %u passes",
           (unsigned)totalSectors, (unsigned)passes);

  for (uint8_t pass = 0; pass < passes; ++pass) {
    // Pass strategy: if passes >= 2, first pass writes random data, last pass writes zeros
    // (secure-erase pattern). Single pass writes zeros only (fast wipe).
    bool useRandom = (passes >= 2 && pass < (passes - 1));

    ESP_LOGW(TAG, "SD raw-sector: pass %u/%u (%s)", (unsigned)(pass + 1), (unsigned)passes,
             useRandom ? "random" : "zeros");

    for (uint32_t sector = 0; sector < totalSectors; sector += sectorsPerBuf) {
      uint32_t count = sectorsPerBuf;
      if (sector + count > totalSectors) {
        count = totalSectors - sector;
      }

      size_t byteCount = (size_t)(count * 512);
      if (useRandom) {
        esp_fill_random(buf, byteCount);
      } else {
        memset(buf, 0, byteCount);
      }

      esp_err_t we = sdmmc_write_sectors(&card, buf, sector, count);
      if (we != ESP_OK) {
        ESP_LOGE(TAG, "SD raw-sector: write failed at sector %u: %s",
                 (unsigned)sector, esp_err_to_name(we));
        // Continue past errors — best-effort wipe of remaining sectors.
      }

      // Progress report every 1024 sectors (every ~512 KB).
      if ((sector % 1024) == 0 || sector + count >= totalSectors) {
        ESP_LOGI(TAG, "SD raw-sector: pass %u/%u — sector %u / %u",
                 (unsigned)(pass + 1), (unsigned)passes, (unsigned)(sector + count),
                 (unsigned)totalSectors);
      }
    }
  }

  ESP_LOGW(TAG, "SD raw-sector: full-LBA wipe complete (%u sectors, %u passes)",
           (unsigned)totalSectors, (unsigned)passes);
  return true;
#else
  // SDMMC host not supported on this SoC (e.g. ESP32-C3). Fall back to file-level wipe.
  (void)buf; (void)bufLen; (void)passes;
  ESP_LOGW(TAG, "SD raw-sector: SOC_SDMMC_HOST_SUPPORTED not defined — falling back");
  return false;
#endif  // SOC_SDMMC_HOST_SUPPORTED
}

// ---- File-level wipe (fallback) ----

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
// Strategy: attempt full-LBA raw-sector wipe first (forensic-grade), fall back to file-level
// overwrite + free-space fill when raw access is unavailable.
__attribute__((weak)) bool wipeSDImpl(const GateConfig& cfg) {
#if defined(SUICIDE_SAFE_MODE)
  ESP_LOGI(TAG, "[SAFE] would wipe SD (sd_passes=%u): full-LBA raw-sector wipe (or file-level "
                "fallback) — NO-OP, no card touched",
           (unsigned)cfg.sd_passes);
  return true;
#elif !defined(SUICIDE_NO_SD) && (defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM))
  uint8_t passes = cfg.sd_passes ? cfg.sd_passes : 1;
  uint8_t* buf = (uint8_t*)malloc(OVERWRITE_BUF);
  if (!buf) {
    ESP_LOGE(TAG, "SD wipe: out of RAM for overwrite buffer");
    return false;
  }

  // PRIMARY: attempt full-LBA raw-sector wipe (forensic-grade). This writes zeros (or
  // random+zeros for passes >= 2) to every sector on the card, bypassing the filesystem.
  bool rawOk = rawSectorWipe(buf, OVERWRITE_BUF, passes);
  if (rawOk) {
    ESP_LOGW(TAG, "SD wipe: full-LBA raw-sector wipe succeeded (forensic-grade)");
    memset(buf, 0, OVERWRITE_BUF);
    free(buf);
    return true;
  }

  // FALLBACK: file-level overwrite + free-space fill. Raw access unavailable (SPI-only SD, no
  // SDMMC host, or driver init failure). This is the portable path.
  ESP_LOGW(TAG, "SD wipe: raw-sector unavailable — falling back to file-level overwrite");
  if (!SD.begin()) {
    ESP_LOGW(TAG, "SD.begin() failed — no card present or bus busy; skipping SD wipe");
    memset(buf, 0, OVERWRITE_BUF);
    free(buf);
    return false;
  }
  ESP_LOGW(TAG, "SD wipe: overwriting all files (%u pass) then free space — best-effort (FTL)",
           (unsigned)passes);
  bool ok = scrubDir(SD, "/", buf, OVERWRITE_BUF, passes);
  if (!ok) {
    ESP_LOGW(TAG, "SD wipe: one or more files could not be scrubbed (see warnings above)");
  }
  overwriteFreeSpace(SD, buf, OVERWRITE_BUF);
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
  // Forensic overwrite knobs (read by the erase helpers): in fast_wipe / brownout-priority mode
  // skip the random overwrite — a plain erase is seconds faster and more likely to finish on a
  // marginal supply (the boot chain still ends erased). Otherwise use cfg.flash_passes random
  // overwrite passes + a final clean erase, then verify all-0xFF.
  // Force erase-only (0 passes) when fast_wipe OR this is a resume — a single NOR erase is
  // forensically sufficient (RESEARCH-DIGEST) and converges fast, so a resumed/brownout wipe is not
  // burned re-doing minutes of overwrite on the big partitions (spiffs can be ~12 MB).
  g_flash_passes = (cfg.fast_wipe || g_resume_fast) ? 0 : cfg.flash_passes;
  g_verify_wipe  = true;
  EntropyGuard entropy;  // true-random overwrite payload for the internal scrub
  ESP_LOGW(TAG, "internal scrub: flash_passes=%u (fast_wipe=%u, resume=%u), verify=on",
           (unsigned)g_flash_passes, (unsigned)cfg.fast_wipe, (unsigned)g_resume_fast);

  bool ok = true;

  const esp_partition_t* running = esp_ota_get_running_partition();

  // App slots. Loss of a non-running slot does not stop the running code. The RUNNING app slot
  // (FORK: typically ota_0) is NOT erased here — that is the brick stage's job; erasing it now would
  // crash mid-sequence. We defer ONLY the running slot and still erase any other app slot.
  if (cfg.wipe_ota) {
    struct AppSlot { esp_partition_subtype_t subtype; const char* name; };
    const AppSlot appSlots[] = {
        {ESP_PARTITION_SUBTYPE_APP_OTA_0, "ota_0"},
        {ESP_PARTITION_SUBTYPE_APP_OTA_1, "ota_1"},   // GUARDIAN/16 MB second app slot (absent on 4 MB)
        {ESP_PARTITION_SUBTYPE_APP_FACTORY, "factory"},  // GUARDIAN gate image. Wiped here ONLY if it
                                                         // is NOT the running app; when factory IS the
                                                         // running gate it is deferred to the brick
                                                         // stage (so GUARDIAN-T1 leaves the gate image
                                                         // — only brick/T2 removes it; see THREAT-MODEL).
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

  // scratch (data subtype 0x40): the SAFE-mode dry-run target. In a REAL wipe it may still hold
  // residue from a prior SAFE simulation, and a 0x40 partition labelled 'scratch' is itself a tell —
  // erase it too. (A SAFE build hits the log-only branch, so a dry run never touches its own target.)
  ok &= eraseDataPartitionRetry((esp_partition_subtype_t)0x40, "scratch");

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

  // RESUME detection (red-team ANGLE 4): BootGate increments resume_count BEFORE re-triggering an
  // interrupted wipe, so resume_count > 0 here means this is a destructive RESUME. A resume must
  // CONVERGE within the bounded resume budget (MAX_WIPE_RESUMES), so it (a) forces erase-only internal
  // scrub (g_resume_fast, read by wipeInternal — a single NOR erase is forensically sufficient) and
  // (b) SKIPS the multi-hour full-LBA SD wipe. Re-running the SD wipe from sector 0 on every resume
  // would burn the whole budget on best-effort FTL-limited SD and never reach the flash holding the
  // real secrets (the salted hash + NVS key), halting GATE_HALTED with them still present.
  const bool isResume = (rt.resume_count > 0);
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
  g_resume_fast = isResume;  // consumed by wipeInternal (ESP32 path); host build skips the static
#endif
  const bool skipSD = cfg.fast_wipe || isResume;

  // Fast-wipe / resume: skip the SD wipe (slowest stage) and go straight to flash erase + brick.
  bool ok = true;
  if (skipSD) {
    ESP_LOGW(TAG, "SKIPPING SD wipe (fast_wipe=%u, resume=%u) — prioritizing flash-erase convergence",
             (unsigned)cfg.fast_wipe, (unsigned)isResume);
  } else {
    // Stage 1: SD (best-effort, FTL-limited; documented). Capture the result.
    ok &= wipeSD(cfg);
  }

  // Stage 2: internal data partitions, guardcfg LAST. Capture the result.
  ok &= wipeInternal(cfg);

  // Red-team (b): panicIndicate() runs HERE — after the destructive work — so we never telegraph an
  // imminent wipe to an attacker before the data is gone. On a brick build the device is already
  // erased by now; on T1 it is data-wiped. (On a real brick with cfg.brick we still signal first,
  // because brickBootChain never returns.)
  panicIndicate(reason);

  // RAM-residue defense (red-team ANGLE 2): the salt + pwhash in BootGate's stack GateConfig are not
  // needed past this point, and trigger() never returns — volatile-zero them now so they cannot be
  // recovered from powered SRAM during the brick or the T1 halt below. (guardcfg flash is also wiped;
  // this kills the in-RAM copy.) SAFE builds scrub a dummy cfg harmlessly.
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
  scrubConfigRam(cfg);
#endif

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
