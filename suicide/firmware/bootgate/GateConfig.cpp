// GateConfig.cpp — read the boot-gate config + runtime counter from the `guardcfg` NVS partition.
//
// Canonical schema: docs/SPEC.md §4. Namespaces `sgate` (config) and `sgate_rt` (runtime counter)
// are kept separate so config can be rewritten by the host without resetting the attempt counter.
//
// FAIL-SAFE: a missing `pwhash` blob (or any NVS failure that leaves us without a hash) =>
// provisioned=false, and an unprovisioned device can NEVER wipe (docs/SPEC.md §6 step 2). Defaults
// for every key are the struct defaults declared in GateConfig.h; we only overwrite a field when
// the corresponding key is actually present in NVS.
//
// Owner-only, defensive anti-forensic layer. The plaintext password is never stored — only
// {salt, pwhash, kdf params} live here, and those are read into RAM, never logged.

#include "GateConfig.h"

#include <string.h>

#include "nvs_flash.h"
#include "nvs.h"

#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
#include "esp_log.h"
#endif

namespace suicide {

namespace {

[[maybe_unused]] constexpr const char* TAG = "gatecfg";  // used by SAFE-mode tombstone logging

// Canonical guardcfg partition name (SPEC §3). The gate's NVS lives ONLY here.
constexpr const char* GUARDCFG_PART = "guardcfg";

// Ensure the gate's NVS partition is initialized exactly once. Arduino-ESP32's core normally calls
// nvs_flash_init() for the DEFAULT `nvs` partition during startup, but BootGate::run() executes very
// early in setup() and we must not depend on ordering. Re-calling init when already initialized
// returns ESP_OK, so this is safe and idempotent.
//
// SCOPED TO guardcfg (SPEC §4.1): we init the `guardcfg` partition by name and NEVER touch the
// default `nvs` partition here. In particular we must NOT nvs_flash_erase() the default partition —
// that would destroy Marauder's own config on every boot. If `guardcfg` itself is new/corrupt we
// erase+reinit ONLY that partition so a first-boot device still reads cleanly (it will simply find
// no keys => provisioned=false). Marauder's own startup owns the default partition's lifecycle.
void ensureNvsReady() {
  esp_err_t err = nvs_flash_init_partition(GUARDCFG_PART);
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    // Truncate + reinit the guardcfg partition ONLY. Never the default `nvs` partition.
    nvs_flash_erase_partition(GUARDCFG_PART);
    nvs_flash_init_partition(GUARDCFG_PART);
  }
}

// Helper: read a u8 key, leaving *dst untouched (default) when the key is absent.
void getU8(nvs_handle_t h, const char* key, uint8_t* dst) {
  uint8_t v;
  if (nvs_get_u8(h, key, &v) == ESP_OK) {
    *dst = v;
  }
}

// Helper: read a u32 key, leaving *dst untouched (default) when the key is absent.
void getU32(nvs_handle_t h, const char* key, uint32_t* dst) {
  uint32_t v;
  if (nvs_get_u32(h, key, &v) == ESP_OK) {
    *dst = v;
  }
}

// Open the runtime namespace (read/write). Declared here (ahead of GateConfig::load) so load() can
// peek the wipe tombstone in `sgate_rt`.
//
// TOMBSTONE PARTITION PINNING (SPEC §8, red-team round 2): `sgate_rt` — which holds the wipe-in-
// progress tombstone (wipe_armed) and the resume bound (resume_count) — is read AND written ONLY in
// the dedicated `guardcfg` partition. There is deliberately NO fallback to the DEFAULT `nvs`
// partition here: a stray/foreign `sgate_rt` namespace sitting in the default partition must never be
// able to drive a false wipe-resume. If guardcfg cannot be opened we return the error and the caller
// fails safe (tombstone reads as absent; counter writes are skipped — monotonic, never a reset).
esp_err_t openRuntime(nvs_open_mode_t mode, nvs_handle_t* h) {
  return nvs_open_from_partition(GUARDCFG_PART, NVS_NS_RT, mode, h);
}

// Helper: read a fixed-size blob into dst, returning true iff the stored blob is exactly `len`
// bytes and was read successfully. A short/missing/oversized blob is treated as absent (the
// fail-safe direction for pwhash/salt).
bool getBlobExact(nvs_handle_t h, const char* key, uint8_t* dst, size_t len) {
  size_t actual = 0;
  if (nvs_get_blob(h, key, nullptr, &actual) != ESP_OK) {
    return false;
  }
  if (actual != len) {
    return false;
  }
  return nvs_get_blob(h, key, dst, &actual) == ESP_OK && actual == len;
}

}  // namespace

GateConfig GateConfig::load() {
  GateConfig cfg;  // every field starts at its safe default (armed=0, provisioned=false, etc.)

  ensureNvsReady();

  // Open the dedicated `guardcfg` NVS partition by namespace. The partition itself is named
  // "guardcfg" in the table; nvs_open_from_partition lets us key off it explicitly so we never
  // collide with Marauder's own `nvs` partition.
  nvs_handle_t h;
  esp_err_t err = nvs_open_from_partition("guardcfg", NVS_NS_CFG, NVS_READONLY, &h);
  if (err != ESP_OK) {
    // Fall back to the default NVS partition in case the build placed `sgate` there (dev/SAFE
    // builds may not carve a separate guardcfg partition). Still read-only.
    err = nvs_open(NVS_NS_CFG, NVS_READONLY, &h);
  }
  if (err != ESP_OK) {
    // No config namespace at all => brand-new / plain-Marauder board. Unprovisioned: cannot wipe.
    cfg.provisioned = false;
    return cfg;
  }

  // ---- schema version (SPEC §4.1: read and validate; unknown/missing version => NOT provisioned) --
  // A schema this firmware does not understand must never be allowed to drive a wipe. provision.py
  // now ALWAYS emits cfg_ver (SPEC §4.1 intent), so the key must be PRESENT and == CFG_VERSION:
  // a MISSING cfg_ver is treated as NOT provisioned (a board image that predates the key, or a
  // partly-written/foreign config, can never drive a wipe). versionOk requires both presence and a
  // recognized value.
  uint8_t cfgVer = 0;
  bool haveVer = (nvs_get_u8(h, "cfg_ver", &cfgVer) == ESP_OK);
  bool versionOk = haveVer && (cfgVer == CFG_VERSION);

  // ---- crypto material (load-bearing for provisioned-ness) ----
  bool haveSalt = getBlobExact(h, "salt", cfg.salt, SALT_LEN);
  bool haveHash = getBlobExact(h, "pwhash", cfg.pwhash, KDF_DKLEN);

  // ---- KDF params ----
  getU32(h, "kdf_iter", &cfg.kdf_iter);
  getU8(h, "kdf_dklen", &cfg.kdf_dklen);

  // ---- arming / policy ----
  getU8(h, "armed", &cfg.armed);
  getU8(h, "arm_pin", &cfg.arm_pin);
  getU8(h, "arm_level", &cfg.arm_level);
  getU8(h, "arm_pull", &cfg.arm_pull);
  getU8(h, "deadman", &cfg.deadman);
  getU8(h, "max_att", &cfg.max_att);

  // SPEC §4.1 safety clamp: max_att >= 1, ALWAYS. A corrupt/hostile stored max_att == 0 would make
  // the very first wrong attempt (att_ct=1 >= 0) trigger a wipe — a foot-gun. Clamp a stored 0 back
  // to the safe compile-time default. (armedFlow additionally refuses to trigger when att_ct == 0.)
  if (cfg.max_att == 0) {
    cfg.max_att = SUICIDE_MAX_ATTEMPTS;
  }

  // ---- wipe scope ----
  getU8(h, "wipe_ota", &cfg.wipe_ota);
  getU8(h, "wipe_nvs", &cfg.wipe_nvs);
  getU8(h, "wipe_spiffs", &cfg.wipe_spiffs);
  getU8(h, "wipe_sd", &cfg.wipe_sd);
  getU8(h, "brick", &cfg.brick);
  getU8(h, "sd_passes", &cfg.sd_passes);

  nvs_close(h);

  // Provisioned ONLY when we have a real hash AND a schema version we understand. Per SPEC §4 the
  // host always writes salt+pwhash together; we additionally require a sane dklen so verify() can't
  // be fooled into a zero-length compare, and a recognized cfg_ver (SPEC §4.1) so an unknown schema
  // can never drive a wipe. A missing/short pwhash or unexpected version => provisioned=false => the
  // gate fails safe (GATE_PASS, no wipe).
  cfg.provisioned = versionOk && haveHash && haveSalt &&
                    cfg.kdf_dklen == KDF_DKLEN && cfg.kdf_iter > 0;

  if (!cfg.provisioned) {
    // Scrub any partially-read crypto material so it can never be used.
    memset(cfg.salt, 0, SALT_LEN);
    memset(cfg.pwhash, 0, KDF_DKLEN);
  }

  // ---- wipe-in-progress TOMBSTONE (SPEC §8 robustness, red-team) ----
  // Peek `sgate_rt.wipe_armed`. If a previous self-destruct started and was interrupted (power loss
  // mid-erase), the tombstone is still set. We surface it as cfg.resumeWipe so BootGate::run() can
  // RE-TRIGGER SelfDestruct on this boot and FINISH the wipe — never report a clean PASS over a
  // partially-erased board. This is read regardless of provisioned-ness (a half-erased guardcfg may
  // read unprovisioned, yet the wipe must still complete).
  {
    nvs_handle_t rh;
    if (openRuntime(NVS_READONLY, &rh) == ESP_OK) {
      uint8_t wipeArmed = 0;
      getU8(rh, "wipe_armed", &wipeArmed);
      nvs_close(rh);
      cfg.resumeWipe = (wipeArmed != 0);
    }
  }

  return cfg;
}

// ---------------------------------------------------------------------------
// GateRuntime — monotonic wrong-attempt counter in `sgate_rt`.
// ---------------------------------------------------------------------------

GateRuntime GateRuntime::load() {
  GateRuntime rt;  // att_ct=0, lock_until=0 by default

  ensureNvsReady();

  nvs_handle_t h;
  if (openRuntime(NVS_READONLY, &h) != ESP_OK) {
    // No runtime namespace yet (first boot) => counter is 0, which is correct.
    return rt;
  }

  getU8(h, "att_ct", &rt.att_ct);
  getU32(h, "lock_until", &rt.lock_until);
  getU8(h, "wipe_armed", &rt.wipe_armed);     // SPEC §8 tombstone (reflect flash state in the struct)
  getU8(h, "resume_count", &rt.resume_count); // SPEC §8 (red-team round 2): DESTRUCTIVE-resume bound

  nvs_close(h);
  return rt;
}

void GateRuntime::commitAttempts() {
  // Persist the attempt counter BEFORE responding to a wrong attempt so a power-cycle mid-attempt
  // cannot reset progress toward max_att (docs/SPEC.md §4 / §6). We open read/write here; the
  // partition is writable on the device (the host wrote it but did not lock it). On any failure we
  // simply leave the prior value — the counter is monotonic, so the worst case is one un-counted
  // attempt, never a silent reset.
  ensureNvsReady();

  nvs_handle_t h;
  if (openRuntime(NVS_READWRITE, &h) != ESP_OK) {
    return;
  }

  nvs_set_u8(h, "att_ct", att_ct);
  nvs_set_u32(h, "lock_until", lock_until);
  nvs_commit(h);  // force the write to flash now — do not rely on lazy commit
  nvs_close(h);
}

void GateRuntime::reset() {
  // Called ONLY on a correct password (docs/SPEC.md §6 step 7). Correct always wins: zero the
  // counter and the backoff gate, then persist immediately.
  att_ct = 0;
  lock_until = 0;

  ensureNvsReady();

  nvs_handle_t h;
  if (openRuntime(NVS_READWRITE, &h) != ESP_OK) {
    return;
  }

  nvs_set_u8(h, "att_ct", 0);
  nvs_set_u32(h, "lock_until", 0);
  nvs_commit(h);
  nvs_close(h);
}

// ---------------------------------------------------------------------------
// Wipe-in-progress TOMBSTONE (SPEC §8 robustness, red-team).
//
// Persisted in `sgate_rt` (key `wipe_armed`) so an interrupted wipe (power loss mid-erase) resumes
// on the next boot instead of leaving a deprovisioned-but-data-present board. setWipeTombstone()
// MUST be called and COMMITTED before any erase begins; clearWipeTombstone() only after a wipe
// verifiably completes. Under SUICIDE_SAFE_MODE both are LOG-ONLY no-ops — a dry run must NEVER
// write a real tombstone (that could arm a real resume-wipe on a later non-SAFE boot).
// ---------------------------------------------------------------------------
bool GateRuntime::setWipeTombstone() {
  wipe_armed = 1;
#if defined(SUICIDE_SAFE_MODE)
  ESP_LOGW(TAG, "[SAFE] would SET wipe tombstone (sgate_rt.wipe_armed=1) — NO-OP (no NVS write)");
  return true;
#else
  ensureNvsReady();

  nvs_handle_t h;
  if (openRuntime(NVS_READWRITE, &h) != ESP_OK) {
    return false;
  }
  esp_err_t e1 = nvs_set_u8(h, "wipe_armed", 1);
  esp_err_t e2 = nvs_commit(h);  // commit NOW — the tombstone must be on flash before any erase
  nvs_close(h);
  return e1 == ESP_OK && e2 == ESP_OK;
#endif
}

bool GateRuntime::clearWipeTombstone() {
  wipe_armed = 0;
#if defined(SUICIDE_SAFE_MODE)
  ESP_LOGW(TAG, "[SAFE] would CLEAR wipe tombstone (sgate_rt.wipe_armed=0) — NO-OP (no NVS write)");
  return true;
#else
  ensureNvsReady();

  nvs_handle_t h;
  if (openRuntime(NVS_READWRITE, &h) != ESP_OK) {
    return false;
  }
  esp_err_t e1 = nvs_set_u8(h, "wipe_armed", 0);
  esp_err_t e2 = nvs_commit(h);
  nvs_close(h);
  return e1 == ESP_OK && e2 == ESP_OK;
#endif
}

// ---------------------------------------------------------------------------
// DESTRUCTIVE-resume bound (SPEC §8 robustness, red-team round 2).
//
// Persist the (already-incremented) in-RAM resume_count to `sgate_rt` BEFORE each resume
// SelfDestruct so the bound advances even if THIS resume is itself power-interrupted — without it an
// endlessly-interrupted resume could spin forever (or prematurely brick). Pinned to guardcfg via
// openRuntime(). LOG-ONLY no-op under SUICIDE_SAFE_MODE (a dry run must never write a real counter).
// ---------------------------------------------------------------------------
bool GateRuntime::commitResumeCount() {
#if defined(SUICIDE_SAFE_MODE)
  ESP_LOGW(TAG, "[SAFE] would persist resume_count=%u (sgate_rt) — NO-OP (no NVS write)",
           (unsigned)resume_count);
  return true;
#else
  ensureNvsReady();

  nvs_handle_t h;
  if (openRuntime(NVS_READWRITE, &h) != ESP_OK) {
    return false;
  }
  esp_err_t e1 = nvs_set_u8(h, "resume_count", resume_count);
  esp_err_t e2 = nvs_commit(h);  // commit NOW — the bound must be on flash before the erase begins
  nvs_close(h);
  return e1 == ESP_OK && e2 == ESP_OK;
#endif
}

// ---------------------------------------------------------------------------
// Residual-tombstone CLEANUP (SPEC §8 / §6, red-team round 2).
//
// Reached ONLY on an UNPROVISIONED or MASTER-DISARMED board that nonetheless carries a tombstone.
// Such a board can NEVER wipe (hard invariant), so the tombstone is residue (foreign/aborted state),
// not a genuine interrupted wipe. We clear the runtime tombstone + resume bound AND erase any
// leftover `sgate` config residue in guardcfg so a later boot cannot misread stale state — then the
// caller continues to GATE_PASS. We NEVER SelfDestruct here.
//
// Scoped to the `guardcfg` partition ONLY (never the default `nvs`). LOG-ONLY no-op under
// SUICIDE_SAFE_MODE: zero real erases (SPEC §5/§8). Returns true iff the real cleanup succeeded.
// ---------------------------------------------------------------------------
bool GateRuntime::cleanupResidualTombstone() {
  wipe_armed = 0;
  resume_count = 0;
#if defined(SUICIDE_SAFE_MODE)
  ESP_LOGW(TAG, "[SAFE] would CLEANUP residual tombstone + sgate residue in guardcfg "
                "(wipe_armed=0, resume_count=0, erase sgate ns) — NO-OP (no NVS write/erase)");
  return true;
#else
  ensureNvsReady();

  // 1) Clear the runtime tombstone + resume bound in `sgate_rt`.
  bool ok = true;
  {
    nvs_handle_t rh;
    if (openRuntime(NVS_READWRITE, &rh) == ESP_OK) {
      esp_err_t e1 = nvs_set_u8(rh, "wipe_armed", 0);
      esp_err_t e2 = nvs_set_u8(rh, "resume_count", 0);
      esp_err_t e3 = nvs_commit(rh);
      nvs_close(rh);
      ok = (e1 == ESP_OK && e2 == ESP_OK && e3 == ESP_OK);
    } else {
      ok = false;
    }
  }

  // 2) Erase any leftover `sgate` config residue, scoped to the guardcfg partition. nvs_erase_all
  //    wipes only the OPEN namespace (`sgate`) in this partition — it never touches Marauder's
  //    default `nvs` partition or the runtime counter namespace.
  {
    nvs_handle_t ch;
    if (nvs_open_from_partition(GUARDCFG_PART, NVS_NS_CFG, NVS_READWRITE, &ch) == ESP_OK) {
      esp_err_t e1 = nvs_erase_all(ch);  // ESP_ERR_NVS_NOT_FOUND is fine (already empty)
      esp_err_t e2 = nvs_commit(ch);
      nvs_close(ch);
      if (e1 != ESP_OK && e1 != ESP_ERR_NVS_NOT_FOUND) {
        ok = false;
      }
      if (e2 != ESP_OK) {
        ok = false;
      }
    }
    // If the `sgate` namespace cannot be opened there is simply no config residue to erase; not an
    // error for cleanup purposes.
  }

  ESP_LOGW(TAG, "residual tombstone CLEANUP on unprovisioned/disarmed board (no wipe) -> %s",
           ok ? "ok" : "partial");
  return ok;
#endif
}

}  // namespace suicide
