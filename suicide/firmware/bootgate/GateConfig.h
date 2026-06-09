// GateConfig.h — Suicide Marauder boot-gate configuration (read from `guardcfg` NVS).
//
// Canonical schema: see docs/SPEC.md §4. Names/keys here MUST match the host provisioner
// (host/provision.py) and the partition table (firmware/partitions/*.csv) byte-for-byte.
//
// Owner-only, defensive anti-forensic layer. A NON-PROVISIONED or MASTER-DISARMED device can
// never wipe (docs/SAFETY.md). Plaintext passwords are NEVER stored — only {salt, pwhash, params}.
#pragma once

#include <Arduino.h>
#include <stdint.h>

namespace suicide {

// ---- NVS namespaces / keys (canonical — do not rename) ----
static constexpr const char* NVS_NS_CFG = "sgate";     // config
static constexpr const char* NVS_NS_RT  = "sgate_rt";  // runtime counter (kept separate)

// ---- defaults (compile-time fallback only; real values live in guardcfg NVS) ----
#ifndef ARMING_PIN
#define ARMING_PIN 27            // classic ESP32 default; never a strapping pin (SPEC §7)
#endif
#ifndef ARMING_ACTIVE_LEVEL
#define ARMING_ACTIVE_LEVEL 1    // armed = HIGH (intact switch drives it; floating reads LOW)
#endif
#ifndef ARMING_PULL
#define ARMING_PULL 2            // 0=none 1=pullup 2=pulldown
#endif
#ifndef SUICIDE_MAX_ATTEMPTS
#define SUICIDE_MAX_ATTEMPTS 2   // user spec: 2 wrong attempts -> wipe (when ARMED)
#endif
#ifndef SUICIDE_KDF_ITER
// 10000 ~= 1s verify on a classic ESP32-D0WD @240MHz (MEASURED: 150000 ~= 16.7s — far too slow for
// a boot gate). With the 2-attempt wipe, online brute-force is moot, so tune purely for UX; offline
// hash resistance comes from T2 flash-encryption + a strong passphrase, not iteration count. SPEC §9.
#define SUICIDE_KDF_ITER 10000u
#endif

static constexpr uint8_t  KDF_DKLEN   = 32;
static constexpr uint8_t  SALT_LEN    = 16;
static constexpr uint8_t  CFG_VERSION = 1;

// Bound on DESTRUCTIVE wipe-resumes (SPEC §8 robustness, red-team round 2). An interrupted wipe
// resumes on the next boot, but a hostile/stuck condition must not spin forever (endless resume /
// premature-brick loop). After this many destructive resumes the gate stops re-triggering and enters
// a distinct, visibly-locked halt (GATE_HALTED) instead of erasing again.
static constexpr uint8_t  MAX_WIPE_RESUMES = 3;

struct GateConfig {
  bool     provisioned = false;          // true iff a pwhash exists in NVS

  // SPEC §8 robustness (red-team): set true iff the `sgate_rt` wipe-in-progress TOMBSTONE
  // (`wipe_armed == 1`) is present. An interrupted self-destruct (power loss mid-erase) leaves the
  // tombstone set; BootGate::run() MUST re-trigger SelfDestruct on the next boot to FINISH the wipe
  // rather than report a clean (deprovisioned-but-data-present) PASS. This is independent of
  // `provisioned`: a partly-erased guardcfg may read as unprovisioned, but the tombstone still
  // forces resume.
  bool     resumeWipe = false;

  uint8_t  salt[SALT_LEN]   = {0};
  uint8_t  pwhash[KDF_DKLEN] = {0};
  uint32_t kdf_iter = SUICIDE_KDF_ITER;
  uint8_t  kdf_dklen = KDF_DKLEN;

  uint8_t  armed   = 0;                  // MASTER ARM (0=DISARMED safe default, 1=ARMED)
  uint8_t  arm_pin = ARMING_PIN;
  uint8_t  arm_level = ARMING_ACTIVE_LEVEL;
  uint8_t  arm_pull  = ARMING_PULL;
  uint8_t  deadman   = 1;                // 1: not-armed line wipes; 0: line only keeps locked
  uint8_t  max_att   = SUICIDE_MAX_ATTEMPTS;

  uint8_t  wipe_ota = 1, wipe_nvs = 1, wipe_spiffs = 1, wipe_sd = 1;
  uint8_t  brick = 0;                    // T1 default 0; T2 default 1 (SPEC §8)
  uint8_t  sd_passes = 1;

  // Load from `sgate` NVS namespace. Missing pwhash => provisioned=false (cannot wipe).
  static GateConfig load();
};

// Runtime monotonic state in `sgate_rt`. Counter survives power cycles; reset only on success.
struct GateRuntime {
  uint8_t  att_ct = 0;
  uint32_t lock_until = 0;               // exponential backoff gate (disarmed mode)
  uint8_t  wipe_armed = 0;               // SPEC §8: wipe-in-progress TOMBSTONE (1 once a real
                                         // self-destruct has started; cleared only on verified
                                         // completion). Survives power loss => resume an interrupted
                                         // wipe on the next boot.
  uint8_t  resume_count = 0;             // SPEC §8 (red-team round 2): count of DESTRUCTIVE wipe-
                                         // resumes already attempted. Incremented BEFORE each resume
                                         // SelfDestruct. After MAX_WIPE_RESUMES the gate stops re-
                                         // triggering and halts visibly (avoid endless resume /
                                         // premature-brick loop). Survives power loss.

  static GateRuntime load();
  void commitAttempts();                 // persist att_ct BEFORE responding to a wrong attempt
  void reset();                          // att_ct=0 on a correct password

  // SPEC §8 robustness (red-team): persistent wipe-in-progress tombstone in `sgate_rt`.
  // setWipeTombstone() writes wipe_armed=1 and COMMITS it BEFORE any erase begins; clearWipe-
  // Tombstone() removes it only after a wipe verifiably completes. Under SUICIDE_SAFE_MODE both are
  // LOG-ONLY no-ops (zero real NVS writes) so a dry run can never arm a real resume-on-next-boot.
  // Returns true iff the (real) NVS write+commit succeeded. SAFE-mode no-ops return true.
  bool setWipeTombstone();
  bool clearWipeTombstone();

  // SPEC §8 (red-team round 2): persist the DESTRUCTIVE-resume counter to `sgate_rt`. Called with the
  // already-incremented in-RAM resume_count BEFORE each resume SelfDestruct so an interrupted resume
  // still advances the bound (no infinite resume loop across power cycles). LOG-ONLY no-op under
  // SUICIDE_SAFE_MODE. Returns true iff the (real) NVS write+commit succeeded.
  bool commitResumeCount();

  // SPEC §8 / §6 (red-team round 2): residual-tombstone CLEANUP for the non-destructive path.
  // When a tombstone is found on an UNPROVISIONED or MASTER-DISARMED board, that board can NEVER
  // wipe (hard invariant), so the tombstone is treated as residue from a foreign/aborted state, not
  // a real interrupted wipe: clear wipe_armed + resume_count AND erase any leftover `guardcfg` config
  // (`sgate`) residue, then continue to GATE_PASS — NEVER SelfDestruct. Scoped to the guardcfg
  // partition only (never the default `nvs`). LOG-ONLY no-op under SUICIDE_SAFE_MODE (zero real
  // erases). Returns true iff the (real) cleanup succeeded.
  bool cleanupResidualTombstone();
};

} // namespace suicide
