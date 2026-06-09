// BootGate.h — the boot-time gate. Call BootGate::run() ONCE, early in setup().
//
// FORK variant hook (docs/SPEC.md §1): in ESP32Marauder.ino, place the call AFTER
// display_obj.RunSetup() and BEFORE settings_obj.begin(). See firmware/integration/INTEGRATION.md.
//
// State machine: docs/SPEC.md §6. Invariants:
//   * unprovisioned OR master-disarmed  -> GATE_PASS, never wipes
//   * correct password                  -> GATE_PASS, resets attempt counter, never wipes
//   * dead-man line not-armed (armed+deadman) -> SelfDestruct before password is even asked
//   * wrong attempts reach max_att (armed)    -> SelfDestruct
#pragma once

#include "GateConfig.h"

namespace suicide {

// GATE_HALTED (SPEC §8, red-team round 2): a distinct, visibly-locked terminal halt. Used when the
// DESTRUCTIVE-resume bound (MAX_WIPE_RESUMES) is exhausted — the gate stops re-triggering the wipe
// (avoid an endless resume / premature-brick loop) and never returns control to Marauder. Unlike
// GATE_TRIGGERED it does NOT erase; it just refuses to boot.
enum GateResult { GATE_PASS, GATE_TRIGGERED, GATE_HALTED };

enum TriggerReason {
  REASON_NONE = 0,
  REASON_DEADMAN,     // arming line not in armed position (dead-man)
  REASON_ATTEMPTS,    // wrong-password count reached max_att
  REASON_HOST_WIPE,   // explicit `wipe` command over serial (host-assisted)
};

class BootGate {
 public:
  // Runs the full gate. Returns GATE_PASS to let Marauder continue booting.
  // GATE_TRIGGERED is returned only in SAFE_MODE (a real trigger does not return).
  static GateResult run();

 private:
  // master-armed path (SPEC §6 steps 5-7). lowSupply=true on a brownout/undervoltage boot: the
  // CORRECT password is still required to boot (no bypass), but destruction is SUPPRESSED — the
  // dead-man pre-check is skipped and reaching max_att LOCKS/halts forever instead of wiping
  // (reliability-first: a flaky rail must NEVER cause a wipe). SPEC §13.
  static GateResult armedFlow(GateConfig& cfg, bool lowSupply);
  static void       backoff(uint32_t attempt);    // re-prompt pacing

  // Wipe-resume helper (SPEC §8, red-team round 2). resumeWipe() decides what to do about a wipe-in-
  // progress tombstone found at boot: a DESTRUCTIVE resume runs ONLY when the board is still
  // provisioned AND armed AND not low-supply; an unprovisioned/disarmed board treats the tombstone as
  // residue and CLEANS it (never wipes); a low-supply board DEFERS (keeps the tombstone, requires the
  // password to boot). Returns GATE_TRIGGERED (destructive resume, does not return in practice on a
  // real wipe), GATE_HALTED (resume bound exhausted), or GATE_PASS-equivalent handled by run().
  // Updates `proceed` to tell run() whether to continue to the normal gate flow after a cleanup/defer.
  static GateResult resumeWipe(GateConfig& cfg, bool lowSupply, bool& proceed);

  // Distinct, visibly-locked terminal halt (GATE_HALTED). Does NOT erase and never returns to
  // Marauder — used when the DESTRUCTIVE-resume bound is exhausted (SPEC §8).
  static GateResult haltLocked(const char* why) __attribute__((noreturn));
};

} // namespace suicide
