// BootGate.cpp — boot-time gate state machine. docs/SPEC.md §6.
//
// Owner-only, DEFENSIVE anti-forensic ("duress") layer for an ESP32 Marauder the operator owns.
// This file implements ONLY the decision logic; the actual destruction lives in SelfDestruct.cpp
// and is itself guarded by SUICIDE_SAFE_MODE. See docs/SAFETY.md and docs/THREAT-MODEL.md.
//
// Hard invariants (SPEC §6):
//   * UNPROVISIONED  -> GATE_PASS, can never wipe (behaves like plain Marauder).
//   * MASTER-DISARMED (cfg.armed == 0) -> GATE_PASS, physically cannot wipe.
//   * CORRECT password -> reset attempt counter, GATE_PASS, never wipes (always wins).
//   * ARMED + deadman + arming line NOT in armed position -> SelfDestruct(REASON_DEADMAN)
//     BEFORE the password is even requested (a missing/cut switch is terminal).
//   * Wrong-password count reaching max_att (ARMED) -> SelfDestruct(REASON_ATTEMPTS).
//     The attempt counter is committed to NVS BEFORE responding, so a power-cycle mid-attempt
//     cannot reset it.
//   * Explicit host `wipe` over serial -> SelfDestruct(REASON_HOST_WIPE).
//   * Undervoltage / low-battery boot (ARMED) -> destruct SUPPRESSED but the correct password is
//     STILL required to boot (NO bypass): the dead-man pre-check is skipped and reaching max_att
//     LOCKS/re-prompts forever instead of wiping. A brownout must NEVER cause a wipe (reliability-
//     first, SPEC §13) and must NEVER hand out an unlocked board.
//   * Wipe-in-progress tombstone (sgate_rt.wipe_armed) -> CONDITIONAL resume (SPEC §8, red-team
//     round 2). A tombstone triggers a DESTRUCTIVE resume ONLY when the board is STILL provisioned
//     AND armed==1 AND NOT low-supply (a genuine interrupted wipe is always armed+provisioned and
//     erases guardcfg LAST, so it still reads armed). Otherwise:
//       - UNPROVISIONED or MASTER-DISARMED -> the board can never wipe: treat the tombstone as
//         residual CLEANUP only (clear it + erase guardcfg residue) and continue to GATE_PASS;
//         NEVER SelfDestruct. (Closes the force-wipe-over-disarmed DoS: a hand-written wipe_armed=1
//         can no longer force a wipe on a disarmed/unprovisioned board.)
//       - LOW-SUPPLY (brownout) -> DEFER: keep the tombstone, do NOT wipe this boot, and require the
//         password to boot normally. A real interrupted wipe finishes on the next good-power boot
//         (reliability-first, SPEC §13).
//     The number of DESTRUCTIVE resumes is BOUNDED (MAX_WIPE_RESUMES): after the bound is exhausted
//     the gate stops re-triggering and enters a distinct, visibly-locked halt (GATE_HALTED) instead
//     of looping forever / prematurely bricking.
//
// The plaintext password buffer returned by suicide::Input::getPassword() is zeroized after every
// verify() — never stored, never logged.

#include "BootGate.h"

#include "GateConfig.h"
#include "ArmingSwitch.h"
#include "GateCrypto.h"
#include "SelfDestruct.h"
#include "GateInput.h"   // suicide::Input — owned by fw-input, selected by one GATE_INPUT_* flag

#include <Arduino.h>
#include <string.h>

#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
#include "esp_log.h"
#include "esp_system.h"   // esp_reset_reason()
#include "esp_sleep.h"
#include "nvs_flash.h"
#include "nvs.h"
// adc battery read is board-specific; we only need a coarse "is the supply too low to trust the
// arming line / NVS write" signal. Provided via the weak hook below. Enhanced with optional
// ADC-based supply voltage check (define SUPPLY_ADC_PIN + SUPPLY_ADC_THRESHOLD_MV at build time).
#endif

namespace suicide {

namespace {

constexpr const char* TAG = "bootgate";

// RAM hygiene (SPEC §4.1): scrub the crypto material from the stack copy of GateConfig before
// Marauder continues. The salted hash is low-sensitivity, but the posture is "never retained".
// volatile writes prevent the compiler from eliding the wipe of soon-dead stack memory.
void scrubConfigSecrets(GateConfig& cfg) {
  volatile uint8_t* h = reinterpret_cast<volatile uint8_t*>(cfg.pwhash);
  for (size_t i = 0; i < sizeof(cfg.pwhash); ++i) h[i] = 0;
  volatile uint8_t* s = reinterpret_cast<volatile uint8_t*>(cfg.salt);
  for (size_t i = 0; i < sizeof(cfg.salt); ++i) s[i] = 0;
}

// ---------------------------------------------------------------------------------------------
// Undervoltage detection (SPEC §13: undervoltage boot => treat as DISARMED, reliability-first).
//
// We deliberately FAIL TOWARD DISARMED (never wipe) when the supply is questionable: a brown-out
// boot is far more likely a flaky battery/USB than a genuine duress event, and wiping on a flaky
// rail risks a half-completed erase. A board package can override gateSupplyIsLow() (declared weak)
// with a real fuel-gauge / ADC reading. Default: uses hardware brownout reset detection AND an
// ADC-based supply voltage check when a voltage divider is wired to SUPPLY_ADC_PIN.
//
// Brownout events are logged to NVS (sgate_rt.brownout_count) so the operator can see how often
// the device experienced low-voltage conditions.
// ---------------------------------------------------------------------------------------------

// ADC-based supply voltage check. Boards with a voltage divider from VIN/VBAT to an ADC-capable
// pin can define SUPPLY_ADC_PIN and SUPPLY_ADC_THRESHOLD_MV. The threshold is the raw ADC reading
// (in mV after attenuation) below which the supply is considered too low for a reliable wipe.
// Default: disabled (no pin defined). Classic ESP32 ADC1 pins (GPIO32-39) are suitable.
#ifndef SUPPLY_ADC_PIN
// No ADC pin configured — ADC voltage check disabled by default. To enable, define in the build:
//   -DSUPPLY_ADC_PIN=34 -DSUPPLY_ADC_THRESHOLD_MV=2800
#endif

#ifndef SUPPLY_ADC_THRESHOLD_MV
#define SUPPLY_ADC_THRESHOLD_MV 2800  // ~2.8V at the ADC pin suggests supply below ~3.0V
#endif

// Log a brownout event to NVS for operator visibility. The counter is monotonic and never reset
// by normal operation — the operator can read it via SM_INFO to see how many brownout boots
// occurred. Under SAFE_MODE this is a log-only no-op.
void logBrownoutEvent() {
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
#if defined(SUICIDE_SAFE_MODE)
  ESP_LOGW(TAG, "[SAFE] would log brownout event to NVS — NO-OP");
#else
  nvs_handle_t h;
  if (nvs_open_from_partition("guardcfg", NVS_NS_RT, NVS_READWRITE, &h) == ESP_OK) {
    uint8_t count = 0;
    nvs_get_u8(h, "bo_count", &count);
    if (count < 0xFF) count++;
    nvs_set_u8(h, "bo_count", count);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGW(TAG, "brownout event logged to NVS (bo_count=%u)", (unsigned)count);
  }
#endif
#endif
}

bool defaultSupplyIsLow() {
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
  // Check 1: a brownout reset is the one reset cause that unambiguously means the rail sagged
  // below the detector threshold on the previous power event.
  esp_reset_reason_t r = esp_reset_reason();
  if (r == ESP_RST_BROWNOUT) {
    logBrownoutEvent();
    return true;
  }

  // Check 2: ADC-based supply voltage check (when configured). Read the ADC pin and compare
  // against the threshold. This catches a low-but-not-brownout condition where the supply is
  // marginal (e.g. a dying battery that hasn't quite triggered the hardware brownout detector).
#if defined(SUPPLY_ADC_PIN)
  // Use the Arduino analogRead with 11dB attenuation for the widest range (~0-3.3V).
  analogSetPinAttenuation(SUPPLY_ADC_PIN, ADC_11db);
  uint32_t reading_mv = analogReadMilliVolts(SUPPLY_ADC_PIN);
  if (reading_mv > 0 && reading_mv < SUPPLY_ADC_THRESHOLD_MV) {
    ESP_LOGW(TAG, "ADC supply check: %u mV < threshold %u mV — treating as low supply",
             (unsigned)reading_mv, (unsigned)SUPPLY_ADC_THRESHOLD_MV);
    logBrownoutEvent();
    return true;
  }
#endif
#endif
  return false;
}

}  // namespace

// Weak hook: board support packages may provide a real undervoltage measurement (fuel gauge / ADC
// divider). If none is linked, defaultSupplyIsLow() is used.
__attribute__((weak)) bool gateSupplyIsLow() { return defaultSupplyIsLow(); }

// ---------------------------------------------------------------------------------------------
// Re-prompt pacing for the ARMED password loop.
//
// ARMED backoff is intentionally HARD and local — there is no host counter reset path here (SPEC
// §6: "armed: hard, no host reset"). It is a fixed short delay only to debounce a held key / serial
// flood; it must NOT meaningfully extend the window, because the real protection is max_att + the
// power-cycle-safe counter, not a timing wall. Exponential lockout (cfg lock_until) is a
// DISARMED-mode nicety and is not exercised on the armed path.
// ---------------------------------------------------------------------------------------------
void BootGate::backoff(uint32_t attempt) {
  // Linear, capped. attempt is 1-based (the just-failed attempt number).
  uint32_t ms = 500u * attempt;
  if (ms > 3000u) {
    ms = 3000u;
  }
  delay(ms);
}

// ---------------------------------------------------------------------------------------------
// armedFlow — SPEC §6 steps 5-7. Reached when cfg.provisioned && cfg.armed == 1.
//
// lowSupply (SPEC §13, brownout-bypass fix): when the supply is questionable (brownout/undervoltage
// boot) destruction is SUPPRESSED but the gate is NOT bypassed. The CORRECT password is STILL
// required to boot — a low rail must never hand an attacker an unlocked board. But because a flaky
// rail must NEVER cause an irreversible wipe (reliability-first), on a low-supply boot we:
//   * SKIP the dead-man pre-check entirely (the ADC/arming-line read is untrustworthy at low V, and
//     a missing switch must not fire the irreversible path on a sagging rail), and
//   * on reaching max_att, LOCK/HALT forever (re-prompt loop, never SelfDestruct) instead of wiping.
// Returns GATE_PASS only on a correct password; otherwise drives SelfDestruct (trusted supply) or
// locks forever (low supply).
// ---------------------------------------------------------------------------------------------
GateResult BootGate::armedFlow(GateConfig& cfg, bool lowSupply) {
  // Step 6: dead-man pre-check. In dead-man mode a cut/floating/unpowered arming wire reads
  // NOT_ARMED and is terminal BEFORE we ever ask for a password.
  // SUPPRESSED on a low-supply boot: do not read the arming line and do not allow a deadman wipe —
  // a brownout must never fire the irreversible path (SPEC §13). The password is still required.
  if (cfg.deadman == 1 && !lowSupply) {
    ArmState line = ArmingSwitch::read(cfg);
    if (line == NOT_ARMED) {
      ESP_LOGW(TAG, "ARMED + deadman: arming line NOT in armed position -> REASON_DEADMAN");
      SelfDestruct::trigger(cfg, REASON_DEADMAN);
      return GATE_TRIGGERED;  // does not return in practice (real, non-SAFE brick)
    }
  } else if (cfg.deadman == 1 && lowSupply) {
    ESP_LOGW(TAG, "low-supply boot: SKIPPING dead-man pre-check (suppress destruct; password still "
                  "required) — reliability-first (SPEC §13)");
  }

  // Step 7: password loop. The runtime counter is monotonic and power-cycle-safe.
  GateRuntime rt = GateRuntime::load();

  Input::begin(cfg);

  for (;;) {
    InputResult in = Input::getPassword(cfg);

    if (!in.got) {
      // No input available yet (timeout / driver still waiting). Re-prompt without counting it as
      // a wrong attempt. Defensive: ensure the buffer is clear before looping.
      memset(in.buf, 0, sizeof(in.buf));
      in.len = 0;
      continue;
    }

    // SPEC §6 authenticated host-wipe: a serial `wipe` command sets wipeRequest=true AND carries the
    // password the operator typed at the wipe confirmation prompt (GateInput_serial.cpp). The wipe is
    // deliberate ONLY when that password verifies. An unauthenticated/accidental `wipe\n` (terminal
    // paste, serial noise) yields an empty/garbage secret that fails verify and is counted as a
    // failed attempt — it can NEVER destroy data on its own.
    const bool isWipeRequest = in.wipeRequest;

    // Verify, then IMMEDIATELY zeroize the plaintext regardless of result.
    bool ok = GateCrypto::verify(in.buf, in.len, cfg);
    memset(in.buf, 0, sizeof(in.buf));
    in.len = 0;

    if (ok) {
      if (isWipeRequest && !lowSupply) {
        // Authenticated, deliberate panic-wipe (SPEC §6). Correct password + explicit `wipe`.
        ESP_LOGW(TAG, "authenticated host wipe (correct password) -> REASON_HOST_WIPE");
        SelfDestruct::trigger(cfg, REASON_HOST_WIPE);
        return GATE_TRIGGERED;  // does not return in practice
      }
      if (isWipeRequest && lowSupply) {
        // Brownout-suppression (SPEC §13): even a correct, deliberate host-wipe must not run on a
        // sagging rail (risk of a half-completed erase). The password verified, so we BOOT normally
        // and reset the counter; the owner can re-issue the wipe on a healthy supply.
        ESP_LOGW(TAG, "low-supply boot: authenticated host wipe SUPPRESSED (booting instead; "
                      "re-issue on a healthy supply) — reliability-first (SPEC §13)");
      }
      // Correct password ALWAYS wins: reset the counter and boot. Never wipes.
      rt.reset();
      rt.commitAttempts();
      ESP_LOGI(TAG, "password correct -> GATE_PASS (attempt counter reset)");
      scrubConfigSecrets(cfg);  // RAM hygiene (SPEC §4.1)
      return GATE_PASS;
    }

    // Wrong attempt (including a `wipe` confirmed with the WRONG password — SPEC §6: a wrong wipe
    // password counts as a failed attempt). COMMIT the incremented counter to NVS *before* responding
    // so a power-cycle mid-attempt cannot rewind it (SPEC §4 sgate_rt.att_ct).
    if (rt.att_ct < 0xFF) {
      rt.att_ct += 1;
    }
    rt.commitAttempts();

    // SPEC §4.1 — the counter FAILS CLOSED. If commitAttempts() could not persist att_ct (NVS
    // read-only / full / encryption misconfig), we must NOT keep accepting unlimited guesses. Detect
    // a failed persist by re-reading the runtime namespace and comparing: if the on-flash value did
    // not advance to our in-RAM count, treat the counter as un-persistable, bound the in-RAM count to
    // max_att, and trigger anyway (fail-toward-policy) rather than degrade to unlimited attempts.
    GateRuntime persisted = GateRuntime::load();
    if (persisted.att_ct < rt.att_ct) {
      ESP_LOGE(TAG,
               "att_ct persist FAILED (flash=%u, ram=%u) -> fail-closed: bound to max_att %u and "
               "trigger REASON_ATTEMPTS",
               (unsigned)persisted.att_ct, (unsigned)rt.att_ct, (unsigned)cfg.max_att);
      rt.att_ct = cfg.max_att;  // bound the in-RAM count so we never grant another guess
    }

    // SPEC §4.1 / §6: att_ct == 0 NEVER triggers (no failed attempt => no wipe), regardless of
    // max_att. We only reach the trigger after at least one real wrong attempt (att_ct >= 1).
    if (rt.att_ct != 0 && rt.att_ct >= cfg.max_att) {
      if (lowSupply) {
        // Brownout-suppression (SPEC §13): a flaky rail must NEVER cause a wipe. We do NOT
        // SelfDestruct. Instead we LOCK and KEEP RE-PROMPTING forever — the CORRECT password (handled
        // at the top of this loop) is still the only way to boot, so there is no bypass. The persisted
        // att_ct stays at/above max_att, so a later boot on a HEALTHY supply will enforce the real
        // REASON_ATTEMPTS policy. We deliberately fall through to the re-prompt (no return, no
        // trigger) rather than halting hard, so a correct password can still rescue the boot.
        Input::notifyLocked(0);  // cosmetic — ONLY on the low-supply LOCK path, never before a wipe
        ESP_LOGW(TAG, "low-supply boot: max_att reached -> LOCK, re-prompting forever (NO wipe; "
                      "correct password still boots) — reliability-first (SPEC §13)");
        backoff(rt.att_ct);
        continue;  // re-prompt; never SelfDestruct on a low-supply boot
      }
      // Good supply: TRIGGER. Do NOT telegraph it — never signal an imminent wipe before the data is
      // gone (red-team; panicIndicate runs AFTER the destructive work in SelfDestruct::trigger).
      ESP_LOGW(TAG, "wrong-password count %u reached max_att %u -> REASON_ATTEMPTS",
               (unsigned)rt.att_ct, (unsigned)cfg.max_att);
      SelfDestruct::trigger(cfg, REASON_ATTEMPTS);
      return GATE_TRIGGERED;  // does not return in practice
    }

    uint8_t attemptsLeft = (rt.att_ct >= cfg.max_att) ? 0
                                                      : (uint8_t)(cfg.max_att - rt.att_ct);

    // Still attempts remaining: respond, pace, re-prompt. No host reset path on the armed loop.
    Input::notifyWrong(attemptsLeft);
    backoff(rt.att_ct);
  }
}

// ---------------------------------------------------------------------------------------------
// run — SPEC §6 steps 1-7. Called ONCE, early in setup() (FORK: after display_obj.RunSetup() and
// before settings_obj.begin(); see firmware/integration/INTEGRATION.md).
// ---------------------------------------------------------------------------------------------
GateResult BootGate::run() {
  // Step 1: load config from the `sgate` NVS namespace (and peek the `sgate_rt` tombstone).
  GateConfig cfg = GateConfig::load();

  // Low-supply state is needed by BOTH the resume decision and the armed flow, so read it once up
  // front. BROWNOUT-BYPASS FIX (SPEC §13): a low-supply/undervoltage boot must NEVER bypass the gate
  // or fire the irreversible path — it only SUPPRESSES / DEFERS destruction.
  const bool lowSupply = gateSupplyIsLow();
  if (lowSupply) {
    ESP_LOGW(TAG, "undervoltage/brownout boot: destruct SUPPRESSED/DEFERRED; password STILL required "
                  "where applicable (no bypass) — reliability-first (SPEC §13)");
  }

  // Step 1.5 (SPEC §8 robustness, red-team round 2): handle a wipe-in-progress tombstone. The
  // ordering FIX is the headline of this round: the tombstone is evaluated AGAINST the provisioned /
  // armed / low-supply gates, NOT before them. A DESTRUCTIVE resume runs ONLY when the board is still
  // provisioned AND armed AND not low-supply; otherwise it is residual cleanup (unprovisioned/
  // disarmed) or a defer (low-supply). resumeWipe() either does not return (real destructive resume),
  // returns GATE_HALTED (resume bound exhausted), or sets `proceed=true` to fall through to the
  // normal gate flow below after a cleanup/defer.
  if (cfg.resumeWipe) {
    bool proceed = false;
    GateResult rr = resumeWipe(cfg, lowSupply, proceed);
    if (!proceed) {
      return rr;  // GATE_TRIGGERED (real wipe; does not return in practice) or GATE_HALTED.
    }
    // proceed == true: cleanup/defer done. cfg may now be unprovisioned (cleanup erased residue) or
    // still provisioned+armed (low-supply defer). Fall through to the normal fail-safe gate flow.
  }

  // Step 2: FAIL-SAFE — an unprovisioned board behaves like plain Marauder and can never wipe.
  if (!cfg.provisioned) {
    ESP_LOGI(TAG, "unprovisioned -> GATE_PASS (cannot wipe)");
    return GATE_PASS;
  }

  // Step 4: MASTER DISARMED — destruct is physically impossible (kept as-is). The correct password
  // is cosmetic here; we simply skip the destruct-capable armed flow.
  if (cfg.armed == 0) {
    ESP_LOGI(TAG, "master DISARMED -> GATE_PASS (cannot wipe)");
    scrubConfigSecrets(cfg);  // RAM hygiene (SPEC §4.1)
    return GATE_PASS;
  }

  // Steps 5-7: master ARMED. armedFlow honors lowSupply to suppress (never bypass) destruction.
  // (On a low-supply DEFER above we kept the tombstone and require the password here; a genuine
  // interrupted wipe finishes on the next good-power boot via the destructive-resume branch.)
  return armedFlow(cfg, lowSupply);
}

// ---------------------------------------------------------------------------------------------
// resumeWipe — SPEC §8 (red-team round 2). Decide what to do about a wipe-in-progress tombstone.
//
// THE FIX: a set tombstone may trigger a DESTRUCTIVE resume ONLY when the board is still provisioned
// AND armed==1 AND NOT low-supply. This preserves real interrupted-wipe resume (a genuine wipe is
// always armed+provisioned and erases guardcfg LAST, so an interrupted wipe still reads armed) while
// closing the force-wipe-over-disarmed DoS (a hand-written wipe_armed=1 can no longer force a wipe on
// a disarmed/unprovisioned board) and the brownout-resume regression.
//
//   * UNPROVISIONED or MASTER-DISARMED -> CLEANUP only: the board can never wipe (hard invariant), so
//     clear the tombstone + erase guardcfg residue and PROCEED to the normal gate flow (GATE_PASS).
//     NEVER SelfDestruct.
//   * LOW-SUPPLY -> DEFER: keep the tombstone, do not wipe this boot, PROCEED so the password gates
//     the boot. The real wipe finishes on the next good-power boot (reliability-first, SPEC §13).
//   * PROVISIONED + ARMED + good supply -> DESTRUCTIVE resume, BOUNDED by MAX_WIPE_RESUMES: after the
//     bound is exhausted, stop re-triggering and enter the visibly-locked halt (GATE_HALTED) instead
//     of an endless resume / premature-brick loop. The resume counter is persisted BEFORE the erase.
//
// `proceed` is set true ONLY for the cleanup/defer paths (caller falls through to the normal flow).
// ---------------------------------------------------------------------------------------------
GateResult BootGate::resumeWipe(GateConfig& cfg, bool lowSupply, bool& proceed) {
  proceed = false;

  // CLEANUP path: an unprovisioned or master-disarmed board can NEVER wipe. A tombstone here is
  // residue (foreign/aborted state), not a genuine interrupted wipe. Clear it (+ erase guardcfg
  // residue) and continue to GATE_PASS. NEVER SelfDestruct.
  if (!cfg.provisioned || cfg.armed == 0) {
    ESP_LOGW(TAG, "wipe tombstone on %s board -> residual CLEANUP only (NO wipe); clearing tombstone "
                  "+ guardcfg residue, continuing to gate flow (SPEC §8/§6)",
             cfg.provisioned ? "master-DISARMED" : "UNPROVISIONED");
    GateRuntime rt = GateRuntime::load();
    rt.cleanupResidualTombstone();  // clears wipe_armed + resume_count + erases sgate residue
    cfg.resumeWipe = false;
    // The cleanup may have erased the `sgate` config residue; reflect that the board is now
    // unprovisioned so the fall-through flow PASSes cleanly. (If it was master-disarmed+provisioned,
    // the disarmed branch still PASSes either way.)
    if (!cfg.provisioned) {
      scrubConfigSecrets(cfg);
    }
    cfg.provisioned = false;
    proceed = true;
    return GATE_PASS;  // value unused by caller when proceed==true
  }

  // DEFER path: low-supply boot on a provisioned+armed board. A flaky rail must NEVER initiate or
  // resume an irreversible wipe (reliability-first, SPEC §13). KEEP the tombstone; require the
  // password to boot normally. A real interrupted wipe finishes on the next good-power boot.
  if (lowSupply) {
    ESP_LOGW(TAG, "wipe tombstone on ARMED board but LOW-SUPPLY boot -> DEFER resume (keep tombstone, "
                  "NO wipe this boot; password required to boot) — reliability-first (SPEC §13)");
    proceed = true;
    return GATE_PASS;  // value unused by caller when proceed==true
  }

  // DESTRUCTIVE resume path: provisioned + armed + good supply. This is the genuine interrupted-wipe
  // case. BOUND the number of resumes so a stuck/hostile condition cannot spin forever.
  GateRuntime rt = GateRuntime::load();
  if (rt.resume_count >= MAX_WIPE_RESUMES) {
    ESP_LOGE(TAG, "wipe resume bound exhausted (resume_count=%u >= %u) -> GATE_HALTED "
                  "(visibly locked; NO further erase) (SPEC §8)",
             (unsigned)rt.resume_count, (unsigned)MAX_WIPE_RESUMES);
    return haltLocked("wipe resume bound exhausted");  // does not return
  }

  // Increment + PERSIST the bound BEFORE the erase so an interrupted resume still advances the count
  // (no infinite resume loop across power cycles).
  if (rt.resume_count < 0xFF) {
    rt.resume_count += 1;
  }
  rt.commitResumeCount();

  ESP_LOGW(TAG, "wipe tombstone set on provisioned+ARMED board (good supply) -> RESUMING interrupted "
                "self-destruct (resume %u/%u) (SPEC §8). Will not PASS over residual data.",
           (unsigned)rt.resume_count, (unsigned)MAX_WIPE_RESUMES);
  SelfDestruct::trigger(cfg, REASON_ATTEMPTS);
  return GATE_TRIGGERED;  // does not return in practice on a real wipe
}

// ---------------------------------------------------------------------------------------------
// haltLocked — distinct, visibly-locked terminal halt (GATE_HALTED). Does NOT erase and never hands
// control back to Marauder. Used when the DESTRUCTIVE-resume bound is exhausted (SPEC §8): we must
// not loop forever re-triggering the wipe, nor PASS over residual data, nor prematurely brick. Under
// SUICIDE_SAFE_MODE this still just halts (it performs ZERO erases either way — it is purely a
// refuse-to-boot state).
// ---------------------------------------------------------------------------------------------
GateResult BootGate::haltLocked(const char* why) {
  ESP_LOGE(TAG, "GATE_HALTED: %s — refusing to boot (visibly locked; no erase)", why ? why : "");
  Input::notifyLocked(0xFFFFFFFFu);  // cosmetic: indicate a terminal lock (best-effort)
  for (;;) {
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
    delay(60000);
#else
    delay(1000);
#endif
  }
}

}  // namespace suicide
