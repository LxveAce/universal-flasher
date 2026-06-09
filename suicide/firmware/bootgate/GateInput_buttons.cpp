// GateInput_buttons.cpp — M5StickC button-combo "code" entry.
//
// Compiles ONLY under GATE_INPUT_BUTTONS (SPEC §5). Target: M5StickC / Plus / Plus2.
//
// ============================== WEAK INPUT — READ THIS ======================================
// This adapter is the WEAKEST of all input classes and is a LAST RESORT. The original StickC
// exposes only 2 usable buttons (SEL_BTN=GPIO37, DW_BTN=GPIO39); the Plus2 adds a third (UP_BTN=
// GPIO35). GPIO37/39 are input-only (fine for buttons). There is NO on-screen grid keyboard on
// StickC (HAS_MINI_KB is not defined for these builds — RESEARCH-DIGEST confirmed). A real
// passphrase is therefore impractical: the "secret" here is a short button SEQUENCE, which has low
// entropy.
//
// PREFER HOST-ASSISTED: for a real password on a StickC, build with GATE_INPUT_SERIAL instead and
// type `unlock <pw>` over USB. Use this button adapter only when truly headless+host-less and you
// accept the low entropy. SAFETY.md / THREAT-MODEL.md cover the consequences.
// ============================================================================================
//
// ENCODING: each button maps to a symbol; the operator presses a sequence terminated by a long-hold
// on the SELECT button (or a timeout). The symbol stream becomes the "password" bytes handed to
// GateCrypto — i.e. the host provisioner must hash the SAME symbol string (e.g. "AABCA"). This keeps
// the device side identical to every other adapter (it just produces a char[] secret).
//
//   SEL (GPIO37) short press   -> 'A'
//   DW  (GPIO39) short press   -> 'B'
//   UP  (GPIO35, Plus2 only)   -> 'C'
//   SEL long-hold (>= kSubmitHoldMs) -> SUBMIT the accumulated sequence
//
// SECURITY: the symbol scratch is zeroized before return; nothing is echoed in clear. Caller
// zeroizes InputResult.buf after verify.
#ifdef GATE_INPUT_BUTTONS

#include "GateInput.h"
#include <Arduino.h>
#include <string.h>

namespace suicide {

namespace {

// Button GPIOs (RESEARCH-DIGEST: M5StickC SEL_BTN=37, DW_BTN=39; Plus2 UP_BTN=35). These are the
// physical buttons wired active-LOW with the panel's pull-ups. Override via -D if a revision differs.
#ifndef STICKC_SEL_BTN
#define STICKC_SEL_BTN 37
#endif
#ifndef STICKC_DW_BTN
#define STICKC_DW_BTN 39
#endif
#ifndef STICKC_UP_BTN          // Plus2 only; set to -1 on the original StickC (2-button) builds
#define STICKC_UP_BTN 35
#endif

constexpr uint32_t kPollGapMs     = 10;
constexpr uint32_t kDebounceMs    = 30;
constexpr uint32_t kSubmitHoldMs  = 1200;   // SEL held this long = submit
constexpr uint32_t kIdleTimeoutMs = 120000; // no press for 2 min -> transient, re-prompt
constexpr size_t   kMaxSymbols    = 32;     // sequence length cap (< char[64] room)

void secureZero(void* p, size_t n) {
  volatile uint8_t* v = reinterpret_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}

inline bool pressed(uint8_t pin) {
  // Active-LOW buttons: pressed reads LOW.
  return digitalRead(pin) == LOW;
}

}  // namespace

void Input::begin(const GateConfig& /*cfg*/) {
  pinMode(STICKC_SEL_BTN, INPUT_PULLUP);
  pinMode(STICKC_DW_BTN, INPUT_PULLUP);
#if STICKC_UP_BTN >= 0
  pinMode(STICKC_UP_BTN, INPUT);   // GPIO35 input-only; panel provides the pull. No internal pullup.
#endif
  Serial.println(F("suicide-gate: button-combo entry (WEAK). SEL=A DW=B"
#if STICKC_UP_BTN >= 0
                   " UP=C"
#endif
                   ", hold SEL to submit."));
}

InputResult Input::getPassword(const GateConfig& /*cfg*/) {
  InputResult r;
  char scratch[kMaxSymbols + 1] = {0};
  size_t n = 0;
  uint32_t lastActivity = millis();

  for (;;) {
    if (millis() - lastActivity > kIdleTimeoutMs) {  // idle -> transient, no attempt counted
      secureZero(scratch, sizeof(scratch));
      return r;
    }

    // ---- SELECT: short press = 'A'; long-hold = submit ----
    if (pressed(STICKC_SEL_BTN)) {
      uint32_t down = millis();
      delay(kDebounceMs);
      bool submitted = false;
      while (pressed(STICKC_SEL_BTN)) {
        if (millis() - down >= kSubmitHoldMs) { submitted = true; break; }
        delay(kPollGapMs);
      }
      lastActivity = millis();
      if (submitted) {
        // Wait for release so the hold isn't re-read, then submit the sequence.
        while (pressed(STICKC_SEL_BTN)) delay(kPollGapMs);
        scratch[n] = '\0';
        if (n == 0) {                 // empty sequence -> transient, not a wrong attempt
          secureZero(scratch, sizeof(scratch));
          return r;
        }
        memcpy(r.buf, scratch, n);
        r.buf[n] = '\0';
        r.len = n;
        r.got = true;
        secureZero(scratch, sizeof(scratch));
        return r;
      }
      if (n < kMaxSymbols) scratch[n++] = 'A';
      continue;
    }

    // ---- DOWN: 'B' ----
    if (pressed(STICKC_DW_BTN)) {
      delay(kDebounceMs);
      while (pressed(STICKC_DW_BTN)) delay(kPollGapMs);
      lastActivity = millis();
      if (n < kMaxSymbols) scratch[n++] = 'B';
      continue;
    }

#if STICKC_UP_BTN >= 0
    // ---- UP (Plus2): 'C' ----
    if (pressed(STICKC_UP_BTN)) {
      delay(kDebounceMs);
      while (pressed(STICKC_UP_BTN)) delay(kPollGapMs);
      lastActivity = millis();
      if (n < kMaxSymbols) scratch[n++] = 'C';
      continue;
    }
#endif

    delay(kPollGapMs);
  }
}

void Input::notifyWrong(uint8_t attemptsLeft) {
  Serial.print(F("suicide-gate: wrong, attempts left "));
  Serial.println(attemptsLeft);
}

void Input::notifyLocked(uint32_t seconds) {
  Serial.print(F("suicide-gate: locked "));
  Serial.print(seconds);
  Serial.println(F("s"));
}

}  // namespace suicide

#endif  // GATE_INPUT_BUTTONS
