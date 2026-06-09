// GateInput_cardputer.cpp — M5Cardputer native QWERTY passphrase entry.
//
// Compiles ONLY under GATE_INPUT_CARDPUTER (SPEC §5). Target: M5Cardputer (StampS3 / ESP32-S3).
// This is the STRONGEST standalone gate: a real, arbitrary-length alphanumeric passphrase typed on
// the physical QWERTY (RESEARCH-DIGEST: confirmed — Marauder reads the full Cardputer key matrix;
// original Cardputer scans a 74HC138 demux matrix, Cardputer ADV offloads to a TCA8418 over I2C).
// No host required.
//
// REUSE: Marauder reads the Cardputer keyboard via M5Cardputer's keyboard API and its own helper
// `isKeyPressed(c)` (RESEARCH-DIGEST: verbatim `isKeyPressed(';')`=up, `('.')`=down, `('(')`=select
// in MenuFunctions.cpp). For free-text entry we read the M5Cardputer Keyboard state directly
// (Enter=submit, Backspace=delete) so any printable key is captured — not just the nav subset.
//
// SECURITY: characters are accumulated into a local scratch (char[64]), NOT echoed in clear (the
// on-screen field shows masked '*'); the scratch is zeroized before return. Caller zeroizes
// InputResult.buf after verify.
#ifdef GATE_INPUT_CARDPUTER

#include "GateInput.h"
#include <Arduino.h>
#include <string.h>

// M5Cardputer keyboard API (bundled with the Cardputer board support Marauder already depends on).
#include <M5Cardputer.h>

namespace suicide {

namespace {

constexpr uint32_t kPollGapMs    = 15;     // debounce-friendly poll cadence
constexpr uint32_t kIdleTimeoutMs = 120000; // 2 min idle -> transient, re-prompt without an attempt

void secureZero(void* p, size_t n) {
  volatile uint8_t* v = reinterpret_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}

}  // namespace

void Input::begin(const GateConfig& /*cfg*/) {
  // Display is set up by Marauder's display_obj.RunSetup() before BootGate::run() (SPEC §1). Ensure
  // the keyboard scanner is live; M5Cardputer.begin() is idempotent for our purposes.
  auto cfg = M5.config();
  M5Cardputer.begin(cfg, /*enableKeyboard=*/true);
}

InputResult Input::getPassword(const GateConfig& /*cfg*/) {
  InputResult r;
  char scratch[64] = {0};
  size_t n = 0;

  uint32_t lastActivity = millis();
  for (;;) {
    if (millis() - lastActivity > kIdleTimeoutMs) {  // idle -> transient, no attempt counted
      secureZero(scratch, sizeof(scratch));
      return r;
    }

    M5Cardputer.update();
    if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
      lastActivity = millis();
      Keyboard_Class::KeysState st = M5Cardputer.Keyboard.keysState();

      // Submit on Enter.
      if (st.enter) {
        scratch[n] = '\0';
        if (n == 0) {                 // empty submit -> transient
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

      // Backspace edits the in-RAM secret (so a typo never becomes a wrong attempt). No echo.
      if (st.del) {
        if (n > 0) n--;
        continue;
      }

      // Append every printable key the matrix reports (full alphanumeric, not just nav keys).
      for (char c : st.word) {
        if (c >= 0x20 && c < 0x7F && n < sizeof(scratch) - 1) {
          scratch[n++] = c;
        }
      }
    }
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

#endif  // GATE_INPUT_CARDPUTER
