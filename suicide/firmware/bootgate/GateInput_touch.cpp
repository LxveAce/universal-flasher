// GateInput_touch.cpp — on-screen PIN/passphrase entry for touchscreen Marauder boards.
//
// Compiles ONLY under GATE_INPUT_TOUCH (SPEC §5). Target boards: CYD 2.4-3.5", Marauder v6/v7/v8 —
// all define HAS_TOUCH (RESEARCH-DIGEST: confirmed against configs.h; the per-board flag list there
// was corrected — V6/CYD use HAS_TOUCH, not HAS_MINI_KB). This is a "full on-device gate": no host
// is required.
//
// REUSE: Marauder already ships a free-text touch keyboard widget used for SSID/Wi-Fi-password
// entry (RESEARCH-DIGEST, confirmed in TouchKeyboard.h):
//     bool keyboardInput(char *buffer, size_t bufLen, const char *title = nullptr);
//   returning KB_DONE / KB_CANCEL. We call it directly so the password prompt is just reuse and the
//   on-screen rendering already masks/handles input. The widget owns echo masking on-screen; we
//   never print the secret to serial.
//
// SECURITY: buffer is filled by the widget, copied into InputResult.buf (char[64]), then the local
// scratch is zeroized. Caller zeroizes InputResult.buf after verify.
#ifdef GATE_INPUT_TOUCH

#include "GateInput.h"
#include <Arduino.h>
#include <string.h>

// Marauder's touch keyboard. In the FORK build this resolves to the firmware's own header; the
// object name mirrors Marauder's global instance. If the upstream type/instance names differ in a
// given Marauder revision, adjust ONLY this include + the call site below (integration shim).
#include "TouchKeyboard.h"

namespace suicide {

namespace {

constexpr const char* kTitle = "Unlock";

// KB_DONE / KB_CANCEL come from Marauder's TouchKeyboard enum. Guard in case a revision renames
// them so this file still expresses intent without a hard build break in SAFE/dev contexts.
#ifndef KB_DONE
#define KB_DONE 1
#endif

void secureZero(void* p, size_t n) {
  volatile uint8_t* v = reinterpret_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}

// Marauder exposes the touch keyboard as a global (commonly `touch_keyboard_obj`). The FORK
// integration step wires this to the real instance; we reference it weakly through a small helper
// so the dependency is in one place. See firmware/integration/INTEGRATION.md.
extern bool touchKeyboardInput(char* buffer, size_t bufLen, const char* title);

}  // namespace

void Input::begin(const GateConfig& /*cfg*/) {
  // Display + touch panel are already initialized by Marauder's display_obj.RunSetup() which the
  // FORK hook runs BEFORE BootGate::run() (SPEC §1). Nothing extra to init here.
}

InputResult Input::getPassword(const GateConfig& /*cfg*/) {
  InputResult r;
  char scratch[64] = {0};

  bool done = touchKeyboardInput(scratch, sizeof(scratch), kTitle);
  if (!done) {                         // KB_CANCEL / dismissed -> transient, re-prompt, no attempt
    secureZero(scratch, sizeof(scratch));
    return r;
  }

  size_t slen = strnlen(scratch, sizeof(scratch) - 1);
  if (slen == 0) {                      // empty entry -> transient, not a wrong attempt
    secureZero(scratch, sizeof(scratch));
    return r;
  }
  memcpy(r.buf, scratch, slen);
  r.buf[slen] = '\0';
  r.len = slen;
  r.got = true;

  secureZero(scratch, sizeof(scratch));
  return r;
}

void Input::notifyWrong(uint8_t attemptsLeft) {
  // Keep feedback on the existing display via serial fallback; the touch widget will redraw on the
  // next getPassword(). We avoid leaking the armed state — only the remaining-attempts count shows.
  Serial.print(F("suicide-gate: wrong, attempts left "));
  Serial.println(attemptsLeft);
}

void Input::notifyLocked(uint32_t seconds) {
  Serial.print(F("suicide-gate: locked "));
  Serial.print(seconds);
  Serial.println(F("s"));
}

// ---- integration shim ----------------------------------------------------------------------
// Default weak binding to Marauder's global touch keyboard. The FORK integration overrides this in
// one place (INTEGRATION.md) if the upstream instance/method names differ. Under SAFE_MODE/dev this
// keeps the unit buildable in isolation.
namespace {
bool touchKeyboardInput(char* buffer, size_t bufLen, const char* title) {
#if defined(SUICIDE_HAVE_TOUCH_KEYBOARD_OBJ)
  // Marauder exposes a FREE function `keyboardInput(char*, size_t, const char*)` (TouchKeyboard.h)
  // that draws the on-screen masked keypad and returns true when the user finishes entry (KB_DONE),
  // false on cancel/dismiss. VERIFIED against justcallmekoko/ESP32Marauder (TouchKeyboard.h:29 and
  // the SSID/password call sites in esp32_marauder.ino / MenuFunctions.cpp). It is NOT a method on a
  // global instance — an earlier revision of this shim wrongly assumed a `touch_keyboard_obj`.
  return ::keyboardInput(buffer, bufLen, title);
#else
  #error "GATE_INPUT_TOUCH requires SUICIDE_HAVE_TOUCH_KEYBOARD_OBJ + Marauder's keyboardInput() (TouchKeyboard.h); see INTEGRATION.md"
#endif
}
}  // namespace

}  // namespace suicide

#endif  // GATE_INPUT_TOUCH
