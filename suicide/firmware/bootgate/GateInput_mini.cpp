// GateInput_mini.cpp — Marauder Mini 5-way joystick passphrase entry.
//
// Compiles ONLY under GATE_INPUT_MINI_KB (SPEC §5). Target: Marauder Mini (also V7, Mini_V3, Rev
// Feather, Cardputer/ADV, M5StickC define HAS_MINI_KB — RESEARCH-DIGEST confirmed against configs.h).
// This is a "full on-device gate": the operator scrolls the on-screen grid keyboard with the
// joystick (L=GPIO13, C=GPIO34, U=GPIO36, R=GPIO39, D=GPIO35) and selects with center, entering a
// full passphrase. No host required.
//
// REUSE: Marauder ships the grid keyboard with a built-in hidden-entry mode (RESEARCH-DIGEST,
// confirmed in MenuFunctions.h):
//     String miniKeyboard(Menu * targetMenu, bool do_pass = false);
//   `do_pass = true` masks the entry as a password — invoked verbatim in the firmware as
//   `this->miniKeyboard(&miniKbMenu, true)`. We reuse exactly that path so masking is inherited.
//
// SECURITY: the returned String is copied into InputResult.buf (char[64]), then the String's heap
// buffer is overwritten and cleared before it goes out of scope. We never print the secret.
#ifdef GATE_INPUT_MINI_KB

#include "GateInput.h"
#include <Arduino.h>
#include <string.h>

// Marauder's menu/keyboard surface. In the FORK build this resolves to the firmware's MenuFunctions
// header which declares miniKeyboard + the Menu type + the global menu instance. If a revision
// renames the instance, adjust ONLY the shim at the bottom (INTEGRATION.md).
#include "MenuFunctions.h"

namespace suicide {

namespace {

void secureZero(void* p, size_t n) {
  volatile uint8_t* v = reinterpret_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}

// Overwrite a String's characters in place then clear it, so the secret does not linger on the heap.
void wipeString(String& s) {
  for (size_t i = 0; i < s.length(); ++i) s.setCharAt(i, '\0');
  s = "";
}

// Bridges to Marauder's grid keyboard in password mode. Defined in the shim below.
String miniPasswordEntry();

}  // namespace

void Input::begin(const GateConfig& /*cfg*/) {
  // Display + joystick GPIOs are initialized by Marauder's display_obj.RunSetup() which the FORK
  // hook runs BEFORE BootGate::run() (SPEC §1). Nothing extra to init here.
}

InputResult Input::getPassword(const GateConfig& /*cfg*/) {
  InputResult r;

  String entry = miniPasswordEntry();   // do_pass=true; masked on-screen
  size_t slen = entry.length();
  if (slen == 0) {                       // cancelled/empty -> transient, re-prompt, no attempt
    wipeString(entry);
    return r;
  }
  if (slen > sizeof(r.buf) - 1) slen = sizeof(r.buf) - 1;  // clamp to char[64]
  memcpy(r.buf, entry.c_str(), slen);
  r.buf[slen] = '\0';
  r.len = slen;
  r.got = true;

  wipeString(entry);                     // scrub heap copy; caller zeroizes r.buf after verify
  return r;
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

// ---- integration shim ----------------------------------------------------------------------
// Calls Marauder's global menu object's miniKeyboard(..., do_pass=true). The grid keyboard needs a
// target Menu; Marauder uses an internal `miniKbMenu`. The FORK integration wires the real instance;
// SUICIDE_HAVE_MENU_OBJ gates that so this file stays buildable in isolation/dev.
namespace {
String miniPasswordEntry() {
#if defined(SUICIDE_HAVE_MENU_OBJ)
  extern MenuFunctions menu_function_obj;   // Marauder global (name confirmed at integration time)
  extern Menu miniKbMenu;                    // Marauder's keyboard target menu
  return menu_function_obj.miniKeyboard(&miniKbMenu, /*do_pass=*/true);
#else
  // Isolated/dev fallback: returns empty so getPassword reports a transient (no secret leaks).
  return String("");
#endif
}
}  // namespace

}  // namespace suicide

#endif  // GATE_INPUT_MINI_KB
