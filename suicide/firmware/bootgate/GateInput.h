// GateInput.h — board-agnostic password/secret entry for the boot-gate. docs/SPEC.md §5, §6.
//
// Owner-only, defensive anti-forensic layer. This module is ONLY an input transport: it collects
// the operator's entered secret (or an explicit host wipe command) and hands it back to BootGate.
// It performs NO verification and makes NO destruct decision — GateCrypto::verify() and the
// BootGate state machine own all of that. Keeping input dumb is deliberate: a board adapter must
// never be able to bypass the master-armed / provisioned invariants.
//
// SECURITY RULES (enforced by every adapter):
//   * The plaintext secret is NEVER echoed in clear on a serial console or any log. Touch/keyboard
//     adapters mask on-screen; serial adapters do not echo characters and never print the password.
//   * `InputResult.buf` is char[64]; the CALLER (BootGate) zeroizes it after use. Adapters must also
//     wipe any internal scratch copy before returning.
//   * No adapter stores the secret anywhere persistent. No CLI argument ever carries a password
//     (SPEC §4, §10): on serial, `unlock <pw>` is typed interactively, not passed on a flash cmdline.
//
// COMPILE-TIME SELECTION — exactly ONE GATE_INPUT_* flag per build (SPEC §5). The flags mirror
// Marauder's own hardware defines so the right native widget is reused:
//
//   | Build flag            | Adapter file              | Reuses Marauder driver        | Board class            |
//   |-----------------------|---------------------------|-------------------------------|------------------------|
//   | GATE_INPUT_SERIAL     | GateInput_serial.cpp      | Serial CLI (getSerialInput)   | headless / any (default)|
//   | GATE_INPUT_TOUCH      | GateInput_touch.cpp       | TouchKeyboard::keyboardInput  | CYD / v6 / v7 / v8     |
//   | GATE_INPUT_MINI_KB    | GateInput_mini.cpp        | miniKeyboard(..., do_pass)    | Marauder Mini (joystick)|
//   | GATE_INPUT_CARDPUTER  | GateInput_cardputer.cpp   | Cardputer QWERTY key matrix   | M5Cardputer (S3)       |
//   | GATE_INPUT_BUTTONS    | GateInput_buttons.cpp     | M5StickC buttons (WEAK)       | M5StickC / Plus / Plus2|
//
// If NO flag is set the build defaults to GATE_INPUT_SERIAL (see the guard at the bottom of this
// file). If MORE THAN ONE is set the build fails with a #error (see same guard). The serial adapter
// is the universal fallback and is also the only one that understands the host-assisted
// `unlock <pw>` / `wipe` protocol (SPEC §5): a `wipe` line sets InputResult.wipeRequest=true, which
// BootGate maps to REASON_HOST_WIPE.
#pragma once

#include <Arduino.h>
#include <stddef.h>
#include "GateConfig.h"

namespace suicide {

// Result of one password-entry interaction.
//   got         : true if a complete secret (or wipe command) was captured this call.
//   buf/len     : the entered secret (NOT NUL-terminated reliance — use len). char[64] per SPEC.
//                 Caller (BootGate) zeroizes buf after GateCrypto::verify().
//   wipeRequest : true only for the serial `wipe` command -> BootGate triggers REASON_HOST_WIPE.
//                 When wipeRequest is true, buf/len carry no password and got is true.
struct InputResult {
  bool   got = false;
  char   buf[64] = {0};
  size_t len = 0;
  bool   wipeRequest = false;
};

class Input {
 public:
  // One-time init of the underlying driver (open Serial, init touch panel, set up key matrix,
  // configure button GPIOs). Safe to call once early in setup(); idempotent within a boot.
  static void begin(const GateConfig& cfg);

  // Block (with internal pacing / timeouts) until the operator supplies a secret or, on serial,
  // an `unlock <pw>` / `wipe` command. Returns InputResult.got=false only on a transient
  // cancel/timeout so BootGate can re-prompt without counting an attempt. The returned buf must be
  // zeroized by the caller. Adapters MUST NOT echo the secret in clear.
  static InputResult getPassword(const GateConfig& cfg);

  // Feedback hooks (no secret material). Implementations keep these short and non-blocking-ish.
  static void notifyWrong(uint8_t attemptsLeft);   // wrong password; attempts remaining before wipe
  static void notifyLocked(uint32_t seconds);       // backoff lockout (disarmed mode) in seconds
};

}  // namespace suicide

// ---- exactly-one-of selection guard (SPEC §5) ----
// Default to the universal headless serial adapter when nothing is specified.
#if !defined(GATE_INPUT_SERIAL) && !defined(GATE_INPUT_TOUCH) &&                                   \
    !defined(GATE_INPUT_MINI_KB) && !defined(GATE_INPUT_CARDPUTER) && !defined(GATE_INPUT_BUTTONS)
#define GATE_INPUT_SERIAL 1
#endif

// Reject ambiguous builds: more than one input class selected.
#if (defined(GATE_INPUT_SERIAL) + defined(GATE_INPUT_TOUCH) + defined(GATE_INPUT_MINI_KB) +        \
     defined(GATE_INPUT_CARDPUTER) + defined(GATE_INPUT_BUTTONS)) > 1
#error "Suicide Marauder: select exactly ONE GATE_INPUT_* flag (SPEC §5)."
#endif
