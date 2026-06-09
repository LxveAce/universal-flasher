// ArmingSwitch.cpp — read the hardware dead-man / arming line at boot. docs/SPEC.md §7.
//
// FAIL-SAFE WIRING (load-bearing, RESEARCH-DIGEST §arming): the switch in its ARMED position drives
// the pin to cfg.arm_level (default HIGH = 3.3V through the intact switch); the pin idles to the
// OPPOSITE level via cfg.arm_pull (default INPUT_PULLDOWN), so a CUT / UNPLUGGED / FLOATING / CORRODED
// wire reads NOT_ARMED. Combined with the master `armed` flag this is two-factor safety.
//
// We are NOT on a strapping pin (SPEC §7 forbids those), so unlike the bootloader sampling window
// we can take our time in setup(): configure the pin, wait SETTLE_MS for the line + pull to settle,
// then sample SAMPLES times. ARMED is returned ONLY if every sample equals cfg.arm_level — any
// single ambiguous/disarmed read collapses to NOT_ARMED (fail-toward-locked/wipe).
//
// Input-only pins (classic ESP32 GPIO34-39) have NO internal pull-up/pull-down: pinMode(...PULLDOWN)
// is a silent no-op there, so the wiring MUST supply an external 10k pull-down. pinIsInputOnly()
// flags this so the host provisioner can warn; here we simply configure plain INPUT on those pins
// and rely on the external resistor (a missing external pull => floating => indeterminate, which the
// unanimous-sample rule will reject, again failing toward NOT_ARMED).

#include "ArmingSwitch.h"

#include <Arduino.h>

namespace suicide {

bool ArmingSwitch::pinIsInputOnly(uint8_t pin) {
  // Classic ESP32: GPIO34, 35, 36 (VP), 39 (VN) — and the full 34..39 band — are input-only and
  // lack internal pulls (RESEARCH-DIGEST: "GPIOs 34 to 39 are GPIs – input only pins"). On S3/C3
  // there is no equivalent input-only band in the safe arming range, so this classic-ESP32 check is
  // the conservative superset; it is harmless on other targets because their default arm_pin is not
  // in 34..39.
#if defined(CONFIG_IDF_TARGET_ESP32) || \
    (!defined(CONFIG_IDF_TARGET_ESP32S2) && !defined(CONFIG_IDF_TARGET_ESP32S3) && \
     !defined(CONFIG_IDF_TARGET_ESP32C3) && !defined(CONFIG_IDF_TARGET_ESP32C6) && \
     !defined(CONFIG_IDF_TARGET_ESP32H2))
  return (pin >= 34 && pin <= 39);
#else
  // Other targets: no input-only pin is used for arming by default (SPEC §7 maps S3->G2, C3->GPIO10).
  (void)pin;
  return false;
#endif
}

ArmState ArmingSwitch::read(const GateConfig& cfg) {
  const uint8_t pin = cfg.arm_pin;
  // The pin level that MEANS armed (1 => HIGH, 0 => LOW). Anything else is treated as HIGH-armed
  // (the SPEC default) so a corrupt value can't silently invert the dead-man sense.
  const int armedReading = (cfg.arm_level == 0) ? LOW : HIGH;

  // ---- configure the pin per cfg, with the fail-safe pull pointing AWAY from "armed" ----
  if (pinIsInputOnly(pin)) {
    // No internal pulls available; external 10k pull-down (or pull-up for an inverted scheme) MUST
    // be present in hardware. Configure as a plain input and trust the external resistor.
    pinMode(pin, INPUT);
  } else {
    switch (cfg.arm_pull) {
      case 1:  // pullup  — idles HIGH; use only with an active-LOW-armed wiring
        pinMode(pin, INPUT_PULLUP);
        break;
      case 2:  // pulldown — idles LOW; the SPEC default for active-HIGH-armed fail-safe
        pinMode(pin, INPUT_PULLDOWN);
        break;
      case 0:  // none — external resistor expected; treat like a bare input
      default:
        pinMode(pin, INPUT);
        break;
    }
  }

  // Let the line and the (internal or external) pull settle before the first sample. Mechanical /
  // reed switches also bounce; the unanimous multi-sample window below covers short bounce.
  delay(SETTLE_MS);

  // ---- sample SAMPLES times; require EVERY sample to equal the armed level ----
  for (uint8_t i = 0; i < SAMPLES; ++i) {
    int v = digitalRead(pin);
    if (v != armedReading) {
      // A single non-armed (or ambiguous) read is terminal: fail toward NOT_ARMED.
      return NOT_ARMED;
    }
    if (i + 1 < SAMPLES) {
      delay(SAMPLE_GAP_MS);
    }
  }

  // Every one of the SAMPLES reads matched the armed level — the switch is confidently in its armed
  // position.
  return ARMED;
}

}  // namespace suicide
