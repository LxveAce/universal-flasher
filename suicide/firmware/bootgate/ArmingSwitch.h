// ArmingSwitch.h — read the hardware dead-man / arming line at boot.
//
// docs/SPEC.md §7. FAIL-SAFE WIRING: the switch in its ARMED position drives the pin to
// cfg.arm_level; the pin idles to the opposite via cfg.arm_pull, so a CUT / UNPLUGGED / FLOATING
// wire reads NOT_ARMED. Combined with the master `armed` flag this gives two-factor safety:
// a fresh/disarmed board cannot wipe, but an ARMED board treats switch removal as a dead-man trip.
//
// Reads occur once, early in setup(), after a short settle, sampled multiple times and required
// unanimous to reject transients. Low-battery/undervoltage boot is treated as DISARMED upstream
// (reliability-first; SPEC §13) — ArmingSwitch only reports the raw line state.
#pragma once

#include "GateConfig.h"

namespace suicide {

enum ArmState { NOT_ARMED = 0, ARMED = 1 };

class ArmingSwitch {
 public:
  static constexpr uint8_t  SAMPLES     = 8;    // unanimous required
  static constexpr uint16_t SETTLE_MS   = 10;   // let the pin/pull settle before sampling
  static constexpr uint16_t SAMPLE_GAP_MS = 2;

  // Configure the pin per cfg (mode incl. input-only pins needing external pulldown), settle,
  // sample SAMPLES times, and return ARMED only if every sample equals cfg.arm_level.
  static ArmState read(const GateConfig& cfg);

  // True if the configured pin is input-only (GPIO34-39 on classic ESP32) and therefore needs an
  // external pulldown — the host provisioner should warn; arm_pull is a no-op in HW there.
  static bool pinIsInputOnly(uint8_t pin);
};

} // namespace suicide
