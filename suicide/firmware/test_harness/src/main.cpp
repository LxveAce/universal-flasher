// SAFE_MODE hardware test harness for the Suicide Marauder boot gate.
//
// Links the REAL firmware/bootgate/* units (serial input adapter) + a stub "Marauder", built with
// -DSUICIDE_SAFE_MODE so the SelfDestruct path performs ZERO real erases — it only logs what it
// *would* do, against the dedicated `scratch` partition. Nothing on the board is ever destroyed.
//
// This is the harness used in docs/HARDWARE-TEST.md (validated on a classic ESP32-D0WD / 4 MB).
// Build it with scripts/build_test_harness.ps1 (or .sh), which copies the bootgate sources next to
// this file and runs PlatformIO. Then drive the gate over USB serial @115200:
//   * unprovisioned board  -> GATE_PASS immediately (cannot wipe)
//   * provisioned + armed   -> password loop; correct -> PASS; wrong x max_att -> SAFE simulated wipe
//
// Provision a guardcfg with host/provision.py and flash it (see docs/PROVISIONING.md / HARDWARE-TEST.md).

#include <Arduino.h>
#include "GateConfig.h"
#include "BootGate.h"

void setup() {
  Serial.begin(115200);
  delay(400);
  Serial.println();
  Serial.println(F("================================================================"));
  Serial.println(F("  Suicide Marauder - GATE TEST HARNESS  (SUICIDE_SAFE_MODE)"));
  Serial.println(F("  This build NEVER erases anything. Serial gate test only."));
  Serial.println(F("================================================================"));

  suicide::GateConfig cfg = suicide::GateConfig::load();
  Serial.printf("[harness] provisioned=%d armed=%d deadman=%d max_att=%d arm_pin=%d arm_level=%d arm_pull=%d brick=%d\n",
                (int)cfg.provisioned, (int)cfg.armed, (int)cfg.deadman, (int)cfg.max_att,
                (int)cfg.arm_pin, (int)cfg.arm_level, (int)cfg.arm_pull, (int)cfg.brick);
  if (!cfg.provisioned) {
    Serial.println(F("[harness] NOT provisioned -> the gate must PASS immediately and never wipe."));
  } else {
    Serial.println(F("[harness] provisioned -> armed flow (SAFE: no real wipe). Enter the password over serial."));
  }

  unsigned long t0 = millis();
  suicide::GateResult r = suicide::BootGate::run();
  unsigned long dt = millis() - t0;

  if (r == suicide::GATE_PASS) {
    Serial.printf("[harness] RESULT: GATE_PASS (%lums) -> a real build would now start Marauder.\n", dt);
  } else {
    Serial.printf("[harness] RESULT: GATE_TRIGGERED (%lums) -> SAFE-mode simulated wipe done; nothing destroyed.\n", dt);
  }
  Serial.println(F("[harness] (idle - reset the board to run the gate again)"));
}

void loop() { delay(1000); }
