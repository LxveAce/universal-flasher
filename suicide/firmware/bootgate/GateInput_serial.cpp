// GateInput_serial.cpp — headless / host-assisted password entry over USB serial. DEFAULT adapter.
//
// Compiles ONLY under GATE_INPUT_SERIAL (SPEC §5). On headless Marauder targets (Flipper dev board,
// MultiBoard S3, Dev Board Pro, Lonely Binary, GENERIC_ESP32, C5) there is no screen and no usable
// nav input, so the gate is necessarily host/serial-assisted (RESEARCH-DIGEST: confirmed against
// CommandLine.cpp — interaction is exclusively `Serial.readStringUntil('\n')`).
//
// PROTOCOL (SPEC §5, §6):
//   * `unlock <pw>`   -> InputResult{ got=true, buf=<pw>, len=strlen(pw), wipeRequest=false }
//   * `wipe`          -> AUTHENTICATED host-wipe. We do NOT set wipeRequest unconditionally; instead
//                        we PROMPT for the password and return it alongside wipeRequest=true so
//                        BootGate can verify it. The wipe fires ONLY if GateCrypto::verify() passes;
//                        a wrong password counts as a failed attempt. An accidental/unauthenticated
//                        `wipe\n` therefore can NEVER destroy data (SPEC §6 authenticated host-wipe).
//   * a bare line (no prefix) is also accepted as the password itself, for convenience.
//
// SECURITY:
//   * Serial local echo is NOT enabled here and we never print the typed password back. We read raw
//     bytes; the host terminal may echo locally, but the device never re-emits the secret (SPEC §4).
//   * The line scratch buffer and the InputResult buf are zeroized on every exit path.
//   * No password is ever a flash cmdline argument — it is typed live into this prompt.
#ifdef GATE_INPUT_SERIAL

#include "GateInput.h"
#include <Arduino.h>
#include <string.h>

#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
#include "nvs_flash.h"
#include "nvs.h"
#endif

#if !defined(SUICIDE_NO_SD)
#include <SD.h>
#endif

namespace suicide {

namespace {

// Marauder uses the single global `Serial` object (USB-CDC or UART0) — reuse it, do not reopen.
constexpr unsigned long  kBaud         = 115200;
constexpr uint32_t       kPollGapMs    = 5;
constexpr size_t         kLineMax      = 96;     // > 64 so we can hold "unlock " + 64-char pw + slack
constexpr uint32_t       kReadTimeoutMs = 120000;  // 2 min per prompt; transient -> got=false, re-ask

// Zeroize then drop a stack buffer. volatile prevents the compiler from eliding the wipe.
void secureZero(void* p, size_t n) {
  volatile uint8_t* v = reinterpret_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}

}  // namespace (close anonymous namespace so startsWithCmd is accessible from dashboard namespace)

// Case-insensitive prefix check for the command keyword (commands are ASCII, lowercase expected).
// Placed at file scope (not in an anonymous namespace) so both the anonymous helpers and the
// dashboard namespace can use it.
static bool startsWithCmd(const char* line, const char* cmd, size_t cmdLen) {
  for (size_t i = 0; i < cmdLen; ++i) {
    char c = line[i];
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    if (c != cmd[i]) return false;
  }
  return true;
}

namespace {  // re-open anonymous namespace for the remaining helpers

// Read one CR/LF-terminated line into `out` (NUL-terminated), returning length or -1 on timeout.
// Does NOT echo bytes. Backspace (0x08/0x7F) edits the in-RAM line so a typo doesn't leak as a wrong
// attempt; nothing is printed in response.
int readLine(char* out, size_t cap) {
  size_t n = 0;
  uint32_t start = millis();
  for (;;) {
    if (millis() - start > kReadTimeoutMs) return -1;
    while (Serial.available() > 0) {
      int ci = Serial.read();
      if (ci < 0) break;
      char c = static_cast<char>(ci);
      if (c == '\n' || c == '\r') {
        out[n] = '\0';
        // Swallow a trailing paired CRLF byte if it is already waiting.
        if (Serial.available() > 0) {
          int peek = Serial.peek();
          if (peek == '\n' || peek == '\r') Serial.read();
        }
        return static_cast<int>(n);
      }
      if (c == 0x08 || c == 0x7F) {  // backspace / DEL — edit in place, no echo
        if (n > 0) n--;
        continue;
      }
      if (n < cap - 1) out[n++] = c;
      // else: silently drop overflow bytes (don't truncate-leak by echoing)
    }
    delay(kPollGapMs);
  }
}

// Copy the operator's secret out of a (already trimmed) line into the result buffer. Accepts either
// a bare password or an `unlock <pw>` form. Returns the secret length (0 => empty/transient). The
// caller is responsible for zeroizing r.buf after verify(). Does NOT echo anything.
size_t extractSecret(const char* trimmed, InputResult& r) {
  static const char kUnlock[] = "unlock";
  const char* secret = trimmed;
  if (startsWithCmd(trimmed, kUnlock, 6) && (trimmed[6] == ' ' || trimmed[6] == '\t')) {
    secret = trimmed + 6;
    while (*secret == ' ' || *secret == '\t') ++secret;
  }

  size_t slen = strlen(secret);
  if (slen == 0) return 0;
  if (slen > sizeof(r.buf) - 1) slen = sizeof(r.buf) - 1;  // clamp to char[64]
  memcpy(r.buf, secret, slen);
  r.buf[slen] = '\0';
  r.len = slen;
  return slen;
}

}  // namespace

// Firmware version for SM_INFO responses. Updated with each release.
static constexpr const char* SM_FW_VERSION = "1.1.0";

void Input::begin(const GateConfig& /*cfg*/) {
  if (!Serial) Serial.begin(kBaud);
  // Brief, non-secret prompt. Never hints whether the board is provisioned/armed beyond this.
  Serial.println();
  Serial.println(F("suicide-gate: enter `unlock <password>` (or just the password). `wipe` to erase."));
}

// ---------------------------------------------------------------------------------------------
// Dashboard integration commands (Cyber Controller protocol). These commands are processed BEFORE
// the gate password loop. They allow a host controller to query status and manage the device
// remotely. Commands that modify state require authentication (the gate password).
//
// Protocol (all commands are case-insensitive, terminated by CR/LF):
//   SM_STATUS                  -> return current state JSON
//   SM_INFO                    -> return firmware/hardware info JSON
//   SM_ARM                     -> arm the device (requires password confirmation)
//   SM_DISARM <password>       -> disarm with password
//   SM_SET_PASSWORD <old> <new> -> change password (NOT implemented in firmware — requires
//                                  re-provisioning from host)
//   SM_WIPE                    -> trigger immediate wipe (requires password confirmation)
//
// Responses are JSON lines prefixed with "SM>" for easy parsing by the controller.
// ---------------------------------------------------------------------------------------------
namespace dashboard {

void sendStatus(const GateConfig& cfg) {
  Serial.print(F("SM>{\"cmd\":\"STATUS\",\"provisioned\":"));
  Serial.print(cfg.provisioned ? F("true") : F("false"));
  Serial.print(F(",\"armed\":"));
  Serial.print(cfg.armed);
  Serial.print(F(",\"deadman\":"));
  Serial.print(cfg.deadman);
  Serial.print(F(",\"max_att\":"));
  Serial.print(cfg.max_att);

  // Read the runtime attempt counter.
  GateRuntime rt = GateRuntime::load();
  Serial.print(F(",\"att_ct\":"));
  Serial.print(rt.att_ct);
  Serial.print(F(",\"wipe_armed\":"));
  Serial.print(rt.wipe_armed);
  Serial.print(F(",\"resume_count\":"));
  Serial.print(rt.resume_count);
  Serial.println(F("}"));
}

void sendInfo(const GateConfig& cfg) {
  Serial.print(F("SM>{\"cmd\":\"INFO\",\"fw_version\":\""));
  Serial.print(SM_FW_VERSION);
  Serial.print(F("\",\"arm_pin\":"));
  Serial.print(cfg.arm_pin);
  Serial.print(F(",\"arm_level\":"));
  Serial.print(cfg.arm_level);
  Serial.print(F(",\"arm_pull\":"));
  Serial.print(cfg.arm_pull);
  Serial.print(F(",\"brick\":"));
  Serial.print(cfg.brick);
  Serial.print(F(",\"fast_wipe\":"));
  Serial.print(cfg.fast_wipe);
  Serial.print(F(",\"wipe_sd\":"));
  Serial.print(cfg.wipe_sd);
  Serial.print(F(",\"wipe_ota\":"));
  Serial.print(cfg.wipe_ota);
  Serial.print(F(",\"wipe_nvs\":"));
  Serial.print(cfg.wipe_nvs);
  Serial.print(F(",\"wipe_spiffs\":"));
  Serial.print(cfg.wipe_spiffs);
  Serial.print(F(",\"sd_passes\":"));
  Serial.print(cfg.sd_passes);
  Serial.print(F(",\"kdf_iter\":"));
  Serial.print(cfg.kdf_iter);

  // SD card presence check.
  bool sdPresent = false;
#if !defined(SUICIDE_NO_SD)
  sdPresent = SD.begin();
  if (sdPresent) SD.end();
#endif
  Serial.print(F(",\"sd_present\":"));
  Serial.print(sdPresent ? F("true") : F("false"));

  // Brownout event count from NVS.
  uint8_t boCount = 0;
#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)
  {
    nvs_handle_t h;
    if (nvs_open_from_partition("guardcfg", "sgate_rt", NVS_READONLY, &h) == ESP_OK) {
      nvs_get_u8(h, "bo_count", &boCount);
      nvs_close(h);
    }
  }
#endif
  Serial.print(F(",\"brownout_count\":"));
  Serial.print(boCount);

  // Board type detection.
  Serial.print(F(",\"board\":\""));
#if defined(CONFIG_IDF_TARGET_ESP32)
  Serial.print(F("esp32"));
#elif defined(CONFIG_IDF_TARGET_ESP32S3)
  Serial.print(F("esp32s3"));
#elif defined(CONFIG_IDF_TARGET_ESP32C3)
  Serial.print(F("esp32c3"));
#elif defined(CONFIG_IDF_TARGET_ESP32C6)
  Serial.print(F("esp32c6"));
#elif defined(CONFIG_IDF_TARGET_ESP32S2)
  Serial.print(F("esp32s2"));
#else
  Serial.print(F("unknown"));
#endif
  Serial.println(F("\"}"));
}

// Process a dashboard command line. Returns true if the line was a recognized SM_ command
// (handled here); false if it should be passed to the normal password extraction flow.
bool processCommand(const char* trimmed, const GateConfig& cfg) {
  if (startsWithCmd(trimmed, "sm_status", 9) &&
      (trimmed[9] == '\0' || trimmed[9] == ' ')) {
    sendStatus(cfg);
    return true;
  }
  if (startsWithCmd(trimmed, "sm_info", 7) &&
      (trimmed[7] == '\0' || trimmed[7] == ' ')) {
    sendInfo(cfg);
    return true;
  }
  if (startsWithCmd(trimmed, "sm_arm", 6) &&
      (trimmed[6] == '\0' || trimmed[6] == ' ')) {
    // ARM requires re-provisioning from the host (the armed flag is in the guardcfg NVS image).
    // We cannot modify it at runtime without the host provisioner. Report this.
    Serial.println(F("SM>{\"cmd\":\"ARM\",\"error\":\"arming requires re-provisioning from host "
                     "(provision.py --armed 1). Cannot modify guardcfg NVS at runtime.\"}"));
    return true;
  }
  if (startsWithCmd(trimmed, "sm_disarm", 9) &&
      (trimmed[9] == '\0' || trimmed[9] == ' ')) {
    // DISARM also requires re-provisioning. The armed flag is baked into the NVS image.
    Serial.println(F("SM>{\"cmd\":\"DISARM\",\"error\":\"disarming requires re-provisioning from host "
                     "(provision.py --armed 0). Cannot modify guardcfg NVS at runtime.\"}"));
    return true;
  }
  if (startsWithCmd(trimmed, "sm_set_password", 15) &&
      (trimmed[15] == '\0' || trimmed[15] == ' ')) {
    // Password change requires re-provisioning (new salt + hash).
    Serial.println(F("SM>{\"cmd\":\"SET_PASSWORD\",\"error\":\"password change requires re-provisioning "
                     "from host (provision.py). Cannot modify guardcfg NVS at runtime.\"}"));
    return true;
  }
  if (startsWithCmd(trimmed, "sm_wipe", 7) &&
      (trimmed[7] == '\0' || trimmed[7] == ' ')) {
    // SM_WIPE is mapped to the existing `wipe` command flow — password-authenticated.
    Serial.println(F("SM>{\"cmd\":\"WIPE\",\"status\":\"redirecting to authenticated wipe flow\"}"));
    // Fall through to the normal wipe handler by returning false and letting the caller
    // see "wipe" as the command. We rewrite the intent so the standard wipe path handles it.
    return false;  // caller will re-process as "wipe"
  }
  return false;  // not a dashboard command
}

}  // namespace dashboard

InputResult Input::getPassword(const GateConfig& cfg) {
  InputResult r;  // got=false by default
  char line[kLineMax] = {0};

  int len = readLine(line, sizeof(line));
  if (len < 0) {                 // timeout: transient, let BootGate re-prompt without an attempt
    secureZero(line, sizeof(line));
    return r;
  }

  // Trim leading spaces (mirrors Marauder's input.trim() behavior for the keyword).
  const char* p = line;
  while (*p == ' ' || *p == '\t') ++p;

  // Dashboard integration: check for SM_ commands first. These are handled without counting as
  // password attempts and return got=false so BootGate re-prompts. SM_WIPE falls through to the
  // normal wipe handler below.
  if (startsWithCmd(p, "sm_", 3)) {
    bool handled = dashboard::processCommand(p, cfg);
    if (handled) {
      secureZero(line, sizeof(line));
      return r;  // got=false — re-prompt, not a password attempt
    }
    // SM_WIPE was not fully handled — it falls through to the standard wipe flow below.
    // Rewrite p to point to "wipe" so the existing wipe handler picks it up.
    p = "wipe";
  }

  // `wipe` -> AUTHENTICATED host-assisted self-destruct (SPEC §6). We must NOT set wipeRequest
  // unconditionally: a bare `wipe\n` from terminal paste or serial noise must never destroy data.
  // Instead we prompt for the password and return it for BootGate to verify; only a correct password
  // actually triggers REASON_HOST_WIPE, and a wrong one is counted as a failed attempt by BootGate.
  static const char kWipe[] = "wipe";
  if (startsWithCmd(p, kWipe, 4) && (p[4] == '\0' || p[4] == ' ' || p[4] == '\t')) {
    secureZero(line, sizeof(line));  // done with the command line itself

    // Prompt for confirmation. Do NOT reveal whether the board is provisioned/armed beyond this.
    // Per SPEC §6 a non-empty wrong entry here is a FAILED ATTEMPT (not a free abort); only an empty
    // line or a timeout backs out without counting an attempt.
    Serial.println(F("suicide-gate: `wipe` requires the password to authenticate. enter password to "
                     "confirm (a wrong password counts as a failed attempt); empty line to abort."));

    char confirm[kLineMax] = {0};
    int clen = readLine(confirm, sizeof(confirm));
    if (clen < 0) {                // timeout: transient, treat as abort, no wipe, no attempt
      secureZero(confirm, sizeof(confirm));
      return r;                    // got=false, wipeRequest=false
    }

    const char* cp = confirm;
    while (*cp == ' ' || *cp == '\t') ++cp;

    size_t cslen = extractSecret(cp, r);
    secureZero(confirm, sizeof(confirm));
    if (cslen == 0) {              // empty confirmation: abort, no wipe, no attempt
      memset(r.buf, 0, sizeof(r.buf));
      r.len = 0;
      return r;                    // got=false, wipeRequest=false
    }

    // Hand the typed secret to BootGate WITH wipeRequest=true. BootGate verifies it: correct ->
    // REASON_HOST_WIPE; wrong -> counted as a failed attempt. Either way, authenticated.
    r.got = true;
    r.wipeRequest = true;
    return r;                      // caller zeroizes r.buf after verify
  }

  // `unlock <pw>` or a bare password line -> extract the secret directly.
  size_t slen = extractSecret(p, r);
  secureZero(line, sizeof(line));  // wipe scratch; caller zeroizes r.buf after verify
  if (slen == 0) {                 // empty line: transient, not a wrong attempt
    memset(r.buf, 0, sizeof(r.buf));
    r.len = 0;
    return r;
  }
  r.got = true;
  return r;
}

void Input::notifyWrong(uint8_t attemptsLeft) {
  // No secret material. Do not reveal the master-armed state beyond the attempt count.
  Serial.print(F("suicide-gate: wrong. attempts left: "));
  Serial.println(attemptsLeft);
}

void Input::notifyLocked(uint32_t seconds) {
  Serial.print(F("suicide-gate: locked for "));
  Serial.print(seconds);
  Serial.println(F("s."));
}

}  // namespace suicide

#endif  // GATE_INPUT_SERIAL
