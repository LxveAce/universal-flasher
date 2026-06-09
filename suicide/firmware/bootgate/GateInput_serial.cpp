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

// Case-insensitive prefix check for the command keyword (commands are ASCII, lowercase expected).
bool startsWithCmd(const char* line, const char* cmd, size_t cmdLen) {
  for (size_t i = 0; i < cmdLen; ++i) {
    char c = line[i];
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    if (c != cmd[i]) return false;
  }
  return true;
}

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

void Input::begin(const GateConfig& /*cfg*/) {
  if (!Serial) Serial.begin(kBaud);
  // Brief, non-secret prompt. Never hints whether the board is provisioned/armed beyond this.
  Serial.println();
  Serial.println(F("suicide-gate: enter `unlock <password>` (or just the password). `wipe` to erase."));
}

InputResult Input::getPassword(const GateConfig& /*cfg*/) {
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
