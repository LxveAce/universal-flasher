// GateCrypto.h — password verification. docs/SPEC.md §9.
//
// PBKDF2-HMAC-SHA256 via mbedtls (bundled with Arduino-ESP32). Argon2id is infeasible on ESP32
// (OWASP 19 MiB minimum > available RAM). Host (host/provision.py) and device MUST use identical
// {iter, dklen, salt}. Comparison is constant-time. The plaintext password buffer is zeroized by
// the caller immediately after verify() returns.
#pragma once

#include "GateConfig.h"

namespace suicide {

class GateCrypto {
 public:
  // Derive PBKDF2-HMAC-SHA256(password, cfg.salt, cfg.kdf_iter, cfg.kdf_dklen) and constant-time
  // compare against cfg.pwhash. Returns true on match. Does not log or retain the password.
  static bool verify(const char* password, size_t len, const GateConfig& cfg);

  // Low-level derive (exposed for self-test / SAFE-mode dummy-key checks).
  static bool derive(const uint8_t* password, size_t pw_len,
                     const uint8_t* salt, size_t salt_len,
                     uint32_t iter, uint8_t* out, size_t out_len);

  // Constant-time memcmp (length-fixed). Returns true iff equal.
  static bool ctEqual(const uint8_t* a, const uint8_t* b, size_t n);
};

} // namespace suicide
