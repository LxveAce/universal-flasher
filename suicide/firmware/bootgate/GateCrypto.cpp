// GateCrypto.cpp — password verification via PBKDF2-HMAC-SHA256 (mbedtls). docs/SPEC.md §9.
//
// Argon2id is infeasible on ESP32 (OWASP 19 MiB minimum > available RAM), so PBKDF2-HMAC-SHA256
// with a high iteration count is the agreed KDF. Host (host/provision.py) and device MUST use
// identical {salt, iter, dklen}; the device re-derives with the params it read from `guardcfg` NVS
// and compares to the stored pwhash in CONSTANT TIME.
//
// The plaintext password is never logged or retained here. derive() writes only into the caller's
// output buffer; verify() zeroizes its own scratch derived-key buffer before returning. The caller
// (BootGate) zeroizes the password buffer immediately after verify() returns (docs/SPEC.md §6).

#include "GateCrypto.h"

#include <string.h>

#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"

namespace suicide {

bool GateCrypto::derive(const uint8_t* password, size_t pw_len,
                        const uint8_t* salt, size_t salt_len,
                        uint32_t iter, uint8_t* out, size_t out_len) {
  if (out == nullptr || out_len == 0 || salt == nullptr || iter == 0) {
    return false;
  }
  // A null password pointer is only valid for a zero-length password; mbedtls tolerates an empty
  // password but we must pass a valid (non-null) pointer for pw_len==0 on some versions.
  static const uint8_t kEmpty = 0;
  if (password == nullptr) {
    if (pw_len != 0) {
      return false;
    }
    password = &kEmpty;
  }

  const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (md_info == nullptr) {
    return false;
  }

#if defined(MBEDTLS_VERSION_NUMBER) && (MBEDTLS_VERSION_NUMBER >= 0x03000000)
  // mbedtls 3.x (current Arduino-ESP32 / IDF v5): the *_ext entry point takes the md_type directly
  // and manages its own HMAC context internally.
  int rc = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                         password, pw_len,
                                         salt, salt_len,
                                         iter,
                                         static_cast<uint32_t>(out_len), out);
  return rc == 0;
#else
  // mbedtls 2.x (older Arduino-ESP32 / IDF v4): set up an explicit HMAC-capable md context and use
  // the classic entry point.
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  int rc = mbedtls_md_setup(&ctx, md_info, /*hmac=*/1);
  if (rc != 0) {
    mbedtls_md_free(&ctx);
    return false;
  }
  rc = mbedtls_pkcs5_pbkdf2_hmac(&ctx,
                                 password, pw_len,
                                 salt, salt_len,
                                 iter,
                                 static_cast<uint32_t>(out_len), out);
  mbedtls_md_free(&ctx);
  return rc == 0;
#endif
}

bool GateCrypto::ctEqual(const uint8_t* a, const uint8_t* b, size_t n) {
  // Constant-time equality: fold every byte difference into an accumulator so the running time and
  // the branch profile depend only on n, never on WHERE the first mismatch is. This denies a timing
  // oracle that could otherwise let an attacker recover the hash byte-by-byte.
  if (a == nullptr || b == nullptr) {
    return false;
  }
  volatile uint8_t diff = 0;
  for (size_t i = 0; i < n; ++i) {
    diff |= static_cast<uint8_t>(a[i] ^ b[i]);
  }
  // Map 0 -> true, anything-else -> false without a data-dependent branch.
  return diff == 0;
}

bool GateCrypto::verify(const char* password, size_t len, const GateConfig& cfg) {
  // Never verify against an unprovisioned/!valid config — that would compare against an all-zero
  // hash and could be satisfied by a password that happens to derive to zeros. The caller already
  // gates on cfg.provisioned, but we defend in depth here.
  if (!cfg.provisioned) {
    return false;
  }
  if (cfg.kdf_dklen == 0 || cfg.kdf_dklen > KDF_DKLEN || cfg.kdf_iter == 0) {
    return false;
  }

  uint8_t derived[KDF_DKLEN];
  memset(derived, 0, sizeof(derived));

  bool ok = derive(reinterpret_cast<const uint8_t*>(password), len,
                   cfg.salt, SALT_LEN,
                   cfg.kdf_iter, derived, cfg.kdf_dklen);

  bool match = false;
  if (ok) {
    match = ctEqual(derived, cfg.pwhash, cfg.kdf_dklen);
  }

  // Zeroize the derived key so it cannot be recovered from stack/heap remnants. memset can be
  // elided by the optimizer for a soon-dead buffer; touching it through a volatile pointer prevents
  // that dead-store elimination.
  volatile uint8_t* p = derived;
  for (size_t i = 0; i < sizeof(derived); ++i) {
    p[i] = 0;
  }

  return match;
}

}  // namespace suicide
