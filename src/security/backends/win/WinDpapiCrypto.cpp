//
// pm::security backend (win32) — DPAPI master key + CNG AES-256-GCM blobs.
//
// Root of trust: a 256-bit random master key wrapped with DPAPI
// (CryptProtectData) so only the current Windows user can unwrap it. Individual
// blobs are sealed with AES-256-GCM (CNG / BCrypt) using a fresh random nonce
// and the caller-supplied AAD.
//
// Compiled only when FEATURE_SECURITY_CRYPTO_WIN_DPAPI is on.
//
// Design reference: docs/security/design.md ("Windows secure storage backend",
// "Windows APIs").
//

#if defined(_WIN32)

#include "security/security_default.hpp"

#if FEATURE_SECURITY_CRYPTO_WIN_DPAPI

#include "security/CryptoStore.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <dpapi.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace pm::security::detail {

namespace {

constexpr std::size_t kKeyBytes   = 32;  // AES-256
constexpr std::size_t kNonceBytes = 12;  // GCM standard nonce
constexpr std::size_t kTagBytes   = 16;  // GCM tag

/// Win32 DPAPI + CNG AES-256-GCM blob store.
class WinDpapiCryptoStore final : public CryptoStore {
public:
    std::vector<std::uint8_t> encryptBlob(std::span<const std::uint8_t> plaintext,
                                          std::string_view aad) override {
        // TODO(security, Phase 2):
        //   1. Load-or-create the DPAPI-wrapped master key (master.key):
        //      - BCryptGenRandom(kKeyBytes) for a new key,
        //      - CryptProtectData(key) → write master.key,
        //      - CryptUnprotectData(master.key) → key in memory.
        //   2. BCryptGenRandom(nonce, kNonceBytes).
        //   3. BCryptEncrypt with BCRYPT_AES_ALGORITHM in GCM chaining mode,
        //      pbAuthData = aad bytes, pbTag = kTagBytes.
        //   4. Return nonce || ciphertext || tag.
        (void)aad;
        (void)plaintext;
        return {};
    }

    std::vector<std::uint8_t> decryptBlob(std::span<const std::uint8_t> ciphertext,
                                          std::string_view aad) override {
        // TODO(security, Phase 2): split nonce/ciphertext/tag, unwrap the master
        // key via CryptUnprotectData, BCryptDecrypt with the same AAD, and return
        // empty on a GCM tag mismatch (tamper / wrong AAD).
        (void)aad;
        (void)ciphertext;
        return {};
    }

    bool isSecure() const noexcept override { return true; }
};

} // namespace

std::unique_ptr<CryptoStore> make_win_dpapi_crypto_store() {
    return std::make_unique<WinDpapiCryptoStore>();
}

} // namespace pm::security::detail

#endif // FEATURE_SECURITY_CRYPTO_WIN_DPAPI
#endif // _WIN32
