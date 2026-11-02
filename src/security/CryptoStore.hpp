#pragma once
//
// pm::security::CryptoStore — backend-agnostic blob encryption for the grant /
// audit databases.
//
// On Windows the backend wraps a DPAPI-protected 256-bit master key and uses
// CNG AES-256-GCM for individual blobs. macOS (Keychain) and Linux (Secret
// Service) backends land later. When no backend is compiled in, a pass-through
// store is returned so the rest of the module is exercisable in dev/test — it
// MUST NOT be used to persist real secrets.
//
// AAD (additional authenticated data) binds ciphertext to its context:
// app-id / profile / grant-id / policy-version / tool-id / manifest-hash /
// workspace-id (design.md "CryptoStore API").
//
// Design reference: docs/security/design.md ("Windows secure storage backend",
// "CryptoStore API").
//

#include "security/types.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace pm::security {

class CryptoStore {
public:
    virtual ~CryptoStore() = default;

    /// Encrypt @p plaintext, authenticating @p aad. Returns nonce||ciphertext||tag.
    virtual std::vector<std::uint8_t> encryptBlob(std::span<const std::uint8_t> plaintext,
                                                  std::string_view aad) = 0;

    /// Decrypt @p ciphertext produced by encryptBlob with the same @p aad.
    /// Returns empty on authentication failure.
    virtual std::vector<std::uint8_t> decryptBlob(std::span<const std::uint8_t> ciphertext,
                                                  std::string_view aad) = 0;

    /// True for a real, persistence-safe backend (false for the pass-through).
    virtual bool isSecure() const noexcept = 0;
};

/// Create the platform's encryption backend, or a pass-through when none is
/// compiled in. Never returns null.
std::unique_ptr<CryptoStore> make_crypto_store();

// ── Secure local storage layout (design.md "Persistence") ────────────────────

/// Resolved on-disk locations under %LOCALAPPDATA%/<App>/security (Windows) or
/// the platform equivalent.
struct SecurityPaths {
    std::filesystem::path dir;        ///< the security/ directory
    std::filesystem::path grantsDb;   ///< grants.db (SQLite)
    std::filesystem::path auditDb;    ///< audit.db  (SQLite)
    std::filesystem::path masterKey;  ///< master.key (DPAPI-wrapped)
};

/// Resolve the security storage paths for @p appName (e.g. "pm-image").
SecurityPaths resolve_security_paths(std::string_view appName);

/// Create @p dir if needed and restrict it to the current user (ACL on Windows,
/// 0700 on POSIX). Returns false when hardening is unavailable/failed.
bool harden_security_dir(const std::filesystem::path& dir);

} // namespace pm::security
