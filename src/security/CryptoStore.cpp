#include "security/CryptoStore.hpp"
#include "security/security_default.hpp"

#include <cstdlib>
#include <system_error>

#if defined(_WIN32)
#  include <cstdlib>  // _wgetenv
#endif

namespace pm::security {

// ── Backend hooks implemented in backends/<os>/* (declared here, defined there)
namespace detail {

#if defined(_WIN32) && FEATURE_SECURITY_CRYPTO_WIN_DPAPI
std::unique_ptr<CryptoStore> make_win_dpapi_crypto_store();
#endif
#if defined(_WIN32)
std::filesystem::path win_local_appdata();
#endif
#if defined(_WIN32) && FEATURE_SECURITY_WIN_ACL
bool win_harden_dir(const std::filesystem::path& dir);
#endif

} // namespace detail

namespace {

/// Insecure fallback used only when no real backend is compiled in. It does NOT
/// encrypt — it returns the plaintext verbatim and reports isSecure()==false so
/// callers can refuse to persist real secrets.
class PassthroughCryptoStore final : public CryptoStore {
public:
    std::vector<std::uint8_t> encryptBlob(std::span<const std::uint8_t> plaintext,
                                          std::string_view) override {
        return {plaintext.begin(), plaintext.end()};
    }
    std::vector<std::uint8_t> decryptBlob(std::span<const std::uint8_t> ciphertext,
                                          std::string_view) override {
        return {ciphertext.begin(), ciphertext.end()};
    }
    bool isSecure() const noexcept override { return false; }
};

std::filesystem::path local_app_root() {
#if defined(_WIN32)
    return detail::win_local_appdata();
#else
    if (const char* xdg = std::getenv("XDG_DATA_HOME"); xdg && *xdg)
        return std::filesystem::path(xdg);
    if (const char* home = std::getenv("HOME"); home && *home)
        return std::filesystem::path(home) / ".local" / "share";
    return std::filesystem::temp_directory_path();
#endif
}

} // namespace

std::unique_ptr<CryptoStore> make_crypto_store() {
#if defined(_WIN32) && FEATURE_SECURITY_CRYPTO_WIN_DPAPI
    if (auto win = detail::make_win_dpapi_crypto_store())
        return win;
#endif
    // TODO(security): macOS Keychain / Linux Secret Service backends.
    return std::make_unique<PassthroughCryptoStore>();
}

SecurityPaths resolve_security_paths(std::string_view appName) {
    std::filesystem::path dir = local_app_root() / std::string(appName) / "security";
    SecurityPaths p;
    p.dir = dir;
    p.grantsDb = dir / "grants.db";
    p.auditDb = dir / "audit.db";
    p.masterKey = dir / "master.key";
    return p;
}

bool harden_security_dir(const std::filesystem::path& dir) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) return false;

#if defined(_WIN32) && FEATURE_SECURITY_WIN_ACL
    return detail::win_harden_dir(dir);
#elif !defined(_WIN32)
    // POSIX: restrict to owner (0700).
    std::filesystem::permissions(
        dir,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace, ec);
    return !ec;
#else
    // TODO(security): ACL hardening disabled at compile time.
    return false;
#endif
}

} // namespace pm::security
