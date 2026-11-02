#include "storage/secure_storage.hpp"

#if defined(__APPLE__)

namespace pm::storage {

bool harden_storage_dir(const std::filesystem::path& dir) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) return false;
    std::filesystem::permissions(
        dir,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace,
        ec);
    return !ec;
}

bool wrap_local_secret(const std::vector<std::uint8_t>& plaintext,
                       std::vector<std::uint8_t>& wrapped,
                       std::string&) {
    wrapped = plaintext;
    return true;
}

bool unwrap_local_secret(const std::vector<std::uint8_t>& wrapped,
                         std::vector<std::uint8_t>& plaintext,
                         std::string&) {
    plaintext = wrapped;
    return true;
}

bool wrap_local_secret_with_policy(const std::vector<std::uint8_t>& plaintext,
                                   std::vector<std::uint8_t>& wrapped,
                                   const SecretProtectionPolicy&,
                                   std::string& err) {
    return wrap_local_secret(plaintext, wrapped, err);
}

bool unwrap_local_secret_with_policy(const std::vector<std::uint8_t>& wrapped,
                                     std::vector<std::uint8_t>& plaintext,
                                     const SecretProtectionPolicy&,
                                     std::string& err) {
    return unwrap_local_secret(wrapped, plaintext, err);
}

SecretProtectionPolicy default_secret_protection_policy() {
    return {};
}

bool verify_user_presence(const SecretProtectionPolicy&, std::string&) {
    return true; // no platform user-verification mechanism; pass through
}

bool verify_user_presence(std::string& err) {
    return verify_user_presence({}, err);
}

} // namespace pm::storage

#endif
