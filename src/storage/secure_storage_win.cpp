#include "storage/secure_storage.hpp"
#include "policy/app_policy.hpp"

#if defined(_WIN32)

#include <windows.h>
#include <dpapi.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace pm::storage {

namespace {

constexpr std::uint8_t k_wrapped_secret_magic[] = {'P', 'M', 'W', '1'};
constexpr std::uint8_t k_mode_mock_hello = 'M';
constexpr std::uint8_t k_mode_windows_hello = 'H';

std::string getenv_string(const char* name) {
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string{};
}

bool env_truthy(const char* name) {
    const std::string value = getenv_string(name);
    return value == "1" || value == "true" || value == "TRUE" || value == "yes" || value == "YES";
}

std::string status_hex(SECURITY_STATUS status) {
    std::ostringstream os;
    os << "0x" << std::hex << static_cast<unsigned long>(status);
    return os.str();
}

bool is_user_cancel_error(const std::string& err) {
    // NCrypt commonly reports NTE_USER_CANCELLED. Some providers surface
    // ERROR_CANCELLED directly or wrapped as an HRESULT.
    return err.find("0x80090036") != std::string::npos ||
        err.find("0x800704c7") != std::string::npos ||
        err.find("0x4c7") != std::string::npos;
}

std::wstring widen_ascii(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

std::wstring widen_utf8(const std::string& s) {
    if (s.empty())
        return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0)
        return widen_ascii(s);
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

/// Test/automation bypass for the Credential Dialog Xaml Host passphrase UI.
/// Synthetic SendInput is ignored by that host; pre-setting NCRYPT_PIN_PROPERTY
/// (the NCrypt analogue of cmdkey for key passwords) lets FinalizeKey / use
/// proceed without the dialog when PM_SECURE_STORAGE_HELLO_PASSPHRASE is set.
std::string hello_pin_from_env() {
    std::string pin = getenv_string("PM_SECURE_STORAGE_HELLO_PASSPHRASE");
    if (pin.empty())
        pin = getenv_string("PM_SECURE_STORAGE_HELLO_PIN");
    return pin;
}

bool apply_hello_pin(NCRYPT_KEY_HANDLE key, std::string& err) {
    const std::string pin = hello_pin_from_env();
    if (pin.empty())
        return true;
    const std::wstring wpin = widen_utf8(pin);
    const DWORD bytes = static_cast<DWORD>((wpin.size() + 1) * sizeof(wchar_t));
    const SECURITY_STATUS status = NCryptSetProperty(
        key,
        NCRYPT_PIN_PROPERTY,
        reinterpret_cast<PBYTE>(const_cast<wchar_t*>(wpin.c_str())),
        bytes,
        0);
    if (status != ERROR_SUCCESS) {
        err = "NCryptSetProperty(NCRYPT_PIN_PROPERTY) failed: " + status_hex(status);
        return false;
    }
    return true;
}

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
}

bool read_u32(const std::vector<std::uint8_t>& bytes, std::size_t& offset, std::uint32_t& value) {
    if (offset + 4 > bytes.size())
        return false;
    value = static_cast<std::uint32_t>(bytes[offset]) |
        (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
        (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
        (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
    offset += 4;
    return true;
}

bool has_envelope(const std::vector<std::uint8_t>& bytes) {
    return bytes.size() >= sizeof(k_wrapped_secret_magic) + 1 &&
        std::memcmp(bytes.data(), k_wrapped_secret_magic, sizeof(k_wrapped_secret_magic)) == 0;
}

bool encode_envelope(std::uint8_t mode,
                     const std::string& key_name,
                     const std::vector<std::uint8_t>& payload,
                     std::vector<std::uint8_t>& out,
                     std::string& err) {
    if (key_name.size() > UINT32_MAX || payload.size() > UINT32_MAX) {
        err = "wrapped secret envelope is too large";
        return false;
    }
    out.clear();
    out.insert(out.end(), std::begin(k_wrapped_secret_magic), std::end(k_wrapped_secret_magic));
    out.push_back(mode);
    append_u32(out, static_cast<std::uint32_t>(key_name.size()));
    out.insert(out.end(), key_name.begin(), key_name.end());
    append_u32(out, static_cast<std::uint32_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    return true;
}

bool decode_envelope(const std::vector<std::uint8_t>& in,
                     std::uint8_t& mode,
                     std::string& key_name,
                     std::vector<std::uint8_t>& payload,
                     std::string& err) {
    if (!has_envelope(in)) {
        err = "wrapped secret envelope is invalid";
        return false;
    }
    std::size_t offset = sizeof(k_wrapped_secret_magic);
    mode = in[offset++];
    std::uint32_t key_len = 0;
    if (!read_u32(in, offset, key_len) || offset + key_len > in.size()) {
        err = "wrapped secret envelope key name is invalid";
        return false;
    }
    key_name.assign(reinterpret_cast<const char*>(in.data() + offset), key_len);
    offset += key_len;
    std::uint32_t payload_len = 0;
    if (!read_u32(in, offset, payload_len) || offset + payload_len != in.size()) {
        err = "wrapped secret envelope payload is invalid";
        return false;
    }
    payload.assign(in.begin() + static_cast<std::ptrdiff_t>(offset), in.end());
    return true;
}

SecretProtectionPolicy normalize_policy(SecretProtectionPolicy policy) {
    if (policy.mode == SecretProtectionMode::PlatformDefault)
        policy = default_secret_protection_policy();
    if (policy.mode == SecretProtectionMode::PlatformDefault)
        policy.mode = SecretProtectionMode::WindowsDpapi;
    if (policy.key_name.empty())
        policy.key_name = "PolyMech.pm-image.secure-storage.v1";
    return policy;
}

bool dpapi_wrap(const std::vector<std::uint8_t>& plaintext,
                std::vector<std::uint8_t>& wrapped,
                std::string& err) {
    wrapped.clear();
    DATA_BLOB in{static_cast<DWORD>(plaintext.size()), const_cast<BYTE*>(plaintext.data())};
    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"pm-secure-storage", nullptr, nullptr, nullptr, 0, &out)) {
        err = "CryptProtectData failed";
        return false;
    }
    wrapped.assign(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return true;
}

bool dpapi_unwrap(const std::vector<std::uint8_t>& wrapped,
                  std::vector<std::uint8_t>& plaintext,
                  std::string& err) {
    plaintext.clear();
    DATA_BLOB in{static_cast<DWORD>(wrapped.size()), const_cast<BYTE*>(wrapped.data())};
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
        err = "CryptUnprotectData failed";
        return false;
    }
    plaintext.assign(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return true;
}

bool mock_confirmed(std::string& err) {
    if (env_truthy("PM_SECURE_STORAGE_MOCK_HELLO_CONFIRM"))
        return true;
    err = "mock Windows Hello confirmation required";
    return false;
}

std::vector<std::uint8_t> mock_transform(const std::vector<std::uint8_t>& in, const std::string& key_name) {
    const std::string key = key_name.empty() ? "mock-windows-hello" : key_name;
    std::vector<std::uint8_t> out = in;
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<std::uint8_t>(out[i] ^ static_cast<std::uint8_t>(key[i % key.size()] + i));
    return out;
}

bool mock_wrap(const std::vector<std::uint8_t>& plaintext,
               const SecretProtectionPolicy& policy,
               std::vector<std::uint8_t>& wrapped,
               std::string& err) {
    if (policy.require_user_confirmation && !mock_confirmed(err))
        return false;
    return encode_envelope(k_mode_mock_hello, policy.key_name, mock_transform(plaintext, policy.key_name), wrapped, err);
}

bool mock_unwrap(const std::vector<std::uint8_t>& envelope,
                 std::vector<std::uint8_t>& plaintext,
                 std::string& err) {
    if (!mock_confirmed(err))
        return false;
    std::uint8_t mode = 0;
    std::string key_name;
    std::vector<std::uint8_t> payload;
    if (!decode_envelope(envelope, mode, key_name, payload, err))
        return false;
    if (mode != k_mode_mock_hello) {
        err = "wrapped secret is not mock Windows Hello protected";
        return false;
    }
    plaintext = mock_transform(payload, key_name);
    return true;
}

bool try_open_or_create_hello_key(const wchar_t* provider_name,
                                  const std::string& provider_label,
                                  const std::string& key_name,
                                  NCRYPT_PROV_HANDLE& provider,
                                  NCRYPT_KEY_HANDLE& key,
                                  std::string& err) {
#if defined(FEATURE_SECURE_STORAGE_WIN_HELLO) && FEATURE_SECURE_STORAGE_WIN_HELLO
    SECURITY_STATUS status = NCryptOpenStorageProvider(&provider, provider_name, 0);
    if (status != ERROR_SUCCESS) {
        err = "NCryptOpenStorageProvider(" + provider_label + ") failed: " + status_hex(status);
        return false;
    }
    const std::wstring wide_name = widen_ascii(key_name);
    status = NCryptOpenKey(provider, &key, wide_name.c_str(), 0, 0);
    if (status == ERROR_SUCCESS) {
        // Existing key: supply PIN so encrypt/decrypt skips the password UI.
        if (!apply_hello_pin(key, err)) {
            NCryptFreeObject(key);
            NCryptFreeObject(provider);
            key = 0;
            provider = 0;
            return false;
        }
        return true;
    }

    status = NCryptCreatePersistedKey(provider, &key, NCRYPT_RSA_ALGORITHM, wide_name.c_str(), 0, 0);
    if (status != ERROR_SUCCESS) {
        err = "NCryptCreatePersistedKey(" + provider_label + ") failed: " + status_hex(status);
        NCryptFreeObject(provider);
        provider = 0;
        return false;
    }
    DWORD bits = 2048;
    status = NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&bits), sizeof(bits), 0);
    if (status != ERROR_SUCCESS) {
        err = "NCryptSetProperty(NCRYPT_LENGTH_PROPERTY) failed: " + status_hex(status);
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        key = 0;
        provider = 0;
        return false;
    }

    const bool have_pin = !hello_pin_from_env().empty();
    const bool skip_ui_protect = env_truthy("PM_SECURE_STORAGE_HELLO_NO_UI_PROTECT") || have_pin;
#ifndef NCRYPT_UI_PROTECT_KEY_FLAG
#define NCRYPT_UI_PROTECT_KEY_FLAG 0x00000001
#endif
    if (!skip_ui_protect) {
        NCRYPT_UI_POLICY ui{};
        ui.dwVersion = 1;
        ui.dwFlags = NCRYPT_UI_PROTECT_KEY_FLAG;
        ui.pszFriendlyName = L"PolyMech secure storage";
        ui.pszDescription = L"Confirm with Windows Hello to unlock local PolyMech asset keys.";
        status = NCryptSetProperty(key, NCRYPT_UI_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&ui), sizeof(ui), 0);
        if (status != ERROR_SUCCESS) {
            err = "NCryptSetProperty(NCRYPT_UI_POLICY_PROPERTY) failed: " + status_hex(status);
            NCryptFreeObject(key);
            NCryptFreeObject(provider);
            key = 0;
            provider = 0;
            return false;
        }
    }

    // Seed PIN before finalize so Credential Dialog Xaml Host is not shown
    // (that host ignores synthetic automation; PIN property is the supported bypass).
    if (!apply_hello_pin(key, err)) {
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        key = 0;
        provider = 0;
        return false;
    }

#ifndef NCRYPT_SILENT_FLAG
#define NCRYPT_SILENT_FLAG 0x00000040
#endif
    const DWORD finalize_flags = have_pin ? NCRYPT_SILENT_FLAG : 0;
    status = NCryptFinalizeKey(key, finalize_flags);
    if (status != ERROR_SUCCESS) {
        err = "NCryptFinalizeKey(" + provider_label + ") failed: " + status_hex(status);
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        key = 0;
        provider = 0;
        return false;
    }
    return true;
#else
    (void)provider_name;
    (void)provider_label;
    (void)key_name;
    (void)provider;
    (void)key;
    err = "Windows Hello TPM secure storage support is not compiled in";
    return false;
#endif
}

bool open_or_create_hello_key(const std::string& key_name, NCRYPT_PROV_HANDLE& provider, NCRYPT_KEY_HANDLE& key, std::string& err) {
    // When a test PIN is pre-seeded, prefer the Platform Crypto Provider first.
    // Microsoft Passport / NGC often still raises Credential Dialog Xaml Host
    // (which ignores synthetic automation) even with NCRYPT_PIN_PROPERTY set.
    const bool pin_mode = !hello_pin_from_env().empty();
    std::string first_err;
    std::string second_err;
    if (pin_mode) {
        if (try_open_or_create_hello_key(L"Microsoft Platform Crypto Provider",
                                         "Microsoft Platform Crypto Provider",
                                         key_name,
                                         provider,
                                         key,
                                         first_err))
            return true;
        if (try_open_or_create_hello_key(L"Microsoft Passport Key Storage Provider",
                                         "Microsoft Passport",
                                         key_name,
                                         provider,
                                         key,
                                         second_err))
            return true;
        err = first_err + "; " + second_err;
        return false;
    }
    if (try_open_or_create_hello_key(L"Microsoft Passport Key Storage Provider",
                                     "Microsoft Passport",
                                     key_name,
                                     provider,
                                     key,
                                     first_err))
        return true;
    if (try_open_or_create_hello_key(L"Microsoft Platform Crypto Provider",
                                     "Microsoft Platform Crypto Provider",
                                     key_name,
                                     provider,
                                     key,
                                     second_err))
        return true;
    err = first_err + "; " + second_err;
    return false;
}

bool hello_wrap(const std::vector<std::uint8_t>& plaintext,
                const SecretProtectionPolicy& policy,
                std::vector<std::uint8_t>& wrapped,
                std::string& err) {
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (!open_or_create_hello_key(policy.key_name, provider, key, err))
        return false;
    BCRYPT_OAEP_PADDING_INFO padding{};
    padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    DWORD out_len = 0;
    SECURITY_STATUS status = NCryptEncrypt(key,
                                           const_cast<PBYTE>(plaintext.data()),
                                           static_cast<DWORD>(plaintext.size()),
                                           &padding,
                                           nullptr,
                                           0,
                                           &out_len,
                                           NCRYPT_PAD_OAEP_FLAG);
    if (status != ERROR_SUCCESS) {
        err = "NCryptEncrypt(Windows Hello) size failed: " + status_hex(status);
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        return false;
    }
    std::vector<std::uint8_t> cipher(out_len);
    status = NCryptEncrypt(key,
                           const_cast<PBYTE>(plaintext.data()),
                           static_cast<DWORD>(plaintext.size()),
                           &padding,
                           cipher.data(),
                           static_cast<DWORD>(cipher.size()),
                           &out_len,
                           NCRYPT_PAD_OAEP_FLAG);
    NCryptFreeObject(key);
    NCryptFreeObject(provider);
    if (status != ERROR_SUCCESS) {
        err = "NCryptEncrypt(Windows Hello) failed: " + status_hex(status);
        return false;
    }
    cipher.resize(out_len);
    return encode_envelope(k_mode_windows_hello, policy.key_name, cipher, wrapped, err);
}

bool hello_unwrap(const std::vector<std::uint8_t>& envelope,
                  std::vector<std::uint8_t>& plaintext,
                  std::string& err) {
    std::uint8_t mode = 0;
    std::string key_name;
    std::vector<std::uint8_t> cipher;
    if (!decode_envelope(envelope, mode, key_name, cipher, err))
        return false;
    if (mode != k_mode_windows_hello) {
        err = "wrapped secret is not Windows Hello protected";
        return false;
    }
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    if (!open_or_create_hello_key(key_name, provider, key, err))
        return false;
    BCRYPT_OAEP_PADDING_INFO padding{};
    padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    DWORD out_len = 0;
    SECURITY_STATUS status = NCryptDecrypt(key,
                                           cipher.data(),
                                           static_cast<DWORD>(cipher.size()),
                                           &padding,
                                           nullptr,
                                           0,
                                           &out_len,
                                           NCRYPT_PAD_OAEP_FLAG);
    if (status != ERROR_SUCCESS) {
        err = "NCryptDecrypt(Windows Hello) size failed: " + status_hex(status);
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        return false;
    }
    plaintext.assign(out_len, 0);
    status = NCryptDecrypt(key,
                           cipher.data(),
                           static_cast<DWORD>(cipher.size()),
                           &padding,
                           plaintext.data(),
                           static_cast<DWORD>(plaintext.size()),
                           &out_len,
                           NCRYPT_PAD_OAEP_FLAG);
    NCryptFreeObject(key);
    NCryptFreeObject(provider);
    if (status != ERROR_SUCCESS) {
        err = "NCryptDecrypt(Windows Hello) failed: " + status_hex(status);
        return false;
    }
    plaintext.resize(out_len);
    return true;
}

} // namespace

// ---------------------------------------------------------------------------
// verify_user_presence — challenge the user via the active protection mode.
// DPAPI mode: no interaction needed (the process credential IS the lock).
// Mock/Hello mode: perform the appropriate challenge.
// ---------------------------------------------------------------------------

bool verify_user_presence(const SecretProtectionPolicy& requested_policy, std::string& err) {
    const SecretProtectionPolicy policy = normalize_policy(requested_policy);
    switch (policy.mode) {
    case SecretProtectionMode::PlatformDefault: // normalize_policy already resolved PlatformDefault
    case SecretProtectionMode::WindowsDpapi:
        return true;
    case SecretProtectionMode::MockWindowsHello:
        return mock_confirmed(err);
    case SecretProtectionMode::WindowsHelloTpm: {
        // Wrap a fixed nonce (public-key op, no UI) then unwrap (private-key op — triggers Hello).
        static const std::vector<std::uint8_t> k_presence_nonce = {
            'P','M','P','R','E','S','E','N','C','E',0,1,0,0,0,0
        };
        std::vector<std::uint8_t> wrapped;
        if (!hello_wrap(k_presence_nonce, policy, wrapped, err))
            return false;
        std::vector<std::uint8_t> plaintext;
        if (!hello_unwrap(wrapped, plaintext, err))
            return false;
        if (plaintext != k_presence_nonce) {
            err = "Windows Hello presence verification round-trip mismatch";
            return false;
        }
        return true;
    }
    }
    err = "verify_user_presence: unknown protection mode";
    return false;
}

bool verify_user_presence(std::string& err) {
    // When Windows Hello is compiled in, use it by default for user-facing presence
    // verification — independent of how local keys are wrapped.
    // Set PM_SECURE_STORAGE_SECRET_PROTECTOR=dpapi to opt out (e.g. in CI / test runs).
#if defined(FEATURE_WINDOWS_GPO) && FEATURE_WINDOWS_GPO
    {
        const std::string gpo = pm::policy::policy_forced_verification_protector();
        if (!gpo.empty()) {
            SecretProtectionPolicy policy;
            if (gpo == "windows-hello" || gpo == "windows-hello-tpm") {
                policy.mode = SecretProtectionMode::WindowsHelloTpm;
            } else {
                // "dpapi" or any unrecognised value — DPAPI is the safe fallback
                policy.mode = SecretProtectionMode::WindowsDpapi;
            }
            policy.key_name = getenv_string("PM_SECURE_STORAGE_WIN_HELLO_KEY_NAME");
            if (policy.key_name.empty())
                policy.key_name = "PolyMech.pm-image.secure-storage.v1";
            policy.require_user_confirmation = true;
            return verify_user_presence(policy, err);
        }
    }
#endif
    const std::string protector = getenv_string("PM_SECURE_STORAGE_SECRET_PROTECTOR");
    SecretProtectionPolicy policy;
    bool hello_was_automatic = false;
    if (protector == "dpapi" || protector == "windows-dpapi") {
        policy.mode = SecretProtectionMode::WindowsDpapi;
    } else if (protector == "mock-windows-hello" || protector == "mock-hello") {
        policy.mode = SecretProtectionMode::MockWindowsHello;
    } else if (protector == "windows-hello" ||
               protector == "windows-hello-tpm" ||
               protector == "tpm") {
        // An explicit request is fail-closed: do not silently weaken it.
        policy.mode = SecretProtectionMode::WindowsHelloTpm;
    } else if (protector.empty()) {
#if defined(FEATURE_SECURE_STORAGE_WIN_HELLO) && FEATURE_SECURE_STORAGE_WIN_HELLO
        // Prefer Hello when available, but an unprovisioned/unsupported Hello
        // installation must not make ordinary operations unusable.
        policy.mode = SecretProtectionMode::WindowsHelloTpm;
        hello_was_automatic = true;
#else
        policy.mode = SecretProtectionMode::WindowsDpapi;
#endif
    } else {
        // Unknown configuration values use the portable Windows baseline.
        policy.mode = SecretProtectionMode::WindowsDpapi;
    }
    const std::string key_name = getenv_string("PM_SECURE_STORAGE_WIN_HELLO_KEY_NAME");
    policy.key_name = key_name.empty() ? "PolyMech.pm-image.secure-storage.v1" : key_name;
    policy.require_user_confirmation = true;
    if (!hello_was_automatic)
        return verify_user_presence(policy, err);

    if (verify_user_presence(policy, err))
        return true;
    if (is_user_cancel_error(err))
        return false;

    // Hello is unavailable rather than rejected by the user. DPAPI remains
    // user-scoped and is also the key-wrapping baseline for this storage.
    policy.mode = SecretProtectionMode::WindowsDpapi;
    err.clear();
    return verify_user_presence(policy, err);
}

bool harden_storage_dir(const std::filesystem::path& dir) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) return false;

    // Phase 1 keeps this non-fatal. The existing security ACL backend can be
    // reused here once secure storage moves beyond the JSON-index MVP.
    DWORD attrs = GetFileAttributesW(dir.wstring().c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

bool wrap_local_secret(const std::vector<std::uint8_t>& plaintext,
                       std::vector<std::uint8_t>& wrapped,
                       std::string& err) {
    return wrap_local_secret_with_policy(plaintext, wrapped, default_secret_protection_policy(), err);
}

bool unwrap_local_secret(const std::vector<std::uint8_t>& wrapped,
                         std::vector<std::uint8_t>& plaintext,
                         std::string& err) {
    return unwrap_local_secret_with_policy(wrapped, plaintext, default_secret_protection_policy(), err);
}

bool wrap_local_secret_with_policy(const std::vector<std::uint8_t>& plaintext,
                                   std::vector<std::uint8_t>& wrapped,
                                   const SecretProtectionPolicy& requested_policy,
                                   std::string& err) {
    const SecretProtectionPolicy policy = normalize_policy(requested_policy);
    if (policy.mode == SecretProtectionMode::MockWindowsHello)
        return mock_wrap(plaintext, policy, wrapped, err);
    if (policy.mode == SecretProtectionMode::WindowsHelloTpm)
        return hello_wrap(plaintext, policy, wrapped, err);
    return dpapi_wrap(plaintext, wrapped, err);
}

bool unwrap_local_secret_with_policy(const std::vector<std::uint8_t>& wrapped,
                                     std::vector<std::uint8_t>& plaintext,
                                     const SecretProtectionPolicy& requested_policy,
                                     std::string& err) {
    if (has_envelope(wrapped)) {
        std::uint8_t mode = 0;
        std::string key_name;
        std::vector<std::uint8_t> payload;
        if (!decode_envelope(wrapped, mode, key_name, payload, err))
            return false;
        if (mode == k_mode_mock_hello)
            return mock_unwrap(wrapped, plaintext, err);
        if (mode == k_mode_windows_hello)
            return hello_unwrap(wrapped, plaintext, err);
        err = "unsupported wrapped secret protection mode";
        return false;
    }
    const SecretProtectionPolicy policy = normalize_policy(requested_policy);
    if (policy.mode == SecretProtectionMode::MockWindowsHello ||
        policy.mode == SecretProtectionMode::WindowsHelloTpm) {
        err = "wrapped secret is DPAPI protected, not " +
            std::string(policy.mode == SecretProtectionMode::MockWindowsHello ? "mock Windows Hello" : "Windows Hello");
        return false;
    }
    return dpapi_unwrap(wrapped, plaintext, err);
}

SecretProtectionPolicy default_secret_protection_policy() {
    SecretProtectionPolicy policy;
    const std::string protector = getenv_string("PM_SECURE_STORAGE_SECRET_PROTECTOR");
    if (protector == "windows-hello" || protector == "windows-hello-tpm" || protector == "tpm") {
        policy.mode = SecretProtectionMode::WindowsHelloTpm;
    } else if (protector == "mock-windows-hello" || protector == "mock-hello") {
        policy.mode = SecretProtectionMode::MockWindowsHello;
    } else {
        policy.mode = SecretProtectionMode::WindowsDpapi;
    }
    const std::string key_name = getenv_string("PM_SECURE_STORAGE_WIN_HELLO_KEY_NAME");
    policy.key_name = key_name.empty() ? "PolyMech.pm-image.secure-storage.v1" : key_name;
    policy.require_user_confirmation = true;
    return policy;
}

} // namespace pm::storage

#endif
