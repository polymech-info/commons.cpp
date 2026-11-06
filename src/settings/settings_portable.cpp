#include "settings/settings_portable.hpp"
#include "fs/path_sanitizer.hpp"

#include "settings/chat_settings_schema.hpp"
#include "logging/pm_log.hpp"

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#if defined(_WIN32)
#include "win/settings_store.hpp"
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace media::portable_settings {
namespace detail {

constexpr char kLocalMagic[4] = {'P', 'M', 'E', '1'};
constexpr char kPassphraseMagic[4] = {'P', 'M', 'S', '1'};
constexpr const char* kKeyFileName = ".settings-key.dat";
constexpr const char* kPassphraseEnv = "POLYMECH_SETTINGS_PASSPHRASE";
std::optional<fs::path> g_profile_dir_override;

bool ensure_sodium(std::string& err) {
    static bool done = false;
    if (done)
        return true;
    if (sodium_init() < 0) {
        err = "sodium_init failed";
        return false;
    }
    done = true;
    return true;
}

bool read_file_bytes(const fs::path& p, std::vector<unsigned char>& out) {
    std::ifstream ifs(p, std::ios::binary);
    if (!ifs.is_open())
        return false;
    ifs.seekg(0, std::ios::end);
    const auto sz = static_cast<size_t>(ifs.tellg());
    ifs.seekg(0, std::ios::beg);
    out.resize(sz);
    if (sz)
        ifs.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(sz));
    return static_cast<bool>(ifs);
}

bool write_file_bytes(const fs::path& p, const unsigned char* data, size_t len) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    if (ec)
        return false;
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open())
        return false;
    if (len)
        ofs.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    return static_cast<bool>(ofs);
}

bool looks_like_json_plaintext(const std::vector<unsigned char>& raw) {
    size_t i = 0;
    while (i < raw.size() && std::isspace(static_cast<unsigned char>(raw[i])))
        ++i;
    return i < raw.size() && raw[i] == '{';
}

fs::path key_path_for_settings(const fs::path& settings_file) {
    return settings_file.parent_path() / kKeyFileName;
}

bool load_or_create_secret_key(const fs::path& settings_file, std::vector<unsigned char>& key32, std::string& err) {
    if (!ensure_sodium(err))
        return false;
    key32.resize(crypto_secretbox_KEYBYTES);
    const fs::path key_path = key_path_for_settings(settings_file);
    std::vector<unsigned char> file_bytes;
    if (fs::exists(key_path)) {
        if (!read_file_bytes(key_path, file_bytes) || file_bytes.size() != crypto_secretbox_KEYBYTES) {
            err = "failed to read settings key file";
            return false;
        }
        std::copy(file_bytes.begin(), file_bytes.end(), key32.begin());
        return true;
    }
    randombytes_buf(key32.data(), key32.size());
    if (!write_file_bytes(key_path, key32.data(), key32.size())) {
        err = "failed to write settings key file";
        return false;
    }
    return true;
}

bool derive_passphrase_key(const char* passphrase,
                           const unsigned char* salt,
                           std::vector<unsigned char>& key32,
                           std::string& err) {
    if (!passphrase || !passphrase[0]) {
        err = "settings file requires POLYMECH_SETTINGS_PASSPHRASE";
        return false;
    }
    if (!ensure_sodium(err))
        return false;
    key32.resize(crypto_secretbox_KEYBYTES);
    if (crypto_pwhash(key32.data(),
                      key32.size(),
                      passphrase,
                      std::strlen(passphrase),
                      salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        err = "crypto_pwhash failed";
        return false;
    }
    return true;
}

bool decode_settings_raw_bytes(const fs::path& settings_file,
                               const std::vector<unsigned char>& raw,
                               std::string& out_json,
                               std::string& err) {
    out_json.clear();
    err.clear();
    if (raw.empty())
        return true;
    if (raw.size() >= sizeof(kLocalMagic) && std::memcmp(raw.data(), kLocalMagic, sizeof(kLocalMagic)) == 0) {
        if (raw.size() < sizeof(kLocalMagic) + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
            err = "encrypted settings truncated";
            return false;
        }
        std::vector<unsigned char> key;
        if (!load_or_create_secret_key(settings_file, key, err))
            return false;
        const unsigned char* nonce = raw.data() + sizeof(kLocalMagic);
        const unsigned char* cipher = nonce + crypto_secretbox_NONCEBYTES;
        const size_t cipher_len = raw.size() - sizeof(kLocalMagic) - crypto_secretbox_NONCEBYTES;
        std::vector<unsigned char> plain(cipher_len - crypto_secretbox_MACBYTES);
        if (crypto_secretbox_open_easy(plain.data(), cipher, cipher_len, nonce, key.data()) != 0) {
            err = "crypto_secretbox_open_easy failed (wrong key or corrupt file)";
            return false;
        }
        out_json.assign(reinterpret_cast<const char*>(plain.data()), plain.size());
        return true;
    }
    if (raw.size() >= sizeof(kPassphraseMagic) && std::memcmp(raw.data(), kPassphraseMagic, sizeof(kPassphraseMagic)) == 0) {
        constexpr size_t header_len = sizeof(kPassphraseMagic) + crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES;
        if (raw.size() < header_len + crypto_secretbox_MACBYTES) {
            err = "passphrase-encrypted settings truncated";
            return false;
        }
        const unsigned char* salt = raw.data() + sizeof(kPassphraseMagic);
        const unsigned char* nonce = salt + crypto_pwhash_SALTBYTES;
        const unsigned char* cipher = nonce + crypto_secretbox_NONCEBYTES;
        const size_t cipher_len = raw.size() - header_len;
        std::vector<unsigned char> key;
        if (!derive_passphrase_key(std::getenv(kPassphraseEnv), salt, key, err))
            return false;
        std::vector<unsigned char> plain(cipher_len - crypto_secretbox_MACBYTES);
        if (crypto_secretbox_open_easy(plain.data(), cipher, cipher_len, nonce, key.data()) != 0) {
            err = "crypto_secretbox_open_easy failed (wrong passphrase or corrupt file)";
            return false;
        }
        out_json.assign(reinterpret_cast<const char*>(plain.data()), plain.size());
        return true;
    }
    if (looks_like_json_plaintext(raw)) {
        out_json.assign(reinterpret_cast<const char*>(raw.data()), raw.size());
        return true;
    }
    err = "not encrypted settings and not valid plaintext JSON";
    return false;
}

bool encrypt_settings_blob(const fs::path& settings_file,
                           const std::string& utf8_json,
                           std::vector<unsigned char>& out,
                           std::string& err) {
    out.clear();
    if (!ensure_sodium(err))
        return false;
    std::vector<unsigned char> key;
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);
    if (const char* passphrase = std::getenv(kPassphraseEnv); passphrase && passphrase[0]) {
        unsigned char salt[crypto_pwhash_SALTBYTES];
        randombytes_buf(salt, sizeof salt);
        if (!derive_passphrase_key(passphrase, salt, key, err))
            return false;
        out.resize(sizeof(kPassphraseMagic) + sizeof salt + sizeof nonce + utf8_json.size() + crypto_secretbox_MACBYTES);
        unsigned char* p = out.data();
        std::memcpy(p, kPassphraseMagic, sizeof(kPassphraseMagic));
        p += sizeof(kPassphraseMagic);
        std::memcpy(p, salt, sizeof salt);
        p += sizeof salt;
        std::memcpy(p, nonce, sizeof nonce);
        p += sizeof nonce;
        crypto_secretbox_easy(p,
                              reinterpret_cast<const unsigned char*>(utf8_json.data()),
                              static_cast<unsigned long long>(utf8_json.size()),
                              nonce,
                              key.data());
        return true;
    }
    if (!load_or_create_secret_key(settings_file, key, err))
        return false;
    out.resize(sizeof(kLocalMagic) + sizeof nonce + utf8_json.size() + crypto_secretbox_MACBYTES);
    unsigned char* p = out.data();
    std::memcpy(p, kLocalMagic, sizeof(kLocalMagic));
    p += sizeof(kLocalMagic);
    std::memcpy(p, nonce, sizeof nonce);
    p += sizeof nonce;
    crypto_secretbox_easy(p,
                          reinterpret_cast<const unsigned char*>(utf8_json.data()),
                          static_cast<unsigned long long>(utf8_json.size()),
                          nonce,
                          key.data());
    return true;
}

bool read_json_file(const fs::path& p, json& out, std::string& err) {
    out = json::object();
    std::vector<unsigned char> raw;
    if (!read_file_bytes(p, raw) || raw.empty())
        return true;
    std::string utf8;
    if (!decode_settings_raw_bytes(p, raw, utf8, err))
        return false;
    try {
        out = json::parse(utf8.empty() ? "{}" : utf8);
        if (!out.is_object())
            out = json::object();
    } catch (const std::exception& e) {
        err = std::string("settings parse: ") + e.what();
        return false;
    }
    return true;
}

// Profile path: process override → profile-dir env override → platform default → cwd/config fallback.
fs::path settings_path() {
    if (g_profile_dir_override.has_value())
        return g_profile_dir_override.value() / "settings.json";
#if defined(__APPLE__)
    if (const char* d = std::getenv("POLYMECH_PM_IMAGE_PROFILE_DIR"); d && d[0])
        return media::path::path_from_utf8(d) / "settings.json";
    if (const char* home = std::getenv("HOME"); home && home[0]) {
        return media::path::path_from_utf8(home) / "Library/Application Support/PolyMech/pm-image/settings.json";
    }
#elif !defined(_WIN32)
    // Linux / Unix: single profile directory (~/.pm-image), same role as %APPDATA%\…\pm-image on Windows.
    // POLYMECH_PM_IMAGE_PROFILE_DIR overrides that directory (settings.json is always inside it).
    if (const char* d = std::getenv("POLYMECH_PM_IMAGE_PROFILE_DIR"); d && d[0])
        return media::path::path_from_utf8(d) / "settings.json";
    if (const char* home = std::getenv("HOME"); home && home[0])
        return media::path::path_from_utf8(home) / ".pm-image" / "settings.json";
#endif
    return fs::current_path() / "config/settings.json";
}

// Effective read path:
// 1) cwd/settings.json   (portable / project-local override)
// 2) profile path        (platform default store)
fs::path effective_read_path(const char** source_out = nullptr) {
    std::error_code ec;
    const fs::path cwd_p = fs::current_path() / "settings.json";
    if (fs::is_regular_file(cwd_p, ec) && !ec) {
        if (source_out) *source_out = "cwd";
        return cwd_p;
    }
    if (source_out) *source_out = "profile";
    return settings_path();
}

// One-time auto-import: seed the profile from cwd/settings.json when the profile is absent.
void maybe_auto_import_from_cwd() {
    static bool checked = false;
    if (checked) return;
    checked = true;

    const fs::path profile = settings_path();
    std::error_code ec;
    if (fs::exists(profile, ec) && !ec) return; // profile already exists

    const fs::path cwd_p = fs::current_path() / "settings.json";
    if (cwd_p == profile) return;
    if (!fs::is_regular_file(cwd_p, ec) || ec) return;

    json root;
    std::string err;
    if (!read_json_file(cwd_p, root, err)) return;
    if (!root.is_object()) return;

    std::vector<unsigned char> blob;
    const std::string utf8 = root.dump(2);
    if (!encrypt_settings_blob(profile, utf8, blob, err)) return;
    if (write_file_bytes(profile, blob.data(), blob.size()))
        logger::info(std::string("[settings] auto-imported profile from cwd: ") + media::path::path_to_utf8(cwd_p));
}

bool read_root(json& out, std::string& err) {
    out = json::object();
    err.clear();

    maybe_auto_import_from_cwd();

    const char* source = nullptr;
    const fs::path p = effective_read_path(&source);
    std::error_code ec;
    const bool exists = fs::exists(p, ec);
    // Missing profile/settings.json is normal first-run: callers use empty-object defaults.
    logger::debug(std::string("[settings] source=") + (source ? source : "?")
                  + " path=" + media::path::path_to_utf8(p)
                  + (exists ? " (found)" : " (not found — defaults)"));

    if (!exists) return true;
    if (!read_json_file(p, out, err)) {
        if (err.empty())
            err = "unable to open settings: " + media::path::path_to_utf8(p);
        return false;
    }
    return true;
}

} // namespace detail

void set_profile_dir_override(const fs::path& dir) {
    detail::g_profile_dir_override = fs::absolute(dir);
}

fs::path settings_pixelwiz_profile_json_path() {
    return detail::settings_path();
}

fs::path settings_pixelwiz_profile_dir() {
    return detail::settings_path().parent_path();
}

bool read_settings_profile_json(json& out, std::string& err) {
    return detail::read_root(out, err);
}

// Always reads from the profile (not cwd) — used by export and import operations.
bool read_profile_direct(json& out, std::string& err) {
    out = json::object();
    err.clear();
    const fs::path p = detail::settings_path();
    std::error_code ec;
    if (!fs::exists(p, ec) || ec) return true;
    return detail::read_json_file(p, out, err);
}

std::filesystem::path settings_codeedit_prefs_json_path() {
#if defined(__APPLE__)
    if (const char* home = std::getenv("HOME"); home && home[0]) {
        return media::path::path_from_utf8(home) / "Library/Application Support/CodeEdit/settings.json";
    }
#endif
    return {};
}

bool merge_settings_import_into_codeedit_prefs(const json& import_root, std::string& err) {
#if !defined(__APPLE__)
    (void)import_root;
    err.clear();
    return true;
#else
    err.clear();
    if (!import_root.is_object()) {
        err = "import root must be a JSON object";
        return false;
    }
    const fs::path path = settings_codeedit_prefs_json_path();
    if (path.empty()) {
        err = "HOME is not set; skipping CodeEdit prefs merge";
        return false;
    }
    json disk = json::object();
    if (fs::exists(path)) {
        std::ifstream ifs(path);
        if (!ifs) {
            err = "unable to open CodeEdit settings: " + media::path::path_to_utf8(path);
            return false;
        }
        try {
            ifs >> disk;
        } catch (const std::exception& e) {
            err = std::string("CodeEdit settings parse: ") + e.what();
            return false;
        }
        if (!disk.is_object()) {
            err = "CodeEdit settings root must be a JSON object";
            return false;
        }
    }
    static constexpr const char* k_keys[] = {
        "providers",
        "chat",
        "chat_web",
        "polymech_text_providers",
        "polymech_active_text_provider",
        "command_provider_overrides",
    };
    for (const char* k : k_keys) {
        if (import_root.contains(k)) {
            disk[k] = import_root[k];
        }
    }
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (ec) {
        err = "create_directories (CodeEdit): " + ec.message();
        return false;
    }
    try {
        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        if (!ofs) {
            err = "unable to write CodeEdit settings: " + media::path::path_to_utf8(path);
            return false;
        }
        ofs << disk.dump(2);
        if (!ofs.good()) {
            err = "write failed: " + media::path::path_to_utf8(path);
            return false;
        }
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
    return true;
#endif
}

bool write_settings_profile_json(const json& root, std::string& err) {
    err.clear();
    if (!root.is_object()) {
        err = "settings JSON root must be an object";
        return false;
    }
    const fs::path p = detail::settings_path();
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    if (ec) {
        err = "create_directories: " + ec.message();
        return false;
    }
    std::vector<unsigned char> blob;
    if (!detail::encrypt_settings_blob(p, root.dump(2), blob, err))
        return false;
    if (!detail::write_file_bytes(p, blob.data(), blob.size())) {
        err = "write failed: " + media::path::path_to_utf8(p);
        return false;
    }
    return true;
}

bool load_chat_provider(ChatProviderSettings& out, std::string& err) {
    out = ChatProviderSettings{};
    json root;
    if (!detail::read_root(root, err)) return false;
    if (!root.contains("chat") || !root["chat"].is_object()) return true;
    media::settings_schema::ChatJsonOptions options;
    options.clear_absent_media_fields = true;
    media::settings_schema::apply_chat_provider_json(root["chat"], out, options);
    return true;
}

namespace {

// Shared by legacy `merge_image_provider_credentials` and the portable provider map.
template <class ProviderMapT>
void merge_image_provider_credentials_impl(std::string&        provider,
                                           std::string&        api_key,
                                           std::string&        base_url,
                                           std::string&        default_model,
                                           const ProviderMapT& pm)
{
    // Provider must already be resolved from `chat.image_provider` (or tool/CLI); do not
    // substitute top-level `active_provider` here.
    if (provider.empty()) {
        return;
    }
    if (const auto it = pm.find(provider); it != pm.end()) {
        if (api_key.empty() && !it->second.api_key.empty()) {
            api_key = it->second.api_key;
        }
        if (base_url.empty() && !it->second.base_url.empty()) {
            base_url = it->second.base_url;
        }
    }
    (void)default_model;
}

} // namespace

bool load_providers(ProviderMap& out, std::string& err) {
    out.clear();
    json root;
    if (!detail::read_root(root, err)) return false;
    if (!root.contains("providers") || !root["providers"].is_object()) return true;
    for (auto it = root["providers"].begin(); it != root["providers"].end(); ++it) {
        const std::string name = it.key();
        const auto& v = it.value();
        ProviderEntry e;
        if (v.contains("api_key") && v["api_key"].is_string()) e.api_key = v["api_key"].get<std::string>();
        if (v.contains("base_url") && v["base_url"].is_string()) e.base_url = v["base_url"].get<std::string>();
        if (v.contains("default_model") && v["default_model"].is_string()) e.default_model = v["default_model"].get<std::string>();
        out[name] = std::move(e);
    }
    return true;
}

void merge_image_provider_credentials(
    std::string& provider,
    std::string& api_key,
    std::string& base_url,
    std::string& default_model,
    bool dry_run) {
    if (dry_run) {
        return;
    }
    ProviderMap pm;
    std::string err;
    if (!load_providers(pm, err)) {
        return;
    }
    merge_image_provider_credentials_impl(provider, api_key, base_url, default_model, pm);
}

} // namespace media::portable_settings
