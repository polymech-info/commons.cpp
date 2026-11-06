#include "settings_store.hpp"
#include "json/json_utils.hpp"
#include "win/settings_empty_override_dlg.hpp"
#include "constants.hpp"
#include "process/app_exe_directory.hpp"
#include "settings/app_storage.hpp"
#include "fs/path_sanitizer.hpp"
#include "string/string_utils.hpp"
#include "ui_defaults.hpp"
#include "settings/chat_settings_schema.hpp"
#include "llm/provider_tools.hpp"
#include "logging/pm_log.hpp"
#include "storage/secure_storage.hpp"
#include "fs/file_watcher.hpp"
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
#include "ipc/cmd_ipc.hpp"
#endif 

#include <sodium.h>

#include <Windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <deque>
#include <iostream>
#include <stdexcept>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iterator>
#include <shlobj.h>
#include <mutex>
#include <sstream>
#include <string_view>
#include <thread>

#ifndef POLYMECH_APP_TANIT_VIEWER
#define POLYMECH_APP_TANIT_VIEWER 0
#endif

#if POLYMECH_APP_TANIT_VIEWER
constexpr const char kDefaultUiWorkbenchId[] = "viewer";
#else
constexpr const char kDefaultUiWorkbenchId[] = "main";
#endif
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace {
#ifndef FEATURE_SECURE_STORAGE
#define FEATURE_SECURE_STORAGE 0
#endif

thread_local std::vector<const char*> g_settings_load_label_stack;
/// @c --ui-reset: ignore persisted workbench UI from settings.json for this process (see set_ui_reset_session).
bool g_ui_reset_session = false;

void (*g_settings_load_trace)(const char* reason) = nullptr;
void (*g_settings_persist_observer)(const char* context, const char* detail) = nullptr;

void report_settings_persist_failure(const char* context, const char* detail)
{
    const std::string ctx = (context && context[0]) ? context : "(unknown)";
    const std::string det = (detail && detail[0]) ? detail : "(no detail)";
    logger::warn("settings persist failed [" + ctx + "]: " + det);
    if (g_settings_persist_observer)
        g_settings_persist_observer(context, detail);
}

// Settings file read cache + optional CLI `--settings` read path (see set_settings_read_path_override).
std::mutex              g_settings_load_mutex;
std::optional<fs::path> g_settings_read_override;
std::optional<fs::path> g_config_dir_override;
enum class ConfigDirOverrideKind : std::uint8_t { None, Cli, Bundled, RegistryApply };
ConfigDirOverrideKind   g_config_dir_override_kind = ConfigDirOverrideKind::None;
std::string             g_settings_cache_json;
bool                    g_settings_cache_valid = false;
std::uint64_t           g_settings_flush_seq = 0;
std::shared_ptr<const nlohmann::json> g_settings_cache_root;
fs::path                g_settings_cache_sp;
fs::file_time_type      g_settings_cache_mtime{};
bool                    g_settings_cache_has_mtime = false;
std::string             g_command_cache_json;
bool                    g_command_cache_valid = false;
fs::path                g_command_cache_path;
fs::file_time_type      g_command_cache_mtime{};
bool                    g_command_cache_has_mtime = false;
bool                    g_settings_exe_auto_import_checked = false;
bool                    g_config_dir_auto_roaming_checked = false;

bool cwd_has_shadowing_settings_json()
{
    std::error_code ec;
    const fs::path cwd = fs::current_path(ec);
    if (ec || cwd.empty() || media::ui_defaults::is_under_install_dir(cwd))
        return false;
    const fs::path cwd_settings = cwd / "settings.json";
    return fs::is_regular_file(cwd_settings, ec) && !ec;
}

fs::path default_user_roaming_config_dir_unlocked()
{
    // Packaged (MSIX, no unvirtualizedResources): durable per-user settings live
    // in the package LocalState (== ApplicationData.Current.LocalFolder). Both
    // tanit.exe and tanit-cli.exe resolve the same path here. Portable builds
    // keep the historical %APPDATA%\<vendor>\<config-slug> roaming default.
    // Store MSIX only — sparse Explorer11 must not redirect to package LocalState.
    if (pm::appdata::uses_package_appdata())
        return pm::appdata::local_state();
    PWSTR path_tmp = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path_tmp)))
        return {};
    fs::path path(path_tmp);
    CoTaskMemFree(path_tmp);
    path /= pm::brand::k_config_subpath_w;
    return path;
}

bool resolve_config_dir_expression(const fs::path& candidate, fs::path& out, std::string* err = nullptr)
{
    out.clear();
    if (candidate.empty())
        return true;
    if (candidate.native().find(L"${") == std::wstring::npos) {
        out = candidate;
        return true;
    }

    // ${} self-check stays here so this helper does not pull command_variables.
    const std::string raw = media::path::path_to_utf8(candidate);
    std::string upper = raw;
    std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    if (upper.find("${CONFIG_DIR}") != std::string::npos
        || upper.find("${APP_DATA}") != std::string::npos
        || upper.find("${KNOWNFOLDER:CONFIG}") != std::string::npos) {
        if (err)
            *err = "config directory cannot reference itself";
        return false;
    }

    std::unordered_map<std::string, std::string> vars;
    vars["APP_ID"]      = pm::brand::k_app_id_u8;
    vars["APP_DISPLAY"] = pm::brand::k_app_display_u8;
    vars["APP_VENDOR"]  = pm::brand::k_vendor_u8;
    const fs::path exe = media::app::exe_executable();
    if (!exe.empty())
        vars["APP_EXE"] = media::path::path_to_utf8(exe);
    const fs::path exe_dir = media::app::exe_parent_directory();
    if (!exe_dir.empty()) {
        const std::string dir = media::path::path_to_utf8(exe_dir);
        vars["tanit"] = dir;
        vars["TANIT_ROOT"] = dir;
    }

    const std::string resolved = media::strutil::substitute_variables(
        raw,
        [&](std::string_view name) -> std::optional<std::string> {
            const std::string key(name);
            if (key.rfind("ENV:", 0) == 0) {
                char* value = nullptr;
                size_t len = 0;
                if (_dupenv_s(&value, &len, key.c_str() + 4) == 0 && value) {
                    std::string out_env(value);
                    free(value);
                    if (!out_env.empty())
                        return out_env;
                }
                return std::nullopt;
            }
            const auto it = vars.find(key);
            if (it == vars.end())
                return std::nullopt;
            return it->second;
        });
    if (resolved.find("${") != std::string::npos) {
        if (err)
            *err = "config directory contains an unresolved variable";
        return false;
    }
    out = media::path::path_from_utf8(resolved);
    return !out.empty();
}

constexpr const wchar_t kRegConfigDirectoryValue[] = L"ConfigDirectory";

bool is_valid_config_dir_candidate(const fs::path& candidate)
{
    if (candidate.empty())
        return false;
    if (media::ui_defaults::is_under_install_dir(candidate))
        return false;
    std::error_code ec;
    if (fs::exists(candidate, ec)) {
        if (ec)
            return false;
        return fs::is_directory(candidate, ec) && !ec;
    }
    return true;
}

fs::path read_config_dir_registry_value_unlocked()
{
    // Packaged builds do not rely on HKCU ConfigDirectory: without
    // unvirtualizedResources the hive is per-package virtualised and not
    // globally visible. Settings are file-based under package LocalState.
    if (pm::appdata::uses_package_appdata())
        return {};
    HKEY hkey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, pm::brand::k_reg_sw_vendor_config_w, 0, KEY_READ, &hkey) != ERROR_SUCCESS)
        return {};
    DWORD type = 0;
    DWORD cb   = 0;
    LSTATUS st = RegGetValueW(hkey, nullptr, kRegConfigDirectoryValue, RRF_RT_REG_SZ, &type, nullptr, &cb);
    if (st != ERROR_SUCCESS || cb < sizeof(wchar_t)) {
        RegCloseKey(hkey);
        return {};
    }
    std::wstring value(cb / sizeof(wchar_t), L'\0');
    st = RegGetValueW(hkey, nullptr, kRegConfigDirectoryValue, RRF_RT_REG_SZ, &type, value.data(), &cb);
    RegCloseKey(hkey);
    if (st != ERROR_SUCCESS)
        return {};
    while (!value.empty() && value.back() == L'\0')
        value.pop_back();
    if (value.empty())
        return {};
    fs::path dir;
    std::string resolve_err;
    if (!resolve_config_dir_expression(std::filesystem::path(value), dir, &resolve_err)) {
        logger::warn("ignoring invalid ConfigDirectory registry value: " + resolve_err);
        return {};
    }
    return is_valid_config_dir_candidate(dir) ? dir : fs::path{};
}

fs::path get_config_dir_unlocked()
{
    if (g_config_dir_override.has_value())
        return g_config_dir_override.value();
    if (const fs::path reg = read_config_dir_registry_value_unlocked(); !reg.empty())
        return reg;
    return default_user_roaming_config_dir_unlocked();
}

fs::path roaming_settings_json_path_unlocked()
{
    return get_config_dir_unlocked() / "settings.json";
}

fs::path roaming_command_json_path_unlocked()
{
    return get_config_dir_unlocked() / "commands.json";
}

void invalidate_settings_cache()
{
    g_settings_cache_valid     = false;
    g_settings_cache_json.clear();
    g_settings_cache_root.reset();
    g_settings_cache_has_mtime = false;
    g_settings_cache_sp.clear();
}

void invalidate_command_cache()
{
    g_command_cache_valid = false;
    g_command_cache_json.clear();
    g_command_cache_path.clear();
    g_command_cache_has_mtime = false;
}

bool settings_cache_is_stale_for_path(const fs::path& sp)
{
    if (!g_settings_cache_valid || g_settings_cache_sp != sp)
        return true;
    std::error_code ec;
    const bool exists = fs::exists(sp, ec) && !ec;
    // No recorded stamp means the cached document was missing. If it has since
    // appeared, or an existing file has no stamp, the cache must be re-read.
    if (!g_settings_cache_has_mtime)
        return exists;
    if (!exists)
        return true;
    const auto current_mtime = fs::last_write_time(sp, ec);
    if (ec)
        return true;
    return current_mtime != g_settings_cache_mtime;
}

bool command_cache_is_stale()
{
    if (!g_command_cache_valid)
        return false;
    std::error_code ec;
    const auto current_mtime = fs::last_write_time(g_command_cache_path, ec);
    if (!g_command_cache_has_mtime)
        return !ec; // a previously missing document appeared
    return ec || current_mtime != g_command_cache_mtime;
}
} // namespace

#include <nlohmann/json.hpp>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

namespace media::settings {

// media::json is the helper namespace. This alias is the nlohmann type.
using json = nlohmann::json;

bool defer_dock_container_load()
{
    return media::layout::LayoutStore::DeferDockContainerLoad();
}

SettingsLoadLabelScope::SettingsLoadLabelScope(const char* reason)
{
    if (reason && reason[0]) {
        g_settings_load_label_stack.push_back(reason);
        pushed_ = true;
    }
}

SettingsLoadLabelScope::~SettingsLoadLabelScope()
{
    if (pushed_ && !g_settings_load_label_stack.empty())
        g_settings_load_label_stack.pop_back();
}

namespace {

constexpr char kMagic[4] = {'P', 'M', 'E', '1'};
constexpr const char* kSettingsProfileUri = "pm://config/settings.json";
constexpr const char* kSettingsProfileSlug = "settings.json";
constexpr const char* kCommandConfigUri = "pm://config/commands.json";
constexpr const char* kCommandConfigSlug = "commands.json";
/** Must match installer / docs: %APPDATA%\<k_config_subpath_w> */
constexpr const wchar_t* kAppDataSubdir = pm::brand::k_config_subpath_w;
constexpr const wchar_t kKeyFileName[] = L".settings-key.dat";

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
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open())
        return false;
    if (len)
        ofs.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    return static_cast<bool>(ofs);
}

bool dpapi_protect(const std::vector<unsigned char>& plain, std::vector<unsigned char>& out) {
    DATA_BLOB in{(DWORD)plain.size(), const_cast<BYTE*>(plain.data())};
    DATA_BLOB out_blob{};
    if (!CryptProtectData(&in, pm::brand::k_settings_dpapi_label_w, nullptr, nullptr, nullptr, 0, &out_blob))
        return false;
    out.assign(out_blob.pbData, out_blob.pbData + out_blob.cbData);
    LocalFree(out_blob.pbData);
    return true;
}

bool dpapi_unprotect(const std::vector<unsigned char>& enc, std::vector<unsigned char>& plain) {
    DATA_BLOB in{(DWORD)enc.size(), const_cast<BYTE*>(enc.data())};
    DATA_BLOB out_blob{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out_blob))
        return false;
    plain.assign(out_blob.pbData, out_blob.pbData + out_blob.cbData);
    LocalFree(out_blob.pbData);
    return true;
}

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

bool load_or_create_secret_key(std::vector<unsigned char>& key32, std::string& err) {
    if (!ensure_sodium(err))
        return false;
    key32.resize(crypto_secretbox_KEYBYTES);

    const fs::path key_path = get_config_dir_unlocked() / kKeyFileName;
    std::vector<unsigned char> file_bytes;
    if (fs::exists(key_path)) {
        if (!read_file_bytes(key_path, file_bytes) || file_bytes.empty()) {
            err = "failed to read settings key file";
            return false;
        }
        std::vector<unsigned char> plain;
        if (!dpapi_unprotect(file_bytes, plain) || plain.size() != crypto_secretbox_KEYBYTES) {
            err = "CryptUnprotectData(settings key) failed";
            return false;
        }
        std::copy(plain.begin(), plain.end(), key32.begin());
        return true;
    }

    randombytes_buf(key32.data(), key32.size());
    std::vector<unsigned char> prot;
    if (!dpapi_protect(key32, prot)) {
        err = "CryptProtectData(settings key) failed";
        return false;
    }
    if (!write_file_bytes(key_path, prot.data(), prot.size())) {
        err = "failed to write settings key file";
        return false;
    }
    return true;
}

bool looks_like_json_plaintext(const std::vector<unsigned char>& raw) {
    size_t i = 0;
    while (i < raw.size() && std::isspace(static_cast<unsigned char>(raw[i])))
        ++i;
    return i < raw.size() && raw[i] == '{';
}

bool decode_settings_raw_bytes(const std::vector<unsigned char>& raw, std::string& out_json, std::string& err_out) {
    out_json.clear();
    err_out.clear();
    if (raw.empty())
        return true;
    std::string err;
    if (!ensure_sodium(err)) {
        err_out = err;
        return false;
    }
    if (raw.size() >= sizeof(kMagic) && std::memcmp(raw.data(), kMagic, sizeof(kMagic)) == 0) {
        if (raw.size() < sizeof(kMagic) + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
            err_out = "encrypted settings truncated";
            return false;
        }
        std::vector<unsigned char> key(crypto_secretbox_KEYBYTES);
        if (!load_or_create_secret_key(key, err)) {
            err_out = err;
            return false;
        }
        const unsigned char* nonce = raw.data() + sizeof(kMagic);
        const unsigned char* cipher = nonce + crypto_secretbox_NONCEBYTES;
        const size_t cipher_len = raw.size() - sizeof(kMagic) - crypto_secretbox_NONCEBYTES;
        if (cipher_len < crypto_secretbox_MACBYTES) {
            err_out = "encrypted settings ciphertext too short";
            return false;
        }
        std::vector<unsigned char> plain(cipher_len - crypto_secretbox_MACBYTES);
        if (crypto_secretbox_open_easy(plain.data(), cipher, cipher_len, nonce, key.data()) != 0) {
            err_out = "crypto_secretbox_open_easy failed (wrong key or corrupt file)";
            return false;
        }
        out_json.assign(reinterpret_cast<const char*>(plain.data()), plain.size());
        return true;
    }
    if (looks_like_json_plaintext(raw)) {
        out_json.assign(reinterpret_cast<const char*>(raw.data()), raw.size());
        return true;
    }
    err_out = "not PME1 encrypted and not valid plaintext JSON";
    return false;
}

bool encrypt_settings_blob(const std::string& utf8_json, std::vector<unsigned char>& out, std::string& err_out) {
    out.clear();
    err_out.clear();
    std::string err;
    if (!ensure_sodium(err)) {
        err_out = err;
        return false;
    }
    std::vector<unsigned char> key(crypto_secretbox_KEYBYTES);
    if (!load_or_create_secret_key(key, err)) {
        err_out = err;
        return false;
    }
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);
    const size_t msg_len = utf8_json.size();
    std::vector<unsigned char> cipher(msg_len + crypto_secretbox_MACBYTES);
    if (crypto_secretbox_easy(cipher.data(), reinterpret_cast<const unsigned char*>(utf8_json.data()), msg_len, nonce,
                              key.data()) != 0) {
        err_out = "crypto_secretbox_easy failed";
        return false;
    }
    out.reserve(sizeof(kMagic) + sizeof nonce + cipher.size());
    out.insert(out.end(), std::begin(kMagic), std::end(kMagic));
    out.insert(out.end(), nonce, nonce + sizeof nonce);
    out.insert(out.end(), cipher.begin(), cipher.end());
    return true;
}

// Temp file + MoveFileEx(REPLACE_EXISTING) so readers never see a truncated
// document and a crash mid-write leaves the previous version intact.
bool write_utf8_plaintext_file(const fs::path& p, const std::string& utf8, std::string& err_out) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    const fs::path tmp = p.parent_path()
        / (p.filename().wstring() + L".tmp-" + std::to_wstring(::GetCurrentProcessId()));
    {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) {
            err_out = "failed to open temp file for writing";
            return false;
        }
        ofs.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
        ofs.flush();
        if (!ofs) {
            err_out = "short write to temp file";
            ofs.close();
            fs::remove(tmp, ec);
            return false;
        }
    }
    if (!::MoveFileExW(tmp.c_str(), p.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        err_out = "atomic replace failed (win32 error " + std::to_string(::GetLastError()) + ")";
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

fs::path settings_profile_meta_path_for(const fs::path& config_dir) {
    return config_dir / "resources" / "documents" / (std::string(kSettingsProfileSlug) + ".doc.meta");
}

fs::path settings_profile_meta_path() {
    return settings_profile_meta_path_for(get_config_dir_unlocked());
}

fs::path command_config_meta_path()
{
    return get_config_dir_unlocked() / "resources" / "documents"
        / (std::string(kCommandConfigSlug) + ".doc.meta");
}

} // namespace

fs::path command_cache_watch_path()
{
#if FEATURE_SECURE_STORAGE
    return command_config_meta_path();
#else
    return roaming_command_json_path_unlocked();
#endif
}

namespace {

fs::path settings_read_path_unlocked()
{
#if FEATURE_SECURE_STORAGE
    return settings_profile_meta_path();
#else
    return roaming_settings_json_path_unlocked();
#endif
}

bool config_dir_has_settings_profile(const fs::path& config_dir) {
    std::error_code ec;
    if (fs::is_regular_file(settings_profile_meta_path_for(config_dir), ec) && !ec)
        return true;
    return fs::is_regular_file(config_dir / "settings.json", ec) && !ec;
}

bool settings_profile_document_exists() {
#if FEATURE_SECURE_STORAGE
    std::error_code ec;
    return fs::is_regular_file(settings_profile_meta_path(), ec) && !ec;
#else
    return false;
#endif
}

bool load_settings_profile_document(std::string& out_json, std::string& err_out) {
    out_json.clear();
    err_out.clear();
#if FEATURE_SECURE_STORAGE
    pm::storage::DocumentLoadPolicy policy;
    policy.require_signature = true;
    policy.require_encryption = true;
    policy.allowed_trust = {pm::model::TrustLevel::UserLocal};
    const auto paths = pm::storage::resolve_storage_paths(get_config_dir_unlocked());
    const auto loaded = pm::storage::load_or_import_seed_document(paths, kSettingsProfileUri, policy);
    if (!loaded.ok) {
        if (loaded.error.rfind("document not found:", 0) == 0)
            return true;
        err_out = "secure storage load failed: " + loaded.error;
        logger::warn(err_out);
        return false;
    }
    out_json.assign(reinterpret_cast<const char*>(loaded.document.data.data()), loaded.document.data.size());
    return true;
#else
    const fs::path sp = roaming_settings_json_path_unlocked();
    std::error_code ec;
    if (!fs::is_regular_file(sp, ec) || ec)
        return true;
    std::vector<unsigned char> raw;
    if (!read_file_bytes(sp, raw) || raw.empty())
        return true;
    return decode_settings_raw_bytes(raw, out_json, err_out);
#endif
}

bool load_command_config_document(std::string& out_json, std::string& err_out) {
    out_json.clear();
    err_out.clear();
#if FEATURE_SECURE_STORAGE
    pm::storage::DocumentLoadPolicy policy;
    policy.require_signature = true;
    policy.require_encryption = true;
    policy.allowed_trust = {pm::model::TrustLevel::UserLocal};
    const auto paths = pm::storage::resolve_storage_paths(get_config_dir_unlocked());
    const auto loaded = pm::storage::load_or_import_seed_document(paths, kCommandConfigUri, policy);
    if (!loaded.ok) {
        if (loaded.error.rfind("document not found:", 0) == 0)
            return true;
        err_out = loaded.error;
        return false;
    }
    out_json.assign(reinterpret_cast<const char*>(loaded.document.data.data()), loaded.document.data.size());
    return true;
#else
    const fs::path p = roaming_command_json_path_unlocked();
    std::error_code ec;
    if (!fs::is_regular_file(p, ec) || ec)
        return true;
    std::vector<unsigned char> raw;
    if (!read_file_bytes(p, raw) || raw.empty())
        return true;
    out_json.assign(reinterpret_cast<const char*>(raw.data()), raw.size());
    return true;
#endif
}

bool save_settings_profile_document(const std::string& utf8_json, std::string& err_out) {
    err_out.clear();
#if FEATURE_SECURE_STORAGE
    pm::storage::PutDocumentRequest req;
    req.uri = kSettingsProfileUri;
    req.type = pm::model::ResourceType::SettingsProfile;
    req.trust = pm::model::TrustLevel::UserLocal;
    req.version = "1";
    req.provider = "user";
    req.signer_id = "local-settings";
    req.encrypt = true;
    req.replace_vendor_seed = true;
    req.data.assign(utf8_json.begin(), utf8_json.end());
    const auto paths = pm::storage::resolve_storage_paths(get_config_dir_unlocked());
    const auto stored = pm::storage::put_document(paths, req);
    if (!stored.ok) {
        err_out = "secure storage put failed: " + stored.error;
        logger::error(err_out);
        return false;
    }
    // put_document already writes the local .sig before committing the index.
    // A second sign_document() replaces that file and races every concurrent reader.
    return true;
#else
    return write_utf8_plaintext_file(roaming_settings_json_path_unlocked(), utf8_json, err_out);
#endif
}

bool save_command_config_document(const std::string& utf8_json, std::string& err_out) {
    err_out.clear();
#if FEATURE_SECURE_STORAGE
    pm::storage::PutDocumentRequest req;
    req.uri = kCommandConfigUri;
    req.type = pm::model::ResourceType::CommandConfig;
    req.trust = pm::model::TrustLevel::UserLocal;
    req.version = "1";
    req.provider = "user";
    req.signer_id = "local-commands";
    req.encrypt = true;
    req.replace_vendor_seed = true;
    req.data.assign(utf8_json.begin(), utf8_json.end());
    const auto paths = pm::storage::resolve_storage_paths(get_config_dir_unlocked());
    const auto stored = pm::storage::put_document(paths, req);
    if (!stored.ok) {
        err_out = stored.error;
        return false;
    }
    return true;
#else
    return write_utf8_plaintext_file(roaming_command_json_path_unlocked(), utf8_json, err_out);
#endif
}

void maybe_auto_import_settings_from_cwd() {
    {
        std::lock_guard<std::mutex> lock(g_settings_load_mutex);
        if (g_settings_read_override || g_settings_exe_auto_import_checked)
            return;
        g_settings_exe_auto_import_checked = true;
    }

#if !FEATURE_SECURE_STORAGE
    return;
#else
    // Only import when the secure roaming profile has no settings yet.
    std::error_code ec;
    const fs::path live_settings = get_settings_json_path();
    if (settings_profile_document_exists())
        return;

    if (fs::is_regular_file(live_settings, ec) && !ec) {
        std::string err;
        if (media::settings::import_settings_file(live_settings, err)) {
            append_explorer_shell_correlation_log_utf8(
                "migrated legacy settings.json into secure settings profile: " + media::path::path_to_utf8(live_settings));
        } else if (!err.empty()) {
            append_explorer_shell_correlation_log_utf8(
                "legacy settings migration failed: " + media::path::path_to_utf8(live_settings) + ": " + err);
        }
        return;
    }

    // Check cwd for a settings.json to seed the profile from.
    if (!cwd_has_shadowing_settings_json())
        return;
    const fs::path cwd_settings = fs::current_path() / "settings.json";
    if (cwd_settings == live_settings)
        return;

    std::string err;
    if (media::settings::import_settings_file(cwd_settings, err)) {
        append_explorer_shell_correlation_log_utf8(
            "auto-imported settings.json from cwd: " + media::path::path_to_utf8(cwd_settings));
    } else if (!err.empty()) {
        append_explorer_shell_correlation_log_utf8(
            "settings auto-import from cwd failed: " + media::path::path_to_utf8(cwd_settings) + ": " + err);
    }
#endif
}

void maybe_auto_set_config_dir_from_exe_roaming_unlocked() {
    // `--config-dir` / `--settings` are explicit test overrides; leave them alone.
    if (g_config_dir_override || g_settings_read_override)
        return;
    if (g_config_dir_auto_roaming_checked)
        return;
    g_config_dir_auto_roaming_checked = true;

    // Packaged installs live under read-only WindowsApps; there is no writable
    // bundled `../roaming` profile beside the exe. Settings resolve to package
    // LocalState via default_user_roaming_config_dir_unlocked() instead.
    if (pm::appdata::uses_package_appdata())
        return;

    // Portable dist layout: exe/../roaming beside the install tree. When present,
    // always prefer it so an unzipped bundle is self-contained and does not touch
    // %APPDATA% or HKCU ConfigDirectory (existing installs stay untouched).
    const fs::path bundled = media::app::exe_bundled_roaming_directory();
    if (bundled.empty())
        return;
    const fs::path user_roaming = default_user_roaming_config_dir_unlocked();
    if (!user_roaming.empty() && bundled == user_roaming)
        return;
    if (!config_dir_has_settings_profile(bundled))
        return;

    g_config_dir_override = fs::absolute(bundled);
    g_config_dir_override_kind = ConfigDirOverrideKind::Bundled;
    invalidate_settings_cache();
    invalidate_command_cache();
    try {
        std::error_code ec;
        fs::create_directories(bundled / "logs", ec);
        const fs::path logf = bundled / "logs" / pm::brand::k_iexecute_log_basename_w;
        std::ofstream out(logf, std::ios::app | std::ios::binary);
        if (out) {
            SYSTEMTIME st{};
            GetLocalTime(&st);
            char ts[48]{};
            sprintf_s(ts, "%04u-%02u-%02u %02u:%02u:%02u  ", (unsigned)st.wYear, (unsigned)st.wMonth,
                      (unsigned)st.wDay, (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond);
            out << ts << "[pm-image] auto-selected bundled roaming config dir: " << media::path::path_to_utf8(bundled) << '\n';
        }
    } catch (...) {
    }
}

} // namespace

void maybe_auto_set_config_dir_from_exe_roaming() {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    maybe_auto_set_config_dir_from_exe_roaming_unlocked();
}

fs::path get_config_dir() {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    fs::path dir = get_config_dir_unlocked();
    if (dir.empty())
        throw std::runtime_error("SHGetKnownFolderPath(RoamingAppData) failed");
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

fs::path default_branded_config_dir() {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    return default_user_roaming_config_dir_unlocked();
}

fs::path read_config_dir_registry_value() {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    return read_config_dir_registry_value_unlocked();
}

bool save_config_dir_registry_value(const fs::path& dir, std::string& err) {
    err.clear();
    // Packaged builds keep settings file-based under package LocalState; the
    // HKCU ConfigDirectory override is a portable-only mechanism.
    if (pm::appdata::uses_package_appdata()) {
        if (dir.empty())
            return true; // clearing a non-existent override is a no-op success
        err = "config directory override is not available in a packaged install";
        return false;
    }
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);

    HKEY hkey = nullptr;
    LSTATUS st  = RegCreateKeyExW(HKEY_CURRENT_USER, pm::brand::k_reg_sw_vendor_config_w, 0, nullptr, 0,
                                 KEY_SET_VALUE, nullptr, &hkey, nullptr);
    if (st != ERROR_SUCCESS) {
        err = "RegCreateKeyExW(ConfigDirectory) failed";
        return false;
    }

    auto close_key = [&](bool ok) {
        RegCloseKey(hkey);
        return ok;
    };

    if (dir.empty()) {
        if (read_config_dir_registry_value_unlocked().empty()
            && g_config_dir_override_kind != ConfigDirOverrideKind::RegistryApply)
            return close_key(true);
        st = RegDeleteValueW(hkey, kRegConfigDirectoryValue);
        if (st != ERROR_SUCCESS && st != ERROR_FILE_NOT_FOUND) {
            err = "RegDeleteValueW(ConfigDirectory) failed";
            return close_key(false);
        }
        if (g_config_dir_override_kind == ConfigDirOverrideKind::RegistryApply) {
            g_config_dir_override.reset();
            g_config_dir_override_kind = ConfigDirOverrideKind::None;
        }
        invalidate_settings_cache();
        invalidate_command_cache();
        return close_key(true);
    }

    fs::path resolved_dir;
    if (!resolve_config_dir_expression(dir, resolved_dir, &err)) {
        if (err.empty())
            err = "invalid config directory expression";
        return close_key(false);
    }
    if (!is_valid_config_dir_candidate(resolved_dir)) {
        err = "invalid config directory path";
        return close_key(false);
    }

    std::error_code ec;
    fs::create_directories(resolved_dir, ec);
    const fs::path abs = fs::absolute(resolved_dir, ec);
    const fs::path current = read_config_dir_registry_value_unlocked();
    std::error_code equivalent_ec;
    if (!current.empty() && fs::equivalent(current, abs, equivalent_ec) && !equivalent_ec)
        return close_key(true);
    const std::wstring w = abs.wstring();
    st = RegSetValueExW(hkey, kRegConfigDirectoryValue, 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(w.c_str()),
                        static_cast<DWORD>((w.size() + 1) * sizeof(wchar_t)));
    if (st != ERROR_SUCCESS) {
        err = "RegSetValueExW(ConfigDirectory) failed";
        return close_key(false);
    }

    g_config_dir_override      = abs;
    g_config_dir_override_kind = ConfigDirOverrideKind::RegistryApply;
    invalidate_settings_cache();
    invalidate_command_cache();
    return close_key(true);
}

std::string config_dir_source_u8() {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    if (g_config_dir_override.has_value()) {
        switch (g_config_dir_override_kind) {
        case ConfigDirOverrideKind::Cli: return "cli";
        case ConfigDirOverrideKind::Bundled: return "bundled";
        case ConfigDirOverrideKind::RegistryApply: return "registry";
        case ConfigDirOverrideKind::None: break;
        }
    }
    if (!read_config_dir_registry_value_unlocked().empty())
        return "registry";
    return "default";
}

bool config_dir_settings_locked() {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    return g_config_dir_override_kind == ConfigDirOverrideKind::Cli
        || g_config_dir_override_kind == ConfigDirOverrideKind::Bundled;
}

fs::path get_models_dir() {
    return media::ui_defaults::effective_models_dir();
}

fs::path get_temp_dir() {
    // Rebuildable scratch lives in package LocalCache when packaged (== LocalCacheFolder);
    // portable builds keep get_config_dir()/temp under the roaming profile.
    const fs::path base = pm::appdata::uses_package_appdata() ? pm::appdata::local_cache() : get_config_dir();
    const fs::path dir = base / "temp";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

fs::path get_logs_dir() {
    // Logs are rebuildable -> LocalCache when packaged; portable builds keep
    // get_config_dir()/logs.
    const fs::path base = pm::appdata::uses_package_appdata() ? pm::appdata::local_cache() : get_config_dir();
    const fs::path dir = base / "logs";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

fs::path get_embedding_models_dir() {
    const fs::path exe = media::app::exe_parent_directory();
    if (exe.empty())
        return {};
    std::vector<fs::path> candidates;
    media::app::append_bundled_models_candidates(candidates, exe);
    std::error_code ec;
    for (const auto& candidate : candidates) {
        if (!fs::is_directory(candidate, ec) || ec)
            continue;
        const fs::path canon = fs::weakly_canonical(candidate, ec);
        if (!ec && !canon.empty())
            return canon;
    }
    return {};
}

fs::path get_user_desktop_dir() {
    PWSTR path_tmp = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_Desktop, 0, nullptr, &path_tmp)))
        return {};
    fs::path path(path_tmp);
    CoTaskMemFree(path_tmp);
    return path;
}

void set_config_dir_override(const fs::path& dir) {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    g_config_dir_override      = fs::absolute(dir);
    g_config_dir_override_kind = ConfigDirOverrideKind::Cli;
    invalidate_settings_cache();
    invalidate_command_cache();
}

fs::path get_settings_json_path() {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    return roaming_settings_json_path_unlocked();
}

fs::path get_command_json_path() {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    return roaming_command_json_path_unlocked();
}

fs::path get_daemon_json_path() {
    return get_config_dir() / "daemon.json";
}

static fs::path settings_effective_read_path_unlocked();

fs::path get_settings_effective_read_path() {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    return settings_effective_read_path_unlocked();
}

bool has_settings_read_path_override() {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    return g_settings_read_override.has_value();
}

void set_settings_read_path_override(const fs::path& absolute_path) {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    g_settings_read_override = absolute_path;
    invalidate_settings_cache();
}

void clear_settings_read_path_override() {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    g_settings_read_override.reset();
    invalidate_settings_cache();
}

namespace {
std::mutex g_explorer_correlation_log_mutex;
} // namespace

void append_explorer_shell_correlation_log_utf8(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_explorer_correlation_log_mutex);
    try {
        const fs::path logf = get_logs_dir() / pm::brand::k_iexecute_log_basename_w;
        std::ofstream      out(logf, std::ios::app | std::ios::binary);
        if (!out)
            return;
        SYSTEMTIME st{};
        GetLocalTime(&st);
        char ts[48]{};
        sprintf_s(ts, "%04u-%02u-%02u %02u:%02u:%02u  ", (unsigned)st.wYear, (unsigned)st.wMonth,
                  (unsigned)st.wDay, (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond);
        out << ts << "[pm-image] " << line << '\n';
        out.flush();
    } catch (...) {
    }
}

static bool parse_settings_root_or_err(const std::string& raw, const char* context, json& out, std::string& err);

// Install a loaded document only after it parses. A `{` followed by invalid
// JSON must not replace the last good root.
static bool settings_commit_loaded_cache(const fs::path& sp, const std::string& raw, std::string& err)
{
    json parsed;
    if (!parse_settings_root_or_err(raw, "load_settings_utf8", parsed, err))
        return false;
    g_settings_cache_json = raw;
    g_settings_cache_root = std::make_shared<const json>(std::move(parsed));
    g_settings_cache_valid = true;
    g_settings_cache_sp = sp;
    std::error_code mtec;
    g_settings_cache_mtime = fs::last_write_time(sp, mtec);
    g_settings_cache_has_mtime = !mtec;
    return true;
}

static bool load_settings_utf8_unlocked(std::string& out_json, std::string& err_out) {
    err_out.clear();
    out_json.clear();
    // Priority: 1) --settings override, 2) cwd/settings.json, 3) secure profile document.
    fs::path sp;
    const char* sp_source = "roaming profile";
    bool sp_selected_from_cwd = false;
    bool sp_selected_from_profile = false;
    if (g_settings_read_override.has_value()) {
        sp = g_settings_read_override.value();
        sp_source = "--settings override";
    } else if (cwd_has_shadowing_settings_json()) {
        sp = fs::current_path() / "settings.json";
        sp_source = "cwd";
        sp_selected_from_cwd = true;
    } else {
#if FEATURE_SECURE_STORAGE
        sp = settings_profile_meta_path();
        sp_source = "secure profile";
        sp_selected_from_profile = true;
#else
        sp = settings_read_path_unlocked();
        sp_source = "roaming profile";
#endif
    }
    const std::string previous_json = g_settings_cache_json;
    const auto previous_root = g_settings_cache_root;
    const fs::path previous_sp = g_settings_cache_sp;
    const auto previous_mtime = g_settings_cache_mtime;
    const bool previous_has_mtime = g_settings_cache_has_mtime;
    const bool had_good = g_settings_cache_valid && !previous_json.empty();
    auto restore_last_good = [&]() -> bool {
        if (!had_good || previous_sp != sp)
            return false;
        logger::warn(std::string("settings: reload failed, keeping last-good cache")
                     + (err_out.empty() ? std::string() : (": " + err_out)));
        out_json = previous_json;
        g_settings_cache_json = previous_json;
        g_settings_cache_root = previous_root;
        g_settings_cache_valid = true;
        g_settings_cache_sp = previous_sp;
        g_settings_cache_mtime = previous_mtime;
        g_settings_cache_has_mtime = previous_has_mtime;
        err_out.clear();
        return true;
    };
    if (g_settings_cache_valid) {
        if (g_settings_cache_sp == sp && !settings_cache_is_stale_for_path(sp)) {
            out_json = g_settings_cache_json;
            return true;
        }
        // Keep last-good until a reload actually succeeds.
        g_settings_cache_valid = false;
    }
    if (g_settings_load_trace) {
        const char* tag
            = g_settings_load_label_stack.empty() ? "(unlabeled)" : g_settings_load_label_stack.back();
        g_settings_load_trace(tag);
    }

    auto fallback_to_roaming_if_cwd = [&]() -> bool {
        if (!sp_selected_from_cwd)
            return false;
        sp = settings_read_path_unlocked();
#if FEATURE_SECURE_STORAGE
        sp_source = "secure profile (fallback from cwd)";
        sp_selected_from_profile = true;
#else
        sp_source = "roaming profile (fallback from cwd)";
#endif
        sp_selected_from_cwd = false;
        return true;
    };

    auto load_selected_profile = [&]() -> bool {
        if (!load_settings_profile_document(out_json, err_out))
            return restore_last_good();
        if (out_json.empty() && had_good && previous_sp == sp) {
            err_out = "settings document empty after reload";
            return restore_last_good();
        }
        logger::debug(std::string("settings: loaded from ") + sp_source + ": " + media::path::path_to_utf8(sp));
        if (!settings_commit_loaded_cache(sp, out_json, err_out))
            return restore_last_good();
        return true;
    };

    if (sp_selected_from_profile) {
        return load_selected_profile();
    }

    if (!fs::exists(sp)) {
        if (!fallback_to_roaming_if_cwd()) {
            out_json.clear();
            if (!settings_commit_loaded_cache(sp, out_json, err_out))
                return restore_last_good();
            return true;
        }
        return load_selected_profile();
    }

    std::vector<unsigned char> raw;
    if (!read_file_bytes(sp, raw) || raw.empty()) {
        if (!fallback_to_roaming_if_cwd()) {
            out_json.clear();
            if (!settings_commit_loaded_cache(sp, out_json, err_out))
                return restore_last_good();
            return true;
        }
        return load_selected_profile();
    }

    if (!decode_settings_raw_bytes(raw, out_json, err_out))
        return restore_last_good();
    logger::debug(std::string("settings: loaded from ") + sp_source + ": " + media::path::path_to_utf8(sp));
    if (!settings_commit_loaded_cache(sp, out_json, err_out))
        return restore_last_good();
    return true;
}

static fs::path settings_effective_read_path_unlocked()
{
    if (g_settings_read_override.has_value())
        return g_settings_read_override.value();
    if (cwd_has_shadowing_settings_json())
        return fs::current_path() / "settings.json";
    return settings_read_path_unlocked();
}

static std::string settings_load_labels_joined()
{
    if (g_settings_load_label_stack.empty())
        return "-";
    std::string out;
    for (std::size_t i = 0; i < g_settings_load_label_stack.size(); ++i) {
        if (i)
            out += '>';
        const char* label = g_settings_load_label_stack[i];
        out += (label && label[0]) ? label : "?";
    }
    return out;
}

static std::string settings_flush_origin(const char* context)
{
    return std::string("via=") + ((context && context[0]) ? context : "(unknown)")
        + " labels=" + settings_load_labels_joined()
        + " pid=" + std::to_string(static_cast<unsigned long>(::GetCurrentProcessId()))
        + " tid=" + std::to_string(static_cast<unsigned long>(::GetCurrentThreadId()));
}

static bool settings_key_uses_items_array(std::string_view key)
{
    return key == SettingsSubtreeKeys::bookmarks
        || key == SettingsSubtreeKeys::visited_files
        || key == SettingsSubtreeKeys::browser_history
        || key == SettingsSubtreeKeys::command_palette_recent
        || key == SettingsSubtreeKeys::explorer_presets
        || key == SettingsSubtreeKeys::xblox_artifacts;
}

static bool settings_key_is_guarded(std::string_view key)
{
    return key == "providers"
        || key == "chat"
        || key == "appearance"
        || key == "window"
        || key == "workbench"
        || key == "custom"
        || key == "agent_variables"
        || key == SettingsSubtreeKeys::bookmarks
        || key == SettingsSubtreeKeys::visited_files
        || key == SettingsSubtreeKeys::browser_history
        || key == SettingsSubtreeKeys::command_palette_recent
        || key == SettingsSubtreeKeys::explorer_presets
        || key == SettingsSubtreeKeys::xblox_artifacts
        || key == SettingsSubtreeKeys::chat_web
        || key == SettingsSubtreeKeys::security
        || key == SettingsSubtreeKeys::permissions
        || key == SettingsSubtreeKeys::scite;
}

static std::size_t settings_provider_filled_count(const json& v)
{
    if (!v.is_object())
        return 0;
    std::size_t n = 0;
    for (auto it = v.begin(); it != v.end(); ++it) {
        const json& row = it.value();
        if (!row.is_object())
            continue;
        const auto nonempty = [](const json& o, const char* field) {
            return o.contains(field) && o[field].is_string()
                && !o[field].get_ref<const std::string&>().empty();
        };
        if (nonempty(row, "api_key") || nonempty(row, "base_url") || nonempty(row, "default_model"))
            ++n;
    }
    return n;
}

static std::size_t settings_items_count(const json& v)
{
    if (v.is_array())
        return v.size();
    if (!v.is_object())
        return 0;
    const auto it = v.find("items");
    if (it == v.end() || !it->is_array())
        return 0;
    return it->size();
}

static std::string settings_value_summary(std::string_view key, const json* v)
{
    if (!v || v->is_null())
        return "null";
    if (v->is_discarded())
        return "discarded";
    if (v->is_array())
        return "array(n=" + std::to_string(v->size()) + ")";
    if (v->is_string())
        return "string(len=" + std::to_string(v->get_ref<const std::string&>().size()) + ")";
    if (v->is_boolean())
        return v->get<bool>() ? "true" : "false";
    if (v->is_number())
        return "number";
    if (!v->is_object())
        return v->type_name();
    if (key == "providers") {
        return "object(n=" + std::to_string(v->size())
            + ",filled=" + std::to_string(settings_provider_filled_count(*v)) + ")";
    }
    if (settings_key_uses_items_array(key))
        return "object(items=" + std::to_string(settings_items_count(*v)) + ")";
    return "object(n=" + std::to_string(v->size()) + ")";
}

static bool settings_value_is_corrupt(std::string_view key, const json& v)
{
    if (v.is_discarded())
        return true;
    if (key == "providers")
        return !v.is_null() && !v.is_object();
    if (settings_key_uses_items_array(key)) {
        if (v.is_null())
            return false;
        if (v.is_object()) {
            const auto it = v.find("items");
            return it != v.end() && !it->is_array();
        }
        return !v.is_array();
    }
    if (key == "chat" || key == "appearance" || key == "window" || key == "workbench"
        || key == "custom" || key == "agent_variables" || key == SettingsSubtreeKeys::chat_web
        || key == SettingsSubtreeKeys::security || key == SettingsSubtreeKeys::scite
        || key == SettingsSubtreeKeys::transfer_filters
        || key == SettingsSubtreeKeys::transfer_filter_presets
        || key == SettingsSubtreeKeys::transfer_options)
        return !v.is_null() && !v.is_object();
    if (key == SettingsSubtreeKeys::permissions)
        return !v.is_null() && !v.is_object() && !v.is_array();
    return false;
}

static bool settings_value_lost_substance(std::string_view key, const json& old_v, const json& new_v)
{
    if (old_v.is_null() || old_v.is_discarded())
        return false;
    if (key == "providers")
        return settings_provider_filled_count(old_v) > 0 && settings_provider_filled_count(new_v) == 0;
    if (settings_key_uses_items_array(key))
        return settings_items_count(old_v) > 0 && settings_items_count(new_v) == 0;
    if ((old_v.is_object() || old_v.is_array()) && !old_v.empty()) {
        if (new_v.is_null() || new_v.is_discarded())
            return true;
        if (new_v.type() != old_v.type())
            return true;
        return new_v.empty();
    }
    if (old_v.is_string() && !old_v.get_ref<const std::string&>().empty()) {
        return new_v.is_null() || new_v.is_discarded()
            || (new_v.is_string() && new_v.get_ref<const std::string&>().empty());
    }
    return false;
}

static void settings_collect_changed_keys(const json& previous, const json& next, std::vector<std::string>& out)
{
    out.clear();
    std::unordered_set<std::string> keys;
    if (previous.is_object()) {
        for (auto it = previous.begin(); it != previous.end(); ++it)
            keys.insert(it.key());
    }
    if (next.is_object()) {
        for (auto it = next.begin(); it != next.end(); ++it)
            keys.insert(it.key());
    }
    out.reserve(keys.size());
    for (const auto& key : keys) {
        const bool had = previous.is_object() && previous.contains(key);
        const bool has = next.is_object() && next.contains(key);
        if (had != has || (had && has && previous[key] != next[key]))
            out.push_back(key);
    }
    std::sort(out.begin(), out.end());
}

static std::string settings_join_keys(const std::vector<std::string>& keys)
{
    if (keys.empty())
        return "-";
    std::string out;
    for (std::size_t i = 0; i < keys.size(); ++i) {
        if (i)
            out += ',';
        out += keys[i];
    }
    return out;
}

struct SettingsGuardHit {
    std::string key;
    std::string before;
    std::string after;
    json restore;
    bool provider_api_key = false;
    std::string provider_name;
    std::string old_api_key;
};

static bool settings_root_prefers_dark(const json& previous)
{
    std::string theme = "system";
    if (previous.is_object() && previous.contains("appearance") && previous["appearance"].is_object())
        theme = previous["appearance"].value("theme", std::string{"system"});
    if (theme == "dark")
        return true;
    if (theme == "light")
        return false;
    DWORD light = 1;
    DWORD n = sizeof(light);
    if (::RegGetValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            L"AppsUseLightTheme",
            RRF_RT_REG_DWORD,
            nullptr,
            &light,
            &n)
        == ERROR_SUCCESS)
        return light == 0;
    return false;
}

static std::vector<SettingsGuardHit> settings_collect_empty_hits(
    const json& previous, const json& next)
{
    std::vector<SettingsGuardHit> hits;
    if (!previous.is_object() || !next.is_object())
        return hits;
    std::vector<std::string> keys;
    keys.reserve(previous.size());
    for (auto it = previous.begin(); it != previous.end(); ++it)
        keys.push_back(it.key());
    bool providers_key_hit = false;
    for (const auto& key : keys) {
        if (!settings_key_is_guarded(key))
            continue;
        const json& old_v = previous[key];
        const bool missing = !next.contains(key);
        const json* new_v = missing ? nullptr : &next[key];
        const bool corrupt = new_v && settings_value_is_corrupt(key, *new_v);
        const bool emptied = missing || (new_v && settings_value_lost_substance(key, old_v, *new_v));
        if (!corrupt && !emptied)
            continue;
        SettingsGuardHit hit;
        hit.key = key;
        hit.before = settings_value_summary(key, &old_v);
        hit.after = missing ? "missing" : settings_value_summary(key, new_v);
        hit.restore = old_v;
        hits.push_back(std::move(hit));
        if (key == "providers")
            providers_key_hit = true;
    }
    if (!providers_key_hit && previous.contains("providers") && previous["providers"].is_object()
        && next.contains("providers") && next["providers"].is_object()) {
        const json& old_p = previous["providers"];
        const json& new_p = next["providers"];
        for (auto it = old_p.begin(); it != old_p.end(); ++it) {
            if (!it.value().is_object())
                continue;
            const std::string old_key = it.value().value("api_key", std::string{});
            if (old_key.empty())
                continue;
            SettingsGuardHit hit;
            hit.provider_api_key = true;
            hit.provider_name = it.key();
            hit.old_api_key = old_key;
            hit.restore = it.value();
            if (!new_p.contains(it.key()) || !new_p[it.key()].is_object()) {
                hit.key = std::string("providers.") + it.key();
                hit.before = "row";
                hit.after = "missing";
                hits.push_back(std::move(hit));
                continue;
            }
            const std::string new_key = new_p[it.key()].value("api_key", std::string{});
            if (new_key.empty()) {
                // Tanit uses Zitadel OAuth sidecar (zitadel-oauth.json); logout clears the
                // mirrored api_key on purpose. Same for auth_mode oauth providers.
                const std::string auth_mode = it.value().value("auth_mode", std::string{});
                if (it.key() == "tanit" || auth_mode == "oauth")
                    continue;
                hit.key = std::string("providers.") + it.key() + ".api_key";
                hit.before = "set";
                hit.after = "empty";
                hits.push_back(std::move(hit));
            }
        }
    }
    return hits;
}

static void settings_apply_keep_existing(json& next, const std::vector<SettingsGuardHit>& hits)
{
    for (const auto& hit : hits) {
        if (hit.provider_api_key) {
            if (!next.contains("providers") || !next["providers"].is_object())
                next["providers"] = json::object();
            if (!next["providers"].contains(hit.provider_name) || !next["providers"][hit.provider_name].is_object())
                next["providers"][hit.provider_name] = hit.restore;
            else
                next["providers"][hit.provider_name]["api_key"] = hit.old_api_key;
            continue;
        }
        next[hit.key] = hit.restore;
    }
}

enum class SettingsAuditResult : std::uint8_t { Ok, Unchanged, InvalidRoot, Cancelled };

static SettingsAuditResult settings_guard_empty_or_corrupt(
    const json& previous, json& next, const char* context, std::string& err)
{
    auto hits = settings_collect_empty_hits(previous, next);
    if (hits.empty())
        return SettingsAuditResult::Ok;

    std::vector<SettingsEmptyOverrideItem> rows;
    rows.reserve(hits.size());
    for (const auto& hit : hits) {
        logger::error(std::string("settings empty/corrupt pending key=") + hit.key
                      + " before=" + hit.before + " after=" + hit.after
                      + " " + settings_flush_origin(context));
        rows.push_back(SettingsEmptyOverrideItem{hit.key, hit.before, hit.after});
    }

    const SettingsEmptyOverrideChoice choice = prompt_empty_settings_override(
        context, rows, settings_root_prefers_dark(previous));
    if (choice == SettingsEmptyOverrideChoice::Cancel) {
        err = "settings empty override cancelled";
        logger::warn(std::string("settings empty override cancelled ") + settings_flush_origin(context));
        return SettingsAuditResult::Cancelled;
    }
    if (choice == SettingsEmptyOverrideChoice::OverwriteEmpty) {
        logger::warn(std::string("settings empty override accepted by user n=")
                     + std::to_string(hits.size()) + " " + settings_flush_origin(context));
        return SettingsAuditResult::Ok;
    }
    settings_apply_keep_existing(next, hits);
    logger::debug(std::string("settings empty override kept existing n=")
                 + std::to_string(hits.size()) + " " + settings_flush_origin(context));
    return SettingsAuditResult::Ok;
}

static bool settings_key_differs(const json& previous, const json& next, const std::string& key)
{
    const bool had = previous.is_object() && previous.contains(key);
    const bool has = next.is_object() && next.contains(key);
    return had != has || (had && has && previous[key] != next[key]);
}

static SettingsAuditResult audit_settings_before_commit(
    const json& previous, json& next, const char* context, std::string& err,
    const std::vector<std::string>* only_keys = nullptr)
{
    if (next.is_discarded() || !next.is_object()) {
        err = std::string("settings root must be a JSON object (") + (context ? context : "commit") + ")";
        logger::error(err + " " + settings_flush_origin(context)
                      + " got=" + (next.is_discarded() ? "discarded" : next.type_name()));
        return SettingsAuditResult::InvalidRoot;
    }
    const SettingsAuditResult guarded = settings_guard_empty_or_corrupt(previous, next, context, err);
    if (guarded == SettingsAuditResult::Cancelled || guarded == SettingsAuditResult::InvalidRoot)
        return guarded;

    std::vector<std::string> changed;
    if (only_keys) {
        changed.reserve(only_keys->size());
        for (const auto& key : *only_keys) {
            if (settings_key_differs(previous, next, key))
                changed.push_back(key);
        }
    } else {
        settings_collect_changed_keys(previous, next, changed);
    }
    if (changed.empty())
        return SettingsAuditResult::Unchanged;

    const std::uint64_t seq = ++g_settings_flush_seq;
    logger::debug("settings flush #" + std::to_string(seq)
                 + " " + settings_flush_origin(context)
                 + " keys=" + settings_join_keys(changed));
    for (const auto& key : changed) {
        const json* before = (previous.is_object() && previous.contains(key)) ? &previous[key] : nullptr;
        const json* after = next.contains(key) ? &next[key] : nullptr;
        if (settings_key_is_guarded(key)
            || (after && settings_value_is_corrupt(key, *after))) {
            logger::debug("settings flush #" + std::to_string(seq) + " " + key
                         + " " + settings_value_summary(key, before)
                         + " -> " + (after ? settings_value_summary(key, after) : "missing"));
        }
    }
    return SettingsAuditResult::Ok;
}

static bool settings_on_disk_mtime_raced(const fs::path& path, const char* context)
{
    if (!g_settings_cache_has_mtime || path.empty())
        return false;
    std::error_code ec;
    const auto current = fs::last_write_time(path, ec);
    if (ec || current == g_settings_cache_mtime)
        return false;
    logger::error(std::string("settings race: on-disk mtime changed during mutate ")
                  + settings_flush_origin(context) + " path=" + media::path::path_to_utf8(path));
    return true;
}

static bool is_plain_settings_json_path(const fs::path& path)
{
#if FEATURE_SECURE_STORAGE
    if (path == settings_profile_meta_path())
        return false;
    const std::string name = media::path::path_to_utf8(path.filename());
    if (name.size() >= 9 && name.compare(name.size() - 9, 9, ".doc.meta") == 0)
        return false;
#endif
    std::error_code ec;
    return fs::is_regular_file(path, ec) && !ec;
}

static bool commit_settings_utf8_unlocked(const std::string& utf8_json, std::string& err_out, const char* context,
                                          json* live_root = nullptr)
{
    err_out.clear();
    const fs::path loaded_from = g_settings_cache_valid
        ? g_settings_cache_sp
        : settings_effective_read_path_unlocked();

    if (is_plain_settings_json_path(loaded_from)) {
        logger::debug(std::string("settings: writing plain file ") + media::path::path_to_utf8(loaded_from)
                      + (context ? std::string(" via ") + context : ""));
        if (!write_utf8_plaintext_file(loaded_from, utf8_json, err_out)) {
            if (err_out.empty())
                err_out = "failed to write settings file: " + media::path::path_to_utf8(loaded_from);
            report_settings_persist_failure(context, err_out.c_str());
            return false;
        }
    } else if (!save_settings_profile_document(utf8_json, err_out)) {
        if (err_out.empty())
            err_out = "failed to write secure settings profile";
        report_settings_persist_failure(context, err_out.c_str());
        return false;
    }

    g_settings_cache_json    = utf8_json;
    g_settings_cache_valid   = true;
    g_settings_cache_sp      = loaded_from;
    if (live_root && live_root->is_object()) {
        g_settings_cache_root = std::make_shared<const json>(std::move(*live_root));
    } else if (utf8_json.empty()) {
        g_settings_cache_root = std::make_shared<const json>(json::object());
    } else {
        json parsed = media::json::try_parse(utf8_json);
        g_settings_cache_root = parsed.is_object()
            ? std::make_shared<const json>(std::move(parsed))
            : nullptr;
    }
    {
        std::error_code mtec;
        g_settings_cache_mtime     = fs::last_write_time(g_settings_cache_sp, mtec);
        g_settings_cache_has_mtime = !mtec;
    }
    logger::debug("settings flush #" + std::to_string(g_settings_flush_seq)
                 + " committed path=" + media::path::path_to_utf8(g_settings_cache_sp)
                 + " bytes=" + std::to_string(utf8_json.size())
                 + " " + settings_flush_origin(context));
    return true;
}

static bool parse_settings_root_or_err(const std::string& raw, const char* context, json& out, std::string& err)
{
    out = json::object();
    if (raw.empty())
        return true;
    try {
        out = json::parse(raw);
    } catch (const std::exception& e) {
        err = std::string("settings JSON parse failed (") + context + "): " + e.what();
        logger::error(err);
        report_settings_persist_failure(context, err.c_str());
        return false;
    }
    if (!out.is_object()) {
        err = std::string("settings root must be a JSON object (") + context + ")";
        logger::error(err);
        report_settings_persist_failure(context, err.c_str());
        return false;
    }
    return true;
}

static bool load_settings_root_unlocked(
    SettingsRootSnapshot& out_root, std::string& err, const char* context)
{
    out_root.reset();
    err.clear();
    if (g_settings_cache_valid && g_settings_cache_root) {
        if (!settings_cache_is_stale_for_path(g_settings_cache_sp)) {
            out_root = g_settings_cache_root;
            return true;
        }
        // Do not drop last-good here. load_settings_utf8_unlocked retries the
        // document and restores the previous cache if the reload is mid-write.
    }
    std::string raw;
    if (!load_settings_utf8_unlocked(raw, err))
        return false;
    if (!g_settings_cache_root) {
        json root;
        if (!parse_settings_root_or_err(raw, context, root, err))
            return false;
        g_settings_cache_root = std::make_shared<const json>(std::move(root));
        logger::trace("settings: parsed root cache once bytes=" + std::to_string(raw.size()));
    }
    out_root = g_settings_cache_root;
    return true;
}

static std::recursive_mutex g_settings_commit_mu;
static thread_local int g_batch_depth = 0;
static thread_local bool g_batch_ok = true;
static thread_local bool g_batch_full_walk = false;
static thread_local const char* g_batch_context = "settings_batch";
static thread_local json g_batch_prev = json::object();
static thread_local json g_batch_next = json::object();
static thread_local std::vector<std::string> g_batch_touched;

// strict dump() throws type_error.316 on invalid UTF-8. That exception leaves
// VisitedFilesSaveLoop's std::thread and std::terminate aborts the process.
static bool dump_settings_pretty(const json& doc, std::string& out, std::string& err, const char* context)
{
    try {
        out = doc.dump(2, ' ', false, json::error_handler_t::replace);
        return true;
    } catch (const std::exception& e) {
        err = std::string("settings dump failed (") + (context && context[0] ? context : "settings")
            + "): " + e.what();
        logger::error(err);
        report_settings_persist_failure(context, err.c_str());
        return false;
    }
}

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT

enum class SettingsIpcCommit { NotActive, Ok, Fail };

static bool                         g_settings_ipc_active = false;
static bool                         g_settings_ipc_is_owner = false;
static std::uint64_t                g_settings_ipc_epoch = 0;
static std::uint64_t                g_settings_ipc_revision = 0;
static std::uint64_t                g_settings_ipc_persist_seq = 0;
static HANDLE                       g_settings_ipc_mutex = nullptr;
static fs::path                     g_settings_ipc_owner_json;
static ::media::cmd_ipc::InstanceDescriptor g_settings_ipc_self;
static ::media::cmd_ipc::InstanceDescriptor g_settings_ipc_owner_desc;
static std::atomic<bool>            g_settings_ipc_stop{false};
static std::mutex                   g_settings_ipc_persist_mu;
static std::condition_variable      g_settings_ipc_persist_cv;
static bool                         g_settings_ipc_persist_pending = false;
static bool                         g_settings_ipc_persist_flush = false;
static std::chrono::steady_clock::time_point g_settings_ipc_persist_due;
static std::thread                  g_settings_ipc_persist_thread;
static std::unique_ptr<media::FileWatcher> g_settings_ipc_watcher;
struct SettingsIpcGuidOutcome {
    std::uint64_t epoch = 0;
    std::uint64_t revision = 0;
    std::string level;
};

static std::mutex                   g_settings_ipc_guid_mu;
static std::deque<std::string>      g_settings_ipc_guid_q;
static std::unordered_map<std::string, SettingsIpcGuidOutcome> g_settings_ipc_guid_done;
static std::mutex                   g_settings_persist_write_mu;
static std::atomic<std::int64_t>    g_settings_ipc_pending{0};
// Even while a settings document is stable, odd while this owner is replacing it.
// A watcher read that overlaps a replace has seen the previous profile.
static std::atomic<std::uint64_t>   g_settings_disk_write_gen{0};
// Last revision actually written by settings_ipc_persist_now. Live edits above
// this are only in memory; the file still holds the previous owner's profile.
static std::uint64_t                g_settings_ipc_persisted_revision = 0;
static json                         g_settings_ipc_last_keys = json::array();

static std::string settings_ipc_env_str(const char* name)
{
    char buf[256];
    const DWORD n = GetEnvironmentVariableA(name, buf, static_cast<DWORD>(sizeof(buf)));
    if (n == 0 || n >= sizeof(buf))
        return {};
    return std::string(buf, n);
}

static int settings_ipc_env_int(const char* name, int fallback)
{
    const std::string v = settings_ipc_env_str(name);
    if (v.empty())
        return fallback;
    return std::atoi(v.c_str());
}

static std::uint64_t settings_ipc_now_ms()
{
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return static_cast<std::uint64_t>(u.QuadPart / 10000ull);
}

static std::wstring settings_ipc_mutex_name_for(const fs::path& config_dir)
{
    const std::string utf = ::media::path::path_to_utf8(config_dir);
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : utf) {
        h ^= c;
        h *= 1099511628211ull;
    }
    std::wostringstream os;
    os << L"Local\\PolyMech.Tanit.SettingsOwner." << std::hex << std::setw(16) << std::setfill(L'0')
       << static_cast<unsigned long long>(h);
    return os.str();
}

static std::string settings_ipc_new_guid()
{
    static std::atomic<std::uint64_t> seq{0};
    char buf[80];
    std::snprintf(buf, sizeof(buf), "%08lx-%016llx-%08llx",
                  static_cast<unsigned long>(GetCurrentProcessId()),
                  static_cast<unsigned long long>(GetTickCount64()),
                  static_cast<unsigned long long>(++seq));
    return buf;
}

static bool settings_ipc_guid_find(const std::string& guid, SettingsIpcGuidOutcome& out)
{
    if (guid.empty())
        return false;
    std::lock_guard<std::mutex> lock(g_settings_ipc_guid_mu);
    const auto it = g_settings_ipc_guid_done.find(guid);
    if (it == g_settings_ipc_guid_done.end())
        return false;
    out = it->second;
    return true;
}

static void settings_ipc_guid_store(const std::string& guid, const SettingsIpcGuidOutcome& outcome)
{
    if (guid.empty())
        return;
    std::lock_guard<std::mutex> lock(g_settings_ipc_guid_mu);
    if (!g_settings_ipc_guid_done.count(guid))
        g_settings_ipc_guid_q.push_back(guid);
    g_settings_ipc_guid_done[guid] = outcome;
    while (g_settings_ipc_guid_q.size() > 256) {
        g_settings_ipc_guid_done.erase(g_settings_ipc_guid_q.front());
        g_settings_ipc_guid_q.pop_front();
    }
}

static void settings_ipc_stamp_meta(json& root)
{
    if (!root.is_object())
        root = json::object();
    root["_meta"] = json{
        {"writer_epoch", g_settings_ipc_epoch},
        {"revision", g_settings_ipc_revision},
        {"writer_pid", static_cast<std::int64_t>(GetCurrentProcessId())},
    };
}

static void settings_ipc_install_cache(json& next, const std::string& dumped)
{
    g_settings_cache_json = dumped;
    g_settings_cache_valid = true;
    if (next.is_object())
        g_settings_cache_root = std::make_shared<const json>(next);
    else
        g_settings_cache_root = std::make_shared<const json>(json::object());
    // Keep sp/mtime in sync with the installed root. Without this, a peer that
    // never disk-loaded (empty sp) fails settings_cache_is_stale_for_path and
    // reloads the OLD disk document over the just-applied IPC root while the
    // owner is still inside its debounce window. Capturing the current disk
    // mtime here means the cache stays fresh until the owner actually commits.
    const fs::path sp = settings_effective_read_path_unlocked();
    if (!sp.empty()) {
        g_settings_cache_sp = sp;
        std::error_code mtec;
        g_settings_cache_mtime = fs::last_write_time(sp, mtec);
        g_settings_cache_has_mtime = !mtec;
    }
}

static void settings_ipc_write_owner_pointer()
{
    try {
        std::error_code ec;
        fs::create_directories(g_settings_ipc_owner_json.parent_path(), ec);
        json j{
            {"pid", g_settings_ipc_self.pid},
            {"id", g_settings_ipc_self.id},
            {"epoch", g_settings_ipc_epoch},
            {"revision", g_settings_ipc_revision},
            {"endpoint", g_settings_ipc_self.endpoint},
        };
        std::ofstream ofs(g_settings_ipc_owner_json, std::ios::binary | std::ios::trunc);
        if (ofs)
            ofs << j.dump(2);
    } catch (...) {
    }
}

static void settings_ipc_remove_owner_pointer_if_ours()
{
    std::error_code ec;
    if (!fs::exists(g_settings_ipc_owner_json, ec))
        return;
    try {
        std::ifstream ifs(g_settings_ipc_owner_json, std::ios::binary);
        if (!ifs)
            return;
        std::ostringstream ss;
        ss << ifs.rdbuf();
        const auto j = media::json::try_parse(ss.str());
        if (!j.is_object())
            return;
        if (j.value("pid", int64_t{0}) != g_settings_ipc_self.pid)
            return;
        fs::remove(g_settings_ipc_owner_json, ec);
    } catch (...) {
    }
}

static void settings_ipc_apply_deleted(json& root, const json& deleted)
{
    if (!root.is_object() || !deleted.is_array())
        return;
    for (const auto& key : deleted) {
        if (!key.is_string())
            continue;
        const std::string name = key.get<std::string>();
        if (name.empty() || name == "_meta")
            continue;
        root.erase(name);
    }
}

static void settings_ipc_apply_fields(json& root, const json& fields)
{
    if (!root.is_object())
        root = json::object();
    if (!fields.is_object())
        return;
    for (auto it = fields.begin(); it != fields.end(); ++it) {
        if (it.key() == "_meta")
            continue;
        // A null field is a deletion. Assigning it used to leave a JSON null in
        // the profile instead of removing the key.
        if (it.value().is_null())
            root.erase(it.key());
        else
            root[it.key()] = it.value();
    }
}

static void settings_ipc_apply_merge(json& root, const std::string& key, const json& fields)
{
    if (!root.is_object())
        root = json::object();
    if (key.empty() || !fields.is_object())
        return;
    if (!root.contains(key) || !root[key].is_object())
        root[key] = json::object();
    for (auto it = fields.begin(); it != fields.end(); ++it)
        root[key][it.key()] = it.value();
}

static void settings_ipc_apply_append_history(json& root, const json& item)
{
    constexpr const char* k = SettingsSubtreeKeys::browser_history;
    if (!root.is_object())
        root = json::object();
    if (!root.contains(k) || !root[k].is_object())
        root[k] = json{{"version", 1}, {"items", json::array()}};
    json& doc = root[k];
    if (!doc.contains("items") || !doc["items"].is_array())
        doc["items"] = json::array();
    json& items = doc["items"];
    const std::string url = item.is_object() ? item.value("url", std::string{}) : std::string{};
    json next = json::array();
    if (item.is_object() && !url.empty())
        next.push_back(item);
    for (const auto& el : items) {
        if (el.is_object() && !url.empty() && el.value("url", std::string{}) == url)
            continue;
        next.push_back(el);
        if (next.size() >= kBrowserHistoryMaxItems)
            break;
    }
    items = std::move(next);
    doc["version"] = 1;
}

static bool settings_ipc_apply_op(json& root, const json& req)
{
    const std::string op = req.value("op", std::string{});
    if (op == "set") {
        const std::string key = req.value("key", std::string{});
        if (key.empty() || key == "_meta")
            return false;
        root[key] = req.contains("value") ? req["value"] : json();
        return true;
    }
    if (op == "set_many") {
        const json& fields = req.contains("fields") ? req["fields"] : json::object();
        settings_ipc_apply_fields(root, fields);
        if (req.contains("deleted"))
            settings_ipc_apply_deleted(root, req["deleted"]);
        return true;
    }
    if (op == "merge") {
        settings_ipc_apply_merge(root, req.value("key", std::string{}),
                                 req.contains("value") ? req["value"] : json::object());
        return true;
    }
    if (op == "delete") {
        const std::string key = req.value("key", std::string{});
        if (key.empty() || key == "_meta")
            return false;
        root.erase(key);
        return true;
    }
    if (op == "append_history") {
        settings_ipc_apply_append_history(root, req.contains("value") ? req["value"] : json::object());
        return true;
    }
    if (op == "replace_root") {
        json repl = req.contains("value") ? req["value"] : json::object();
        if (!repl.is_object())
            return false;
        root = std::move(repl);
        return true;
    }
    return false;
}

static json settings_ipc_fields_for_keys(const json& root, const std::vector<std::string>& keys)
{
    json fields = json::object();
    for (const auto& key : keys) {
        if (key == "_meta")
            continue;
        if (root.is_object() && root.contains(key))
            fields[key] = root[key];
    }
    return fields;
}

static json settings_ipc_deleted_keys(const json& root, const std::vector<std::string>& keys)
{
    json deleted = json::array();
    for (const auto& key : keys) {
        if (key == "_meta")
            continue;
        if (!root.is_object() || !root.contains(key))
            deleted.push_back(key);
    }
    return deleted;
}

static void settings_ipc_broadcast(const std::string& action, const json& extra)
{
    const auto self_pid = g_settings_ipc_self.pid;
    for (const auto& inst : ::media::cmd_ipc::list_instances()) {
        if (inst.pid == self_pid)
            continue;
        nlohmann::json reply;
        std::string ipc_err;
        if (!::media::cmd_ipc::send_action(inst, action, extra, reply, ipc_err, 500)) {
            logger::warn("settings ipc broadcast failed pid=" + std::to_string(inst.pid)
                         + " action=" + action
                         + (ipc_err.empty() ? std::string() : (": " + ipc_err)));
        }
    }
}

static int settings_ipc_debounce_ms()
{
    const int v = settings_ipc_env_int("TANIT_SETTINGS_DEBOUNCE_MS", 750);
    return v < 0 ? 750 : v;
}

static void settings_ipc_schedule_persist(bool flush_now)
{
    std::lock_guard<std::mutex> lock(g_settings_ipc_persist_mu);
    g_settings_ipc_persist_pending = true;
    if (flush_now) {
        g_settings_ipc_persist_flush = true;
        g_settings_ipc_persist_due = std::chrono::steady_clock::now();
    } else {
        g_settings_ipc_persist_due =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(settings_ipc_debounce_ms());
    }
    g_settings_ipc_persist_cv.notify_all();
}

static bool settings_ipc_persist_now(const char* context, std::uint64_t* wrote_revision = nullptr)
{
    std::lock_guard<std::mutex> write_lock(g_settings_persist_write_mu);
    const int delay_ms = settings_ipc_env_int("TANIT_SETTINGS_PERSIST_DELAY_MS", 0);
    if (delay_ms > 0)
        Sleep(static_cast<DWORD>(delay_ms));

    // Odd generation for the whole replace, including the temp file the watcher sees.
    g_settings_disk_write_gen.fetch_add(1, std::memory_order_acq_rel);
    struct WriteGenGuard {
        ~WriteGenGuard() { g_settings_disk_write_gen.fetch_add(1, std::memory_order_acq_rel); }
    } write_gen_guard;

    json next;
    std::string dumped;
    std::string err;
    {
        std::lock_guard<std::mutex> lock(g_settings_load_mutex);
        const std::uint64_t rev = g_settings_ipc_revision;
        if (g_settings_cache_root && g_settings_cache_root->is_object())
            next = *g_settings_cache_root;
        else
            next = json::object();
        settings_ipc_stamp_meta(next);
        if (!dump_settings_pretty(next, dumped, err, context))
            return false;
        const bool ok = commit_settings_utf8_unlocked(dumped, err, context, &next);
        if (ok) {
            ++g_settings_ipc_persist_seq;
            g_settings_ipc_persisted_revision = rev;
            if (wrote_revision)
                *wrote_revision = rev;
        }
        if (!ok && !err.empty())
            logger::warn(std::string("settings owner persist failed: ") + err);
        return ok;
    }
}

static void settings_ipc_persist_thread_main()
{
    std::unique_lock<std::mutex> lk(g_settings_ipc_persist_mu);
    while (!g_settings_ipc_stop.load()) {
        if (!g_settings_ipc_persist_pending) {
            g_settings_ipc_persist_cv.wait(
                lk, [] { return g_settings_ipc_stop.load() || g_settings_ipc_persist_pending; });
            continue;
        }
        const auto due = g_settings_ipc_persist_due;
        if (g_settings_ipc_persist_cv.wait_until(lk, due, [] {
                return g_settings_ipc_stop.load() || g_settings_ipc_persist_flush;
            })) {
            if (g_settings_ipc_stop.load())
                break;
        }
        const bool flush = g_settings_ipc_persist_flush;
        g_settings_ipc_persist_pending = false;
        g_settings_ipc_persist_flush = false;
        lk.unlock();
        const bool wrote = settings_ipc_persist_now("settings_owner_debounce");
        if (wrote)
            settings_ipc_write_owner_pointer();
        lk.lock();
        if (!wrote && !g_settings_ipc_stop.load()) {
            g_settings_ipc_persist_pending = true;
            g_settings_ipc_persist_flush = g_settings_ipc_persist_flush || flush;
            if (!g_settings_ipc_persist_flush)
                g_settings_ipc_persist_due =
                    std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
            logger::warn("settings owner persist failed; keeping dirty state");
        }
    }
}

static bool settings_watch_change_is_profile(const media::FileChange& ch)
{
    if (ch.kind == media::FileChangeKind::OverflowRescan)
        return true;
    const std::string name = ::media::path::path_to_utf8(ch.path.filename());
    if (name.empty())
        return false;
    if (name == kSettingsProfileSlug)
        return true;
    const std::string prefix = std::string(kSettingsProfileSlug) + ".";
    if (name.compare(0, prefix.size(), prefix) != 0)
        return false;
    // settings.json.doc.tmp is the atomic-replace temp. Opening the live blob
    // while it exists still returns the previous profile.
    return name.size() < 4 || name.compare(name.size() - 4, 4, ".tmp") != 0;
}

static bool settings_watch_batch_touches_profile(const std::vector<media::FileChange>& batch)
{
    for (const auto& ch : batch) {
        if (settings_watch_change_is_profile(ch))
            return true;
    }
    return false;
}

static bool settings_load_disk_root(json& out, std::string& err)
{
    out = json::object();
    std::string raw;
#if FEATURE_SECURE_STORAGE
    if (!load_settings_profile_document(raw, err))
        return false;
#else
    const fs::path sp = roaming_settings_json_path_unlocked();
    std::vector<unsigned char> bytes;
    if (!read_file_bytes(sp, bytes) || bytes.empty())
        return true;
    if (!decode_settings_raw_bytes(bytes, raw, err))
        return false;
#endif
    if (raw.empty())
        return true;
    return parse_settings_root_or_err(raw, "settings_owner_watch", out, err);
}

static bool settings_root_body_equal(const json& a, const json& b)
{
    if (!a.is_object() || !b.is_object())
        return false;
    auto body_has = [](const json& root, const json& other) {
        for (auto it = root.begin(); it != root.end(); ++it) {
            if (it.key() == "_meta")
                continue;
            if (!other.contains(it.key()) || other[it.key()] != it.value())
                return false;
        }
        return true;
    };
    return body_has(a, b) && body_has(b, a);
}

// True when the on-disk profile was produced by this owner and does not carry
// a revision past the live root. That includes the echo of our own flush.
static bool settings_disk_is_own_or_older(const json& disk)
{
    const json meta = (disk.contains("_meta") && disk["_meta"].is_object())
        ? disk["_meta"] : json::object();
    const auto disk_epoch = meta.value("writer_epoch", std::uint64_t{0});
    const auto disk_rev = meta.value("revision", std::uint64_t{0});
    const auto disk_pid = meta.value("writer_pid", static_cast<std::int64_t>(0));
    const auto self_pid = static_cast<std::int64_t>(GetCurrentProcessId());
    if (disk_pid == self_pid && disk_rev <= g_settings_ipc_revision)
        return true;
    return disk_epoch == g_settings_ipc_epoch && disk_rev <= g_settings_ipc_revision;
}

static void settings_ipc_on_watch(std::vector<media::FileChange> batch)
{
    if (!g_settings_ipc_is_owner || g_settings_ipc_stop.load())
        return;
    // commands.json, mcp.json, and home.page share this folder. They are not
    // settings edits, including when this process wrote them.
    if (!settings_watch_batch_touches_profile(batch))
        return;

    // Sample before the read. persist_now holds the generation odd across the
    // replace, and a read started on the even value finishes against a new one.
    const auto write_gen = g_settings_disk_write_gen.load(std::memory_order_acquire);
    if (write_gen % 2 != 0)
        return;

    json disk;
    std::string err;
    if (!settings_load_disk_root(disk, err) || !disk.is_object())
        return;
    if (g_settings_disk_write_gen.load(std::memory_order_acquire) != write_gen)
        return;

    json next;
    std::vector<std::string> keys{"*"};
    bool publish = false;
    {
        std::lock_guard<std::mutex> lock(g_settings_load_mutex);
        if (g_settings_disk_write_gen.load(std::memory_order_acquire) != write_gen)
            return;
        // Same body: echo of our flush, or a second notification for a profile
        // we already adopted. Leave the live root alone.
        if (g_settings_cache_root && settings_root_body_equal(*g_settings_cache_root, disk))
            return;
        if (settings_disk_is_own_or_older(disk))
            return;
        // The file still has the previous process's epoch until our debounce
        // lands. Adopting it here drops keyboard_shortcuts and the shutdown
        // flush then writes that reverted root.
        if (g_settings_ipc_revision > g_settings_ipc_persisted_revision) {
            logger::debug("settings watch: kept live root (disk is behind unpersisted revision "
                          + std::to_string(g_settings_ipc_revision) + ")");
            return;
        }

        next = disk;
        ++g_settings_ipc_revision;
        settings_ipc_stamp_meta(next);
        std::string dumped;
        if (!dump_settings_pretty(next, dumped, err, "settings_owner_watch"))
            return;
        settings_ipc_install_cache(next, dumped);
        g_settings_ipc_last_keys = keys;
        publish = true;
    }
    if (!publish)
        return;
    settings_ipc_broadcast("settings_reloaded", json{
        {"epoch", g_settings_ipc_epoch},
        {"revision", g_settings_ipc_revision},
        {"keys", keys},
        {"root", next},
    });
}

static void settings_ipc_start_watcher()
{
    fs::path folder;
#if FEATURE_SECURE_STORAGE
    folder = get_config_dir() / "resources" / "documents";
#else
    folder = get_config_dir();
#endif
    std::error_code ec;
    fs::create_directories(folder, ec);
    g_settings_ipc_watcher = std::make_unique<media::FileWatcher>(settings_ipc_on_watch);
    (void)g_settings_ipc_watcher->Watch(folder, false);
}

static bool settings_ipc_become_owner(::media::cmd_ipc::InstanceDescriptor& desc, bool abandoned)
{
    g_settings_ipc_is_owner = true;
    g_settings_ipc_active = true;
    g_settings_ipc_epoch = settings_ipc_now_ms();
    g_settings_ipc_revision = 0;
    g_settings_ipc_self = desc;
    desc.settings_owner = true;
    desc.settings_epoch = g_settings_ipc_epoch;
    desc.settings_revision = g_settings_ipc_revision;
    g_settings_ipc_stop.store(false);
    {
        std::lock_guard<std::mutex> lock(g_settings_load_mutex);
        // REVERT startup-perf: this always reloaded the profile and pretty-dumped
        // it (settings.json is ~267KB) on the UI thread inside command-IPC start,
        // before the first ShowWindow. A warm cache already has the document.
        // writer_epoch is stamped on the next owner flush (settings_ipc_stamp_meta
        // in the persist path). The owner pointer file still records the epoch.
        // Restore the load + dump_settings_pretty + settings_ipc_install_cache
        // block below if peers need _meta.writer_epoch in the cached document
        // before the first save.
        if (!(g_settings_cache_valid && g_settings_cache_root && g_settings_cache_root->is_object())) {
            SettingsRootSnapshot snap;
            std::string err;
            if (load_settings_root_unlocked(snap, err, "settings_owner_claim") && snap && snap->is_object()) {
                json next = *snap;
                settings_ipc_stamp_meta(next);
                std::string dumped;
                if (dump_settings_pretty(next, dumped, err, "settings_owner_claim"))
                    settings_ipc_install_cache(next, dumped);
            }
        }
    }
    settings_ipc_write_owner_pointer();
    g_settings_ipc_persist_pending = false;
    g_settings_ipc_persist_flush = false;
    if (!g_settings_ipc_persist_thread.joinable())
        g_settings_ipc_persist_thread = std::thread(settings_ipc_persist_thread_main);
    if (!g_settings_ipc_watcher)
        settings_ipc_start_watcher();
    logger::debug(std::string("settings ipc: this process is owner epoch=")
                  + std::to_string(g_settings_ipc_epoch)
                  + (abandoned ? " (mutex abandoned)" : ""));
    return true;
}

static bool settings_ipc_connect_owner(::media::cmd_ipc::InstanceDescriptor& desc)
{
    ::media::cmd_ipc::InstanceDescriptor owner{};
    bool found = false;
    std::error_code ec;
    if (fs::is_regular_file(g_settings_ipc_owner_json, ec) && !ec) {
        try {
            std::ifstream ifs(g_settings_ipc_owner_json, std::ios::binary);
            std::ostringstream ss;
            ss << ifs.rdbuf();
            const auto j = media::json::try_parse(ss.str());
            const std::string id = j.value("id", std::string{});
            if (!id.empty() && ::media::cmd_ipc::find_instance(id, owner))
                found = true;
        } catch (...) {
        }
    }
    if (!found) {
        for (const auto& inst : ::media::cmd_ipc::list_instances()) {
            if (inst.settings_owner && inst.pid != desc.pid) {
                owner = inst;
                found = true;
                break;
            }
        }
    }
    if (!found || owner.pid == desc.pid)
        return false;

    nlohmann::json reply;
    std::string err;
    if (!::media::cmd_ipc::send_action(owner, "settings_snapshot", {}, reply, err, 3000)
        || reply.value("type", std::string{}) != "settings_snapshot") {
        logger::warn(std::string("settings ipc: snapshot failed: ") + err);
        return false;
    }
    g_settings_ipc_is_owner = false;
    g_settings_ipc_active = true;
    g_settings_ipc_owner_desc = owner;
    g_settings_ipc_self = desc;
    g_settings_ipc_epoch = reply.value("epoch", std::uint64_t{0});
    g_settings_ipc_revision = reply.value("revision", std::uint64_t{0});
    desc.settings_owner = false;
    desc.settings_epoch = g_settings_ipc_epoch;
    desc.settings_revision = g_settings_ipc_revision;
    if (reply.contains("root") && reply["root"].is_object()) {
        json next = reply["root"];
        std::string dumped;
        std::string dump_err;
        if (dump_settings_pretty(next, dumped, dump_err, "settings_ipc_snapshot")) {
            std::lock_guard<std::mutex> lock(g_settings_load_mutex);
            settings_ipc_install_cache(next, dumped);
        }
    }
    logger::debug("settings ipc: connected to owner pid=" + std::to_string(owner.pid));
    return true;
}

static bool settings_ipc_pull_snapshot(std::string& err)
{
    err.clear();
    if (g_settings_ipc_is_owner || !g_settings_ipc_active)
        return false;
    nlohmann::json reply;
    if (!::media::cmd_ipc::send_action(
            g_settings_ipc_owner_desc, "settings_snapshot", {}, reply, err, 3000)
        || reply.value("type", std::string{}) != "settings_snapshot"
        || !reply.contains("root") || !reply["root"].is_object()) {
        if (err.empty())
            err = reply.value("error", std::string{"settings snapshot failed"});
        return false;
    }
    json next = reply["root"];
    std::string dumped;
    std::string dump_err;
    if (!dump_settings_pretty(next, dumped, dump_err, "settings_ipc_snapshot")) {
        err = dump_err;
        return false;
    }
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    settings_ipc_install_cache(next, dumped);
    g_settings_ipc_epoch = reply.value("epoch", g_settings_ipc_epoch);
    g_settings_ipc_revision = reply.value("revision", g_settings_ipc_revision);
    return true;
}

static bool settings_ipc_flush_owner(std::string& err)
{
    err.clear();
    nlohmann::json reply;
    std::string ipc_err;
    if (!::media::cmd_ipc::send_action(
            g_settings_ipc_owner_desc, "settings_flush", {}, reply, ipc_err, 5000)) {
        err = ipc_err.empty() ? "settings flush failed" : ipc_err;
        return false;
    }
    if (reply.value("type", std::string{}) == "settings_ack"
        && reply.value("level", std::string{}) == "persisted") {
        g_settings_ipc_epoch = reply.value("epoch", g_settings_ipc_epoch);
        g_settings_ipc_revision = reply.value("revision", g_settings_ipc_revision);
        return true;
    }
    err = reply.value("error", std::string{"settings persist failed"});
    return false;
}

static SettingsIpcCommit settings_ipc_try_commit(json& next,
                                                 const std::vector<std::string>& changed_keys,
                                                 const char* context,
                                                 std::string& err,
                                                 bool flush_now)
{
    if (!g_settings_ipc_active)
        return SettingsIpcCommit::NotActive;
    std::vector<std::string> keys;
    keys.reserve(changed_keys.size());
    for (const auto& k : changed_keys) {
        if (k != "_meta")
            keys.push_back(k);
    }
    if (keys.empty())
        return SettingsIpcCommit::Ok;

    const json fields = settings_ipc_fields_for_keys(next, keys);
    const json deleted = settings_ipc_deleted_keys(next, keys);

    if (g_settings_ipc_is_owner) {
        std::uint64_t revision = 0;
        std::uint64_t epoch = 0;
        {
            std::lock_guard<std::mutex> lock(g_settings_load_mutex);
            const auto saved_revision = g_settings_ipc_revision;
            ++g_settings_ipc_revision;
            settings_ipc_stamp_meta(next);
            std::string dumped;
            if (!dump_settings_pretty(next, dumped, err, context)) {
                g_settings_ipc_revision = saved_revision;
                return SettingsIpcCommit::Fail;
            }
            settings_ipc_install_cache(next, dumped);
            revision = g_settings_ipc_revision;
            epoch = g_settings_ipc_epoch;
            g_settings_ipc_last_keys = keys;
        }
        g_settings_ipc_self.settings_revision = revision;
        json extra{
            {"epoch", epoch},
            {"revision", revision},
            {"keys", keys},
            {"op", "set_many"},
            {"fields", fields},
            {"deleted", deleted},
        };
        settings_ipc_broadcast("settings_changed", extra);
        if (flush_now) {
            if (!settings_ipc_persist_now(context)) {
                settings_ipc_schedule_persist(true);
                err = "settings persist failed";
                return SettingsIpcCommit::Fail;
            }
        } else {
            settings_ipc_schedule_persist(false);
        }
        return SettingsIpcCommit::Ok;
    }

    std::string guid = settings_ipc_new_guid();
    if (const std::string forced = settings_ipc_env_str("TANIT_SETTINGS_MUTATE_GUID"); !forced.empty())
        guid = forced;
    json extra{
        {"guid", guid},
        {"base_epoch", g_settings_ipc_epoch},
        {"base_revision", g_settings_ipc_revision},
        {"op", "set_many"},
        {"fields", fields},
        {"deleted", deleted},
        {"durability", flush_now ? "flush_now" : "debounced"},
    };
    nlohmann::json reply;
    std::string ipc_err;
    bool sent = false;
    ++g_settings_ipc_pending;
    for (int attempt = 0; attempt < 3 && !sent; ++attempt) {
        sent = ::media::cmd_ipc::send_action(
            g_settings_ipc_owner_desc, "settings_mutate", extra, reply, ipc_err, 1000);
    }
    --g_settings_ipc_pending;
    if (!sent) {
        err = std::string("settings ipc mutate failed: ")
            + (ipc_err.empty() ? "no acknowledgement" : ipc_err);
        logger::warn(err);
        return SettingsIpcCommit::Fail;
    }
    const std::string type = reply.value("type", std::string{});
    if (type == "settings_conflict") {
        std::string snap_err;
        (void)settings_ipc_pull_snapshot(snap_err);
        err = reply.value("error", std::string{"settings conflict"});
        logger::warn(std::string("settings ipc mutate conflict: ") + err);
        return SettingsIpcCommit::Fail;
    }
    if (type != "settings_ack") {
        if (reply.value("level", std::string{}) == "dirty") {
            std::string snap_err;
            (void)settings_ipc_pull_snapshot(snap_err);
        }
        err = reply.value("error", ipc_err.empty() ? std::string{"settings ipc mutate rejected"} : ipc_err);
        logger::warn(std::string("settings ipc mutate rejected: ") + err);
        return SettingsIpcCommit::Fail;
    }
    g_settings_ipc_epoch = reply.value("epoch", g_settings_ipc_epoch);
    g_settings_ipc_revision = reply.value("revision", g_settings_ipc_revision);
    std::string snap_err;
    if (!settings_ipc_pull_snapshot(snap_err)) {
        std::lock_guard<std::mutex> lock(g_settings_load_mutex);
        json root = (g_settings_cache_root && g_settings_cache_root->is_object())
            ? json(*g_settings_cache_root) : json::object();
        json synth{
            {"op", "set_many"},
            {"fields", fields},
            {"deleted", deleted},
        };
        if (settings_ipc_apply_op(root, synth)) {
            std::string dumped;
            std::string dump_err;
            if (dump_settings_pretty(root, dumped, dump_err, context))
                settings_ipc_install_cache(root, dumped);
        }
    }
    if (flush_now && reply.value("level", std::string{}) != "persisted") {
        if (!settings_ipc_flush_owner(err))
            return SettingsIpcCommit::Fail;
    }
    return SettingsIpcCommit::Ok;
}

static bool settings_ipc_context_flush_now(const char* context)
{
    if (!context || !context[0])
        return false;
    const std::string_view c(context);
    return c.find("ui_close") != std::string_view::npos
        || c == "save_settings_utf8"
        || c.find("import") != std::string_view::npos;
}

#endif // FEATURE_COMMAND_IPC_NEXT

static bool commit_audited_root(const json& previous, json& next, const char* context, std::string& err,
                                const std::vector<std::string>* only_keys)
{
    const SettingsAuditResult audit = audit_settings_before_commit(previous, next, context, err, only_keys);
    if (audit == SettingsAuditResult::Cancelled)
        return false;
    if (audit == SettingsAuditResult::InvalidRoot) {
        report_settings_persist_failure(context, err.c_str());
        return false;
    }
    if (audit == SettingsAuditResult::Unchanged) {
        logger::debug(std::string("settings flush skipped (unchanged) ") + settings_flush_origin(context));
        return true;
    }
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    {
        std::vector<std::string> changed;
        if (only_keys) {
            for (const auto& key : *only_keys) {
                if (settings_key_differs(previous, next, key))
                    changed.push_back(key);
            }
        } else {
            settings_collect_changed_keys(previous, next, changed);
        }
        const SettingsIpcCommit ipc = settings_ipc_try_commit(
            next, changed, context, err, settings_ipc_context_flush_now(context));
        if (ipc == SettingsIpcCommit::Ok)
            return true;
        if (ipc == SettingsIpcCommit::Fail)
            return false;
    }
#endif
    std::string dumped;
    if (!dump_settings_pretty(next, dumped, err, context))
        return false;
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    if (settings_on_disk_mtime_raced(
            g_settings_cache_valid ? g_settings_cache_sp : settings_effective_read_path_unlocked(),
            context)) {
        SettingsRootSnapshot snap;
        std::string load_err;
        if (!load_settings_root_unlocked(snap, load_err, context) || !snap || !snap->is_object()) {
            err = load_err.empty() ? "settings changed on disk during save" : load_err;
            return false;
        }
        json latest = *snap;
        std::vector<std::string> keys;
        if (only_keys)
            keys = *only_keys;
        else
            settings_collect_changed_keys(previous, next, keys);
        for (const auto& key : keys) {
            if (key == "_meta")
                continue;
            if (next.contains(key))
                latest[key] = next[key];
            else
                latest.erase(key);
        }
        next = std::move(latest);
        if (!dump_settings_pretty(next, dumped, err, context))
            return false;
    }
    return commit_settings_utf8_unlocked(dumped, err, context, &next);
}

void begin_settings_commit_batch(const char* context)
{
    if (g_batch_depth++ > 0)
        return;
    g_settings_commit_mu.lock();
    g_batch_context = (context && context[0]) ? context : "settings_batch";
    g_batch_ok = true;
    g_batch_full_walk = false;
    g_batch_touched.clear();
    maybe_auto_import_settings_from_cwd();
    std::string err;
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    SettingsRootSnapshot snapshot;
    if (!load_settings_root_unlocked(snapshot, err, g_batch_context)) {
        g_batch_ok = false;
        g_batch_prev = json::object();
        g_batch_next = json::object();
        if (!err.empty())
            report_settings_persist_failure(g_batch_context, err.c_str());
        return;
    }
    g_batch_prev = snapshot ? *snapshot : json::object();
    g_batch_next = g_batch_prev;
}

bool end_settings_commit_batch()
{
    if (g_batch_depth <= 0)
        return true;
    if (--g_batch_depth > 0)
        return g_batch_ok;
    struct UnlockCommit {
        ~UnlockCommit() { g_settings_commit_mu.unlock(); }
    } unlock_commit;
    const bool ok = g_batch_ok;
    const char* context = g_batch_context;
    const bool full_walk = g_batch_full_walk;
    std::vector<std::string> touched = std::move(g_batch_touched);
    json previous = std::move(g_batch_prev);
    json next = std::move(g_batch_next);
    g_batch_prev = json::object();
    g_batch_next = json::object();
    g_batch_touched.clear();
    g_batch_full_walk = false;
    if (!ok)
        return false;
    std::string err;
    const std::vector<std::string>* only = full_walk ? nullptr : &touched;
    return commit_audited_root(previous, next, context, err, only);
}

bool mutate_settings_root(const char* context, const SettingsRootMutator& mutator, std::string& err,
                          const char* touched_key)
{
    if (g_batch_depth > 0) {
        if (!g_batch_ok)
            return false;
        json trial = g_batch_next;
        if (!mutator(trial, err)) {
            g_batch_ok = false;
            return false;
        }
        g_batch_next = std::move(trial);
        if (touched_key && touched_key[0])
            g_batch_touched.emplace_back(touched_key);
        else
            g_batch_full_walk = true;
        return true;
    }

    std::lock_guard<std::recursive_mutex> commit_lock(g_settings_commit_mu);
    maybe_auto_import_settings_from_cwd();
    SettingsRootSnapshot snapshot;
    json j;
    {
        std::lock_guard<std::mutex> lock(g_settings_load_mutex);
        if (g_settings_cache_valid && settings_cache_is_stale_for_path(g_settings_cache_sp)) {
            logger::warn(std::string("settings race: cache stale before mutate ")
                         + settings_flush_origin(context)
                         + " path=" + media::path::path_to_utf8(g_settings_cache_sp));
        }
        if (!load_settings_root_unlocked(snapshot, err, context)) {
            if (!err.empty())
                report_settings_persist_failure(context, err.c_str());
            return false;
        }
        j = snapshot ? *snapshot : json::object();
        if (!mutator(j, err))
            return false;
    }
    const json empty = json::object();
    const json& previous = snapshot ? *snapshot : empty;
    std::vector<std::string> only;
    const std::vector<std::string>* only_keys = nullptr;
    if (touched_key && touched_key[0]) {
        only.emplace_back(touched_key);
        only_keys = &only;
    }
    return commit_audited_root(previous, j, context, err, only_keys);
}

bool load_settings_utf8(std::string& out_json, std::string& err_out) {
    maybe_auto_import_settings_from_cwd();
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    return load_settings_utf8_unlocked(out_json, err_out);
}

bool load_settings_root(SettingsRootSnapshot& out_root, std::string& err_out)
{
    maybe_auto_import_settings_from_cwd();
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    return load_settings_root_unlocked(out_root, err_out, "load_settings_root");
}

bool load_command_json_utf8(std::string& out_json, std::string& err_out) {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    err_out.clear();
    out_json.clear();
    if (g_command_cache_valid && !command_cache_is_stale()) {
        out_json = g_command_cache_json;
        return true;
    }
    const std::string previous = g_command_cache_json;
    const bool had_good = g_command_cache_valid && !previous.empty();
    const fs::path previous_path = g_command_cache_path;
    const auto previous_mtime = g_command_cache_mtime;
    const bool previous_has_mtime = g_command_cache_has_mtime;

    bool loaded = false;
#if FEATURE_SECURE_STORAGE
    loaded = load_command_config_document(out_json, err_out);
#else
    const fs::path p = roaming_command_json_path_unlocked();
    if (!fs::exists(p)) {
        loaded = true;
    } else {
        std::vector<unsigned char> raw;
        if (!read_file_bytes(p, raw)) {
            err_out = "failed to read " + media::path::path_to_utf8(p);
        } else {
            out_json.assign(reinterpret_cast<const char*>(raw.data()), raw.size());
            loaded = true;
        }
    }
#endif
    if (loaded && out_json.empty() && had_good) {
        err_out = err_out.empty() ? "commands document empty after reload" : err_out;
        loaded = false;
    }
    if (!loaded) {
        if (had_good) {
            logger::warn(std::string("commands: reload failed, keeping last-good cache")
                         + (err_out.empty() ? std::string() : (": " + err_out)));
            out_json = previous;
            g_command_cache_json = previous;
            g_command_cache_valid = true;
            g_command_cache_path = previous_path;
            g_command_cache_mtime = previous_mtime;
            g_command_cache_has_mtime = previous_has_mtime;
            err_out.clear();
            return true;
        }
        return false;
    }

    g_command_cache_json = out_json;
    g_command_cache_valid = true;
    g_command_cache_path = command_cache_watch_path();
    {
        std::error_code mtec;
        g_command_cache_mtime = fs::last_write_time(g_command_cache_path, mtec);
        g_command_cache_has_mtime = !mtec;
    }
    logger::trace("commands: loaded byte cache once bytes=" + std::to_string(out_json.size()));
    return true;
}

bool save_command_json_utf8(const std::string& utf8_json, std::string& err_out) {
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);
    bool saved = false;
#if FEATURE_SECURE_STORAGE
    saved = save_command_config_document(utf8_json, err_out);
#else
    saved = write_utf8_plaintext_file(roaming_command_json_path_unlocked(), utf8_json, err_out);
#endif
    if (!saved)
        return false;

    g_command_cache_json = utf8_json;
    g_command_cache_valid = true;
    g_command_cache_path = command_cache_watch_path();
    {
        std::error_code mtec;
        g_command_cache_mtime = fs::last_write_time(g_command_cache_path, mtec);
        g_command_cache_has_mtime = !mtec;
    }
    return true;
}

std::mutex& command_document_mutex()
{
    static std::mutex m;
    return m;
}

bool update_command_json_utf8(const std::function<bool(std::string& utf8_json, std::string& err)>& mutate,
                              std::string& err_out)
{
    // Separate from g_settings_load_mutex: load/save take that one internally.
    std::lock_guard<std::mutex> lock(command_document_mutex());
    std::string doc;
    if (!load_command_json_utf8(doc, err_out))
        return false;
    if (!mutate(doc, err_out))
        return false;
    return save_command_json_utf8(doc, err_out);
}

void set_settings_load_tracing(void (*fn)(const char*)) { g_settings_load_trace = fn; }

void clear_settings_load_tracing() { g_settings_load_trace = nullptr; }

void set_settings_persist_observer(void (*fn)(const char* context, const char* detail))
{
    g_settings_persist_observer = fn;
}

void clear_settings_persist_observer() { g_settings_persist_observer = nullptr; }

bool save_settings_utf8(const std::string& utf8_json, std::string& err_out) {
    std::lock_guard<std::recursive_mutex> commit_lock(g_settings_commit_mu);
    json previous = json::object();
    json next;
    {
        std::lock_guard<std::mutex> lock(g_settings_load_mutex);
        if (g_settings_cache_valid && settings_cache_is_stale_for_path(g_settings_cache_sp)) {
            logger::warn(std::string("settings race: cache stale before replace ")
                         + settings_flush_origin("save_settings_utf8")
                         + " path=" + media::path::path_to_utf8(g_settings_cache_sp));
        }
        if (g_settings_cache_root && g_settings_cache_root->is_object()) {
            previous = *g_settings_cache_root;
        } else {
            SettingsRootSnapshot snap;
            std::string load_err;
            if (load_settings_root_unlocked(snap, load_err, "save_settings_utf8") && snap && snap->is_object())
                previous = *snap;
            else if (g_settings_cache_valid && !g_settings_cache_json.empty()) {
                json parsed = media::json::try_parse(g_settings_cache_json);
                if (parsed.is_object())
                    previous = std::move(parsed);
            }
        }
        if (utf8_json.empty()) {
            next = json::object();
            logger::warn(std::string("settings empty replace payload ") + settings_flush_origin("save_settings_utf8"));
        } else {
            next = media::json::try_parse(utf8_json);
        }
    }
    const SettingsAuditResult audit = audit_settings_before_commit(previous, next, "save_settings_utf8", err_out);
    if (audit == SettingsAuditResult::Cancelled)
        return false;
    if (audit == SettingsAuditResult::InvalidRoot) {
        report_settings_persist_failure("save_settings_utf8", err_out.c_str());
        return false;
    }
    if (audit == SettingsAuditResult::Unchanged) {
        logger::debug(std::string("settings flush skipped (unchanged) ") + settings_flush_origin("save_settings_utf8"));
        return true;
    }
#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT
    {
        std::vector<std::string> changed;
        settings_collect_changed_keys(previous, next, changed);
        const SettingsIpcCommit ipc = settings_ipc_try_commit(
            next, changed, "save_settings_utf8", err_out, true);
        if (ipc == SettingsIpcCommit::Ok)
            return true;
        if (ipc == SettingsIpcCommit::Fail)
            return false;
    }
#endif
    std::string dumped;
    if (!dump_settings_pretty(next, dumped, err_out, "save_settings_utf8"))
        return false;
    {
        std::lock_guard<std::mutex> lock(g_settings_load_mutex);
        if (settings_on_disk_mtime_raced(
                g_settings_cache_valid ? g_settings_cache_sp : settings_effective_read_path_unlocked(),
                "save_settings_utf8")) {
            SettingsRootSnapshot snap;
            std::string load_err;
            if (!load_settings_root_unlocked(snap, load_err, "save_settings_utf8") || !snap || !snap->is_object()) {
                err_out = load_err.empty() ? "settings changed on disk during save" : load_err;
                return false;
            }
            json latest = *snap;
            std::vector<std::string> keys;
            settings_collect_changed_keys(previous, next, keys);
            for (const auto& key : keys) {
                if (key == "_meta")
                    continue;
                if (next.contains(key))
                    latest[key] = next[key];
                else
                    latest.erase(key);
            }
            next = std::move(latest);
            if (!dump_settings_pretty(next, dumped, err_out, "save_settings_utf8"))
                return false;
        }
        return commit_settings_utf8_unlocked(dumped, err_out, "save_settings_utf8", &next);
    }
}

/// Ensures @c workbench.<slot>.chrome exists for exports (and any missing sub-keys).
static void ensure_workbench_chrome_keys_for_export(
    json& j, const char* workbench_slot, bool def_menu, bool def_status, bool def_ribbon)
{
    const char* slot = (workbench_slot && workbench_slot[0]) ? workbench_slot : "main";
    if (!j.is_object())
        j = json::object();
    if (!j.contains("workbench") || !j["workbench"].is_object())
        j["workbench"] = json::object();
    if (!j["workbench"].contains(slot) || !j["workbench"][slot].is_object())
        j["workbench"][slot] = json::object();
    json& w = j["workbench"][slot];
    if (!w.contains("chrome") || !w["chrome"].is_object())
        w["chrome"] = json::object();
    json& c = w["chrome"];
    if (!c.contains("show_menu") || !c["show_menu"].is_boolean())
        c["show_menu"] = def_menu;
    if (!c.contains("show_status_bar") || !c["show_status_bar"].is_boolean())
        c["show_status_bar"] = def_status;
    if (!c.contains("show_ribbon_strip") || !c["show_ribbon_strip"].is_boolean())
        c["show_ribbon_strip"] = def_ribbon;
    if (!c.contains("ribbon_small_icons_only") || !c["ribbon_small_icons_only"].is_boolean())
        c["ribbon_small_icons_only"] = false;
    if (!c.contains("ribbon_show_labels") || !c["ribbon_show_labels"].is_boolean())
        c["ribbon_show_labels"] = !c["ribbon_small_icons_only"].get<bool>();
    if (!c.contains("ribbon_show_groups") || !c["ribbon_show_groups"].is_boolean())
        c["ribbon_show_groups"] = true;
    if (!c.contains("always_restore") || !c["always_restore"].is_boolean())
        c["always_restore"] = false;
    if (!c.contains("auto_grow") || !c["auto_grow"].is_boolean())
        c["auto_grow"] = true;
}

static void ensure_workbench_window_defaults_for_export(json& j, const char* workbench_slot, int def_w, int def_h)
{
    const char* slot = (workbench_slot && workbench_slot[0]) ? workbench_slot : "main";
    if (!j.is_object())
        j = json::object();
    if (!j.contains("workbench") || !j["workbench"].is_object())
        j["workbench"] = json::object();
    if (!j["workbench"].contains(slot) || !j["workbench"][slot].is_object())
        j["workbench"][slot] = json::object();
    json& w = j["workbench"][slot];
    if (!w.contains("window_defaults") || !w["window_defaults"].is_object())
        w["window_defaults"] = json::object();
    json& d = w["window_defaults"];
    if (!d.contains("width") || !d["width"].is_number_integer())
        d["width"]  = def_w;
    if (!d.contains("height") || !d["height"].is_number_integer())
        d["height"] = def_h;
}

static void ensure_ui_workbench_key_for_export(json& j)
{
    if (!j.is_object())
        j = json::object();
    if (!j.contains("ui") || !j["ui"].is_object())
        j["ui"] = json::object();
    if (!j["ui"].contains("workbench") || !j["ui"]["workbench"].is_string())
        j["ui"]["workbench"] = "main";
}

bool export_settings_file(const fs::path& path, bool encrypted, std::string& err_out) {
    const SettingsLoadLabelScope _ls("export_settings_file");
    err_out.clear();
    // Export always reads from the secure roaming profile, never from cwd.
    std::string raw;
    if (!load_settings_profile_document(raw, err_out))
        return false;
    if (raw.empty())
        raw = "{}";
    try {
        json jdoc = json::parse(raw);
        ensure_workbench_chrome_keys_for_export(jdoc, "main", false, true, true);
        ensure_workbench_window_defaults_for_export(jdoc, "main", 1280, 860);
        // Chat-first workbench (`CChatSimpleWorkbench`); `ui.workbench` in live settings selects at startup.
        ensure_workbench_chrome_keys_for_export(jdoc, "chat", false, true, true);
        ensure_workbench_window_defaults_for_export(jdoc, "chat", 640, 720);
        ensure_workbench_chrome_keys_for_export(jdoc, "viewer", false, true, true);
        ensure_workbench_window_defaults_for_export(jdoc, "viewer", 960, 720);
        ensure_workbench_chrome_keys_for_export(jdoc, "filemanager", false, true, true);
        ensure_workbench_window_defaults_for_export(jdoc, "filemanager", 1280, 860);
        ensure_ui_workbench_key_for_export(jdoc);
        if (jdoc.contains("chat") && jdoc["chat"].is_object())
            jdoc["chat"].erase("api_key");
        if (jdoc.contains("providers") && jdoc["providers"].is_object()) {
            for (auto it = jdoc["providers"].begin(); it != jdoc["providers"].end(); ++it) {
                if (it.value().is_object())
                    it.value().erase("api_key");
            }
        }
        raw = jdoc.dump();
    } catch (const std::exception& e) {
        err_out = std::string("JSON: ") + e.what();
        return false;
    }
    if (encrypted) {
        std::vector<unsigned char> blob;
        if (!encrypt_settings_blob(raw, blob, err_out))
            return false;
        if (!write_file_bytes(path, blob.data(), blob.size())) {
            err_out = "failed to write export file";
            return false;
        }
        return true;
    }
    std::string pretty;
    try {
        pretty = nlohmann::json::parse(raw).dump(2);
    } catch (const std::exception& e) {
        err_out = std::string("JSON: ") + e.what();
        return false;
    }
    if (!write_utf8_plaintext_file(path, pretty, err_out))
        return false;
    return true;
}

bool import_settings_file(const fs::path& path, std::string& err_out) {
    err_out.clear();
    std::vector<unsigned char> raw;
    if (!read_file_bytes(path, raw) || raw.empty()) {
        err_out = "file is empty or could not be read";
        return false;
    }
    std::string json;
    if (!decode_settings_raw_bytes(raw, json, err_out))
        return false;
    if (json.empty())
        json = "{}";
    return save_settings_utf8(json, err_out);
}

// ---------------------------------------------------------------------------
// Subtrees (custom / history / any top-level key)
// ---------------------------------------------------------------------------

bool load_subtree(const std::string& key, nlohmann::json& out, std::string& err) {
    const SettingsLoadLabelScope _ls("load_subtree");
    out = json();
    err.clear();
    SettingsRootSnapshot root;
    if (!load_settings_root(root, err))
        return false;
    if (root && root->contains(key))
        out = (*root)[key];
    return true;
}

bool save_subtree(const std::string& key, const nlohmann::json& value, std::string& err) {
    const SettingsLoadLabelScope _ls("save_subtree");
    err.clear();
    if (value.is_discarded()) {
        err = "save_subtree: discarded JSON for key=" + key;
        logger::error(err);
        return false;
    }
    const std::string context = "save_subtree/" + key;
    const bool incoming_empty = value.is_null()
        || (settings_key_uses_items_array(key) && settings_items_count(value) == 0)
        || (key == "providers" && settings_provider_filled_count(value) == 0)
        || ((value.is_object() || value.is_array()) && value.empty());
    if (settings_key_is_guarded(key) && (incoming_empty || settings_value_is_corrupt(key, value))) {
        logger::warn("settings incoming empty/corrupt subtree key=" + key
                     + " value=" + settings_value_summary(key, &value)
                     + " " + settings_flush_origin(context.c_str()));
    }
    return mutate_settings_root(
        context.c_str(),
        [&](json& j, std::string& merr) -> bool {
            (void)merr;
            j[key] = value;
            return true;
        },
        err,
        key.c_str());
}

bool merge_subtree_object(const std::string& key, const nlohmann::json& fields, std::string& err) {
    const SettingsLoadLabelScope _ls("merge_subtree_object");
    err.clear();
    if (!fields.is_object()) {
        err = "merge_subtree_object: `fields` must be a JSON object";
        logger::warn("merge_subtree_object: rejected non-object fields for key=" + key);
        return false;
    }

    const std::string context = "merge_subtree_object/" + key;
    return mutate_settings_root(
        context.c_str(),
        [&](json& j, std::string& merr) -> bool {
            (void)merr;
            const bool had_subtree = j.contains(key);
            const bool subtree_was_object = had_subtree && j[key].is_object();

            if (!j.contains(key) || !j[key].is_object()) {
                if (had_subtree && !subtree_was_object)
                    logger::warn(std::string("merge_subtree_object: key=") + key + " existed but was "
                                 + j[key].type_name() + ", replacing with {}");
                j[key] = json::object();
            }

            for (const auto& [k, v] : fields.items())
                j[key][k] = v;
            return true;
        },
        err);
}

bool load_custom_data(nlohmann::json& out, std::string& err) {
    return load_subtree(SettingsSubtreeKeys::custom, out, err);
}

bool save_custom_data(const nlohmann::json& value, std::string& err) {
    return save_subtree(SettingsSubtreeKeys::custom, value, err);
}

bool load_history_data(nlohmann::json& out, std::string& err) {
    return load_subtree(SettingsSubtreeKeys::history, out, err);
}

bool save_history_data(const nlohmann::json& value, std::string& err) {
    return save_subtree(SettingsSubtreeKeys::history, value, err);
}

bool load_agent_variables(nlohmann::json& out, std::string& err) {
    if (!load_subtree("agent_variables", out, err))
        return false;
    if (!out.is_object())
        out = json::object();
    return true;
}

bool save_agent_variables(const nlohmann::json& values, std::string& err) {
    return merge_subtree_object("agent_variables", values, err);
}

// ---------------------------------------------------------------------------
// Explorer shell presets (settings.json["explorer_presets"])
// ---------------------------------------------------------------------------

namespace {

bool json_to_explorer_preset(const json& o, ExplorerPreset& out) {
    out = ExplorerPreset{};
    if (!o.is_object())
        return false;
    if (!o.contains("id") || !o["id"].is_string())
        return false;
    if (!o.contains("label") || !o["label"].is_string())
        return false;
    if (!o.contains("op") || !o["op"].is_string())
        return false;
    out.id    = o["id"].get<std::string>();
    out.label = o["label"].get<std::string>();
    out.op    = o["op"].get<std::string>();
    if (out.id.empty() || out.op.empty())
        return false;
    if (o.contains("args") && o["args"].is_object())
        out.args = o["args"];
    return true;
}

bool json_to_bookmark_item(const json& o, BookmarkItem& out)
{
    out = BookmarkItem{};
    if (!o.is_object())
        return false;
    if (!o.contains("kind") || !o["kind"].is_string())
        return false;
    if (!o.contains("path") || !o["path"].is_string())
        return false;
    out.kind = o["kind"].get<std::string>();
    out.path = o["path"].get<std::string>();
    if (out.kind.empty() || out.path.empty())
        return false;
    if (o.contains("node_kind") && o["node_kind"].is_string())
        out.node_kind = o["node_kind"].get<std::string>();
    if (o.contains("label") && o["label"].is_string())
        out.label = o["label"].get<std::string>();
    if (o.contains("searchable") && o["searchable"].is_boolean())
        out.searchable = o["searchable"].get<bool>();
    if (o.contains("share") && o["share"].is_boolean())
        out.share = o["share"].get<bool>();
    return true;
}

bool json_to_visited_file_item(const json& o, VisitedFileEntry& out)
{
    out = VisitedFileEntry{};
    if (!o.is_object())
        return false;
    if (!o.contains("path") || !o["path"].is_string())
        return false;
    out.path = o["path"].get<std::string>();
    if (out.path.empty())
        return false;
    if (o.contains("visited_at") && o["visited_at"].is_string())
        out.visited_at = o["visited_at"].get<std::string>();
    if (o.contains("workbench") && o["workbench"].is_string())
        out.workbench = o["workbench"].get<std::string>();
    return true;
}

bool json_to_browser_history_item(const json& o, BrowserHistoryEntry& out)
{
    out = BrowserHistoryEntry{};
    if (!o.is_object())
        return false;
    if (!o.contains("url") || !o["url"].is_string())
        return false;
    out.url = o["url"].get<std::string>();
    if (out.url.empty())
        return false;
    if (o.contains("title") && o["title"].is_string())
        out.title = o["title"].get<std::string>();
    if (o.contains("visited_at") && o["visited_at"].is_string())
        out.visited_at = o["visited_at"].get<std::string>();
    return true;
}

} // namespace

bool load_explorer_presets(std::vector<ExplorerPreset>& out, std::string& err) {
    out.clear();
    err.clear();
    json j;
    if (!load_subtree(SettingsSubtreeKeys::explorer_presets, j, err))
        return false;
    if (j.is_null() || j.empty())
        return true;
    try {
        if (!j.is_object())
            return true;
        const auto it = j.find("items");
        if (it == j.end() || !it->is_array())
            return true;
        for (const auto& el : *it) {
            ExplorerPreset p;
            if (json_to_explorer_preset(el, p))
                out.push_back(std::move(p));
        }
    } catch (const std::exception& e) {
        err = std::string("load_explorer_presets: ") + e.what();
        return false;
    }
    return true;
}

bool save_explorer_presets(const std::vector<ExplorerPreset>& items, std::string& err) {
    err.clear();
    json arr = json::array();
    for (const auto& p : items) {
        if (p.id.empty() || p.op.empty())
            continue;
        json o{{"id", p.id}, {"label", p.label}, {"op", p.op}};
        if (!p.args.is_null() && p.args.is_object() && !p.args.empty())
            o["args"] = p.args;
        else
            o["args"] = json::object();
        arr.push_back(std::move(o));
    }
    const json doc{{"version", 1}, {"items", std::move(arr)}};
    return save_subtree(SettingsSubtreeKeys::explorer_presets, doc, err);
}

bool load_bookmarks(std::vector<BookmarkItem>& out, std::string& err)
{
    out.clear();
    err.clear();
    json j;
    if (!load_subtree(SettingsSubtreeKeys::bookmarks, j, err))
        return false;
    if (j.is_null() || j.empty())
        return true;
    try {
        if (!j.is_object())
            return true;
        const auto it = j.find("items");
        if (it == j.end() || !it->is_array())
            return true;
        for (const auto& el : *it) {
            BookmarkItem b;
            if (json_to_bookmark_item(el, b))
                out.push_back(std::move(b));
        }
    } catch (const std::exception& e) {
        err = std::string("load_bookmarks: ") + e.what();
        return false;
    }
    return true;
}

bool save_bookmarks(const std::vector<BookmarkItem>& items, std::string& err)
{
    err.clear();
    json arr = json::array();
    for (const auto& b : items) {
        if (b.kind.empty() || b.path.empty())
            continue;
        json o{
            {"kind", b.kind},
            {"path", b.path},
        };
        if (!b.node_kind.empty())
            o["node_kind"] = b.node_kind;
        if (!b.label.empty())
            o["label"] = b.label;
        o["searchable"] = b.searchable;
        o["share"] = b.share;
        arr.push_back(std::move(o));
    }
    const json doc{{"version", 1}, {"items", std::move(arr)}};
    if (doc["items"].empty()) {
        logger::warn(std::string("settings incoming empty bookmarks ")
                     + settings_flush_origin("save_subtree/bookmarks"));
    }
    return save_subtree(SettingsSubtreeKeys::bookmarks, doc, err);
}

bool load_visited_files(std::vector<VisitedFileEntry>& out, std::string& err)
{
    out.clear();
    err.clear();
    json j;
    if (!load_subtree(SettingsSubtreeKeys::visited_files, j, err))
        return false;
    if (j.is_null() || j.empty())
        return true;
    try {
        if (!j.is_object())
            return true;
        const auto it = j.find("items");
        if (it == j.end() || !it->is_array())
            return true;
        for (const auto& el : *it) {
            VisitedFileEntry row;
            if (json_to_visited_file_item(el, row))
                out.push_back(std::move(row));
            if (out.size() >= kVisitedFilesMax)
                break;
        }
    } catch (const std::exception& e) {
        err = std::string("load_visited_files: ") + e.what();
        return false;
    }
    return true;
}

bool save_visited_files(const std::vector<VisitedFileEntry>& items, std::string& err)
{
    err.clear();
    json arr = json::array();
    for (const auto& row : items) {
        if (row.path.empty())
            continue;
        json o{
            {"path", row.path},
            {"visited_at", row.visited_at},
            {"workbench", row.workbench},
        };
        arr.push_back(std::move(o));
        if (arr.size() >= kVisitedFilesMax)
            break;
    }
    const json doc{{"version", 1}, {"items", std::move(arr)}};
    return save_subtree(SettingsSubtreeKeys::visited_files, doc, err);
}

bool load_browser_history(std::vector<BrowserHistoryEntry>& out, std::string& err)
{
    out.clear();
    err.clear();
    json j;
    if (!load_subtree(SettingsSubtreeKeys::browser_history, j, err))
        return false;
    if (j.is_null() || j.empty())
        return true;
    try {
        if (!j.is_object())
            return true;
        const auto it = j.find("items");
        if (it == j.end() || !it->is_array())
            return true;
        for (const auto& el : *it) {
            BrowserHistoryEntry row;
            if (json_to_browser_history_item(el, row))
                out.push_back(std::move(row));
            if (out.size() >= kBrowserHistoryMaxItems)
                break;
        }
    } catch (const std::exception& e) {
        err = std::string("load_browser_history: ") + e.what();
        return false;
    }
    return true;
}

bool save_browser_history(const std::vector<BrowserHistoryEntry>& items, std::string& err)
{
    err.clear();
    json arr = json::array();
    for (const auto& row : items) {
        if (row.url.empty())
            continue;
        json o{{"url", row.url}, {"visited_at", row.visited_at}};
        if (!row.title.empty())
            o["title"] = row.title;
        arr.push_back(std::move(o));
        if (arr.size() >= kBrowserHistoryMaxItems)
            break;
    }
    const json doc{{"version", 1}, {"items", std::move(arr)}};
    return save_subtree(SettingsSubtreeKeys::browser_history, doc, err);
}

bool load_command_palette_recent(std::vector<std::string>& out, std::string& err)
{
    out.clear();
    err.clear();
    json j;
    if (!load_subtree(SettingsSubtreeKeys::command_palette_recent, j, err))
        return false;
    if (j.is_null() || j.empty())
        return true;
    try {
        if (!j.is_object())
            return true;
        const auto it = j.find("items");
        if (it == j.end() || !it->is_array())
            return true;
        for (const auto& el : *it) {
            if (el.is_string()) {
                const std::string id = el.get<std::string>();
                if (!id.empty())
                    out.push_back(id);
            }
        }
    } catch (const std::exception& e) {
        err = std::string("load_command_palette_recent: ") + e.what();
        return false;
    }
    return true;
}

bool save_command_palette_recent(const std::vector<std::string>& ids, std::string& err)
{
    err.clear();
    json arr = json::array();
    for (const auto& id : ids) {
        if (id.empty())
            continue;
        arr.push_back(id);
    }
    const json doc{{"version", 1}, {"items", std::move(arr)}};
    return save_subtree(SettingsSubtreeKeys::command_palette_recent, doc, err);
}

static void cap_xblox_artifact_items(json& doc)
{
    if (!doc.is_object() || !doc.contains("items") || !doc["items"].is_array())
        return;
    auto& items = doc["items"];
    if (items.size() <= k_xblox_artifacts_max_entries)
        return;
    json kept = json::array();
    for (std::size_t i = 0; i < k_xblox_artifacts_max_entries; ++i)
        kept.push_back(items[i]);
    items = std::move(kept);
}

bool load_xblox_artifacts(nlohmann::json& out, std::string& err)
{
    out = json::object();
    err.clear();
    json j;
    if (!load_subtree(SettingsSubtreeKeys::xblox_artifacts, j, err))
        return false;
    if (j.is_null() || j.empty())
        return true;
    if (!j.is_object()) {
        err = "load_xblox_artifacts: root must be an object";
        return false;
    }
    out = std::move(j);
    if (out.contains("items") && out["items"].is_array()
        && out["items"].size() > k_xblox_artifacts_max_entries) {
        cap_xblox_artifact_items(out);
        std::string save_err;
        if (!save_xblox_artifacts(out, save_err) && !save_err.empty())
            logger::warn("load_xblox_artifacts: trim failed: " + save_err);
    }
    return true;
}

bool save_xblox_artifacts(const nlohmann::json& doc, std::string& err)
{
    err.clear();
    if (!doc.is_object()) {
        err = "save_xblox_artifacts: doc must be an object";
        return false;
    }
    json capped = doc;
    cap_xblox_artifact_items(capped);
    return save_subtree(SettingsSubtreeKeys::xblox_artifacts, capped, err);
}

namespace {

std::string artifact_path_key(std::string path)
{
    while (!path.empty() && (path.back() == '\\' || path.back() == '/'))
        path.pop_back();
    path = media::strutil::lower_ascii(std::move(path));
    return path;
}

} // namespace

bool append_xblox_artifact_entries(const nlohmann::json& entries,
                                   std::string& err,
                                   std::size_t max_entries)
{
    err.clear();
    if (!entries.is_array() || entries.empty()) {
        logger::debug("[xblox-artifacts] append skipped (no run rows)");
        return true;
    }
    if (max_entries == 0 || max_entries > k_xblox_artifacts_max_entries)
        max_entries = k_xblox_artifacts_max_entries;

    const std::size_t incoming_count = entries.size();
    std::size_t merged_count          = 0;

    const bool ok = mutate_settings_root(
        "append_xblox_artifact_entries",
        [&](json& j, std::string& merr) -> bool {
            (void)merr;
            json doc = json::object();
            if (j.contains(SettingsSubtreeKeys::xblox_artifacts)
                && j[SettingsSubtreeKeys::xblox_artifacts].is_object()) {
                doc = j[SettingsSubtreeKeys::xblox_artifacts];
            }

            json items = (doc.contains("items") && doc["items"].is_array()) ? doc["items"] : json::array();

            std::unordered_set<std::string> seen;
            json                            merged = json::array();

            auto push_row = [&](json row) {
                if (!row.is_object())
                    return;
                if (!row.contains("path") || !row["path"].is_string())
                    return;
                const std::string key = artifact_path_key(row["path"].get<std::string>());
                if (key.empty() || !seen.insert(key).second)
                    return;
                merged.push_back(std::move(row));
            };

            for (auto it = entries.rbegin(); it != entries.rend(); ++it)
                push_row(*it);
            for (const auto& row : items)
                push_row(row);

            while (max_entries > 0 && merged.size() > max_entries)
                merged.erase(merged.end() - 1);

            merged_count = merged.size();
            if (incoming_count > 0 && merged_count == 0) {
                err = "append_xblox_artifact_entries: merge dropped all incoming rows";
                logger::error(std::string("[xblox-artifacts] ") + err);
                return false;
            }

            doc["version"] = 1;
            doc["items"]   = std::move(merged);
            j[SettingsSubtreeKeys::xblox_artifacts] = std::move(doc);
            return true;
        },
        err);

    if (!ok && !err.empty())
        logger::error(std::string("[xblox-artifacts] append failed: ") + err);
    return ok;
}

// ---------------------------------------------------------------------------
// Web chat (WebView2) — prompt history + quick actions
// ---------------------------------------------------------------------------

bool load_chat_web(json& out, std::string& err) {
    err.clear();
    if (!load_subtree(SettingsSubtreeKeys::chat_web, out, err))
        return false;
    if (out.is_null() || !out.is_object())
        out = json::object();
    return true;
}

bool save_chat_web(const json& doc, std::string& err) {
    err.clear();
    return save_subtree(SettingsSubtreeKeys::chat_web, doc, err);
}

// ---------------------------------------------------------------------------
// Provider management
// ---------------------------------------------------------------------------

const ProviderDefaults* known_providers(int* count_out) {
    static const std::vector<ProviderDefaults> kProviders = [] {
        std::vector<ProviderDefaults> out;
        const auto* reg = pm::llm::provider_registry_data();
        const auto  n   = pm::llm::provider_registry_size();
        out.reserve(pm::llm::provider_enabled_registry_size());
        for (std::size_t i = 0; i < n; ++i) {
            if (!reg[i].build_enabled)
                continue;
            ProviderDefaults row;
            row.name         = reg[i].name;
            row.display_name = reg[i].display_name;
            row.base_url     = reg[i].base_url;
            for (std::size_t m = 0; m < reg[i].model_count; ++m)
                row.models.push_back(reg[i].models[m]);
            out.push_back(std::move(row));
        }
        return out;
    }();
    if (count_out)
        *count_out = static_cast<int>(kProviders.size());
    return kProviders.data();
}

bool load_providers(ProviderMap& out, std::string& err) {
    const SettingsLoadLabelScope _ls("load_providers");
    out.clear();

    // Initialise known rows for UI display. Runtime selection comes from explicit
    // chat/tool settings, not from provider-row default_model.
    int n = 0;
    for (const auto* p = known_providers(&n); n--; ++p) {
        ProviderEntry e;
        e.base_url      = p->base_url;
        out[p->name]    = std::move(e);
    }

    SettingsRootSnapshot root;
    if (!load_settings_root(root, err))
        return false;

    try {
        const auto& j = *root;
        if (j.contains("providers") && j["providers"].is_object()) {
            for (auto& [name, val] : j["providers"].items()) {
                ProviderEntry& e = out[name];
                if (val.contains("api_key")       && val["api_key"].is_string())
                    e.api_key       = val["api_key"].get<std::string>();
                if (val.contains("base_url")      && val["base_url"].is_string())
                    e.base_url      = val["base_url"].get<std::string>();
                if (val.contains("default_model") && val["default_model"].is_string())
                    e.default_model = val["default_model"].get<std::string>();
                if (val.contains("auth_mode")     && val["auth_mode"].is_string())
                    e.auth_mode     = val["auth_mode"].get<std::string>();
            }
        }
    } catch (const std::exception& ex) {
        err = std::string("JSON parse error: ") + ex.what();
        return false;
    }
    return true;
}

bool save_providers(const ProviderMap& providers, std::string& err) {
    const SettingsLoadLabelScope _ls("save_providers");
    if (providers.empty()) {
        logger::warn(std::string("settings incoming empty providers map ")
                     + settings_flush_origin("save_providers"));
    } else {
        std::size_t filled = 0;
        for (const auto& [name, e] : providers) {
            if (!e.api_key.empty() || !e.base_url.empty() || !e.default_model.empty())
                ++filled;
        }
        if (filled == 0) {
            logger::warn("settings incoming providers have no api_key/base_url/default_model n="
                         + std::to_string(providers.size()) + " "
                         + settings_flush_origin("save_providers"));
        }
    }
    return mutate_settings_root(
        "save_providers",
        [&](json& root, std::string&) {
            auto& jproviders = root["providers"];
            if (!jproviders.is_object())
                jproviders = json::object();
            for (const auto& [name, e] : providers) {
                jproviders[name]["api_key"]       = e.api_key;
                jproviders[name]["base_url"]      = e.base_url;
                jproviders[name]["default_model"] = e.default_model;
                jproviders[name]["auth_mode"]     = e.auth_mode;
            }
            root.erase("active_provider");
            return true;
        },
        err);
}

// ---------------------------------------------------------------------------
// Window / dock layout
// ---------------------------------------------------------------------------

namespace {

const char* workbench_slot_or_main(const char* s)
{
    return (s && s[0]) ? s : "main";
}

void workbench_chrome_apply_slot_defaults(media::settings::WorkbenchChromeSettings& out, const char* workbench_slot)
{
    const char* slot = workbench_slot_or_main(workbench_slot);
    if (std::strcmp(slot, "chat") == 0) {
        out.show_main_menu     = false;
        out.show_status_bar    = false;
        out.show_ribbon_strip  = true;
    } else if (std::strcmp(slot, "viewer") == 0) {
        out.show_main_menu    = false;
        out.show_status_bar   = true;
        out.show_ribbon_strip = true;
    } else if (std::strcmp(slot, "filemanager") == 0) {
        out.show_main_menu    = false;
        out.show_status_bar   = true;
        out.show_ribbon_strip = true;
    }
}

} // namespace

bool load_workbench_window_defaults(WorkbenchWindowDefaults& out, std::string& err, const char* workbench_slot)
{
    return media::layout::LayoutStore::LoadWorkbenchWindowDefaults(out, err, workbench_slot);
}

bool load_window_layout(WindowLayout& out, std::string& err, const char* workbench_slot) {
    return media::layout::LayoutStore::LoadWindowLayout(out, err, workbench_slot);
}

bool save_window_layout(const WindowLayout& layout, std::string& err, const char* workbench_slot) {
    return media::layout::LayoutStore::SaveWindowLayout(layout, err, workbench_slot);
}

bool set_filetree_show_shell_frames(bool show, std::string& err, const char* workbench_slot) {
    return media::layout::LayoutStore::SetFiletreeShowShellFrames(show, err, workbench_slot);
}

bool set_filetree_filter_mask(const std::string& mask, std::string& err, const char* workbench_slot) {
    return media::layout::LayoutStore::SetFiletreeFilterMask(mask, err, workbench_slot);
}

bool set_filetree_glob_select_history(const std::vector<std::string>& history, std::string& err,
                                      const char* workbench_slot) {
    return media::layout::LayoutStore::SetFiletreeGlobSelectHistory(history, err, workbench_slot);
}

bool load_workbench_chrome(WorkbenchChromeSettings& out, std::string& err, const char* workbench_slot)
{
    const SettingsLoadLabelScope _ls("workbench_chrome");
    out  = WorkbenchChromeSettings{};
    workbench_chrome_apply_slot_defaults(out, workbench_slot);
    err.clear();
    if (g_ui_reset_session)
        return true;
    SettingsRootSnapshot root;
    if (!load_settings_root(root, err))
        return false;
    try {
        const auto& j     = *root;
        const char* slot  = workbench_slot_or_main(workbench_slot);
        if (!j.contains("workbench") || !j["workbench"].is_object())
            return true;
        if (!j["workbench"].contains(slot) || !j["workbench"][slot].is_object())
            return true;
        const auto& w = j["workbench"][slot];
        if (!w.contains("chrome") || !w["chrome"].is_object())
            return true;
        const auto& c   = w["chrome"];
        bool def_menu = false, def_status = true, def_ribbon = true;
        if (std::strcmp(slot, "chat") == 0) {
            def_status = false;
        }
        out.show_main_menu          = c.value("show_menu",               def_menu);
        out.show_status_bar         = c.value("show_status_bar",         def_status);
        out.show_ribbon_strip       = c.value("show_ribbon_strip",       def_ribbon);
        out.ribbon_small_icons_only = c.value("ribbon_small_icons_only", false);
        out.ribbon_show_labels      = c.value("ribbon_show_labels", !out.ribbon_small_icons_only);
        out.ribbon_show_groups      = c.value("ribbon_show_groups", true);
        out.always_restore          = c.value("always_restore",          false);
        out.auto_grow               = c.value("auto_grow",               true);
    } catch (const std::exception& ex) {
        err = std::string("workbench_chrome: ") + ex.what();
        return false;
    }
    return true;
}

/// Shared write-through helper for `workbench.<slot>.chrome.<key>` boolean toggles.
static bool set_workbench_chrome_bool_key(
    const char* key, bool value, std::string& err, const char* workbench_slot)
{
    const char* slot = workbench_slot_or_main(workbench_slot);
    err.clear();
    return mutate_settings_root(
        "set_workbench_chrome_bool_key",
        [&](json& root, std::string&) {
            auto& workbench = root["workbench"];
            if (!workbench.is_object())
                workbench = json::object();
            auto& workbench_slot = workbench[slot];
            if (!workbench_slot.is_object())
                workbench_slot = json::object();
            auto& chrome = workbench_slot["chrome"];
            if (!chrome.is_object())
                chrome = json::object();
            chrome[key] = value;
            return true;
        },
        err);
}

bool set_workbench_chrome_ribbon_small_icons_only(bool small_only, std::string& err, const char* workbench_slot)
{
    const SettingsLoadLabelScope _ls("set_workbench_chrome_ribbon_small_icons_only");
    return set_workbench_chrome_bool_key("ribbon_small_icons_only", small_only, err, workbench_slot);
}

bool set_workbench_chrome_ribbon_show_labels(bool show, std::string& err, const char* workbench_slot)
{
    const SettingsLoadLabelScope _ls("set_workbench_chrome_ribbon_show_labels");
    return set_workbench_chrome_bool_key("ribbon_show_labels", show, err, workbench_slot);
}

bool set_workbench_chrome_ribbon_show_groups(bool show, std::string& err, const char* workbench_slot)
{
    const SettingsLoadLabelScope _ls("set_workbench_chrome_ribbon_show_groups");
    return set_workbench_chrome_bool_key("ribbon_show_groups", show, err, workbench_slot);
}

bool set_workbench_chrome_show_ribbon_strip(bool show, std::string& err, const char* workbench_slot)
{
    const SettingsLoadLabelScope _ls("set_workbench_chrome_show_ribbon_strip");
    return set_workbench_chrome_bool_key("show_ribbon_strip", show, err, workbench_slot);
}

bool set_workbench_chrome_auto_grow(bool enabled, std::string& err, const char* workbench_slot)
{
    const SettingsLoadLabelScope _ls("set_workbench_chrome_auto_grow");
    return set_workbench_chrome_bool_key("auto_grow", enabled, err, workbench_slot);
}

namespace {
void workbench_panel_defaults_apply_slot_defaults(media::settings::WorkbenchPanelDefaults& out, const char* slot)
{
    if (std::strcmp(slot, "chat") == 0) {
        out.filetree    = true;
        out.queue       = false;
        out.log         = false;
        out.chat        = false;
        out.centre_view = "chat";
    } else if (std::strcmp(slot, "viewer") == 0) {
        out.filetree    = false;
        out.queue       = false;
        out.log         = false;
        out.chat        = false;
        out.centre_view = "file_viewer";
    } else if (std::strcmp(slot, "filemanager") == 0) {
        out.filetree    = true;
        out.queue       = false;
        out.log         = false;
        out.chat        = false;
        out.centre_view = "file_viewer";
    } else { // "main" and any unknown slot
        out.filetree    = true;
        out.queue       = true;
        out.log         = true;
        out.chat        = false;
        out.centre_view = "file_viewer";
    }
}
} // namespace (anonymous — declared inside the earlier namespace block closure)

bool save_workbench_chrome(const WorkbenchChromeSettings& chrome, std::string& err, const char* workbench_slot)
{
    const SettingsLoadLabelScope _ls("save_workbench_chrome");
    const char* slot = workbench_slot_or_main(workbench_slot);
    err.clear();

    return mutate_settings_root(
        "save_workbench_chrome",
        [&](json& root, std::string&) {
            auto& workbench = root["workbench"];
            if (!workbench.is_object())
                workbench = json::object();
            auto& workbench_slot = workbench[slot];
            if (!workbench_slot.is_object())
                workbench_slot = json::object();
            auto& saved = workbench_slot["chrome"];
            saved = {
                {"show_menu", chrome.show_main_menu},
                {"show_status_bar", chrome.show_status_bar},
                {"show_ribbon_strip", chrome.show_ribbon_strip},
                {"ribbon_small_icons_only", chrome.ribbon_small_icons_only},
                {"ribbon_show_labels", chrome.ribbon_show_labels},
                {"ribbon_show_groups", chrome.ribbon_show_groups},
                {"always_restore", chrome.always_restore},
                {"auto_grow", chrome.auto_grow},
            };
            return true;
        },
        err);
}

bool load_workbench_panel_defaults(WorkbenchPanelDefaults& out, std::string& err, const char* workbench_slot)
{
    const SettingsLoadLabelScope _ls("load_workbench_panel_defaults");
    const char* slot = workbench_slot_or_main(workbench_slot);
    out  = WorkbenchPanelDefaults{};
    workbench_panel_defaults_apply_slot_defaults(out, slot);
    err.clear();
    if (g_ui_reset_session)
        return true;
    SettingsRootSnapshot root;
    if (!load_settings_root(root, err))
        return false;
    try {
        const auto& j = *root;
        if (!j.contains("workbench") || !j["workbench"].is_object())
            return true;
        if (!j["workbench"].contains(slot) || !j["workbench"][slot].is_object())
            return true;
        const auto& w = j["workbench"][slot];
        if (!w.contains("panel_defaults") || !w["panel_defaults"].is_object())
            return true;
        const auto& p = w["panel_defaults"];
        // Use slot defaults as the fallback for each key so absent keys stay sensible.
        WorkbenchPanelDefaults def{};
        workbench_panel_defaults_apply_slot_defaults(def, slot);
        out.filetree    = p.value("filetree",     def.filetree);
        out.queue       = p.value("queue",        def.queue);
        out.log         = p.value("log",          def.log);
        out.chat        = p.value("chat",         def.chat);
        out.centre_view = p.value("centre_view",  def.centre_view);
    } catch (const std::exception& ex) {
        err = std::string("load_workbench_panel_defaults: ") + ex.what();
        return false;
    }
    return true;
}

bool save_workbench_panel_defaults(const WorkbenchPanelDefaults& d, std::string& err, const char* workbench_slot)
{
    const SettingsLoadLabelScope _ls("save_workbench_panel_defaults");
    const char* slot = workbench_slot_or_main(workbench_slot);
    err.clear();

    return mutate_settings_root(
        "save_workbench_panel_defaults",
        [&](json& root, std::string&) {
            auto& workbench = root["workbench"];
            if (!workbench.is_object())
                workbench = json::object();
            auto& workbench_slot = workbench[slot];
            if (!workbench_slot.is_object())
                workbench_slot = json::object();
            workbench_slot["panel_defaults"] = {
                {"filetree", d.filetree},
                {"queue", d.queue},
                {"log", d.log},
                {"chat", d.chat},
                {"centre_view", d.centre_view},
            };
            return true;
        },
        err);
}

static std::string g_workbench_id_cli_once;

void set_ui_reset_session(bool active) noexcept
{
    g_ui_reset_session = active;
}

bool ui_reset_session() noexcept
{
    return g_ui_reset_session;
}

void set_ui_workbench_id_cli_override(const char* id)
{
    g_workbench_id_cli_once.clear();
    if (id && id[0]) {
        g_workbench_id_cli_once = id;
    }
}

// Viewer app CLI override (--app); reserved for future per-app routing.
static std::string g_viewer_app_cli_once;

void set_ui_viewer_app_cli_override(const char* app)
{
    g_viewer_app_cli_once.clear();
    if (app && app[0]) {
        g_viewer_app_cli_once = app;
    }
}

bool peek_ui_viewer_app_cli_override(std::string& out) noexcept
{
    if (g_viewer_app_cli_once.empty())
        return false;
    out = g_viewer_app_cli_once;
    return true;
}

static bool workbench_id_from_settings_root(const json& j, std::string& out, std::string& err)
{
    out = kDefaultUiWorkbenchId;
    try {
        if (!j.is_object() || !j.contains("ui") || !j["ui"].is_object() || !j["ui"].contains("workbench"))
            return true;
        const auto& w = j["ui"]["workbench"];
        if (!w.is_string())
            return true;
        const std::string id = w.get<std::string>();
#if POLYMECH_APP_TANIT_VIEWER
        if (id == "viewer")
            out = "viewer";
#else
        if (id == "chat")
            out = "chat";
        else if (id == "viewer")
            out = "viewer";
        else if (id == "filemanager")
            out = "filemanager";
        else if (id == "main")
            out = "main";
#endif
    } catch (const std::exception& ex) {
        err = std::string("ui.workbench: ") + ex.what();
        return false;
    }
    return true;
}

bool load_persisted_settings_ui_workbench_id(std::string& out, std::string& err)
{
    out = kDefaultUiWorkbenchId;
    err.clear();
    SettingsRootSnapshot root;
    if (!load_settings_root(root, err))
        return false;
    return workbench_id_from_settings_root(*root, out, err);
}

bool peek_settings_ui_workbench_id(std::string& out, std::string& err)
{
    out = kDefaultUiWorkbenchId;
    err.clear();
    if (!g_workbench_id_cli_once.empty()) {
        out = g_workbench_id_cli_once;
        return true;
    }
    if (g_ui_reset_session) {
        out = kDefaultUiWorkbenchId;
        return true;
    }
    return load_persisted_settings_ui_workbench_id(out, err);
}

bool load_settings_ui_workbench_id(std::string& out, std::string& err)
{
    out = kDefaultUiWorkbenchId;
    err.clear();
    if (!g_workbench_id_cli_once.empty()) {
        out = g_workbench_id_cli_once;
        g_workbench_id_cli_once.clear();
        return true;
    }
    if (g_ui_reset_session) {
        out = kDefaultUiWorkbenchId;
        return true;
    }
    return load_persisted_settings_ui_workbench_id(out, err);
}

bool save_settings_ui_workbench_id(const std::string& id, std::string& err)
{
#if POLYMECH_APP_TANIT_VIEWER
    if (id != "viewer") {
        err = "save_settings_ui_workbench_id: Tanit Viewer is pinned to workbench 'viewer'";
        return false;
    }
#else
    if (id != "main" && id != "chat" && id != "viewer" && id != "filemanager") {
        err = "save_settings_ui_workbench_id: unknown id '" + id + "'";
        return false;
    }
#endif
    return merge_subtree_object("ui", json{{"workbench", id}}, err);
}

// ── Appearance ───────────────────────────────────────────────────────────────

static const char* theme_to_str(Theme t) {
    switch (t) {
    case Theme::Light: return "light";
    case Theme::Dark:  return "dark";
    case Theme::System:
    default:           return "system";
    }
}
static Theme theme_from_str(const std::string& s) {
    if (s == "light") return Theme::Light;
    if (s == "dark")  return Theme::Dark;
    return Theme::System;
}

static const char* kDisplayLangCodes[] = {"en", "es", "de", "it", "fr", "ar", "zh"};

static void normalize_display_language(std::string& s) {
    if (s.empty()) {
        s = "en";
        return;
    }
    s = media::strutil::lower_ascii(std::move(s));
    for (const char* ok : kDisplayLangCodes) {
        if (s == ok)
            return;
    }
    s = "en";
}

bool load_appearance(AppearanceSettings& out, std::string& err) {
    const SettingsLoadLabelScope _ls("appearance");
    out = AppearanceSettings{};
    SettingsRootSnapshot root;
    if (!load_settings_root(root, err))
        return false;
    try {
        const auto& j = *root;
        if (j.contains("appearance") && j["appearance"].is_object()) {
            const auto& a = j["appearance"];
            if (a.contains("theme") && a["theme"].is_string())
                out.theme = theme_from_str(a["theme"].get<std::string>());
            if (a.contains("font_size_extra_pt") && a["font_size_extra_pt"].is_number_integer()) {
                int v = a["font_size_extra_pt"].get<int>();
                if (v < 0) v = 0; if (v > 8) v = 8;
                // Stored step: 2 = system message font. Applied in `ui_font`.
                out.font_size_extra_pt = v;
            }
            if (a.contains("display_language") && a["display_language"].is_string())
                out.display_language = a["display_language"].get<std::string>();
            normalize_display_language(out.display_language);
            if (a.contains("use_native_editor") && a["use_native_editor"].is_boolean())
                out.use_native_editor = a["use_native_editor"].get<bool>();
            if (a.contains("use_mpv_player") && a["use_mpv_player"].is_boolean())
                out.use_mpv_player = a["use_mpv_player"].get<bool>();
            if (a.contains("use_native_3d_viewer") && a["use_native_3d_viewer"].is_boolean())
                out.use_native_3d_viewer = a["use_native_3d_viewer"].get<bool>();
            if (a.contains("show_3d_object_tree") && a["show_3d_object_tree"].is_boolean())
                out.show_3d_object_tree = a["show_3d_object_tree"].get<bool>();
            if (a.contains("media_autoplay") && a["media_autoplay"].is_boolean())
                out.media_autoplay = a["media_autoplay"].get<bool>();
            if (a.contains("media_autoplay_next") && a["media_autoplay_next"].is_boolean())
                out.media_autoplay_next = a["media_autoplay_next"].get<bool>();
        }
    } catch (const std::exception& e) {
        err = std::string("appearance parse: ") + e.what();
        return false;
    }
    return true;
}

bool save_appearance(const AppearanceSettings& a, std::string& err) {
    const SettingsLoadLabelScope _ls("save_appearance");
    int v = a.font_size_extra_pt;
    if (v < 0) v = 0; if (v > 8) v = 8;
    std::string lang = a.display_language;
    normalize_display_language(lang);
    return mutate_settings_root(
        "save_appearance",
        [&](json& root, std::string&) {
            auto& ap = root["appearance"];
            if (!ap.is_object())
                ap = json::object();
            ap["theme"] = theme_to_str(a.theme);
            ap["font_size_extra_pt"] = v;
            ap["display_language"] = lang;
            ap["use_native_editor"] = a.use_native_editor;
            ap["use_mpv_player"] = a.use_mpv_player;
            ap["use_native_3d_viewer"] = a.use_native_3d_viewer;
            ap["show_3d_object_tree"] = a.show_3d_object_tree;
            ap["media_autoplay"] = a.media_autoplay;
            ap["media_autoplay_next"] = a.media_autoplay_next;
            return true;
        },
        err);
}

namespace {

constexpr std::size_t kTransferFilterCap = 64;

void clamp_transfer_filters(TransferFilterSettings& filters)
{
    if (filters.rules.size() > kTransferFilterCap)
        filters.rules.resize(kTransferFilterCap);
    for (TransferFilterRule& rule : filters.rules) {
        if (rule.pattern.size() > 512)
            rule.pattern.resize(512);
    }
}

void read_transfer_filter_fields(const json& node, TransferFilterSettings& out)
{
    auto flag = [&](const char* key, bool& dest) {
        if (node.contains(key) && node[key].is_boolean())
            dest = node[key].get<bool>();
    };
    flag("respect_ignores", out.respect_ignores);
    flag("gitignore", out.gitignore);
    flag("npmignore", out.npmignore);
    flag("dockerignore", out.dockerignore);
    flag("dotignore", out.dotignore);
    flag("skip_vcs", out.skip_vcs);
    if (node.contains("rules") && node["rules"].is_array()) {
        out.rules.clear();
        for (const auto& row : node["rules"]) {
            if (!row.is_object())
                continue;
            TransferFilterRule rule;
            if (row.contains("enabled") && row["enabled"].is_boolean())
                rule.enabled = row["enabled"].get<bool>();
            if (row.contains("include") && row["include"].is_boolean())
                rule.include = row["include"].get<bool>();
            if (row.contains("pattern") && row["pattern"].is_string())
                rule.pattern = row["pattern"].get<std::string>();
            out.rules.push_back(std::move(rule));
        }
    }
    clamp_transfer_filters(out);
}

json transfer_filter_fields(const TransferFilterSettings& filters)
{
    TransferFilterSettings copy = filters;
    clamp_transfer_filters(copy);
    json rules = json::array();
    for (const TransferFilterRule& rule : copy.rules) {
        rules.push_back({
            {"enabled", rule.enabled},
            {"include", rule.include},
            {"pattern", rule.pattern},
        });
    }
    return {
        {"respect_ignores", copy.respect_ignores},
        {"gitignore", copy.gitignore},
        {"npmignore", copy.npmignore},
        {"dockerignore", copy.dockerignore},
        {"dotignore", copy.dotignore},
        {"skip_vcs", copy.skip_vcs},
        {"rules", std::move(rules)},
    };
}

void trim_preset_name(std::string& text)
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
        text.erase(text.begin());
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
        text.pop_back();
}

void clamp_transfer_filter_presets(TransferFilterPresetLibrary& library)
{
    constexpr std::size_t kMaxPresets = 32;
    constexpr std::size_t kMaxName = 256;
    std::vector<TransferFilterPreset> kept;
    kept.reserve(library.items.size());
    for (TransferFilterPreset& item : library.items) {
        trim_preset_name(item.name);
        if (item.name.size() > kMaxName)
            item.name.resize(kMaxName);
        if (item.name.empty())
            continue;
        bool duplicate = false;
        for (const TransferFilterPreset& have : kept) {
            if (have.name == item.name) {
                duplicate = true;
                break;
            }
        }
        if (duplicate)
            continue;
        clamp_transfer_filters(item.filters);
        kept.push_back(std::move(item));
        if (kept.size() >= kMaxPresets)
            break;
    }
    library.items = std::move(kept);
    trim_preset_name(library.active);
    if (library.active.size() > kMaxName)
        library.active.resize(kMaxName);
    bool found = false;
    for (const TransferFilterPreset& item : library.items) {
        if (item.name == library.active) {
            found = true;
            break;
        }
    }
    if (!found)
        library.active.clear();
}

} // namespace

bool load_transfer_filters(TransferFilterSettings& out, std::string& err)
{
    const SettingsLoadLabelScope _ls("transfer_filters");
    out = TransferFilterSettings{};
    SettingsRootSnapshot root;
    if (!load_settings_root(root, err))
        return false;
    try {
        const auto& j = *root;
        if (!j.contains(SettingsSubtreeKeys::transfer_filters)
            || !j[SettingsSubtreeKeys::transfer_filters].is_object()) {
            return true;
        }
        read_transfer_filter_fields(j[SettingsSubtreeKeys::transfer_filters], out);
    } catch (const std::exception& e) {
        err = std::string("transfer_filters parse: ") + e.what();
        return false;
    }
    return true;
}

bool save_transfer_filters(const TransferFilterSettings& filters, std::string& err)
{
    const SettingsLoadLabelScope _ls("save_transfer_filters");
    return mutate_settings_root(
        "save_transfer_filters",
        [&](json& root, std::string&) {
            root[SettingsSubtreeKeys::transfer_filters] = transfer_filter_fields(filters);
            return true;
        },
        err);
}

bool load_transfer_filter_presets(TransferFilterPresetLibrary& out, std::string& err)
{
    const SettingsLoadLabelScope _ls("transfer_filter_presets");
    out = TransferFilterPresetLibrary{};
    SettingsRootSnapshot root;
    if (!load_settings_root(root, err))
        return false;
    try {
        const auto& j = *root;
        if (!j.contains(SettingsSubtreeKeys::transfer_filter_presets)
            || !j[SettingsSubtreeKeys::transfer_filter_presets].is_object()) {
            return true;
        }
        const auto& node = j[SettingsSubtreeKeys::transfer_filter_presets];
        if (node.contains("active") && node["active"].is_string())
            out.active = node["active"].get<std::string>();
        if (node.contains("items") && node["items"].is_array()) {
            for (const auto& row : node["items"]) {
                if (!row.is_object())
                    continue;
                TransferFilterPreset preset;
                if (row.contains("name") && row["name"].is_string())
                    preset.name = row["name"].get<std::string>();
                read_transfer_filter_fields(row, preset.filters);
                out.items.push_back(std::move(preset));
            }
        }
        clamp_transfer_filter_presets(out);
    } catch (const std::exception& e) {
        err = std::string("transfer_filter_presets parse: ") + e.what();
        return false;
    }
    return true;
}

bool save_transfer_filter_presets(const TransferFilterPresetLibrary& library, std::string& err)
{
    const SettingsLoadLabelScope _ls("save_transfer_filter_presets");
    TransferFilterPresetLibrary copy = library;
    clamp_transfer_filter_presets(copy);
    return mutate_settings_root(
        "save_transfer_filter_presets",
        [&](json& root, std::string&) {
            json items = json::array();
            for (const TransferFilterPreset& preset : copy.items) {
                json row = transfer_filter_fields(preset.filters);
                row["name"] = preset.name;
                items.push_back(std::move(row));
            }
            root[SettingsSubtreeKeys::transfer_filter_presets] = {
                {"active", copy.active},
                {"items", std::move(items)},
            };
            return true;
        },
        err);
}

namespace {

int clamp_speed_mb_s(int value)
{
    if (value < 1)
        return 1;
    if (value > 4096)
        return 4096;
    return value;
}

} // namespace

bool load_transfer_options(TransferOptionSettings& out, std::string& err)
{
    const SettingsLoadLabelScope _ls("transfer_options");
    out = TransferOptionSettings{};
    SettingsRootSnapshot root;
    if (!load_settings_root(root, err))
        return false;
    try {
        const auto& j = *root;
        if (!j.contains(SettingsSubtreeKeys::transfer_options)
            || !j[SettingsSubtreeKeys::transfer_options].is_object()) {
            return true;
        }
        const auto& node = j[SettingsSubtreeKeys::transfer_options];
        auto flag = [&](const char* key, bool& dest) {
            if (node.contains(key) && node[key].is_boolean())
                dest = node[key].get<bool>();
        };
        flag("wait_for_others", out.wait_for_others);
        flag("skip_errors", out.skip_errors);
        flag("limit_speed", out.limit_speed);
        flag("preserve_attributes", out.preserve_attributes);
        flag("preserve_times", out.preserve_times);
        flag("preserve_archive_encrypted", out.preserve_archive_encrypted);
        if (node.contains("speed_mb_s") && node["speed_mb_s"].is_number_integer())
            out.speed_mb_s = clamp_speed_mb_s(node["speed_mb_s"].get<int>());
    } catch (const std::exception& e) {
        err = std::string("transfer_options parse: ") + e.what();
        return false;
    }
    return true;
}

bool save_transfer_options(const TransferOptionSettings& options, std::string& err)
{
    const SettingsLoadLabelScope _ls("save_transfer_options");
    TransferOptionSettings copy = options;
    copy.speed_mb_s = clamp_speed_mb_s(copy.speed_mb_s);
    return mutate_settings_root(
        "save_transfer_options",
        [&](json& root, std::string&) {
            root[SettingsSubtreeKeys::transfer_options] = {
                {"wait_for_others", copy.wait_for_others},
                {"skip_errors", copy.skip_errors},
                {"limit_speed", copy.limit_speed},
                {"speed_mb_s", copy.speed_mb_s},
                {"preserve_attributes", copy.preserve_attributes},
                {"preserve_times", copy.preserve_times},
                {"preserve_archive_encrypted", copy.preserve_archive_encrypted},
            };
            return true;
        },
        err);
}

namespace {

void clamp_scite(SciteSettings& s)
{
    if (s.font_face.empty())
        s.font_face = "Consolas";
    if (s.font_size_pt < 8)
        s.font_size_pt = 8;
    if (s.font_size_pt > 36)
        s.font_size_pt = 36;
    if (s.magnification < -10)
        s.magnification = -10;
    if (s.magnification > 20)
        s.magnification = 20;
}

} // namespace

bool load_scite(SciteSettings& out, std::string& err)
{
    const SettingsLoadLabelScope _ls("scite");
    out = SciteSettings{};
    SettingsRootSnapshot root;
    if (!load_settings_root(root, err))
        return false;
    try {
        const auto& j = *root;
        if (j.contains(SettingsSubtreeKeys::scite) && j[SettingsSubtreeKeys::scite].is_object()) {
            const auto& a = j[SettingsSubtreeKeys::scite];
            if (a.contains("font_face") && a["font_face"].is_string()) {
                out.font_face = a["font_face"].get<std::string>();
            }
            if (a.contains("font_size_pt") && a["font_size_pt"].is_number_integer())
                out.font_size_pt = a["font_size_pt"].get<int>();
            if (a.contains("magnification") && a["magnification"].is_number_integer())
                out.magnification = a["magnification"].get<int>();
            if (a.contains("wrap") && a["wrap"].is_boolean())
                out.wrap = a["wrap"].get<bool>();
        }
        clamp_scite(out);
    } catch (const std::exception& e) {
        err = std::string("scite parse: ") + e.what();
        return false;
    }
    return true;
}

bool save_scite(const SciteSettings& s, std::string& err)
{
    const SettingsLoadLabelScope _ls("save_scite");
    SciteSettings clamped = s;
    clamp_scite(clamped);
    return mutate_settings_root(
        "save_scite",
        [&](json& root, std::string&) {
            auto& sc = root[SettingsSubtreeKeys::scite];
            if (!sc.is_object())
                sc = json::object();
            sc["font_face"] = clamped.font_face;
            sc["font_size_pt"] = clamped.font_size_pt;
            sc["magnification"] = clamped.magnification;
            sc["wrap"] = clamped.wrap;
            return true;
        },
        err);
}

bool set_scite_magnification(int magnification, std::string& err)
{
    const SettingsLoadLabelScope _ls("set_scite_magnification");
    SciteSettings s{};
    if (!load_scite(s, err))
        return false;
    s.magnification = magnification;
    clamp_scite(s);
    return merge_subtree_object(
        SettingsSubtreeKeys::scite,
        json{{"magnification", s.magnification}},
        err);
}

std::string get_active_api_key(std::string& provider_name_out) {
    provider_name_out.clear();
    return {};
}

bool get_active_image_provider(ProviderEntry& out, std::string& provider_name_out) {
    provider_name_out.clear();
    out = ProviderEntry{};
    return false;
}

std::string get_google_provider_api_key() {
    ProviderMap pm;
    std::string err;
    if (!media::settings::load_providers(pm, err))
        return {};
    auto it = pm.find("google");
    if (it == pm.end())
        return {};
    return it->second.api_key;
}

// ---------------------------------------------------------------------------
// Chat provider (settings.json["chat"])
//
// Preset list: settings.json["custom"]["settings_chat_presets"] — loaded/saved by
// settings_runtime + settingsChatPresetsGet/Save (CWebViewManager). Schema helpers
// in chat_settings_schema.cpp; each preset includes optional `runner` (default native),
// `add_tanit_mcp_server` (default true), `load_agent_md` (default true), and `consent_ui`
// (`yolo` / `auto-deny`, same as CLI `--consent-ui`).
// ---------------------------------------------------------------------------

bool load_chat_provider(ChatProviderSettings& out, std::string& err) {
    const SettingsLoadLabelScope _ls("load_chat_provider");
    out = ChatProviderSettings{};

    SettingsRootSnapshot root;
    if (!load_settings_root(root, err))
        return false;

    try {
        const auto& j = *root;
        if (!j.contains("chat") || !j["chat"].is_object())
            return true;
        const auto& c = j["chat"];
        media::settings_schema::ChatJsonOptions options;
        options.clear_absent_media_fields = true;
        media::settings_schema::apply_chat_provider_json(c, out, options);
        // If the user has never set these in JSON, do not use struct defaults
        // ("replicate") as an implicit pick — `pm image meta` and image tools use
        // per-provider `default_model` for `chat.image_provider` only, not
        // top-level `active_provider` (see `apply_image_ai_cli_defaults_from_app` /
        // `apply_chat_image_defaults_for_tool_options`).
        if (!c.contains("image_provider") || !c["image_provider"].is_string()) out.image_provider.clear();
        if (!c.contains("image_model") || !c["image_model"].is_string()) out.image_model.clear();
        if (!c.contains("image_recognition_provider") || !c["image_recognition_provider"].is_string())
            out.image_recognition_provider.clear();
        if (!c.contains("image_recognition_model") || !c["image_recognition_model"].is_string()) out.image_recognition_model.clear();
        if (!c.contains("video_provider") || !c["video_provider"].is_string()) out.video_provider.clear();
        if (!c.contains("video_model") || !c["video_model"].is_string()) out.video_model.clear();
    } catch (const std::exception& e) {
        err = std::string("chat parse: ") + e.what();
        return false;
    }
    return true;
}

bool save_chat_provider(const ChatProviderSettings& s, std::string& err) {
    const SettingsLoadLabelScope _ls("save_chat_provider");
    return mutate_settings_root(
        "save_chat_provider",
        [&](json& root, std::string&) {
            root["chat"] = media::settings_schema::chat_provider_settings_json(s);
            return true;
        },
        err);
}

// ---------------------------------------------------------------------------
// Batch sessions (sessions.json — not the settings profile)
// ---------------------------------------------------------------------------

namespace {

std::mutex g_sessions_write_mu;

/// Read sessions.json as a UTF-8 string.  Returns true even when the file
/// does not exist (out_json is empty in that case).
bool load_sessions_raw(std::string& out_json, std::string& err)
{
    out_json.clear();
    err.clear();
    const fs::path p = get_sessions_json_path();
    if (!fs::exists(p))
        return true;

    std::ifstream ifs(p, std::ios::binary);
    if (!ifs.is_open()) {
        err = "sessions: cannot open " + media::path::path_to_utf8(p);
        return false;
    }
    out_json.assign(std::istreambuf_iterator<char>(ifs),
                    std::istreambuf_iterator<char>());
    return true;
}

bool save_sessions_raw(const std::string& utf8_json, std::string& err)
{
    std::lock_guard<std::mutex> lock(g_sessions_write_mu);
    const fs::path p = get_sessions_json_path();
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);

    const fs::path tmp = p.parent_path()
        / ("sessions.json." + std::to_string(GetCurrentProcessId()) + ".tmp");
    {
        std::ofstream ofs(tmp, std::ios::trunc | std::ios::binary);
        if (!ofs.is_open()) {
            err = "sessions: cannot write " + media::path::path_to_utf8(tmp);
            return false;
        }
        ofs << utf8_json;
        ofs.flush();
        if (!ofs.good()) {
            err = "sessions: write failed " + media::path::path_to_utf8(tmp);
            ofs.close();
            fs::remove(tmp, ec);
            return false;
        }
    }
    fs::rename(tmp, p, ec);
    if (ec) {
        err = "sessions: rename failed: " + ec.message();
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

SessionItem item_from_json(const json& j)
{
    SessionItem it;
    if (j.contains("path")   && j["path"].is_string())   it.path   = j["path"].get<std::string>();
    if (j.contains("sha256") && j["sha256"].is_string())  it.sha256 = j["sha256"].get<std::string>();
    if (j.contains("status") && j["status"].is_string())  it.status = j["status"].get<std::string>();
    if (j.contains("error")  && j["error"].is_string())   it.error  = j["error"].get<std::string>();
    return it;
}

json item_to_json(const SessionItem& it)
{
    return json{{"path", it.path}, {"sha256", it.sha256},
                {"status", it.status}, {"error", it.error}};
}

PersistedSession session_from_json(const json& j)
{
    PersistedSession s;
    if (j.contains("session_id")  && j["session_id"].is_string())   s.session_id  = j["session_id"].get<std::string>();
    if (j.contains("op")          && j["op"].is_string())           s.op          = j["op"].get<std::string>();
    if (j.contains("options"))                                       s.options     = j["options"];
    if (j.contains("created_at")  && j["created_at"].is_string())   s.created_at  = j["created_at"].get<std::string>();
    if (j.contains("updated_at")  && j["updated_at"].is_string())   s.updated_at  = j["updated_at"].get<std::string>();
    if (j.contains("items") && j["items"].is_array()) {
        for (const auto& it : j["items"])
            s.items.push_back(item_from_json(it));
    }
    return s;
}

json session_to_json(const PersistedSession& s)
{
    json items = json::array();
    for (const auto& it : s.items)
        items.push_back(item_to_json(it));
    return json{
        {"session_id",  s.session_id},
        {"op",          s.op},
        {"options",     s.options},
        {"items",       items},
        {"created_at",  s.created_at},
        {"updated_at",  s.updated_at}
    };
}

} // namespace

fs::path get_sessions_json_path()
{
    return get_config_dir() / "sessions.json";
}

bool load_sessions(std::vector<PersistedSession>& out, std::string& err)
{
    out.clear();
    std::string raw;
    if (!load_sessions_raw(raw, err))
        return false;
    if (raw.empty())
        return true;
    try {
        auto j = json::parse(raw);
        if (!j.contains("sessions") || !j["sessions"].is_array())
            return true;
        for (const auto& sj : j["sessions"])
            out.push_back(session_from_json(sj));
    } catch (const std::exception& e) {
        err = std::string("sessions parse: ") + e.what();
        return false;
    }
    return true;
}

bool save_session(const PersistedSession& s, std::string& err)
{
    std::vector<PersistedSession> all;
    if (!load_sessions(all, err))
        return false;

    bool found = false;
    for (auto& existing : all) {
        if (existing.session_id == s.session_id) {
            existing = s;
            found = true;
            break;
        }
    }
    if (!found)
        all.push_back(s);

    json root = json::object();
    root["sessions"] = json::array();
    for (const auto& sess : all)
        root["sessions"].push_back(session_to_json(sess));

    return save_sessions_raw(root.dump(2), err);
}

bool delete_session(const std::string& session_id, std::string& err)
{
    std::vector<PersistedSession> all;
    if (!load_sessions(all, err))
        return false;

    const auto before = all.size();
    all.erase(std::remove_if(all.begin(), all.end(),
        [&](const PersistedSession& s) { return s.session_id == session_id; }),
        all.end());

    if (all.size() == before)
        return true; // nothing to delete — not an error

    json root = json::object();
    root["sessions"] = json::array();
    for (const auto& sess : all)
        root["sessions"].push_back(session_to_json(sess));

    return save_sessions_raw(root.dump(2), err);
}

std::vector<PersistedSession> list_sessions(const std::string& op_filter)
{
    std::string err;
    std::vector<PersistedSession> all;
    load_sessions(all, err);
    if (op_filter.empty())
        return all;
    std::vector<PersistedSession> out;
    for (const auto& s : all)
        if (s.op == op_filter) out.push_back(s);
    return out;
}

bool reset_profile_encryption_key(int& rewritten, std::string& err_out) {
    rewritten = 0;
    err_out.clear();
#if !FEATURE_SECURE_STORAGE
    err_out = "secure storage is not enabled";
    return false;
#else
    std::lock_guard<std::mutex> lock(g_settings_load_mutex);

    struct Snap {
        std::string uri;
        pm::model::ResourceType type = pm::model::ResourceType::Unknown;
        pm::model::TrustLevel trust = pm::model::TrustLevel::UserLocal;
        std::string version = "1";
        std::string provider = "user";
        std::string signer_id;
        std::vector<std::uint8_t> data;
    };

    const auto paths = pm::storage::resolve_storage_paths(get_config_dir_unlocked());
    const auto listed = pm::storage::list_documents(paths);
    if (!listed.ok) {
        err_out = listed.error.empty() ? "failed to list profile documents" : listed.error;
        return false;
    }

    auto apply_cache = [](Snap& snap) {
        if (!snap.data.empty())
            return;
        if (snap.uri == kSettingsProfileUri && g_settings_cache_valid && !g_settings_cache_json.empty())
            snap.data.assign(g_settings_cache_json.begin(), g_settings_cache_json.end());
        else if (snap.uri == kCommandConfigUri && g_command_cache_valid && !g_command_cache_json.empty())
            snap.data.assign(g_command_cache_json.begin(), g_command_cache_json.end());
    };

    auto take_document = [&](const std::string& uri, const pm::model::ResourceMeta* hint, Snap& snap, bool& present) -> bool {
        present = false;
        snap = Snap{};
        snap.uri = uri;
        pm::storage::DocumentLoadPolicy policy;
        const auto loaded = pm::storage::load_document(paths, uri, policy);
        if (!loaded.ok && loaded.error.rfind("document not found:", 0) == 0) {
            if (uri == kSettingsProfileUri) {
                snap.type = pm::model::ResourceType::SettingsProfile;
                snap.signer_id = "local-settings";
            } else if (uri == kCommandConfigUri) {
                snap.type = pm::model::ResourceType::CommandConfig;
                snap.signer_id = "local-commands";
            } else if (hint) {
                snap.type = hint->type;
                snap.trust = hint->trust;
                snap.signer_id = hint->signer_id;
            }
            apply_cache(snap);
            if (!snap.data.empty() && snap.type != pm::model::ResourceType::Unknown) {
                present = true;
                return true;
            }
            if (hint && hint->encrypted) {
                err_out = "cannot read " + uri + ": " + loaded.error;
                return false;
            }
            return true;
        }

        const bool have_meta = !loaded.document.meta.uri.empty();
        const bool encrypted = have_meta ? loaded.document.meta.encrypted : (hint && hint->encrypted);
        const auto trust = have_meta ? loaded.document.meta.trust : (hint ? hint->trust : pm::model::TrustLevel::UserLocal);
        if (encrypted && trust != pm::model::TrustLevel::UserLocal) {
            err_out = "encrypted document is not user-local: " + uri;
            return false;
        }

        snap.type = have_meta ? loaded.document.meta.type : (hint ? hint->type : pm::model::ResourceType::Unknown);
        snap.trust = trust;
        if (have_meta && !loaded.document.meta.version.empty())
            snap.version = loaded.document.meta.version;
        if (have_meta && !loaded.document.meta.provider.empty())
            snap.provider = loaded.document.meta.provider;
        snap.signer_id = have_meta ? loaded.document.meta.signer_id : (hint ? hint->signer_id : std::string{});
        const bool digest_mismatch = loaded.error == "document digest mismatch";
        if (loaded.ok || digest_mismatch)
            snap.data = loaded.document.data;
        apply_cache(snap);

        const bool profile_doc = uri == kSettingsProfileUri || uri == kCommandConfigUri;
        if (!encrypted && !profile_doc)
            return true;
        if (snap.data.empty()) {
            err_out = "cannot read " + uri + (loaded.error.empty() ? std::string() : (": " + loaded.error));
            return false;
        }
        if (snap.type == pm::model::ResourceType::Unknown) {
            err_out = "document type is unknown: " + uri;
            return false;
        }
        if (snap.signer_id.empty()) {
            if (uri == kSettingsProfileUri)
                snap.signer_id = "local-settings";
            else if (uri == kCommandConfigUri)
                snap.signer_id = "local-commands";
        }
        present = true;
        return true;
    };

    std::vector<Snap> snaps;
    std::unordered_set<std::string> seen;
    for (const auto& item : listed.items) {
        if (item.uri.empty() || !seen.insert(item.uri).second)
            continue;
        Snap snap;
        bool present = false;
        if (!take_document(item.uri, &item, snap, present))
            return false;
        if (present)
            snaps.push_back(std::move(snap));
    }
    for (const char* uri : {kSettingsProfileUri, kCommandConfigUri}) {
        if (!seen.insert(uri).second)
            continue;
        Snap snap;
        bool present = false;
        if (!take_document(uri, nullptr, snap, present))
            return false;
        if (present)
            snaps.push_back(std::move(snap));
    }

    auto put_snap = [&](const Snap& snap, std::string& err) -> bool {
        pm::storage::PutDocumentRequest req;
        req.uri = snap.uri;
        req.type = snap.type;
        req.trust = snap.trust;
        req.version = snap.version.empty() ? "1" : snap.version;
        req.provider = snap.provider.empty() ? "user" : snap.provider;
        req.signer_id = snap.signer_id;
        req.encrypt = true;
        req.data = snap.data;
        const auto stored = pm::storage::put_document(paths, req);
        if (!stored.ok) {
            err = snap.uri + ": " + (stored.error.empty() ? "put failed" : stored.error);
            return false;
        }
        return true;
    };

    auto verify_snap = [&](const Snap& snap, std::string& err) -> bool {
        pm::storage::DocumentLoadPolicy policy;
        policy.require_signature = true;
        policy.require_encryption = true;
        policy.allowed_trust = {snap.trust};
        const auto loaded = pm::storage::load_document(paths, snap.uri, policy);
        if (!loaded.ok) {
            err = snap.uri + ": " + (loaded.error.empty() ? "reload failed" : loaded.error);
            return false;
        }
        if (loaded.document.data != snap.data) {
            err = snap.uri + ": reloaded document does not match the saved bytes";
            return false;
        }
        return true;
    };

    std::vector<std::uint8_t> previous_key;
    if (!pm::storage::replace_local_encryption_key(paths, previous_key, err_out)) {
        if (err_out.empty())
            err_out = "failed to replace the encryption key";
        return false;
    }

    auto rollback = [&](const std::string& why) -> bool {
        err_out = why;
        std::string restore_err;
        if (!pm::storage::restore_local_encryption_key(paths, previous_key, restore_err)) {
            err_out += "; previous key restore failed: " + restore_err;
            return false;
        }
        for (const auto& snap : snaps) {
            std::string put_err;
            if (!put_snap(snap, put_err)) {
                err_out += "; rollback rewrite failed: " + put_err;
                return false;
            }
        }
        pm::storage::discard_replaced_encryption_key_backup(paths);
        return false;
    };

    for (const auto& snap : snaps) {
        std::string put_err;
        if (!put_snap(snap, put_err))
            return rollback(put_err);
    }
    for (const auto& snap : snaps) {
        std::string verify_err;
        if (!verify_snap(snap, verify_err))
            return rollback(verify_err);
    }

    bool touched_settings = false;
    bool touched_commands = false;
    for (const auto& snap : snaps) {
        if (snap.uri == kSettingsProfileUri)
            touched_settings = true;
        else if (snap.uri == kCommandConfigUri)
            touched_commands = true;
    }
    if (touched_settings && g_settings_cache_valid) {
        std::error_code mtec;
        g_settings_cache_sp = settings_profile_meta_path();
        g_settings_cache_mtime = fs::last_write_time(g_settings_cache_sp, mtec);
        g_settings_cache_has_mtime = !mtec;
    }
    if (touched_commands && g_command_cache_valid) {
        std::error_code mtec;
        g_command_cache_path = command_cache_watch_path();
        g_command_cache_mtime = fs::last_write_time(g_command_cache_path, mtec);
        g_command_cache_has_mtime = !mtec;
    }

    pm::storage::discard_replaced_encryption_key_backup(paths);
    rewritten = static_cast<int>(snaps.size());
    return true;
#endif
}

#if defined(FEATURE_COMMAND_IPC_NEXT) && FEATURE_COMMAND_IPC_NEXT

void settings_ipc_on_server_start(::media::cmd_ipc::InstanceDescriptor& desc)
{
    g_settings_ipc_self = desc;
    g_settings_ipc_owner_json = get_config_dir() / "run-ipc" / "settings-owner.json";
    const std::wstring name = settings_ipc_mutex_name_for(get_config_dir());
    HANDLE h = CreateMutexW(nullptr, FALSE, name.c_str());
    if (!h) {
        logger::warn("settings ipc: CreateMutex failed err=" + std::to_string(GetLastError()));
        return;
    }
    const DWORD wait = WaitForSingleObject(h, 0);
    if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED) {
        g_settings_ipc_mutex = h;
        settings_ipc_become_owner(desc, wait == WAIT_ABANDONED);
        return;
    }
    CloseHandle(h);
    if (settings_ipc_connect_owner(desc))
        return;
    h = CreateMutexW(nullptr, FALSE, name.c_str());
    if (!h)
        return;
    const DWORD wait2 = WaitForSingleObject(h, 0);
    if (wait2 == WAIT_OBJECT_0 || wait2 == WAIT_ABANDONED) {
        g_settings_ipc_mutex = h;
        settings_ipc_become_owner(desc, wait2 == WAIT_ABANDONED);
        return;
    }
    CloseHandle(h);
    logger::debug("settings ipc: no owner claimed; this process keeps local writes");
}

void settings_ipc_on_server_stop()
{
    g_settings_ipc_stop.store(true);
    {
        std::lock_guard<std::mutex> lock(g_settings_ipc_persist_mu);
        g_settings_ipc_persist_cv.notify_all();
    }
    if (g_settings_ipc_is_owner)
        (void)settings_ipc_persist_now("settings_owner_shutdown");
    if (g_settings_ipc_watcher) {
        g_settings_ipc_watcher->Stop();
        g_settings_ipc_watcher.reset();
    }
    if (g_settings_ipc_persist_thread.joinable())
        g_settings_ipc_persist_thread.join();
    if (g_settings_ipc_mutex) {
        ReleaseMutex(g_settings_ipc_mutex);
        CloseHandle(g_settings_ipc_mutex);
        g_settings_ipc_mutex = nullptr;
    }
    settings_ipc_remove_owner_pointer_if_ours();
    g_settings_ipc_active = false;
    g_settings_ipc_is_owner = false;
}

nlohmann::json settings_ipc_status_json()
{
    json meta = json::object();
    json last_keys = json::array();
    std::uint64_t epoch = 0;
    std::uint64_t revision = 0;
    {
        std::lock_guard<std::mutex> lock(g_settings_load_mutex);
        epoch = g_settings_ipc_epoch;
        revision = g_settings_ipc_revision;
        last_keys = g_settings_ipc_last_keys;
        meta = json{
            {"writer_epoch", epoch},
            {"revision", revision},
            {"writer_pid", static_cast<std::int64_t>(GetCurrentProcessId())},
        };
        if (g_settings_cache_root && g_settings_cache_root->is_object()
            && g_settings_cache_root->contains("_meta")
            && (*g_settings_cache_root)["_meta"].is_object())
            meta = (*g_settings_cache_root)["_meta"];
    }
    const std::int64_t self_pid = static_cast<std::int64_t>(GetCurrentProcessId());
    const std::int64_t owner_pid = g_settings_ipc_is_owner ? self_pid : g_settings_ipc_owner_desc.pid;
    return nlohmann::json{
        {"owner", g_settings_ipc_is_owner},
        {"active", g_settings_ipc_active},
        {"ipcNext", true},
        {"pid", self_pid},
        {"ownerPid", owner_pid},
        {"epoch", epoch},
        {"revision", revision},
        {"pending", g_settings_ipc_pending.load()},
        {"persistSeq", g_settings_ipc_persist_seq},
        {"lastKeys", std::move(last_keys)},
        {"lastCommitMeta", std::move(meta)},
    };
}

nlohmann::json settings_ipc_handle(const nlohmann::json& req)
{
    const std::string action = req.value("action", std::string{});
    nlohmann::json reply;
    reply["pid"] = static_cast<std::int64_t>(GetCurrentProcessId());

    if (action == "settings_heartbeat") {
        reply["type"] = "settings_heartbeat";
        reply["epoch"] = g_settings_ipc_epoch;
        reply["revision"] = g_settings_ipc_revision;
        reply["monotonic_ms"] = static_cast<std::uint64_t>(GetTickCount64());
        return reply;
    }

    if (action == "settings_status") {
        nlohmann::json s = settings_ipc_status_json();
        s["type"] = "settings_status";
        return s;
    }

    if (action == "settings_snapshot") {
        json root = json::object();
        {
            std::lock_guard<std::mutex> lock(g_settings_load_mutex);
            if (g_settings_cache_root && g_settings_cache_root->is_object())
                root = *g_settings_cache_root;
        }
        reply["type"] = "settings_snapshot";
        reply["epoch"] = g_settings_ipc_epoch;
        reply["revision"] = g_settings_ipc_revision;
        reply["root"] = std::move(root);
        return reply;
    }

    if (action == "settings_changed" || action == "settings_reloaded") {
        if (g_settings_ipc_is_owner) {
            reply["type"] = action + std::string("_ack");
            return reply;
        }
        const auto msg_epoch = req.value("epoch", std::uint64_t{0});
        const auto msg_rev = req.value("revision", std::uint64_t{0});
        bool resnapshot = false;
        json next;
        {
            std::lock_guard<std::mutex> lock(g_settings_load_mutex);
            const bool epoch_gap = msg_epoch != g_settings_ipc_epoch;
            const bool rev_gap = msg_rev > g_settings_ipc_revision + 1;
            const bool duplicate = !epoch_gap && msg_rev <= g_settings_ipc_revision;
            const bool full_root = action == "settings_reloaded"
                && req.contains("root") && req["root"].is_object();
            if (duplicate) {
                reply["type"] = action + std::string("_ack");
                reply["epoch"] = g_settings_ipc_epoch;
                reply["revision"] = g_settings_ipc_revision;
                return reply;
            }
            // A delta that skips revisions, or a different owner epoch, is not
            // applied onto a stale local root. The full reloaded document is
            // authoritative for its own epoch.
            if ((epoch_gap && !full_root) || (rev_gap && !full_root)) {
                resnapshot = true;
            } else {
                next = (g_settings_cache_root && g_settings_cache_root->is_object())
                    ? json(*g_settings_cache_root) : json::object();
                if (full_root)
                    next = req["root"];
                else if (!settings_ipc_apply_op(next, req)) {
                    resnapshot = true;
                } else {
                    g_settings_ipc_epoch = msg_epoch;
                    g_settings_ipc_revision = msg_rev;
                    if (req.contains("keys"))
                        g_settings_ipc_last_keys = req["keys"];
                    std::string dumped;
                    std::string err;
                    if (dump_settings_pretty(next, dumped, err, "settings_ipc_peer"))
                        settings_ipc_install_cache(next, dumped);
                }
            }
        }
        if (resnapshot) {
            std::string snap_err;
            if (!settings_ipc_pull_snapshot(snap_err))
                logger::warn(std::string("settings ipc peer resnapshot failed: ") + snap_err);
        }
        logger::debug(std::string("settings ipc: peer ") + action
                      + " rev=" + std::to_string(g_settings_ipc_revision)
                      + " keys=" + g_settings_ipc_last_keys.dump());
        reply["type"] = action + std::string("_ack");
        reply["epoch"] = g_settings_ipc_epoch;
        reply["revision"] = g_settings_ipc_revision;
        return reply;
    }

    if (action == "settings_flush") {
        if (!g_settings_ipc_is_owner) {
            reply["type"] = "error";
            reply["error"] = "not settings owner";
            return reply;
        }
        if (!settings_ipc_persist_now("settings_flush")) {
            settings_ipc_schedule_persist(true);
            reply["type"] = "error";
            reply["error"] = "settings persist failed";
            reply["level"] = "dirty";
            reply["epoch"] = g_settings_ipc_epoch;
            reply["revision"] = g_settings_ipc_revision;
            return reply;
        }
        reply["type"] = "settings_ack";
        reply["level"] = "persisted";
        reply["epoch"] = g_settings_ipc_epoch;
        reply["revision"] = g_settings_ipc_revision;
        return reply;
    }

    if (action != "settings_mutate") {
        reply["type"] = "error";
        reply["error"] = "unknown action: " + action;
        return reply;
    }

    if (!g_settings_ipc_is_owner) {
        reply["type"] = "error";
        reply["error"] = "not settings owner";
        return reply;
    }

    if (settings_ipc_env_int("TANIT_SETTINGS_HANG_IPC", 0) != 0) {
        while (!g_settings_ipc_stop.load())
            Sleep(100);
        reply["type"] = "error";
        reply["error"] = "settings owner hung";
        return reply;
    }

    const int ack_delay = settings_ipc_env_int("TANIT_SETTINGS_ACK_DELAY_MS", 0);
    const std::string guid = req.value("guid", std::string{});
    const bool flush = req.value("durability", std::string{}) == "flush_now";
    SettingsIpcGuidOutcome prior;
    if (settings_ipc_guid_find(guid, prior)) {
        if (flush && prior.level != "persisted") {
            if (!settings_ipc_persist_now("settings_mutate")) {
                settings_ipc_schedule_persist(true);
                reply["type"] = "error";
                reply["error"] = "settings persist failed";
                reply["level"] = "dirty";
                reply["guid"] = guid;
                reply["epoch"] = prior.epoch;
                reply["revision"] = prior.revision;
                return reply;
            }
            prior.level = "persisted";
            settings_ipc_guid_store(guid, prior);
        }
        reply["type"] = "settings_ack";
        reply["guid"] = guid;
        reply["level"] = prior.level.empty() ? "accepted" : prior.level;
        reply["epoch"] = prior.epoch;
        reply["revision"] = prior.revision;
        return reply;
    }

    json next;
    std::vector<std::string> keys;
    SettingsIpcGuidOutcome outcome;
    {
        std::lock_guard<std::mutex> lock(g_settings_load_mutex);
        if (req.contains("base_epoch") || req.contains("base_revision")) {
            const auto base_epoch = req.value("base_epoch", std::uint64_t{0});
            const auto base_rev = req.value("base_revision", std::uint64_t{0});
            if (base_epoch != g_settings_ipc_epoch || base_rev != g_settings_ipc_revision) {
                reply["type"] = "settings_conflict";
                reply["error"] = "settings revision moved; resnapshot and retry";
                reply["epoch"] = g_settings_ipc_epoch;
                reply["revision"] = g_settings_ipc_revision;
                return reply;
            }
        }
        next = (g_settings_cache_root && g_settings_cache_root->is_object())
            ? json(*g_settings_cache_root) : json::object();
        json previous = next;
        if (!settings_ipc_apply_op(next, req)) {
            reply["type"] = "error";
            reply["error"] = "invalid settings mutation";
            return reply;
        }
        const auto saved_revision = g_settings_ipc_revision;
        ++g_settings_ipc_revision;
        settings_ipc_stamp_meta(next);
        std::string dumped;
        std::string err;
        if (!dump_settings_pretty(next, dumped, err, "settings_mutate")) {
            g_settings_ipc_revision = saved_revision;
            reply["type"] = "error";
            reply["error"] = err;
            return reply;
        }
        settings_ipc_install_cache(next, dumped);
        settings_collect_changed_keys(previous, next, keys);
        g_settings_ipc_last_keys = keys;
        outcome.epoch = g_settings_ipc_epoch;
        outcome.revision = g_settings_ipc_revision;
        outcome.level = "accepted";
    }
    settings_ipc_guid_store(guid, outcome);
    json extra{
        {"epoch", outcome.epoch},
        {"revision", outcome.revision},
        {"keys", keys},
        {"op", req.value("op", std::string{"set_many"})},
        {"fields", req.contains("fields") ? req["fields"] : settings_ipc_fields_for_keys(next, keys)},
        {"deleted", req.contains("deleted") ? req["deleted"] : settings_ipc_deleted_keys(next, keys)},
        {"value", req.contains("value") ? req["value"] : json()},
        {"key", req.value("key", std::string{})},
    };
    settings_ipc_broadcast("settings_changed", extra);
    if (flush) {
        if (!settings_ipc_persist_now("settings_mutate")) {
            settings_ipc_schedule_persist(true);
            reply["type"] = "error";
            reply["error"] = "settings persist failed";
            reply["level"] = "dirty";
            reply["guid"] = guid;
            reply["epoch"] = outcome.epoch;
            reply["revision"] = outcome.revision;
            return reply;
        }
        outcome.level = "persisted";
        settings_ipc_guid_store(guid, outcome);
    } else {
        settings_ipc_schedule_persist(false);
    }
    if (ack_delay > 0)
        Sleep(static_cast<DWORD>(ack_delay));
    reply["type"] = "settings_ack";
    reply["guid"] = guid;
    reply["level"] = outcome.level;
    reply["epoch"] = outcome.epoch;
    reply["revision"] = outcome.revision;
    return reply;
}

#endif // FEATURE_COMMAND_IPC_NEXT

} // namespace media::settings
