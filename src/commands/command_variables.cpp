#include "command_variables.hpp"
#include "core/app_storage.hpp"
#include "fs/path_sanitizer.hpp"
#include "core/settings_store.hpp"
#include "settings_portable.hpp"
#include "vfs/virtual_uri.hpp"
#include "logger/logger.h"
#include "string/string_utils.hpp"

#include <cctype>
#include <algorithm>
#include <chrono>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <filesystem>
#include <mutex>
#include <optional>
#if defined(_WIN32)
#include <windows.h>
#include <shlobj.h>
#endif

namespace fs = std::filesystem;

namespace media::commands {
namespace {

std::mutex g_variable_mu;
std::vector<VariableContributor> g_variable_contributors;
std::vector<PaletteContributor> g_palette_contributors;

} // namespace

void add_variable_contributor(VariableContributor fn)
{
    if (!fn)
        return;
    std::lock_guard<std::mutex> lk(g_variable_mu);
    g_variable_contributors.push_back(std::move(fn));
}

void add_palette_contributor(PaletteContributor fn)
{
    if (!fn)
        return;
    std::lock_guard<std::mutex> lk(g_variable_mu);
    g_palette_contributors.push_back(std::move(fn));
}

void apply_palette_contributors(const PalettePush& push)
{
    std::vector<PaletteContributor> extra;
    {
        std::lock_guard<std::mutex> lk(g_variable_mu);
        extra = g_palette_contributors;
    }
    for (const auto& fn : extra) {
        if (fn)
            fn(push);
    }
}

namespace {

std::string two_digits(int value)
{
    char buf[8]{};
    std::snprintf(buf, sizeof(buf), "%02d", value);
    return buf;
}

// Re-emit a token unchanged when it cannot be resolved, preserving the
// original ${key} text so downstream blocks see the literal rather than
// getting a silent empty string.
inline std::string unresolved_var(const std::string& key)
{
    std::string s;
    s.reserve(key.size() + 3);
    s += "${";
    s += key;
    s += '}';
    return s;
}

std::optional<std::string> lookup_variable_key(const std::string& key,
                                               const VariableMap& vars,
                                               bool quiet,
                                               bool path_functions,
                                               bool user_variables);

// Apply a filesystem path decomposition function to a variable whose name is
// encoded after the colon in `key` (e.g. "PATH_DIR:CURRENT_FILE" → look up
// "CURRENT_FILE", run `fn` on that path). Inner names use the same lookup as
// `${CURRENT_FILE}` / `${USER:…}` so preview and execution stay aligned.
// `prefix_len` is sizeof("PATH_DIR:") - 1 at each call site.
template<typename Fn>
std::string apply_path_fn(const std::string& key, std::size_t prefix_len,
                          const VariableMap& vars, bool user_variables, Fn&& fn)
{
    const std::string inner = key.substr(prefix_len);
    std::string source;
    if (const auto it = vars.find(inner); it != vars.end() && !it->second.empty()) {
        source = it->second;
    } else if (auto looked = lookup_variable_key(inner, vars, true, false, user_variables)) {
        source = std::move(*looked);
    }
    if (source.empty())
        return unresolved_var(key);
    const std::string result = fn(media::path::path_from_utf8(media::path::normalize_local_path(source, true)));
    if (result.empty())
        return unresolved_var(key);
    return media::path::normalize_local_path(result, true);
}

void resolve_json_string(nlohmann::json& item, const char* key, const VariableMap& vars, std::string* err,
                         bool normalize_path = false)
{
    if (item.contains(key) && item[key].is_string()) {
        std::string resolved = resolve_variables(item[key].get<std::string>(), vars, err);
        item[key] = media::path::normalize_local_path(resolved, normalize_path);
    }
}

void resolve_json_string_array(nlohmann::json& item, const char* key, const VariableMap& vars, std::string* err)
{
    if (!item.contains(key) || !item[key].is_array())
        return;
    for (auto& value : item[key]) {
        if (value.is_string()) {
            std::string resolved = resolve_variables(value.get<std::string>(), vars, err);
            value = media::path::normalize_local_path(resolved, true);
        }
    }
}

fs::path absolute_context_path(const std::string& value, const std::string& cwd);
std::vector<std::string> absolute_selection_paths(const std::vector<std::string>& paths,
                                                  const std::string& cwd);

template<typename Resolve>
void resolve_arg_array(nlohmann::json& item,
                       const char* key,
                       const VariableContext& context,
                       Resolve resolve)
{
    if (!item.contains(key) || !item[key].is_array())
        return;

    const std::vector<std::string> selection =
        absolute_selection_paths(context.selection_paths, context.cwd);
    nlohmann::json resolved = nlohmann::json::array();
    std::vector<std::string> pending;
    pending.reserve(item[key].size() + selection.size());
    auto flush = [&]() {
        if (pending.empty())
            return;
        for (auto& arg : media::strutil::normalize_command_args(pending, selection))
            resolved.push_back(std::move(arg));
        pending.clear();
    };
    for (const auto& value : item[key]) {
        if (!value.is_string()) {
            flush();
            resolved.push_back(value);
            continue;
        }
        const std::string raw = value.get<std::string>();
        if (raw == "${CURRENT_SELECTION}" && !selection.empty())
            pending.push_back(raw);
        else
            pending.push_back(resolve(raw));
    }
    flush();
    item[key] = std::move(resolved);
}

void resolve_json_arg_array(nlohmann::json& item,
                            const char* key,
                            const VariableMap& vars,
                            const VariableContext& context,
                            std::string* err)
{
    resolve_arg_array(item, key, context, [&](const std::string& raw) {
        return media::path::normalize_local_path(resolve_variables(raw, vars, err));
    });
}

bool is_variable_key_char(char ch)
{
    return std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' || ch == ':';
}

std::string environment_variable(const std::string& name)
{
    if (name.empty())
        return {};
    const char* value = std::getenv(name.c_str());
    return value ? std::string(value) : std::string{};
}

fs::path absolute_context_path(const std::string& value, const std::string& cwd)
{
    fs::path path = media::path::path_from_utf8(value);
    if (path.is_absolute())
        return path.lexically_normal();
    if (!cwd.empty())
        return (media::path::path_from_utf8(cwd) / path).lexically_normal();
    std::error_code ec;
    fs::path absolute = fs::absolute(path, ec);
    return ec ? path.lexically_normal() : absolute.lexically_normal();
}

std::string quote_selection_part(const std::string& value)
{
    if (value.empty())
        return "\"\"";
    const bool needs_quote = value.find_first_of(" \t\n\v\"") != std::string::npos;
    if (!needs_quote)
        return value;
    std::string out;
    out.reserve(value.size() + 2);
    out.push_back('"');
    for (char ch : value) {
        if (ch == '"')
            out.push_back('\\');
        out.push_back(ch);
    }
    out.push_back('"');
    return out;
}

std::vector<std::string> absolute_selection_paths(const std::vector<std::string>& paths,
                                                     const std::string& cwd)
{
    std::vector<std::string> out;
    out.reserve(paths.size());
    for (const auto& value : paths) {
        if (value.empty())
            continue;
        out.push_back(media::path::path_to_utf8(absolute_context_path(value, cwd)));
    }
    return out;
}

std::string selection_list_value(const std::vector<std::string>& absolute_paths)
{
    std::string out;
    for (const auto& path : absolute_paths) {
        if (path.empty())
            continue;
        if (!out.empty())
            out.push_back(' ');
        out += quote_selection_part(path);
    }
    return out;
}

std::string normalize_known_folder_name(std::string name)
{
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char ch) {
        return ch == '-' || ch == ' ' ? '_' : static_cast<char>(std::toupper(ch));
    });
    return name;
}

// KNOWNFOLDER paths must not carry a trailing separator: `${KNOWNFOLDER:Desktop}\file`
// and `${KNOWNFOLDER:Desktop}\\file` should both resolve to a single canonical path
// after normalization, not `Desktop\\file`.
std::string trim_trailing_path_separators(std::string path)
{
    while (!path.empty()) {
        const char c = path.back();
        if (c == '/' || c == '\\')
            path.pop_back();
        else
            break;
    }
    return path;
}

#if defined(_WIN32)
std::wstring utf8_to_wide_local(const std::string& s)
{
    if (s.empty())
        return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0)
        return std::wstring(s.begin(), s.end());
    std::wstring out(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string wide_to_utf8_local(const std::wstring& w)
{
    if (w.empty())
        return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0)
        return {};
    std::string out(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), out.data(), n, nullptr, nullptr);
    return out;
}

const KNOWNFOLDERID* known_folder_id_for_name(const std::string& name)
{
    const std::string key = normalize_known_folder_name(name);
    struct KnownFolderEntry {
        const char* name;
        const KNOWNFOLDERID* id;
    };
    static const KnownFolderEntry entries[] = {
        {"HOME", &FOLDERID_Profile},
        {"PROFILE", &FOLDERID_Profile},
        {"DESKTOP", &FOLDERID_Desktop},
        {"DOCUMENTS", &FOLDERID_Documents},
        {"DOWNLOADS", &FOLDERID_Downloads},
        {"PICTURES", &FOLDERID_Pictures},
        {"MUSIC", &FOLDERID_Music},
        {"VIDEOS", &FOLDERID_Videos},
        {"TEMPLATES", &FOLDERID_Templates},
        {"FAVORITES", &FOLDERID_Favorites},
        {"LINKS", &FOLDERID_Links},
        {"SAVED_GAMES", &FOLDERID_SavedGames},
        {"SCREENSHOTS", &FOLDERID_Screenshots},
        {"LOCAL_APP_DATA", &FOLDERID_LocalAppData},
        {"DATA", &FOLDERID_LocalAppData},
        {"ROAMING_APP_DATA", &FOLDERID_RoamingAppData},
        {"CONFIG", &FOLDERID_RoamingAppData},
        {"PROGRAM_DATA", &FOLDERID_ProgramData},
        {"CACHE", &FOLDERID_LocalAppData},
        {"PUBLIC", &FOLDERID_Public},
        {"PUBLIC_DESKTOP", &FOLDERID_PublicDesktop},
        {"PUBLIC_DOCUMENTS", &FOLDERID_PublicDocuments},
        {"PUBLIC_DOWNLOADS", &FOLDERID_PublicDownloads},
        {"PUBLIC_PICTURES", &FOLDERID_PublicPictures},
        {"PUBLIC_MUSIC", &FOLDERID_PublicMusic},
        {"PUBLIC_VIDEOS", &FOLDERID_PublicVideos},
        {"WINDOWS", &FOLDERID_Windows},
        {"SYSTEM", &FOLDERID_System},
        {"PROGRAM_FILES", &FOLDERID_ProgramFiles},
        {"PROGRAM_FILES_X86", &FOLDERID_ProgramFilesX86},
        {"FONTS", &FOLDERID_Fonts},
        {"START_MENU", &FOLDERID_StartMenu},
        {"PROGRAMS", &FOLDERID_Programs},
        {"STARTUP", &FOLDERID_Startup},
        // ── All-users / machine-wide install paths ──────────────────────────
        {"COMMON_START_MENU",   &FOLDERID_CommonStartMenu},
        {"PROGRAMS_COMMON",     &FOLDERID_CommonPrograms},
        {"STARTUP_COMMON",      &FOLDERID_CommonStartup},
        // ── Shell integration helpers ────────────────────────────────────────
        {"SEND_TO",             &FOLDERID_SendTo},
        {"RECENT",              &FOLDERID_Recent},
    };
    for (const auto& entry : entries) {
        if (key == entry.name)
            return entry.id;
    }
    return nullptr;
}

std::string known_folder_path(const std::string& name)
{
    const std::string key = normalize_known_folder_name(name);
    if (key == "TEMP" || key == "TMP") {
        std::string tmp = environment_variable("TEMP");
        if (tmp.empty())
            tmp = environment_variable("TMP");
        return tmp;
    }
    // `Config` is an app-level alias: resolve to the actual app config directory
    // (package LocalState when packaged, %APPDATA%\PolyMech\<config-slug> when portable),
    // NOT bare RoamingAppData.
    if (key == "CONFIG") {
#if defined(_WIN32)
        // On Windows use the authoritative Win32 config dir (SHGetKnownFolderPath +
        // brand sub-path) — settings_pixelwiz_profile_dir() falls back to cwd/config
        // when the portable override is not set, which is wrong for the UI process.
        try {
            const fs::path dir = media::settings::get_config_dir();
            if (!dir.empty()) return media::path::path_to_utf8(dir);
        } catch (...) {}
#else
        const fs::path dir = media::portable_settings::settings_pixelwiz_profile_dir();
        if (!dir.empty()) return media::path::path_to_utf8(dir);
#endif
        // fall through to KNOWNFOLDERID resolution as a last resort
    }
    // `Cache` is an app-level alias for the rebuildable cache root (downloaded models,
    // thumbnails, embeddings, temp, logs): package LocalCache when packaged
    // (== ApplicationData.Current.LocalCacheFolder), %LOCALAPPDATA%\PolyMech\<config-slug>
    // when portable. Without this, a packaged build writing to bare %LOCALAPPDATA% would
    // be silently virtualised into the package store; this gives presets an explicit,
    // honest cache dir shared with Tanit's own cache.
    if (key == "CACHE") {
#if defined(_WIN32)
        try {
            const fs::path dir = pm::appdata::local_cache();
            if (!dir.empty()) return media::path::path_to_utf8(dir);
        } catch (...) {}
#endif
        // fall through to KNOWNFOLDERID resolution as a last resort
    }
    const KNOWNFOLDERID* id = known_folder_id_for_name(name);
    if (id) {
        PWSTR path = nullptr;
        const HRESULT hr = ::SHGetKnownFolderPath(*id, KF_FLAG_DEFAULT, nullptr, &path);
        if (SUCCEEDED(hr) && path) {
            std::wstring w(path);
            ::CoTaskMemFree(path);
            return wide_to_utf8_local(w);
        }
    }

    HRESULT init = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool uninit = SUCCEEDED(init);
    if (init == RPC_E_CHANGED_MODE)
        init = S_OK;
    if (FAILED(init))
        return {};

    std::string out;
    IKnownFolderManager* manager = nullptr;
    if (SUCCEEDED(::CoCreateInstance(CLSID_KnownFolderManager, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&manager))) && manager) {
        IKnownFolder* folder = nullptr;
        const std::wstring wname = utf8_to_wide_local(name);
        if (SUCCEEDED(manager->GetFolderByName(wname.c_str(), &folder)) && folder) {
            PWSTR path = nullptr;
            if (SUCCEEDED(folder->GetPath(KF_FLAG_DEFAULT, &path)) && path) {
                out = wide_to_utf8_local(path);
                ::CoTaskMemFree(path);
            }
            folder->Release();
        }
        manager->Release();
    }
    if (uninit)
        ::CoUninitialize();
    return out;
}
#else
std::string home_dir()
{
    return environment_variable("HOME");
}

std::string path_or_home_child(const std::string& path)
{
    if (!path.empty())
        return path;
    return {};
}

std::string home_child(const char* child)
{
    const std::string home = home_dir();
    if (home.empty())
        return {};
    return media::path::path_to_utf8(media::path::path_from_utf8(home) / child);
}

std::string xdg_base_dir(const char* env_name, const char* fallback_child)
{
    const std::string configured = environment_variable(env_name);
    if (!configured.empty())
        return configured;
    return home_child(fallback_child);
}

#if defined(__APPLE__)
std::string known_folder_path(const std::string& name)
{
    const std::string key = normalize_known_folder_name(name);
    if (key == "HOME" || key == "PROFILE") return home_dir();
    if (key == "DESKTOP") return home_child("Desktop");
    if (key == "DOCUMENTS") return home_child("Documents");
    if (key == "DOWNLOADS") return home_child("Downloads");
    if (key == "PICTURES") return home_child("Pictures");
    if (key == "MUSIC") return home_child("Music");
    if (key == "VIDEOS" || key == "MOVIES") return home_child("Movies");
    if (key == "CONFIG") return home_child("Library/Preferences");
    if (key == "DATA" || key == "LOCAL_APP_DATA" || key == "APPLICATION_SUPPORT")
        return home_child("Library/Application Support");
    if (key == "CACHE") return home_child("Library/Caches");
    if (key == "TEMP" || key == "TMP") {
        const std::string tmp = environment_variable("TMPDIR");
        return tmp.empty() ? std::string("/tmp") : tmp;
    }
    // ── Installer / package paths ────────────────────────────────────────────
    if (key == "PROGRAM_FILES" || key == "PROGRAMS"
        || key == "COMMON_START_MENU" || key == "PROGRAMS_COMMON")
        return std::string("/Applications");
    if (key == "PROGRAM_DATA")     return std::string("/Library/Application Support");
    if (key == "FONTS")            return std::string("/Library/Fonts");
    if (key == "STARTUP")          return home_child("Library/LaunchAgents");
    if (key == "STARTUP_COMMON")   return std::string("/Library/LaunchDaemons");
    if (key == "SYSTEM_DIR")       return std::string("/usr/lib");
    if (key == "SYSTEM")           return std::string("/usr/lib");
    if (key == "PUBLIC")           return std::string("/Users/Shared");
    if (key == "RECENT")           return home_child("Library/Recent Items");
    // WINDOWS_DIR, SEND_TO have no macOS equivalent — return empty.
    return {};
}
#else
std::string unquote_xdg_value(std::string value)
{
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
        value.erase(value.begin());
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
        value.pop_back();
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
        value = value.substr(1, value.size() - 2);
    const std::string home = home_dir();
    if (!home.empty()) {
        const std::string var1 = "$HOME";
        const std::string var2 = "${HOME}";
        if (value.rfind(var1, 0) == 0)
            value.replace(0, var1.size(), home);
        if (value.rfind(var2, 0) == 0)
            value.replace(0, var2.size(), home);
    }
    return value;
}

std::string xdg_user_dir(const char* key_name, const char* fallback_child)
{
    const std::string config_home = xdg_base_dir("XDG_CONFIG_HOME", ".config");
    if (!config_home.empty()) {
        std::ifstream in(media::path::path_from_utf8(config_home) / "user-dirs.dirs");
        std::string line;
        const std::string prefix = std::string("XDG_") + key_name + "_DIR=";
        while (std::getline(in, line)) {
            if (line.rfind(prefix, 0) == 0)
                return path_or_home_child(unquote_xdg_value(line.substr(prefix.size())));
        }
    }
    return home_child(fallback_child);
}

std::string known_folder_path(const std::string& name)
{
    const std::string key = normalize_known_folder_name(name);
    if (key == "HOME" || key == "PROFILE") return home_dir();
    if (key == "DESKTOP") return xdg_user_dir("DESKTOP", "Desktop");
    if (key == "DOCUMENTS") return xdg_user_dir("DOCUMENTS", "Documents");
    if (key == "DOWNLOADS") return xdg_user_dir("DOWNLOAD", "Downloads");
    if (key == "PICTURES") return xdg_user_dir("PICTURES", "Pictures");
    if (key == "MUSIC") return xdg_user_dir("MUSIC", "Music");
    if (key == "VIDEOS") return xdg_user_dir("VIDEOS", "Videos");
    if (key == "PUBLIC") return xdg_user_dir("PUBLICSHARE", "Public");
    if (key == "TEMPLATES") return xdg_user_dir("TEMPLATES", "Templates");
    if (key == "CONFIG") return xdg_base_dir("XDG_CONFIG_HOME", ".config");
    if (key == "DATA" || key == "LOCAL_APP_DATA")
        return xdg_base_dir("XDG_DATA_HOME", ".local/share");
    if (key == "CACHE") return xdg_base_dir("XDG_CACHE_HOME", ".cache");
    if (key == "STATE") return xdg_base_dir("XDG_STATE_HOME", ".local/state");
    if (key == "TEMP" || key == "TMP") {
        const std::string tmp = environment_variable("TMPDIR");
        return tmp.empty() ? std::string("/tmp") : tmp;
    }
    // ── Installer / package paths ────────────────────────────────────────────
    if (key == "PROGRAM_FILES" || key == "PROGRAMS")
        return std::string("/usr/local/bin");
    if (key == "COMMON_START_MENU" || key == "PROGRAMS_COMMON")
        return std::string("/usr/share/applications");
    if (key == "PROGRAM_DATA")  return std::string("/var/lib");
    if (key == "FONTS")         return std::string("/usr/share/fonts");
    if (key == "STARTUP") {
        const std::string cfg = xdg_base_dir("XDG_CONFIG_HOME", ".config");
        return cfg.empty() ? std::string{} : media::path::path_to_utf8((media::path::path_from_utf8(cfg) / "autostart"));
    }
    if (key == "STARTUP_COMMON") return std::string("/etc/xdg/autostart");
    if (key == "SYSTEM_DIR" || key == "SYSTEM") return std::string("/usr/lib");
    // WINDOWS_DIR, SEND_TO, RECENT have no Linux equivalent — return empty.
    return {};
}
#endif
#endif

/// Strip encoding / modifier suffixes from a POSIX locale (`en_US.UTF-8@euro` → `en-US`).
std::string normalize_locale_tag(std::string s)
{
    const auto at = s.find('@');
    if (at != std::string::npos)
        s.erase(at);
    const auto dot = s.find('.');
    if (dot != std::string::npos)
        s.erase(dot);
    for (char& c : s) {
        if (c == '_')
            c = '-';
    }
    return s;
}

std::string posix_locale_from_env()
{
    const char* keys[] = { "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE" };
    for (const char* key : keys) {
        const char* v = std::getenv(key);
        if (!v || !*v)
            continue;
        std::string raw = v;
        // LANGUAGE may be a colon-separated preference list — take the first.
        const auto colon = raw.find(':');
        if (colon != std::string::npos)
            raw.erase(colon);
        if (raw == "C" || raw == "POSIX")
            continue;
        auto tag = normalize_locale_tag(std::move(raw));
        if (!tag.empty())
            return tag;
    }
    return {};
}

#if defined(_WIN32)
std::string win_locale_name_from_api(int (WINAPI* fn)(LPWSTR, int))
{
    wchar_t locale[LOCALE_NAME_MAX_LENGTH] = {};
    if (fn && fn(locale, LOCALE_NAME_MAX_LENGTH) > 0)
        return wide_to_utf8_local(locale);
    return {};
}

std::string win_locale_name_from_langid(LANGID lang)
{
    wchar_t locale[LOCALE_NAME_MAX_LENGTH] = {};
    if (::LCIDToLocaleName(MAKELCID(lang, SORT_DEFAULT), locale, LOCALE_NAME_MAX_LENGTH, 0) > 0)
        return wide_to_utf8_local(locale);
    return {};
}
#endif

/// OS install / system default locale (BCP-47), e.g. `en-US`.
std::string detect_os_lang()
{
#if defined(_WIN32)
    if (auto s = win_locale_name_from_api(::GetSystemDefaultLocaleName); !s.empty())
        return s;
    if (auto s = win_locale_name_from_langid(::GetSystemDefaultUILanguage()); !s.empty())
        return s;
#endif
    if (auto s = posix_locale_from_env(); !s.empty())
        return s;
    return "en";
}

/// Current user's UI / preferred language (BCP-47), e.g. `de-DE`.
std::string detect_user_lang()
{
#if defined(_WIN32)
    if (auto s = win_locale_name_from_langid(::GetUserDefaultUILanguage()); !s.empty())
        return s;
    if (auto s = win_locale_name_from_api(::GetUserDefaultLocaleName); !s.empty())
        return s;
#endif
    if (auto s = posix_locale_from_env(); !s.empty())
        return s;
    return "en";
}

struct PathRootCandidate {
    fs::path    root;
    std::string token;
};

#if defined(_WIN32)
bool paths_equal_icase(const fs::path& a, const fs::path& b)
{
    std::error_code ec;
    if (fs::equivalent(a, b, ec) && !ec)
        return true;
    const std::wstring aw = a.lexically_normal().wstring();
    const std::wstring bw = b.lexically_normal().wstring();
    return aw.size() == bw.size() && _wcsicmp(aw.c_str(), bw.c_str()) == 0;
}

bool path_under_root(const fs::path& root, const fs::path& path)
{
    if (paths_equal_icase(root, path))
        return true;
    const std::wstring rw = root.lexically_normal().wstring();
    const std::wstring pw = path.lexically_normal().wstring();
    if (pw.size() <= rw.size())
        return false;
    if (_wcsnicmp(pw.c_str(), rw.c_str(), static_cast<std::size_t>(rw.size())) != 0)
        return false;
    const wchar_t next = pw[rw.size()];
    return next == L'\\' || next == L'/';
}
#else
bool paths_equal_icase(const fs::path& a, const fs::path& b)
{
    std::error_code ec;
    if (fs::equivalent(a, b, ec) && !ec)
        return true;
    return a.lexically_normal() == b.lexically_normal();
}

bool path_under_root(const fs::path& root, const fs::path& path)
{
    std::error_code ec;
    const fs::path rel = fs::relative(path.lexically_normal(), root.lexically_normal(), ec);
    if (ec || rel.empty())
        return paths_equal_icase(root, path);
    if (rel.native() == ".")
        return true;
    return rel.native()[0] != '.';
}
#endif

void append_known_folder_candidates(std::vector<PathRootCandidate>& out)
{
    static constexpr struct { const char* name; } k_folders[] = {
        {"Home"}, {"Config"}, {"Data"}, {"Cache"}, {"Temp"},
        {"Profile"}, {"Desktop"}, {"Documents"}, {"Downloads"}, {"Pictures"},
        {"Music"}, {"Videos"}, {"Templates"}, {"Favorites"}, {"Links"},
        {"Saved_Games"}, {"Screenshots"},
        {"Local_App_Data"}, {"Roaming_App_Data"}, {"Program_Data"},
        {"Public"}, {"Public_Desktop"}, {"Public_Documents"}, {"Public_Downloads"},
        {"Public_Pictures"}, {"Public_Music"}, {"Public_Videos"},
        {"Windows"}, {"System"}, {"Program_Files"}, {"Program_Files_X86"},
        {"Fonts"}, {"Start_Menu"}, {"Programs"}, {"Startup"},
    };
    for (const auto& entry : k_folders) {
        const std::string root = known_folder_path(entry.name);
        if (root.empty())
            continue;
        out.push_back({media::path::path_from_utf8(root), std::string("KNOWNFOLDER:") + entry.name});
    }
}

void append_variable_map_candidates(std::vector<PathRootCandidate>& out, const VariableMap& vars)
{
    static constexpr const char* k_vars[] = {
        "TANIT_SHARED", "TANIT_SCRIPTS", "TANIT_ROOT", "tanit",
        "APP_DATA", "APP_LOCAL_DATA", "APP_PROGRAM_DATA",
        "CONFIG_DIR", "MODELS_DIR", "TEMP_DIR", "MCP_CONFIG", "CACHE_DIR",
        "VFS_PUBLIC_DIR", "VFS_USER_DIR", "DEFAULT_FOLDER",
        "PROGRAM_FILES", "PROGRAM_FILES_X86", "PROGRAM_DATA",
        "START_MENU", "START_MENU_COMMON", "PROGRAMS", "PROGRAMS_COMMON",
        "STARTUP", "STARTUP_COMMON", "FONTS", "SYSTEM_DIR", "WINDOWS_DIR",
        "PUBLIC", "PUBLIC_DESKTOP", "SEND_TO", "RECENT",
        "INSTALL_ROOT", "INSTALL_BIN",
    };
    for (const char* name : k_vars) {
        const auto it = vars.find(name);
        if (it == vars.end() || it->second.empty())
            continue;
        out.push_back({media::path::path_from_utf8(it->second), name});
    }
}

std::vector<PathRootCandidate> path_root_candidates(const VariableMap& vars)
{
    std::vector<PathRootCandidate> out;
    append_known_folder_candidates(out);
    append_variable_map_candidates(out, vars);
    std::sort(out.begin(), out.end(), [](const PathRootCandidate& a, const PathRootCandidate& b) {
        return a.root.native().size() > b.root.native().size();
    });
    std::vector<PathRootCandidate> deduped;
    deduped.reserve(out.size());
    for (const auto& c : out) {
        if (c.root.empty())
            continue;
        bool seen = false;
        for (const auto& d : deduped) {
            if (paths_equal_icase(c.root, d.root)) {
                seen = true;
                break;
            }
        }
        if (!seen)
            deduped.push_back(c);
    }
    return deduped;
}

bool has_uri_scheme(std::string_view path)
{
    const auto sep = path.find("://");
    if (sep == std::string_view::npos || sep == 0 || sep > 16)
        return false;
    for (std::size_t i = 0; i < sep; ++i) {
        const unsigned char ch = static_cast<unsigned char>(path[i]);
        if (!std::isalnum(ch) && ch != '+' && ch != '.' && ch != '-')
            return false;
    }
    return true;
}

std::string path_to_stored_expression_impl(std::string_view path, const VariableMap& vars)
{
    if (path.empty())
        return {};
    if (path.find("${") != std::string_view::npos)
        return std::string(path);
    if (const std::string vfs = pm::vfs::repair_vfs_location(path); !vfs.empty())
        return vfs;
    if (has_uri_scheme(path) || pm::vfs::is_remote_uri(path))
        return std::string(path);
    std::error_code ec;
    fs::path abs = media::path::path_from_utf8(path);
    if (!abs.is_absolute()) {
        const fs::path cwd = fs::current_path(ec);
        if (!ec && !cwd.empty())
            abs = cwd / abs;
    }
    abs = abs.lexically_normal();
    if (abs.empty())
        return std::string(path);

    for (const PathRootCandidate& c : path_root_candidates(vars)) {
        if (c.root.empty() || c.token.empty())
            continue;
        const fs::path root = c.root.lexically_normal();
        if (!path_under_root(root, abs))
            continue;
        std::error_code rel_ec;
        fs::path rel = fs::relative(abs, root, rel_ec);
        if (rel_ec)
            rel = fs::path{};
        // generic_string()/string() narrow through the ANSI code page. U+2019
        // in "Claudette’s …" becomes byte 0x92, which is not UTF-8, so the
        // settings dump throws type_error.316 and --src cannot reopen the path.
        const auto rel_u8 = rel.generic_u8string();
        const std::string rel_s = (rel.empty() || rel == ".")
            ? std::string{}
            : std::string(reinterpret_cast<const char*>(rel_u8.data()), rel_u8.size());
        if (rel_s.empty())
            return std::string("${") + c.token + "}";
        return std::string("${") + c.token + "}/" + rel_s;
    }
    return media::path::path_to_utf8(abs);
}

} // namespace

std::string os_known_folder(const std::string& name)
{
    return known_folder_path(name);
}

std::optional<std::string> user_variable_value(const std::string& name)
{
    if (name.empty())
        return std::nullopt;
    nlohmann::json vars;
    std::string err;
    if (!media::settings::load_subtree("variables", vars, err) || !vars.is_object())
        return std::nullopt;
    const auto it = vars.find(name);
    if (it == vars.end())
        return std::nullopt;
    if (it->is_string())
        return it->get<std::string>();
    if (it->is_null())
        return std::string{};
    return it->dump();
}

namespace {

bool validate_variable_template(std::string_view value, std::string* err)
{
    for (std::size_t i = 0; i < value.size();) {
        if (i + 1 < value.size() && value[i] == '$' && value[i + 1] == '{') {
            const std::size_t key_start = i + 2;
            std::size_t k = key_start;
            while (k < value.size() && is_variable_key_char(value[k]))
                ++k;
            if (k >= value.size() || value[k] != '}') {
                if (err)
                    *err = "command_variables: unclosed `${`";
                return false;
            }
            if (k == key_start) {
                if (err)
                    *err = "command_variables: empty ${} key";
                return false;
            }
            i = k + 1;
            continue;
        }
        if (value[i] == '\0') {
            if (err)
                *err = "command_variables: null byte in template";
            return false;
        }
        ++i;
    }
    return true;
}

std::optional<std::string> lookup_variable_key(const std::string& key,
                                               const VariableMap& vars,
                                               bool quiet,
                                               bool path_functions,
                                               bool user_variables)
{
    if (key.rfind("ENV:", 0) == 0) {
        const std::string env = environment_variable(key.substr(4));
        if (!env.empty())
            return env;
        if (!quiet)
            logger::warn("[variables] unresolved ${" + key + "}: env var not set");
        return std::nullopt;
    }
    if (user_variables && key.rfind("USER:", 0) == 0) {
        if (const auto value = user_variable_value(key.substr(5)))
            return *value;
        if (!quiet)
            logger::warn("[variables] unresolved ${" + key + "}: user variable not set");
        return std::nullopt;
    }
    if (key.rfind("KNOWNFOLDER:", 0) == 0) {
        std::string folder = known_folder_path(key.substr(12));
        if (!folder.empty())
            return trim_trailing_path_separators(std::move(folder));
        if (!quiet)
            logger::warn("[variables] unresolved ${" + key + "}: known folder not found");
        return std::nullopt;
    }
    if (path_functions && key.rfind("PATH_DIR:", 0) == 0) {
        const std::string resolved = apply_path_fn(key, sizeof("PATH_DIR:") - 1, vars, user_variables, [](const fs::path& p) {
            const auto d = p.parent_path();
            return d.empty() ? std::string(".") : media::path::path_to_utf8(d);
        });
        return resolved == unresolved_var(key) ? std::nullopt : std::optional<std::string>(resolved);
    }
    if (path_functions && key.rfind("PATH_NAME:", 0) == 0) {
        const std::string resolved = apply_path_fn(key, sizeof("PATH_NAME:") - 1, vars, user_variables, [](const fs::path& p) {
            return media::path::path_to_utf8(p.stem());
        });
        return resolved == unresolved_var(key) ? std::nullopt : std::optional<std::string>(resolved);
    }
    if (path_functions && key.rfind("PATH_EXT:", 0) == 0) {
        const std::string resolved = apply_path_fn(key, sizeof("PATH_EXT:") - 1, vars, user_variables, [](const fs::path& p) {
            return media::path::path_to_utf8(p.extension());
        });
        return resolved == unresolved_var(key) ? std::nullopt : std::optional<std::string>(resolved);
    }
    if (path_functions && key.rfind("PATH_BASE:", 0) == 0) {
        const std::string resolved = apply_path_fn(key, sizeof("PATH_BASE:") - 1, vars, user_variables, [](const fs::path& p) {
            return media::path::path_to_utf8(p.filename());
        });
        return resolved == unresolved_var(key) ? std::nullopt : std::optional<std::string>(resolved);
    }
    if (path_functions && key.rfind("PATH_ABS:", 0) == 0) {
        const std::string resolved = apply_path_fn(key, sizeof("PATH_ABS:") - 1, vars, user_variables, [&vars](const fs::path& p) {
            if (p.is_absolute())
                return media::path::path_to_utf8(p.lexically_normal());
            const auto cwd = vars.find("CWD");
            const fs::path base = (cwd != vars.end() && !cwd->second.empty())
                ? media::path::path_from_utf8(cwd->second) : fs::current_path();
            return media::path::path_to_utf8((base / p).lexically_normal());
        });
        return resolved == unresolved_var(key) ? std::nullopt : std::optional<std::string>(resolved);
    }
    if (const auto it = vars.find(key); it != vars.end())
        return it->second;
    if (user_variables) {
        if (const auto uv = user_variable_value(key); uv.has_value())
            return *uv;
    }
    if (!quiet)
        logger::warn("[variables] unresolved ${" + key + "}: not in variable map");
    return std::nullopt;
}

bool is_custom_command_source_arg(std::string_view arg)
{
    return arg == "--src" || arg == "-s" || arg == "--input" || arg == "-i";
}

bool is_cli_variable_override_key(std::string_view key)
{
    if (key.rfind("arg-", 0) == 0)
        return key.size() > 4;
    static constexpr const char* kKnown[] = {
        "CURRENT_FILE",
        "CURRENT_FILE_NAME",
        "CURRENT_PATH",
        "CURRENT_SELECTION",
        "CURRENT_HWND",
        "CURRENT_PID",
        "CURRENT_WINTITLE",
        "CURRENT_PROCESS",
        "CURRENT_SCREEN_SPEC",
        "CWD",
        "SRC_FILE",
        "SRC_DIR",
        "SRC_NAME",
        "SRC_EXT",
        "SRC_FILE_EXT",
        "SRC_REL",
        "VOICE_WAKE",
        "VOICE_COMMAND",
        "VOICE_FULL",
    };
    for (const char* name : kKnown) {
        if (key == name)
            return true;
    }
    return false;
}

std::string normalize_cli_override_key(std::string key)
{
    if (key.rfind("arg-", 0) == 0)
        key.erase(0, 4);
    return key;
}

bool is_cli_variable_override_token(std::string_view tok)
{
    if (tok.size() <= 2 || tok.rfind("--", 0) != 0 || tok == "--")
        return false;
    if (is_custom_command_source_arg(tok))
        return false;
    std::string_view key = tok.substr(2);
    if (const auto eq = key.find('='); eq != std::string_view::npos)
        key = key.substr(0, eq);
    return is_cli_variable_override_key(key);
}

std::vector<std::string> split_selection_override_paths(const std::string& value,
                                                        const std::string& cwd)
{
    std::vector<std::string> out;
    std::string cur;
    bool in_quote = false;
    char quote = '\0';
    for (char ch : value) {
        if (in_quote) {
            if (ch == quote)
                in_quote = false;
            else
                cur.push_back(ch);
            continue;
        }
        if (ch == '\'' || ch == '"') {
            in_quote = true;
            quote = ch;
            continue;
        }
        if (ch == ' ' || ch == '\t') {
            if (!cur.empty()) {
                out.push_back(media::path::path_to_utf8(absolute_context_path(cur, cwd)));
                cur.clear();
            }
            continue;
        }
        cur.push_back(ch);
    }
    if (!cur.empty())
        out.push_back(media::path::path_to_utf8(absolute_context_path(cur, cwd)));
    return out;
}

std::mutex g_voice_mu;
VoiceUtterance g_last_voice;

bool voice_empty(const VoiceUtterance& u)
{
    return u.wake.empty() && u.command.empty() && u.full.empty();
}

VoiceUtterance voice_from_env()
{
    VoiceUtterance u;
    if (const char* v = std::getenv(kVoiceWakeEnv); v && *v)
        u.wake = v;
    if (const char* v = std::getenv(kVoiceCommandEnv); v && *v)
        u.command = v;
    if (const char* v = std::getenv(kVoiceFullEnv); v && *v)
        u.full = v;
    return u;
}

VoiceUtterance resolve_voice_utterance(const VariableContext& context)
{
    VoiceUtterance last;
    {
        std::lock_guard<std::mutex> lock(g_voice_mu);
        last = g_last_voice;
    }
    if (voice_empty(last))
        last = voice_from_env();
    VoiceUtterance u;
    u.wake = !context.voice_wake.empty() ? context.voice_wake : last.wake;
    u.command = !context.voice_command.empty() ? context.voice_command : last.command;
    u.full = !context.voice_full.empty() ? context.voice_full : last.full;
    return u;
}

} // namespace

void set_last_voice_utterance(VoiceUtterance utterance)
{
    std::lock_guard<std::mutex> lock(g_voice_mu);
    g_last_voice = std::move(utterance);
}

VoiceUtterance last_voice_utterance()
{
    std::lock_guard<std::mutex> lock(g_voice_mu);
    return g_last_voice;
}

void apply_voice_variables(VariableMap& vars, const VoiceUtterance& utterance)
{
    if (!utterance.wake.empty())
        vars["VOICE_WAKE"] = utterance.wake;
    if (!utterance.command.empty())
        vars["VOICE_COMMAND"] = utterance.command;
    if (!utterance.full.empty())
        vars["VOICE_FULL"] = utterance.full;
}

void append_voice_utterance_env(std::vector<std::pair<std::string, std::string>>& extra_env)
{
    const VoiceUtterance u = last_voice_utterance();
    if (!u.wake.empty())
        extra_env.emplace_back(kVoiceWakeEnv, u.wake);
    if (!u.command.empty())
        extra_env.emplace_back(kVoiceCommandEnv, u.command);
    if (!u.full.empty())
        extra_env.emplace_back(kVoiceFullEnv, u.full);
}

VariableMap make_variable_map(const VariableContext& context)
{
    install_host_variables();
    VariableMap vars;

    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    vars["YYYY"] = std::to_string(tm.tm_year + 1900);
    vars["MM"] = two_digits(tm.tm_mon + 1);
    vars["DD"] = two_digits(tm.tm_mday);
    vars["HH"] = two_digits(tm.tm_hour);
    vars["mm"] = two_digits(tm.tm_min);
    vars["SS"] = two_digits(tm.tm_sec);

    vars["CWD"] = context.cwd;
    if (!context.cwd.empty())
        vars["CURRENT_PATH"] = media::path::path_to_utf8(media::path::path_from_utf8(context.cwd).lexically_normal());
    // Index N matches the Nth path in ${CURRENT_SELECTION} (file-view order).
    // ${PATH_DIR:CURRENT_SELECTION_0} and the other PATH_* helpers compose
    // because the indexed path is a normal map entry.
    const std::vector<std::string> selection_paths =
        absolute_selection_paths(context.selection_paths, context.cwd);
    const std::string current_selection = selection_list_value(selection_paths);
    if (!current_selection.empty())
        vars["CURRENT_SELECTION"] = current_selection;
    if (!selection_paths.empty()) {
        vars["CURRENT_SELECTION_COUNT"] = std::to_string(selection_paths.size());
        for (std::size_t i = 0; i < selection_paths.size(); ++i)
            vars["CURRENT_SELECTION_" + std::to_string(i)] = selection_paths[i];
    }
    if (!context.current_hwnd.empty()) {
        vars["CURRENT_HWND"] = context.current_hwnd;
        vars["CURRENT_SCREEN_SPEC"] = "screen:0:hwnd=" + context.current_hwnd;
    }
    if (!context.current_pid.empty())
        vars["CURRENT_PID"] = context.current_pid;
    if (!context.current_wintitle.empty())
        vars["CURRENT_WINTITLE"] = context.current_wintitle;
    if (!context.current_process.empty())
        vars["CURRENT_PROCESS"] = context.current_process;
    if (!context.current_url.empty())
        vars["CURRENT_URL"] = context.current_url;
    if (!context.current_url_title.empty())
        vars["CURRENT_URL_TITLE"] = context.current_url_title;
    if (!context.last_url.empty())
        vars["LAST_URL"] = context.last_url;
    if (!context.browser_tabs.empty()) {
        vars["BROWSER_TAB_COUNT"] = std::to_string(context.browser_tabs.size());
        for (std::size_t i = 0; i < context.browser_tabs.size(); ++i) {
            const BrowserTabVariable& tab = context.browser_tabs[i];
            if (!tab.url.empty())
                vars["BROWSER_TAB_" + std::to_string(i)] = tab.url;
            if (!tab.title.empty())
                vars["BROWSER_TAB_TITLE_" + std::to_string(i)] = tab.title;
        }
    }
    vars["PATH_SEP"] = std::string(1, fs::path::preferred_separator);
#if defined(_WIN32)
    vars["PATH_LIST_SEP"] = ";";
#else
    vars["PATH_LIST_SEP"] = ":";
#endif

    vars["OS_LANG"]   = detect_os_lang();
    vars["USER_LANG"] = detect_user_lang();

    // CACHE_DIR — OS temporary directory (GetTempPath / $TMPDIR / /tmp).
    {
        std::error_code ec;
        const fs::path tmp = fs::temp_directory_path(ec);
        if (!ec && !tmp.empty())
            vars["CACHE_DIR"] = media::path::path_to_generic_utf8(tmp);
    }

    // ── OS install / package paths (short-form over ${KNOWNFOLDER:…}) ─────────
    // Pre-populate so bundle manifests can write ${PROGRAM_FILES} directly.
    {
        static constexpr struct { const char* var; const char* folder; } k_install[] = {
            {"PROGRAM_FILES",       "PROGRAM_FILES"},
            {"PROGRAM_FILES_X86",   "PROGRAM_FILES_X86"},
            {"PROGRAM_DATA",        "PROGRAM_DATA"},
            {"START_MENU",          "START_MENU"},
            {"START_MENU_COMMON",   "COMMON_START_MENU"},
            {"PROGRAMS",            "PROGRAMS"},
            {"PROGRAMS_COMMON",     "PROGRAMS_COMMON"},
            {"STARTUP",             "STARTUP"},
            {"STARTUP_COMMON",      "STARTUP_COMMON"},
            {"FONTS",               "FONTS"},
            {"SYSTEM_DIR",          "SYSTEM"},
            {"WINDOWS_DIR",         "WINDOWS"},
            {"PUBLIC",              "PUBLIC"},
            {"PUBLIC_DESKTOP",      "PUBLIC_DESKTOP"},
            {"SEND_TO",             "SEND_TO"},
            {"RECENT",              "RECENT"},
        };
        for (const auto& e : k_install) {
            std::string v = known_folder_path(e.folder);
            if (!v.empty())
                vars[e.var] = std::move(v);
        }
    }

    // ── Install context ───────────────────────────────────────────────────────
    if (!context.install_root.empty()) {
        vars["INSTALL_ROOT"] = context.install_root;
        std::error_code ec;
        const fs::path bin_dir = media::path::path_from_utf8(context.install_root) / "bin";
        vars["INSTALL_BIN"] = (fs::is_directory(bin_dir, ec) && !ec)
            ? media::path::path_to_utf8(bin_dir)
            : context.install_root;
    }

    if (!context.source_file.empty())
        apply_source_file_variables(vars, context.source_file, context.cwd);

    apply_voice_variables(vars, resolve_voice_utterance(context));

    std::vector<VariableContributor> extra;
    {
        std::lock_guard<std::mutex> lk(g_variable_mu);
        extra = g_variable_contributors;
    }
    for (const auto& fn : extra) {
        if (fn)
            fn(vars, context);
    }
    return vars;
}

void apply_source_file_variables(VariableMap&       vars,
                                 const std::string& source_file,
                                 const std::string& cwd,
                                 const std::string& rel_base)
{
    if (source_file.empty())
        return;

    const fs::path  src     = media::path::path_from_utf8(source_file);
    const fs::path  current = absolute_context_path(source_file, cwd);
    std::error_code current_ec;
    const bool      current_is_directory = fs::is_directory(current, current_ec);
    std::string     ext = media::path::path_to_utf8(src.extension());
    if (current_is_directory) {
        vars["CURRENT_PATH"] = media::path::path_to_utf8(current);
    } else {
        vars["CURRENT_FILE"]      = media::path::path_to_utf8(current);
        vars["CURRENT_FILE_NAME"] = media::path::path_to_utf8(current.filename());
        vars["CURRENT_PATH"]      = media::path::path_to_utf8(current.parent_path());
    }
    vars["SRC_FILE"]     = source_file;
    vars["SRC_DIR"]      = media::path::path_to_utf8(src.parent_path());
    vars["SRC_NAME"]     = media::path::path_to_utf8(src.stem());
    vars["SRC_FILE_EXT"] = ext;
    if (!ext.empty() && ext.front() == '.')
        ext.erase(ext.begin());
    vars["SRC_EXT"] = ext;

    if (!rel_base.empty()) {
        std::error_code rel_ec;
        const fs::path  base_abs = absolute_context_path(rel_base, cwd);
        const fs::path  rel      = fs::relative(current, base_abs, rel_ec);
        std::string     rel_s    = (!rel_ec && !rel.empty()) ? media::path::path_to_generic_utf8(rel) : std::string{};
        if (rel_s.empty() || rel_s.rfind("..", 0) == 0)
            rel_s = media::path::path_to_generic_utf8(src.filename());
        vars["SRC_REL"] = rel_s;
    }
}

void refresh_derived_variables(VariableMap& vars, const VariableMap* overrides)
{
    auto explicitly_overridden = [&](const char* key) {
        return overrides && overrides->find(key) != overrides->end();
    };

    if (!explicitly_overridden("INSTALL_BIN")) {
        const auto it_root = vars.find("INSTALL_ROOT");
        if (it_root != vars.end() && !it_root->second.empty()) {
            std::error_code ec;
            const fs::path bin_dir = media::path::path_from_utf8(it_root->second) / "bin";
            vars["INSTALL_BIN"] = (fs::is_directory(bin_dir, ec) && !ec)
                ? media::path::path_to_utf8(bin_dir)
                : it_root->second;
        }
    }

    if (!explicitly_overridden("VFS_PUBLIC_DIR")) {
        const auto it_pd = vars.find("APP_PROGRAM_DATA");
        if (it_pd != vars.end() && !it_pd->second.empty())
            vars["VFS_PUBLIC_DIR"] = media::path::path_to_utf8((media::path::path_from_utf8(it_pd->second) / "vfs" / "public"));
    }

    if (!explicitly_overridden("VFS_USER_DIR")) {
        const auto it_ad = vars.find("APP_DATA");
        if (it_ad != vars.end() && !it_ad->second.empty())
            vars["VFS_USER_DIR"] = media::path::path_to_utf8((media::path::path_from_utf8(it_ad->second) / "vfs" / "user"));
    }
}

std::string resolve_variables(std::string_view value, const VariableMap& vars, std::string* err, bool quiet)
{
    static constexpr bool kPathFunctions = true;

    if (err)
        err->clear();
    if (!validate_variable_template(value, err))
        return std::string(value);

    return media::strutil::substitute_variables(
        std::string(value),
        [&](std::string_view name) -> std::optional<std::string> {
            return lookup_variable_key(
                std::string(name), vars, quiet, kPathFunctions, true);
        });
}

std::string resolve_builtin_variables(std::string_view value,
                                      const VariableMap& vars,
                                      std::string* err,
                                      bool quiet)
{
    static constexpr bool kPathFunctions = true;
    static constexpr bool kUserVariables = false;

    if (err)
        err->clear();
    if (!validate_variable_template(value, err))
        return std::string(value);

    return media::strutil::substitute_variables(
        std::string(value),
        [&](std::string_view name) -> std::optional<std::string> {
            return lookup_variable_key(
                std::string(name), vars, quiet, kPathFunctions, kUserVariables);
        });
}

void deep_resolve_json_string(nlohmann::json& item, const char* key, const VariableMap& vars,
                              std::string* err, bool normalize_path = false)
{
    if (!item.contains(key) || !item[key].is_string())
        return;
    std::string resolved = deep_resolve_variables(item[key].get<std::string>(), vars, err);
    item[key] = media::path::normalize_local_path(resolved, normalize_path);
}

void deep_resolve_json_arg_array(nlohmann::json& item,
                                 const char* key,
                                 const VariableMap& vars,
                                 const VariableContext& context,
                                 std::string* err)
{
    resolve_arg_array(item, key, context, [&](const std::string& raw) {
        return media::path::normalize_local_path(deep_resolve_variables(raw, vars, err));
    });
}

void resolve_custom_command_item_variables_impl(nlohmann::json& item,
                                               const VariableContext& context,
                                               VariableMap vars,
                                               std::string* err)
{
    deep_resolve_json_string(item, "cwd", vars, err, true);
    if (item.contains("cwd") && item["cwd"].is_string())
        vars["CWD"] = item["cwd"].get<std::string>();

    deep_resolve_json_arg_array(item, "globalArgs", vars, context, err);
    deep_resolve_json_arg_array(item, "args", vars, context, err);
    deep_resolve_json_string(item, "url", vars, err);
    deep_resolve_json_string(item, "path", vars, err, true);

    if (item.contains("externalCommand") && item["externalCommand"].is_object()) {
        auto& ext = item["externalCommand"];
        deep_resolve_json_string(ext, "cwd", vars, err, true);
        if (ext.contains("cwd") && ext["cwd"].is_string() && !ext["cwd"].get<std::string>().empty())
            vars["CWD"] = ext["cwd"].get<std::string>();
        deep_resolve_json_string(ext, "command", vars, err, true);
        deep_resolve_json_string(ext, "shellLine", vars, err);
        deep_resolve_json_arg_array(ext, "args", vars, context, err);
    }

    if (item.contains("source") && item["source"].is_object()) {
        auto& source = item["source"];
        if (source.contains("files") && source["files"].is_array()) {
            for (auto& value : source["files"]) {
                if (value.is_string())
                    value = media::path::normalize_local_path(
                        deep_resolve_variables(value.get<std::string>(), vars, err), true);
            }
        }
        if (source.contains("folders") && source["folders"].is_array()) {
            for (auto& value : source["folders"]) {
                if (value.is_string())
                    value = media::path::normalize_local_path(
                        deep_resolve_variables(value.get<std::string>(), vars, err), true);
            }
        }
    }

    if (item.contains("output") && item["output"].is_object()) {
        auto& output = item["output"];
        deep_resolve_json_string(output, "directory", vars, err, true);
        deep_resolve_json_string(output, "file", vars, err, true);
    }
}

void resolve_custom_command_item_variables(nlohmann::json& item,
                                           const VariableContext& context,
                                           std::string* err)
{
    resolve_custom_command_item_variables_impl(item, context, make_variable_map(context), err);
}

void resolve_custom_command_item_variables(nlohmann::json& item,
                                           const VariableContext& context,
                                           const VariableMap& extra_vars,
                                           std::string* err)
{
    VariableMap vars = make_variable_map(context);
    if (!extra_vars.empty())
        apply_variable_overrides(vars, extra_vars, err);
    resolve_custom_command_item_variables_impl(item, context, std::move(vars), err);
}

bool selection_mode_is_per_item(std::string_view mode)
{
    return mode == "perItem";
}

std::vector<VariableContext> build_selection_contexts(const VariableContext& base,
                                                      bool per_item)
{
    if (per_item && !base.selection_paths.empty()) {
        std::vector<VariableContext> out;
        out.reserve(base.selection_paths.size());
        for (const auto& path : base.selection_paths) {
            VariableContext item = base;
            item.source_file = path;
            item.selection_paths = {path};
            out.push_back(std::move(item));
        }
        return out;
    }
    return {base};
}

std::string json_override_value_to_string(const nlohmann::json& v)
{
    if (v.is_string())
        return v.get<std::string>();
    if (v.is_number_integer())
        return std::to_string(v.get<long long>());
    if (v.is_number_unsigned())
        return std::to_string(v.get<unsigned long long>());
    if (v.is_number_float()) {
        const double d = v.get<double>();
        if (d == static_cast<double>(static_cast<long long>(d)))
            return std::to_string(static_cast<long long>(d));
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%.17g", d);
        return buf;
    }
    if (v.is_boolean())
        return v.get<bool>() ? "true" : "false";
    if (v.is_null())
        return {};
    return v.dump();
}

const nlohmann::json* variable_override_object(const nlohmann::json& j)
{
    if (j.is_object() && j.contains("variables") && j["variables"].is_object())
        return &j["variables"];
    if (j.is_object())
        return &j;
    return nullptr;
}

std::optional<VariableMap> parse_variable_overrides(const nlohmann::json& j, std::string* err)
{
    const nlohmann::json* obj = variable_override_object(j);
    if (!obj) {
        if (err) *err = "variable config must be a JSON object";
        return std::nullopt;
    }

    VariableMap out;
    for (auto it = obj->begin(); it != obj->end(); ++it) {
        if (it.key().empty()) {
            if (err) *err = "variable config: empty key";
            return std::nullopt;
        }
        if (!it.value().is_string() && !it.value().is_number() && !it.value().is_boolean()
            && !it.value().is_null()) {
            if (err) *err = "variable config: value for '" + it.key() + "' must be scalar";
            return std::nullopt;
        }
        out[it.key()] = json_override_value_to_string(it.value());
    }
    return out;
}

std::optional<VariableMap> load_variable_overrides(const std::string& path, std::string* err)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        if (err) *err = "cannot open variable config: " + path;
        return std::nullopt;
    }
    try {
        const auto j = nlohmann::json::parse(f);
        return parse_variable_overrides(j, err);
    } catch (const std::exception& ex) {
        if (err) *err = std::string("variable config JSON parse error in '") + path + "': " + ex.what();
        return std::nullopt;
    }
}

std::string deep_resolve_variables(std::string_view value,
                                   const VariableMap& vars,
                                   std::string* err,
                                   int max_passes)
{
    const int passes = std::clamp(max_passes, 1, kMaxDeepVariablePasses);
    if (passes <= 1)
        return resolve_variables(value, vars, err);

    if (!media::strutil::has_variable_tokens(std::string(value)))
        return std::string(value);

    std::string cur(value);
    std::vector<std::string> seen;
    for (int pass = 0; pass < passes; ++pass) {
        if (!media::strutil::has_variable_tokens(cur))
            break;
        std::string resolve_err;
        const bool quiet = pass > 0;
        std::string next = resolve_variables(cur, vars, &resolve_err, quiet);
        if (!resolve_err.empty()) {
            if (err) *err = resolve_err;
            return std::string(value);
        }
        if (next == cur)
            break;
        if (std::find(seen.begin(), seen.end(), next) != seen.end()) {
            if (err) *err = "command_variables: circular variable reference";
            return std::string(value);
        }
        seen.push_back(std::move(cur));
        cur = std::move(next);
    }
    return cur;
}

bool apply_variable_overrides(VariableMap& vars,
                              const VariableMap& overrides,
                              std::string* err,
                              int max_passes)
{
    if (overrides.empty())
        return true;

    const int passes = std::clamp(max_passes, 1, kMaxDeepVariablePasses);
    for (int pass = 0; pass < passes; ++pass) {
        bool any_change = false;
        for (const auto& [key, raw] : overrides) {
            std::string resolve_err;
            const std::string resolved = resolve_variables(raw, vars, &resolve_err, pass > 0);
            if (!resolve_err.empty()) {
                if (err) *err = resolve_err;
                return false;
            }
            const auto it = vars.find(key);
            if (it == vars.end() || it->second != resolved) {
                vars[key] = resolved;
                any_change = true;
            }
        }
        if (!any_change)
            break;

        bool needs_another = false;
        for (const auto& [key, raw] : overrides) {
            (void)raw;
            const auto it = vars.find(key);
            if (it != vars.end() && media::strutil::has_variable_tokens(it->second)) {
                needs_another = true;
                break;
            }
        }
        if (!needs_another)
            break;

        if (pass + 1 >= passes) {
            for (const auto& [key, raw] : overrides) {
                (void)raw;
                const auto it = vars.find(key);
                if (it != vars.end() && media::strutil::has_variable_tokens(it->second)) {
                    if (err) *err = "variable override unresolved after deep expansion: " + key;
                    return false;
                }
            }
        }
    }
    return true;
}

std::string resolve_installer_path(std::string_view path, const VariableMap& vars, std::string* err)
{
    const std::string raw(path);
    if (raw.empty())
        return {};

    std::string resolved = resolve_variables(raw, vars, err);
    if (err && !err->empty())
        return {};
    if (resolved.empty()) {
        if (err) *err = "path is empty after variable expansion: " + raw;
        return {};
    }

    std::error_code ec;
    fs::path p = media::path::path_from_utf8(resolved);
    if (!p.is_absolute())
        p = fs::absolute(p, ec);
    return media::path::normalize_local_path(media::path::path_to_utf8(p), true);
}

VariableMap make_bundle_variable_map(const VariableContext& context, std::string* err)
{
    VariableMap vars = make_variable_map(context);
    if (context.variable_config_path.empty())
        return vars;

    std::string resolve_err;
    const std::string config_path = resolve_installer_path(context.variable_config_path, vars, &resolve_err);
    if (!resolve_err.empty()) {
        if (err) *err = resolve_err;
        return {};
    }

    std::string load_err;
    const auto overrides = load_variable_overrides(config_path, &load_err);
    if (!overrides) {
        if (err) *err = load_err.empty() ? "variable config load failed" : load_err;
        return {};
    }
    if (!apply_variable_overrides(vars, *overrides, err))
        return {};
    refresh_derived_variables(vars, &*overrides);
    return vars;
}

std::string path_to_stored_expression(std::string_view path, const VariableContext& context)
{
    return path_to_stored_expression_impl(path, make_variable_map(context));
}

std::string expand_stored_text(std::string_view text)
{
    if (text.empty() || text.find("${") == std::string_view::npos)
        return std::string(text);
    return resolve_variables(text, make_variable_map({}));
}

std::string stored_scope_expression(std::string_view scope)
{
    if (scope.empty() || scope.find("${") != std::string_view::npos)
        return std::string(scope);
    constexpr std::string_view k_file = "file://";
    if (scope.size() >= k_file.size()
        && media::strutil::starts_with_ascii_ci(scope, k_file)) {
        const std::string_view rest = scope.substr(k_file.size());
        const auto star = rest.find('*');
        const std::string_view path = star == std::string_view::npos ? rest : rest.substr(0, star);
        const std::string_view suffix = star == std::string_view::npos ? std::string_view{} : rest.substr(star);
        if (path.empty())
            return std::string(scope);
        std::string stored = path_to_stored_expression(path);
        // path_to_stored_expression strips a trailing separator. A file://dir/** scope
        // must keep that separator or the glob glues onto the directory name.
        if (!suffix.empty() && suffix.front() == '*' && !stored.empty() && stored.back() != '/')
            stored.push_back('/');
        return std::string(k_file) + stored + std::string(suffix);
    }
    if (has_uri_scheme(scope) || pm::vfs::is_remote_uri(scope))
        return std::string(scope);
    if (const std::string vfs = pm::vfs::repair_vfs_location(scope); !vfs.empty())
        return vfs;
    return path_to_stored_expression(scope);
}

ParsedCustomCliExtras parse_custom_command_cli_extras(const std::vector<std::string>& extra_args)
{
    ParsedCustomCliExtras out;
    bool passthrough_only = false;
    bool dropping_selection_values = false;
    bool dropping_override_values = false;

    for (size_t i = 0; i < extra_args.size(); ++i) {
        const std::string& arg = extra_args[i];
        if (!passthrough_only && arg == "--") {
            passthrough_only = true;
            dropping_selection_values = false;
            dropping_override_values = false;
            continue;
        }

        if (!passthrough_only) {
            if (dropping_selection_values) {
                if (!arg.empty() && arg[0] == '-')
                    dropping_selection_values = false;
                else
                    continue;
            }
            if (dropping_override_values) {
                if (!arg.empty() && arg[0] == '-')
                    dropping_override_values = false;
                else
                    continue;
            }
            if (is_custom_command_source_arg(arg)) {
                dropping_selection_values = true;
                continue;
            }
            if (is_cli_variable_override_token(arg)) {
                std::string key = arg.substr(2);
                std::string value;
                if (const auto eq = key.find('='); eq != std::string::npos) {
                    value = key.substr(eq + 1);
                    key = key.substr(0, eq);
                } else if (i + 1 < extra_args.size() && !extra_args[i + 1].empty()
                           && extra_args[i + 1][0] != '-') {
                    value = extra_args[i + 1];
                    dropping_override_values = true;
                } else {
                    value = "true";
                }
                key = normalize_cli_override_key(std::move(key));
                if (!key.empty())
                    out.overrides[key] = value;
                continue;
            }
        }

        out.passthrough.push_back(arg);
    }
    return out;
}

void enrich_context_from_cli_overrides(VariableContext& ctx, VariableMap& overrides)
{
    if (overrides.empty())
        return;

    const auto abs_cwd = [&]() {
        if (!ctx.cwd.empty())
            return ctx.cwd;
        std::error_code ec;
        return media::path::path_to_utf8(fs::current_path(ec));
    }();

    const auto normalize_path_override = [&](const std::string& key, std::string& value) {
        if (value.empty())
            return;
        if (key == "CURRENT_FILE" || key == "SRC_FILE" || key == "CWD"
            || key == "CURRENT_PATH" || key == "SRC_DIR")
            value = media::path::path_to_utf8(absolute_context_path(value, abs_cwd));
    };
    for (auto& [key, value] : overrides)
        normalize_path_override(key, value);

    if (ctx.cwd.empty()) {
        if (const auto it = overrides.find("CWD"); it != overrides.end() && !it->second.empty())
            ctx.cwd = it->second;
    }

    if (ctx.source_file.empty()) {
        if (const auto it = overrides.find("CURRENT_FILE"); it != overrides.end() && !it->second.empty())
            ctx.source_file = it->second;
        else if (const auto it = overrides.find("SRC_FILE"); it != overrides.end() && !it->second.empty())
            ctx.source_file = it->second;
    }

    if (ctx.selection_paths.empty()) {
        if (const auto it = overrides.find("CURRENT_SELECTION"); it != overrides.end()
            && !it->second.empty()) {
            ctx.selection_paths = split_selection_override_paths(it->second, ctx.cwd.empty() ? abs_cwd : ctx.cwd);
        } else if (!ctx.source_file.empty()) {
            ctx.selection_paths = {ctx.source_file};
        }
    }

    if (ctx.current_hwnd.empty()) {
        if (const auto it = overrides.find("CURRENT_HWND"); it != overrides.end() && !it->second.empty())
            ctx.current_hwnd = it->second;
    }
    if (ctx.current_pid.empty()) {
        if (const auto it = overrides.find("CURRENT_PID"); it != overrides.end() && !it->second.empty())
            ctx.current_pid = it->second;
    }
    if (ctx.current_wintitle.empty()) {
        if (const auto it = overrides.find("CURRENT_WINTITLE"); it != overrides.end())
            ctx.current_wintitle = it->second;
    }
    if (ctx.current_process.empty()) {
        if (const auto it = overrides.find("CURRENT_PROCESS"); it != overrides.end() && !it->second.empty())
            ctx.current_process = it->second;
    }
    if (ctx.current_url.empty()) {
        if (const auto it = overrides.find("CURRENT_URL"); it != overrides.end() && !it->second.empty())
            ctx.current_url = it->second;
    }
    if (ctx.current_url_title.empty()) {
        if (const auto it = overrides.find("CURRENT_URL_TITLE"); it != overrides.end())
            ctx.current_url_title = it->second;
    }
    if (ctx.last_url.empty()) {
        if (const auto it = overrides.find("LAST_URL"); it != overrides.end() && !it->second.empty())
            ctx.last_url = it->second;
    }

    if (ctx.voice_wake.empty()) {
        if (const auto it = overrides.find("VOICE_WAKE"); it != overrides.end())
            ctx.voice_wake = it->second;
    }
    if (ctx.voice_command.empty()) {
        if (const auto it = overrides.find("VOICE_COMMAND"); it != overrides.end())
            ctx.voice_command = it->second;
    }
    if (ctx.voice_full.empty()) {
        if (const auto it = overrides.find("VOICE_FULL"); it != overrides.end())
            ctx.voice_full = it->second;
    }
}

} // namespace media::commands
