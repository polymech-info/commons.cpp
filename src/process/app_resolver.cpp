#include "app_resolver.hpp"
#include "fs/path_sanitizer.hpp"

#include "app_exe_directory.hpp"
#include "constants.hpp"
#include "logging/pm_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <mutex>
#include <string_view>
#include <unordered_set>
#include <utility>
#include "string/string_utils.hpp"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  ifndef IO_REPARSE_TAG_APPEXECLINK
#    define IO_REPARSE_TAG_APPEXECLINK (0x8000001BL)
#  endif
#else
#  include <unistd.h>
#endif

namespace media::app {
namespace {

namespace fs = std::filesystem;

constexpr const char k_ch[] = "app_resolver";

std::mutex g_mu;
std::vector<KnownTool> g_known_tools;
bool g_bin_scanned = false;
AppDiscoveryFn g_app_discovery;

ResolveSource effective_sources(const ResolveRequest& request)
{
    if (request.sources != ResolveSource::None)
        return request.sources;
    return request.intent == ResolveIntent::Command ? k_command_sources : k_application_sources;
}


std::string trim_copy(std::string_view in)
{
    std::size_t b = 0;
    while (b < in.size() && std::isspace(static_cast<unsigned char>(in[b])))
        ++b;
    std::size_t e = in.size();
    while (e > b && std::isspace(static_cast<unsigned char>(in[e - 1])))
        --e;
    return std::string(in.substr(b, e - b));
}

std::string strip_quotes(std::string s)
{
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
        return s.substr(1, s.size() - 2);
    return s;
}

fs::path path_from_utf8(std::string_view s)
{
    return media::path::path_from_utf8(std::string(s));
}

std::string path_key(const fs::path& p)
{
    std::string s = media::path::path_to_utf8(p);
    for (char& c : s) {
        if (c == '/')
            c = '\\';
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    while (!s.empty() && (s.back() == '\\' || s.back() == '/'))
        s.pop_back();
    return s;
}

bool iequals_ascii(std::string_view a, std::string_view b)
{
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const auto ca = static_cast<unsigned char>(a[i]);
        const auto cb = static_cast<unsigned char>(b[i]);
        if (std::tolower(ca) != std::tolower(cb))
            return false;
    }
    return true;
}

bool env_key_match(std::string_view a, std::string_view b)
{
#if defined(_WIN32)
    return iequals_ascii(a, b);
#else
    return a == b;
#endif
}

std::string env_lookup(const EnvironmentMap* env, std::string_view name)
{
    if (!env)
        return {};
    for (const auto& [k, v] : *env) {
        if (env_key_match(k, name))
            return v;
    }
    return {};
}

#if defined(_WIN32)
std::string wide_to_utf8(std::wstring_view ws)
{
    if (ws.empty())
        return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
                                        nullptr, 0, nullptr, nullptr);
    if (n <= 0)
        return {};
    std::string out(static_cast<std::size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()),
                          out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring utf8_to_wide(std::string_view s)
{
    if (s.empty())
        return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0)
        return {};
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string win_env(const wchar_t* name, const EnvironmentMap* env, std::string_view utf8_name)
{
    if (const std::string from_map = env_lookup(env, utf8_name); !from_map.empty())
        return from_map;
    const DWORD n = ::GetEnvironmentVariableW(name, nullptr, 0);
    if (n == 0)
        return {};
    std::wstring buf(n, L'\0');
    const DWORD got = ::GetEnvironmentVariableW(name, buf.data(), n);
    if (got == 0)
        return {};
    if (!buf.empty() && buf.back() == L'\0')
        buf.pop_back();
    if (got < buf.size())
        buf.resize(got);
    return wide_to_utf8(buf);
}

bool is_appexeclink(const fs::path& p)
{
    WIN32_FIND_DATAW fd{};
    const HANDLE h = ::FindFirstFileW(p.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    ::FindClose(h);
    return (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
        && fd.dwReserved0 == IO_REPARSE_TAG_APPEXECLINK;
}
#endif

std::string posix_env(const char* name, const EnvironmentMap* env)
{
    if (const std::string from_map = env_lookup(env, name); !from_map.empty())
        return from_map;
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : std::string{};
}

std::vector<std::string> split_env_list(const std::string& text, char sep)
{
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t end = text.find(sep, start);
        const std::string item = text.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (!item.empty())
            out.push_back(item);
        if (end == std::string::npos)
            break;
        start = end + 1;
    }
    return out;
}

std::string stem_lower(const fs::path& p)
{
    return media::strutil::lower_ascii(media::path::path_to_utf8(p.stem()));
}

std::string filename_lower(const fs::path& p)
{
    return media::strutil::lower_ascii(media::path::path_to_utf8(p.filename()));
}

std::string ext_lower(const fs::path& p)
{
    return media::strutil::lower_ascii(media::path::path_to_utf8(p.extension()));
}

bool looks_like_path(std::string_view q)
{
    if (q.empty())
        return false;
    if (q.size() >= 2 && q[1] == ':')
        return true;
    return q.find('/') != std::string_view::npos || q.find('\\') != std::string_view::npos;
}

bool exists_path(const fs::path& p)
{
    std::error_code ec;
    return !p.empty() && fs::exists(p, ec) && !ec;
}

bool is_regularish_file(const fs::path& p)
{
    std::error_code ec;
    if (p.empty() || !fs::exists(p, ec) || ec)
        return false;
    if (fs::is_directory(p, ec) || ec)
        return false;
    return true;
}

#if !defined(_WIN32)
bool is_executable_bit(const fs::path& p)
{
    return ::access(p.c_str(), X_OK) == 0;
}
#endif

std::vector<std::string> pathext_list(const ResolveRequest& request)
{
#if defined(_WIN32)
    std::string raw = win_env(L"PATHEXT", request.environment, "PATHEXT");
    if (raw.empty())
        raw = ".COM;.EXE;.BAT;.CMD";
    auto items = split_env_list(raw, ';');
    std::vector<std::string> out;
    out.reserve(items.size());
    for (std::string item : items) {
        item = media::strutil::lower_ascii(trim_copy(item));
        if (item.empty())
            continue;
        if (item.front() != '.')
            item.insert(item.begin(), '.');
        out.push_back(std::move(item));
    }
    return out;
#else
    (void)request;
    return {};
#endif
}

bool pathext_contains(const ResolveRequest& request, const std::string& ext)
{
    for (const auto& item : pathext_list(request)) {
        if (item == ext)
            return true;
    }
    return false;
}

std::vector<fs::path> name_candidates(std::string_view query, const ResolveRequest& request)
{
    std::vector<fs::path> out;
    const fs::path raw = path_from_utf8(query);
    if (raw.has_extension()) {
        out.push_back(raw.filename());
        return out;
    }
#if defined(_WIN32)
    for (const std::string& ext : pathext_list(request))
        out.push_back(path_from_utf8(std::string(query) + ext));
#else
    out.push_back(raw.filename());
    (void)request;
#endif
    return out;
}

LaunchKind kind_from_path(const fs::path& p, bool alias)
{
    if (alias)
        return LaunchKind::AppAlias;
    const std::string ext = ext_lower(p);
    if (ext == ".cmd" || ext == ".bat")
        return LaunchKind::CmdScript;
    if (ext == ".ps1")
        return LaunchKind::PowerShell;
    if (ext == ".app")
        return LaunchKind::Bundle;
    if (ext == ".exe" || ext == ".com" || ext.empty())
        return LaunchKind::Native;
    return LaunchKind::Unknown;
}

bool file_runnable(const fs::path& p)
{
    if (!is_regularish_file(p))
        return false;
#if defined(_WIN32)
    return true;
#else
    return is_executable_bit(p);
#endif
}

void apply_alias_flags(ResolvedApplication& app)
{
    if (app.executable.empty())
        return;
#if defined(_WIN32)
    if (!is_appexeclink(app.executable))
        return;
    app.app_execution_alias = true;
    app.packaged = true;
    if (app.source != ApplicationSource::WindowsPackage)
        app.source = ApplicationSource::AppExecutionAlias;
    app.kind = LaunchKind::AppAlias;
    if (!app.launch_name)
        app.launch_name = media::path::path_to_utf8(app.executable.filename());
#endif
}

void finalize_candidate(ResolvedApplication& app, const ResolveRequest& request)
{
    apply_alias_flags(app);
    if (app.kind == LaunchKind::Unknown)
        app.kind = kind_from_path(app.executable, app.app_execution_alias);
    if (app.display_name.empty())
        app.display_name = media::path::path_to_utf8(app.executable.stem());
    app.exists = exists_path(app.executable);
    if (app.match == MatchQuality::Heuristic) {
        app.directly_executable = false;
    } else {
        app.directly_executable =
            app.exists && (app.kind == LaunchKind::Native
                           || app.kind == LaunchKind::AppAlias
                           || app.kind == LaunchKind::Bundle
                           || (app.kind == LaunchKind::CmdScript
                               && pathext_contains(request, ext_lower(app.executable))));
    }
}

int source_rank(ApplicationSource source)
{
    switch (source) {
    case ApplicationSource::ExplicitPath: return 0;
    case ApplicationSource::TanitKnownTool: return 1;
    case ApplicationSource::TanitBundled: return 2;
    case ApplicationSource::TanitPlugin: return 3;
    case ApplicationSource::Path: return 10;
    case ApplicationSource::MacPath:
    case ApplicationSource::LinuxPath: return 10;
    case ApplicationSource::WindowsAppPaths: return 20;
    case ApplicationSource::AppExecutionAlias: return 21;
    case ApplicationSource::WindowsPackage: return 22;
    case ApplicationSource::ExistingAppDiscovery: return 30;
    default: return 40;
    }
}

int match_rank(MatchQuality match)
{
    switch (match) {
    case MatchQuality::Exact: return 0;
    case MatchQuality::Registered: return 1;
    case MatchQuality::Heuristic: return 2;
    }
    return 3;
}

std::string identity_key(const ResolvedApplication& app)
{
    if (app.app_execution_alias && app.launch_name)
        return "alias:" + media::strutil::lower_ascii(*app.launch_name);
    if (!app.executable.empty())
        return "exe:" + path_key(app.executable);
    if (app.launch_name)
        return "launch:" + media::strutil::lower_ascii(*app.launch_name);
    return "name:" + media::strutil::lower_ascii(app.display_name);
}

void sort_and_dedup(std::vector<ResolvedApplication>& results)
{
    std::stable_sort(results.begin(), results.end(), [](const ResolvedApplication& a, const ResolvedApplication& b) {
        const int ma = match_rank(a.match);
        const int mb = match_rank(b.match);
        if (ma != mb)
            return ma < mb;
        const int sa = source_rank(a.source);
        const int sb = source_rank(b.source);
        if (sa != sb)
            return sa < sb;
        if (a.source_order != b.source_order)
            return a.source_order < b.source_order;
        if (a.path_index && b.path_index && *a.path_index != *b.path_index)
            return *a.path_index < *b.path_index;
        return path_key(a.executable) < path_key(b.executable);
    });
    std::unordered_set<std::string> seen;
    std::vector<ResolvedApplication> kept;
    kept.reserve(results.size());
    for (auto& app : results) {
        if (!seen.insert(identity_key(app)).second)
            continue;
        kept.push_back(std::move(app));
    }
    results.swap(kept);
}

bool query_matches_tool(std::string_view query, const KnownTool& tool)
{
    const std::string q = media::strutil::lower_ascii(std::string(query));
    if (q.empty())
        return false;
    if (iequals_ascii(tool.name, query))
        return true;
    const std::string stem = stem_lower(tool.path);
    const std::string file = filename_lower(tool.path);
    if (q == stem || q == file)
        return true;
#if defined(_WIN32)
    if (q + ".exe" == file || q == stem + ".exe")
        return true;
#endif
    return false;
}

void ensure_bin_tools_locked()
{
    if (g_bin_scanned)
        return;
    g_bin_scanned = true;
    const fs::path bin = exe_bin_directory();
    if (bin.empty())
        return;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(bin, ec)) {
        if (ec || !entry.is_regular_file(ec))
            continue;
        const fs::path p = entry.path();
        const std::string name = stem_lower(p);
        if (name.empty())
            continue;
        bool exists = false;
        for (const auto& t : g_known_tools) {
            if (iequals_ascii(t.name, name) || path_key(t.path) == path_key(p)) {
                exists = true;
                break;
            }
        }
        if (exists)
            continue;
        KnownTool tool;
        tool.name = name;
        tool.path = p;
        tool.install_root = bin;
        tool.display_name = media::path::path_to_utf8(p.stem());
        g_known_tools.push_back(std::move(tool));
    }
}

ResolvedApplication make_base(std::string_view query)
{
    ResolvedApplication app;
    app.query = std::string(query);
    return app;
}

void add_file_candidate(std::vector<ResolvedApplication>& results,
                        std::string_view query,
                        const fs::path& file,
                        ApplicationSource source,
                        const ResolveRequest& request,
                        std::size_t source_order = 0,
                        std::optional<std::size_t> path_index = std::nullopt,
                        bool bundled = false)
{
    if (file.empty() || !file_runnable(file))
        return;
    ResolvedApplication app = make_base(query);
    app.executable = file;
    app.source = source;
    app.kind = kind_from_path(file, false);
    app.match = MatchQuality::Exact;
    app.source_order = source_order;
    app.path_index = path_index;
    app.bundled = bundled;
    if (source == ApplicationSource::Path) {
#if defined(__APPLE__)
        app.source = ApplicationSource::MacPath;
#elif !defined(_WIN32)
        app.source = ApplicationSource::LinuxPath;
#endif
    }
    finalize_candidate(app, request);
    if (!app.exists)
        return;
    results.push_back(std::move(app));
}

void add_explicit(std::vector<ResolvedApplication>& results,
                  std::string_view query,
                  const ResolveRequest& request)
{
    if (!has_source(effective_sources(request), ResolveSource::Explicit) || !looks_like_path(query))
        return;
    fs::path raw = path_from_utf8(strip_quotes(std::string(query)));
    if (raw.is_relative() && request.cwd)
        raw = *request.cwd / raw;
    std::vector<fs::path> variants;
    variants.push_back(raw);
#if defined(_WIN32)
    if (!raw.has_extension()) {
        for (const std::string& ext : pathext_list(request))
            variants.push_back(path_from_utf8(media::path::path_to_utf8(raw) + ext));
    }
#endif
    for (const fs::path& v : variants) {
        if (!exists_path(v))
            continue;
        add_file_candidate(results, query, v, ApplicationSource::ExplicitPath, request);
        if (!request.all)
            return;
    }
}

void add_known_tools(std::vector<ResolvedApplication>& results,
                     std::string_view query,
                     const ResolveRequest& request)
{
    if (!has_source(effective_sources(request), ResolveSource::Tanit))
        return;
    std::vector<KnownTool> tools;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        ensure_bin_tools_locked();
        tools = g_known_tools;
    }
    for (const KnownTool& tool : tools) {
        if (!query_matches_tool(query, tool))
            continue;
        if (!exists_path(tool.path))
            continue;
        const bool from_bin = path_key(tool.path.parent_path()) == path_key(exe_bin_directory());
        ResolvedApplication app = make_base(query);
        app.executable = tool.path;
        app.install_root = tool.install_root.empty() ? tool.path.parent_path() : tool.install_root;
        app.display_name = tool.display_name.empty() ? tool.name : tool.display_name;
        app.source = from_bin ? ApplicationSource::TanitBundled : ApplicationSource::TanitKnownTool;
        app.bundled = true;
        app.match = MatchQuality::Exact;
        app.metadata["known_tool"] = tool.name;
        finalize_candidate(app, request);
        if (!app.exists)
            continue;
        results.push_back(std::move(app));
        if (!request.all)
            return;
    }
}

void search_dir(std::vector<ResolvedApplication>& results,
                std::string_view query,
                const fs::path& dir,
                ApplicationSource source,
                const ResolveRequest& request,
                std::size_t source_order,
                std::optional<std::size_t> path_index)
{
    if (dir.empty())
        return;
    std::error_code ec;
    if (!fs::is_directory(dir, ec) || ec)
        return;
    for (const fs::path& name : name_candidates(query, request)) {
        const std::size_t before = results.size();
        add_file_candidate(results, query, dir / name.filename(), source, request,
                           source_order, path_index, false);
        if (!request.all && results.size() > before)
            return;
    }
}

void add_extra_paths(std::vector<ResolvedApplication>& results,
                     std::string_view query,
                     const ResolveRequest& request)
{
    if (!has_source(effective_sources(request), ResolveSource::Path) || looks_like_path(query))
        return;
    for (std::size_t i = 0; i < request.extra_paths.size(); ++i) {
        search_dir(results, query, request.extra_paths[i], ApplicationSource::Path,
                   request, i, i);
        if (!request.all && !results.empty())
            return;
    }
}

void add_environment_path(std::vector<ResolvedApplication>& results,
                          std::string_view query,
                          const ResolveRequest& request)
{
    if (!has_source(effective_sources(request), ResolveSource::Path) || looks_like_path(query))
        return;
#if defined(_WIN32)
    const std::string raw = win_env(L"PATH", request.environment, "PATH");
    const auto dirs = split_env_list(raw, ';');
#else
    const std::string raw = posix_env("PATH", request.environment);
    const auto dirs = split_env_list(raw, ':');
#endif
    const std::size_t extra_n = request.extra_paths.size();
    for (std::size_t i = 0; i < dirs.size(); ++i) {
        const fs::path dir = path_from_utf8(dirs[i]);
        search_dir(results, query, dir, ApplicationSource::Path, request, extra_n + i, i);
        if (!request.all && !results.empty())
            return;
    }
}

#if defined(_WIN32)
std::string reg_read_sz(HKEY key, const wchar_t* value_name)
{
    DWORD type = 0;
    DWORD cb = 0;
    if (::RegQueryValueExW(key, value_name, nullptr, &type, nullptr, &cb) != ERROR_SUCCESS)
        return {};
    if (type != REG_SZ && type != REG_EXPAND_SZ)
        return {};
    if (cb < sizeof(wchar_t))
        return {};
    std::wstring buf(cb / sizeof(wchar_t), L'\0');
    if (::RegQueryValueExW(key, value_name, nullptr, &type,
                           reinterpret_cast<LPBYTE>(buf.data()), &cb) != ERROR_SUCCESS)
        return {};
    while (!buf.empty() && buf.back() == L'\0')
        buf.pop_back();
    if (type == REG_EXPAND_SZ) {
        wchar_t expanded[32768]{};
        const DWORD cap = static_cast<DWORD>(sizeof(expanded) / sizeof(expanded[0]));
        const DWORD n = ::ExpandEnvironmentStringsW(buf.c_str(), expanded, cap);
        if (n > 0 && n < cap)
            buf = expanded;
    }
    return wide_to_utf8(buf);
}

std::string unquote_exe(std::string s)
{
    s = trim_copy(s);
    if (s.size() >= 2 && s.front() == '"') {
        const auto end = s.find('"', 1);
        if (end != std::string::npos)
            return s.substr(1, end - 1);
    }
    return s;
}

bool try_app_paths_key(HKEY root, const std::wstring& rel, ResolvedApplication& app)
{
    HKEY key = nullptr;
    if (::RegOpenKeyExW(root, rel.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS)
        return false;
    const std::string exe = unquote_exe(reg_read_sz(key, nullptr));
    const std::string path_val = unquote_exe(reg_read_sz(key, L"Path"));
    ::RegCloseKey(key);
    if (exe.empty())
        return false;
    app.executable = path_from_utf8(exe);
    if (!path_val.empty())
        app.app_paths_env = path_from_utf8(path_val);
    return true;
}

void add_windows_app_paths(std::vector<ResolvedApplication>& results,
                           std::string_view query,
                           const ResolveRequest& request)
{
    if (!has_source(effective_sources(request), ResolveSource::AppPaths))
        return;
    std::string name = trim_copy(query);
    if (name.empty() || looks_like_path(name))
        return;
    if (name.find('.') == std::string::npos)
        name += ".exe";
    const std::wstring rel = L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + utf8_to_wide(name);
    const std::wstring rel32 = L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + utf8_to_wide(name);

    ResolvedApplication app = make_base(query);
    app.source = ApplicationSource::WindowsAppPaths;
    app.match = MatchQuality::Exact;
    bool found = false;
    try {
        found = try_app_paths_key(HKEY_CURRENT_USER, rel, app)
            || try_app_paths_key(HKEY_LOCAL_MACHINE, rel, app)
            || try_app_paths_key(HKEY_LOCAL_MACHINE, rel32, app);
    } catch (...) {
        pm::log::debug_lazy(k_ch, [&] {
            return std::string("app paths read failed for ") + name;
        });
        return;
    }
    if (!found)
        return;
    finalize_candidate(app, request);
    if (!app.exists)
        return;
    results.push_back(std::move(app));
}
#endif

void add_existing_discovery(std::vector<ResolvedApplication>& results,
                            std::string_view query,
                            const ResolveRequest& request)
{
    if (request.intent == ResolveIntent::Command)
        return;
    if (!has_source(effective_sources(request), ResolveSource::AppIndex))
        return;
    AppDiscoveryFn fn;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        fn = g_app_discovery;
    }
    if (!fn)
        return;
    std::vector<ResolvedApplication> extra;
    try {
        extra = fn(query, request);
    } catch (...) {
        pm::log::debug_lazy(k_ch, [] {
            return std::string("existing app discovery failed");
        });
        return;
    }
    for (auto& app : extra) {
        if (app.query.empty())
            app.query = std::string(query);
        if (app.source == ApplicationSource::Unknown)
            app.source = ApplicationSource::ExistingAppDiscovery;
        if (app.match == MatchQuality::Exact)
            app.match = MatchQuality::Heuristic;
        finalize_candidate(app, request);
        if (!app.exists)
            continue;
        results.push_back(std::move(app));
    }
}

} // namespace

std::string_view application_source_id(ApplicationSource source)
{
    switch (source) {
    case ApplicationSource::ExplicitPath: return "explicit-path";
    case ApplicationSource::TanitBundled: return "tanit-bundled";
    case ApplicationSource::TanitPlugin: return "tanit-plugin";
    case ApplicationSource::TanitKnownTool: return "tanit-known-tool";
    case ApplicationSource::Path: return "path";
    case ApplicationSource::AppExecutionAlias: return "app-execution-alias";
    case ApplicationSource::WindowsAppPaths: return "windows-app-paths";
    case ApplicationSource::WindowsRegisteredApp: return "windows-registered-app";
    case ApplicationSource::WindowsStartMenu: return "windows-start-menu";
    case ApplicationSource::WindowsPackage: return "windows-package";
    case ApplicationSource::MacApplicationBundle: return "mac-application-bundle";
    case ApplicationSource::MacPath: return "mac-path";
    case ApplicationSource::LinuxDesktopEntry: return "linux-desktop-entry";
    case ApplicationSource::LinuxPath: return "linux-path";
    case ApplicationSource::ExistingAppDiscovery: return "existing-app-discovery";
    case ApplicationSource::Unknown: return "unknown";
    }
    return "unknown";
}

std::string_view launch_kind_id(LaunchKind kind)
{
    switch (kind) {
    case LaunchKind::Native: return "native";
    case LaunchKind::CmdScript: return "cmd-script";
    case LaunchKind::PowerShell: return "powershell";
    case LaunchKind::AppAlias: return "app-alias";
    case LaunchKind::Bundle: return "bundle";
    case LaunchKind::Unknown: return "unknown";
    }
    return "unknown";
}

std::string_view match_quality_id(MatchQuality match)
{
    switch (match) {
    case MatchQuality::Exact: return "exact";
    case MatchQuality::Registered: return "registered";
    case MatchQuality::Heuristic: return "heuristic";
    }
    return "heuristic";
}

void register_known_tool(KnownTool tool)
{
    if (tool.name.empty() || tool.path.empty())
        return;
    std::lock_guard<std::mutex> lock(g_mu);
    for (auto& existing : g_known_tools) {
        if (iequals_ascii(existing.name, tool.name)) {
            existing = std::move(tool);
            return;
        }
    }
    g_known_tools.push_back(std::move(tool));
}

void clear_known_tools()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_known_tools.clear();
    g_bin_scanned = false;
}

void set_existing_app_discovery_fn(AppDiscoveryFn fn)
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_app_discovery = std::move(fn);
}

std::vector<ResolvedApplication> resolve_application(std::string_view query, const ResolveRequest& request)
{
    const std::string q = trim_copy(query);
    if (q.empty())
        return {};

    std::vector<ResolvedApplication> results;
    auto enough = [&]() -> bool {
        return !request.all && !results.empty();
    };

    try {
        add_explicit(results, q, request);
        if (!enough())
            add_known_tools(results, q, request);
        if (!enough())
            add_extra_paths(results, q, request);
        if (!enough())
            add_environment_path(results, q, request);
#if defined(_WIN32)
        if (!enough())
            add_windows_app_paths(results, q, request);
#endif
        add_existing_discovery(results, q, request);
    } catch (...) {
        pm::log::debug_lazy(k_ch, [&] {
            return std::string("resolve failed for ") + q;
        });
    }

    sort_and_dedup(results);
    if (!request.all && results.size() > 1)
        results.resize(1);
    return results;
}

std::optional<ResolvedApplication> resolve_first_application(std::string_view query, const ResolveRequest& request)
{
    ResolveRequest first = request;
    first.all = false;
    auto results = resolve_application(query, first);
    if (results.empty())
        return std::nullopt;
    return std::move(results.front());
}

std::optional<fs::path> resolve_application_directory(std::string_view query, const ResolveRequest& request)
{
    ResolveRequest req = request;
    if (req.intent == ResolveIntent::Command)
        req.intent = ResolveIntent::InstallRoot;
    auto app = resolve_first_application(query, req);
    if (!app || app->install_root.empty())
        return std::nullopt;
    return app->install_root;
}

} // namespace media::app
