#include "app_exe_directory.hpp"
#include "fs/path_sanitizer.hpp"
#include "app_resolver.hpp"
#include "constants.hpp"
#include "pm_branding_config.hpp"
#include "ui_defaults.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#include <appmodel.h>
#ifndef PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_OVERRIDE
#define PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_OVERRIDE 0x00000004
#endif
#ifndef PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY
#define PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY \
    ProcThreadAttributeValue(18, FALSE, TRUE, FALSE)
#endif
#pragma comment(lib, "Advapi32.lib")
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <cstdint>
#else
#include <unistd.h>
#endif

namespace media::app {

namespace fs = std::filesystem;

namespace {

bool is_regular_file_path(const fs::path& path)
{
    std::error_code ec;
    return fs::is_regular_file(path, ec) && !ec;
}

} // namespace

fs::path exe_executable()
{
#if defined(_WIN32)
    // Large buffer: MAX_PATH truncates long install paths (Jump List / Start Menu used 32k).
    std::vector<wchar_t> buf(32768, L'\0');
    const DWORD n = ::GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size() - 1));
    if (n == 0)
        return {};
    return fs::path(std::wstring(buf.data(), n));
#elif defined(__APPLE__)
    char buf[4096]{};
    std::uint32_t sz = sizeof(buf);
    if (_NSGetExecutablePath(buf, &sz) != 0)
        return {};
    std::error_code ec;
    const fs::path raw(buf);
    const fs::path canon = fs::weakly_canonical(raw, ec);
    if (ec || canon.empty())
        return raw;
    return canon;
#else
    char buf[4096]{};
    const ssize_t len = ::readlink("/proc/self/exe", buf, sizeof(buf) - 2);
    if (len <= 0)
        return {};
    buf[len] = '\0';
    std::error_code ec;
    const fs::path canon = fs::weakly_canonical(media::path::path_from_utf8(std::string_view(buf, static_cast<std::size_t>(len))), ec);
    if (!ec && !canon.empty())
        return canon;
    return media::path::path_from_utf8(std::string_view(buf, static_cast<std::size_t>(len)));
#endif
}

fs::path exe_parent_directory()
{
    const fs::path exe = exe_executable();
    if (exe.empty())
        return {};
    return exe.parent_path();
}

fs::path exe_cli_executable()
{
    const fs::path dir = exe_parent_directory();
    if (dir.empty())
        return {};
#if defined(_WIN32)
    const fs::path cli = dir / pm::brand::k_exe_basename_cli_w;
#else
    const fs::path cli = dir / pm::brand::k_exe_stem_cli_u8;
#endif
    if (is_regular_file_path(cli))
        return cli;
    return {};
}

#if defined(_WIN32)

namespace {

constexpr wchar_t k_chrome_cli_key[] =
    L"Software\\Google\\Chrome\\NativeMessagingHosts\\com.polymech.tanit.chrome";
constexpr wchar_t k_chrome_cli_reg_key[] =
    L"HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.polymech.tanit.chrome";

bool path_under_windowsapps(const std::wstring& path)
{
    std::wstring folded = path;
    for (wchar_t& c : folded) {
        if (c == L'/')
            c = L'\\';
        else if (c >= L'A' && c <= L'Z')
            c = static_cast<wchar_t>(c - L'A' + L'a');
    }
    return folded.find(L"\\windowsapps\\") != std::wstring::npos;
}

bool paths_equal_ci(const std::wstring& a, const std::wstring& b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        wchar_t ca = a[i];
        wchar_t cb = b[i];
        if (ca == L'/')
            ca = L'\\';
        if (cb == L'/')
            cb = L'\\';
        if (ca >= L'A' && ca <= L'Z')
            ca = static_cast<wchar_t>(ca - L'A' + L'a');
        if (cb >= L'A' && cb <= L'Z')
            cb = static_cast<wchar_t>(cb - L'A' + L'a');
        if (ca != cb)
            return false;
    }
    return true;
}

bool process_in_app_package()
{
    UINT32 len = 0;
    return ::GetCurrentPackageFullName(&len, nullptr) != APPMODEL_ERROR_NO_PACKAGE;
}

bool command_line_is_agent_serve()
{
    const wchar_t* cmd = ::GetCommandLineW();
    if (!cmd)
        return false;
    const wchar_t* p = cmd;
    while ((p = ::wcsstr(p, L"--serve")) != nullptr) {
        const wchar_t next = p[7];
        if (next == L'\0' || next == L' ' || next == L'\t' || next == L'"')
            return true;
        p += 7;
    }
    return false;
}

std::wstring query_chrome_cli_value()
{
    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER, k_chrome_cli_key, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return {};
    wchar_t buf[32768]{};
    DWORD type = 0;
    DWORD size = sizeof(buf);
    const LSTATUS st = ::RegQueryValueExW(key, L"cli", nullptr, &type,
                                          reinterpret_cast<LPBYTE>(buf), &size);
    ::RegCloseKey(key);
    if (st != ERROR_SUCCESS || type != REG_SZ)
        return {};
    return std::wstring(buf);
}

bool set_chrome_cli_value(const std::wstring& value)
{
    HKEY key = nullptr;
    if (::RegOpenKeyExW(HKEY_CURRENT_USER, k_chrome_cli_key, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS)
        return false;
    const LSTATUS st = ::RegSetValueExW(
        key, L"cli", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(value.c_str()),
        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    ::RegCloseKey(key);
    return st == ERROR_SUCCESS;
}

bool run_reg_breakaway(const std::wstring& args)
{
    wchar_t sys[MAX_PATH]{};
    const UINT nsys = ::GetSystemDirectoryW(sys, MAX_PATH);
    if (nsys == 0 || nsys >= MAX_PATH)
        return false;
    const std::wstring exe = std::wstring(sys) + L"\\reg.exe";
    std::wstring cmd = L"\"" + exe + L"\" " + args;
    std::vector<wchar_t> mutable_cmd(cmd.begin(), cmd.end());
    mutable_cmd.push_back(L'\0');

    DWORD policy = PROCESS_CREATION_DESKTOP_APP_BREAKAWAY_OVERRIDE;
    SIZE_T attr_size = 0;
    ::InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;
    si.lpAttributeList = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        ::HeapAlloc(::GetProcessHeap(), 0, attr_size));
    const BOOL list_inited = si.lpAttributeList
        && ::InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attr_size);
    const BOOL attrs_ok = list_inited
        && ::UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY,
                                       &policy, sizeof(policy), nullptr, nullptr);
    PROCESS_INFORMATION pi{};
    const BOOL created = attrs_ok && ::CreateProcessW(
        exe.c_str(), mutable_cmd.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
        &si.StartupInfo, &pi);
    if (list_inited)
        ::DeleteProcThreadAttributeList(si.lpAttributeList);
    if (si.lpAttributeList)
        ::HeapFree(::GetProcessHeap(), 0, si.lpAttributeList);
    if (!created)
        return false;
    ::WaitForSingleObject(pi.hProcess, 15000);
    DWORD code = 1;
    ::GetExitCodeProcess(pi.hProcess, &code);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    return code == 0;
}

fs::path launchable_cli_for_chrome_host()
{
    const fs::path cli = exe_cli_executable();
    if (cli.empty())
        return {};
    if (!path_under_windowsapps(cli.wstring()))
        return cli;
    wchar_t local[MAX_PATH]{};
    const DWORD n = ::GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return {};
    const fs::path alias = std::filesystem::path(local) / L"Microsoft" / L"WindowsApps" / pm::brand::k_exe_basename_cli_w;
    if (!is_regular_file_path(alias))
        return {};
    return alias;
}

} // namespace

void publish_running_cli_for_chrome_host()
{
    if (std::string_view(pm::brand::k_app_id_u8) != "tanit")
        return;
    if (command_line_is_agent_serve())
        return;
    const fs::path cli = launchable_cli_for_chrome_host();
    if (cli.empty() || !is_regular_file_path(cli))
        return;
    const std::wstring value = cli.wstring();
    if (value.find(L'"') != std::wstring::npos)
        return;

    if (process_in_app_package()) {
        const std::wstring query = std::wstring(L"query ") + k_chrome_cli_reg_key + L" /ve";
        if (!run_reg_breakaway(query))
            return;
        const std::wstring add = std::wstring(L"add ") + k_chrome_cli_reg_key
            + L" /v cli /t REG_SZ /d \"" + value + L"\" /f";
        run_reg_breakaway(add);
        return;
    }

    if (paths_equal_ci(query_chrome_cli_value(), value))
        return;
    set_chrome_cli_value(value);
}

#endif

fs::path exe_gui_executable()
{
    const fs::path dir = exe_parent_directory();
    if (dir.empty())
        return {};
    // Product GUI only. POLYMECH_APP_TANIT_VIEWER already rewrites PM_APP_ID_SLUG
    // to tanit-viewer; FEATURE_VIEWER_WEB is unrelated (WebView2 dock, both SKUs).
#if defined(_WIN32)
    const fs::path gui = dir / pm::brand::k_exe_basename_w;
#else
    const fs::path gui = dir / pm::brand::k_app_id_u8;
#endif
    if (is_regular_file_path(gui))
        return gui;
    return {};
}

fs::path exe_bin_directory()
{
    const fs::path dir = exe_parent_directory();
    if (dir.empty())
        return {};
    fs::path bin = dir / "bin";
    std::error_code ec;
    if (fs::is_directory(bin, ec) && !ec)
        return bin;
    return {};
}

fs::path exe_bundled_roaming_directory()
{
    const fs::path parent = exe_parent_directory();
    if (parent.empty())
        return {};
    std::error_code ec;
    const fs::path candidate = parent / ".." / "roaming";
    const fs::path canon = fs::weakly_canonical(candidate, ec);
    if (ec || canon.empty())
        return {};
    if (!fs::is_directory(canon, ec) || ec)
        return {};
    return canon;
}

fs::path resolve_third_party_executable(const fs::path& executable)
{
    if (executable.empty())
        return {};

    ResolveRequest opts;
    opts.intent = ResolveIntent::Command;
    opts.sources = ResolveSource::Explicit | ResolveSource::Tanit
                 | ResolveSource::Path | ResolveSource::AppPaths;
    opts.all = false;
    // Same extra folders RunTool / process_runner prepend to PATH
    // (`ui.appPathDirectories`). Searched before the process PATH so a
    // native claude.exe in a user app-path dir wins over an npm .cmd shim.
    for (const auto& dir : media::ui_defaults::app_search_path_dirs()) {
        if (!dir.empty())
            opts.extra_paths.push_back(std::filesystem::path(dir));
    }

    const auto found = resolve_first_application(media::path::path_to_utf8(executable), opts);
    if (found)
        return found->executable;
    return {};
}

void append_dist_shared_candidates(
    std::vector<fs::path>& out, const fs::path& exe_dir, const fs::path& relative)
{
    if (exe_dir.empty() || relative.empty())
        return;
    const fs::path parent = exe_dir.parent_path();
    if (!parent.empty())
        out.push_back(parent / L"shared" / relative);
    out.push_back(exe_dir / L"shared" / relative);
    out.push_back(exe_dir / relative);
}

fs::path resolve_dist_shared_file(const fs::path& relative)
{
    if (relative.empty())
        return {};
    std::vector<fs::path> candidates;
    append_dist_shared_candidates(candidates, exe_parent_directory(), relative);
    for (const fs::path& candidate : candidates) {
        if (is_regular_file_path(candidate))
            return candidate;
    }
    return {};
}

fs::path resolve_dist_shared_directory()
{
    const fs::path exe_dir = exe_parent_directory();
    if (exe_dir.empty())
        return {};
    std::error_code ec;
    const fs::path parent = exe_dir.parent_path();
    if (!parent.empty()) {
        const fs::path candidate = parent / L"shared";
        if (fs::is_directory(candidate, ec) && !ec)
            return candidate;
    }
    const fs::path beside = exe_dir / L"shared";
    if (fs::is_directory(beside, ec) && !ec)
        return beside;
    return {};
}

void append_bundled_models_candidates(std::vector<fs::path>& out, const fs::path& exe_dir)
{
    if (exe_dir.empty())
        return;
    out.push_back(exe_dir / "shared" / "models");
    out.push_back(exe_dir / "models");
    const fs::path parent = exe_dir.parent_path();
    if (!parent.empty())
        out.push_back(parent / "models");
}

fs::path resolve_tabler_assets_pfs()
{
    return resolve_dist_shared_file(L"assets.pfs");
}

fs::path resolve_tabler_filled_vendor_dir()
{
    const fs::path relative = L"vendor/tabler-icons/icons/filled";
    const fs::path exe_dir  = exe_parent_directory();
    if (exe_dir.empty())
        return {};
    std::error_code ec;
    const fs::path parent = exe_dir.parent_path();
    if (!parent.empty()) {
        const fs::path candidate = parent / relative;
        if (fs::is_directory(candidate, ec) && !ec)
            return candidate;
    }
    const fs::path beside = exe_dir / relative;
    if (fs::is_directory(beside, ec) && !ec)
        return beside;
    return {};
}

void append_dist_bundle_candidates(
    std::vector<fs::path>& out,
    const fs::path& exe_dir,
    const fs::path& app_stem,
    const fs::path& relative)
{
    if (exe_dir.empty() || app_stem.empty() || relative.empty())
        return;
    const fs::path parent = exe_dir.parent_path();
    if (!parent.empty())
        out.push_back(parent / L"bundles" / app_stem / relative);
    out.push_back(exe_dir / L"bundles" / app_stem / relative);
}

fs::path resolve_tanit_chrome_extension_dir()
{
    const fs::path exe_dir = exe_parent_directory();
    if (exe_dir.empty())
        return {};
    std::error_code ec;
    const fs::path relative = L"extension/tanit-chrome";
    const fs::path parent = exe_dir.parent_path();
    if (!parent.empty()) {
        const fs::path candidate = parent / relative;
        if (fs::is_directory(candidate, ec) && !ec)
            return candidate;
    }
    const fs::path beside = exe_dir / relative;
    if (fs::is_directory(beside, ec) && !ec)
        return beside;
    return {};
}

} // namespace media::app
