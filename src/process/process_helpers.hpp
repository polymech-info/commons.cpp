#pragma once
//
// Shared process-launching primitives used by ProcessRunner, command_runner,
// CLI dispatch, xblox, and the ribbon custom-command layer.
//
// Consolidates: quote_process_arg, widen_utf8, terminate_process_tree,
// detect_shell, build_environment_block — all previously duplicated across
// multiple translation units.
//

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace pm::commons::host {
std::filesystem::path exe_bin_directory();
}

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <tlhelp32.h>
#endif

namespace media::process {

// ═══════════════════════════════════════════════════════════════════════════════
// §1  String helpers
// ═══════════════════════════════════════════════════════════════════════════════

#if defined(_WIN32)

/// MSDN-style command-line quoting: wraps in double-quotes when needed,
/// escapes embedded backslashes+quotes per CRT argv parsing rules.
inline std::wstring quote_process_arg(std::wstring_view arg)
{
    if (arg.empty())
        return L"\"\"";
    bool need_quotes = false;
    for (wchar_t ch : arg) {
        if (ch == L' ' || ch == L'\t' || ch == L'\n' || ch == L'\r' || ch == L'"') {
            need_quotes = true;
            break;
        }
    }
    if (!need_quotes)
        return std::wstring(arg);
    std::wstring out = L"\"";
    size_t backslashes = 0;
    for (wchar_t ch : arg) {
        if (ch == L'\\') {
            ++backslashes;
            continue;
        }
        if (ch == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
        } else {
            out.append(backslashes, L'\\');
            out.push_back(ch);
        }
        backslashes = 0;
    }
    out.append(backslashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}

/// UTF-8 → wide string via Win32 MultiByteToWideChar.
inline std::wstring widen_utf8(const std::string& s)
{
    if (s.empty()) return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring ws(static_cast<size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), ws.data(), n);
    return ws;
}

/// Wide string → UTF-8 via Win32 WideCharToMultiByte.
inline std::string narrow_utf8(const std::wstring& ws)
{
    if (ws.empty()) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), static_cast<int>(ws.size()),
                                  nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(static_cast<size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), static_cast<int>(ws.size()),
                          s.data(), n, nullptr, nullptr);
    return s;
}

#else

/// wchar_t is UTF-32 on this platform. Encode each code point as UTF-8.
inline std::string narrow_utf8(const std::wstring& ws)
{
    std::string out;
    out.reserve(ws.size());
    for (wchar_t wc : ws) {
        const auto cp = static_cast<uint32_t>(wc);
        if (cp < 0x80u) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800u) {
            out.push_back(static_cast<char>(0xC0u | (cp >> 6)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        } else if (cp < 0x10000u) {
            out.push_back(static_cast<char>(0xE0u | (cp >> 12)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        } else if (cp < 0x110000u) {
            out.push_back(static_cast<char>(0xF0u | (cp >> 18)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
            out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
        }
    }
    return out;
}

#endif // _WIN32

/// POSIX shell quoting: wraps in single-quotes, escaping embedded single-quotes.
inline std::string shell_quote_posix(const std::string& s)
{
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') out += "'\\''";
        else out.push_back(c);
    }
    out.push_back('\'');
    return out;
}

// ═══════════════════════════════════════════════════════════════════════════════
// §2  Environment helpers
// ═══════════════════════════════════════════════════════════════════════════════

inline std::string env_or(const char* var, const char* fallback)
{
    const char* v = std::getenv(var);
    return (v && v[0]) ? std::string(v) : std::string(fallback);
}

inline bool file_exists_at(const std::string& p)
{
    std::error_code ec;
    return std::filesystem::exists(std::filesystem::path(p), ec);
}

#if defined(_WIN32)

inline std::wstring getenv_w(const wchar_t* name)
{
    const DWORD needed = ::GetEnvironmentVariableW(name, nullptr, 0);
    if (needed == 0) return {};
    std::wstring value(needed, L'\0');
    const DWORD n = ::GetEnvironmentVariableW(name, value.data(), needed);
    if (n == 0) return {};
    value.resize(n);
    return value;
}

inline bool path_contains_part(const std::wstring& path, const std::wstring& part)
{
    if (path.empty() || part.empty()) return false;
    size_t start = 0;
    while (start <= path.size()) {
        const size_t end = path.find(L';', start);
        std::wstring item = path.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start);
        std::wstring cmp = part;
        while (!item.empty() && (item.back() == L'\\' || item.back() == L'/')) item.pop_back();
        while (!cmp.empty() && (cmp.back() == L'\\' || cmp.back() == L'/')) cmp.pop_back();
        if (!item.empty() && CompareStringOrdinal(item.c_str(), -1, cmp.c_str(), -1, TRUE) == CSTR_EQUAL)
            return true;
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    return false;
}

inline void prepend_path_part(std::wstring& path, const std::wstring& part)
{
    if (part.empty() || path_contains_part(path, part)) return;
    path = path.empty() ? part : part + L";" + path;
}

inline void append_path_part(std::wstring& path, const std::wstring& part)
{
    if (part.empty() || path_contains_part(path, part)) return;
    path = path.empty() ? part : path + L";" + part;
}

inline std::wstring exe_adjacent_bin_dir()
{
    return pm::commons::host::exe_bin_directory().wstring();
}

/// Build a full environment block with exe-adjacent/bin prepended to PATH
/// (before app-path dirs and the inherited PATH, matching
/// resolve_third_party_executable), any extra path entries from
/// `extra_path_prepends`, and optional extra `key → value` variables
/// (`extra_env`) that override inherited entries with the same
/// (case-insensitive) name.
inline std::vector<wchar_t> build_environment_block(
    const std::vector<std::wstring>& extra_path_prepends = {},
    const std::vector<std::pair<std::wstring, std::wstring>>& extra_env = {})
{
    std::wstring path = getenv_w(L"Path");
    if (path.empty()) path = getenv_w(L"PATH");
    for (auto it = extra_path_prepends.rbegin(); it != extra_path_prepends.rend(); ++it)
        prepend_path_part(path, *it);
    prepend_path_part(path, exe_adjacent_bin_dir());

    auto extra_env_match = [&extra_env](const std::wstring& key) -> const std::wstring* {
        for (const auto& [k, v] : extra_env) {
            if (_wcsicmp(key.c_str(), k.c_str()) == 0) return &v;
        }
        return nullptr;
    };

    std::vector<std::wstring> entries;
    bool has_path = false;
    std::vector<bool> extra_used(extra_env.size(), false);
    if (LPWCH env = ::GetEnvironmentStringsW()) {
        for (const wchar_t* p = env; p && *p;) {
            std::wstring entry(p);
            const size_t eq = entry.find(L'=');
            const std::wstring key = eq != std::wstring::npos ? entry.substr(0, eq) : std::wstring{};
            if (eq != std::wstring::npos && _wcsicmp(key.c_str(), L"Path") == 0) {
                entries.push_back(L"Path=" + path);
                has_path = true;
            } else if (const std::wstring* ov = extra_env_match(key)) {
                entries.push_back(key + L"=" + *ov);
                for (size_t i = 0; i < extra_env.size(); ++i) {
                    if (_wcsicmp(key.c_str(), extra_env[i].first.c_str()) == 0)
                        extra_used[i] = true;
                }
            } else {
                entries.push_back(std::move(entry));
            }
            p += wcslen(p) + 1;
        }
        ::FreeEnvironmentStringsW(env);
    }
    if (!has_path && !path.empty())
        entries.push_back(L"Path=" + path);
    for (size_t i = 0; i < extra_env.size(); ++i) {
        if (!extra_used[i] && !extra_env[i].first.empty())
            entries.push_back(extra_env[i].first + L"=" + extra_env[i].second);
    }

    std::vector<wchar_t> block;
    for (const auto& entry : entries) {
        block.insert(block.end(), entry.begin(), entry.end());
        block.push_back(L'\0');
    }
    block.push_back(L'\0');
    return block;
}

// ═══════════════════════════════════════════════════════════════════════════════
// §3  Process tree management
// ═══════════════════════════════════════════════════════════════════════════════

/// Recursively terminate a process and all its descendants (Win32).
inline void terminate_process_tree(DWORD pid)
{
    if (pid == 0) return;

    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (::Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ParentProcessID == pid)
                    terminate_process_tree(pe.th32ProcessID);
            } while (::Process32NextW(snap, &pe));
        }
        ::CloseHandle(snap);
    }

    HANDLE h = ::OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (!h) return;
    ::TerminateProcess(h, 1);
    ::WaitForSingleObject(h, 1000);
    ::CloseHandle(h);
}

#endif // _WIN32

// ═══════════════════════════════════════════════════════════════════════════════
// §4  Shell detection
// ═══════════════════════════════════════════════════════════════════════════════

struct ShellSpec {
    std::string exe;
    std::string flag;
    bool        is_pwsh = false;
};

#if defined(_WIN32)

inline ShellSpec detect_shell_windows(const std::string& hint)
{
    if (hint == "cmd")
        return { env_or("SystemRoot", "C:\\Windows") + "\\System32\\cmd.exe", "/c", false };

    if (hint == "bash" || hint == "sh") {
        const std::string git_bash = env_or("ProgramFiles", "C:\\Program Files") +
            "\\Git\\bin\\bash.exe";
        if (file_exists_at(git_bash))
            return { git_bash, "-c", false };
        return { "bash", "-c", false };
    }

    if (hint == "zsh" || hint == "fish")
        return { hint, "-c", false };

    if (hint == "powershell") {
        const std::string sys = env_or("SystemRoot", "C:\\Windows");
        const std::string ps5 = sys + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        return { file_exists_at(ps5) ? ps5 : std::string("powershell"),
                 "-NoProfile -NonInteractive -Command", true };
    }

    if (hint == "auto" || hint == "pwsh") {
        const std::string pf = env_or("ProgramFiles", "C:\\Program Files");
        const std::string pwsh7 = pf + "\\PowerShell\\7\\pwsh.exe";
        if (file_exists_at(pwsh7))
            return { pwsh7, "-NoProfile -NonInteractive -Command", true };

        const std::string sys = env_or("SystemRoot", "C:\\Windows");
        const std::string ps5 = sys + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        if (file_exists_at(ps5))
            return { ps5, "-NoProfile -NonInteractive -Command", true };

        if (hint == "pwsh")
            return { "pwsh", "-NoProfile -NonInteractive -Command", true };

        return { sys + "\\System32\\cmd.exe", "/c", false };
    }

    return { "cmd.exe", "/c", false };
}

#else

inline ShellSpec detect_shell_unix(const std::string& hint)
{
    if (hint == "bash")
        return { "/bin/bash", "-c", false };
    if (hint == "sh")
        return { "/bin/sh", "-c", false };
    if (hint == "pwsh" || hint == "powershell")
        return { "pwsh", "-NoProfile -NonInteractive -Command", true };
    if (hint == "zsh" || hint == "fish")
        return { hint, "-c", false };

    const char* sh = std::getenv("SHELL");
    if (sh && sh[0] == '/') {
        std::error_code ec;
        if (std::filesystem::exists(std::filesystem::path(sh), ec))
            return { sh, "-c", false };
    }
    if (std::filesystem::exists("/bin/bash"))
        return { "/bin/bash", "-c", false };
    return { "/bin/sh", "-c", false };
}

#endif

/// Cross-platform shell detection. Accepts hint: "auto", "cmd", "pwsh", "bash", "sh".
inline ShellSpec detect_shell(const std::string& hint = "auto")
{
    std::string h = hint;
    for (char& c : h) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (h.empty()) h = "auto";

#if defined(_WIN32)
    return detect_shell_windows(h);
#else
    return detect_shell_unix(h);
#endif
}

} // namespace media::process
