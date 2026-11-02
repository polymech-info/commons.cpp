#include "process_runner.hpp"

#include "string/string_sanitizers.hpp"
#include "host/services.hpp"
#include "logging/pm_log.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#else
#  include <cerrno>
#  include <cstdlib>
#  include <cstring>
#  include <signal.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

namespace media::process {

namespace {

constexpr const char k_ch[] = "process_runner";
std::atomic<std::uint64_t> g_next_run_id{1};

std::string launch_ext_lower(const std::string& path)
{
    std::size_t slash = path.find_last_of("/\\");
    std::size_t dot = path.find_last_of('.');
    if (dot == std::string::npos || (slash != std::string::npos && dot < slash))
        return {};
    std::string ext = path.substr(dot);
    for (char& c : ext)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return ext;
}

std::string fold_search_dir(std::string dir)
{
    while (!dir.empty() && (dir.back() == '/' || dir.back() == '\\'))
        dir.pop_back();
#if defined(_WIN32)
    for (char& c : dir)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
#endif
    return dir;
}

void apply_app_search_paths(RunOptions& opts)
{
    if (!opts.augment_path && !opts.use_shell && opts.extra_path_prepends.empty())
        return;
    const auto dirs = pm::commons::host::app_search_path_dirs();
    if (dirs.empty())
        return;
    std::vector<std::string> merged;
    merged.reserve(dirs.size() + opts.extra_path_prepends.size());
    auto push_unique = [&](const std::string& dir) {
        if (dir.empty())
            return;
        const std::string key = fold_search_dir(dir);
        for (const auto& existing : merged) {
            if (fold_search_dir(existing) == key)
                return;
        }
        merged.push_back(dir);
    };
    for (const auto& dir : dirs)
        push_unique(dir);
    for (const auto& dir : opts.extra_path_prepends)
        push_unique(dir);
    opts.extra_path_prepends = std::move(merged);
}

void wrap_script_launch(RunOptions& opts)
{
    if (opts.use_shell || opts.executable.empty())
        return;
    const std::string ext = launch_ext_lower(opts.executable);
    if (ext == ".ps1") {
        const auto shell = detect_shell("pwsh");
        std::vector<std::string> args;
        args.emplace_back("-NoProfile");
        args.emplace_back("-NonInteractive");
        args.emplace_back("-File");
        args.push_back(opts.executable);
        args.insert(args.end(), opts.args.begin(), opts.args.end());
        opts.executable = shell.exe;
        opts.args = std::move(args);
        return;
    }
#if defined(_WIN32)
    if (ext == ".cmd" || ext == ".bat") {
        const auto shell = detect_shell("cmd");
        std::vector<std::string> args;
        args.emplace_back("/c");
        args.push_back(opts.executable);
        args.insert(args.end(), opts.args.begin(), opts.args.end());
        opts.executable = shell.exe;
        opts.args = std::move(args);
    }
#endif
}

#if !defined(_WIN32)
void apply_posix_child_env(const RunOptions& opts)
{
    if (opts.augment_path || !opts.extra_path_prepends.empty()) {
        std::string path;
        for (const auto& part : opts.extra_path_prepends) {
            if (part.empty())
                continue;
            if (!path.empty())
                path.push_back(':');
            path += part;
        }
        const std::string bin = pm::commons::host::exe_bin_directory().string();
        if (!bin.empty()) {
            if (!path.empty())
                path.push_back(':');
            path += bin;
        }
        if (const char* inherited = std::getenv("PATH"); inherited && *inherited) {
            if (!path.empty())
                path.push_back(':');
            path += inherited;
        }
        if (!path.empty())
            setenv("PATH", path.c_str(), 1);
    }
    for (const auto& [key, value] : opts.extra_env) {
        if (!key.empty())
            setenv(key.c_str(), value.c_str(), 1);
    }
}
#endif

// ═══════════════════════════════════════════════════════════════════════════════
// §0  Lifetime Job Object (kill-on-close)
// ═══════════════════════════════════════════════════════════════════════════════
//
// A single process-wide Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
// Children we assign here are terminated automatically when *this* process exits
// — the OS closes our last handle to the job on process teardown (graceful OR
// crash) and the limit fires. This is the safety net that prevents "work" spawns
// (agent shells, launcher/ribbon commands, MCP servers) from orphaning when the
// UI window closes. Created lazily; never destroyed (process lifetime).

#if defined(_WIN32)

std::string format_win32_error(DWORD code);  // defined in §2 below

HANDLE lifetime_job() noexcept
{
    static HANDLE s_job = [] () -> HANDLE {
        HANDLE job = ::CreateJobObjectW(nullptr, nullptr);
        if (!job) {
            pm::log::warn(k_ch, "CreateJobObjectW failed: " + format_win32_error(::GetLastError()));
            return nullptr;
        }
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!::SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info, sizeof(info))) {
            pm::log::warn(k_ch, "SetInformationJobObject(KILL_ON_JOB_CLOSE) failed: "
                                + format_win32_error(::GetLastError()));
            ::CloseHandle(job);
            return nullptr;
        }
        return job;
    }();
    return s_job;
}

HANDLE create_kill_on_close_job() noexcept
{
    HANDLE job = ::CreateJobObjectW(nullptr, nullptr);
    if (!job) return nullptr;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!::SetInformationJobObject(
            job, JobObjectExtendedLimitInformation, &info, sizeof(info))) {
        ::CloseHandle(job);
        return nullptr;
    }
    return job;
}

#endif // _WIN32

// ═══════════════════════════════════════════════════════════════════════════════
// §1  Cancellation atomics for Captured mode (cross-thread abort)
// ═══════════════════════════════════════════════════════════════════════════════

// Captured runs are concurrent (typed chat, realtime delegation, MCP/external
// runners). A single global PID was lossy: the latest spawn overwrote the
// previous one, and completion of either cleared the slot for both. Keep every
// active root PID so cancel-all and shutdown can terminate every process tree.
std::mutex& captured_runs_mu()
{
    static std::mutex m;
    return m;
}

std::unordered_set<unsigned long>& captured_run_pids()
{
    static std::unordered_set<unsigned long> pids;
    return pids;
}

void register_captured_run(unsigned long pid)
{
    if (!pid) return;
    std::lock_guard<std::mutex> lk(captured_runs_mu());
    captured_run_pids().insert(pid);
}

void unregister_captured_run(unsigned long pid)
{
    if (!pid) return;
    std::lock_guard<std::mutex> lk(captured_runs_mu());
    captured_run_pids().erase(pid);
}

std::vector<unsigned long> snapshot_captured_runs()
{
    std::lock_guard<std::mutex> lk(captured_runs_mu());
    return std::vector<unsigned long>(
        captured_run_pids().begin(), captured_run_pids().end());
}

// ═══════════════════════════════════════════════════════════════════════════════
// §2  Output helpers
// ═══════════════════════════════════════════════════════════════════════════════

std::string normalize_crlf(std::string s)
{
    s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());
    return s;
}

std::string tail_truncate(const std::string& s, size_t max_bytes)
{
    if (s.size() <= max_bytes) return s;
    constexpr const char kTrunc[] = "\n\xe2\x80\xa6 [output truncated; showing last portion] \xe2\x80\xa6\n";
    return std::string(kTrunc) + s.substr(s.size() - max_bytes + sizeof(kTrunc));
}

// Python and yt-dlp write a pipe in the active ANSI code page. U+2019 is the
// single byte 0x92 there. That byte is not UTF-8; substituting U+FFFD makes
// the model quote a path the filesystem guard cannot narrow.
static std::string legacy_bytes_to_utf8(const char* data, size_t n)
{
    if (!data || n == 0)
        return {};
#if defined(_WIN32)
    const int wlen = ::MultiByteToWideChar(
        CP_ACP, 0, data, static_cast<int>(n), nullptr, 0);
    if (wlen <= 0)
        return {};
    std::wstring wide(static_cast<size_t>(wlen), L'\0');
    if (::MultiByteToWideChar(CP_ACP, 0, data, static_cast<int>(n), wide.data(), wlen) != wlen)
        return {};
    std::wstring kept;
    kept.reserve(wide.size());
    for (wchar_t ch : wide) {
        if (ch != static_cast<wchar_t>(0xFFFD))
            kept.push_back(ch);
    }
    if (kept.empty())
        return {};
    const int ulen = ::WideCharToMultiByte(
        CP_UTF8, 0, kept.data(), static_cast<int>(kept.size()),
        nullptr, 0, nullptr, nullptr);
    if (ulen <= 0)
        return {};
    std::string utf8(static_cast<size_t>(ulen), '\0');
    ::WideCharToMultiByte(
        CP_UTF8, 0, kept.data(), static_cast<int>(kept.size()),
        utf8.data(), ulen, nullptr, nullptr);
    return utf8;
#else
    return {};
#endif
}

// ReadFile/read fills a fixed buffer, so a multi-byte code point is often split
// across two reads. Holding the dangling lead keeps the character. Bytes that
// are not UTF-8 are decoded as the active code page; a replacement character
// is dropped so it cannot become a filename.
struct Utf8Capture {
    std::string hold;

    static int seq_len(unsigned char c)
    {
        if (c <= 0x7F) return 1;
        if (c >= 0xC2 && c <= 0xDF) return 2;
        if (c >= 0xE0 && c <= 0xEF) return 3;
        if (c >= 0xF0 && c <= 0xF4) return 4;
        return 0;
    }

    std::string push(const char* data, size_t n, bool eof)
    {
        std::string in;
        in.reserve(hold.size() + n);
        in.append(hold);
        hold.clear();
        if (data && n)
            in.append(data, n);

        std::string out;
        out.reserve(in.size());
        size_t i = 0;
        // >0 complete UTF-8 length, <0 incomplete lead, 0 not UTF-8.
        auto utf8_at = [&](size_t at) -> int {
            if (at >= in.size())
                return 0;
            const unsigned char c = static_cast<unsigned char>(in[at]);
            const int need = seq_len(c);
            if (need == 1)
                return 1;
            if (need == 0)
                return 0;
            if (at + static_cast<size_t>(need) > in.size())
                return -need;
            for (int k = 1; k < need; ++k) {
                if ((static_cast<unsigned char>(in[at + static_cast<size_t>(k)]) & 0xC0) != 0x80)
                    return 0;
            }
            if (need >= 3) {
                const unsigned char c1 = static_cast<unsigned char>(in[at + 1]);
                if (need == 3 && ((c == 0xE0 && c1 < 0xA0) || (c == 0xED && c1 > 0x9F)))
                    return 0;
                if (need == 4 && ((c == 0xF0 && c1 < 0x90) || (c == 0xF4 && c1 > 0x8F)))
                    return 0;
            }
            return need;
        };
        while (i < in.size()) {
            const int kind = utf8_at(i);
            if (kind > 0) {
                out.append(in, i, static_cast<size_t>(kind));
                i += static_cast<size_t>(kind);
                continue;
            }
            if (kind < 0 && !eof) {
                hold.assign(in, i, std::string::npos);
                break;
            }
            size_t j = i + 1;
            while (j < in.size()) {
                const int next = utf8_at(j);
                if (next > 0)
                    break;
                if (next < 0 && !eof)
                    break;
                ++j;
            }
            out += legacy_bytes_to_utf8(in.data() + i, j - i);
            i = j;
        }
        return out;
    }
};

void deliver_chunk(const RunOptions::ChunkCb& on_chunk,
                   const std::string& stream,
                   const std::string& chunk)
{
    if (!on_chunk || chunk.empty())
        return;
    try {
        on_chunk(stream, chunk);
    } catch (...) {
        // Reader thread: an exception here (JSON dump of bad bytes) is terminate.
    }
}

std::string finalize_captured_text(std::string raw, size_t max_bytes)
{
    raw = tail_truncate(normalize_crlf(std::move(raw)), max_bytes);
    return media::str_san::apply_text_sanitizer(
        raw, media::str_san::TextSanitizer::RepairInvalidUtf8);
}

std::string strip_ansi_csi(std::string s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        if (s[i] == '\x1b' && i + 1 < s.size() && s[i + 1] == '[') {
            i += 2;
            while (i < s.size() && s[i] != 'm')
                ++i;
            if (i < s.size())
                ++i;
            continue;
        }
        out.push_back(s[i++]);
    }
    return out;
}

void log_child_stdio_line(const std::string& stream,
                          const std::string& command_id,
                          unsigned long pid,
                          std::string line)
{
    line = strip_ansi_csi(std::move(line));
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'
                             || line.back() == ' ' || line.back() == '\t'))
        line.pop_back();
    if (line.empty())
        return;
    constexpr size_t k_max_line = 2000;
    if (line.size() > k_max_line)
        line = line.substr(0, k_max_line) + " ...";

    std::string prefix = stream;
    if (!command_id.empty())
        prefix += " id=" + command_id;
    prefix += " pid=" + std::to_string(pid) + " ";

    // Child CLI uses `[%H:%M:%S] [level] rest` — keep the payload and the level.
    std::string level;
    std::string rest;
    if (line.size() > 2 && line[0] == '[') {
        const auto t1 = line.find(']');
        if (t1 != std::string::npos && t1 + 2 < line.size()
            && line[t1 + 1] == ' ' && line[t1 + 2] == '[') {
            const auto t2 = line.find(']', t1 + 3);
            if (t2 != std::string::npos) {
                level = line.substr(t1 + 3, t2 - (t1 + 3));
                for (char& c : level)
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                rest = (t2 + 1 < line.size() && line[t2 + 1] == ' ')
                    ? line.substr(t2 + 2) : line.substr(t2 + 1);
            }
        }
    }

    const std::string msg = prefix + (rest.empty() ? line : rest);
    if (level == "trace")
        logger::trace(pm::log::prefixed("cmd_run", msg));
    else if (level == "debug")
        pm::log::debug("cmd_run", msg);
    else if (level == "warn" || level == "warning")
        pm::log::warn("cmd_run", msg);
    else if (level == "error" || level == "err")
        pm::log::error("cmd_run", msg);
    else if (level == "critical")
        pm::log::error("cmd_run", msg);
    else if (level == "info")
        pm::log::info("cmd_run", msg);
    else if (stream == "stderr")
        pm::log::debug("cmd_run", msg);
    else
        pm::log::info("cmd_run", msg);
}

struct ChildStreamLog {
    std::string stream;
    std::string command_id;
    unsigned long pid = 0;
    size_t max_bytes = 128 * 1024;
    size_t seen = 0;
    bool truncated = false;
    std::string carry;
    RunOptions::ChunkCb on_chunk;

    void feed(const char* data, size_t n)
    {
        if (!data || n == 0)
            return;
        deliver_chunk(on_chunk, stream, std::string(data, n));
        if (truncated)
            return;
        carry.append(data, n);
        size_t pos = 0;
        for (;;) {
            const auto nl = carry.find('\n', pos);
            if (nl == std::string::npos)
                break;
            emit_line(carry.substr(pos, nl - pos));
            pos = nl + 1;
        }
        if (pos > 0)
            carry.erase(0, pos);
        if (carry.size() > 4000) {
            emit_line(std::move(carry));
            carry.clear();
        }
    }

    void finish()
    {
        if (!carry.empty()) {
            emit_line(std::move(carry));
            carry.clear();
        }
    }

private:
    void emit_line(std::string line)
    {
        if (truncated)
            return;
        if (seen >= max_bytes) {
            truncated = true;
            pm::log::warn("cmd_run", stream
                + (command_id.empty() ? std::string() : " id=" + command_id)
                + " output truncated after " + std::to_string(max_bytes) + " bytes");
            return;
        }
        seen += line.size();
        log_child_stdio_line(stream, command_id, pid, std::move(line));
        if (seen >= max_bytes && !truncated) {
            truncated = true;
            pm::log::warn("cmd_run", stream
                + (command_id.empty() ? std::string() : " id=" + command_id)
                + " output truncated after " + std::to_string(max_bytes) + " bytes");
        }
    }
};

#if defined(_WIN32)
std::string format_win32_error(DWORD code)
{
    LPWSTR buf = nullptr;
    const DWORD len = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    std::wstring w = (buf && len > 0) ? std::wstring(buf, len) : std::wstring(L"unknown error");
    if (buf) ::LocalFree(buf);
    while (!w.empty() && (w.back() == L'\r' || w.back() == L'\n' || w.back() == L' '))
        w.pop_back();
    std::string out(w.size(), '?');
    for (size_t i = 0; i < w.size(); ++i)
        out[i] = (w[i] < 0x80) ? static_cast<char>(w[i]) : '?';
    return "code " + std::to_string(code) + ": " + out;
}
#endif

// ═══════════════════════════════════════════════════════════════════════════════
// §3  Command-line building
// ═══════════════════════════════════════════════════════════════════════════════

#if defined(_WIN32)

struct SpawnSpec {
    std::wstring cmdline;
    std::vector<wchar_t> env_block;
    std::wstring wcwd;
};

SpawnSpec build_spawn_spec(const RunOptions& opts)
{
    SpawnSpec sp;

    // CWD
    if (!opts.cwd.empty())
        sp.wcwd = widen_utf8(opts.cwd);

    // Environment block (PATH extras apply even when augment_path is off)
    if (opts.augment_path || !opts.extra_path_prepends.empty() || !opts.extra_env.empty()) {
        std::vector<std::wstring> extra;
        for (const auto& p : opts.extra_path_prepends)
            extra.push_back(widen_utf8(p));
        std::vector<std::pair<std::wstring, std::wstring>> extra_env;
        for (const auto& [k, v] : opts.extra_env)
            extra_env.emplace_back(widen_utf8(k), widen_utf8(v));
        sp.env_block = build_environment_block(extra, extra_env);
    }

    // Shell-wrapped command
    if (opts.use_shell && !opts.shell_command.empty()) {
        const auto shell = detect_shell(opts.shell_hint);
        sp.cmdline = L"\"" + widen_utf8(shell.exe) + L"\" " + widen_utf8(shell.flag) + L" \"";
        std::wstring wcmd = widen_utf8(opts.shell_command);
        for (wchar_t c : wcmd) {
            if (c == L'"') sp.cmdline += L"\\\"";
            else sp.cmdline += c;
        }
        sp.cmdline += L"\"";
        return sp;
    }

    // Direct executable + args
    if (!opts.executable.empty()) {
        sp.cmdline = quote_process_arg(widen_utf8(opts.executable));
        for (const auto& a : opts.args) {
            sp.cmdline.push_back(L' ');
            sp.cmdline += quote_process_arg(widen_utf8(a));
        }
        if (opts.new_console_window && !opts.close_on_exit)
            sp.cmdline += L" --pause-on-exit";
    }

    return sp;
}

#endif // _WIN32

// ═══════════════════════════════════════════════════════════════════════════════
// §4  Async mode (fire-and-forget with watcher thread)
// ═══════════════════════════════════════════════════════════════════════════════

#if defined(_WIN32)

RunResult run_async(const RunOptions& opts)
{
    RunResult result;
    const auto sp = build_spawn_spec(opts);
    if (sp.cmdline.empty()) {
        result.error = "empty command line";
        return result;
    }

    // Hidden-window children have nowhere to print — pipe stdio and forward
    // lines into the host log so hotkey / ribbon / launcher runs are debuggable.
    HANDLE out_r = nullptr, out_w = nullptr;
    HANDLE err_r = nullptr, err_w = nullptr;
    bool pipes = false;
    if (!opts.new_console_window) {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        if (::CreatePipe(&out_r, &out_w, &sa, 0) && ::CreatePipe(&err_r, &err_w, &sa, 0)) {
            ::SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
            ::SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0);
            pipes = true;
        } else {
            if (out_r) ::CloseHandle(out_r);
            if (out_w) ::CloseHandle(out_w);
            if (err_r) ::CloseHandle(err_r);
            if (err_w) ::CloseHandle(err_w);
            out_r = out_w = err_r = err_w = nullptr;
            pm::log::warn(k_ch, "async stdout/stderr pipes unavailable; child IO will be discarded");
        }
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    if (pipes) {
        // CREATE_NO_WINDOW already suppresses the child's console. Do not set
        // STARTF_USESHOWWINDOW+SW_HIDE: the first ShowWindow in the child uses
        // that value, so GUI windows (webcam preview) stay invisible.
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = out_w;
        si.hStdError = err_w;
        si.hStdInput = INVALID_HANDLE_VALUE;
    }
    PROCESS_INFORMATION pi{};
    DWORD flags = CREATE_UNICODE_ENVIRONMENT;
    flags |= opts.new_console_window ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW;

    std::vector<wchar_t> buf(sp.cmdline.begin(), sp.cmdline.end());
    buf.push_back(L'\0');
    const wchar_t* cwdp = sp.wcwd.empty() ? nullptr : sp.wcwd.c_str();
    void* envp = sp.env_block.empty() ? nullptr : const_cast<wchar_t*>(sp.env_block.data());

    if (opts.bind_to_parent)
        flags |= CREATE_SUSPENDED;  // assign to the kill-on-close job before it runs

    if (!::CreateProcessW(nullptr, buf.data(), nullptr, nullptr, pipes ? TRUE : FALSE,
                          flags, envp, cwdp, &si, &pi)) {
        const DWORD err = ::GetLastError();
        if (out_r) ::CloseHandle(out_r);
        if (out_w) ::CloseHandle(out_w);
        if (err_r) ::CloseHandle(err_r);
        if (err_w) ::CloseHandle(err_w);
        result.error = "CreateProcessW failed: " + format_win32_error(err);
        pm::log::warn(k_ch, result.error);
        return result;
    }
    (void)::AllowSetForegroundWindow(pi.dwProcessId);
    if (opts.bind_to_parent) {
        bind_process_to_lifetime_job(pi.hProcess);
        ::ResumeThread(pi.hThread);
    }
    ::CloseHandle(pi.hThread);
    if (pipes) {
        ::CloseHandle(out_w);
        ::CloseHandle(err_w);
        out_w = err_w = nullptr;
    }

    result.ok     = true;
    result.run_id = g_next_run_id.fetch_add(1, std::memory_order_relaxed);
    result.pid    = pi.dwProcessId;

    auto on_exit = opts.on_exit;
    auto on_chunk = opts.on_output_chunk;
    auto run_id  = result.run_id;
    auto pid     = result.pid;
    HANDLE hProc = pi.hProcess;
    const std::string command_id = opts.command_id;
    const size_t max_bytes = opts.capture_max_bytes;

    std::thread t_out;
    std::thread t_err;
    if (pipes) {
        auto out_log = std::make_shared<ChildStreamLog>();
        out_log->stream = "stdout";
        out_log->command_id = command_id;
        out_log->pid = pid;
        out_log->max_bytes = max_bytes;
        out_log->on_chunk = on_chunk;
        auto err_log = std::make_shared<ChildStreamLog>();
        err_log->stream = "stderr";
        err_log->command_id = command_id;
        err_log->pid = pid;
        err_log->max_bytes = max_bytes;
        err_log->on_chunk = on_chunk;
        t_out = std::thread([out_log, out_r] {
            Utf8Capture cap;
            char tmp[4096];
            DWORD n = 0;
            while (::ReadFile(out_r, tmp, sizeof(tmp), &n, nullptr) && n > 0) {
                const std::string chunk = cap.push(tmp, static_cast<size_t>(n), false);
                if (!chunk.empty())
                    out_log->feed(chunk.data(), chunk.size());
            }
            const std::string tail = cap.push(nullptr, 0, true);
            if (!tail.empty())
                out_log->feed(tail.data(), tail.size());
            out_log->finish();
        });
        t_err = std::thread([err_log, err_r] {
            Utf8Capture cap;
            char tmp[4096];
            DWORD n = 0;
            while (::ReadFile(err_r, tmp, sizeof(tmp), &n, nullptr) && n > 0) {
                const std::string chunk = cap.push(tmp, static_cast<size_t>(n), false);
                if (!chunk.empty())
                    err_log->feed(chunk.data(), chunk.size());
            }
            const std::string tail = cap.push(nullptr, 0, true);
            if (!tail.empty())
                err_log->feed(tail.data(), tail.size());
            err_log->finish();
        });
    }

    std::thread([hProc, on_exit, run_id, pid,
                 t_out = std::move(t_out), t_err = std::move(t_err),
                 out_r, err_r, pipes]() mutable {
        DWORD exitCode = 0;
        if (::WaitForSingleObject(hProc, INFINITE) == WAIT_OBJECT_0) {
            if (!::GetExitCodeProcess(hProc, &exitCode))
                exitCode = static_cast<DWORD>(-1);
        }
        ::CloseHandle(hProc);
        if (t_out.joinable())
            t_out.join();
        if (t_err.joinable())
            t_err.join();
        if (pipes) {
            if (out_r) ::CloseHandle(out_r);
            if (err_r) ::CloseHandle(err_r);
        }
        if (on_exit)
            on_exit(run_id, pid, static_cast<int>(exitCode));
    }).detach();

    return result;
}

#else // POSIX

RunResult run_async(const RunOptions& opts)
{
    RunResult result;

    std::string executable;
    std::vector<std::string> args;
    if (opts.use_shell && !opts.shell_command.empty()) {
        const auto shell = detect_shell(opts.shell_hint);
        executable = shell.exe;
        args = {shell.exe, "-c", opts.shell_command};
    } else if (!opts.executable.empty()) {
        executable = opts.executable;
        args.reserve(opts.args.size() + 1);
        args.push_back(opts.executable);
        args.insert(args.end(), opts.args.begin(), opts.args.end());
    } else {
        result.error = "empty command";
        return result;
    }

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& arg : args)
        argv.push_back(arg.data());
    argv.push_back(nullptr);

    const pid_t child = fork();
    if (child < 0) {
        result.error = "fork failed: " + std::string(std::strerror(errno));
        pm::log::warn(k_ch, result.error);
        return result;
    }
    if (child == 0) {
        if (!opts.cwd.empty() && chdir(opts.cwd.c_str()) != 0)
            _exit(127);

        apply_posix_child_env(opts);

        execvp(executable.c_str(), argv.data());
        _exit(127);
    }

    result.ok = true;
    result.run_id = g_next_run_id.fetch_add(1, std::memory_order_relaxed);
    result.pid = static_cast<unsigned long>(child);

    auto on_exit = opts.on_exit;
    const auto run_id = result.run_id;
    const auto pid = result.pid;
    std::thread([child, on_exit = std::move(on_exit), run_id, pid] {
        int status = 0;
        pid_t waited;
        do {
            waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);

        int exit_code = -1;
        if (waited == child) {
            if (WIFEXITED(status))
                exit_code = WEXITSTATUS(status);
            else if (WIFSIGNALED(status))
                exit_code = 128 + WTERMSIG(status);
        }
        if (on_exit)
            on_exit(run_id, pid, exit_code);
    }).detach();

    return result;
}

#endif

// ═══════════════════════════════════════════════════════════════════════════════
// §5  Sync mode (block until exit, no IO capture)
// ═══════════════════════════════════════════════════════════════════════════════

#if defined(_WIN32)

RunResult run_sync(const RunOptions& opts)
{
    namespace chr = std::chrono;
    RunResult result;
    const auto sp = build_spawn_spec(opts);
    if (sp.cmdline.empty()) {
        result.error = "empty command line";
        return result;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    DWORD flags = CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP;
    if (opts.new_console_window) flags |= CREATE_NEW_CONSOLE;
    else flags |= CREATE_NO_WINDOW;
    if (opts.bind_to_parent) flags |= CREATE_SUSPENDED;

    std::vector<wchar_t> buf(sp.cmdline.begin(), sp.cmdline.end());
    buf.push_back(L'\0');
    const wchar_t* cwdp = sp.wcwd.empty() ? nullptr : sp.wcwd.c_str();
    void* envp = sp.env_block.empty() ? nullptr : const_cast<wchar_t*>(sp.env_block.data());
    HANDLE run_job = opts.bind_to_parent ? create_kill_on_close_job() : nullptr;

    if (!::CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE,
                          flags, envp, cwdp, &si, &pi)) {
        const DWORD err = ::GetLastError();
        if (run_job) ::CloseHandle(run_job);
        result.error = "CreateProcessW failed: " + format_win32_error(err);
        return result;
    }
    (void)::AllowSetForegroundWindow(pi.dwProcessId);
    if (opts.bind_to_parent) {
        if (!run_job || !::AssignProcessToJobObject(run_job, pi.hProcess)) {
            if (run_job) {
                ::CloseHandle(run_job);
                run_job = nullptr;
            }
            (void)bind_process_to_lifetime_job(pi.hProcess);
        }
        ::ResumeThread(pi.hThread);
    }
    ::CloseHandle(pi.hThread);

    const auto deadline = opts.timeout_ms > 0
        ? chr::steady_clock::now() + chr::milliseconds(opts.timeout_ms)
        : chr::steady_clock::time_point::max();

    for (;;) {
        const DWORD wait = ::WaitForSingleObject(pi.hProcess, 100);
        if (wait == WAIT_OBJECT_0) {
            DWORD ec = 0;
            ::GetExitCodeProcess(pi.hProcess, &ec);
            result.exit_code = static_cast<int>(ec);
            result.ok = true;
            break;
        }
        if (wait == WAIT_FAILED) {
            result.error = "WaitForSingleObject failed";
            if (run_job) (void)::TerminateJobObject(run_job, 1);
            else terminate_process_tree(pi.dwProcessId);
            break;
        }
        if (opts.timeout_ms > 0 && chr::steady_clock::now() >= deadline) {
            result.timed_out = true;
            result.error = "timed out after " + std::to_string(opts.timeout_ms) + "ms";
            if (run_job) (void)::TerminateJobObject(run_job, 1);
            else terminate_process_tree(pi.dwProcessId);
            ::WaitForSingleObject(pi.hProcess, 3000);
            break;
        }
        if (opts.on_cancel_check && opts.on_cancel_check()) {
            // Give console-aware children a brief graceful window, then always
            // reap the complete tree before returning. The old loop broke after
            // sending CTRL_BREAK, so its escalation branch was unreachable and
            // children routinely survived as zombies.
            (void)::GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pi.dwProcessId);
            if (::WaitForSingleObject(pi.hProcess, 1000) != WAIT_OBJECT_0) {
                if (run_job) (void)::TerminateJobObject(run_job, 130);
                else terminate_process_tree(pi.dwProcessId);
                (void)::WaitForSingleObject(pi.hProcess, 3000);
            }
            result.cancelled = true;
            result.error = "cancelled";
            break;
        }
    }

    if (run_job) {
        // Reap descendants that outlived a naturally-exited shell root.
        (void)::TerminateJobObject(run_job, 0);
        ::CloseHandle(run_job);
    }
    ::CloseHandle(pi.hProcess);
    result.pid = pi.dwProcessId;
    return result;
}

#else // POSIX

RunResult run_sync(const RunOptions& opts)
{
    RunResult result;
    std::string cmd;
    if (opts.use_shell && !opts.shell_command.empty()) {
        const auto shell = detect_shell(opts.shell_hint);
        if (!opts.cwd.empty())
            cmd += "cd " + shell_quote_posix(opts.cwd) + " && ";
        cmd += shell_quote_posix(shell.exe) + " " + shell.flag + " " + shell_quote_posix(opts.shell_command);
    } else if (!opts.executable.empty()) {
        if (!opts.cwd.empty())
            cmd += "cd " + shell_quote_posix(opts.cwd) + " && ";
        cmd += shell_quote_posix(opts.executable);
        for (const auto& arg : opts.args)
            cmd += " " + shell_quote_posix(arg);
    } else {
        result.error = "empty command";
        return result;
    }
    if (opts.augment_path || !opts.extra_path_prepends.empty()) {
        std::string path;
        for (const auto& part : opts.extra_path_prepends) {
            if (part.empty())
                continue;
            if (!path.empty())
                path.push_back(':');
            path += part;
        }
        const std::string bin = pm::commons::host::exe_bin_directory().string();
        if (!bin.empty()) {
            if (!path.empty())
                path.push_back(':');
            path += bin;
        }
        if (const char* inherited = std::getenv("PATH"); inherited && *inherited) {
            if (!path.empty())
                path.push_back(':');
            path += inherited;
        }
        if (!path.empty())
            cmd = "PATH=" + shell_quote_posix(path) + " " + cmd;
    }
    result.exit_code = std::system(cmd.c_str());
    result.ok = true;
    return result;
}

#endif

// ═══════════════════════════════════════════════════════════════════════════════
// §6  Captured mode (block with piped stdout/stderr)
// ═══════════════════════════════════════════════════════════════════════════════

#if defined(_WIN32)

RunResult run_captured(const RunOptions& opts)
{
    namespace chr = std::chrono;
    RunResult result;
    const auto sp = build_spawn_spec(opts);
    if (sp.cmdline.empty()) {
        result.error = "empty command line";
        return result;
    }

    // Pipes
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hStdoutRead = nullptr, hStdoutWrite = nullptr;
    HANDLE hStderrRead = nullptr, hStderrWrite = nullptr;

    if (!::CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) {
        result.error = "CreatePipe(stdout) failed";
        return result;
    }
    ::SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);

    if (!::CreatePipe(&hStderrRead, &hStderrWrite, &sa, 0)) {
        ::CloseHandle(hStdoutRead);
        ::CloseHandle(hStdoutWrite);
        result.error = "CreatePipe(stderr) failed";
        return result;
    }
    ::SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdoutWrite;
    si.hStdError  = hStderrWrite;

    HANDLE hStdinNull = nullptr;
    if (opts.redirect_stdin_null) {
        hStdinNull = ::CreateFileW(L"NUL", GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   &sa, OPEN_EXISTING, 0, nullptr);
        if (hStdinNull && hStdinNull != INVALID_HANDLE_VALUE)
            si.hStdInput = hStdinNull;
        else
            si.hStdInput = INVALID_HANDLE_VALUE;
    } else {
        si.hStdInput = INVALID_HANDLE_VALUE;
    }

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(sp.cmdline.begin(), sp.cmdline.end());
    buf.push_back(L'\0');
    const wchar_t* cwdp = sp.wcwd.empty() ? nullptr : sp.wcwd.c_str();
    void* envp = sp.env_block.empty() ? nullptr : const_cast<wchar_t*>(sp.env_block.data());

    DWORD cap_flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT;
    if (opts.bind_to_parent) cap_flags |= CREATE_SUSPENDED;
    HANDLE run_job = opts.bind_to_parent ? create_kill_on_close_job() : nullptr;

    BOOL ok = ::CreateProcessW(
        nullptr, buf.data(), nullptr, nullptr,
        TRUE, cap_flags, envp, cwdp, &si, &pi);

    ::CloseHandle(hStdoutWrite);
    ::CloseHandle(hStderrWrite);
    if (hStdinNull && hStdinNull != INVALID_HANDLE_VALUE)
        ::CloseHandle(hStdinNull);

    if (!ok) {
        DWORD err = ::GetLastError();
        if (run_job) ::CloseHandle(run_job);
        ::CloseHandle(hStdoutRead);
        ::CloseHandle(hStderrRead);
        result.error = "CreateProcessW failed: " + format_win32_error(err);
        return result;
    }
    (void)::AllowSetForegroundWindow(pi.dwProcessId);
    if (opts.bind_to_parent) {
        if (!run_job || !::AssignProcessToJobObject(run_job, pi.hProcess)) {
            if (run_job) {
                ::CloseHandle(run_job);
                run_job = nullptr;
            }
            (void)bind_process_to_lifetime_job(pi.hProcess);
        }
        ::ResumeThread(pi.hThread);
    }
    ::CloseHandle(pi.hThread);

    register_captured_run(pi.dwProcessId);

    // Reader threads
    std::string captured_stdout, captured_stderr;
    std::mutex  mtx_out, mtx_err;
    auto on_chunk = opts.on_output_chunk;

    auto reader = [&on_chunk](HANDLE handle, std::string& dest, std::mutex& mtx,
                              const std::string& stream_name) {
        Utf8Capture cap;
        char tmp[4096];
        DWORD n = 0;
        while (::ReadFile(handle, tmp, sizeof(tmp), &n, nullptr) && n > 0) {
            const std::string chunk = cap.push(tmp, static_cast<size_t>(n), false);
            if (chunk.empty())
                continue;
            { std::lock_guard<std::mutex> lk(mtx); dest.append(chunk); }
            deliver_chunk(on_chunk, stream_name, chunk);
        }
        const std::string tail = cap.push(nullptr, 0, true);
        if (!tail.empty()) {
            { std::lock_guard<std::mutex> lk(mtx); dest.append(tail); }
            deliver_chunk(on_chunk, stream_name, tail);
        }
    };

    std::thread t_out(reader, hStdoutRead, std::ref(captured_stdout), std::ref(mtx_out), std::string("stdout"));
    std::thread t_err(reader, hStderrRead, std::ref(captured_stderr), std::ref(mtx_err), std::string("stderr"));

    // Wait with timeout + cancel
    const auto deadline = opts.timeout_ms > 0
        ? chr::steady_clock::now() + chr::milliseconds(opts.timeout_ms)
        : chr::steady_clock::time_point::max();

    constexpr DWORD k_poll_ms = 200;
    while (true) {
        DWORD wait_ms = static_cast<DWORD>(
            std::min<long long>(k_poll_ms,
                chr::duration_cast<chr::milliseconds>(deadline - chr::steady_clock::now()).count()));
        if (wait_ms == 0 || chr::steady_clock::now() >= deadline) wait_ms = 0;

        DWORD wr = ::WaitForSingleObject(pi.hProcess, wait_ms);
        if (wr == WAIT_OBJECT_0) {
            DWORD ec = 0;
            ::GetExitCodeProcess(pi.hProcess, &ec);
            result.exit_code = static_cast<int>(ec);
            result.ok = true;
            break;
        }
        if (opts.timeout_ms > 0 && chr::steady_clock::now() >= deadline) {
            result.timed_out = true;
            result.error = "timed out after " + std::to_string(opts.timeout_ms) + "ms";
            if (run_job) (void)::TerminateJobObject(run_job, 1);
            else terminate_process_tree(pi.dwProcessId);
            ::WaitForSingleObject(pi.hProcess, 3000);
            break;
        }
        if (opts.on_cancel_check && opts.on_cancel_check()) {
            result.cancelled = true;
            result.error = "cancelled";
            if (run_job) (void)::TerminateJobObject(run_job, 130);
            else terminate_process_tree(pi.dwProcessId);
            ::WaitForSingleObject(pi.hProcess, 3000);
            break;
        }
    }

    unregister_captured_run(pi.dwProcessId);

    // Captured mode owns the whole process tree. A command can let its shell
    // root exit while a background descendant keeps inherited pipe handles
    // open; joining readers would then hang forever and leave that descendant
    // orphaned. Reap any remainder before draining the pipes.
    if (run_job) {
        (void)::TerminateJobObject(run_job, 0);
        ::CloseHandle(run_job);
    } else {
        terminate_process_tree(pi.dwProcessId);
    }

    // Drain reader threads
    t_out.join();
    t_err.join();

    ::CloseHandle(hStdoutRead);
    ::CloseHandle(hStderrRead);
    ::CloseHandle(pi.hProcess);

    // Normalize & truncate
    result.stdout_text = finalize_captured_text(std::move(captured_stdout), opts.capture_max_bytes);
    result.stderr_text = finalize_captured_text(std::move(captured_stderr), opts.capture_max_bytes);
    result.pid = pi.dwProcessId;

    return result;
}

#else // POSIX

RunResult run_captured(const RunOptions& opts)
{
    namespace chr = std::chrono;
    RunResult result;

    std::string shell_cmd;
    if (opts.use_shell && !opts.shell_command.empty()) {
        shell_cmd = opts.shell_command;
    } else if (!opts.executable.empty()) {
        shell_cmd = shell_quote_posix(opts.executable);
        for (const auto& arg : opts.args)
            shell_cmd += " " + shell_quote_posix(arg);
    } else {
        result.error = "empty command";
        return result;
    }

    const auto shell = detect_shell(opts.use_shell ? opts.shell_hint : "auto");

    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};

    if (pipe(stdout_pipe) != 0) { result.error = "pipe(stdout) failed"; return result; }
    if (pipe(stderr_pipe) != 0) {
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        result.error = "pipe(stderr) failed";
        return result;
    }

    pid_t child = fork();
    if (child < 0) {
        close(stdout_pipe[0]); close(stdout_pipe[1]);
        close(stderr_pipe[0]); close(stderr_pipe[1]);
        result.error = "fork() failed";
        return result;
    }

    if (child == 0) {
        // Give the captured shell its own process group so cancellation kills
        // grandchildren too (the command may spawn compilers, agents, etc.).
        (void)setpgid(0, 0);
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);
        close(STDIN_FILENO);

        if (!opts.cwd.empty()) {
            if (chdir(opts.cwd.c_str()) != 0)
                _exit(127);
        }

        apply_posix_child_env(opts);
        execlp(shell.exe.c_str(), shell.exe.c_str(), "-c", shell_cmd.c_str(), nullptr);
        _exit(127);
    }

    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    (void)setpgid(child, child); // close the parent/child setpgid race
    register_captured_run(static_cast<unsigned long>(child));

    // Reader threads
    std::string captured_stdout, captured_stderr;
    std::mutex  mtx_out, mtx_err;
    auto on_chunk = opts.on_output_chunk;

    auto reader = [&on_chunk](int fd, std::string& dest, std::mutex& mtx,
                              const std::string& stream_name) {
        Utf8Capture cap;
        char tmp[4096];
        ssize_t n;
        while ((n = ::read(fd, tmp, sizeof(tmp))) > 0) {
            const std::string chunk = cap.push(tmp, static_cast<size_t>(n), false);
            if (chunk.empty())
                continue;
            { std::lock_guard<std::mutex> lk(mtx); dest.append(chunk); }
            deliver_chunk(on_chunk, stream_name, chunk);
        }
        const std::string tail = cap.push(nullptr, 0, true);
        if (!tail.empty()) {
            { std::lock_guard<std::mutex> lk(mtx); dest.append(tail); }
            deliver_chunk(on_chunk, stream_name, tail);
        }
    };

    std::thread t_out(reader, stdout_pipe[0], std::ref(captured_stdout), std::ref(mtx_out), std::string("stdout"));
    std::thread t_err(reader, stderr_pipe[0], std::ref(captured_stderr), std::ref(mtx_err), std::string("stderr"));

    // Wait with timeout + cancel
    const auto deadline = opts.timeout_ms > 0
        ? chr::steady_clock::now() + chr::milliseconds(opts.timeout_ms)
        : chr::steady_clock::time_point::max();

    constexpr int k_poll_us = 200000;
    while (true) {
        int status = 0;
        pid_t wp = waitpid(child, &status, WNOHANG);
        if (wp > 0) {
            result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            result.ok = true;
            break;
        }
        if (opts.timeout_ms > 0 && chr::steady_clock::now() >= deadline) {
            result.timed_out = true;
            result.error = "timed out after " + std::to_string(opts.timeout_ms) + "ms";
            kill(-child, SIGKILL);
            waitpid(child, nullptr, 0);
            break;
        }
        if (opts.on_cancel_check && opts.on_cancel_check()) {
            result.cancelled = true;
            result.error = "cancelled";
            kill(-child, SIGTERM);
            usleep(500000);
            kill(-child, SIGKILL);
            waitpid(child, nullptr, 0);
            break;
        }
        usleep(k_poll_us);
    }

    unregister_captured_run(static_cast<unsigned long>(child));

    // Kill background descendants that outlived the captured shell root and
    // may still hold stdout/stderr pipe descriptors open.
    (void)kill(-child, SIGTERM);
    usleep(100000);
    (void)kill(-child, SIGKILL);

    t_out.join();
    t_err.join();

    close(stdout_pipe[0]);
    close(stderr_pipe[0]);

    result.stdout_text = finalize_captured_text(std::move(captured_stdout), opts.capture_max_bytes);
    result.stderr_text = finalize_captured_text(std::move(captured_stderr), opts.capture_max_bytes);
    result.pid = static_cast<unsigned long>(child);

    return result;
}

#endif

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════════════
// §7  Public API
// ═══════════════════════════════════════════════════════════════════════════════

ClosePolicy parse_close_policy(std::string_view value) noexcept
{
    if (value == "persist")
        return ClosePolicy::Persist;
    if (value == "closeWithOwner" || value == "close_with_owner")
        return ClosePolicy::CloseWithOwner;
    return ClosePolicy::Default;
}

RunResult run(const RunOptions& opts)
{
    pm::log::debug_lazy(k_ch, [&] {
        std::string s = "run mode=";
        switch (opts.mode) {
        case RunMode::Async:    s += "async"; break;
        case RunMode::Sync:     s += "sync"; break;
        case RunMode::Captured: s += "captured"; break;
        }
        if (opts.use_shell)
            s += " shell=\"" + opts.shell_command.substr(0, 80) + "\"";
        else
            s += " exe=\"" + opts.executable.substr(0, 80) + "\"";
        if (!opts.cwd.empty())
            s += " cwd=\"" + opts.cwd + "\"";
        if (opts.timeout_ms > 0)
            s += " timeout=" + std::to_string(opts.timeout_ms) + "ms";
        if (!opts.use_shell && !opts.args.empty()) {
            s += " argc=" + std::to_string(opts.args.size());
            s += " args=\"";
            std::size_t n = 0;
            for (std::size_t i = 0; i < opts.args.size() && n < 1200; ++i) {
                if (i > 0)
                    s += ' ';
                if (i > 0 && (opts.args[i - 1] == "-p" || opts.args[i - 1] == "--print")) {
                    s += "[prompt:" + std::to_string(opts.args[i].size()) + " chars]";
                    continue;
                }
                const std::string& a = opts.args[i];
                s += a;
                n += a.size();
            }
            if (n >= 1200)
                s += "...";
            s += '"';
        }
        return s;
    });

    // Search folders from settings, script wrap, then optional closePolicy.
    RunOptions normalized = opts;
    apply_app_search_paths(normalized);
    wrap_script_launch(normalized);
    if (opts.close_policy != ClosePolicy::Default)
        normalized.bind_to_parent = (opts.close_policy == ClosePolicy::CloseWithOwner);

    switch (normalized.mode) {
    case RunMode::Async:    return run_async(normalized);
    case RunMode::Sync:     return run_sync(normalized);
    case RunMode::Captured: return run_captured(normalized);
    }
    RunResult r;
    r.error = "unknown run mode";
    return r;
}

void abort_captured_run()
{
    const auto pids = snapshot_captured_runs();
#if defined(_WIN32)
    for (const unsigned long raw_pid : pids)
        terminate_process_tree(static_cast<DWORD>(raw_pid));
#else
    for (const unsigned long raw_pid : pids)
        (void)kill(-static_cast<pid_t>(raw_pid), SIGTERM);
    if (!pids.empty()) usleep(200000);
    for (const unsigned long raw_pid : pids)
        (void)kill(-static_cast<pid_t>(raw_pid), SIGKILL);
#endif
    if (!pids.empty())
        pm::log::info(k_ch, "abort_captured_run: terminated "
                              + std::to_string(pids.size()) + " process tree(s)");
}

#if defined(_WIN32)
bool bind_process_to_lifetime_job(void* process_handle) noexcept
{
    if (!process_handle) return false;
    HANDLE job = lifetime_job();
    if (!job) return false;
    if (!::AssignProcessToJobObject(job, static_cast<HANDLE>(process_handle))) {
        // Common, benign reason: the child is already in a job that disallows
        // nesting (older hosts). Log once-ish and move on — we still TerminateProcess
        // on explicit cancel paths.
        pm::log::warn(k_ch, "AssignProcessToJobObject failed: "
                            + format_win32_error(::GetLastError()));
        return false;
    }
    return true;
}
#endif

} // namespace media::process
