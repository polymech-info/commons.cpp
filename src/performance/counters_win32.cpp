#include "counters.hpp"
#include "fs/path_sanitizer.hpp"

#include "gpu/gpu_memory_stats.hpp"
#include "logging/logger.h"
#include "settings/win/settings_store.hpp"

#include <psapi.h>
#include <windows.h>

#if defined(FEATURE_BROWSER) && FEATURE_BROWSER && !defined(PM_IMAGE_CLI_ONLY)
#  include <WebView2.h>
#  include <wrl.h>
using Microsoft::WRL::ComPtr;
#endif

#include <algorithm>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <sstream>
#include <vector>

#pragma comment(lib, "Psapi.lib")

namespace pm::perf {
namespace {

constexpr std::size_t kMaxSamples = 360; // ~12 min @ 2s
constexpr std::size_t kMaxEvents  = 400;

std::mutex g_mu;
Sample     g_last{};
bool       g_ui_consumer = false;

ULONGLONG g_sys_prev_kernel = 0;
ULONGLONG g_sys_prev_user   = 0;
ULONGLONG g_sys_prev_idle   = 0;

ULONGLONG g_host_prev_kernel = 0;
ULONGLONG g_host_prev_user   = 0;
ULONGLONG g_host_prev_wall   = 0;

ULONGLONG g_last_gpu_tick = 0;
bool      g_gpu_available = false;
int       g_gpu_pct = 0;
double    g_gpu_used_gb = 0.0;
double    g_gpu_total_gb = 0.0;
std::string g_gpu_name;

struct PidCpuState {
    DWORD     pid = 0;
    ULONGLONG kernel = 0;
    ULONGLONG user = 0;
    ULONGLONG wall = 0;
};

std::vector<PidCpuState> g_wv2_cpu_prev;
std::vector<void*>       g_envs; // ICoreWebView2Environment*

std::deque<Sample> g_samples;
std::deque<Event>  g_events;

std::optional<std::filesystem::path> g_log_path;
bool g_log_checked = false;

bool env_truthy(const wchar_t* name) noexcept
{
    wchar_t buf[32]{};
    const DWORD n = ::GetEnvironmentVariableW(name, buf, static_cast<DWORD>(std::size(buf)));
    if (n == 0 || n >= std::size(buf))
        return false;
    if (buf[0] == L'0' && buf[1] == L'\0')
        return false;
    if (_wcsicmp(buf, L"off") == 0 || _wcsicmp(buf, L"false") == 0)
        return false;
    return true;
}

ULONGLONG ft_to_ull(const FILETIME& ft) noexcept
{
    return (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

int logical_cpu_count() noexcept
{
    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    return si.dwNumberOfProcessors > 0 ? static_cast<int>(si.dwNumberOfProcessors) : 1;
}

void ensure_log_unlocked()
{
    if (g_log_checked)
        return;
    g_log_checked = true;
    if (!env_truthy(L"PM_SYSPROBE"))
        return;
    try {
        const auto dir = media::settings::get_logs_dir();
        SYSTEMTIME st{};
        ::GetLocalTime(&st);
        char name[64]{};
        std::snprintf(name, sizeof(name), "sysprobe-%04u%02u%02u-%02u%02u%02u.log",
                      static_cast<unsigned>(st.wYear), static_cast<unsigned>(st.wMonth),
                      static_cast<unsigned>(st.wDay), static_cast<unsigned>(st.wHour),
                      static_cast<unsigned>(st.wMinute), static_cast<unsigned>(st.wSecond));
        g_log_path = dir / name;
        std::ofstream out(g_log_path->wstring(), std::ios::app | std::ios::binary);
        if (out) {
            out << "# sysprobe pid=" << ::GetCurrentProcessId()
                << " config=" << media::path::path_to_utf8(dir.parent_path()) << "\n";
            logger::info(std::string("[sysprobe] file sink: ") + g_log_path->string());
        }
    } catch (...) {
        g_log_path.reset();
    }
}

void append_log_unlocked(const std::string& line)
{
    ensure_log_unlocked();
    if (!g_log_path)
        return;
    try {
        std::ofstream out(g_log_path->wstring(), std::ios::app | std::ios::binary);
        if (out)
            out << line << '\n';
    } catch (...) {
    }
}

void push_sample_unlocked(const Sample& s)
{
    g_samples.push_back(s);
    while (g_samples.size() > kMaxSamples)
        g_samples.pop_front();
    append_log_unlocked(sample_to_log_line(s));
}

void sample_wv2_unlocked(Sample& out, ULONGLONG wall_now)
{
    out.wv2_n = 0;
    out.wv2_ws_mb = 0;
    out.wv2_cpu_pct = 0;
    out.wv2_browser = out.wv2_renderer = out.wv2_gpu = out.wv2_utility = out.wv2_other = 0;

#if !(defined(FEATURE_BROWSER) && FEATURE_BROWSER) || defined(PM_IMAGE_CLI_ONLY)
    (void)wall_now;
    return;
#else
    struct Proc {
        DWORD pid = 0;
        COREWEBVIEW2_PROCESS_KIND kind = COREWEBVIEW2_PROCESS_KIND_BROWSER;
    };
    std::vector<Proc> procs;
    procs.reserve(32);

    for (void* raw : g_envs) {
        if (!raw)
            continue;
        ComPtr<ICoreWebView2Environment> env(reinterpret_cast<ICoreWebView2Environment*>(raw));
        ComPtr<ICoreWebView2Environment8> env8;
        if (FAILED(env.As(&env8)) || !env8)
            continue;
        ComPtr<ICoreWebView2ProcessInfoCollection> col;
        if (FAILED(env8->GetProcessInfos(&col)) || !col)
            continue;
        UINT count = 0;
        col->get_Count(&count);
        for (UINT i = 0; i < count; ++i) {
            ComPtr<ICoreWebView2ProcessInfo> info;
            if (FAILED(col->GetValueAtIndex(i, &info)) || !info)
                continue;
            INT32 pid = 0;
            COREWEBVIEW2_PROCESS_KIND kind = COREWEBVIEW2_PROCESS_KIND_BROWSER;
            info->get_ProcessId(&pid);
            info->get_Kind(&kind);
            if (pid <= 0)
                continue;
            const DWORD dpid = static_cast<DWORD>(pid);
            bool seen = false;
            for (const auto& p : procs) {
                if (p.pid == dpid) {
                    seen = true;
                    break;
                }
            }
            if (!seen)
                procs.push_back(Proc{dpid, kind});
        }
    }

    const int ncpu = logical_cpu_count();
    std::vector<PidCpuState> next_states;
    next_states.reserve(procs.size());

    long long cpu_num = 0;
    long long cpu_den = 0;

    for (const auto& p : procs) {
        ++out.wv2_n;
        switch (p.kind) {
        case COREWEBVIEW2_PROCESS_KIND_BROWSER:   ++out.wv2_browser; break;
        case COREWEBVIEW2_PROCESS_KIND_RENDERER:  ++out.wv2_renderer; break;
        case COREWEBVIEW2_PROCESS_KIND_GPU:       ++out.wv2_gpu; break;
        case COREWEBVIEW2_PROCESS_KIND_UTILITY:   ++out.wv2_utility; break;
        default:                                  ++out.wv2_other; break;
        }

        HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
        if (!h)
            continue;

        PROCESS_MEMORY_COUNTERS_EX pmc{};
        pmc.cb = sizeof(pmc);
        if (::GetProcessMemoryInfo(h, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc)))
            out.wv2_ws_mb += static_cast<unsigned>(pmc.WorkingSetSize / (1024U * 1024U));

        FILETIME c{}, e{}, k{}, u{};
        if (::GetProcessTimes(h, &c, &e, &k, &u)) {
            const ULONGLONG ku = ft_to_ull(k);
            const ULONGLONG uu = ft_to_ull(u);
            PidCpuState st{p.pid, ku, uu, wall_now};
            for (const auto& prev : g_wv2_cpu_prev) {
                if (prev.pid != p.pid || prev.wall == 0)
                    continue;
                const ULONGLONG dCpu = (ku - prev.kernel) + (uu - prev.user);
                const ULONGLONG dWall = wall_now - prev.wall;
                if (dWall > 0 && ncpu > 0) {
                    const ULONGLONG dWall100ns = dWall * 10000ULL * static_cast<ULONGLONG>(ncpu);
                    if (dWall100ns > 0) {
                        cpu_num += static_cast<long long>(dCpu * 100ULL / dWall100ns);
                        cpu_den += 1;
                    }
                }
                break;
            }
            next_states.push_back(st);
        }
        ::CloseHandle(h);
    }

    g_wv2_cpu_prev = std::move(next_states);
    if (cpu_den > 0)
        out.wv2_cpu_pct = static_cast<int>(std::clamp(cpu_num / cpu_den, 0LL, 100LL));
#endif
}

Sample sample_unlocked()
{
    Sample out{};
    out.tick_ms = ::GetTickCount64();

    FILETIME idleFT{}, kernelFT{}, userFT{};
    if (::GetSystemTimes(&idleFT, &kernelFT, &userFT)) {
        const ULONGLONG idle = ft_to_ull(idleFT);
        const ULONGLONG kernel = ft_to_ull(kernelFT);
        const ULONGLONG user = ft_to_ull(userFT);
        const ULONGLONG dK = kernel - g_sys_prev_kernel;
        const ULONGLONG dU = user - g_sys_prev_user;
        const ULONGLONG dI = idle - g_sys_prev_idle;
        const ULONGLONG dTotal = dK + dU;
        // GetSystemTimes units are 100ns; approximate wall via tick delta below.
        if (g_host_prev_wall > 0 && out.tick_ms >= g_host_prev_wall)
            out.sys_cpu_interval_ms = static_cast<unsigned>(out.tick_ms - g_host_prev_wall);
        if (dTotal > 0)
            out.sys_cpu_pct = static_cast<int>((dTotal - dI) * 100 / dTotal);
        g_sys_prev_kernel = kernel;
        g_sys_prev_user = user;
        g_sys_prev_idle = idle;
    }

    MEMORYSTATUSEX msx{};
    msx.dwLength = sizeof(msx);
    if (::GlobalMemoryStatusEx(&msx)) {
        const auto used = msx.ullTotalPhys - msx.ullAvailPhys;
        out.sys_mem_used_gb = used / (1024.0 * 1024 * 1024);
        out.sys_mem_total_gb = msx.ullTotalPhys / (1024.0 * 1024 * 1024);
        if (msx.ullTotalPhys > 0)
            out.sys_mem_pct = static_cast<int>(used * 100 / msx.ullTotalPhys);
    }

    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (::GetProcessMemoryInfo(::GetCurrentProcess(),
                               reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))
        && pmc.WorkingSetSize > 0)
        out.host_ws_mb = static_cast<unsigned>(pmc.WorkingSetSize / (1024U * 1024U));

    FILETIME c{}, e{}, k{}, u{};
    if (::GetProcessTimes(::GetCurrentProcess(), &c, &e, &k, &u)) {
        const ULONGLONG ku = ft_to_ull(k);
        const ULONGLONG uu = ft_to_ull(u);
        const ULONGLONG wall = out.tick_ms;
        // FILETIME is 100ns; /10'000 → ms.
        out.host_cpu_time_ms = (ku + uu) / 10000ULL;
        if (g_host_prev_wall > 0) {
            const ULONGLONG dCpu = (ku - g_host_prev_kernel) + (uu - g_host_prev_user);
            const ULONGLONG dWall = wall - g_host_prev_wall;
            out.host_cpu_interval_ms = static_cast<unsigned>(dWall);
            if (out.sys_cpu_interval_ms == 0)
                out.sys_cpu_interval_ms = static_cast<unsigned>(dWall);
            const int ncpu = logical_cpu_count();
            if (dWall > 0 && ncpu > 0) {
                const ULONGLONG dWall100ns = dWall * 10000ULL * static_cast<ULONGLONG>(ncpu);
                if (dWall100ns > 0)
                    out.host_cpu_pct = static_cast<int>(
                        std::clamp(dCpu * 100ULL / dWall100ns, 0ULL, 100ULL));
            }
        }
        g_host_prev_kernel = ku;
        g_host_prev_user = uu;
        g_host_prev_wall = wall;
    }

    if (g_last_gpu_tick == 0 || out.tick_ms - g_last_gpu_tick >= 2000) {
        g_last_gpu_tick = out.tick_ms;
        g_gpu_available = false;
        g_gpu_pct = 0;
        g_gpu_used_gb = 0.0;
        g_gpu_total_gb = 0.0;
        g_gpu_name.clear();
        try {
            const auto gpu = media::gpu::query_gpu_memory();
            if (gpu.available && gpu.total_mib > 0) {
                g_gpu_available = true;
                g_gpu_pct = std::clamp(
                    static_cast<int>((static_cast<long long>(gpu.used_mib) * 100) / gpu.total_mib),
                    0, 100);
                g_gpu_used_gb = gpu.used_mib / 1024.0;
                g_gpu_total_gb = gpu.total_mib / 1024.0;
                if (!gpu.devices.empty() && !gpu.devices.front().name.empty())
                    g_gpu_name = gpu.devices.front().name;
            }
        } catch (...) {
            g_gpu_available = false;
            g_gpu_name.clear();
        }
    }
    out.gpu_available = g_gpu_available;
    out.gpu_pct = g_gpu_pct;
    out.gpu_used_gb = g_gpu_used_gb;
    out.gpu_total_gb = g_gpu_total_gb;
    out.gpu_name = g_gpu_name;

    sample_wv2_unlocked(out, out.tick_ms);

    out.sys_cpu_pct = std::clamp(out.sys_cpu_pct, 0, 100);
    out.sys_mem_pct = std::clamp(out.sys_mem_pct, 0, 100);
    out.host_cpu_pct = std::clamp(out.host_cpu_pct, 0, 100);
    out.wv2_cpu_pct = std::clamp(out.wv2_cpu_pct, 0, 100);

    g_last = out;
    push_sample_unlocked(out);
    return out;
}

std::string json_escape(std::string_view s)
{
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '\\': o += "\\\\"; break;
        case '"':  o += "\\\""; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char b[8];
                std::snprintf(b, sizeof(b), "\\u%04x", static_cast<unsigned>(c));
                o += b;
            } else {
                o += c;
            }
        }
    }
    return o;
}

} // namespace

Sample sample()
{
    std::lock_guard lock(g_mu);
    return sample_unlocked();
}

Sample last_sample() noexcept
{
    std::lock_guard lock(g_mu);
    return g_last;
}

void set_ui_consumer(bool active) noexcept
{
    std::lock_guard lock(g_mu);
    g_ui_consumer = active;
}

bool ui_consumer_active() noexcept
{
    std::lock_guard lock(g_mu);
    return g_ui_consumer;
}

void register_webview_environment(void* environment) noexcept
{
#if defined(FEATURE_BROWSER) && FEATURE_BROWSER && !defined(PM_IMAGE_CLI_ONLY)
    if (!environment)
        return;
    std::lock_guard lock(g_mu);
    for (void* e : g_envs) {
        if (e == environment)
            return;
    }
    reinterpret_cast<IUnknown*>(environment)->AddRef();
    g_envs.push_back(environment);
#else
    (void)environment;
#endif
}

void unregister_webview_environment(void* environment) noexcept
{
#if defined(FEATURE_BROWSER) && FEATURE_BROWSER && !defined(PM_IMAGE_CLI_ONLY)
    if (!environment)
        return;
    std::lock_guard lock(g_mu);
    auto it = std::find(g_envs.begin(), g_envs.end(), environment);
    if (it == g_envs.end())
        return;
    reinterpret_cast<IUnknown*>(environment)->Release();
    g_envs.erase(it);
#else
    (void)environment;
#endif
}

void emit_event(std::string_view name, std::string_view surface, std::string_view detail)
{
    Event ev;
    ev.tick_ms = ::GetTickCount64();
    ev.name.assign(name);
    ev.surface.assign(surface);
    ev.detail.assign(detail);
    std::lock_guard lock(g_mu);
    g_events.push_back(ev);
    while (g_events.size() > kMaxEvents)
        g_events.pop_front();
    append_log_unlocked(event_to_log_line(ev));
}

std::vector<Sample> recent_samples(std::size_t max_count)
{
    std::lock_guard lock(g_mu);
    if (max_count == 0 || g_samples.empty())
        return {};
    const std::size_t n = std::min(max_count, g_samples.size());
    return std::vector<Sample>(g_samples.end() - static_cast<std::ptrdiff_t>(n), g_samples.end());
}

std::vector<Event> recent_events(std::size_t max_count)
{
    std::lock_guard lock(g_mu);
    if (max_count == 0 || g_events.empty())
        return {};
    const std::size_t n = std::min(max_count, g_events.size());
    return std::vector<Event>(g_events.end() - static_cast<std::ptrdiff_t>(n), g_events.end());
}

std::string sample_to_json_object(const Sample& s)
{
    std::ostringstream o;
    o << "{\"tickMs\":" << s.tick_ms
      << ",\"sysCpu\":" << s.sys_cpu_pct
      << ",\"sysMem\":" << s.sys_mem_pct
      << ",\"sysMemUsedGb\":" << s.sys_mem_used_gb
      << ",\"sysMemTotalGb\":" << s.sys_mem_total_gb
      << ",\"hostWsMb\":" << s.host_ws_mb
      << ",\"hostCpu\":" << s.host_cpu_pct
      << ",\"hostCpuIntervalMs\":" << s.host_cpu_interval_ms
      << ",\"sysCpuIntervalMs\":" << s.sys_cpu_interval_ms
      << ",\"hostCpuTimeMs\":" << s.host_cpu_time_ms
      << ",\"hostCpuSemantics\":\"interval_since_prev_sample\""
      << ",\"gpuAvailable\":" << (s.gpu_available ? "true" : "false")
      << ",\"gpuPct\":" << s.gpu_pct
      << ",\"gpuUsedGb\":" << s.gpu_used_gb
      << ",\"gpuTotalGb\":" << s.gpu_total_gb
      << ",\"gpuName\":\"" << json_escape(s.gpu_name) << '"'
      << ",\"wv2N\":" << s.wv2_n
      << ",\"wv2WsMb\":" << s.wv2_ws_mb
      << ",\"wv2Cpu\":" << s.wv2_cpu_pct
      << ",\"wv2\":{\"B\":" << s.wv2_browser
      << ",\"R\":" << s.wv2_renderer
      << ",\"G\":" << s.wv2_gpu
      << ",\"U\":" << s.wv2_utility
      << ",\"O\":" << s.wv2_other << "}}";
    return o.str();
}

std::string event_to_json_object(const Event& e)
{
    std::ostringstream o;
    o << "{\"tickMs\":" << e.tick_ms
      << ",\"name\":\"" << json_escape(e.name) << '"'
      << ",\"surface\":\"" << json_escape(e.surface) << '"'
      << ",\"detail\":\"" << json_escape(e.detail) << "\"}";
    return o.str();
}

std::string sample_to_log_line(const Sample& s)
{
    char b[384];
    std::snprintf(
        b, sizeof(b),
        "%llu sys_cpu=%d sys_mem=%d host_ws_mb=%u host_cpu=%d gpu_pct=%d wv2_n=%d wv2_ws_mb=%u wv2_cpu=%d wv2=B%d,R%d,G%d,U%d",
        static_cast<unsigned long long>(s.tick_ms), s.sys_cpu_pct, s.sys_mem_pct, s.host_ws_mb, s.host_cpu_pct,
        s.gpu_pct, s.wv2_n, s.wv2_ws_mb, s.wv2_cpu_pct, s.wv2_browser, s.wv2_renderer, s.wv2_gpu, s.wv2_utility);
    return b;
}

std::string event_to_log_line(const Event& e)
{
    std::ostringstream o;
    o << "evt tick=" << e.tick_ms << " name=" << e.name;
    if (!e.surface.empty())
        o << " surface=" << e.surface;
    if (!e.detail.empty())
        o << " detail=" << e.detail;
    return o.str();
}

bool file_sink_enabled() noexcept
{
    return env_truthy(L"PM_SYSPROBE");
}

} // namespace pm::perf
