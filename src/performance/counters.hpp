#pragma once
// Shared host / WebView2 performance counters (statusbar + perfui popup + optional log).
// See docs/perf-next.md.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace pm::perf {

/// One sample tick (status-bar cadence = 2000 ms).
struct Sample {
    std::uint64_t tick_ms = 0; ///< GetTickCount64 at sample time

    int sys_cpu_pct = 0;
    int sys_mem_pct = 0;
    double sys_mem_used_gb = 0.0;
    double sys_mem_total_gb = 0.0;

    unsigned host_ws_mb = 0;
    int      host_cpu_pct = 0;
    /// Wall ms spanned by this sample's host/sys CPU % (0 on first seed sample).
    unsigned host_cpu_interval_ms = 0;
    unsigned sys_cpu_interval_ms  = 0;
    /// Cumulative process CPU time (kernel+user) in ms — use Δ/wall for benchmark cores.
    std::uint64_t host_cpu_time_ms = 0;

    bool gpu_available = false;
    int  gpu_pct = 0;
    double gpu_used_gb = 0.0;
    double gpu_total_gb = 0.0;
    std::string gpu_name; ///< Primary adapter name when available.

    int      wv2_n = 0;
    unsigned wv2_ws_mb = 0;
    int      wv2_cpu_pct = 0;
    int      wv2_browser = 0;
    int      wv2_renderer = 0;
    int      wv2_gpu = 0;
    int      wv2_utility = 0;
    int      wv2_other = 0;
};

struct Event {
    std::uint64_t tick_ms = 0;
    std::string   name;
    std::string   surface; ///< chat / settings / viewer / …
    std::string   detail;  ///< free-form (uri, ok=, …)
};

/// Take one sample (updates internal deltas). Thread: UI / main.
Sample sample();

/// Last sample from @ref sample (zeros until first call).
Sample last_sample() noexcept;

/// Keep the stats timer alive even when the status bar is hidden (perf popup).
void set_ui_consumer(bool active) noexcept;
bool ui_consumer_active() noexcept;

/// Register / unregister a live WebView2 environment (ICoreWebView2Environment*).
/// Opaque void* avoids pulling WebView2.h into every consumer.
void register_webview_environment(void* environment) noexcept;
void unregister_webview_environment(void* environment) noexcept;

/// Push a sparse event into the ring (and optional log).
void emit_event(std::string_view name,
                std::string_view surface = {},
                std::string_view detail = {});

/// Recent history for popup catch-up (oldest → newest).
std::vector<Sample> recent_samples(std::size_t max_count = 300);
std::vector<Event>  recent_events(std::size_t max_count = 200);

/// UTF-8 JSON object for host→web (`sysprobeTick` payload fields).
std::string sample_to_json_object(const Sample& s);
/// UTF-8 JSON object for `sysprobeEvt` payload fields.
std::string event_to_json_object(const Event& e);
/// Compact key=value log line (no trailing newline).
std::string sample_to_log_line(const Sample& s);
std::string event_to_log_line(const Event& e);

/// True when PM_SYSPROBE is truthy (file sink under config_dir()/logs).
bool file_sink_enabled() noexcept;

} // namespace pm::perf
