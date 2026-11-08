#pragma once

#include <string>
#include <string_view>

namespace pm::logging {

/// Product facts for the VictoriaLogs sink. `install_victoria_forwarder` does
/// nothing until this is set. `env_var=off` (also `0`, `false`, `none`) disables
/// the sink. An unset variable uses `default_url`.
struct VictoriaForwarderConfig {
    std::string env_var;
    std::string default_url;
    std::string source;
    std::string build;
};

void set_victoria_forwarder_config(VictoriaForwarderConfig config);

/// Probe VictoriaLogs once per process and attach a sink to the current default
/// logger. `logger::init_stderr` can replace that logger later; call this again
/// to reattach. The health probe does not run a second time.
void install_victoria_forwarder();

/// Send queued events. Returns after the queue drains or a short timeout.
void flush_victoria_forwarder();

/// Remember a line the spdlog sink already forwarded, so the Log panel mirror
/// does not send it again.
void remember_victoria_mirror(std::string_view formatted_line);

/// Forward a Log panel line that did not come from the spdlog sink.
void forward_victoria_panel_line(std::string_view line);

} // namespace pm::logging
