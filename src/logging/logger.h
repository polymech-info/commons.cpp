#pragma once

#include <string>

namespace logger {

/// Initialize the default logger (call once at startup).
void init(const std::string &app_name = "polymech", const std::string &log_level = "info");

/// Initialize logger with stderr sink (use in worker/IPC mode).
void init_stderr(const std::string &app_name = "polymech-worker", const std::string &log_level = "info");

/// stderr color sink plus an optional UTF-8 log file (append). If @p log_file_utf8 is empty, same as @ref init_stderr.
void init_stderr_and_file(
    const std::string& app_name,
    const std::string& log_level,
    const std::string& log_file_utf8);

#if defined(__APPLE__)
/// Resolve `PM_IMAGE_LOG_DIR/<filename>` or `$HOME/Desktop/<filename>` (UTF-8 path string).
std::string macos_file_log_path_for_filename_utf8(const std::string& log_filename);

/** Once per process: `init_stderr_and_file` using @ref macos_file_log_path_for_filename_utf8 with `app_id_u8 + ".log"`,
 *  then `os_log` (subsystem `com.polymech.pm-image`, category `FileLogging`) and `fprintf(stderr, …)` so Terminal
 *  and **Console.app** show where spdlog writes. Safe if called from CLI and again from PixelWiz. */
void macos_bootstrap_file_logging_utf8(const char* app_id_u8, const char* log_level_u8);
#endif

/// Initialize logger with stderr and file sink (use in UDS worker mode).
void init_uds(const std::string &app_name = "polymech-worker", const std::string &log_level = "info", const std::string &log_file = "logs/uds.json");

/// Set the default spdlog level (stderr/stdout logger). Normalizes case; accepts
/// trace|debug|info|warn|warning|error|err|critical|off|none. Unknown values fall back to info.
void set_log_level(const std::string& level);

/// Flush the default spdlog sink(s) (stderr/stdout). Call before process exit so the shell is not left
/// waiting for a final line of log output (common with `wWinMain` + Windows Terminal / PowerShell).
void flush();

/// Cheap level checks for call sites whose message formatting is non-trivial.
bool trace_enabled();
bool debug_enabled();

/// Log at various levels.
void info(const std::string &msg);
void warn(const std::string &msg);
void error(const std::string &msg);
void debug(const std::string &msg);
void trace(const std::string &msg);

} // namespace logger
