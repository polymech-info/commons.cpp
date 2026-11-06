#include "logging/logger.h"

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/spdlog.h>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <vector>

#if defined(__APPLE__)
#    include <cstdio>
#    include <cstdlib>
#    include <os/log.h>
#endif


namespace logger {

namespace {

void normalize_level_token(std::string& s)
{
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

void apply_log_level_normalized(std::string level)
{
    normalize_level_token(level);
    if (level == "warning")
        level = "warn";
    if (level == "err")
        level = "error";
    if (level == "none")
        level = "off";

    if (level == "trace")
        spdlog::set_level(spdlog::level::trace);
    else if (level == "debug")
        spdlog::set_level(spdlog::level::debug);
    else if (level == "warn")
        spdlog::set_level(spdlog::level::warn);
    else if (level == "error")
        spdlog::set_level(spdlog::level::err);
    else if (level == "critical")
        spdlog::set_level(spdlog::level::critical);
    else if (level == "off")
        spdlog::set_level(spdlog::level::off);
    else
        spdlog::set_level(spdlog::level::info);
}

} // namespace

void set_log_level(const std::string& level)
{
    apply_log_level_normalized(level);
    if (auto l = spdlog::default_logger())
        l->flush();
}

void init(const std::string &app_name, const std::string &log_level) {
  auto console = spdlog::stdout_color_mt(app_name);
  spdlog::set_default_logger(console);
  apply_log_level_normalized(log_level);
  spdlog::set_pattern("[%H:%M:%S] [%^%l%$] %v");
}

void init_stderr(const std::string &app_name, const std::string &log_level) {
  try {
    auto console = spdlog::stderr_color_mt(app_name);
    spdlog::set_default_logger(console);
  } catch (const spdlog::spdlog_ex&) {
    if (auto existing = spdlog::get(app_name))
      spdlog::set_default_logger(existing);
  }
  apply_log_level_normalized(log_level);
  spdlog::set_pattern("[%H:%M:%S] [%^%l%$] %v");
}

void init_stderr_and_file(const std::string& app_name, const std::string& log_level, const std::string& log_file_utf8)
{
    auto stderr_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
    std::vector<spdlog::sink_ptr> sinks{stderr_sink};
    if (!log_file_utf8.empty()) {
        try {
            namespace fs = std::filesystem;
            const fs::path p(log_file_utf8);
            std::error_code ec;
            fs::create_directories(p.parent_path(), ec);
            auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file_utf8, /*truncate=*/false);
            sinks.push_back(file_sink);
        } catch (...) {
            // File sink optional — keep stderr-only if path is bad or not creatable.
        }
    }
    if (sinks.size() == 1U) {
        auto console = std::make_shared<spdlog::logger>(app_name, sinks.front());
        spdlog::set_default_logger(console);
    } else {
        auto multi = std::make_shared<spdlog::logger>(app_name, sinks.begin(), sinks.end());
        spdlog::set_default_logger(multi);
        spdlog::flush_every(std::chrono::seconds(3));
        spdlog::flush_on(spdlog::level::info);
    }
    apply_log_level_normalized(log_level);
    spdlog::set_pattern("[%H:%M:%S] [%^%l%$] %v");
}

#if defined(__APPLE__)
namespace {

std::filesystem::path macos_pm_image_log_dir_from_env()
{
    const char* raw = std::getenv("PM_IMAGE_LOG_DIR");
    if (!raw || !raw[0])
        return {};
    std::string dir(raw);
    while (!dir.empty() && std::isspace(static_cast<unsigned char>(dir.front())))
        dir.erase(0, 1);
    while (!dir.empty() && std::isspace(static_cast<unsigned char>(dir.back())))
        dir.pop_back();
    if (dir.empty())
        return {};
    namespace fs = std::filesystem;
    std::error_code ec;
    const fs::path abs = fs::absolute(fs::path(dir), ec);
    if (ec || abs.empty())
        return {};
    return abs;
}

bool macos_can_append_log_file(const std::filesystem::path& file)
{
    try {
        namespace fs = std::filesystem;
        std::error_code ec;
        fs::create_directories(file.parent_path(), ec);
        (void)ec;
        std::ofstream out(file, std::ios::app | std::ios::binary);
        return static_cast<bool>(out);
    } catch (...) {
        return false;
    }
}

} // namespace

std::string macos_file_log_path_for_filename_utf8(const std::string& log_filename)
{
    namespace fs = std::filesystem;
    std::vector<fs::path> candidates;
    const fs::path env_dir = macos_pm_image_log_dir_from_env();
    if (!env_dir.empty())
        candidates.push_back(env_dir / log_filename);
    const char* home = std::getenv("HOME");
    if (home && home[0]) {
        const fs::path h(home);
        candidates.push_back(h / "Desktop" / log_filename);
        candidates.push_back(h / "Library" / "Logs" / "pm-image" / log_filename);
    }
    for (const auto& p : candidates) {
        if (macos_can_append_log_file(p))
            return p.string();
    }
    return {};
}

void macos_bootstrap_file_logging_utf8(const char* app_id_u8, const char* log_level_u8)
{
    static std::once_flag once;
    std::call_once(once, [app_id_u8, log_level_u8] {
        if (!app_id_u8 || !app_id_u8[0])
            return;
        const std::string aid(app_id_u8);
        const std::string lev((log_level_u8 && log_level_u8[0]) ? log_level_u8 : "info");
        const std::string path = macos_file_log_path_for_filename_utf8(aid + ".log");
        init_stderr_and_file(aid, lev, path);
        os_log_t lg = os_log_create("com.polymech.pm-image", "FileLogging");
        if (!path.empty()) {
            // DEFAULT shows in Console.app without requiring "Info" visibility for some filters.
            os_log_with_type(lg, OS_LOG_TYPE_DEFAULT, "pm-image-spdlog-file %{public}s", path.c_str());
            std::fprintf(
                stderr,
                "%s: pm-image-spdlog-file %s (Console.app: subsystem com.polymech.pm-image or search "
                "pm-image-spdlog-file)\n",
                aid.c_str(),
                path.c_str());
            if (auto l = spdlog::default_logger()) {
                if (l->sinks().size() >= 2U) {
                    l->info("pm-image-spdlog-file: {}", path);
                    l->flush();
                } else {
                    std::fprintf(
                        stderr,
                        "%s: pm-image-spdlog-file path %s was chosen but file sink failed; stderr only\n",
                        aid.c_str(),
                        path.c_str());
                }
            }
        } else {
            os_log_with_type(
                lg,
                OS_LOG_TYPE_DEFAULT,
                "pm-image-spdlog-file: no writable log path (Desktop / Library/Logs/pm-image / "
                "PM_IMAGE_LOG_DIR); stderr only");
            std::fprintf(
                stderr,
                "%s: pm-image-spdlog-file no writable file path (try PM_IMAGE_LOG_DIR); stderr only\n",
                aid.c_str());
        }
        (void)std::fflush(stderr);
    });
}
#endif

void flush() {
  if (auto l = spdlog::default_logger())
    l->flush();
}

void init_uds(const std::string &app_name, const std::string &log_level, const std::string &log_file) {
  auto console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
  
  std::filesystem::path log_path(log_file);
  std::error_code ec;
  std::filesystem::create_directories(log_path.parent_path(), ec);
  
  auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file, false); // false = append
  
  std::vector<spdlog::sink_ptr> sinks {console_sink, file_sink};
  auto multi_logger = std::make_shared<spdlog::logger>(app_name, sinks.begin(), sinks.end());
  
  spdlog::set_default_logger(multi_logger);
  apply_log_level_normalized(log_level);
  spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
  // Ensure logs are flushed immediately to file 
  spdlog::flush_every(std::chrono::seconds(1));
  spdlog::flush_on(spdlog::level::info);
}

bool trace_enabled()
{
  const auto log = spdlog::default_logger();
  return log && log->should_log(spdlog::level::trace);
}

bool debug_enabled()
{
  const auto log = spdlog::default_logger();
  return log && log->should_log(spdlog::level::debug);
}

void info(const std::string &msg) { spdlog::info(msg); }
void warn(const std::string &msg) { spdlog::warn(msg); }
void error(const std::string &msg) { spdlog::error(msg); }
void debug(const std::string &msg) { spdlog::debug(msg); }
void trace(const std::string &msg) { spdlog::trace(msg); }

} // namespace logger
