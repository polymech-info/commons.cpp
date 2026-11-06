#pragma once

#include "polymech_export.h"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace media::app {

using EnvironmentMap = std::unordered_map<std::string, std::string>;

enum class ResolveIntent {
    Command,     // what would execute?
    Application, // find installed application
    InstallRoot  // interested primarily in application root
};

enum class ResolveSource : std::uint32_t {
    None      = 0,
    Explicit  = 1u << 0,
    Tanit     = 1u << 1,
    Path      = 1u << 2,  // extra_paths, then PATH + PATHEXT
    AppPaths  = 1u << 3,  // direct App Paths key lookup
    AppIndex  = 1u << 4,  // cached AppFinder inventory
    Heuristic = 1u << 5   // reserved; Command never uses live scans
};

constexpr ResolveSource operator|(ResolveSource a, ResolveSource b)
{
    return static_cast<ResolveSource>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}
constexpr ResolveSource operator&(ResolveSource a, ResolveSource b)
{
    return static_cast<ResolveSource>(static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b));
}
constexpr bool has_source(ResolveSource set, ResolveSource bit)
{
    return (static_cast<std::uint32_t>(set) & static_cast<std::uint32_t>(bit)) != 0;
}

constexpr ResolveSource k_command_sources =
    ResolveSource::Explicit | ResolveSource::Tanit | ResolveSource::Path | ResolveSource::AppPaths;
constexpr ResolveSource k_application_sources = k_command_sources | ResolveSource::AppIndex;

enum class ApplicationSource {
    ExplicitPath,
    TanitBundled,
    TanitPlugin,
    TanitKnownTool,
    Path,
    AppExecutionAlias,
    WindowsAppPaths,
    WindowsRegisteredApp,
    WindowsStartMenu,
    WindowsPackage,
    MacApplicationBundle,
    MacPath,
    LinuxDesktopEntry,
    LinuxPath,
    ExistingAppDiscovery,
    Unknown
};

enum class LaunchKind {
    Native,
    CmdScript,
    PowerShell,
    AppAlias,
    Bundle,
    Unknown
};

enum class MatchQuality {
    Exact,
    Registered,
    Heuristic
};

struct ResolvedApplication {
    std::string query;

    std::filesystem::path executable;
    std::filesystem::path install_root; // only when actually known
    std::optional<std::filesystem::path> working_directory;
    std::optional<std::filesystem::path> app_paths_env;
    std::optional<std::filesystem::path> physical_executable;

    std::string display_name;

    ApplicationSource source = ApplicationSource::Unknown;
    LaunchKind kind = LaunchKind::Unknown;
    MatchQuality match = MatchQuality::Exact;
    std::size_t source_order = 0;

    std::optional<std::string> launch_name;

    bool exists = false;
    bool directly_executable = false;
    bool bundled = false;
    bool packaged = false;
    bool app_execution_alias = false;

    std::optional<std::size_t> path_index;

    std::unordered_map<std::string, std::string> metadata;
};

struct ResolveRequest {
    ResolveIntent intent = ResolveIntent::Command;
    ResolveSource sources = ResolveSource::None; // None → default for intent
    bool all = false;

    const EnvironmentMap* environment = nullptr;
    std::optional<std::filesystem::path> cwd;
    std::vector<std::filesystem::path> extra_paths;
};

struct KnownTool {
    std::string name;
    std::filesystem::path path;
    std::filesystem::path install_root;
    std::string display_name;
};

using AppDiscoveryFn = std::function<std::vector<ResolvedApplication>(
    std::string_view query, const ResolveRequest& request)>;

/// One public pipeline. Command is cheap/exact. Application/InstallRoot may
/// consume the cached AppFinder index. Ordinary misses return empty.
POLYMECH_API std::vector<ResolvedApplication> resolve_application(
    std::string_view query,
    const ResolveRequest& request = {});

POLYMECH_API std::optional<ResolvedApplication> resolve_first_application(
    std::string_view query,
    const ResolveRequest& request = {});

/// `install_root` of the first candidate, only when that field is known.
POLYMECH_API std::optional<std::filesystem::path> resolve_application_directory(
    std::string_view query,
    const ResolveRequest& request = {});

POLYMECH_API void register_known_tool(KnownTool tool);
POLYMECH_API void clear_known_tools();

POLYMECH_API void set_existing_app_discovery_fn(AppDiscoveryFn fn);

POLYMECH_API std::string_view application_source_id(ApplicationSource source);
POLYMECH_API std::string_view launch_kind_id(LaunchKind kind);
POLYMECH_API std::string_view match_quality_id(MatchQuality match);

} // namespace media::app
