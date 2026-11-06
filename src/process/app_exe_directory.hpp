#pragma once

#include "polymech_export.h"

#include <filesystem>
#include <vector>

namespace media::app {

/// Parent directory of the running executable (install / `dist` folder), or empty if unknown.
POLYMECH_API std::filesystem::path exe_parent_directory();

/// Full path of the running executable, or empty if unknown.
POLYMECH_API std::filesystem::path exe_executable();

/// Full path of the CLI sibling executable (e.g. tanit-cli / tanit-cli.exe),
/// or empty if the file cannot be found next to the running executable.
POLYMECH_API std::filesystem::path exe_cli_executable();

#if defined(_WIN32)
/// Write this process's CLI path to the Chrome native-messaging `cli` value.
/// The host reads that value before PATH, so the last Tanit exe the user
/// started is the one Chrome spawns. Agent `--serve` does not write (that
/// child is the host's, not a new winner). A Store image under WindowsApps is
/// recorded as the execution alias, and only when that alias file exists.
POLYMECH_API void publish_running_cli_for_chrome_host();
#endif

/// Full path of the GUI product executable (e.g. tanit.exe / tanit-viewer.exe,
/// or the POSIX stem from `PM_APP_ID_SLUG`), resolved next to the running
/// executable. Empty if that branded file is missing.
///
/// Uses the current product basename (`k_exe_basename_w` / `k_app_id_u8`), not
/// `FEATURE_VIEWER_WEB` (capability; ON in both SKUs) and not
/// `k_viewer_exe_basename_w` (Open-with copy of the full Tanit exe). The
/// viewer SKU is `POLYMECH_APP_TANIT_VIEWER`, which already sets
/// `PM_APP_ID_SLUG=tanit-viewer` so this path is `tanit-viewer.exe`.
POLYMECH_API std::filesystem::path exe_gui_executable();

/// Directory for bundled third-party executables next to the app, e.g. `dist/win-x64/bin`.
POLYMECH_API std::filesystem::path exe_bin_directory();

/// Install-bundled profile directory beside the exe parent, e.g. `dist/roaming` when the exe lives in
/// `dist/bin`. Empty when the path is missing or not a directory.
POLYMECH_API std::filesystem::path exe_bundled_roaming_directory();

/// Resolve a bundled third-party executable: `exe_bin_directory()` / known
/// tools, then `ui.appPathDirectories` (same list RunTool prepends to PATH),
/// then process PATH and Windows App Paths. On Windows, PATHEXT prefers `.exe`
/// over `.cmd`.
POLYMECH_API std::filesystem::path resolve_third_party_executable(const std::filesystem::path& executable);

/// Append candidate paths for `dist/shared/<relative>` and co-located copies (works for
/// `dist/win-x64`, `dist/win-x64-viewer`, and legacy beside-exe layouts).
POLYMECH_API void append_dist_shared_candidates(
    std::vector<std::filesystem::path>& out,
    const std::filesystem::path& exe_dir,
    const std::filesystem::path& relative);

/// First existing regular file among dist/shared candidates (prefers `exe/../shared/...`).
POLYMECH_API std::filesystem::path resolve_dist_shared_file(
    const std::filesystem::path& relative);

/// `dist/shared` directory for the current install layout (prefers `exe/../shared`).
POLYMECH_API std::filesystem::path resolve_dist_shared_directory();

/// Shipped model roots next to the exe: `exe/shared/models` (Store), `exe/models`,
/// then `exe/../models` (desktop `win-x64` sibling). Does not require the dirs to exist.
POLYMECH_API void append_bundled_models_candidates(
    std::vector<std::filesystem::path>& out,
    const std::filesystem::path& exe_dir);

/// `dist/shared/assets.pfs` (Tabler filled SVG archive), or empty when absent.
POLYMECH_API std::filesystem::path resolve_tabler_assets_pfs();

/// Loose Tabler filled icons directory (`dist/vendor/tabler-icons/icons/filled`), or empty.
POLYMECH_API std::filesystem::path resolve_tabler_filled_vendor_dir();

/// Append candidate paths for `dist/bundles/<app_stem>/<relative>`.
POLYMECH_API void append_dist_bundle_candidates(
    std::vector<std::filesystem::path>& out,
    const std::filesystem::path& exe_dir,
    const std::filesystem::path& app_stem,
    const std::filesystem::path& relative);

/// Shipped Tanit Chrome MV3 extension folder (`dist/extension/tanit-chrome`), or empty.
POLYMECH_API std::filesystem::path resolve_tanit_chrome_extension_dir();

} // namespace media::app
