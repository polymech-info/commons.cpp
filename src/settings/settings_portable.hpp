#pragma once

#include "core/settings_types.hpp"

#include <filesystem>
#include <string>

#include <nlohmann/json.hpp>

namespace media::portable_settings {

using ProviderEntry = media::settings_types::ProviderEntry;
using ProviderMap = media::settings_types::ProviderMap;
using ChatProviderSettings = media::settings_types::ChatProviderSettings;

bool load_chat_provider(ChatProviderSettings& out, std::string& err);
bool load_providers(ProviderMap& out, std::string& err);

/// Fill API key / base URL from `providers[provider]`. The caller must have set `provider`
/// explicitly from chat settings or a command/tool override; this never fills a missing model
/// from provider-row defaults. Skips when `dry_run` is true.
void merge_image_provider_credentials(
    std::string& provider,
    std::string& api_key,
    std::string& base_url,
    std::string& default_model,
    bool dry_run);

// ---------------------------------------------------------------------------
// PixelWiz / pm-image profile JSON (UTF-8). Windows GUI profile may be PME1;
// use `pm-image settings export|import` on Windows for that store.
// Linux/Unix: ~/.pm-image/settings.json unless the profile dir is overridden.
// ---------------------------------------------------------------------------
void set_profile_dir_override(const std::filesystem::path& dir);
std::filesystem::path settings_pixelwiz_profile_json_path();
/// Parent directory of portable `settings.json` (profile root). macOS: Library/…/pm-image;
/// Linux/Unix: ~/.pm-image or POLYMECH_PM_IMAGE_PROFILE_DIR.
std::filesystem::path settings_pixelwiz_profile_dir();
/// Read path: cwd/settings.json first, then profile (for normal loads).
bool read_settings_profile_json(nlohmann::json& out, std::string& err);
/// Read from profile only — used by export/import, never picks up cwd.
bool read_profile_direct(nlohmann::json& out, std::string& err);
bool write_settings_profile_json(const nlohmann::json& root, std::string& err);

/// macOS: `~/Library/Application Support/CodeEdit/settings.json` (empty path elsewhere).
std::filesystem::path settings_codeedit_prefs_json_path();

/// macOS: merge portable profile keys from `import_root` into CodeEdit prefs so the app file
/// stays aligned with `pm-image settings import`. No-op on other platforms (returns true).
bool merge_settings_import_into_codeedit_prefs(const nlohmann::json& import_root, std::string& err);

} // namespace media::portable_settings
