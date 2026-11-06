#pragma once

#include <filesystem>
#include <string>

namespace media::settings_archive {

struct ConfigBackupOptions {
    bool include_commands = true;
    bool include_mcp = false;
    bool include_prompts = false;
    bool include_home_page = true;
};

/// Write a ZIP of the app profile (portable settings.json + profile files; skips web* dirs, .settings-key.dat, and .cloud_storage_key).
bool export_settings_archive_zip(const std::filesystem::path& out, std::string& err_out);

/// Restore a profile ZIP produced by @ref export_settings_archive_zip.
bool import_settings_archive_zip(const std::filesystem::path& zip_path, std::string& err_out);

/// Write a small config backup ZIP: settings.json plus optional commands/mcp files only.
bool export_config_backup_zip(const std::filesystem::path& out,
                              const ConfigBackupOptions& options,
                              std::string& err_out);

/// Restore a ZIP produced by @ref export_config_backup_zip.
bool import_config_backup_zip(const std::filesystem::path& zip_path, std::string& err_out);

} // namespace media::settings_archive
