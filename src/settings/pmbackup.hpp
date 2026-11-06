#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "core/settings_archive.hpp"

namespace media::pmbackup {

/// Portable cloud-backup encryption key (32-byte secretbox key). User copies this file to other machines.
inline constexpr const char k_cloud_storage_key_name[] = ".cloud_storage_key";
/// Encrypted profile blob suffix for cloud VFS uploads.
inline constexpr const char k_profile_backup_suffix[] = ".pmbackup";

/// Legacy fixed cloud backup name (download fallback only).
inline constexpr const char k_profile_backup_legacy_filename[] = "profile.pmbackup";

struct PmbackupOptions {
    settings_archive::ConfigBackupOptions content{};
    /// Empty = @c config_dir/.cloud_storage_key (v1 key-file mode).
    std::filesystem::path cloud_storage_key_override{};
    /// Non-empty = Argon2id passphrase encryption (v2); key file is not used.
    std::string passphrase;
};

std::filesystem::path cloud_storage_key_path(const std::filesystem::path& config_dir);

/// Local-time backup basename: @c yyyy-mm-dd-hh.pmbackup
std::string profile_backup_filename_now();

/// True for @c yyyy-mm-dd-hh.pmbackup names.
bool is_timestamped_profile_backup_filename(const std::string& filename);

/// Newest timestamped backup, else legacy @ref k_profile_backup_legacy_filename, else empty.
std::string select_newest_profile_backup_filename(const std::vector<std::string>& filenames);

/// Resolve key path: @p override_key when non-empty, else @ref cloud_storage_key_path.
std::filesystem::path resolve_cloud_storage_key_path(const std::filesystem::path& config_dir,
                                                     const std::filesystem::path& override_key = {});

/// Load key file or create a new random key at @p key_path on first export/upload.
bool load_or_create_cloud_storage_key_at(const std::filesystem::path& key_path, std::string& err);

/// Load an existing key at @p key_path (import/decrypt). Does not create a key.
bool load_cloud_storage_key_at(const std::filesystem::path& key_path, std::string& err);

/// Load @ref k_cloud_storage_key_name under @p config_dir or create it on first export/upload.
bool load_or_create_cloud_storage_key(const std::filesystem::path& config_dir, std::string& err);

/// Load default @ref k_cloud_storage_key_name under @p config_dir. Does not create a key.
bool load_cloud_storage_key(const std::filesystem::path& config_dir, std::string& err);

/// Ensure the profile key exists, then copy it to @p dest (Save As for sharing with another machine).
bool export_cloud_storage_key_file(const std::filesystem::path& dest, std::string& err,
                                   const std::filesystem::path& config_dir = {});

/// Validate @p src as a 32-byte key and install it as the profile @ref k_cloud_storage_key_name.
bool import_cloud_storage_key_file(const std::filesystem::path& src, std::string& err,
                                   const std::filesystem::path& config_dir = {});

/// Replace the profile key with a fresh random 32-byte key. Old keyfile-encrypted backups will not decrypt.
bool regenerate_cloud_storage_key(std::string& err, const std::filesystem::path& config_dir = {});

/// Encrypt settings/commands/mcp/home.page config backup (ZIP) into a @c .pmbackup file.
/// v1 = key file; v2 = passphrase when @p options.passphrase is non-empty.
bool export_profile_pmbackup(const std::filesystem::path& out,
                             std::string& err,
                             const PmbackupOptions& options = {});

/// Decrypt a @c .pmbackup file and restore config backup contents into the current profile.
bool import_profile_pmbackup(const std::filesystem::path& backup_path,
                             std::string& err,
                             const PmbackupOptions& options = {});
} // namespace media::pmbackup
