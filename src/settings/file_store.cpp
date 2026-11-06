#include "settings/store.hpp"

namespace media::settings {

std::filesystem::path get_config_dir();
std::filesystem::path get_models_dir();
std::filesystem::path get_temp_dir();
std::filesystem::path get_logs_dir();
void set_config_dir_override(const std::filesystem::path& dir);
void set_settings_read_path_override(const std::filesystem::path& absolute_path);
void clear_settings_read_path_override();
bool load_settings_utf8(std::string& out_json, std::string& err);
bool save_settings_utf8(const std::string& utf8_json, std::string& err);
bool load_subtree(const std::string& key, nlohmann::json& out, std::string& err);
bool save_subtree(const std::string& key, const nlohmann::json& value, std::string& err);
bool export_settings_file(const std::filesystem::path& path, bool encrypted, std::string& err);
#if defined(_WIN32)
bool reset_profile_encryption_key(int& rewritten, std::string& err);
#endif

std::filesystem::path FileStore::config_dir() { return get_config_dir(); }
std::filesystem::path FileStore::models_dir() { return get_models_dir(); }
std::filesystem::path FileStore::temp_dir() { return get_temp_dir(); }
std::filesystem::path FileStore::logs_dir() { return get_logs_dir(); }

void FileStore::set_config_dir_override(const std::filesystem::path& dir)
{
    ::media::settings::set_config_dir_override(dir);
}

void FileStore::set_settings_read_path_override(const std::filesystem::path& absolute_path)
{
    ::media::settings::set_settings_read_path_override(absolute_path);
}

void FileStore::clear_settings_read_path_override()
{
    ::media::settings::clear_settings_read_path_override();
}

bool FileStore::load_settings_utf8(std::string& out_json, std::string& err)
{
    return ::media::settings::load_settings_utf8(out_json, err);
}

bool FileStore::save_settings_utf8(const std::string& utf8_json, std::string& err)
{
    return ::media::settings::save_settings_utf8(utf8_json, err);
}

bool FileStore::load_subtree(const std::string& key, nlohmann::json& out, std::string& err)
{
    return ::media::settings::load_subtree(key, out, err);
}

bool FileStore::save_subtree(const std::string& key, const nlohmann::json& value, std::string& err)
{
    return ::media::settings::save_subtree(key, value, err);
}

bool FileStore::export_settings_file(const std::filesystem::path& path, bool encrypted, std::string& err)
{
    return ::media::settings::export_settings_file(path, encrypted, err);
}

bool FileStore::reset_profile_encryption_key(int& rewritten, std::string& err)
{
#if defined(_WIN32)
    return ::media::settings::reset_profile_encryption_key(rewritten, err);
#else
    (void)rewritten;
    err = "profile key reset is part of the Windows file store";
    return false;
#endif
}

Store& open_store(const HostConfig& config)
{
    static FileStore store;
    if (!config.config_dir.empty())
        store.set_config_dir_override(config.config_dir);
    return store;
}

} // namespace media::settings
