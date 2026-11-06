#pragma once

// Profile document. FileStore is the default. A database adapter implements Store.

#include <filesystem>
#include <string>

#include <nlohmann/json.hpp>

namespace media::settings {

enum class StorageKind {
    File,
};

struct HostConfig {
    StorageKind kind = StorageKind::File;
    std::filesystem::path config_dir;
    std::filesystem::path models_dir;
    std::filesystem::path temp_dir;
    std::filesystem::path logs_dir;
};

class Store {
public:
    virtual ~Store() = default;

    virtual std::filesystem::path config_dir() = 0;
    virtual std::filesystem::path models_dir() = 0;
    virtual std::filesystem::path temp_dir() = 0;
    virtual std::filesystem::path logs_dir() = 0;

    virtual void set_config_dir_override(const std::filesystem::path& dir) = 0;
    virtual void set_settings_read_path_override(const std::filesystem::path& absolute_path) = 0;
    virtual void clear_settings_read_path_override() = 0;

    virtual bool load_settings_utf8(std::string& out_json, std::string& err) = 0;
    virtual bool save_settings_utf8(const std::string& utf8_json, std::string& err) = 0;
    virtual bool load_subtree(const std::string& key, nlohmann::json& out, std::string& err) = 0;
    virtual bool save_subtree(const std::string& key, const nlohmann::json& value, std::string& err) = 0;
    virtual bool export_settings_file(const std::filesystem::path& path, bool encrypted, std::string& err) = 0;
    virtual bool reset_profile_encryption_key(int& rewritten, std::string& err) = 0;
};

class FileStore final : public Store {
public:
    std::filesystem::path config_dir() override;
    std::filesystem::path models_dir() override;
    std::filesystem::path temp_dir() override;
    std::filesystem::path logs_dir() override;

    void set_config_dir_override(const std::filesystem::path& dir) override;
    void set_settings_read_path_override(const std::filesystem::path& absolute_path) override;
    void clear_settings_read_path_override() override;

    bool load_settings_utf8(std::string& out_json, std::string& err) override;
    bool save_settings_utf8(const std::string& utf8_json, std::string& err) override;
    bool load_subtree(const std::string& key, nlohmann::json& out, std::string& err) override;
    bool save_subtree(const std::string& key, const nlohmann::json& value, std::string& err) override;
    bool export_settings_file(const std::filesystem::path& path, bool encrypted, std::string& err) override;
    bool reset_profile_encryption_key(int& rewritten, std::string& err) override;
};

Store& open_store(const HostConfig& config = {});

} // namespace media::settings
