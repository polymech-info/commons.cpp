#pragma once

// Host-owned facts the portable library asks for. The settings store, branding
// strings, and tool registries stay on the host and are installed as callbacks.

#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "security/types.hpp"

namespace pm::commons::host {

void set_exe_parent_directory(std::function<std::filesystem::path()> fn);
void set_exe_executable(std::function<std::filesystem::path()> fn);
void set_exe_bin_directory(std::function<std::filesystem::path()> fn);
void set_resolve_third_party_executable(
    std::function<std::filesystem::path(const std::filesystem::path&)> fn);

std::filesystem::path exe_parent_directory();
std::filesystem::path exe_executable();
std::filesystem::path exe_bin_directory();
std::filesystem::path resolve_third_party_executable(const std::filesystem::path& name);

void set_config_dir(std::function<std::filesystem::path()> fn);
void set_models_dir(std::function<std::filesystem::path()> fn);
void set_temp_dir(std::function<std::filesystem::path()> fn);
std::filesystem::path config_dir();
std::filesystem::path models_dir();
std::filesystem::path temp_dir();

void set_load_subtree(std::function<bool(const std::string&, nlohmann::json&, std::string&)> fn);
void set_save_subtree(std::function<bool(const std::string&, const nlohmann::json&, std::string&)> fn);
bool load_subtree(const std::string& key, nlohmann::json& out, std::string& err);
bool save_subtree(const std::string& key, const nlohmann::json& value, std::string& err);

struct Appearance {
    int theme = 0; // 0 system, 1 light, 2 dark
    std::string display_language = "en";
};
void set_load_appearance(std::function<bool(Appearance&, std::string&)> fn);
bool load_appearance(Appearance& out, std::string& err);

void set_expand_stored_text(std::function<std::string(std::string_view)> fn);
void set_path_to_stored(std::function<std::string(std::string_view)> fn);
void set_stored_scope(std::function<std::string(std::string_view)> fn);
std::string expand_stored_text(std::string_view text);
std::string path_to_stored(std::string_view path);
std::string stored_scope(std::string_view scope);

void set_cancel_requested(std::function<bool()> fn);
bool cancel_requested();

void set_app_search_path_dirs(std::function<std::vector<std::string>()> fn);
std::vector<std::string> app_search_path_dirs();

void set_magic_database_path(std::string path);
std::string magic_database_path();

struct ProviderRow {
    std::string name;
    std::string display_name;
    std::string policy_key;
    bool build_enabled = false;
};
void set_provider_rows(std::function<std::vector<ProviderRow>()> fn);
std::vector<ProviderRow> provider_rows();
const ProviderRow* find_provider(std::string_view name, const std::vector<ProviderRow>& rows);

enum class ToolGroup {
    File, Image, Utility, Scheduler, Memory, Computer, Browser, Service, App, Network
};
struct ToolRow {
    std::string name;
    ToolGroup group = ToolGroup::File;
};
void set_tool_rows(std::function<std::vector<ToolRow>()> fn);
std::vector<ToolRow> tool_rows();

struct OriginEntry {
    std::string id;
    std::string binary;
    std::string display;
    pm::security::OriginKind kind = pm::security::OriginKind::Unknown;
};
void set_origin_entries(std::vector<OriginEntry> entries);
const std::vector<OriginEntry>& origin_entries();

using AppCmdAllowedFn = bool (*)(int cmd_enum);
void set_app_cmd_allowed(AppCmdAllowedFn fn);
bool app_cmd_allowed(int cmd_enum, bool& handled);

void set_policy_registry_root(std::wstring root);
const std::wstring& policy_registry_root();

} // namespace pm::commons::host
