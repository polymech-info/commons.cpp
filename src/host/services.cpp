#include "host/services.hpp"

#include <algorithm>
#include <cctype>

namespace pm::commons::host {
namespace {

std::function<std::filesystem::path()> g_exe_parent;
std::function<std::filesystem::path()> g_exe_executable;
std::function<std::filesystem::path()> g_exe_bin;
std::function<std::filesystem::path(const std::filesystem::path&)> g_resolve;
std::function<std::filesystem::path()> g_config_dir;
std::function<std::filesystem::path()> g_models_dir;
std::function<std::filesystem::path()> g_temp_dir;
std::function<bool(const std::string&, nlohmann::json&, std::string&)> g_load_subtree;
std::function<bool(const std::string&, const nlohmann::json&, std::string&)> g_save_subtree;
std::function<bool(Appearance&, std::string&)> g_load_appearance;
std::function<std::string(std::string_view)> g_expand;
std::function<std::string(std::string_view)> g_path_to_stored;
std::function<std::string(std::string_view)> g_stored_scope;
std::function<bool()> g_cancel;
std::function<std::vector<std::string>()> g_search_dirs;
std::function<std::vector<ProviderRow>()> g_providers;
std::function<std::vector<ToolRow>()> g_tools;
std::vector<OriginEntry> g_origins;
AppCmdAllowedFn g_app_cmd = nullptr;
std::string g_magic_db;
std::wstring g_policy_root;

std::string identity(std::string_view text)
{
    return std::string(text);
}

std::filesystem::path call_path(const std::function<std::filesystem::path()>& fn)
{
    return fn ? fn() : std::filesystem::path{};
}

} // namespace

void set_exe_parent_directory(std::function<std::filesystem::path()> fn) { g_exe_parent = std::move(fn); }
void set_exe_executable(std::function<std::filesystem::path()> fn) { g_exe_executable = std::move(fn); }
void set_exe_bin_directory(std::function<std::filesystem::path()> fn) { g_exe_bin = std::move(fn); }
void set_resolve_third_party_executable(
    std::function<std::filesystem::path(const std::filesystem::path&)> fn) { g_resolve = std::move(fn); }

std::filesystem::path exe_parent_directory() { return call_path(g_exe_parent); }
std::filesystem::path exe_executable() { return call_path(g_exe_executable); }
std::filesystem::path exe_bin_directory() { return call_path(g_exe_bin); }
std::filesystem::path resolve_third_party_executable(const std::filesystem::path& name)
{
    return g_resolve ? g_resolve(name) : std::filesystem::path{};
}

void set_config_dir(std::function<std::filesystem::path()> fn) { g_config_dir = std::move(fn); }
void set_models_dir(std::function<std::filesystem::path()> fn) { g_models_dir = std::move(fn); }
void set_temp_dir(std::function<std::filesystem::path()> fn) { g_temp_dir = std::move(fn); }
std::filesystem::path config_dir() { return call_path(g_config_dir); }
std::filesystem::path models_dir() { return call_path(g_models_dir); }
std::filesystem::path temp_dir() { return call_path(g_temp_dir); }

void set_load_subtree(std::function<bool(const std::string&, nlohmann::json&, std::string&)> fn)
{
    g_load_subtree = std::move(fn);
}
void set_save_subtree(std::function<bool(const std::string&, const nlohmann::json&, std::string&)> fn)
{
    g_save_subtree = std::move(fn);
}
bool load_subtree(const std::string& key, nlohmann::json& out, std::string& err)
{
    if (!g_load_subtree)
        return false;
    return g_load_subtree(key, out, err);
}
bool save_subtree(const std::string& key, const nlohmann::json& value, std::string& err)
{
    if (!g_save_subtree) {
        err = "settings store is not installed";
        return false;
    }
    return g_save_subtree(key, value, err);
}

void set_load_appearance(std::function<bool(Appearance&, std::string&)> fn)
{
    g_load_appearance = std::move(fn);
}
bool load_appearance(Appearance& out, std::string& err)
{
    if (!g_load_appearance)
        return false;
    return g_load_appearance(out, err);
}

void set_expand_stored_text(std::function<std::string(std::string_view)> fn) { g_expand = std::move(fn); }
void set_path_to_stored(std::function<std::string(std::string_view)> fn) { g_path_to_stored = std::move(fn); }
void set_stored_scope(std::function<std::string(std::string_view)> fn) { g_stored_scope = std::move(fn); }
std::string expand_stored_text(std::string_view text) { return g_expand ? g_expand(text) : identity(text); }
std::string path_to_stored(std::string_view path) { return g_path_to_stored ? g_path_to_stored(path) : identity(path); }
std::string stored_scope(std::string_view scope) { return g_stored_scope ? g_stored_scope(scope) : identity(scope); }

void set_cancel_requested(std::function<bool()> fn) { g_cancel = std::move(fn); }
bool cancel_requested() { return g_cancel ? g_cancel() : false; }

void set_app_search_path_dirs(std::function<std::vector<std::string>()> fn) { g_search_dirs = std::move(fn); }
std::vector<std::string> app_search_path_dirs()
{
    return g_search_dirs ? g_search_dirs() : std::vector<std::string>{};
}

void set_magic_database_path(std::string path) { g_magic_db = std::move(path); }
std::string magic_database_path() { return g_magic_db; }

void set_provider_rows(std::function<std::vector<ProviderRow>()> fn) { g_providers = std::move(fn); }
std::vector<ProviderRow> provider_rows()
{
    return g_providers ? g_providers() : std::vector<ProviderRow>{};
}

const ProviderRow* find_provider(std::string_view name, const std::vector<ProviderRow>& rows)
{
    auto lower = [](std::string_view s) {
        std::string out(s);
        for (char& c : out)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return out;
    };
    const std::string want = lower(name);
    for (const auto& row : rows) {
        if (lower(row.name) == want)
            return &row;
    }
    return nullptr;
}

void set_tool_rows(std::function<std::vector<ToolRow>()> fn) { g_tools = std::move(fn); }
std::vector<ToolRow> tool_rows()
{
    return g_tools ? g_tools() : std::vector<ToolRow>{};
}

void set_origin_entries(std::vector<OriginEntry> entries) { g_origins = std::move(entries); }
const std::vector<OriginEntry>& origin_entries() { return g_origins; }

void set_app_cmd_allowed(AppCmdAllowedFn fn) { g_app_cmd = fn; }
bool app_cmd_allowed(int cmd_enum, bool& handled)
{
    handled = g_app_cmd != nullptr;
    return handled ? g_app_cmd(cmd_enum) : true;
}

void set_policy_registry_root(std::wstring root) { g_policy_root = std::move(root); }
const std::wstring& policy_registry_root() { return g_policy_root; }

} // namespace pm::commons::host
