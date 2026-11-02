#pragma once

#include "plugin_abi.h"
#include "shared_library.hpp"

#include <string>
#include <vector>

namespace pm::plugins {

enum class LoadState : uint32_t {
    Missing = 0,
    LoadFailed,
    AbiMismatch,
    RuntimeMissing,
    Ready,
    Active,
    Installed, // manifest cataloged; DLL not mapped yet
};

enum class Entitlement : uint32_t {
    Locked = 0,
    Free,
    Demo,
    Owned,
};

struct PluginDll {
    std::string    path;
    std::string    name;
    SharedLibrary  library;
    int            info_count = 0;
    bool           is_static = false;
};

struct PluginEntry {
    int           dll_index = -1;
    int           position_in_dll = 0;
    int           index_in_category = 0;
    LoadState     load_state = LoadState::Missing;
    Entitlement   entitlement = Entitlement::Locked;
    bool          needed_by_session = false;
    bool          active = false;
    PmPluginInfo  info{};
    const void*   task_api = nullptr;
};

struct PluginCategory {
    std::string      name;
    uint32_t         id = PM_PLUGIN_CATEGORY_UNKNOWN;
    std::vector<int> entry_indices;
};

struct State {
    bool        initialized = false;
    bool        scan_enabled = false;
    std::string plugins_dir;
    int         dlls_found = 0;
    int         entries_ready = 0;
    std::string error;
};

class PluginManager {
public:
    PluginManager();
    ~PluginManager();

    PluginManager(const PluginManager&) = delete;
    PluginManager& operator=(const PluginManager&) = delete;

    int  parse_plugins(const std::string& directory);
    bool register_plugin(const std::string& path);
    bool register_static(const char* name, int count, const PmPluginInfo* infos);

    bool unload_plugin_dll(int dll_index);
    bool reload_plugin_dll(int dll_index);
    void release_all();

    /** Catalog only. Does not LoadLibrary. */
    PluginEntry*       lookup_component(const PmPluginGuid& guid);
    const PluginEntry* lookup_component(const PmPluginGuid& guid) const;
    /** Lookup, then map the owning DLL on first use. */
    PluginEntry*       find_component(const PmPluginGuid& guid);
    const PluginEntry* find_component(const PmPluginGuid& guid) const;
    void               mark_needed(const PmPluginGuid& guid);

    int                   category_count() const;
    const PluginCategory* category_at(int index) const;
    int                   category_index(const char* name) const;

    int              dll_count() const;
    const PluginDll* dll_at(int index) const;

    int                plugin_count(int category_index) const;
    const PluginEntry* plugin_at(int category_index, int plugin_index) const;
    PluginEntry*       plugin_at(int category_index, int plugin_index);

    const std::vector<PluginEntry>& entries() const { return entries_; }

private:
    void seed_known_capabilities();
    int  add_category(uint32_t id, const char* name);
    int  add_or_find_entry(const PmPluginGuid& guid);
    bool catalog_dll_path(const std::string& path);
    bool load_dll_path(const std::string& path);
    bool ensure_loaded(int dll_index);
    int  find_dll_index(const std::string& path) const;
    PluginEntry* lookup_component_mut(const PmPluginGuid& guid);
    void apply_info(int dll_index, int position, const PmPluginInfo& info, LoadState state);
    void deactivate_dll_entries(int dll_index, LoadState state);

    std::vector<PluginCategory> categories_;
    std::vector<PluginDll>      dlls_;
    std::vector<PluginEntry>    entries_;
};

PluginManager& manager();

/** Apply `--log-level` before initialize(). Logger lives in this DLL; the exe
 *  copy of logger::set_log_level does not reach plugin host.log. */
void set_bootstrap_log_level(const char* level) noexcept;

/** Initialize before CLI/UI registration (same bootstrap window as ms_app_store). */
const State& initialize() noexcept;
const State& state() noexcept;

const char* category_name(uint32_t id) noexcept;
const char* load_state_name(LoadState state) noexcept;
const char* entitlement_name(Entitlement entitlement) noexcept;

} // namespace pm::plugins
