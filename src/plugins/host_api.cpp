#include "host_api.hpp"

#include "host/services.hpp"
#include "logger/logger.h"

#include <cstdlib>
#include <cstring>
#include <string>

namespace pm::plugins {
namespace {

char g_exe_dir[PM_PLUGIN_PATH_LENGTH]{};
char g_plugins_dir[PM_PLUGIN_PATH_LENGTH]{};
char g_models_dir[PM_PLUGIN_PATH_LENGTH]{};
char g_cache_dir[PM_PLUGIN_PATH_LENGTH]{};

void copy_path(char* dest, size_t cap, const std::string& src)
{
    if (!dest || cap == 0)
        return;
    dest[0] = '\0';
    if (src.empty())
        return;
    const size_t n = src.size() < cap - 1 ? src.size() : cap - 1;
    std::memcpy(dest, src.data(), n);
    dest[n] = '\0';
}

void host_log(int level, const char* message)
{
    const std::string msg = message ? message : "";
    switch (level) {
    case PM_PLUGIN_LOG_TRACE: logger::trace(msg); break;
    case PM_PLUGIN_LOG_DEBUG: logger::debug(msg); break;
    case PM_PLUGIN_LOG_WARN:  logger::warn(msg);  break;
    case PM_PLUGIN_LOG_ERROR: logger::error(msg); break;
    default:                  logger::info(msg);  break;
    }
}

const char* host_exe_dir() { return g_exe_dir; }
const char* host_plugins_dir() { return g_plugins_dir; }
const char* host_models_dir() { return g_models_dir; }
const char* host_cache_dir() { return g_cache_dir; }

int host_entitlement(const PmPluginGuid*)
{
    /* Loading a DLL does not grant a paid capability. Store snapshot comes later. */
    return PM_PLUGIN_ENTITLEMENT_OWNED;
}

void* host_alloc(size_t bytes)
{
    return bytes ? std::malloc(bytes) : nullptr;
}

void host_free(void* ptr)
{
    std::free(ptr);
}

PmHostApi g_host_api{
    PM_PLUGIN_ABI_VERSION,
    &host_log,
    &host_exe_dir,
    &host_plugins_dir,
    &host_models_dir,
    &host_cache_dir,
    &host_entitlement,
    &host_alloc,
    &host_free,
};

} // namespace

void refresh_host_paths() noexcept
{
    try {
        copy_path(g_exe_dir, sizeof(g_exe_dir), pm::commons::host::exe_parent_directory().string());
        copy_path(g_plugins_dir, sizeof(g_plugins_dir),
                  (pm::commons::host::exe_parent_directory() / "plugins").string());
        copy_path(g_models_dir, sizeof(g_models_dir), pm::commons::host::models_dir().string());
        copy_path(g_cache_dir, sizeof(g_cache_dir), pm::commons::host::temp_dir().string());
    } catch (...) {
        /* Path helpers may throw on filesystem errors; keep last-good buffers. */
    }
}

const PmHostApi& host_api() noexcept
{
    return g_host_api;
}

} // namespace pm::plugins
