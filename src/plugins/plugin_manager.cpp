#include "plugin_manager.hpp"

#include "host_api.hpp"
#include "plugin_guids.h"
#include "logger/logger.h"

#include "host/services.hpp"

#include <nlohmann/json.hpp>

#include <cstring>
#include <fstream>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#include <string.h>
#pragma comment(lib, "psapi.lib")
#endif
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <mutex>
#include <string>
#include <utility>

#ifndef FEATURE_PLUGINS
#define FEATURE_PLUGINS 1
#endif

namespace pm::plugins {
namespace {

namespace fs = std::filesystem;

std::once_flag g_initialize_once;
State          g_state;
PluginManager  g_manager;
std::string    g_bootstrap_log_level = "info";

const char* k_category_names[] = {
    "unknown",
    "onnx",
    "local-ai",
    "vision",
    "audio",
    "extensions",
};

bool has_plugin_extension(const fs::path& path)
{
#if defined(_WIN32)
    const auto ext = path.extension().string();
    return _stricmp(ext.c_str(), ".dll") == 0;
#elif defined(__APPLE__)
    return path.extension() == ".dylib";
#else
    return path.extension() == ".so";
#endif
}

bool is_plugin_module_file(const fs::path& path)
{
    if (!has_plugin_extension(path))
        return false;
    const std::string stem = path.stem().string();
    return stem.find("-plugin") != std::string::npos
        || stem.find("_plugin") != std::string::npos;
}

std::string file_stem(const fs::path& path)
{
    return path.stem().string();
}

int64_t now_us()
{
#if defined(_WIN32)
    static LARGE_INTEGER freq = []() {
        LARGE_INTEGER f{};
        ::QueryPerformanceFrequency(&f);
        return f;
    }();
    LARGE_INTEGER c{};
    ::QueryPerformanceCounter(&c);
    if (freq.QuadPart <= 0)
        return 0;
    return static_cast<int64_t>((c.QuadPart * 1000000LL) / freq.QuadPart);
#else
    using clock = std::chrono::steady_clock;
    return std::chrono::duration_cast<std::chrono::microseconds>(
               clock::now().time_since_epoch())
        .count();
#endif
}

struct MemSample {
    uint64_t ws = 0;
    uint64_t priv = 0;
    bool     ok = false;
};

MemSample sample_mem()
{
    MemSample s;
#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (::GetProcessMemoryInfo(::GetCurrentProcess(),
                               reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                               sizeof(pmc))) {
        s.ws = static_cast<uint64_t>(pmc.WorkingSetSize);
        s.priv = static_cast<uint64_t>(pmc.PrivateUsage);
        s.ok = true;
    }
#endif
    return s;
}

uint64_t module_image_bytes(void* handle)
{
#if defined(_WIN32)
    if (!handle)
        return 0;
    MODULEINFO mi{};
    if (::GetModuleInformation(::GetCurrentProcess(), static_cast<HMODULE>(handle),
                               &mi, sizeof(mi)))
        return static_cast<uint64_t>(mi.SizeOfImage);
#endif
    (void)handle;
    return 0;
}

std::string signed_bytes(int64_t v)
{
    std::string out = (v >= 0) ? "+" : "";
    out += std::to_string(v);
    return out;
}

std::string dt_ms(int64_t us)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.3f", static_cast<double>(us) / 1000.0);
    return buf;
}

void copy_cstr(char* dest, size_t cap, const char* src)
{
    if (!dest || cap == 0)
        return;
    dest[0] = '\0';
    if (!src)
        return;
    std::strncpy(dest, src, cap - 1);
    dest[cap - 1] = '\0';
}

PluginEntry make_placeholder(const PmPluginGuid& guid, uint32_t category, const char* name)
{
    PluginEntry entry;
    entry.info.category = category;
    entry.info.flags = PM_PLUGIN_FLAG_NONE;
    entry.info.abi_version = PM_PLUGIN_ABI_VERSION;
    copy_cstr(entry.info.name, sizeof(entry.info.name), name);
    entry.info.capability_count = 1;
    entry.info.capabilities[0] = guid;
    entry.load_state = LoadState::Missing;
    entry.entitlement = Entitlement::Locked;
    return entry;
}

} // namespace

const char* category_name(uint32_t id) noexcept
{
    if (id >= sizeof(k_category_names) / sizeof(k_category_names[0]))
        return k_category_names[0];
    return k_category_names[id];
}

const char* load_state_name(LoadState state) noexcept
{
    switch (state) {
    case LoadState::Missing:        return "missing";
    case LoadState::LoadFailed:     return "load_failed";
    case LoadState::AbiMismatch:    return "abi_mismatch";
    case LoadState::RuntimeMissing: return "runtime_missing";
    case LoadState::Ready:          return "ready";
    case LoadState::Active:         return "active";
    case LoadState::Installed:      return "installed";
    }
    return "missing";
}

const char* entitlement_name(Entitlement entitlement) noexcept
{
    switch (entitlement) {
    case Entitlement::Locked: return "locked";
    case Entitlement::Free:   return "free";
    case Entitlement::Demo:   return "demo";
    case Entitlement::Owned:  return "owned";
    }
    return "locked";
}

PluginManager::PluginManager()
{
    seed_known_capabilities();
}

PluginManager::~PluginManager()
{
    release_all();
}

void PluginManager::seed_known_capabilities()
{
    add_category(PM_PLUGIN_CATEGORY_ONNX, "onnx");
    add_category(PM_PLUGIN_CATEGORY_LOCAL_AI, "local-ai");
    add_category(PM_PLUGIN_CATEGORY_VISION, "vision");
    add_category(PM_PLUGIN_CATEGORY_AUDIO, "audio");
    add_category(PM_PLUGIN_CATEGORY_EXTENSIONS, "extensions");

    struct Seed {
        PmPluginGuid guid;
        uint32_t     category;
        const char*  name;
    };
    const Seed seeds[] = {
        { guid::k_test_ping,        PM_PLUGIN_CATEGORY_EXTENSIONS, "test.ping" },
        { guid::k_onnx_session,     PM_PLUGIN_CATEGORY_ONNX,       "onnx.session" },
        { guid::k_onnx_classify,    PM_PLUGIN_CATEGORY_ONNX,       "onnx.classify" },
        { guid::k_onnx_ocr,         PM_PLUGIN_CATEGORY_ONNX,       "onnx.ocr" },
        { guid::k_onnx_detect,      PM_PLUGIN_CATEGORY_ONNX,       "onnx.detect" },
        { guid::k_onnx_layout,      PM_PLUGIN_CATEGORY_ONNX,       "onnx.layout" },
        { guid::k_onnx_gtcrn,       PM_PLUGIN_CATEGORY_ONNX,       "onnx.gtcrn" },
        { guid::k_local_ai_embed,   PM_PLUGIN_CATEGORY_LOCAL_AI,   "local-ai.embed" },
        { guid::k_local_ai_chat,    PM_PLUGIN_CATEGORY_LOCAL_AI,   "local-ai.chat" },
        { guid::k_local_ai_vectors, PM_PLUGIN_CATEGORY_LOCAL_AI,   "local-ai.vectors" },
        { guid::k_local_ai_vlm,     PM_PLUGIN_CATEGORY_LOCAL_AI,   "local-ai.vlm" },
        { guid::k_audio_whisper,    PM_PLUGIN_CATEGORY_AUDIO,      "audio.whisper" },
        { guid::k_audio_vibevoice,  PM_PLUGIN_CATEGORY_AUDIO,      "audio.vibevoice" },
        { guid::k_audio_moss,       PM_PLUGIN_CATEGORY_AUDIO,      "audio.moss" },
        { guid::k_search_office,    PM_PLUGIN_CATEGORY_EXTENSIONS, "search.office" },
        { guid::k_llm_kbot,         PM_PLUGIN_CATEGORY_LOCAL_AI,   "llm.kbot" },
        { guid::k_editor_scintilla, PM_PLUGIN_CATEGORY_EXTENSIONS, "editor.scintilla" },
        { guid::k_audio_webrtc,     PM_PLUGIN_CATEGORY_AUDIO,      "audio.webrtc" },
        { guid::k_search_pdf,       PM_PLUGIN_CATEGORY_EXTENSIONS, "search.pdf" },
        { guid::k_ui_ftxui,         PM_PLUGIN_CATEGORY_EXTENSIONS, "ui.ftxui" },
        { guid::k_llm_chat,         PM_PLUGIN_CATEGORY_LOCAL_AI,   "llm.chat" },
        { guid::k_viewer_mpv,       PM_PLUGIN_CATEGORY_EXTENSIONS, "viewer.mpv" },
        { guid::k_viewer_3d,        PM_PLUGIN_CATEGORY_EXTENSIONS, "viewer.3d" },
    };
    for (const auto& seed : seeds) {
        PluginEntry entry = make_placeholder(seed.guid, seed.category, seed.name);
        const int cat = add_category(seed.category, category_name(seed.category));
        entry.index_in_category = static_cast<int>(categories_[static_cast<size_t>(cat)].entry_indices.size());
        categories_[static_cast<size_t>(cat)].entry_indices.push_back(static_cast<int>(entries_.size()));
        entries_.push_back(entry);
    }
}

int PluginManager::add_category(uint32_t id, const char* name)
{
    const char* resolved = (name && *name) ? name : category_name(id);
    for (int i = 0; i < static_cast<int>(categories_.size()); ++i) {
        if (categories_[static_cast<size_t>(i)].id == id
            || categories_[static_cast<size_t>(i)].name == resolved)
            return i;
    }
    PluginCategory cat;
    cat.name = resolved;
    cat.id = id;
    categories_.push_back(std::move(cat));
    return static_cast<int>(categories_.size()) - 1;
}

int PluginManager::add_or_find_entry(const PmPluginGuid& guid)
{
    for (int i = 0; i < static_cast<int>(entries_.size()); ++i) {
        if (entries_[static_cast<size_t>(i)].info.capability_count > 0
            && pm_plugin_guid_equal(entries_[static_cast<size_t>(i)].info.capabilities[0], guid))
            return i;
        for (uint32_t c = 0; c < entries_[static_cast<size_t>(i)].info.capability_count; ++c) {
            if (pm_plugin_guid_equal(entries_[static_cast<size_t>(i)].info.capabilities[c], guid))
                return i;
        }
    }
    PluginEntry entry;
    entry.info.capability_count = 1;
    entry.info.capabilities[0] = guid;
    entries_.push_back(entry);
    return static_cast<int>(entries_.size()) - 1;
}

void PluginManager::apply_info(int dll_index, int position, const PmPluginInfo& info, LoadState state)
{
    const int cat = add_category(info.category, category_name(info.category));
    int entry_index = -1;
    if (info.capability_count > 0)
        entry_index = add_or_find_entry(info.capabilities[0]);
    if (entry_index < 0) {
        PluginEntry fresh;
        entry_index = static_cast<int>(entries_.size());
        entries_.push_back(fresh);
        categories_[static_cast<size_t>(cat)].entry_indices.push_back(entry_index);
        entries_[static_cast<size_t>(entry_index)].index_in_category =
            static_cast<int>(categories_[static_cast<size_t>(cat)].entry_indices.size()) - 1;
    }

    PluginEntry& entry = entries_[static_cast<size_t>(entry_index)];
    entry.dll_index = dll_index;
    entry.position_in_dll = position;
    entry.info = info;
    entry.task_api = info.task_api;
    entry.load_state = state;
    entry.active = state == LoadState::Ready || state == LoadState::Active;
    const int ent = host_api().entitlement
        ? host_api().entitlement(info.capability_count ? &info.capabilities[0] : nullptr)
        : PM_PLUGIN_ENTITLEMENT_LOCKED;
    entry.entitlement = static_cast<Entitlement>(ent);

    bool listed = false;
    for (int idx : categories_[static_cast<size_t>(cat)].entry_indices) {
        if (idx == entry_index) {
            listed = true;
            break;
        }
    }
    if (!listed) {
        entry.index_in_category = static_cast<int>(categories_[static_cast<size_t>(cat)].entry_indices.size());
        categories_[static_cast<size_t>(cat)].entry_indices.push_back(entry_index);
    }
}

bool guid_from_capability_name(const std::string& name, PmPluginGuid& out)
{
    struct Map {
        const char*  name;
        PmPluginGuid guid;
    };
    static const Map k_map[] = {
        { "test.ping",        guid::k_test_ping },
        { "onnx.session",     guid::k_onnx_session },
        { "onnx.classify",    guid::k_onnx_classify },
        { "onnx.ocr",         guid::k_onnx_ocr },
        { "onnx.detect",      guid::k_onnx_detect },
        { "onnx.layout",      guid::k_onnx_layout },
        { "onnx.gtcrn",       guid::k_onnx_gtcrn },
        { "local-ai.embed",   guid::k_local_ai_embed },
        { "local-ai.chat",    guid::k_local_ai_chat },
        { "local-ai.vectors", guid::k_local_ai_vectors },
        { "local-ai.vlm",     guid::k_local_ai_vlm },
        { "audio.whisper",    guid::k_audio_whisper },
        { "audio.vibevoice",  guid::k_audio_vibevoice },
        { "audio.moss",       guid::k_audio_moss },
        { "search.office",    guid::k_search_office },
        { "llm.kbot",         guid::k_llm_kbot },
        { "editor.scintilla", guid::k_editor_scintilla },
        { "audio.webrtc",     guid::k_audio_webrtc },
        { "search.pdf",       guid::k_search_pdf },
        { "ui.ftxui",         guid::k_ui_ftxui },
        { "llm.chat",         guid::k_llm_chat },
        { "viewer.mpv",       guid::k_viewer_mpv },
        { "viewer.3d",        guid::k_viewer_3d },
    };
    for (const auto& row : k_map) {
        if (name == row.name) {
            out = row.guid;
            return true;
        }
    }
    return false;
}

int PluginManager::find_dll_index(const std::string& path) const
{
    for (int i = 0; i < static_cast<int>(dlls_.size()); ++i) {
        if (dlls_[static_cast<size_t>(i)].path == path)
            return i;
    }
    return -1;
}

bool PluginManager::catalog_dll_path(const std::string& path)
{
    if (path.empty())
        return false;
    if (find_dll_index(path) >= 0)
        return true;

    const int64_t t0 = now_us();
    PluginDll dll;
    dll.path = path;
    dll.name = file_stem(fs::path(path));
    const int dll_index = static_cast<int>(dlls_.size());
    dlls_.push_back(std::move(dll));

    const fs::path manifest_path = fs::path(path).parent_path() / "plugin.manifest.json";
    std::error_code ec;
    if (!fs::is_regular_file(manifest_path, ec) || ec) {
        logger::trace(std::string("[plugins] catalog skip (no manifest): ") + path);
        return true;
    }

    nlohmann::json doc;
    try {
        std::ifstream in(manifest_path);
        if (!in)
            return true;
        in >> doc;
    } catch (const std::exception& e) {
        logger::warn(std::string("[plugins] catalog manifest parse failed: ")
                     + manifest_path.string() + " " + e.what());
        return true;
    }

    std::string caps_joined;
    const auto caps = doc.value("capabilities", nlohmann::json::array());
    int bound = 0;
    if (caps.is_array()) {
        for (const auto& cap : caps) {
            if (!cap.is_string())
                continue;
            const std::string name = cap.get<std::string>();
            if (!caps_joined.empty())
                caps_joined += ",";
            caps_joined += name;
            PmPluginGuid guid{};
            if (!guid_from_capability_name(name, guid)) {
                logger::trace(std::string("[plugins] catalog unknown cap=") + name
                              + " dll=" + file_stem(fs::path(path)));
                continue;
            }
            const int entry_index = add_or_find_entry(guid);
            PluginEntry& entry = entries_[static_cast<size_t>(entry_index)];
            entry.dll_index = dll_index;
            entry.load_state = LoadState::Installed;
            entry.active = false;
            entry.task_api = nullptr;
            entry.info.abi_version = doc.value("abi_version", PM_PLUGIN_ABI_VERSION);
            copy_cstr(entry.info.name, sizeof(entry.info.name), name.c_str());
            const std::string desc = doc.value("name", std::string{});
            copy_cstr(entry.info.description, sizeof(entry.info.description), desc.c_str());
            ++bound;
        }
    }
/*
    logger::trace(std::string("[plugins] catalog dll=") + file_stem(fs::path(path))
                  + " path=" + path
                  + " caps=" + (caps_joined.empty() ? "-" : caps_joined)
                  + " bound=" + std::to_string(bound)
                  + " catalog_ms=" + dt_ms(now_us() - t0)
                  + " state=installed (not mapped)");
*/
    return true;
}

bool PluginManager::ensure_loaded(int dll_index)
{
    if (dll_index < 0 || dll_index >= static_cast<int>(dlls_.size()))
        return false;
    PluginDll& dll = dlls_[static_cast<size_t>(dll_index)];
    if (dll.is_static || dll.library.loaded())
        return true;
    logger::trace(std::string("[plugins] load_on_demand dll=") + dll.name
                  + " path=" + dll.path
                  + " via=find_component");
    return load_dll_path(dll.path);
}

bool PluginManager::load_dll_path(const std::string& path)
{
    int dll_index = find_dll_index(path);
    if (dll_index >= 0) {
        PluginDll& existing = dlls_[static_cast<size_t>(dll_index)];
        if (existing.library.loaded() || existing.is_static)
            return true;
    }

    PluginDll fresh;
    fresh.path = path;
    fresh.name = file_stem(fs::path(path));
    PluginDll* dll = &fresh;
    if (dll_index >= 0)
        dll = &dlls_[static_cast<size_t>(dll_index)];
    else
        dll->name = fresh.name;

    const fs::path parent = fs::path(path).parent_path();
    const std::string search = parent.string();
#if defined(_WIN32)
    // Qt's qgetenv() on MSVC reads the CRT environment (getenv_s), which
    // SetEnvironmentVariable does not update. _wputenv_s updates both.
    {
        const fs::path platforms = parent / "qt6" / "plugins" / "platforms";
        std::error_code qt_ec;
        if (fs::is_directory(platforms, qt_ec)) {
            _wputenv_s(L"QT_PLUGIN_PATH", (parent / "qt6" / "plugins").c_str());
            _wputenv_s(L"QT_QPA_PLATFORM_PLUGIN_PATH", platforms.c_str());
            logger::trace(std::string("[plugins] qt platform path=") + platforms.string());
        }
    }
#endif
    const int64_t t0 = now_us();
    const MemSample mem0 = sample_mem();
    if (!dll->library.load(path, search)) {
        const int64_t map_us = now_us() - t0;
        logger::warn(std::string("[plugins] load_failed: ") + path
                     + " map_ms=" + dt_ms(map_us));
        if (dll_index < 0)
            dlls_.push_back(std::move(fresh));
        else
            deactivate_dll_entries(dll_index, LoadState::LoadFailed);
        return false;
    }
    const int64_t t1 = now_us();

    auto* abi = reinterpret_cast<PmPluginAbiVersionFn>(
        dll->library.get_function_ptr("pm_plugin_abi_version"));
    auto* count_fn = reinterpret_cast<PmPluginGetInfoCountFn>(
        dll->library.get_function_ptr("pm_plugin_get_info_count"));
    auto* info_fn = reinterpret_cast<PmPluginGetInfoFn>(
        dll->library.get_function_ptr("pm_plugin_get_info"));
    if (!abi || !count_fn || !info_fn) {
        logger::warn(std::string("[plugins] missing required exports: ") + path);
        dll->library.release();
        if (dll_index < 0)
            dlls_.push_back(std::move(fresh));
        else
            deactivate_dll_entries(dll_index, LoadState::LoadFailed);
        return false;
    }

    LoadState state = LoadState::Ready;
    if (abi() != PM_PLUGIN_ABI_VERSION) {
        logger::warn(std::string("[plugins] abi_mismatch: ") + path
                     + " got=" + std::to_string(abi())
                     + " want=" + std::to_string(PM_PLUGIN_ABI_VERSION));
        state = LoadState::AbiMismatch;
        dll->library.release();
        if (dll_index < 0)
            dlls_.push_back(std::move(fresh));
        else
            deactivate_dll_entries(dll_index, state);
        return false;
    }
    if (auto* probe = reinterpret_cast<PmPluginProbeRuntimeFn>(
            dll->library.get_function_ptr("pm_plugin_probe_runtime"))) {
        if (probe(&host_api()) != 0)
            state = LoadState::RuntimeMissing;
    }

    const int count = count_fn();
    dll->info_count = count < 0 ? 0 : count;
    if (dll_index < 0) {
        dll_index = static_cast<int>(dlls_.size());
        dlls_.push_back(std::move(fresh));
        dll = &dlls_[static_cast<size_t>(dll_index)];
    }

    if (state == LoadState::Ready || state == LoadState::RuntimeMissing) {
        for (int i = 0; i < dll->info_count; ++i) {
            const PmPluginInfo* info = info_fn(i);
            if (!info)
                continue;
            apply_info(dll_index, i, *info, state);
            if (info->callback && state == LoadState::Ready)
                info->callback(PM_PLUGIN_CB_LOAD, &host_api());
        }
    }

    const int64_t t2 = now_us();
    const MemSample mem1 = sample_mem();
    const uint64_t image = module_image_bytes(dll->library.handle());
    const int64_t map_us = t1 - t0;
    const int64_t bind_us = t2 - t1;
    const int64_t total_us = t2 - t0;
    std::string line = std::string("[plugins] loaded dll=") + dll->name
        + " state=" + load_state_name(state)
        + " infos=" + std::to_string(dll->info_count)
        + " map_ms=" + dt_ms(map_us)
        + " bind_ms=" + dt_ms(bind_us)
        + " total_ms=" + dt_ms(total_us)
        + " image=" + std::to_string(image);
    if (mem0.ok && mem1.ok) {
        const int64_t d_ws = static_cast<int64_t>(mem1.ws) - static_cast<int64_t>(mem0.ws);
        const int64_t d_priv = static_cast<int64_t>(mem1.priv) - static_cast<int64_t>(mem0.priv);
        line += " ws=" + std::to_string(mem0.ws) + "->" + std::to_string(mem1.ws)
            + " d_ws=" + signed_bytes(d_ws)
            + " priv=" + std::to_string(mem0.priv) + "->" + std::to_string(mem1.priv)
            + " d_priv=" + signed_bytes(d_priv);
    }
    logger::trace(line);
    return state == LoadState::Ready;
}

int PluginManager::parse_plugins(const std::string& directory)
{
    int found = 0;
    std::error_code ec;
    if (directory.empty() || !fs::is_directory(directory, ec) || ec)
        return 0;

    for (const auto& entry : fs::directory_iterator(directory, ec)) {
        if (ec)
            break;
        std::error_code inner;
        if (entry.is_regular_file(inner) && is_plugin_module_file(entry.path())) {
            if (catalog_dll_path(entry.path().string()))
                ++found;
            continue;
        }
        if (!entry.is_directory(inner))
            continue;
        for (const auto& child : fs::directory_iterator(entry.path(), inner)) {
            if (inner)
                break;
            if (child.is_regular_file(inner) && is_plugin_module_file(child.path())) {
                if (catalog_dll_path(child.path().string()))
                    ++found;
            }
        }
    }
    return found;
}

bool PluginManager::register_plugin(const std::string& path)
{
    if (path.empty())
        return false;
    return load_dll_path(path);
}

bool PluginManager::register_static(const char* name, int count, const PmPluginInfo* infos)
{
    if (!name || !infos || count <= 0)
        return false;

    PluginDll dll;
    dll.path = name;
    dll.name = name;
    dll.info_count = count;
    dll.is_static = true;
    const int dll_index = static_cast<int>(dlls_.size());
    dlls_.push_back(std::move(dll));

    for (int i = 0; i < count; ++i) {
        apply_info(dll_index, i, infos[i], LoadState::Ready);
        if (infos[i].callback)
            infos[i].callback(PM_PLUGIN_CB_LOAD, &host_api());
    }
    return true;
}

void PluginManager::deactivate_dll_entries(int dll_index, LoadState state)
{
    for (auto& entry : entries_) {
        if (entry.dll_index != dll_index)
            continue;
        if (entry.info.callback && entry.load_state == LoadState::Ready)
            entry.info.callback(PM_PLUGIN_CB_UNLOAD, nullptr);
        entry.task_api = nullptr;
        entry.active = false;
        entry.load_state = state;
        entry.dll_index = state == LoadState::Missing ? -1 : entry.dll_index;
    }
}

bool PluginManager::unload_plugin_dll(int dll_index)
{
    if (dll_index < 0 || dll_index >= static_cast<int>(dlls_.size()))
        return false;
    PluginDll& dll = dlls_[static_cast<size_t>(dll_index)];
    deactivate_dll_entries(dll_index, LoadState::Missing);
    if (!dll.is_static)
        dll.library.release();
    return true;
}

bool PluginManager::reload_plugin_dll(int dll_index)
{
    if (dll_index < 0 || dll_index >= static_cast<int>(dlls_.size()))
        return false;
    const std::string path = dlls_[static_cast<size_t>(dll_index)].path;
    const bool is_static = dlls_[static_cast<size_t>(dll_index)].is_static;
    unload_plugin_dll(dll_index);
    if (is_static)
        return false;
    return register_plugin(path);
}

void PluginManager::release_all()
{
    for (int i = 0; i < static_cast<int>(dlls_.size()); ++i)
        unload_plugin_dll(i);
    dlls_.clear();
}

PluginEntry* PluginManager::lookup_component_mut(const PmPluginGuid& guid)
{
    for (auto& entry : entries_) {
        for (uint32_t i = 0; i < entry.info.capability_count; ++i) {
            if (pm_plugin_guid_equal(entry.info.capabilities[i], guid))
                return &entry;
        }
    }
    return nullptr;
}

PluginEntry* PluginManager::lookup_component(const PmPluginGuid& guid)
{
    return lookup_component_mut(guid);
}

const PluginEntry* PluginManager::lookup_component(const PmPluginGuid& guid) const
{
    return const_cast<PluginManager*>(this)->lookup_component_mut(guid);
}

PluginEntry* PluginManager::find_component(const PmPluginGuid& guid)
{
    PluginEntry* entry = lookup_component_mut(guid);
    if (!entry)
        return nullptr;
    if (entry->load_state == LoadState::Installed && entry->dll_index >= 0)
        ensure_loaded(entry->dll_index);
    return lookup_component_mut(guid);
}

const PluginEntry* PluginManager::find_component(const PmPluginGuid& guid) const
{
    return lookup_component(guid);
}

void PluginManager::mark_needed(const PmPluginGuid& guid)
{
    if (PluginEntry* entry = lookup_component_mut(guid))
        entry->needed_by_session = true;
}

int PluginManager::category_count() const
{
    return static_cast<int>(categories_.size());
}

const PluginCategory* PluginManager::category_at(int index) const
{
    if (index < 0 || index >= static_cast<int>(categories_.size()))
        return nullptr;
    return &categories_[static_cast<size_t>(index)];
}

int PluginManager::category_index(const char* name) const
{
    if (!name)
        return -1;
    for (int i = 0; i < static_cast<int>(categories_.size()); ++i) {
        if (categories_[static_cast<size_t>(i)].name == name)
            return i;
    }
    return -1;
}

int PluginManager::dll_count() const
{
    return static_cast<int>(dlls_.size());
}

const PluginDll* PluginManager::dll_at(int index) const
{
    if (index < 0 || index >= static_cast<int>(dlls_.size()))
        return nullptr;
    return &dlls_[static_cast<size_t>(index)];
}

int PluginManager::plugin_count(int category_index) const
{
    const PluginCategory* cat = category_at(category_index);
    return cat ? static_cast<int>(cat->entry_indices.size()) : 0;
}

const PluginEntry* PluginManager::plugin_at(int category_index, int plugin_index) const
{
    const PluginCategory* cat = category_at(category_index);
    if (!cat || plugin_index < 0 || plugin_index >= static_cast<int>(cat->entry_indices.size()))
        return nullptr;
    return &entries_[static_cast<size_t>(cat->entry_indices[static_cast<size_t>(plugin_index)])];
}

PluginEntry* PluginManager::plugin_at(int category_index, int plugin_index)
{
    return const_cast<PluginEntry*>(
        static_cast<const PluginManager*>(this)->plugin_at(category_index, plugin_index));
}

PluginManager& manager()
{
    return g_manager;
}

namespace {

void initialize_once() noexcept
{
    try {
        // Logger is static-linked into this DLL. The exe's logger::init_stderr
        // does not affect host_log / logger::info here. Default spdlog is stdout
        // with a `[` timestamp and breaks `tanit-cli --json`.
        logger::init_stderr("tanit", g_bootstrap_log_level);
        refresh_host_paths();
        g_state.scan_enabled = FEATURE_PLUGINS != 0;
        const fs::path dir = pm::commons::host::exe_parent_directory() / "plugins";
        g_state.plugins_dir = dir.string();

        const int64_t t_catalog0 = now_us();
        const MemSample mem0 = sample_mem();
        if (g_state.scan_enabled)
            g_state.dlls_found = g_manager.parse_plugins(g_state.plugins_dir);
        const int64_t catalog_us = now_us() - t_catalog0;
        const MemSample mem1 = sample_mem();

        int installed = 0;
        int mapped = 0;
        for (const auto& entry : g_manager.entries()) {
            if (entry.load_state == LoadState::Installed)
                ++installed;
            if (entry.load_state == LoadState::Ready || entry.load_state == LoadState::Active)
                ++g_state.entries_ready;
        }
        for (int i = 0; i < g_manager.dll_count(); ++i) {
            const PluginDll* dll = g_manager.dll_at(i);
            if (dll && dll->library.loaded())
                ++mapped;
        }

        std::string init = std::string("[plugins] init dir=") + g_state.plugins_dir
            + " dlls=" + std::to_string(g_state.dlls_found)
            + " installed=" + std::to_string(installed)
            + " mapped=" + std::to_string(mapped)
            + " ready=" + std::to_string(g_state.entries_ready)
            + " catalog_ms=" + dt_ms(catalog_us);
        if (mem0.ok && mem1.ok) {
            const int64_t d_ws = static_cast<int64_t>(mem1.ws) - static_cast<int64_t>(mem0.ws);
            const int64_t d_priv = static_cast<int64_t>(mem1.priv) - static_cast<int64_t>(mem0.priv);
            init += " d_ws=" + signed_bytes(d_ws) + " d_priv=" + signed_bytes(d_priv);
        }
        init += " (catalog only; LoadLibrary on find_component)";
        logger::trace(init);
    } catch (const std::exception& e) {
        g_state.error = e.what();
        logger::warn(std::string("[plugins] init failed: ") + g_state.error);
    } catch (...) {
        g_state.error = "unknown error";
        logger::warn("[plugins] init failed: unknown error");
    }
    g_state.initialized = true;
}

} // namespace

void set_bootstrap_log_level(const char* level) noexcept
{
    if (level && *level)
        g_bootstrap_log_level = level;
}

const State& initialize() noexcept
{
    std::call_once(g_initialize_once, initialize_once);
    return g_state;
}

const State& state() noexcept
{
    return initialize();
}

} // namespace pm::plugins
