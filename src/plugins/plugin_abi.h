#pragma once

/*
 * Tanit plugin ABI — POD / C only across the host↔DLL boundary.
 *
 * Required exports (extern "C"):
 *   uint32_t            pm_plugin_abi_version(void);
 *   int                 pm_plugin_get_info_count(void);
 *   const PmPluginInfo* pm_plugin_get_info(int index);
 *
 * Optional:
 *   int pm_plugin_probe_runtime(const PmHostApi* host);
 *     0 = runtime present, non-zero = runtime_missing.
 *
 * No STL, exceptions, RTTI, or nlohmann across this boundary.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PM_PLUGIN_ABI_VERSION
#define PM_PLUGIN_ABI_VERSION 1u
#endif
#define PM_PLUGIN_NAME_LENGTH 80
#define PM_PLUGIN_DESC_LENGTH 160
#define PM_PLUGIN_MAX_CAPABILITIES 16
#define PM_PLUGIN_PATH_LENGTH 512

typedef struct PmPluginGuid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t  data4[8];
} PmPluginGuid;

enum PmPluginCategory {
    PM_PLUGIN_CATEGORY_UNKNOWN    = 0,
    PM_PLUGIN_CATEGORY_ONNX       = 1,
    PM_PLUGIN_CATEGORY_LOCAL_AI   = 2,
    PM_PLUGIN_CATEGORY_VISION     = 3,
    PM_PLUGIN_CATEGORY_AUDIO      = 4,
    PM_PLUGIN_CATEGORY_EXTENSIONS = 5
};

enum PmPluginFlag {
    PM_PLUGIN_FLAG_NONE                   = 0,
    PM_PLUGIN_FLAG_RECEIVE_NOTIFICATION   = 1u << 0
};

enum PmPluginCallbackReason {
    PM_PLUGIN_CB_NONE   = 0,
    PM_PLUGIN_CB_LOAD   = 1,
    PM_PLUGIN_CB_UNLOAD = 2,
    PM_PLUGIN_CB_NOTIFY = 3
};

enum PmPluginLogLevel {
    PM_PLUGIN_LOG_TRACE = 0,
    PM_PLUGIN_LOG_DEBUG = 1,
    PM_PLUGIN_LOG_INFO  = 2,
    PM_PLUGIN_LOG_WARN   = 3,
    PM_PLUGIN_LOG_ERROR = 4
};

enum PmPluginEntitlement {
    PM_PLUGIN_ENTITLEMENT_LOCKED = 0,
    PM_PLUGIN_ENTITLEMENT_FREE   = 1,
    PM_PLUGIN_ENTITLEMENT_DEMO   = 2,
    PM_PLUGIN_ENTITLEMENT_OWNED  = 3
};

typedef struct PmHostApi {
    uint32_t abi_version;
    void        (*log)(int level, const char* message);
    const char* (*exe_dir)(void);
    const char* (*plugins_dir)(void);
    const char* (*models_dir)(void);
    const char* (*cache_dir)(void);
    int         (*entitlement)(const PmPluginGuid* capability);
    void*       (*alloc)(size_t bytes);
    void        (*free)(void* ptr);
} PmHostApi;

typedef void (*PmPluginCallback)(int reason, const PmHostApi* host);

typedef struct PmPluginInfo {
    uint32_t         category;
    uint32_t         flags;
    uint32_t         abi_version;
    char             name[PM_PLUGIN_NAME_LENGTH];
    char             description[PM_PLUGIN_DESC_LENGTH];
    uint32_t         capability_count;
    PmPluginGuid     capabilities[PM_PLUGIN_MAX_CAPABILITIES];
    PmPluginCallback callback;
    const void*      task_api;
} PmPluginInfo;

typedef uint32_t            (*PmPluginAbiVersionFn)(void);
typedef int                 (*PmPluginGetInfoCountFn)(void);
typedef const PmPluginInfo* (*PmPluginGetInfoFn)(int index);
typedef int                 (*PmPluginProbeRuntimeFn)(const PmHostApi* host);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
inline bool pm_plugin_guid_equal(const PmPluginGuid& a, const PmPluginGuid& b) noexcept
{
    return a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3
        && a.data4[0] == b.data4[0] && a.data4[1] == b.data4[1]
        && a.data4[2] == b.data4[2] && a.data4[3] == b.data4[3]
        && a.data4[4] == b.data4[4] && a.data4[5] == b.data4[5]
        && a.data4[6] == b.data4[6] && a.data4[7] == b.data4[7];
}

inline bool pm_plugin_guid_is_zero(const PmPluginGuid& g) noexcept
{
    return g.data1 == 0 && g.data2 == 0 && g.data3 == 0
        && g.data4[0] == 0 && g.data4[1] == 0 && g.data4[2] == 0 && g.data4[3] == 0
        && g.data4[4] == 0 && g.data4[5] == 0 && g.data4[6] == 0 && g.data4[7] == 0;
}
#endif
