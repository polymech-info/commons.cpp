#pragma once

#include "core/library_utils.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <dxgi.h>
#define PM_POPEN  _popen
#define PM_PCLOSE _pclose
#else
#define PM_POPEN  popen
#define PM_PCLOSE pclose
#endif

namespace media::gpu {

struct GpuInfo
{
    int index = 0;

    std::string vendor;
    std::string name;
    std::string driver;

    bool unifiedMemory = false;

    std::uint64_t memoryUsedMb = 0;
    std::uint64_t memoryTotalMb = 0;

    bool hasMemoryUsed = false;
    bool hasMemoryTotal = false;

    float utilizationGpu = -1.0f;
    float utilizationMemory = -1.0f;

    bool isDiscrete = false;
};

struct GpuStatusLine
{
    std::string text;
};

struct GpuMemoryDevice {
    int         index = 0;
    std::string name;
    int         used_mib = 0;
    int         total_mib = 0;
};

struct GpuMemoryStats {
    bool                         available = false;
    int                          used_mib = 0;
    int                          total_mib = 0;
    std::vector<GpuMemoryDevice> devices;
};

inline std::string trim_copy(std::string s)
{
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

namespace detail {

inline std::uint64_t bytes_to_mib(std::uint64_t bytes) noexcept
{
    return bytes / (1024ULL * 1024ULL);
}

inline int clamp_mib_to_int(std::uint64_t mb) noexcept
{
    return mb > static_cast<std::uint64_t>(std::numeric_limits<int>::max())
        ? std::numeric_limits<int>::max()
        : static_cast<int>(mb);
}

inline std::string format_mib(std::uint64_t mb)
{
    std::ostringstream os;
    if (mb >= 1024) {
        const double gb = static_cast<double>(mb) / 1024.0;
        if (gb >= 10.0)
            os << std::fixed << std::setprecision(0) << gb << "GB";
        else
            os << std::fixed << std::setprecision(1) << gb << "GB";
    } else {
        os << mb << "MB";
    }
    return os.str();
}

inline std::string compact_name(std::string name)
{
    name = trim_copy(std::move(name));
    constexpr const char* prefixes[] = {
        "NVIDIA GeForce ",
        "NVIDIA ",
        "AMD Radeon ",
        "AMD ",
        "Intel(R) ",
        "Intel ",
    };
    for (const char* prefix : prefixes) {
        const std::string p(prefix);
        if (name.rfind(p, 0) == 0)
            return name.substr(p.size());
    }
    return name;
}

inline GpuStatusLine make_status_line(const std::vector<GpuInfo>& gpus)
{
    for (const auto& gpu : gpus) {
        if (gpu.name.empty())
            continue;

        GpuStatusLine line;
        line.text = compact_name(gpu.name);
        if (gpu.hasMemoryUsed && gpu.hasMemoryTotal) {
            line.text += " ";
            line.text += format_mib(gpu.memoryUsedMb);
            line.text += " / ";
            line.text += format_mib(gpu.memoryTotalMb);
        } else if (gpu.hasMemoryTotal) {
            line.text += gpu.unifiedMemory ? " Unified WS " : " VRAM ";
            line.text += format_mib(gpu.memoryTotalMb);
        }
        return line;
    }
    return {};
}

#if defined(_WIN32)

inline std::string wide_to_utf8(const wchar_t* value)
{
    if (!value || !*value) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<std::size_t>(n - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, value, -1, out.data(), n, nullptr, nullptr);
    return out;
}

inline std::string vendor_from_pci_id(unsigned vendorId)
{
    switch (vendorId) {
    case 0x10DE: return "NVIDIA";
    case 0x1002:
    case 0x1022: return "AMD";
    case 0x8086: return "Intel";
    default: {
        std::ostringstream os;
        os << "0x" << std::hex << std::uppercase << vendorId;
        return os.str();
    }
    }
}

inline bool is_software_adapter(const DXGI_ADAPTER_DESC1& desc) noexcept
{
    return (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0
        || desc.VendorId == 0x1414; // Microsoft Basic Render Driver.
}

inline std::vector<GpuInfo> query_dxgi()
{
    std::vector<GpuInfo> out;
    IDXGIFactory1* factory = nullptr;
    if (FAILED(::CreateDXGIFactory1(__uuidof(IDXGIFactory1), reinterpret_cast<void**>(&factory))) || !factory)
        return out;

    for (UINT i = 0;; ++i) {
        IDXGIAdapter1* adapter = nullptr;
        const HRESULT hr = factory->EnumAdapters1(i, &adapter);
        if (hr == DXGI_ERROR_NOT_FOUND)
            break;
        if (FAILED(hr) || !adapter)
            continue;

        DXGI_ADAPTER_DESC1 desc{};
        if (SUCCEEDED(adapter->GetDesc1(&desc)) && !is_software_adapter(desc)) {
            GpuInfo gpu;
            gpu.index = static_cast<int>(out.size());
            gpu.vendor = vendor_from_pci_id(desc.VendorId);
            gpu.name = wide_to_utf8(desc.Description);
            gpu.memoryTotalMb = bytes_to_mib(static_cast<std::uint64_t>(desc.DedicatedVideoMemory));
            gpu.hasMemoryTotal = gpu.memoryTotalMb > 0;
            gpu.unifiedMemory = !gpu.hasMemoryTotal && desc.SharedSystemMemory > 0;
            if (gpu.unifiedMemory) {
                gpu.memoryTotalMb = bytes_to_mib(static_cast<std::uint64_t>(desc.SharedSystemMemory));
                gpu.hasMemoryTotal = gpu.memoryTotalMb > 0;
            }
            gpu.isDiscrete = desc.DedicatedVideoMemory > 0;
            out.push_back(std::move(gpu));
        }
        adapter->Release();
    }

    factory->Release();
    return out;
}

inline std::vector<GpuInfo> query_nvml()
{
    using nvmlDevice_t = void*;
    using nvmlReturn_t = int;
    struct nvmlMemory_t {
        unsigned long long total;
        unsigned long long free;
        unsigned long long used;
    };
    struct nvmlUtilization_t {
        unsigned int gpu;
        unsigned int memory;
    };
    constexpr nvmlReturn_t NVML_SUCCESS = 0;

    void* lib = media::library::load("nvml.dll");
    if (!lib)
        return {};

    auto sym = [&](const char* name) -> void* { return media::library::sym(lib, name); };
    using InitFn = nvmlReturn_t (*)();
    using ShutdownFn = nvmlReturn_t (*)();
    using GetCountFn = nvmlReturn_t (*)(unsigned int*);
    using GetHandleFn = nvmlReturn_t (*)(unsigned int, nvmlDevice_t*);
    using GetNameFn = nvmlReturn_t (*)(nvmlDevice_t, char*, unsigned int);
    using GetDriverFn = nvmlReturn_t (*)(char*, unsigned int);
    using GetMemoryFn = nvmlReturn_t (*)(nvmlDevice_t, nvmlMemory_t*);
    using GetUtilFn = nvmlReturn_t (*)(nvmlDevice_t, nvmlUtilization_t*);

    struct NvmlHandle {
        void* lib = nullptr;
        ShutdownFn shutdown = nullptr;
        ~NvmlHandle()
        {
            if (shutdown) shutdown();
            if (lib) media::library::unload(lib);
        }
    } guard{lib, nullptr};

    auto init = reinterpret_cast<InitFn>(sym("nvmlInit_v2"));
    if (!init)
        init = reinterpret_cast<InitFn>(sym("nvmlInit"));
    guard.shutdown = reinterpret_cast<ShutdownFn>(sym("nvmlShutdown"));
    auto getCount = reinterpret_cast<GetCountFn>(sym("nvmlDeviceGetCount_v2"));
    if (!getCount)
        getCount = reinterpret_cast<GetCountFn>(sym("nvmlDeviceGetCount"));
    auto getHandle = reinterpret_cast<GetHandleFn>(sym("nvmlDeviceGetHandleByIndex_v2"));
    if (!getHandle)
        getHandle = reinterpret_cast<GetHandleFn>(sym("nvmlDeviceGetHandleByIndex"));
    auto getName = reinterpret_cast<GetNameFn>(sym("nvmlDeviceGetName"));
    auto getDriver = reinterpret_cast<GetDriverFn>(sym("nvmlSystemGetDriverVersion"));
    auto getMemory = reinterpret_cast<GetMemoryFn>(sym("nvmlDeviceGetMemoryInfo"));
    auto getUtil = reinterpret_cast<GetUtilFn>(sym("nvmlDeviceGetUtilizationRates"));

    if (!init || !getCount || !getHandle || !getName || !getMemory || init() != NVML_SUCCESS)
        return {};

    unsigned int count = 0;
    if (getCount(&count) != NVML_SUCCESS || count == 0)
        return {};

    char driver[128]{};
    std::string driverVersion;
    if (getDriver && getDriver(driver, static_cast<unsigned int>(sizeof(driver))) == NVML_SUCCESS)
        driverVersion = driver;

    std::vector<GpuInfo> out;
    for (unsigned int i = 0; i < count; ++i) {
        nvmlDevice_t device = nullptr;
        if (getHandle(i, &device) != NVML_SUCCESS || !device)
            continue;

        char name[256]{};
        nvmlMemory_t mem{};
        GpuInfo gpu;
        gpu.index = static_cast<int>(out.size());
        gpu.vendor = "NVIDIA";
        gpu.driver = driverVersion;
        if (getName(device, name, static_cast<unsigned int>(sizeof(name))) == NVML_SUCCESS)
            gpu.name = trim_copy(name);
        if (getMemory(device, &mem) == NVML_SUCCESS) {
            gpu.memoryUsedMb = bytes_to_mib(mem.used);
            gpu.memoryTotalMb = bytes_to_mib(mem.total);
            gpu.hasMemoryUsed = true;
            gpu.hasMemoryTotal = gpu.memoryTotalMb > 0;
        }
        if (getUtil) {
            nvmlUtilization_t util{};
            if (getUtil(device, &util) == NVML_SUCCESS) {
                gpu.utilizationGpu = static_cast<float>(util.gpu);
                gpu.utilizationMemory = static_cast<float>(util.memory);
            }
        }
        gpu.isDiscrete = true;
        out.push_back(std::move(gpu));
    }
    return out;
}

#endif

inline GpuMemoryStats stats_from_infos(const std::vector<GpuInfo>& infos)
{
    GpuMemoryStats stats;
    for (const auto& gpu : infos) {
        if (!gpu.hasMemoryUsed && !gpu.hasMemoryTotal)
            continue;
        GpuMemoryDevice dev;
        dev.index = gpu.index;
        dev.name = gpu.name;
        dev.used_mib = gpu.hasMemoryUsed ? clamp_mib_to_int(gpu.memoryUsedMb) : 0;
        dev.total_mib = gpu.hasMemoryTotal ? clamp_mib_to_int(gpu.memoryTotalMb) : 0;
        stats.used_mib += dev.used_mib;
        stats.total_mib += dev.total_mib;
        stats.devices.push_back(std::move(dev));
    }
    stats.available = !stats.devices.empty();
    return stats;
}

inline GpuMemoryStats query_gpu_memory_legacy()
{
    GpuMemoryStats stats;
    const char* cmd =
        "nvidia-smi --query-gpu=index,name,memory.used,memory.total "
#if defined(_WIN32)
        "--format=csv,noheader,nounits 2>NUL";
#else
        "--format=csv,noheader,nounits 2>/dev/null";
#endif

    FILE* pipe = PM_POPEN(cmd, "r");
    if (!pipe) return stats;

    char buffer[512];
    std::string output;
    while (std::fgets(buffer, sizeof(buffer), pipe)) output += buffer;
    PM_PCLOSE(pipe);

    std::stringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        if (trim_copy(line).empty()) continue;
        std::stringstream cols(line);
        std::string index_s, name, used_s, total_s;
        if (!std::getline(cols, index_s, ',')) continue;
        if (!std::getline(cols, name, ',')) continue;
        if (!std::getline(cols, used_s, ',')) continue;
        if (!std::getline(cols, total_s, ',')) continue;

        try {
            GpuMemoryDevice dev;
            dev.index     = std::stoi(trim_copy(index_s));
            dev.name      = trim_copy(name);
            dev.used_mib  = std::stoi(trim_copy(used_s));
            dev.total_mib = std::stoi(trim_copy(total_s));
            stats.used_mib  += dev.used_mib;
            stats.total_mib += dev.total_mib;
            stats.devices.push_back(std::move(dev));
        } catch (...) {
            // Ignore malformed rows; nvidia-smi output is best-effort telemetry.
        }
    }

    stats.available = !stats.devices.empty();
    return stats;
}

} // namespace detail

class GpuMetrics
{
public:
    static std::vector<GpuInfo> enumerate()
    {
#if defined(_WIN32)
        std::vector<GpuInfo> out = detail::query_nvml();
        if (!out.empty())
            return out;
        return detail::query_dxgi();
#else
        std::vector<GpuInfo> out;
        const auto legacy = detail::query_gpu_memory_legacy();
        if (!legacy.available)
            return out;
        out.reserve(legacy.devices.size());
        for (const auto& dev : legacy.devices) {
            GpuInfo gpu;
            gpu.index = dev.index;
            gpu.vendor = "NVIDIA";
            gpu.name = dev.name;
            gpu.memoryUsedMb = static_cast<std::uint64_t>(std::max(0, dev.used_mib));
            gpu.memoryTotalMb = static_cast<std::uint64_t>(std::max(0, dev.total_mib));
            gpu.hasMemoryUsed = true;
            gpu.hasMemoryTotal = dev.total_mib > 0;
            gpu.isDiscrete = true;
            out.push_back(std::move(gpu));
        }
        return out;
#endif
    }
};

inline GpuStatusLine make_status_line(const std::vector<GpuInfo>& gpus)
{
    return detail::make_status_line(gpus);
}

inline GpuStatusLine make_status_line()
{
    return make_status_line(GpuMetrics::enumerate());
}

inline GpuMemoryStats query_gpu_memory()
{
#if defined(_WIN32)
    return detail::stats_from_infos(GpuMetrics::enumerate());
#else
    return detail::query_gpu_memory_legacy();
#endif
}

struct GpuMemorySampler {
    GpuMemoryStats baseline;
    GpuMemoryStats peak;

    explicit GpuMemorySampler(bool enabled)
    {
        if (!enabled) return;
        baseline = query_gpu_memory();
        peak = baseline;
    }

    void sample()
    {
        if (!baseline.available) return;
        const auto current = query_gpu_memory();
        if (current.available && current.used_mib > peak.used_mib) peak = current;
    }

    int delta_mib() const noexcept
    {
        return (baseline.available && peak.available) ? peak.used_mib - baseline.used_mib : 0;
    }
};

} // namespace media::gpu

#undef PM_POPEN
#undef PM_PCLOSE
