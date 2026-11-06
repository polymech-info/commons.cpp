#include "sys_metrics.h"

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

namespace polymech {
size_t get_current_rss_mb() {
  PROCESS_MEMORY_COUNTERS info;
  if (GetProcessMemoryInfo(GetCurrentProcess(), &info, sizeof(info))) {
    return (size_t)(info.WorkingSetSize) / (1024 * 1024);
  }
  return 0;
}

uint64_t get_cpu_time_ms() {
  FILETIME creationTime, exitTime, kernelTime, userTime;
  if (GetProcessTimes(GetCurrentProcess(), &creationTime, &exitTime, &kernelTime, &userTime)) {
    ULARGE_INTEGER kernel, user;
    kernel.LowPart = kernelTime.dwLowDateTime;
    kernel.HighPart = kernelTime.dwHighDateTime;
    user.LowPart = userTime.dwLowDateTime;
    user.HighPart = userTime.dwHighDateTime;
    return (kernel.QuadPart + user.QuadPart) / 10000;
  }
  return 0;
}
}
#else
namespace polymech {
size_t get_current_rss_mb() { return 0; }
uint64_t get_cpu_time_ms() { return 0; }
}
#endif
