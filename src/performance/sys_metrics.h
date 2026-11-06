#pragma once
#include <cstddef>
#include <cstdint>

namespace polymech {
size_t get_current_rss_mb();
uint64_t get_cpu_time_ms();
}
