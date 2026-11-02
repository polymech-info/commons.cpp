#pragma once

/// Compile-time log floor for `pm::log::*_lazy` (see `docs/logging.md`).
/// **Higher** numeric value = fewer messages compiled in.
///
/// | Value | Name  | Keeps |
/// |------:|-------|-------|
/// | 0 | TRACE | trace, debug, info, warn, error |
/// | 1 | DEBUG | debug, info, warn, error |
/// | 2 | INFO  | info, warn, error (typical **Release** default) |
/// | 3 | WARN  | warn, error |
/// | 4 | ERROR | error only |
/// | 5 | OFF   | none of the `_lazy` helpers emit |
///
/// CMake sets `PM_COMPILE_LOG_LEVEL` on the `pm-media` target as **PUBLIC** (see root
/// `CMakeLists.txt`) so dependents (e.g. `pm-image`) compile the same floor. If unset (e.g. IDE
/// single-file compile), default to **TRACE** so `*_lazy` bodies are not stripped.

#ifndef PM_COMPILE_LOG_LEVEL
#  define PM_COMPILE_LOG_LEVEL 0
#endif

namespace pm::log::detail {

inline constexpr int kSevTrace = 0;
inline constexpr int kSevDebug = 1;
inline constexpr int kSevInfo  = 2;
inline constexpr int kSevWarn  = 3;
inline constexpr int kSevErr   = 4;

inline constexpr int compile_log_level = PM_COMPILE_LOG_LEVEL;

} // namespace pm::log::detail
