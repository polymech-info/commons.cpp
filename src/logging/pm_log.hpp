#pragma once

#include "logging/pm_log_level.hpp"
#include "logger/logger.h"

#include <string>
#include <string_view>
#include <type_traits>
#include <utility> // declval

namespace pm::log {

/// Prefix `msg` with `[channel]` for grep-friendly console / file lines.
inline std::string prefixed(std::string_view channel, const std::string& msg)
{
    std::string out;
    out.reserve(channel.size() + msg.size() + 3);
    out.push_back('[');
    out.append(channel);
    out.append("] ");
    out.append(msg);
    return out;
}

namespace detail {

template<typename F>
using log_string_result_t = decltype(std::declval<F>()());

} // namespace detail

/// **Compile-time + lazy:** when `PM_COMPILE_LOG_LEVEL` is above debug, the lambda is **not**
/// invoked (no string work). Prefer this over `debug()` for hot paths.
template<typename F>
inline void debug_lazy(std::string_view channel, F&& make_message)
{
    if constexpr (detail::kSevDebug >= detail::compile_log_level) {
        static_assert(std::is_convertible_v<detail::log_string_result_t<F>, std::string>,
                      "make_message() must return std::string (or convertible)");
        logger::debug(prefixed(channel, std::forward<F>(make_message)()));
    } else {
        (void)channel;
        (void)make_message;
    }
}

/// Same contract as `debug_lazy` for trace (maps to `logger::trace`).
template<typename F>
inline void trace_lazy(std::string_view channel, F&& make_message)
{
    if constexpr (detail::kSevTrace >= detail::compile_log_level) {
        static_assert(std::is_convertible_v<detail::log_string_result_t<F>, std::string>,
                      "make_message() must return std::string (or convertible)");
        logger::trace(prefixed(channel, std::forward<F>(make_message)()));
    } else {
        (void)channel;
        (void)make_message;
    }
}

template<typename F>
inline void info_lazy(std::string_view channel, F&& make_message)
{
    if constexpr (detail::kSevInfo >= detail::compile_log_level) {
        static_assert(std::is_convertible_v<detail::log_string_result_t<F>, std::string>,
                      "make_message() must return std::string (or convertible)");
        logger::info(prefixed(channel, std::forward<F>(make_message)()));
    } else {
        (void)channel;
        (void)make_message;
    }
}

template<typename F>
inline void warn_lazy(std::string_view channel, F&& make_message)
{
    if constexpr (detail::kSevWarn >= detail::compile_log_level) {
        static_assert(std::is_convertible_v<detail::log_string_result_t<F>, std::string>,
                      "make_message() must return std::string (or convertible)");
        logger::warn(prefixed(channel, std::forward<F>(make_message)()));
    } else {
        (void)channel;
        (void)make_message;
    }
}

template<typename F>
inline void error_lazy(std::string_view channel, F&& make_message)
{
    if constexpr (detail::kSevErr >= detail::compile_log_level) {
        static_assert(std::is_convertible_v<detail::log_string_result_t<F>, std::string>,
                      "make_message() must return std::string (or convertible)");
        logger::error(prefixed(channel, std::forward<F>(make_message)()));
    } else {
        (void)channel;
        (void)make_message;
    }
}

/// Eager forms: always evaluate `msg`. `debug()` is still omitted at compile time when the
/// floor is above DEBUG (message text is still built at the call site — prefer `debug_lazy`).
inline void info(std::string_view channel, const std::string& msg)
{
    if constexpr (detail::kSevInfo >= detail::compile_log_level)
        logger::info(prefixed(channel, msg));
}

inline void warn(std::string_view channel, const std::string& msg)
{
    if constexpr (detail::kSevWarn >= detail::compile_log_level)
        logger::warn(prefixed(channel, msg));
}

inline void error(std::string_view channel, const std::string& msg)
{
    if constexpr (detail::kSevErr >= detail::compile_log_level)
        logger::error(prefixed(channel, msg));
}

inline void debug(std::string_view channel, const std::string& msg)
{
    if constexpr (detail::kSevDebug >= detail::compile_log_level)
        logger::debug(prefixed(channel, msg));
}

} // namespace pm::log
