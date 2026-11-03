#pragma once

#include <nlohmann/json.hpp>

#include <istream>
#include <string>
#include <string_view>

namespace media::json {

/// Non-throwing JSON parse for untrusted text (LLM output, HTTP/MCP bodies,
/// WebView messages, user files). Never calls std::abort() even when nlohmann
/// is built with JSON_NOEXCEPTION. On failure returns a discarded json (test
/// with is_discarded()).
inline nlohmann::json try_parse(std::string_view text)
{
    return nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
}

inline nlohmann::json try_parse(std::istream& in)
{
    return nlohmann::json::parse(in, nullptr, /*allow_exceptions=*/false);
}

inline bool parse_ok(const nlohmann::json& j) noexcept
{
    return !j.is_discarded();
}

/// Parse or return `fallback` (default: discarded → treat as null object/array
/// at call site via json_child_* helpers).
inline nlohmann::json parse_or(std::string_view text, nlohmann::json fallback = {})
{
    nlohmann::json j = try_parse(text);
    return parse_ok(j) ? std::move(j) : std::move(fallback);
}

inline nlohmann::json parse_object_or(std::string_view text)
{
    nlohmann::json j = try_parse(text);
    return (parse_ok(j) && j.is_object()) ? std::move(j) : nlohmann::json::object();
}

inline nlohmann::json parse_array_or(std::string_view text)
{
    nlohmann::json j = try_parse(text);
    return (parse_ok(j) && j.is_array()) ? std::move(j) : nlohmann::json::array();
}

} // namespace media::json
