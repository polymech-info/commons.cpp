#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace media::str_san {

/** Sentinel userId for unauthenticated / anonymous (matches ref DefaultSanitizers). */
inline constexpr std::string_view k_anonymous_user_id  = "anonymous";
/** Sentinel userId for any authenticated user. */
inline constexpr std::string_view k_authenticated_user_id = "authenticated";

std::string clean_path(std::string_view raw);
std::vector<std::string> path_segments(std::string_view raw);
std::string normalise_path(std::string_view raw);

/**
 * @param err  Set if invalid: empty / invalid UUID
 * @return Normalised (lowercased) UUID, or empty if `err` set
 */
std::string clean_uuid(std::string_view raw, std::string &err);
bool        is_uuid(std::string_view raw);
std::string clean_id(std::string_view raw, std::string &err);
std::string clean_group_name(std::string_view raw, std::string &err);
std::string clean_permission(std::string_view raw, std::string &err);
std::vector<std::string> clean_permissions(const std::vector<std::string> &raw, std::string &err);

// ── Composable text sanitizers ───────────────────────────────────────────────
//
// These are intentionally byte/string-level filters with no dependency on the
// HTML/Markdown package (pm-media links html, not the reverse). They are used
// before content is injected into LLM prompts or rendered through Markdown/HTML
// paths. Keep semantic parsers in packages/html; keep reusable safety profiles
// here.
enum class TextSanitizer : std::uint8_t {
    StripUtf8Bom,
    RepairInvalidUtf8,
    /// Keep printable ASCII plus text controls: TAB, LF, CR. Removes emoji,
    /// smart punctuation, zero-width/control-format chars, and other non-ASCII.
    StripNonAsciiExceptTextControls,
    StripHtmlComments,
    StripHtmlDangerousElements,
};

inline constexpr std::array<TextSanitizer, 3> k_common_text_sanitizers{{
    TextSanitizer::StripUtf8Bom,
    TextSanitizer::RepairInvalidUtf8,
    TextSanitizer::StripNonAsciiExceptTextControls,
}};

inline constexpr std::array<TextSanitizer, 5> k_default_html_sanitizers{{
    TextSanitizer::StripUtf8Bom,
    TextSanitizer::RepairInvalidUtf8,
    TextSanitizer::StripNonAsciiExceptTextControls,
    TextSanitizer::StripHtmlComments,
    TextSanitizer::StripHtmlDangerousElements,
}};

inline constexpr std::array<TextSanitizer, 5> k_default_markdown_sanitizers{{
    TextSanitizer::StripUtf8Bom,
    TextSanitizer::RepairInvalidUtf8,
    TextSanitizer::StripNonAsciiExceptTextControls,
    TextSanitizer::StripHtmlComments,
    TextSanitizer::StripHtmlDangerousElements,
}};

/// Skills are Markdown and are injected into the system prompt. Use the
/// Markdown profile by default so prompt-injection carrier text (emoji,
/// zero-width chars, raw HTML script/style blocks) is stripped before assembly.
inline constexpr auto k_default_skill_prompt_sanitizers = k_default_markdown_sanitizers;

std::string apply_text_sanitizer(std::string_view raw, TextSanitizer sanitizer);
std::string apply_text_sanitizers(std::string_view raw, const TextSanitizer* sanitizers, std::size_t count);

/**
 * Decode text-like file bytes to UTF-8 and make the result safe for JSON/JSONB
 * storage. Handles UTF-16 LE/BE BOMs and common UTF-16 NUL-byte patterns, strips
 * UTF-8 BOMs, repairs invalid UTF-8, and removes U+0000 / raw NUL bytes because
 * PostgreSQL json/jsonb rejects them even when escaped.
 */
std::string normalise_text_for_json_storage(std::string_view raw);

/// Byte length of `s` that is valid UTF-8 and does not exceed `max_bytes`.
/// Never ends on a continuation or a dangling multi-byte lead.
std::size_t utf8_safe_prefix_len(std::string_view s, std::size_t max_bytes);
std::string utf8_safe_prefix(std::string_view s, std::size_t max_bytes);
/// Byte length of a suffix of `s` that starts on a code-point boundary and
/// does not exceed `max_bytes`. Leading continuation bytes are dropped.
std::size_t utf8_safe_suffix_len(std::string_view s, std::size_t max_bytes);
std::string utf8_safe_suffix(std::string_view s, std::size_t max_bytes);
/// Clip `s` to `max_bytes` on a code-point boundary, then append `ellipsis`.
/// The ellipsis bytes are reserved before the cut so a lead byte is never
/// left immediately before `.` / `…`.
std::string utf8_safe_ellipsize(std::string_view s, std::size_t max_bytes,
                                std::string_view ellipsis = "...");

template <std::size_t N>
std::string apply_text_sanitizers(std::string_view raw, const std::array<TextSanitizer, N>& sanitizers)
{
    return apply_text_sanitizers(raw, sanitizers.data(), sanitizers.size());
}

/** Reject empty/whitespace-only. */
std::string assert_non_empty_str(std::string_view value, std::string_view label, std::string &err);
bool       assert_non_empty_list(const std::vector<std::string> &values, std::string_view label, std::string &err);

} // namespace media::str_san
