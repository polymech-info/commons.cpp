#include "string/string_filters.hpp"

#include <algorithm>
#include <cctype>
#include <utility>
#include <vector>

namespace media::llm::string_filters {
namespace {

bool starts_with_ascii(const std::string& s, const std::string& prefix)
{
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with_ascii(const std::string& s, const std::string& suffix)
{
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

} // namespace

std::string trim_copy(std::string s)
{
    const auto not_space = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

std::string strip_thinking_sections(std::string text)
{
    constexpr const char* open_tag = "<think>";
    constexpr const char* close_tag = "</think>";
    std::size_t pos = 0;
    while ((pos = text.find(open_tag, pos)) != std::string::npos) {
        const std::size_t close = text.find(close_tag, pos + 7);
        if (close == std::string::npos) {
            text.erase(pos);
            break;
        }
        text.erase(pos, close + 8 - pos);
    }
    return trim_copy(std::move(text));
}

std::string strip_wrapping_markdown_fence(std::string text)
{
    text = trim_copy(std::move(text));
    if (!starts_with_ascii(text, "```"))
        return text;

    const std::size_t first_newline = text.find('\n');
    if (first_newline == std::string::npos)
        return text;

    std::string body = trim_copy(text.substr(first_newline + 1));
    if (ends_with_ascii(body, "```"))
        body.erase(body.size() - 3);
    return trim_copy(std::move(body));
}

std::string strip_role_markers(std::string text)
{
    text = trim_copy(std::move(text));
    const std::vector<std::string> leading = {
        "<|assistant|>",
        "<|im_start|>assistant",
        "assistant:",
        "Assistant:",
        "ASSISTANT:",
    };
    bool changed = true;
    while (changed) {
        changed = false;
        text = trim_copy(std::move(text));
        for (const auto& token : leading) {
            if (starts_with_ascii(text, token)) {
                text.erase(0, token.size());
                changed = true;
                break;
            }
        }
    }

    for (;;) {
        text = trim_copy(std::move(text));
        if (ends_with_ascii(text, "<|im_end|>")) {
            text.erase(text.size() - 10);
            continue;
        }
        if (ends_with_ascii(text, "</s>")) {
            text.erase(text.size() - 4);
            continue;
        }
        break;
    }
    return trim_copy(std::move(text));
}

GeneratedTextFilterResult filter_generated_text(std::string text,
                                                const GeneratedTextFilterOptions& options)
{
    const std::string original = text;
    if (options.strip_thinking)
        text = strip_thinking_sections(std::move(text));
    if (options.strip_fences)
        text = strip_wrapping_markdown_fence(std::move(text));
    if (options.strip_role_labels)
        text = strip_role_markers(std::move(text));
    if (options.trim_output)
        text = trim_copy(std::move(text));

    const bool changed = text != original;
    const bool empty_after_filter = text.empty() && !original.empty();
    return {
        std::move(text),
        changed,
        empty_after_filter,
    };
}

} // namespace media::llm::string_filters
