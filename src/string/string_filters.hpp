#pragma once

#include <string>

namespace media::llm::string_filters {

struct GeneratedTextFilterOptions {
    bool strip_thinking = true;
    bool strip_fences = true;
    bool strip_role_labels = true;
    bool trim_output = true;
};

struct GeneratedTextFilterResult {
    std::string text;
    bool changed = false;
    bool empty_after_filter = false;
};

std::string trim_copy(std::string s);
std::string strip_thinking_sections(std::string text);
std::string strip_wrapping_markdown_fence(std::string text);
std::string strip_role_markers(std::string text);

GeneratedTextFilterResult filter_generated_text(std::string text,
                                                const GeneratedTextFilterOptions& options = {});

} // namespace media::llm::string_filters
