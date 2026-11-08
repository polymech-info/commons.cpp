#include "fs/glob_filter.hpp"

#include "fs/file_extensions.hpp"

#include <cctype>
#include <string>
#include "fs/path_sanitizer.hpp"
#include "string/string_utils.hpp"

namespace media::llm {

namespace {


bool exclude_set_contains_lower(std::string_view key_lower) {
    for (const char* e : pmui::k_llm_glob_exclude_names) {
        if (key_lower == e) return true;
    }
    return false;
}

} // namespace

bool glob_exclude_default_path_component(std::string_view name_utf8) {
    if (name_utf8.empty()) return false;
    if (name_utf8[0] == '.') return true;

    std::string key(name_utf8);
    key = media::strutil::lower_ascii(key);
    return exclude_set_contains_lower(std::string_view(key));
}

bool glob_path_has_excluded_component(const std::filesystem::path& path) {
    for (const auto& part : path) {
        const std::string seg = media::path::path_to_utf8(part);
        if (seg.empty() || seg == "." || seg == "..") continue;
        if (glob_exclude_default_path_component(seg)) return true;
    }
    return false;
}

bool glob_file_extension_blocked_like_file_read(std::string_view ext_lower) {
    for (const char* b : pmui::k_llm_glob_blocked_exts) {
        if (ext_lower == b) return true;
    }
    return false;
}

} // namespace media::llm
