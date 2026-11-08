#pragma once

// Dev-folder name rules for directory walks, plus the extension denylist
// shared with file reads.

#include <filesystem>
#include <string_view>

namespace media::llm {

/// True when a single path component should be skipped under a project tree.
bool glob_exclude_default_path_component(std::string_view name_utf8);

/// True when any filename segment matches glob_exclude_default_path_component.
bool glob_path_has_excluded_component(const std::filesystem::path& path);

/// Extension denylist shared with file reads. `ext_lower` includes the dot.
bool glob_file_extension_blocked_like_file_read(std::string_view ext_lower);

} // namespace media::llm
