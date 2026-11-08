#pragma once

// Path policy for tools and viewers.
// Deny lists live in file_extensions.hpp (k_sensitive_path_prefixes,
// k_llm_write_blocked_exts). The .cpp also checks dotfiles and platform hidden files.

#include <filesystem>
#include <string>

namespace media::llm {

/// Non-empty reason when a tool must not read, write, list, or emit this path.
/// Empty means allowed. Blocks dot-named basenames, platform-hidden files, and
/// sensitive prefixes. An existing path is normalized with weakly_canonical first.
std::string llm_fs_guard_deny_reason(const std::filesystem::path& path);

/// Same sensitive-path blocks as llm_fs_guard_deny_reason, but allows a
/// user-opened dotfile and FILE_ATTRIBUTE_HIDDEN / UF_HIDDEN.
std::string llm_fs_guard_viewer_deny_reason(const std::filesystem::path& path);

/// k_sensitive_path_prefixes only. Does not check dotfiles or the platform
/// hidden flag. Callers that have their own include_hidden option use this.
bool llm_is_sensitive_path(const std::filesystem::path& path);

/// Write targets only. Blocks disallowed extensions and system prefixes.
/// Image, video, and audio extensions on the allowlist are permitted.
std::string llm_fs_guard_write_deny_reason(const std::filesystem::path& path);

} // namespace media::llm
