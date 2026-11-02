#pragma once

#include <string>
#include <string_view>

namespace pm::filters {

// Per-directory mask file. Gitignore is the default. `.ignore` is the same
// syntax with a different file name, so later kinds can sit beside it.
enum class MaskKind {
    None,
    Gitignore,
    Ignore,
};

[[nodiscard]] const char* mask_file_name(MaskKind kind) noexcept;

[[nodiscard]] bool parse_mask_kind(std::string_view text, MaskKind& out);

// True when a mask file from `kind` ignores `path`. Walks parent directories
// up to a `.git` directory (that directory's mask is included). No mask file
// means not ignored. `!` is a positive exception; the last matching pattern
// wins, closer directories first.
[[nodiscard]] bool is_ignored(
    std::string_view path,
    bool is_dir,
    MaskKind kind);

// Same walk as `is_ignored`, reading `file_name` (for example `.npmignore`).
[[nodiscard]] bool is_ignored_named(
    std::string_view path,
    bool is_dir,
    std::string_view file_name);

} // namespace pm::filters
