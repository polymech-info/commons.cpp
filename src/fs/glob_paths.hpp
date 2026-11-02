#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace media {

enum class GalleryGlob {
    IMAGES,
};

/** True if path likely needs filesystem glob expansion (*, ?, **). */
bool has_glob_tokens(const std::string &path);

/**
 * Expand a leading `~` or `~/` to the current user's home directory.
 * Works on Windows (USERPROFILE / HOMEDRIVE+HOMEPATH) and POSIX (HOME).
 * Only bare `~` is expanded — `~user/path` is returned unchanged.
 * The path is returned as-is when the home directory cannot be determined.
 */
std::string expand_home_dir(std::string path);

/**
 * Match a normalized path string against a glob-style pattern (forward slashes only).
 * Supports `**` (any depth), and `*` / `?` within a single path segment (not across `/`).
 * A leading `./` on the pattern is ignored. Empty pattern matches an empty path only.
 */
bool path_matches_path_glob(std::string_view path_norm, std::string_view pattern_norm);

/**
 * True if `output` uses dst templates (`${SRC_DIR}`, `${SRC_NAME}`, `${SRC_FILE_EXT}` or `&{…}`).
 * @see docs/Examples.md — SRC_NAME is the stem (no extension); SRC_FILE_EXT includes the leading dot.
 */
bool has_dst_template(const std::string &output_spec);

/**
 * Resolve input spec to a list of inputs: `http(s)://` URL (single), literal file, or glob / recursive glob.
 * Each entry is an absolute filesystem path in UTF-8 with generic separators, or the full URL string.
 */
std::vector<std::string> expand_input_paths(const std::string &input_spec, std::string &err_out);

/**
 * Resolve one CLI `--src` / batch segment: `http(s)://` URL, glob / `**` pattern, existing file,
 * or directory (all supported image files, recursive). Not for semicolon-joined multi-file (use
 * `InputSelection` for multiple arguments).
 */
std::vector<std::string> expand_one_cli_src(const std::string &segment, std::string &err_out);

/** True if @p path belongs to the requested gallery glob preset. */
bool path_matches_gallery_glob(const std::filesystem::path &path, GalleryGlob glob = GalleryGlob::IMAGES);

/**
 * Map inputs to output paths: optional per-file dst templates, one output file,
 * or one file per input under a directory (trailing separator or existing directory).
 * If `output_spec` is empty and `implicit_format_cli` is non-null, builds default output next to
 * each input (same rules as `default_output_path_for_one_input`) using `*implicit_format_cli` and
 * `implicit_stem_suffix` (optional).
 */
std::vector<std::pair<std::string, std::filesystem::path>>
pair_resize_paths(const std::string &input_spec, const std::string &output_spec, std::string &err_out,
                  const std::string *implicit_format_cli = nullptr,
                  const std::string *implicit_stem_suffix = nullptr);

} // namespace media
