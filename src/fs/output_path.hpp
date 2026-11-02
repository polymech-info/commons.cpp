#pragma once

#include <string>

namespace media {

/**
 * Single-segment filename sanitizer — mirrors packages/acl `sanitizeFilename` (illegal chars,
 * control chars, Windows reserved names, trailing dots/spaces). Result truncated to 255 UTF-8 bytes.
 */
std::string sanitize_filename(std::string input);

/**
 * One resolved input (absolute file path or URL) → default output path next to source (URLs → cwd),
 * same naming rules as `default_output_path_for_resize` for a single file.
 */
std::string default_output_path_for_one_input(const std::string &resolved_input, const std::string &format_cli,
                                              std::string &err_out, const std::string &stem_suffix = {});

/**
 * When CLI omits output: expand inputs; if exactly one file/URL, build default output; if multiple
 * files match, returns empty with err_out cleared — caller pairs jobs via `pair_resize_paths` with
 * implicit format/stem. On real errors, err_out is set.
 */
std::string default_output_path_for_resize(const std::string &input_spec, const std::string &format_cli,
                                           std::string &err_out, const std::string &stem_suffix = {});

} // namespace media
